'use strict';

// NONACTIVATED, read-only PostgreSQL18 + independently challenge-signed head
// composition. No SemApps auth registration, production service import,
// signup cutover or fallback to Redis/local memory is permitted.
const { isDisposableCredentialHeadAuthority } = require('./credential-signed-latest-head');
const EPOCH = /^[1-9][0-9]{0,18}$/u;
const HEX = /^[0-9a-f]{64}$/u;
const MAX = 9223372036854775807n;
function fail(code) {
  const error = new Error('Canonical credential authority unavailable');
  error.code = code;
  throw error;
}
function epoch(value) {
  return typeof value === 'string' && EPOCH.test(value) && BigInt(value) <= MAX;
}
function equals(a, b) {
  return a && b && a.authority === b.authority &&
    a.subject === b.subject && a.epoch === b.epoch &&
    a.state === b.state && a.digest === b.digest;
}
function createDisposableCertifiedCredentialReader({
  pool, headAuthority, fixtureOnly = false
} = {}) {
  if (process.env.NODE_ENV !== 'test' ||
      process.env.PAPER_CREDENTIAL_PG_DISPOSABLE !== 'confirmed' ||
      process.env.PAPER_CREDENTIAL_HEAD_DISPOSABLE !== 'confirmed' ||
      fixtureOnly !== true)
    fail('CREDENTIAL_PG_NOT_RELEASED');
  if (typeof pool?.connect !== 'function' ||
      !isDisposableCredentialHeadAuthority(headAuthority))
    fail('CREDENTIAL_PG_CONFIGURATION_INVALID');

  async function borrow() {
    let timedOut = false, timer;
    const task = Promise.resolve().then(() => pool.connect()).then(client => {
      if (timedOut) {
        client?.release?.(true);
        fail('CREDENTIAL_PG_UNAVAILABLE');
      }
      if (typeof client?.query !== 'function' || typeof client?.release !== 'function')
        fail('CREDENTIAL_PG_UNAVAILABLE');
      return client;
    });
    try {
      return await Promise.race([task, new Promise((_, reject) => {
        timer = setTimeout(() => { timedOut = true; reject(Error('connect timeout')); }, 2500);
      })]);
    } finally { clearTimeout(timer); }
  }
  const ADMISSION = [
    'SELECT current_setting(\'server_version_num\')::integer AS version,',
    'current_user=session_user AS sole_login,',
    'NOT pg_catalog.pg_is_in_recovery() AS primary_host,',
    'r.rolcanlogin AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole',
    ' OR r.rolreplication OR r.rolbypassrls) AS restricted,',
    "pg_catalog.pg_has_role(current_user,'paper_credential_reader','USAGE') AS reader,",
    "pg_catalog.pg_has_role(current_user,'paper_credential_reader','SET') AS can_switch,",
    "pg_catalog.pg_has_role(current_user,'paper_credential_enroller','MEMBER') AS enroller,",
    "pg_catalog.pg_has_role(current_user,'paper_credential_coordinator','MEMBER') AS coordinator,",
    "pg_catalog.has_schema_privilege(current_user,'paper_credential_epoch','CREATE') AS schema_create,",
    "pg_catalog.has_table_privilege(current_user,'paper_credential_epoch.owners',",
    " 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS direct_access,",
    "pg_catalog.has_function_privilege(current_user,",
    " 'paper_credential_epoch.read_certified(text)','EXECUTE') AS certified_read,",
    "pg_catalog.has_function_privilege(current_user,",
    " 'paper_credential_epoch.enroll_owner(text)','EXECUTE') AS can_enroll,",
    "pg_catalog.has_function_privilege(current_user,",
    " 'paper_credential_epoch.begin_change(text,uuid,bigint)','EXECUTE') AS can_begin,",
    "pg_catalog.has_function_privilege(current_user,",
    " 'paper_credential_epoch.seal_change(text,uuid,bigint,bytea)','EXECUTE') AS can_seal,",
    "pg_catalog.has_function_privilege(current_user,",
    " 'paper_credential_epoch.disable_owner(text)','EXECUTE') AS can_disable",
    'FROM pg_catalog.pg_roles r WHERE r.rolname=current_user'
  ].join(' ');

  async function assertRole(client) {
    let result;
    try {
      result = await client.query({ text: ADMISSION, query_timeout: 3000 });
    } catch { fail('CREDENTIAL_PG_ROLE_UNSAFE'); }
    const x = result?.rows?.[0];
    if (result?.rowCount !== 1 || x?.version < 180000 ||
        x?.sole_login !== true || x?.primary_host !== true ||
        x?.restricted !== true || x?.reader !== true || x?.can_switch !== false ||
        x?.enroller !== false || x?.coordinator !== false ||
        x?.schema_create !== false || x?.direct_access !== false ||
        x?.certified_read !== true || x?.can_enroll !== false ||
        x?.can_begin !== false || x?.can_seal !== false ||
        x?.can_disable !== false)
      fail('CREDENTIAL_PG_ROLE_UNSAFE');
  }
  async function readOwnerState(webId) {
    if (process.env.NODE_ENV !== 'test') fail('CREDENTIAL_PG_NOT_RELEASED');
    let client, discard = false;
    try {
      // No source-provided user-supplied certified head or cached approval.
      // Both remote responses are independently nonce-bound to this request.
      const before = await headAuthority.readFresh(webId);
      client = await borrow();
      await assertRole(client);
      const result = await client.query({
        text: 'SELECT mode,state,epoch,digest FROM paper_credential_epoch.read_certified($1::text)',
        values: [webId], query_timeout: 3000
      });
      const row = result?.rows?.[0];
      if (result?.rowCount !== 1 || !row || row.mode !== 'unified' ||
          !['active', 'pending', 'disabled'].includes(row.state) ||
          !epoch(row.epoch) || !HEX.test(row.digest || ''))
        fail('CREDENTIAL_PG_MISSING_OR_INVALID');
      const after = await headAuthority.readFresh(webId);
      if (!equals(before, after) ||
          before.epoch !== row.epoch || before.state !== row.state ||
          before.digest !== row.digest)
        fail('CREDENTIAL_PG_ROLLBACK_OR_RACE');
      return Object.freeze({
        webId, mode: 'unified', epoch: row.epoch, state: row.state
      });
    } catch (error) {
      discard = true;
      if (typeof error?.code === 'string' &&
          (error.code.startsWith('CREDENTIAL_PG_') ||
           error.code.startsWith('CREDENTIAL_HEAD_')))
        throw error;
      fail('CREDENTIAL_PG_UNAVAILABLE');
    } finally {
      if (client) client.release(discard);
    }
  }
  return Object.freeze({ readOwnerState, releaseAccepted: false });
}
module.exports = { createDisposableCertifiedCredentialReader };
