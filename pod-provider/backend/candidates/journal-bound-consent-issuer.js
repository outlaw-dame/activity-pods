'use strict';

// NONACTIVATED provider-held restricted PostgreSQL issuer. Only an owner-
// claimed HttpOnly browser enrollment session can reserve a new PENDING
// canonical consent; application/browser never receives this SQL credential.
// Neither arbitrary reservation/operation IDs nor a user-selected WebID,
// DID, app or rights can be supplied to the SQL admission function.
function unavailable(code) {
  const error = new Error('Owner-bound pending consent issuance unavailable');
  error.code = code;
  throw error;
}
function createDisposableJournalBoundConsentIssuer({
  pool, providerId, browserOrigin, fixtureOnly = false
} = {}) {
  const gate = () => {
    if (fixtureOnly !== true || process.env.NODE_ENV !== 'test' ||
        process.env.PAPER_JOURNAL_BOUND_SAI_DISPOSABLE !== 'confirmed' ||
        process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed') {
      unavailable('OWNER_CONSENT_ISSUER_NOT_RELEASED');
    }
  };
  gate();
  for (const expected of [providerId, browserOrigin]) {
    let parsed;
    try { parsed = new URL(expected); }
    catch { unavailable('OWNER_CONSENT_ISSUER_CONFIGURATION_INVALID'); }
    if (typeof expected !== 'string' || expected.length > 2048 ||
        parsed.protocol !== 'https:' || parsed.username || parsed.password ||
        parsed.search || parsed.hash || parsed.origin !== expected) {
      unavailable('OWNER_CONSENT_ISSUER_CONFIGURATION_INVALID');
    }
  }
  if (typeof pool?.connect !== 'function') unavailable('OWNER_CONSENT_ISSUER_CONFIGURATION_INVALID');

  async function borrow() {
    let expired = false, timer;
    const pending = Promise.resolve().then(() => pool.connect()).then(client => {
      if (expired) {
        client.release(true);
        unavailable('OWNER_CONSENT_ISSUER_CONNECTION_UNAVAILABLE');
      }
      if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
        unavailable('OWNER_CONSENT_ISSUER_CONNECTION_UNAVAILABLE');
      }
      return client;
    });
    try {
      return await Promise.race([pending, new Promise((_, reject) => {
        timer = setTimeout(() => { expired = true; reject(new Error('Issuer acquire timeout')); }, 3500);
      })]);
    } finally { clearTimeout(timer); }
  }

  async function admission(client) {
    gate();
    let result;
    try {
      result = await client.query(
        "SELECT current_setting('server_version_num')::integer AS version," +
        "current_user=session_user AS own_login," +
        "r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR" +
        " r.rolreplication OR r.rolbypassrls) AS restricted," +
        "pg_catalog.pg_has_role(current_user,'paper_atproto_consent_issuer','USAGE') AS issuer," +
        "pg_catalog.pg_has_role(current_user,'paper_atproto_consent_issuer','SET') AS can_switch," +
        "pg_catalog.pg_has_role(current_user,'paper_atproto_consent_attestor','MEMBER') AS attestor," +
        "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_importer','MEMBER') AS importer," +
        "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_revoker','MEMBER') AS revoker," +
        "pg_catalog.has_schema_privilege(current_user,'paper_atproto_authority','CREATE') AS schema_create," +
        "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS table_access," +
        "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_authority.consents','SELECT,INSERT,UPDATE,REFERENCES') AS column_access," +
        "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.begin_session_owner_consent(text,text,bytea)','EXECUTE') AS begin_session," +
        "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.begin_bound_owner_consent(uuid,uuid)','EXECUTE') AS begin_raw," +
        "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.begin_owner_consent(text,text,text,uuid,bytea)','EXECUTE') AS begin_legacy," +
        "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.attest_bound_owner_consent(uuid,uuid,text,text,bytea)','EXECUTE') AS attest," +
        "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.confirm_bound_owner_consent(uuid,uuid,text,text,bytea)','EXECUTE') AS confirm," +
        "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members WHERE member=r.oid) AS memberships," +
        "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members am WHERE am.member=r.oid" +
        " AND (am.set_option OR am.admin_option OR NOT am.inherit_option)) AS bad_options," +
        "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members am" +
        " WHERE am.member='paper_atproto_consent_issuer'::regrole) AS parent_roles" +
        " FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"
      );
    } catch { unavailable('OWNER_CONSENT_ISSUER_ROLE_UNSAFE'); }
    const p = result.rows?.[0];
    if (result.rowCount !== 1 || p.version < 180000 || p.own_login !== true ||
        p.restricted !== true || p.issuer !== true || p.can_switch !== false ||
        p.attestor !== false || p.importer !== false || p.revoker !== false ||
        p.schema_create !== false || p.table_access !== false || p.column_access !== false ||
        p.begin_session !== true || p.begin_raw !== false || p.begin_legacy !== false ||
        p.attest !== false || p.confirm !== false || p.memberships !== 1 ||
        p.bad_options !== 0 || p.parent_roles !== 0) {
      unavailable('OWNER_CONSENT_ISSUER_ROLE_UNSAFE');
    }
    return true;
  }
  return Object.freeze({
    async reserve({ providerId: provider, origin, tokenHash } = {}) {
      gate();
      if (provider !== providerId || origin !== browserOrigin ||
          !Buffer.isBuffer(tokenHash) || tokenHash.length !== 32) {
        unavailable('OWNER_CONSENT_ISSUER_SCOPE_INVALID');
      }
      // Never cache authority decisions across a database restore, privilege
      // change or pool reconnection. Each call checks its actual PG LOGIN.
      let client, discard = false;
      try {
        client = await borrow();
        // Privilege audit and state-changing CAS occur on the SAME PG login
        // connection. Never borrow another session between these checks.
        await admission(client);
        const result = await client.query({
          text: 'SELECT paper_atproto_authority.begin_session_owner_consent($1::text,$2::text,$3::bytea) AS allowed',
          values: [providerId, browserOrigin, tokenHash],
          query_timeout: 5000
        });
        if (result.rowCount !== 1 || result.rows[0]?.allowed !== true) {
          unavailable('OWNER_CONSENT_ISSUER_JOURNAL_NOT_CURRENT');
        }
        return true;
      } catch (error) {
        discard = true;
        throw error?.code?.startsWith('OWNER_CONSENT_') ? error :
          Object.assign(new Error('Bound consent issuer database unavailable'),
            { code: 'OWNER_CONSENT_ISSUER_UNAVAILABLE' });
      } finally {
        if (client) client.release(discard);
      }
    }
  });
}
module.exports = { createDisposableJournalBoundConsentIssuer };
