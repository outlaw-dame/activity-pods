'use strict';

// Restricted enrollment only. No normal JWT, identity creation or completion.
const crypto = require('node:crypto');
const COOKIE = '__Host-paper-enrollment';
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const hash = (purpose, value) => crypto.createHash('sha256')
  .update('paper:enrollment:v1:' + purpose + '\0').update(value).digest();
function deny(code = 'ENROLLMENT_UNAVAILABLE') {
  const error = new Error('Enrollment is unavailable or requires reconciliation');
  error.code = code;
  error.retryable = false;
  throw error;
}
function url(value, origin = false) {
  try {
    const u = new URL(value);
    if (typeof value !== 'string' || value.length > 2048 || u.protocol !== 'https:' ||
        u.username || u.password || u.hash || u.hostname.includes('*') || (origin ? u.origin !== value : u.href !== value)) deny();
    return value;
  } catch { deny('ENROLLMENT_CONFIGURATION_INVALID'); }
}
function identifiers(values) {
  if (!Array.isArray(values) || values.length > 128 ||
      values.some(v => typeof v !== 'string' || v.length > 2048 ||
        !(/^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]+$/u.test(v))) ||
      new Set(values).size !== values.length) deny('ENROLLMENT_SELECTION_INVALID');
  return [...values].sort();
}
function requirements(value) {
  if (!value || Object.keys(value).sort().join(',') !== 'optional,required,revision' ||
      !/^[a-f0-9]{64}$/u.test(value.revision || '')) deny('ENROLLMENT_REQUIREMENTS_INVALID');
  const result = { required: identifiers(value.required), optional: identifiers(value.optional), revision: value.revision };
  if (result.optional.some(v => result.required.includes(v)) ||
      Buffer.byteLength(JSON.stringify(result)) > 32768) deny('ENROLLMENT_REQUIREMENTS_INVALID');
  return result;
}
function cookieToken(header) {
  if (typeof header !== 'string' || header.length > 8192) deny();
  const values = header.split(';').map(v => v.trim()).filter(v => v.startsWith(COOKIE + '='));
  const value = values[0]?.slice(COOKIE.length + 1);
  if (values.length !== 1 || !TOKEN.test(value || '') ||
      Buffer.from(value, 'base64url').toString('base64url') !== value) deny();
  return value;
}

async function bounded(work) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(work), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Enrollment dependency timeout')), 30000);
    })]);
  } finally { clearTimeout(timer); }
}

function createProviderBrowserEnrollment({ pool, providerId, appClientId, appUri,
  browserOrigin, returnUri, csrfKey, loadRequirements, registerApp,
  reserveOwnerConsent, journalBoundConsent = false, fixtureOnly = false } = {}) {
  url(providerId, true); url(appClientId); url(appUri); url(browserOrigin, true); url(returnUri);
  if (!pool?.connect || !Buffer.isBuffer(csrfKey) || csrfKey.length !== 32 ||
      typeof loadRequirements !== 'function' || typeof registerApp !== 'function' ||
      typeof journalBoundConsent !== 'boolean' ||
      (journalBoundConsent && typeof reserveOwnerConsent !== 'function') ||
      (!journalBoundConsent && reserveOwnerConsent !== undefined)) deny('ENROLLMENT_CONFIGURATION_INVALID');
  const key = Buffer.from(csrfKey);
  const gate = () => {
    if (fixtureOnly !== true || process.env.NODE_ENV !== 'test' ||
        process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed' ||
        process.env.PAPER_BROWSER_ENROLLMENT_DISPOSABLE !== 'confirmed' ||
        (journalBoundConsent && process.env.PAPER_JOURNAL_BOUND_SAI_DISPOSABLE !== 'confirmed')) {
      deny('ENROLLMENT_NOT_RELEASED');
    }
  };
  const csrf = token => crypto.createHmac('sha256', key)
    .update('paper:enrollment:csrf:v1\0').update(browserOrigin).update('\0').update(token).digest('base64url');
  async function borrow() {
    let expired = false, timer;
    const pending = Promise.resolve().then(() => pool.connect()).then(client => {
      if (expired) { client.release(true); deny(); }
      return client;
    });
    try {
      return await Promise.race([pending, new Promise((_, reject) => {
        timer = setTimeout(() => { expired = true; reject(new Error('Enrollment connection timeout')); }, 5000);
      })]);
    } finally { clearTimeout(timer); }
  }
  async function query(text, values) {
    gate();
    let client, discard = false;
    try {
      client = await borrow();
      // Check and execute on the same SQL connection. This login must have
      // only the enrollment role and no direct account/journal access.
      const role = await client.query({ text: `SELECT
        NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
          AND r.rolcanlogin AND current_user=session_user
          AND pg_catalog.pg_has_role(current_user,'paper_enrollment_runtime','USAGE')
          AND NOT pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='paper_account_candidate'),'MEMBER')
          AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'CREATE')
          AND NOT pg_catalog.has_schema_privilege(current_user,'paper_account_candidate','CREATE')
          AND NOT pg_catalog.has_schema_privilege(current_user,'public','CREATE')
          AND (SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member=r.oid)=1
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles p ON p.oid=m.member
            WHERE p.rolname='paper_enrollment_runtime')
          AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles p ON p.oid=m.roleid
            WHERE m.member=r.oid AND p.rolname='paper_enrollment_runtime'
              AND m.inherit_option AND NOT m.set_option AND NOT m.admin_option
              AND NOT (p.rolcanlogin OR p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls))
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='paper_account_candidate' AND c.relkind IN ('r','p') AND
              (pg_catalog.has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
               OR pg_catalog.has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
          AS allowed FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`, query_timeout: 5000 });
      if (role.rowCount !== 1 || role.rows[0].allowed !== true) deny();
      return await client.query({ text, values, query_timeout: 5000 });
    } catch { discard = true; deny(); }
    finally { if (client) client.release(discard); }
  }
  function browser(header, origin) {
    gate();
    if (origin !== browserOrigin) deny();
    const token = cookieToken(header);
    return { token, tokenHash: hash('session', token) };
  }
  async function read(session) {
    const result = await query('SELECT * FROM paper_account_candidate.read_enrollment($1,$2,$3)',
      [providerId, session.tokenHash, browserOrigin]);
    if (result.rowCount !== 1 || result.rows[0].app_client_id !== appClientId || result.rows[0].app_uri !== appUri ||
        result.rows[0].return_uri !== returnUri) deny();
    return result.rows[0];
  }
  async function currentRequirements() {
    try { return requirements(await bounded(() => loadRequirements(appUri))); }
    catch { deny('ENROLLMENT_REQUIREMENTS_UNAVAILABLE'); }
  }
  async function issue({ operationId, idempotencyHmac, requestHmac, setCookie } = {}) {
    gate();
    if (!UUID.test(operationId || '') || !Buffer.isBuffer(idempotencyHmac) || idempotencyHmac.length !== 32 ||
        !Buffer.isBuffer(requestHmac) || requestHmac.length !== 32 || typeof setCookie !== 'function') deny();
    const needs = await currentRequirements();
    const token = crypto.randomBytes(32).toString('base64url');
    const result = await query('SELECT paper_account_candidate.begin_enrollment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) AS allowed',
      [providerId, appClientId, operationId, idempotencyHmac, requestHmac,
        hash('session', token), hash('csrf', csrf(token)), browserOrigin, appUri, returnUri, JSON.stringify(needs)]);
    if (result.rows[0]?.allowed !== true) deny();
    // No secret in the returned JSON. The HTTP adapter owns this header sink.
    setCookie(`${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600`);
    return { state: 'awaiting_consent', csrfToken: csrf(token), appUri, requirements: needs };
  }
  async function view({ cookie, origin } = {}) {
    const session = browser(cookie, origin);
    const row = await read(session);
    return { state: row.enrollment_state, appUri, requirements: requirements(row.requirements),
      csrfToken: csrf(session.token) };
  }
  async function consent({ cookie, origin, csrfToken, approve, selected } = {}) {
    const session = browser(cookie, origin);
    if (!TOKEN.test(csrfToken || '') || !crypto.timingSafeEqual(Buffer.from(csrfToken), Buffer.from(csrf(session.token))) ||
        typeof approve !== 'boolean') deny();
    const row = await read(session);
    if (row.enrollment_state !== 'awaiting_consent') deny('ENROLLMENT_ALREADY_CLAIMED');
    let selection = null;
    if (approve) {
      const needs = requirements(row.requirements);
      // App changes require a new reviewed transaction, never silently wider consent.
      if (JSON.stringify(await currentRequirements()) !== JSON.stringify(needs)) deny('ENROLLMENT_REQUIREMENTS_CHANGED');
      const values = identifiers(selected);
      if (needs.required.some(v => !values.includes(v)) ||
          values.some(v => !needs.required.includes(v) && !needs.optional.includes(v))) deny('ENROLLMENT_SELECTION_INVALID');
      selection = { acceptedAccessNeeds: values.filter(v => !v.startsWith('apods:')),
        acceptedSpecialRights: values.filter(v => v.startsWith('apods:')) };
    } else if (selected !== undefined && (!Array.isArray(selected) || selected.length)) deny();
    const claim = await query('SELECT paper_account_candidate.claim_enrollment_consent($1,$2,$3,$4,$5,$6) AS allowed',
      [providerId, session.tokenHash, hash('csrf', csrfToken), browserOrigin, approve, selection && JSON.stringify(selection)]);
    if (claim.rows[0]?.allowed !== true) deny('ENROLLMENT_ALREADY_CLAIMED');
    if (!approve) return { state: 'denied' };
    if (journalBoundConsent) {
      // Only a successfully claimed, immutable owner approval may reserve a
      // PENDING canonical grant. The hashed HttpOnly session token and fixed
      // provider/origin are resolved by a *separate restricted PG issuer* to
      // the exact existing signup journal and reservation.
      //
      // If this write is ambiguous, do NOT attempt the native SAI mutation or
      // replay the claim. The journal stays consent_claimed until reconciled.
      try {
        const admitted = await bounded(() => reserveOwnerConsent({
          providerId, origin: browserOrigin, tokenHash: Buffer.from(session.tokenHash)
        }));
        if (admitted !== true) throw Error('Canonical pending consent was not admitted');
      } catch { deny('ENROLLMENT_CONSENT_RECONCILIATION_REQUIRED'); }
    }
    // One call only. A timeout, crash or lost acknowledgment leaves the SQL
    // claim fenced. No replay is allowed to create another native SAI grant.
    let registrationUri;
    try {
      registrationUri = await bounded(() => registerApp({ webId: row.webid, username: row.username, appUri, ...selection }));
      url(registrationUri);
    } catch { deny('ENROLLMENT_CONSENT_RECONCILIATION_REQUIRED'); }
    const recorded = await query('SELECT paper_account_candidate.record_enrollment_consent($1,$2,$3,$4) AS allowed',
      [providerId, session.tokenHash, browserOrigin, registrationUri]);
    if (recorded.rows[0]?.allowed !== true) deny('ENROLLMENT_CONSENT_RECONCILIATION_REQUIRED');
    return { state: 'consent_recorded', completionPending: true };
  }
  return Object.freeze({ issue, view, consent, assertEnabled: gate });
}

module.exports = { createProviderBrowserEnrollment };
