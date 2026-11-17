import crypto from 'node:crypto';
import lifecycle from '../postgres-account-lifecycle.js';
import { assertRestrictedV4BridgeLogin } from './pg-v4-bridge-role-admission.mjs';

const PROVIDER = 'https://paper.example.org';
const ROLE = 'paper_account_signup_reserver';
const POLICY = {
  accounts: {
    SELECT: ['account_id','username_key'], INSERT: ['account_id','provider_id','username_key'], UPDATE: []
  },
  signup_operations: {
    SELECT: ['operation_id','provider_id','account_id','app_client_id','hmac_key_version','idempotency_hmac','request_hmac','state','generation'],
    INSERT: ['operation_id','provider_id','account_id','app_client_id','hmac_key_version','idempotency_hmac','request_hmac'],
    UPDATE: ['state','may_have_side_effects','generation','changed_at']
  }
};
function deny() {
  const error = new Error('Canonical signup admission requires reconciliation');
  error.code = 'CANONICAL_SIGNUP_ADMISSION_UNAVAILABLE';
  error.retryable = false;
  throw error;
}
function gate() {
  if (process.env.NODE_ENV !== 'test' || process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed' ||
      process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE !== 'confirmed' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') deny();
}
async function assertReserver(client) {
  const result = await client.query(`SELECT r.rolcanlogin
    AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
    AND current_user=session_user
    AND (SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member=r.oid)=1
    AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles p ON p.oid=m.roleid
      WHERE m.member=r.oid AND p.rolname=$1 AND m.inherit_option AND NOT m.set_option AND NOT m.admin_option
      AND NOT (p.rolcanlogin OR p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls))
    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles p ON p.oid=m.member WHERE p.rolname=$1)
    AND NOT pg_catalog.has_database_privilege(current_user,pg_catalog.current_database(),'CREATE')
    AND NOT pg_catalog.has_schema_privilege(current_user,'public','CREATE')
    AND NOT pg_catalog.has_schema_privilege(current_user,'paper_account_candidate','CREATE')
    AND NOT pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace
      WHERE nspname='paper_account_candidate'),'MEMBER') AS allowed
    FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`, [ROLE]);
  if (result.rowCount !== 1 || result.rows[0].allowed !== true) deny();
  // Catalog-only bounded scan: permit exactly the columns used by the existing
  // lifecycle reserve/fence methods, including checking column-only drift.
  const columns = await client.query(`SELECT n.nspname,c.relname,a.attname,
    pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'SELECT') AS select_ok,
    pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'INSERT') AS insert_ok,
    pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'UPDATE') AS update_ok,
    pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'REFERENCES') AS references_ok,
    pg_catalog.has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS other_ok
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
    WHERE n.nspname IN ('paper_account_candidate','paper_account_reservation_proof',
      'paper_atproto_authority','paper_atproto_repo_proof') AND c.relkind IN ('r','p')
    ORDER BY c.relname,a.attnum`);
  if (!columns.rows.some(c => c.relname === 'accounts') ||
      !columns.rows.some(c => c.relname === 'signup_operations')) deny();
  const functions = await client.query(`SELECT
    pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE') AS allowed,
    n.nspname,p.proname FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname IN ('paper_account_candidate','paper_account_reservation_proof',
      'paper_atproto_authority','paper_atproto_repo_proof')`);
  if (functions.rows.some(f => f.allowed !== false) || !functions.rows.some(f =>
      f.nspname === 'paper_account_reservation_proof' && f.proname === 'canonical_signup_is_fenced')) deny();
  for (const column of columns.rows) {
    for (const permission of ['SELECT','INSERT','UPDATE']) {
      const expected = column.nspname === 'paper_account_candidate' &&
        (POLICY[column.relname]?.[permission].includes(column.attname) || false);
      if (column[permission.toLowerCase() + '_ok'] !== expected) deny();
    }
    if (column.references_ok !== false || column.other_ok !== false) deny();
  }
}

export function createCanonicalCoordinatorAdmission({ reserverPool, binderPool, appClientId, hmacKey, hmacKeyVersion = 1 } = {}) {
  gate();
  let app;
  try { app = new URL(appClientId); } catch { deny(); }
  if (app.protocol !== 'https:' || app.href !== appClientId || app.username || app.password || app.hash ||
      appClientId.length > 256 || !reserverPool?.connect || !binderPool?.connect ||
      !Buffer.isBuffer(hmacKey) || hmacKey.length !== 32 ||
      !Number.isSafeInteger(hmacKeyVersion) || hmacKeyVersion < 1 || hmacKeyVersion > 255) deny();
  const secret = Buffer.from(hmacKey);
  const appScope = crypto.createHash('sha256').update('activitypods:approved-app:v1\0').update(appClientId).digest('hex');
  const canonical = lifecycle.createCandidate({ fixtureOnly: true, pool: {
    async connect() {
      const client = await reserverPool.connect();
      try { await assertReserver(client); return client; }
      catch { client.release(true); deny(); }
    }
  } });
  const digest = (purpose, value) => crypto.createHmac('sha256', secret).update(purpose + '\0').update(value).digest();
  async function admit({ appScope: requestedApp, username, idempotencyKey, requestFingerprint, reservationId } = {}) {
    gate();
    if (requestedApp !== appScope || !/^[a-z][a-z0-9_-]{1,31}$/u.test(username || '') ||
        !/^[A-Za-z0-9._:-]{8,128}$/u.test(idempotencyKey || '') || !/^[a-f0-9]{64}$/u.test(requestFingerprint || '') ||
        !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(reservationId || '')) deny();
    const scope = { providerId: PROVIDER, appClientId, hmacKeyVersion,
      idempotencyHmac: digest('account-signup-idempotency-v1', idempotencyKey),
      requestHmac: digest('account-signup-request-v1', requestFingerprint),
      accountId: crypto.randomUUID(), operationId: crypto.randomUUID(), username };
    try {
      const reserved = await canonical.reserveSignup(scope);
      if (reserved.replay !== false || reserved.state !== 'reserved') deny();
      const client = await binderPool.connect();
      let discard = false;
      try {
        await assertRestrictedV4BridgeLogin(client, 'binder');
        const keyHash = crypto.createHash('sha256').update('activitypods:account-reservation:key:v1\0')
          .update(PROVIDER + '/provider').update('\0').update(appScope).update('\0').update(idempotencyKey).digest();
        const bound = await client.query('SELECT paper_account_reservation_proof.bind_v4_signup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) AS bound',
          [reservationId, PROVIDER + '/provider', appScope, keyHash, Buffer.from(requestFingerprint, 'hex'),
            PROVIDER, appClientId, scope.accountId, scope.operationId, hmacKeyVersion, scope.idempotencyHmac, scope.requestHmac]);
        if (bound.rows[0]?.bound !== true) deny();
      } catch (error) { discard = true; throw error; }
      finally { client.release(discard); }
      const fenced = await canonical.markSignupMayHaveSideEffects(scope);
      if (fenced.replay !== false || fenced.state !== 'reconciliation_required') deny();
      return Object.freeze({ accountId: scope.accountId, operationId: scope.operationId });
    } catch { deny(); }
  }
  return Object.freeze({ admit });
}
