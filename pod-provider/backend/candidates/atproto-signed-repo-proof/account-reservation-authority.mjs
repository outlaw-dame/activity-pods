/**
 * TEST-ONLY PostgreSQL lifecycle reservation proof for ActivityPods NEW accounts.
 * The issuer and the provider are NOT allowed to infer identity from a client
 * claim. ActivityPods remains the only WebID/AP/DID/PDS identity owner.
 *
 * No automatic lease takeover, failed-state reuse, or response/token replay:
 * a network timeout can follow an irreversible WebID/DID operation.
 */
import crypto from 'node:crypto';

const PROVIDER = 'https://paper.example.org/provider';
const WEBID_ROOT = 'https://paper.example.org/users/';
const FP = /^[a-f0-9]{64}$/u;
const USERNAME = /^[a-z][a-z0-9_-]{1,31}$/u;
const KEY = /^[a-zA-Z0-9._:-]{8,128}$/u;
const APP = /^[a-zA-Z0-9._:-]{1,128}$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/iu;

function assertDisposable() {
  if (process.env.NODE_ENV !== 'test' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
      process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE !== 'confirmed') {
    throw Error('PostgreSQL pre-account reservation proof is not released');
  }
}
function deny() {
  const error = Error('Invalid PostgreSQL account reservation input');
  error.code = 'ACCOUNT_RESERVATION_INPUT_INVALID';
  throw error;
}
function validateInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      !APP.test(input.appClientId) || !USERNAME.test(input.username) ||
      !KEY.test(input.idempotencyKey) || !FP.test(input.requestFingerprint) ||
      !Number.isInteger(input.dailyLimit) || input.dailyLimit < 1 ||
      input.dailyLimit > 100000) deny();
}
function hashKey(app, key) {
  return crypto.createHash('sha256')
    .update('activitypods:account-reservation:key:v1\0', 'utf8')
    .update(PROVIDER, 'utf8').update('\0', 'utf8')
    .update(app, 'utf8').update('\0', 'utf8')
    .update(key, 'utf8').digest();
}
function assertFence(value) {
  if (!value || typeof value !== 'object' ||
      !APP.test(value.appClientId) || !KEY.test(value.idempotencyKey) ||
      !UUID.test(value.reservationId) || !UUID.test(value.fenceToken)) deny();
}
function assertPool(pool) {
  if (!pool || typeof pool.query !== 'function') deny();
}
export function makeAccountReservationAuthority({workerPool, issuerPool} = {}) {
  assertDisposable();
  assertPool(workerPool);
  const api = {
    async reserve(input) {
      assertDisposable();
      validateInput(input);
      const result = await workerPool.query(
        'SELECT outcome,reservation_id,fence_token,lease_expires_at ' +
        'FROM paper_account_reservation_proof.reserve($1,$2,$3,$4,$5,$6,$7,$8)',
        [PROVIDER, input.appClientId, hashKey(input.appClientId, input.idempotencyKey),
          Buffer.from(input.requestFingerprint, 'hex'), input.username,
          WEBID_ROOT + input.username, input.dailyLimit, 120]
      );
      if (result.rowCount !== 1 ||
          !['reserved', 'already_reserved', 'completed', 'idempotency_conflict',
            'quota_exceeded', 'username_taken'].includes(result.rows[0]?.outcome)) {
        throw Error('Unexpected account reservation authority response');
      }
      const row = result.rows[0];
      if (row.outcome !== 'reserved' && row.fence_token !== null) {
        throw Error('PostgreSQL replay unexpectedly returned a fencing credential');
      }
      return Object.freeze({
        outcome: row.outcome,
        reservationId: row.reservation_id || null,
        fenceToken: row.outcome === 'reserved' ? row.fence_token : null,
        leaseExpiresAt: row.lease_expires_at || null
      });
    },
    async startSideEffects(fence) {
      assertDisposable();
      assertFence(fence);
      const result = await workerPool.query(
        'SELECT paper_account_reservation_proof.start_side_effects($1,$2,$3,$4,$5) AS started',
        [PROVIDER, fence.appClientId, hashKey(fence.appClientId, fence.idempotencyKey),
          fence.reservationId, fence.fenceToken]
      );
      return result.rowCount === 1 && result.rows[0]?.started === true;
    },
    async complete(fence, proof) {
      assertDisposable();
      assertFence(fence);
      if (!proof || typeof proof !== 'object' ||
          proof.webId !== WEBID_ROOT + proof.username ||
          !USERNAME.test(proof.username || '') ||
          typeof proof.activityPubActorId !== 'string' ||
          typeof proof.atprotoDid !== 'string' ||
          typeof proof.atprotoPdsUrl !== 'string' ||
          !FP.test(proof.evidenceSha256 || '')) deny();
      // This candidate proves monotonic SQL fencing, not PDS cryptographic
      // attestation. A production caller MUST verify the evidence independently.
      const result = await workerPool.query(
        'SELECT paper_account_reservation_proof.complete($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS completed',
        [PROVIDER, fence.appClientId, hashKey(fence.appClientId, fence.idempotencyKey),
          fence.reservationId, fence.fenceToken, proof.webId,
          proof.activityPubActorId, proof.atprotoDid, proof.atprotoPdsUrl,
          Buffer.from(proof.evidenceSha256, 'hex')]
      );
      return result.rowCount === 1 && result.rows[0]?.completed === true;
    },
    async assertDatasetBinding(fence, dataset, expectedWebId) {
      assertDisposable();
      assertFence(fence);
      if (!issuerPool) throw Error('Separate restricted issuer PostgreSQL connection is required');
      assertPool(issuerPool);
      if (!USERNAME.test(dataset) || expectedWebId !== WEBID_ROOT + dataset) deny();
      const result = await issuerPool.query(
        'SELECT paper_account_reservation_proof.dataset_binding_is_live($1,$2,$3,$4,$5,$6) AS admitted',
        [PROVIDER, fence.appClientId, fence.reservationId,
          fence.fenceToken, dataset, expectedWebId]
      );
      return result.rowCount === 1 && result.rows[0]?.admitted === true;
    }
  };
  return Object.freeze(api);
}
export async function assertRestrictedAccountProofLogin(pool, kind) {
  assertDisposable();
  assertPool(pool);
  if (!['worker', 'issuer'].includes(kind)) deny();
  const expectedRole = kind === 'worker' ?
    'paper_account_proof_worker' : 'paper_account_proof_issuer';
  const result = await pool.query(`
    SELECT current_user AS role_name,
      current_setting('server_version_num')::int AS version,
      (SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=current_user) AS can_login,
      (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
       FROM pg_catalog.pg_roles WHERE rolname = current_user) AS privileged,
      pg_has_role(current_user, $1, 'USAGE') AS expected_role,
      pg_has_role(current_user, $1, 'SET') AS role_switch,
      pg_has_role(current_user, (SELECT nspowner FROM pg_catalog.pg_namespace
        WHERE nspname='paper_account_reservation_proof'), 'MEMBER') AS owner_member,
      (SELECT count(*)::int FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles member_role ON member_role.oid=am.member
       JOIN pg_catalog.pg_roles target_role ON target_role.oid=am.roleid
       WHERE member_role.rolname=current_user AND target_role.rolname<>$1) AS extra_roles,
      (SELECT count(*)::int FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles member_role ON member_role.oid=am.member
       JOIN pg_catalog.pg_roles target_role ON target_role.oid=am.roleid
       WHERE member_role.rolname=current_user AND target_role.rolname=$1
         AND (am.set_option OR am.admin_option OR NOT am.inherit_option)) AS bad_role_options,
      (SELECT count(*)::int FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles member_role ON member_role.oid=am.member
       WHERE member_role.rolname=$1) AS inherited_extra_roles,
      has_schema_privilege(current_user, 'paper_account_reservation_proof', 'CREATE') AS schema_create,
      has_table_privilege(current_user, 'paper_account_reservation_proof.reservations',
        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS ledger_dml,
      has_table_privilege(current_user, 'paper_account_reservation_proof.daily_usage',
        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS quota_dml,
      pg_has_role(current_user, 'pg_read_all_data', 'member') AS read_all,
      pg_has_role(current_user, 'pg_write_all_data', 'member') AS write_all,
      pg_has_role(current_user, 'pg_monitor', 'member') AS monitor,
      has_function_privilege(current_user,
        'paper_account_reservation_proof.reserve(text,text,bytea,bytea,text,text,integer,integer)',
        'EXECUTE') AS can_reserve,
      has_function_privilege(current_user,
        'paper_account_reservation_proof.start_side_effects(text,text,bytea,uuid,uuid)',
        'EXECUTE') AS can_start,
      has_function_privilege(current_user,
        'paper_account_reservation_proof.complete(text,text,bytea,uuid,uuid,text,text,text,text,bytea)',
        'EXECUTE') AS can_complete,
      has_function_privilege(current_user,
        'paper_account_reservation_proof.dataset_binding_is_live(text,text,uuid,uuid,text,text)',
        'EXECUTE') AS can_issue`,[expectedRole]);
  const row = result.rows[0];
  const safe = result.rowCount === 1 && row.version >= 180000 &&
    row.can_login === true && row.privileged === false &&
    row.expected_role === true && row.role_switch === false &&
    row.owner_member === false && row.extra_roles === 0 &&
    row.bad_role_options === 0 && row.inherited_extra_roles === 0 &&
    row.schema_create === false && row.ledger_dml === false &&
    row.quota_dml === false && row.read_all === false &&
    row.write_all === false && row.monitor === false &&
    row.can_reserve === (kind === 'worker') &&
    row.can_start === (kind === 'worker') &&
    row.can_complete === (kind === 'worker') &&
    row.can_issue === (kind === 'issuer');
  if (!safe) {
    const error = Error('Restricted pre-account PostgreSQL privileges are unsafe');
    error.code = 'ACCOUNT_RESERVATION_SQL_PRIVILEGES_UNSAFE';
    throw error;
  }
  return true;
}
