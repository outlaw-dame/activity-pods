'use strict';

/**
 * NON-ACTIVATED PostgreSQL operational-account lifecycle candidate.
 *
 * Not registered as a Moleculer service. The reviewed integration must
 * supply a single bounded pg.Pool per process and enforce the approved-app
 * authorization and email verification BEFORE calling reserve().
 *
 * External side effects (Jena/SAI, WebID, AP actor, PLC, PDS) must never be
 * retried automatically on a lost lease or an unknown commit outcome.
 * Each operation is externally assigned a stable UUID and a fresh lease UUID.
 * A lease is NOT authority to overwrite a completed identity.
 */
const { MoleculerError } = require('moleculer').Errors;
const { isCanonicalHttpsWebId } = require('../utils/unified-identity-policy');
const TABLE = 'paper_account_candidate.operations';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DID = /^did:plc:[a-z2-7]{24}$/;
const CID = /^bafy[a-z2-7]{24,}$/;
const LEASE_SECONDS = 300;
function fail(type, status = 409) {
  throw new MoleculerError(type, status, type);
}
function requiredString(value, max = 2048) {
  return typeof value === 'string' && value.length >= 1 &&
    value.length <= max && !/[\u0000-\u001f\u007f]/u.test(value);
}
function digest(value) {
  return Buffer.isBuffer(value) && value.length === 32;
}
function baseInput(input) {
  if (!input || !UUID.test(input.operationId || '') ||
      !UUID.test(input.leaseToken || '')) fail('ACCOUNT_LEDGER_INVALID_OPERATION', 400);
}
function validateReserve(input) {
  baseInput(input);
  if (!requiredString(input.providerId, 255) ||
      !requiredString(input.appClientId) ||
      !requiredString(input.usernameKey, 128) ||
      input.usernameKey !== input.usernameKey.toLowerCase() ||
      !digest(input.idempotencyDigest) || !digest(input.requestDigest) ||
      (input.verifiedEmailHmac != null && !digest(input.verifiedEmailHmac))) {
    fail('ACCOUNT_LEDGER_INVALID_RESERVATION', 400);
  }
}
function publicResult(row) {
  return {
    operationId: row.operation_id,
    state: row.state,
    webId: row.canonical_webid || null,
    did: row.atproto_did || null,
    version: Number(row.version)
  };
}
async function transaction(pool, fn) {
  const client = await pool.connect();
  let open = false;
  let committing = false;
  let discard = false;
  try {
    await client.query('BEGIN');
    open = true;
    await client.query("SET LOCAL lock_timeout = '2500ms'");
    await client.query("SET LOCAL statement_timeout = '8000ms'");
    await client.query("SET LOCAL idle_in_transaction_session_timeout = '5000ms'");
    const value = await fn(client);
    committing = true;
    await client.query('COMMIT');
    open = false;
    return value;
  } catch (err) {
    if (committing) {
      // The application cannot know whether a COMMIT was durable if its
      // response is lost. Do not emit a retryable success/failure guess.
      discard = true;
      fail('ACCOUNT_LEDGER_COMMIT_OUTCOME_UNKNOWN', 503);
    }
    if (open) {
      try { await client.query('ROLLBACK'); }
      catch (_rollbackError) { discard = true; }
    }
    if (err?.code === '23505') fail('ACCOUNT_LEDGER_IDENTITY_RESERVED', 409);
    if (err?.code === '55P03' || err?.code === '57014') fail('ACCOUNT_LEDGER_BUSY', 503);
    throw err;
  } finally {
    client.release(discard);
  }
}

function createAccountPostgresLifecycleCandidate({ pool } = {}) {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError('ACCOUNT_LEDGER_PG_POOL_REQUIRED');
  }
  return Object.freeze({
    // Exactly one reservation is allowed for a provider+username and
    // provider+app+idempotency HMAC. Concurrent INSERTs serialize on the
    // database unique constraints, not on a local JavaScript Map.
    async reserve(input) {
      validateReserve(input);
      return transaction(pool, async client => {
        const inserted = await client.query(
          `INSERT INTO ${TABLE} (
            operation_id, provider_id, app_client_id, idempotency_digest,
            request_digest, username_key, verified_email_hmac,
            lease_token, lease_expires_at
          ) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8::uuid,
            clock_timestamp() + ($9::integer * interval '1 second'))
          ON CONFLICT DO NOTHING RETURNING operation_id`,
          [input.operationId, input.providerId, input.appClientId,
            input.idempotencyDigest, input.requestDigest, input.usernameKey,
            input.verifiedEmailHmac || null, input.leaseToken, LEASE_SECONDS]
        );
        // Always look up by the authorized idempotency tuple. A different
        // operation holding this username/email is a hard conflict.
        const found = await client.query(
          `SELECT operation_id, request_digest, username_key, state,
                  canonical_webid, atproto_did, version, lease_expires_at
           FROM ${TABLE}
           WHERE provider_id=$1 AND app_client_id=$2 AND idempotency_digest=$3
           FOR UPDATE`,
          [input.providerId, input.appClientId, input.idempotencyDigest]
        );
        if (found.rowCount !== 1) fail('ACCOUNT_LEDGER_IDENTITY_RESERVED');
        const row = found.rows[0];
        if (!Buffer.isBuffer(row.request_digest) ||
            !row.request_digest.equals(input.requestDigest) ||
            row.username_key !== input.usernameKey) {
          fail('ACCOUNT_LEDGER_IDEMPOTENCY_MISMATCH');
        }
        if (inserted.rowCount !== 1) {
          if (row.state === 'completed') return { ...publicResult(row), replay: true };
          // Expired leases are NOT a reason to repeat irreversible identity
          // creation; reconciliation needs to establish what actually exists.
          fail('ACCOUNT_LEDGER_RECONCILIATION_REQUIRED', 409);
        }
        return { ...publicResult(row), replay: false };
      });
    },

    async markAccountCreated(input) {
      baseInput(input);
      if (!isCanonicalHttpsWebId(input.webId)) {
        fail('ACCOUNT_LEDGER_INVALID_WEBID', 400);
      }
      return transaction(pool, async client => {
        const updated = await client.query(
          `UPDATE ${TABLE}
           SET state='account_created', canonical_webid=$3,
               activitypub_actor_id=$3, version=version+1,
               updated_at=clock_timestamp()
           WHERE operation_id=$1::uuid AND lease_token=$2::uuid
             AND state='reserved' AND lease_expires_at > clock_timestamp()
           RETURNING operation_id, state, canonical_webid, atproto_did, version`,
          [input.operationId, input.leaseToken, input.webId]
        );
        if (updated.rowCount !== 1) fail('ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
        return publicResult(updated.rows[0]);
      });
    },

    async markIdentitiesReady(input) {
      baseInput(input);
      if (!DID.test(input.did || '') || !CID.test(input.repoRootCid || '') ||
          !requiredString(input.repoRev, 64) || !digest(input.signedRepoProofDigest)) {
        fail('ACCOUNT_LEDGER_UNVERIFIED_IDENTITY', 400);
      }
      return transaction(pool, async client => {
        const updated = await client.query(
          `UPDATE ${TABLE}
           SET state='identities_ready', atproto_did=$3,
               pds_repo_root_cid=$4, pds_repo_rev=$5,
               signed_repo_proof_digest=$6, version=version+1,
               updated_at=clock_timestamp()
           WHERE operation_id=$1::uuid AND lease_token=$2::uuid
             AND state='account_created' AND lease_expires_at > clock_timestamp()
           RETURNING operation_id, state, canonical_webid, atproto_did, version`,
          [input.operationId, input.leaseToken, input.did,
            input.repoRootCid, input.repoRev, input.signedRepoProofDigest]
        );
        if (updated.rowCount !== 1) fail('ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
        return publicResult(updated.rows[0]);
      });
    },

    async complete(input) {
      baseInput(input);
      return transaction(pool, async client => {
        const updated = await client.query(
          `UPDATE ${TABLE} SET state='completed', version=version+1,
                  updated_at=clock_timestamp()
           WHERE operation_id=$1::uuid AND lease_token=$2::uuid
             AND state='identities_ready' AND lease_expires_at > clock_timestamp()
           RETURNING operation_id, state, canonical_webid, atproto_did, version`,
          [input.operationId, input.leaseToken]
        );
        if (updated.rowCount !== 1) fail('ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
        return publicResult(updated.rows[0]);
      });
    },

    async requireReconciliation(input) {
      baseInput(input);
      return transaction(pool, async client => {
        const updated = await client.query(
          `UPDATE ${TABLE} SET state='needs_reconciliation', version=version+1,
                  updated_at=clock_timestamp()
           WHERE operation_id=$1::uuid AND lease_token=$2::uuid
             AND state <> 'completed'
           RETURNING operation_id, state, canonical_webid, atproto_did, version`,
          [input.operationId, input.leaseToken]
        );
        if (updated.rowCount !== 1) fail('ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
        return publicResult(updated.rows[0]);
      });
    }
  });
}
module.exports = { createAccountPostgresLifecycleCandidate };
