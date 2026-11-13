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
 * The injected digests MUST be provider-keyed, domain-separated HMAC-SHA-256
 * with a protected key and an explicit rotation protocol before activation;
 * raw SHA-256 of credentials, emails or predictable client keys is unsafe.
 * A lease is NOT authority to overwrite a completed identity.
 */
const crypto = require('node:crypto');
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

function createAccountPostgresLifecycleCandidate({
  pool, resolveTrustedKeyDid, verifyGenesis, verifyPds
} = {}) {
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

    /**
     * Store one immutable signed genesis archive after resolving the actual
     * did:plc document and verifying every CAR block + commit signature.
     * Never accept signing authority supplied in a client request.
     *
     * Verification is kept OUTSIDE the SQL transaction to avoid holding a
     * row lock while fetching a DID or parsing CAR bytes.
     */
    async stageSignedGenesis(input) {
      baseInput(input);
      const genesis = input.genesis;
      if (!DID.test(genesis?.did || '') || !CID.test(genesis?.rootCid || '') ||
          !requiredString(genesis?.rev, 64) ||
          !Buffer.isBuffer(genesis?.car) ||
          genesis.car.length < 32 || genesis.car.length > 256 * 1024) {
        fail('ACCOUNT_LEDGER_INVALID_GENESIS', 400);
      }
      if (typeof resolveTrustedKeyDid !== 'function' ||
          typeof verifyGenesis !== 'function') {
        fail('ACCOUNT_LEDGER_GENESIS_VERIFIER_REQUIRED', 503);
      }
      const trustedKeyDid = await resolveTrustedKeyDid(genesis.did);
      if (typeof trustedKeyDid !== 'string' ||
          !/^did:key:z[1-9A-HJ-NP-Za-km-z]{30,160}$/.test(trustedKeyDid)) {
        fail('ACCOUNT_LEDGER_UNVERIFIED_SIGNING_AUTHORITY', 503);
      }
      let verified;
      try {
        verified = await verifyGenesis({
          did: genesis.did, rootCid: genesis.rootCid,
          rev: genesis.rev, car: genesis.car, trustedKeyDid
        });
      } catch (_error) {
        fail('ACCOUNT_LEDGER_INVALID_SIGNED_GENESIS', 503);
      }
      if (verified?.did !== genesis.did ||
          verified.rootCid !== genesis.rootCid ||
          verified.rev !== genesis.rev ||
          verified.keyDid !== trustedKeyDid ||
          !Buffer.isBuffer(verified.car) ||
          !verified.car.equals(genesis.car)) {
        fail('ACCOUNT_LEDGER_INVALID_SIGNED_GENESIS', 503);
      }
      const digestBytes = crypto.createHash('sha256').update(genesis.car).digest();
      return transaction(pool, async client => {
        const owner = await client.query(
          `SELECT state, lease_expires_at FROM ${TABLE}
           WHERE operation_id=$1::uuid AND lease_token=$2::uuid
             AND state='account_created'
             AND lease_expires_at > clock_timestamp()
           FOR UPDATE`, [input.operationId, input.leaseToken]
        );
        if (owner.rowCount !== 1) fail('ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
        const inserted = await client.query(
          `INSERT INTO paper_account_candidate.signed_genesis
           (operation_id, did, root_cid, repo_rev, signing_key_did,
            car_bytes, car_sha256)
           VALUES ($1::uuid,$2,$3,$4,$5,$6,$7)
           ON CONFLICT DO NOTHING RETURNING operation_id`,
          [input.operationId, genesis.did, genesis.rootCid, genesis.rev,
            trustedKeyDid, genesis.car, digestBytes]
        );
        if (inserted.rowCount !== 1) {
          const existing = await client.query(
            `SELECT did,root_cid,repo_rev,signing_key_did,car_sha256
             FROM paper_account_candidate.signed_genesis
             WHERE operation_id=$1::uuid`, [input.operationId]
          );
          if (existing.rowCount !== 1 ||
              existing.rows[0].did !== genesis.did ||
              existing.rows[0].root_cid !== genesis.rootCid ||
              existing.rows[0].repo_rev !== genesis.rev ||
              existing.rows[0].signing_key_did !== trustedKeyDid ||
              !existing.rows[0].car_sha256.equals(digestBytes)) {
            fail('ACCOUNT_LEDGER_GENESIS_CONFLICT');
          }
        }
        return Object.freeze({
          operationId: input.operationId, did: genesis.did,
          rootCid: genesis.rootCid, rev: genesis.rev,
          staged: true, replay: inserted.rowCount !== 1
        });
      });
    },

    /**
     * Advance only AFTER verifying the live PDS over XRPC. The immutable
     * signed-genesis row alone does not establish a working PDS.
     * No unsigned client-supplied digest is accepted as verification.
     */
    async markIdentitiesReady(input) {
      baseInput(input);
      if (!DID.test(input.did || '') || !CID.test(input.repoRootCid || '') ||
          !requiredString(input.repoRev, 64) ||
          !requiredString(input.handle, 253) ||
          !requiredString(input.expectedPdsUrl, 2048)) {
        fail('ACCOUNT_LEDGER_UNVERIFIED_IDENTITY', 400);
      }
      if (typeof verifyPds !== 'function') {
        fail('ACCOUNT_LEDGER_LIVE_PDS_VERIFIER_REQUIRED', 503);
      }
      // One indexed row read (no scan); remote verification happens without
      // an open DB transaction, which keeps pool/lock cost bounded.
      const evidence = await pool.query(
        `SELECT did, root_cid, repo_rev, signing_key_did, car_sha256
         FROM paper_account_candidate.signed_genesis
         WHERE operation_id=$1::uuid`, [input.operationId]
      );
      if (evidence.rowCount !== 1) fail('ACCOUNT_LEDGER_GENESIS_NOT_STAGED', 503);
      const staged = evidence.rows[0];
      if (staged.did !== input.did || staged.root_cid !== input.repoRootCid ||
          staged.repo_rev !== input.repoRev) {
        fail('ACCOUNT_LEDGER_GENESIS_CONFLICT', 409);
      }
      let remote;
      try {
        remote = await verifyPds({
          did:input.did,handle:input.handle,
          expectedPdsUrl:input.expectedPdsUrl,
          expectedRootCid:input.repoRootCid, expectedRev:input.repoRev
        });
      } catch (_) {
        fail('ACCOUNT_LEDGER_PDS_NOT_VERIFIED', 503);
      }
      if (remote?.did !== input.did ||
          remote.rootCid !== input.repoRootCid ||
          remote.rev !== input.repoRev ||
          remote.keyDid !== staged.signing_key_did ||
          remote.pdsUrl !== input.expectedPdsUrl ||
          !Buffer.isBuffer(remote.carSha256) ||
          !staged.car_sha256.equals(remote.carSha256)) {
        fail('ACCOUNT_LEDGER_PDS_NOT_VERIFIED', 503);
      }
      // Store a compact replay-safe proof fingerprint. The canonical live
      // proof remains the PDS's signed CAR + PLC directory document.
      const liveProof = crypto.createHash('sha256')
        .update(['pds-sync-v1',input.did,input.handle,
          input.expectedPdsUrl,input.repoRootCid,input.repoRev,
          staged.car_sha256.toString('hex')].join('\0'))
        .digest();
      return transaction(pool, async client => {
        const updated = await client.query(
          `UPDATE ${TABLE} AS op
           SET state='identities_ready',
               atproto_did=g.did, pds_repo_root_cid=g.root_cid,
               pds_repo_rev=g.repo_rev,
               signed_repo_proof_digest=g.car_sha256,
               pds_sync_proof_digest=$3,
               version=op.version+1, updated_at=clock_timestamp()
           FROM paper_account_candidate.signed_genesis AS g
           WHERE op.operation_id=$1::uuid AND op.lease_token=$2::uuid
             AND op.state='account_created'
             AND op.lease_expires_at > clock_timestamp()
             AND g.operation_id=op.operation_id
             AND g.did=$4 AND g.root_cid=$5 AND g.repo_rev=$6
             AND g.signing_key_did=$7 AND g.car_sha256=$8
           RETURNING op.operation_id,op.state,op.canonical_webid,op.atproto_did,op.version`,
          [input.operationId,input.leaseToken,liveProof,
            input.did,input.repoRootCid,input.repoRev,
            staged.signing_key_did,staged.car_sha256]
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
