/**
 * Isolated PostgreSQL 18-backed proof of a single authoritative genesis
 * repository transaction. Not registered in Moleculer or available to signup.
 *
 * Transaction invariant:
 * repo head + both content-addressed blocks + native-event outbox row +
 * the RDF projection recovery-intent row either all commit, or none commit. A durable native outbox entry stays
 * pending until a separately verified publisher/consumer exists.
 *
 * The trusted signer remains outside PostgreSQL; no keys are stored here.
 */
import { Buffer } from 'node:buffer';
import {
  assertManagedDid, makeTid, buildSignedEmptyRepo,
  carFromBlocks, verifySignedEmptyRepo
} from './genesis.mjs';

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function assertAccountId(accountId) {
  if (typeof accountId !== 'string' || accountId.length > 2048) {
    fail('ATPROTO_ACCOUNT_INVALID', 'Invalid canonical WebID account');
  }
  let url;
  try {
    url = new URL(accountId);
  } catch {
    fail('ATPROTO_ACCOUNT_INVALID', 'Account is not a valid HTTPS WebID');
  }
  if (url.protocol !== 'https:' || !url.hostname || url.href !== accountId ||
      url.username || url.password || url.hash || url.search) {
    fail('ATPROTO_ACCOUNT_INVALID', 'Canonical account must be a normalized HTTPS WebID');
  }
  return accountId;
}

function requirePool(pool) {
  if (!pool || typeof pool.connect !== 'function' || typeof pool.query !== 'function') {
    fail('ATPROTO_PROOF_CONFIGURATION_INVALID', 'Explicit PG pool is required');
  }
}

/**
 * The proof writer only runs with explicit fixtureOnly=true AND the
 * disposable-test environment marker, and never with NODE_ENV=production.
 * No accidental provider authority cutover is permitted by importing it.
 */
export function createSignedRepoProofStore({ pool, fixtureOnly = false } = {}) {
  requirePool(pool);
  if (fixtureOnly !== true || process.env.NODE_ENV === 'production' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') {
    return Object.freeze({
      bootstrap: async () => fail('ATPROTO_REPO_PROOF_NOT_RELEASED', 'No production repository writer is enabled'),
      verify: async () => fail('ATPROTO_REPO_PROOF_NOT_RELEASED', 'No production repository reader is enabled')
    });
  }

  async function verify({ accountId, did, publicKeyPem }) {
    assertAccountId(accountId);
    assertManagedDid(did);
    // One PostgreSQL statement supplies the repo head, both CID-addressed
    // blocks and its native-event/poison state from ONE MVCC snapshot.
    // Separate SELECTs could combine a superseded head with a newer outbox
    // or vice versa while a concurrent signed-record transaction commits.
    // Do not hold a pooled connection or database lock during CAR validation.
    const snapshot = await pool.query(
      `SELECT r.rev, r.head_cid, r.root_cid,
              commit_block.block AS commit_bytes,
              mst_block.block AS root_bytes,
              event.id AS outbox_id, event.kind AS outbox_kind,
              event.status AS outbox_status, event.rev AS outbox_rev,
              event.blocked_at AS outbox_blocked_at,
              EXISTS (
                SELECT 1 FROM paper_atproto_repo_proof.native_event_outbox blocked
                WHERE blocked.did = r.did AND blocked.status = 'pending'
                  AND blocked.blocked_at IS NOT NULL
              ) AS blocked_history
         FROM paper_atproto_repo_proof.repos r
         LEFT JOIN paper_atproto_repo_proof.blocks commit_block
           ON commit_block.did = r.did AND commit_block.cid = r.head_cid
         LEFT JOIN paper_atproto_repo_proof.blocks mst_block
           ON mst_block.did = r.did AND mst_block.cid = r.root_cid
         LEFT JOIN paper_atproto_repo_proof.native_event_outbox event
           ON event.did = r.did AND event.commit_cid = r.head_cid
        WHERE r.account_id = $1 AND r.did = $2`,
      [accountId, did]
    );
    if (snapshot.rowCount !== 1) {
      fail('ATPROTO_REPO_NOT_FOUND', 'No authoritative repository is stored for this account');
    }
    const row = snapshot.rows[0];
    if (!Buffer.isBuffer(row.commit_bytes) || !Buffer.isBuffer(row.root_bytes)) {
      fail('ATPROTO_REPO_BLOCKS_MISSING', 'Repository commit or MST block is missing');
    }
    const carBytes = await carFromBlocks({
      commitCid: row.head_cid,
      rootCid: row.root_cid,
      commitBytes: row.commit_bytes,
      rootBytes: row.root_bytes
    });
    const verified = await verifySignedEmptyRepo({ did, carBytes, publicKeyPem });
    if (verified.commitCid !== row.head_cid || verified.rootCid !== row.root_cid ||
        verified.rev !== row.rev) {
      fail('ATPROTO_REPO_HEAD_MISMATCH', 'Stored head and independently verified CAR disagree');
    }
    if (row.outbox_id == null || row.outbox_kind !== 'at.commit.v1' ||
        row.outbox_rev !== row.rev) {
      fail('ATPROTO_REPO_OUTBOX_MISSING', 'Native event outbox must be committed with the repository');
    }
    if (row.outbox_blocked_at !== null ||
        row.blocked_history === true) {
      fail('ATPROTO_REPO_OUTBOX_BLOCKED', 'Native event needs explicit provider recovery');
    }
    return Object.freeze({
      accountId, did,
      rev: verified.rev, rootCid: verified.rootCid,
      commitCid: verified.commitCid,
      carBytes,
      outboxStatus: row.outbox_status,
      verified: true
    });
  }

  async function bootstrap({
    accountId, did, signer, publicKeyPem,
    rev = makeTid(), testFailAfterBlocks = false, testFailAfterOutbox = false
  }) {
    assertAccountId(accountId);
    assertManagedDid(did);
    if ((testFailAfterBlocks !== false || testFailAfterOutbox !== false) &&
        process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') {
      fail('ATPROTO_TEST_FAILPOINT_FORBIDDEN', 'Failure injection is limited to disposable proof tests');
    }

    // Sign and verify outside the DB transaction so a slow signer does not
    // hold database locks or a connection. Unique identity + advisory lock
    // makes races single-writer once persistence begins.
    const signed = await buildSignedEmptyRepo({ did, rev, signer, publicKeyPem });
    const client = await pool.connect();
    let transactionOpen = false;
    let commitAttempted = false;
    let discardConnection = false;
    let replay = false;
    try {
      await client.query('BEGIN');
      transactionOpen = true;
      await client.query("SET LOCAL lock_timeout = '5s'");
      await client.query("SET LOCAL statement_timeout = '10s'");
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))',
        [accountId]
      );
      const existing = await client.query(
        'SELECT did FROM paper_atproto_repo_proof.repos WHERE account_id = $1 FOR UPDATE',
        [accountId]
      );
      if (existing.rowCount > 0) {
        if (existing.rows[0].did !== did) {
          fail('ATPROTO_ACCOUNT_DID_CONFLICT', 'Account already owns a different DID');
        }
        replay = true;
      } else {
        await client.query(
          'INSERT INTO paper_atproto_repo_proof.repos (account_id,did,rev,head_cid,root_cid) VALUES ($1,$2,$3,$4,$5)',
          [accountId, did, signed.rev, signed.commitCid, signed.rootCid]
        );
        await client.query(
          'INSERT INTO paper_atproto_repo_proof.blocks (did,cid,block) VALUES ($1,$2,$3),($1,$4,$5)',
          [did, signed.commitCid, signed.commitBytes, signed.rootCid, signed.rootBytes]
        );
        if (testFailAfterBlocks) fail('ATPROTO_TEST_INJECTED_FAILURE', 'Simulated crash before outbox persistence');
        await client.query(
          "INSERT INTO paper_atproto_repo_proof.native_event_outbox (did,commit_cid,rev,kind) VALUES ($1,$2,$3,'at.commit.v1')",
          [did, signed.commitCid, signed.rev]
        );
        if (testFailAfterOutbox) {
          fail('ATPROTO_TEST_INJECTED_FAILURE', 'Simulated crash before RDF recovery intent persistence');
        }
        // This insertion is in the SAME transaction. A committed repo can
        // never lack a durable, discoverable RDF projection recovery intent.
        await client.query(
          `INSERT INTO paper_atproto_repo_proof.rdf_projection_jobs
            (account_id,did,head_cid,root_cid,rev)
            VALUES ($1,$2,$3,$4,$5)`,
          [accountId, did, signed.commitCid, signed.rootCid, signed.rev]
        );
      }
      // A lost COMMIT reply can mean the signed repo, blocks, outbox
      // and RDF intent ALL committed. Never assume it rolled back.
      commitAttempted = true;
      await client.query('COMMIT');
      transactionOpen = false;
    } catch (error) {
      if (commitAttempted) {
        discardConnection = true;
        fail('ATPROTO_REPO_COMMIT_OUTCOME_UNKNOWN',
          'Repository commit acknowledgment uncertain; reconcile by verified head and outbox');
      }
      if (transactionOpen) {
        try { await client.query('ROLLBACK'); } catch { discardConnection = true; }
      }
      throw error;
    } finally {
      // Critically release before any post-commit verification query:
      // verification uses the same bounded connection pool. Holding this
      // client across read-back deadlocks concurrent replays at max pool size.
      client.release(discardConnection);
    }
    // Read back from authoritative DB AFTER releasing transaction client;
    // reject missing/corrupt signature, CIDs, CAR or outbox.
    const proof = await verify({ accountId, did, publicKeyPem });
    return Object.freeze({ ...proof, replay });
  }

  return Object.freeze({ bootstrap, verify });
}
