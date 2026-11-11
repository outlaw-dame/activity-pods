/**
 * Isolated PostgreSQL 18-backed proof of a single authoritative genesis
 * repository transaction. Not registered in Moleculer or available to signup.
 *
 * Transaction invariant:
 * repo head + both content-addressed blocks + native-event outbox row
 * either all commit, or none commit. A durable native outbox entry stays
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
 * Only fixtureOnly=true enables this experimental writer, deliberately
 * preventing an accidental production authority cutover from an import.
 */
export function createSignedRepoProofStore({ pool, fixtureOnly = false } = {}) {
  requirePool(pool);
  if (fixtureOnly !== true) {
    return Object.freeze({
      bootstrap: async () => fail('ATPROTO_REPO_PROOF_NOT_RELEASED', 'No production repository writer is enabled'),
      verify: async () => fail('ATPROTO_REPO_PROOF_NOT_RELEASED', 'No production repository reader is enabled')
    });
  }

  async function verify({ accountId, did, publicKeyPem }) {
    assertAccountId(accountId);
    assertManagedDid(did);
    const rows = await pool.query(
      'SELECT account_id, did, rev, head_cid, root_cid FROM paper_atproto_repo_proof.repos WHERE account_id = $1 AND did = $2',
      [accountId, did]
    );
    if (rows.rowCount !== 1) fail('ATPROTO_REPO_NOT_FOUND', 'No authoritative repository is stored for this account');
    const row = rows.rows[0];
    const blocks = await pool.query(
      'SELECT cid, block FROM paper_atproto_repo_proof.blocks WHERE did = $1 AND cid IN ($2, $3)',
      [did, row.head_cid, row.root_cid]
    );
    if (blocks.rowCount !== 2) fail('ATPROTO_REPO_BLOCKS_MISSING', 'Repository commit or MST block is missing');
    const byCid = new Map(blocks.rows.map(block => [block.cid, block.block]));
    const carBytes = await carFromBlocks({
      commitCid: row.head_cid,
      rootCid: row.root_cid,
      commitBytes: byCid.get(row.head_cid),
      rootBytes: byCid.get(row.root_cid)
    });
    const verified = await verifySignedEmptyRepo({ did, carBytes, publicKeyPem });
    if (verified.commitCid !== row.head_cid || verified.rootCid !== row.root_cid ||
        verified.rev !== row.rev) {
      fail('ATPROTO_REPO_HEAD_MISMATCH', 'Stored head and independently verified CAR disagree');
    }
    const outbox = await pool.query(
      'SELECT id, kind, status, rev FROM paper_atproto_repo_proof.native_event_outbox WHERE did = $1 AND commit_cid = $2',
      [did, row.head_cid]
    );
    if (outbox.rowCount !== 1 || outbox.rows[0].kind !== 'at.commit.v1' ||
        outbox.rows[0].rev !== row.rev) {
      fail('ATPROTO_REPO_OUTBOX_MISSING', 'Native event outbox must be committed with the repository');
    }
    return Object.freeze({
      accountId, did,
      rev: verified.rev, rootCid: verified.rootCid,
      commitCid: verified.commitCid,
      carBytes,
      outboxStatus: outbox.rows[0].status,
      verified: true
    });
  }

  async function bootstrap({
    accountId, did, signer, publicKeyPem,
    rev = makeTid(), testFailAfterBlocks = false
  }) {
    assertAccountId(accountId);
    assertManagedDid(did);
    if (testFailAfterBlocks !== false && process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') {
      fail('ATPROTO_TEST_FAILPOINT_FORBIDDEN', 'Failure injection is limited to disposable proof tests');
    }

    // Sign and verify outside the DB transaction so a slow signer does not
    // hold database locks or a connection. Unique identity + advisory lock
    // makes races single-writer once persistence begins.
    const signed = await buildSignedEmptyRepo({ did, rev, signer, publicKeyPem });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
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
        await client.query('COMMIT');
        const proof = await verify({ accountId, did, publicKeyPem });
        return Object.freeze({ ...proof, replay: true });
      }

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
      await client.query('COMMIT');
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch { /* already aborted/disconnected */ }
      throw error;
    } finally {
      client.release();
    }
    // Read back from the authoritative DB and independently revalidate
    // signed commit, all CIDs, CAR and outbox; no "repoInitialized" flag used.
    const proof = await verify({ accountId, did, publicKeyPem });
    return Object.freeze({ ...proof, replay: false });
  }

  return Object.freeze({ bootstrap, verify });
}
