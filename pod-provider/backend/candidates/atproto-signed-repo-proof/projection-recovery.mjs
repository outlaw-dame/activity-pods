/**
 * NON-ACTIVATED: PostgreSQL -> protected Jena/RDF projection recovery proof.
 * PG owns signed repo head, blocks and outbox. Jena owns WebID/AP/DID identity.
 * The injected trusted RDF writer MUST provide atomic Jena-side monotone-fence
 * CAS on its persisted resource; read/PUT does not implement that contract.
 */
import crypto from 'node:crypto';

const T = 'paper_atproto_repo_proof.rdf_projection_jobs';
const DID = /^did:plc:[a-z2-7]{24}$/;
const CID = /^bafyre[a-z2-7]{53}$/;
const TID = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/;
const TERMINAL = new Set(['RDF_FENCE_CONFLICT', 'RDF_PROJECTION_CONFLICT',
  'PROJECTION_AUTH_REVOKED', 'PROJECTION_IDENTITY_DRIFT',
  'PROJECTION_VERIFIED_HEAD_CHANGED']);

function fail(code, message) {
  const err = new Error(message); err.code = code; throw err;
}
function accountCheck(accountId, did) {
  if (typeof accountId !== 'string' || accountId.length > 2048 || !DID.test(did || '')) {
    fail('PROJECTION_IDENTITY_INVALID', 'Invalid managed account/DID');
  }
  let parsed;
  try { parsed = new URL(accountId); } catch { fail('PROJECTION_IDENTITY_INVALID', 'Invalid WebID'); }
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.href !== accountId ||
      parsed.search || parsed.hash || parsed.username || parsed.password) {
    fail('PROJECTION_IDENTITY_INVALID', 'Account must be a canonical HTTPS WebID');
  }
}
function checkProof(p, accountId, did) {
  if (!p || p.verified !== true || p.accountId !== accountId || p.did !== did ||
      !CID.test(p.commitCid || '') || !CID.test(p.rootCid || '') ||
      !TID.test(p.rev || '') || !['pending', 'delivered'].includes(p.outboxStatus)) {
    fail('PROJECTION_EVIDENCE_INVALID', 'Missing signed repository evidence');
  }
}
function checkJob(row, p) {
  if (!row || row.account_id !== p.accountId || row.did !== p.did ||
      row.head_cid !== p.commitCid || row.root_cid !== p.rootCid ||
      row.rev !== p.rev || Number(row.generation) !== 1) {
    fail('PROJECTION_VERIFIED_HEAD_CHANGED', 'Recovery intent differs from signed PG head');
  }
}
function checkRdfIdentity(record, accountId, did) {
  if (!record || record.canonicalAccountId !== accountId ||
      record.webId !== accountId || record.activityPubActorId !== accountId ||
      record.atprotoDid !== did || record.atprotoSource !== 'local' ||
      record.atprotoManaged !== true || record.status !== 'active') {
    fail('PROJECTION_IDENTITY_DRIFT', 'Protected RDF identity association changed');
  }
}
function checkProjected(record, p, fence) {
  checkRdfIdentity(record, p.accountId, p.did);
  if (record.repoInitialized !== true || record.repoRootCid !== p.rootCid ||
      record.repoRev !== p.rev || record.repoProjectionFence !== fence) {
    fail('RDF_PROJECTION_CONFLICT', 'Protected RDF repository projection is inconsistent');
  }
}
function retryDelaySeconds(attempt) {
  const ceiling = Math.min(300, 2 ** Math.min(attempt, 9));
  return crypto.randomInt(1000, Math.max(1001, Math.floor(ceiling * 1000) + 1)) / 1000;
}

/**
 * verifyNativeEvidence: trusted provider callback verifying real CAR, signature,
 * MST, head, DID key and outbox, returning a sanitized proof.
 * authorize: protected provider/SAI permission, MUST return literal true.
 * readRdf: authoritative protected binding, never a public cache.
 * applyRdfFenced: atomic conditional Jena update of root/rev/epoch and
 *                 identity assertions. Rejects stale/equal fence unless exact.
 */
export function createRdfProjectionRecovery({
  pool, verifyNativeEvidence, authorize, readRdf, applyRdfFenced,
  fixtureOnly = false, leaseSeconds = 15, maxAttempts = 8
} = {}) {
  if (process.env.NODE_ENV === 'production' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' || fixtureOnly !== true) {
    const unavailable = async () => fail('PROJECTION_NOT_RELEASED', 'RDF recovery is not activated');
    return Object.freeze({ reconcile: unavailable, readiness: unavailable, inspect: unavailable });
  }
  if (!pool || typeof pool.query !== 'function' ||
      [verifyNativeEvidence, authorize, readRdf, applyRdfFenced].some(x => typeof x !== 'function') ||
      !Number.isInteger(leaseSeconds) || leaseSeconds < 1 || leaseSeconds > 300 ||
      !Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 20) {
    fail('PROJECTION_CONFIGURATION_INVALID', 'PG, verification, grants and fenced RDF writer required');
  }

  const permitted = async (accountId, did, fence = null) => {
    if ((await authorize({ accountId, did, scope: 'atproto:rdf-projection', fence })) !== true) {
      fail('PROJECTION_AUTH_REVOKED', 'Current provider authority not granted');
    }
  };
  const evidence = async (accountId, did) => {
    const p = await verifyNativeEvidence({ accountId, did });
    checkProof(p, accountId, did);
    return p;
  };
  async function job(accountId, did) {
    const r = await pool.query(
      'SELECT account_id,did,head_cid,root_cid,rev,generation,state,lease_epoch,' +
      'lease_owner,lease_until,attempt_count,applied_at,last_error_code FROM ' + T +
      ' WHERE account_id=$1 AND did=$2', [accountId, did]
    );
    if (r.rowCount !== 1) fail('PROJECTION_INTENT_MISSING', 'Signed genesis has no recovery intent');
    return r.rows[0];
  }
  async function readiness({ accountId, did }) {
    accountCheck(accountId, did);
    await permitted(accountId, did);
    const p = await evidence(accountId, did);
    const row = await job(accountId, did);
    checkJob(row, p);
    if (row.state !== 'applied' || !row.applied_at) {
      fail('PROJECTION_NOT_READY', 'RDF projection has no durable completion');
    }
    checkProjected(await readRdf({ accountId, did }), p, String(row.lease_epoch));
    await permitted(accountId, did, String(row.lease_epoch));
    return Object.freeze({
      ready: true, accountId, did, headCid: p.commitCid, rootCid: p.rootCid,
      rev: p.rev, fence: String(row.lease_epoch), outboxStatus: p.outboxStatus
    });
  }
  async function inspect({ accountId, did }) {
    accountCheck(accountId, did);
    await permitted(accountId, did);
    const p = await evidence(accountId, did);
    const row = await job(accountId, did);
    checkJob(row, p);
    const rdf = await readRdf({ accountId, did });
    checkRdfIdentity(rdf, accountId, did);
    const matched = rdf.repoInitialized === true && rdf.repoRootCid === p.rootCid &&
      rdf.repoRev === p.rev && rdf.repoProjectionFence === String(row.lease_epoch);
    return Object.freeze({
      accountId, did, status: row.state, fence: String(row.lease_epoch),
      attempts: row.attempt_count,
      requiresRecovery: row.state !== 'applied' || !matched,
      inconsistentCompletedProjection: row.state === 'applied' && !matched
    });
  }
  async function claim(accountId, did) {
    // A single PG UPDATE serializes concurrent claims across real replicas.
    // Never hold the PG lease transaction or connection during network I/O.
    const owner = crypto.randomUUID();
    const r = await pool.query(
      'UPDATE ' + T + ' SET state=$6,lease_owner=$3::uuid,lease_epoch=lease_epoch+1,' +
      "lease_until=clock_timestamp()+($4::int * INTERVAL '1 second')," +
      'attempt_count=attempt_count+1,last_error_code=NULL,updated_at=clock_timestamp() ' +
      "WHERE account_id=$1 AND did=$2 AND attempt_count < $5::int AND " +
      "((state='pending' AND next_attempt_at<=clock_timestamp()) OR " +
      "(state='leased' AND lease_until<=clock_timestamp())) " +
      'RETURNING account_id,did,head_cid,root_cid,rev,generation,' +
      'lease_owner,lease_epoch,attempt_count',
      [accountId, did, owner, leaseSeconds, maxAttempts, 'leased']
    );
    return r.rowCount === 1 ? r.rows[0] : null;
  }
  async function finishFailure(accountId, did, claimed, code) {
    const fatal = TERMINAL.has(code) || claimed.attempt_count >= maxAttempts;
    const delay = fatal ? 0 : retryDelaySeconds(claimed.attempt_count);
    // Never clear or override a newer replica's lease.
    await pool.query(
      'UPDATE ' + T + ' SET state=$5,lease_owner=NULL,lease_until=NULL,' +
      "next_attempt_at=clock_timestamp()+($6::float8 * INTERVAL '1 second')," +
      'last_error_code=$7,updated_at=clock_timestamp() WHERE ' +
      "account_id=$1 AND did=$2 AND lease_owner=$3::uuid AND lease_epoch=$4::bigint " +
      "AND state='leased' AND lease_until>clock_timestamp()",
      [accountId, did, claimed.lease_owner, claimed.lease_epoch,
        fatal ? 'blocked' : 'pending', delay,
        /^[A-Z][A-Z0-9_]{2,79}$/.test(code || '') ? code : 'PROJECTION_RETRYABLE_ERROR']
    );
  }
  async function reconcile({ accountId, did, testCrashAfterRdf = false }) {
    accountCheck(accountId, did);
    await permitted(accountId, did);
    const p = await evidence(accountId, did);
    const before = await job(accountId, did);
    checkJob(before, p);
    if (before.state === 'applied') return readiness({ accountId, did });
    if (before.state === 'blocked') fail('PROJECTION_BLOCKED', 'Operator review required');
    // Exhausted *pending* rows must not remain permanently 'busy':
    // claim() refuses attempt_count >= maxAttempts, so without this
    // transition they would never become operator-visible blocked work.
    // Conditional update avoids clobbering an in-flight concurrent claim.
    await pool.query(
      'UPDATE ' + T + " SET state='blocked',lease_owner=NULL,lease_until=NULL," +
      "last_error_code='PROJECTION_RETRY_EXHAUSTED',updated_at=clock_timestamp() " +
      "WHERE account_id=$1 AND did=$2 AND state='pending' " +
      'AND attempt_count >= $3::int',
      [accountId, did, maxAttempts]
    );
    // Expired last-attempt leases cannot be left permanently in a busy state.
    await pool.query(
      'UPDATE ' + T + " SET state='blocked',lease_owner=NULL,lease_until=NULL," +
      "last_error_code='PROJECTION_RETRY_EXHAUSTED',updated_at=clock_timestamp() " +
      "WHERE account_id=$1 AND did=$2 AND state='leased' " +
      'AND lease_until<=clock_timestamp() AND attempt_count >= $3::int',
      [accountId, did, maxAttempts]
    );
    const leased = await claim(accountId, did);
    if (!leased) {
      const current = await job(accountId, did);
      checkJob(current, p);
      if (current.state === 'applied') return readiness({ accountId, did });
      if (current.state === 'blocked') fail('PROJECTION_BLOCKED', 'Operator review required');
      return Object.freeze({ accountId, did, status: 'busy', retryScheduled: true });
    }
    checkJob(leased, p);
    const fence = String(leased.lease_epoch);
    try {
      await permitted(accountId, did, fence);
      checkRdfIdentity(await readRdf({ accountId, did }), accountId, did);
      await applyRdfFenced({
        accountId, did, headCid: p.commitCid, rootCid: p.rootCid,
        rev: p.rev, fence,
        expectedIdentity: { canonicalAccountId: accountId, webId: accountId,
          activityPubActorId: accountId, atprotoDid: did }
      });
      // Crash simulation: leave the lease intact and recover at epoch+1.
      if (testCrashAfterRdf) {
        fail('PROJECTION_TEST_CRASH', 'Simulated crash after RDF write but before PG ACK');
      }
      await permitted(accountId, did, fence);
      const fresh = await evidence(accountId, did);
      if (fresh.commitCid !== p.commitCid || fresh.rootCid !== p.rootCid || fresh.rev !== p.rev) {
        fail('PROJECTION_VERIFIED_HEAD_CHANGED', 'Signed repository changed during projection');
      }
      checkProjected(await readRdf({ accountId, did }), p, fence);
      const ack = await pool.query(
        'UPDATE ' + T + " SET state='applied',lease_owner=NULL,lease_until=NULL," +
        'applied_at=clock_timestamp(),last_error_code=NULL,updated_at=clock_timestamp() ' +
        'WHERE account_id=$1 AND did=$2 AND lease_owner=$3::uuid AND ' +
        "lease_epoch=$4::bigint AND state='leased' AND lease_until>clock_timestamp() " +
        'AND head_cid=$5 AND root_cid=$6 AND rev=$7 RETURNING lease_epoch',
        [accountId, did, leased.lease_owner, fence, p.commitCid, p.rootCid, p.rev]
      );
      if (ack.rowCount !== 1) fail('PROJECTION_STALE_FENCE', 'Lease superseded before durable ACK');
      return readiness({ accountId, did });
    } catch (e) {
      if (e?.code !== 'PROJECTION_TEST_CRASH') {
        await finishFailure(accountId, did, leased, e?.code);
      }
      throw e;
    }
  }
  return Object.freeze({ reconcile, readiness, inspect });
}
