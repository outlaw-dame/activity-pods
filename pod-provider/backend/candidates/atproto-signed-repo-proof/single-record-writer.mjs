/**
 * Nonactivated PostgreSQL 18 single-record mutation writer.
 *
 * Repository head, immutable DAG-CBOR blocks, the native-event outbox and
 * monotonically-fenced RDF projection intent commit atomically. The expected
 * signed head is an explicit CAS: race losers never retry/sign again behind
 * the caller's back. This DOES NOT register XRPC or support >1 MST record.
 */
import { Buffer } from 'node:buffer';
import * as cbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { assertManagedDid, assertTid, makeTid } from './genesis.mjs';
import {
  buildSignedSingleRecordSnapshot, checkRecordPath,
  verifySignedSingleRecordSnapshot, carFromSingleRecordBlocks
} from './signed-single-record.mjs';

const ROOT = 'paper_atproto_repo_proof';
const DID = /^did:plc:[a-z2-7]{24}$/u;
const CID_RE = /^bafyre[a-z2-7]{53}$/u;
const MAX_GENERATION = Number.MAX_SAFE_INTEGER;
const TID_ALPHABET = '234567abcdefghijklmnopqrstuvwxyz';
function nextTidAfter(previous) {
  assertTid(previous);
  let value = 0n;
  for (const symbol of previous) {
    const digit = TID_ALPHABET.indexOf(symbol);
    if (digit < 0) fail('SINGLE_RECORD_REVISION_INVALID');
    value = (value << 5n) | BigInt(digit);
  }
  const priorMicros = value >> 10n;
  const currentMicros = BigInt(Date.now()) * 1000n;
  // Never rely on randomized clock IDs to make two same-millisecond
  // commits monotonic. Advance at least one microsecond when needed.
  const micros = currentMicros > priorMicros ? currentMicros : priorMicros + 1n;
  return makeTid(micros);
}
function fail(code) {
  const e = new Error('Signed repository mutation unavailable');
  e.code = code;
  throw e;
}
function accountCheck(accountId) {
  let url;
  try { url = new URL(accountId); } catch { fail('SINGLE_RECORD_ACCOUNT_INVALID'); }
  if (typeof accountId !== 'string' || accountId.length > 2048 ||
      url.protocol !== 'https:' || url.href !== accountId ||
      url.username || url.password || url.search || url.hash) {
    fail('SINGLE_RECORD_ACCOUNT_INVALID');
  }
}
function requireReleased() {
  if (process.env.NODE_ENV === 'production' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') {
    fail('SINGLE_RECORD_WRITER_NOT_RELEASED');
  }
}
function checkPool(pool) {
  if (!pool || typeof pool.query !== 'function' ||
      typeof pool.connect !== 'function') fail('SINGLE_RECORD_WRITER_CONFIGURATION_INVALID');
}

/**
 * Read the signed head and its complete bounded CAR from the current PG row.
 * A current one-leaf root must reference exactly one existing content block.
 * All content hashes, signatures and records are verified before use.
 */
async function verifiedStoredSnapshot(pool,{did,headCid,rootCid,publicKeyPem}) {
  const blocks = await pool.query(
    'SELECT cid,block FROM '+ROOT+'.blocks WHERE did=$1 AND cid IN ($2,$3)',
    [did,headCid,rootCid]
  );
  if (blocks.rowCount !== 2) fail('SINGLE_RECORD_HEAD_BLOCK_MISSING');
  const byCid = new Map(blocks.rows.map(row => [row.cid, row.block]));
  let tree;
  try { tree = cbor.decode(byCid.get(rootCid)); }
  catch { fail('SINGLE_RECORD_MST_INVALID'); }
  let recordCid = null, recordBytes = null;
  if (Array.isArray(tree?.e) && tree.e.length === 1 &&
    CID.asCID(tree.e[0]?.v)) {
    recordCid = tree.e[0].v.toString();
    const record = await pool.query(
    'SELECT block FROM '+ROOT+'.blocks WHERE did=$1 AND cid=$2',
    [did, recordCid]
    );
    if (record.rowCount !== 1) fail('SINGLE_RECORD_RECORD_BLOCK_MISSING');
    recordBytes = record.rows[0].block;
  }
  const carBytes = await carFromSingleRecordBlocks({
    commitCid:headCid,rootCid:rootCid,
    commitBytes:byCid.get(headCid),rootBytes:byCid.get(rootCid),
    recordCid,recordBytes
  });
  const signed = await verifySignedSingleRecordSnapshot({
    did,publicKeyPem,carBytes
  });
  if (signed.commitCid !== headCid || signed.rootCid !== rootCid ||
    signed.recordCid !== recordCid) {
    fail('SINGLE_RECORD_HEAD_MISMATCH');
  }
  return signed;
}

export function createSignedSingleRecordWriter({
  pool, authorize, fixtureOnly = false
} = {}) {
  checkPool(pool);
  if (fixtureOnly !== true || process.env.NODE_ENV === 'production' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') {
    const unavailable = async () => fail('SINGLE_RECORD_WRITER_NOT_RELEASED');
    return Object.freeze({ write: unavailable, verify: unavailable });
  }
  if (typeof authorize !== 'function') {
    fail('SINGLE_RECORD_WRITER_CONFIGURATION_INVALID');
  }
  async function allowed(accountId, did, expectedCommitCid) {
    if ((await authorize({
      accountId, did, expectedCommitCid, scope: 'atproto:record-write'
    })) !== true) {
      fail('SINGLE_RECORD_WRITE_NOT_AUTHORIZED');
    }
  }
  async function verify({ accountId, did, publicKeyPem }) {
    requireReleased();
    accountCheck(accountId); assertManagedDid(did);
    const head = await pool.query(
      'SELECT account_id,did,head_cid,root_cid,rev,generation FROM '+ROOT+
      '.repos WHERE account_id=$1 AND did=$2', [accountId,did]
    );
    if (head.rowCount !== 1) fail('SINGLE_RECORD_REPO_NOT_FOUND');
    const h = head.rows[0];
    const generation = Number(h.generation);
    if (!Number.isSafeInteger(generation) || generation < 1) {
      fail('SINGLE_RECORD_GENERATION_INVALID');
    }
    const signed = await verifiedStoredSnapshot(pool,{
      did,headCid:h.head_cid,rootCid:h.root_cid,publicKeyPem
    });
    if(signed.rev!==h.rev)fail('SINGLE_RECORD_HEAD_MISMATCH');
    const recordCid=signed.recordCid;
    const outbox = await pool.query(
      'SELECT rev,kind,status,blocked_at FROM '+ROOT+
      '.native_event_outbox WHERE did=$1 AND commit_cid=$2',
      [did,h.head_cid]
    );
    if (outbox.rowCount !== 1 || outbox.rows[0].rev !== h.rev ||
        outbox.rows[0].kind !== 'at.commit.v1' ||
        outbox.rows[0].blocked_at !== null ||
        !['pending','delivered'].includes(outbox.rows[0].status)) {
      fail('SINGLE_RECORD_OUTBOX_MISMATCH');
    }
    let previousRootCid=null,previousRev=null,previousCommitCid=null;
    if (generation > 1) {
      const mutation = await pool.query(
        'SELECT action,path,record_cid,rev,generation,previous_commit_cid,'+
        'previous_root_cid,previous_rev,previous_record_cid FROM '+ROOT+
        '.record_mutations WHERE did=$1 AND commit_cid=$2',
        [did,h.head_cid]
      );
      if (mutation.rowCount !== 1 ||
          Number(mutation.rows[0].generation) !== generation ||
          mutation.rows[0].rev !== h.rev ||
          (mutation.rows[0].record_cid ?? null) !== recordCid ||
          (recordCid !== null && mutation.rows[0].path !== signed.path)) {
        fail('SINGLE_RECORD_MUTATION_AUDIT_MISMATCH');
      }
      const audit=mutation.rows[0];
      previousRootCid=audit.previous_root_cid;
      previousRev=audit.previous_rev;
      previousCommitCid=audit.previous_commit_cid;
      if(!CID_RE.test(previousRootCid||'') ||
         !CID_RE.test(previousCommitCid||'')){
        fail('SINGLE_RECORD_PARENT_INVALID');
      }
      const parent=await verifiedStoredSnapshot(pool,{
        did,headCid:previousCommitCid,rootCid:previousRootCid,publicKeyPem
      });
      if(parent.rev!==previousRev ||
         parent.recordCid!==audit.previous_record_cid ||
         (parent.path!==null && audit.path!==parent.path) ||
         previousRev>=signed.rev){
        fail('SINGLE_RECORD_PARENT_INVALID');
      }
    }
    return Object.freeze({
      verified:true,accountId,did,rev:signed.rev,
      commitCid:signed.commitCid,rootCid:signed.rootCid,
      recordCid:signed.recordCid,path:signed.path,
      previousRootCid,previousRev,previousCommitCid,
      generation,outboxStatus:outbox.rows[0].status,carBytes:signed.carBytes
    });
  }
  async function write({
    accountId,did,expectedCommitCid,expectedRev,
    action,path,record=null,signer,publicKeyPem,rev=null,
    testFailAfterBlocks=false,testFailAfterOutbox=false
  }) {
    requireReleased();
    accountCheck(accountId);assertManagedDid(did);
    if (!CID_RE.test(expectedCommitCid||'') ||
        !['create','update','delete'].includes(action)) {
      fail('SINGLE_RECORD_WRITE_INPUT_INVALID');
    }
    assertTid(expectedRev);
    if (rev !== null) assertTid(rev);
    checkRecordPath(path);
    if (action !== 'delete' && (!record || record.$type !== path.split('/')[0])) {
      fail('SINGLE_RECORD_WRITE_INPUT_INVALID');
    }
    if (action === 'delete' && record !== null) {
      fail('SINGLE_RECORD_WRITE_INPUT_INVALID');
    }
    await allowed(accountId,did,expectedCommitCid);
    const previous = await verify({accountId,did,publicKeyPem});
    if (previous.commitCid !== expectedCommitCid ||
        previous.rev !== expectedRev) fail('SINGLE_RECORD_STALE_HEAD');
    const nextRev = rev === null ? nextTidAfter(previous.rev) : rev;
    if (nextRev <= previous.rev) fail('SINGLE_RECORD_REVISION_NOT_INCREASING');
    if (previous.generation >= MAX_GENERATION) {
      fail('SINGLE_RECORD_GENERATION_EXHAUSTED');
    }
    if (action === 'create' && previous.recordCid !== null) {
      fail('SINGLE_RECORD_PATH_EXISTS');
    }
    if (action !== 'create' &&
        (previous.path !== path || previous.recordCid === null)) {
      fail('SINGLE_RECORD_PATH_NOT_FOUND');
    }
    const signed = await buildSignedSingleRecordSnapshot({
      did,rev:nextRev,signer,publicKeyPem,
      path:action==='delete'?null:path,
      record:action==='delete'?null:record
    });
    if (action==='update' && signed.recordCid===previous.recordCid) {
      fail('SINGLE_RECORD_NOOP_UPDATE');
    }
    await allowed(accountId,did,expectedCommitCid);
    const client=await pool.connect();
    let transactionOpen=false,commitAttempted=false,discard=false;
    try {
      await client.query('BEGIN');transactionOpen=true;
      await client.query("SET LOCAL lock_timeout='3000ms'");
      await client.query("SET LOCAL statement_timeout='8000ms'");
      await client.query("SET LOCAL idle_in_transaction_session_timeout='4000ms'");
      const row=await client.query(
        'SELECT head_cid,root_cid,rev,generation FROM '+ROOT+
        '.repos WHERE account_id=$1 AND did=$2 FOR UPDATE',
        [accountId,did]
      );
      if (row.rowCount!==1 || row.rows[0].head_cid!==expectedCommitCid ||
          row.rows[0].rev!==expectedRev ||
          Number(row.rows[0].generation)!==previous.generation) {
        fail('SINGLE_RECORD_STALE_HEAD');
      }
      const intent=await client.query(
        'SELECT state,head_cid,rev,generation FROM '+ROOT+
        '.rdf_projection_jobs WHERE account_id=$1 AND did=$2 FOR UPDATE',
        [accountId,did]
      );
      if (intent.rowCount!==1 || intent.rows[0].state!=='applied' ||
          intent.rows[0].head_cid!==expectedCommitCid ||
          intent.rows[0].rev!==expectedRev ||
          Number(intent.rows[0].generation)!==previous.generation) {
        fail('SINGLE_RECORD_PROJECTION_NOT_APPLIED');
      }
      // Immutable content-addressed blocks. Identical blocks may be shared
      // by unchanged records or repeated MST roots. Reject any mismatch.
      for (const block of signed.blocks) {
        await client.query(
          'INSERT INTO '+ROOT+'.blocks(did,cid,block) VALUES($1,$2,$3) '+
          'ON CONFLICT(did,cid) DO NOTHING',
          [did,block.cid,block.bytes]
        );
        const actual=await client.query(
          'SELECT block FROM '+ROOT+'.blocks WHERE did=$1 AND cid=$2',
          [did,block.cid]
        );
        if (actual.rowCount!==1 ||
            !Buffer.from(actual.rows[0].block).equals(block.bytes)) {
          fail('SINGLE_RECORD_BLOCK_COLLISION');
        }
      }
      if(testFailAfterBlocks) fail('SINGLE_RECORD_TEST_INJECTED_FAILURE');
      const generation=previous.generation+1;
      const updated=await client.query(
        'UPDATE '+ROOT+'.repos SET head_cid=$3,root_cid=$4,rev=$5,'+
        'generation=$6 WHERE account_id=$1 AND did=$2 AND head_cid=$7 '+
        'AND rev=$8 AND generation=$9 RETURNING generation',
        [accountId,did,signed.commitCid,signed.rootCid,signed.rev,generation,
          expectedCommitCid,expectedRev,previous.generation]
      );
      if(updated.rowCount!==1) fail('SINGLE_RECORD_STALE_HEAD');
      await client.query(
        'INSERT INTO '+ROOT+'.native_event_outbox(did,commit_cid,rev,kind) '+
        "VALUES($1,$2,$3,'at.commit.v1')",
        [did,signed.commitCid,signed.rev]
      );
      await client.query(
        'INSERT INTO '+ROOT+'.record_mutations '+
        '(did,commit_cid,previous_commit_cid,previous_root_cid,previous_rev,rev,action,'+
        'path,previous_record_cid,record_cid,generation) '+
        'VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
        [did,signed.commitCid,expectedCommitCid,previous.rootCid,
          expectedRev,signed.rev,action,path,
          previous.recordCid,signed.recordCid,generation]
      );
      if(testFailAfterOutbox) fail('SINGLE_RECORD_TEST_INJECTED_FAILURE');
      // Preserve the monotone Jena fence. A new signed head must be projected
      // and ACKed before any further mutation or public readiness.
      const pending=await client.query(
        'UPDATE '+ROOT+'.rdf_projection_jobs SET head_cid=$3,root_cid=$4,'+
        "rev=$5,generation=$6,state='pending',lease_owner=NULL,"+
        'lease_until=NULL,attempt_count=0,next_attempt_at=clock_timestamp(),'+
        'last_error_code=NULL,applied_at=NULL,updated_at=clock_timestamp() '+
        "WHERE account_id=$1 AND did=$2 AND state='applied' "+
        'AND head_cid=$7 AND rev=$8 AND generation=$9 RETURNING generation,lease_epoch',
        [accountId,did,signed.commitCid,signed.rootCid,signed.rev,generation,
          expectedCommitCid,expectedRev,previous.generation]
      );
      if(pending.rowCount!==1) fail('SINGLE_RECORD_PROJECTION_NOT_APPLIED');
      commitAttempted=true;
      await client.query('COMMIT');transactionOpen=false;
    }catch(error){
      if(commitAttempted){
        discard=true;
        fail('SINGLE_RECORD_COMMIT_OUTCOME_UNKNOWN');
      }
      if(transactionOpen){
        try{await client.query('ROLLBACK');}catch{discard=true;}
      }
      throw error;
    }finally{
      client.release(discard);
    }
    return verify({accountId,did,publicKeyPem});
  }
  return Object.freeze({verify,write});
}
