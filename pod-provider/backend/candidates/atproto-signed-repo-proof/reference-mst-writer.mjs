/**
 * NONACTIVATED disposable PostgreSQL v3 multi-record MST writer.
 *
 * Uses the maintained open-source @atproto/repo MST, NOT another
 * home-grown MST implementation. The reference package is injected by the
 * trusted CI/integration process; no dynamic user-selected import or public
 * XRPC service exists. Production must pin+lock its own reviewed dependency.
 *
 * Only changed MST nodes, a record block and signed commit are appended;
 * old records and tree nodes remain immutable. There is no account-wide
 * scan, no network/SAI call under a database transaction and no automatic
 * retry/rebase of stale record mutations.
 */
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import { CID } from 'multiformats/cid';
import * as cbor from '@ipld/dag-cbor';
import { assertManagedDid, assertTid, normalizeK256LowS } from './genesis.mjs';
import {
  checkRecordPath, checkRecord, cid, decodeCanonical, signatureFrom
} from './signed-single-record.mjs';
import { nextTidAfter } from './single-record-writer.mjs';

const TABLE='paper_atproto_repo_proof';
const CID_RE=/^bafyre[a-z2-7]{53}$/u;
const MAX_BLOCK_BYTES=131072;
const MAX_READS=192;
const MAX_READ_BYTES=2*1024*1024;
const MAX_CHANGED_BLOCKS=96;
const MAX_CHANGED_BYTES=1024*1024;
const MAX_GENERATION=Number.MAX_SAFE_INTEGER;

function fail(code) {
  const error=new Error('Signed reference-MST repository operation unavailable');
  error.code=code;
  throw error;
}
function enabled(fixtureOnly) {
  if(fixtureOnly!==true || process.env.NODE_ENV==='production' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed') {
    fail('REFERENCE_MST_NOT_RELEASED');
  }
}
function checkedAccount(accountId) {
  if(typeof accountId!=='string' || accountId.length>2048) {
    fail('REFERENCE_MST_ACCOUNT_INVALID');
  }
  let u;
  try {u=new URL(accountId);}catch{fail('REFERENCE_MST_ACCOUNT_INVALID');}
  if(u.protocol!=='https:' || u.href!==accountId || !u.hostname ||
     u.username || u.password || u.hash || u.search) {
    fail('REFERENCE_MST_ACCOUNT_INVALID');
  }
}
function checkedPublicKey(pem) {
  if(typeof pem!=='string' || pem.length>4096) fail('REFERENCE_MST_KEY_INVALID');
  try {
    const key=crypto.createPublicKey(pem);
    if(key.asymmetricKeyType!=='ec' ||
       key.asymmetricKeyDetails?.namedCurve!=='secp256k1') {
      fail('REFERENCE_MST_KEY_INVALID');
    }
    return key;
  }catch{fail('REFERENCE_MST_KEY_INVALID');}
}
function checkedCid(text) {
  if(typeof text!=='string' || !CID_RE.test(text)) {
    fail('REFERENCE_MST_CID_INVALID');
  }
  return CID.parse(text);
}
function requireReference(ref) {
  if(!ref || typeof ref.MST?.load!=='function' ||
     typeof ref.ReadableBlockstore!=='function' ||
     typeof ref.BlockMap!=='function') fail('REFERENCE_MST_LIBRARY_REQUIRED');
}

/** Per-operation lazy reader: every CID-addressed read is scoped and hashed. */
function readerFor(pool,ref,did,overlay=new Map()) {
  let reads=0,bytesRead=0;
  const overlayBlocks=overlay;
  class SafeReader extends ref.ReadableBlockstore {
    async getBytes(link) {
      const key=link.toString();
      checkedCid(key);
      if(++reads>MAX_READS)fail('REFERENCE_MST_READ_BUDGET_EXCEEDED');
      let bytes=overlayBlocks.get(key);
      if(bytes===undefined){
        const rows=await pool.query(
          'SELECT block FROM '+TABLE+'.blocks WHERE did=$1 AND cid=$2',
          [did,key]
        );
        if(rows.rowCount!==1)return null;
        bytes=Buffer.from(rows.rows[0].block);
      }
      if(!(bytes instanceof Uint8Array) || bytes.length<1 ||
         bytes.length>MAX_BLOCK_BYTES ||
         (bytesRead+=bytes.length)>MAX_READ_BYTES ||
         !(await cid(bytes)).equals(link)) {
        fail('REFERENCE_MST_DURABLE_BLOCK_INVALID');
      }
      return Buffer.from(bytes);
    }
    async has(link) {
      const key=link.toString();
      checkedCid(key);
      if(++reads>MAX_READS)fail('REFERENCE_MST_READ_BUDGET_EXCEEDED');
      if(overlayBlocks.has(key))return true;
      const rows=await pool.query(
        'SELECT 1 FROM '+TABLE+'.blocks WHERE did=$1 AND cid=$2',
        [did,key]
      );
      return rows.rowCount===1;
    }
    async getBlocks(links) {
      if(!Array.isArray(links) || links.length>MAX_READS){
        fail('REFERENCE_MST_READ_BUDGET_EXCEEDED');
      }
      const blocks=new ref.BlockMap();
      const missing=[];
      for(const link of links) {
        const bytes=await this.getBytes(link);
        if(bytes===null)missing.push(link);
        else blocks.set(link,bytes);
      }
      return {blocks,missing};
    }
  }
  return new SafeReader();
}
function checkedCommit(bytes,{did,headCid,rev,rootCid,publicKey}) {
  const body=decodeCanonical(bytes);
  if(!body || body.did!==did || body.version!==3 ||
     body.prev!==null || !CID.asCID(body.data) ||
     body.data.toString()!==rootCid || body.rev!==rev ||
     !(body.sig instanceof Uint8Array) || body.sig.length!==64 ||
     Object.keys(body).sort().join(',')!=='data,did,prev,rev,sig,version') {
    fail('REFERENCE_MST_COMMIT_INVALID');
  }
  assertTid(body.rev);
  let lowS;
  try{lowS=normalizeK256LowS(body.sig);}
  catch{fail('REFERENCE_MST_SIGNATURE_INVALID');}
  if(!Buffer.from(lowS).equals(Buffer.from(body.sig))) {
    fail('REFERENCE_MST_SIGNATURE_NONCANONICAL');
  }
  const {sig,...unsigned}=body;
  if(!crypto.verify('sha256',Buffer.from(cbor.encode(unsigned)),{
    key:publicKey,dsaEncoding:'ieee-p1363'
  },Buffer.from(sig))) {
    fail('REFERENCE_MST_SIGNATURE_INVALID');
  }
  return Object.freeze({commitCid:headCid,rootCid,rev,verified:true});
}
async function verifyCommitBytes(reader,{did,headCid,rev,rootCid,publicKey}) {
  const bytes=await reader.getBytes(checkedCid(headCid));
  if(!bytes)fail('REFERENCE_MST_COMMIT_MISSING');
  return checkedCommit(bytes,{did,headCid,rev,rootCid,publicKey});
}
async function signedNewCommit({did,rev,rootCid,signer,publicKey}) {
  assertManagedDid(did);
  assertTid(rev);
  checkedCid(rootCid);
  if(typeof signer!=='function')fail('REFERENCE_MST_SIGNER_REQUIRED');
  const unsigned={did,version:3,data:CID.parse(rootCid),rev,prev:null};
  const unsignedBytes=Buffer.from(cbor.encode(unsigned));
  const sig=signatureFrom(await signer(unsignedBytes));
  if(!crypto.verify('sha256',unsignedBytes,{
    key:publicKey,dsaEncoding:'ieee-p1363'
  },Buffer.from(sig))) {
    fail('REFERENCE_MST_SIGNATURE_INVALID');
  }
  const bytes=Buffer.from(cbor.encode({...unsigned,sig:new Uint8Array(sig)}));
  const link=await cid(bytes);
  checkedCommit(bytes,{
    did,headCid:link.toString(),rev,rootCid,publicKey
  });
  return Object.freeze({cid:link.toString(),bytes});
}

/**
 * Uses the existing genesis repo, same immutable blocks, same single-writer
 * head, same native event outbox, same monotonically-fenced RDF intent and
 * same historical one-operation-per-commit audit. No new account DB.
 */
export function createReferenceMstWriter({
  pool,reference,authorize,fixtureOnly=false
}={}) {
  if(fixtureOnly!==true || process.env.NODE_ENV==='production' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed') {
    const unavailable=async()=>fail('REFERENCE_MST_NOT_RELEASED');
    return Object.freeze({verify:unavailable,write:unavailable});
  }
  requireReference(reference);
  if(typeof pool?.query!=='function' ||
     typeof pool?.connect!=='function' ||
     typeof authorize!=='function'){
    fail('REFERENCE_MST_CONFIGURATION_INVALID');
  }
  const auth=async(accountId,did,expectedCommitCid)=>{
    if((await authorize({
      accountId,did,expectedCommitCid,scope:'atproto:record-write'
    }))!==true)fail('REFERENCE_MST_NOT_AUTHORIZED');
  };
  async function verify({accountId,did,publicKeyPem,path=null}) {
    enabled(fixtureOnly);checkedAccount(accountId);assertManagedDid(did);
    const publicKey=checkedPublicKey(publicKeyPem);
    if(path!==null)checkRecordPath(path);
    const query=await pool.query(
      'SELECT account_id,did,head_cid,root_cid,rev,generation '+
      'FROM '+TABLE+'.repos WHERE account_id=$1 AND did=$2',
      [accountId,did]
    );
    if(query.rowCount!==1)fail('REFERENCE_MST_REPO_NOT_FOUND');
    const row=query.rows[0],generation=Number(row.generation);
    if(!Number.isSafeInteger(generation)||generation<1||
       generation>=MAX_GENERATION)fail('REFERENCE_MST_GENERATION_INVALID');
    checkedCid(row.head_cid);checkedCid(row.root_cid);
    assertTid(row.rev);
    const reader=readerFor(pool,reference,did);
    await verifyCommitBytes(reader,{
      did,headCid:row.head_cid,rootCid:row.root_cid,rev:row.rev,publicKey
    });
    const tree=reference.MST.load(reader,checkedCid(row.root_cid));
    // Force decoding of the actual root MST, not merely trusting the CID
    // string stored in the PostgreSQL repository row.
    try {await tree.getEntries();}
    catch{fail('REFERENCE_MST_ROOT_INVALID');}
    let recordCid=null;
    if(path!==null){
      try {recordCid=(await tree.get(path))?.toString()??null;}
      catch{fail('REFERENCE_MST_PATH_INVALID');}
      if(recordCid!==null){
        const bytes=await reader.getBytes(checkedCid(recordCid));
        if(!bytes)fail('REFERENCE_MST_RECORD_MISSING');
        const record=decodeCanonical(bytes);
        checkRecord(record,path);
      }
    }
    const outbox=await pool.query(
      'SELECT rev,kind,status,blocked_at,'+
      'EXISTS(SELECT 1 FROM '+TABLE+'.native_event_outbox blocked '+
      "WHERE blocked.did=$1 AND blocked.status='pending' "+
      'AND blocked.blocked_at IS NOT NULL) AS blocked_history '+
      'FROM '+TABLE+'.native_event_outbox '+
      'WHERE did=$1 AND commit_cid=$2',[did,row.head_cid]
    );
    if(outbox.rowCount!==1 || outbox.rows[0].rev!==row.rev ||
       outbox.rows[0].kind!=='at.commit.v1' ||
       !['pending','delivered'].includes(outbox.rows[0].status)){
      fail('REFERENCE_MST_OUTBOX_MISMATCH');
    }
    if(outbox.rows[0].blocked_at!==null ||
       outbox.rows[0].blocked_history===true){
      fail('REFERENCE_MST_OUTBOX_BLOCKED');
    }
    let previousCommitCid=null,previousRootCid=null,previousRev=null;
    if(generation>1){
      const history=await pool.query(
        'SELECT previous_commit_cid,previous_root_cid,previous_rev,rev,'+
        'generation FROM '+TABLE+'.record_mutations '+
        'WHERE did=$1 AND commit_cid=$2',[did,row.head_cid]
      );
      if(history.rowCount!==1 ||
         Number(history.rows[0].generation)!==generation ||
         history.rows[0].rev!==row.rev){
        fail('REFERENCE_MST_HISTORY_INVALID');
      }
      previousCommitCid=history.rows[0].previous_commit_cid;
      previousRootCid=history.rows[0].previous_root_cid;
      previousRev=history.rows[0].previous_rev;
      checkedCid(previousRootCid);checkedCid(previousCommitCid);
      assertTid(previousRev);
      if(previousRev>=row.rev)fail('REFERENCE_MST_HISTORY_INVALID');
      await verifyCommitBytes(reader,{
        did,headCid:previousCommitCid,rootCid:previousRootCid,
        rev:previousRev,publicKey
      });
    }
    return Object.freeze({
      verified:true,accountId,did,
      commitCid:row.head_cid,rootCid:row.root_cid,rev:row.rev,
      generation,recordCid,path,previousCommitCid,previousRootCid,
      previousRev,outboxStatus:outbox.rows[0].status
    });
  }
  async function write({
    accountId,did,expectedCommitCid,expectedRev,action,path,
    record=null,signer,publicKeyPem,
    testFailAfterBlocks=false,testFailAfterOutbox=false
  }) {
    enabled(fixtureOnly);checkedAccount(accountId);assertManagedDid(did);
    checkedCid(expectedCommitCid);assertTid(expectedRev);checkRecordPath(path);
    if(!['create','update','delete'].includes(action) ||
       (action==='delete' && record!==null) ||
       (action!=='delete' && (!record||record.$type!==path.split('/')[0]))){
      fail('REFERENCE_MST_MUTATION_INVALID');
    }
    const publicKey=checkedPublicKey(publicKeyPem);
    await auth(accountId,did,expectedCommitCid);
    const prior=await verify({accountId,did,publicKeyPem,path});
    if(prior.commitCid!==expectedCommitCid || prior.rev!==expectedRev){
      fail('REFERENCE_MST_STALE_HEAD');
    }
    if(prior.generation>=MAX_GENERATION-1){
      fail('REFERENCE_MST_GENERATION_EXHAUSTED');
    }
    if((action==='create' && prior.recordCid!==null) ||
       (action!=='create' && prior.recordCid===null)){
      fail(action==='create'?'REFERENCE_MST_PATH_EXISTS':'REFERENCE_MST_PATH_NOT_FOUND');
    }
    const reader=readerFor(pool,reference,did);
    const tree=reference.MST.load(reader,checkedCid(prior.rootCid));
    let newCid=null,recordBytes=null;
    if(action!=='delete'){
      recordBytes=checkRecord(record,path);
      newCid=(await cid(recordBytes)).toString();
      if(action==='update' && newCid===prior.recordCid) {
        fail('REFERENCE_MST_NOOP_UPDATE');
      }
    }
    let next;
    try{
      if(action==='create')next=await tree.add(path,checkedCid(newCid));
      else if(action==='update')next=await tree.update(path,checkedCid(newCid));
      else next=await tree.delete(path);
    }catch{fail('REFERENCE_MST_TREE_MUTATION_INVALID');}
    let changed;
    try{changed=await next.getUnstoredBlocks();}
    catch{fail('REFERENCE_MST_TREE_SERIALIZATION_INVALID');}
    const rootCid=changed.root.toString();
    checkedCid(rootCid);
    if(rootCid===prior.rootCid)fail('REFERENCE_MST_NOOP_UPDATE');
    const blocks=new Map();
    let changedBytes=0;
    async function addBlock(blockCid,bytes){
      checkedCid(blockCid);
      if(!(bytes instanceof Uint8Array) ||
         bytes.length<1 || bytes.length>MAX_BLOCK_BYTES ||
         !(await cid(bytes)).equals(CID.parse(blockCid))) {
        fail('REFERENCE_MST_CHANGED_BLOCK_INVALID');
      }
      if(blocks.has(blockCid)) {
        if(!blocks.get(blockCid).equals(Buffer.from(bytes))) {
          fail('REFERENCE_MST_CHANGED_BLOCK_COLLISION');
        }
        return;
      }
      changedBytes+=bytes.byteLength;
      if(blocks.size>=MAX_CHANGED_BLOCKS ||
         changedBytes>MAX_CHANGED_BYTES)fail('REFERENCE_MST_WRITE_BUDGET_EXCEEDED');
      blocks.set(blockCid,Buffer.from(bytes));
    }
    for(const [link,bytes] of changed.blocks)await addBlock(link.toString(),bytes);
    if(recordBytes!==null)await addBlock(newCid,recordBytes);
    // The changed MST root must be either in the staged delta or the DB,
    // with no need to enumerate any unrelated existing record.
    const stagedReader=readerFor(pool,reference,did,blocks);
    const stagedTree=reference.MST.load(stagedReader,checkedCid(rootCid));
    let resolved;
    try {resolved=await stagedTree.get(path);}
    catch{fail('REFERENCE_MST_CHANGED_TREE_INVALID');}
    if((resolved?.toString()??null)!==(newCid??null)){
      fail('REFERENCE_MST_CHANGED_TREE_INVALID');
    }
    const rev=nextTidAfter(prior.rev);
    const signed=await signedNewCommit({
      did,rev,rootCid,signer,publicKey
    });
    await addBlock(signed.cid,signed.bytes);
    await auth(accountId,did,expectedCommitCid);

    const client=await pool.connect();
    let inTransaction=false,commitAttempted=false,discard=false;
    try{
      await client.query('BEGIN');inTransaction=true;
      await client.query("SET LOCAL lock_timeout='3000ms'");
      await client.query("SET LOCAL statement_timeout='8000ms'");
      await client.query("SET LOCAL idle_in_transaction_session_timeout='4000ms'");
      const head=await client.query(
        'SELECT head_cid,root_cid,rev,generation FROM '+TABLE+
        '.repos WHERE account_id=$1 AND did=$2 FOR UPDATE',[accountId,did]
      );
      if(head.rowCount!==1 ||
         head.rows[0].head_cid!==prior.commitCid ||
         head.rows[0].root_cid!==prior.rootCid ||
         head.rows[0].rev!==prior.rev ||
         Number(head.rows[0].generation)!==prior.generation) {
        fail('REFERENCE_MST_STALE_HEAD');
      }
      const fence=await client.query(
        'SELECT head_cid,root_cid,rev,generation,state FROM '+TABLE+
        '.rdf_projection_jobs WHERE account_id=$1 AND did=$2 FOR UPDATE',
        [accountId,did]
      );
      if(fence.rowCount!==1 ||
         fence.rows[0].state!=='applied' ||
         fence.rows[0].head_cid!==prior.commitCid ||
         fence.rows[0].root_cid!==prior.rootCid ||
         fence.rows[0].rev!==prior.rev ||
         Number(fence.rows[0].generation)!==prior.generation) {
        fail('REFERENCE_MST_PROJECTION_NOT_APPLIED');
      }
      const blocked=await client.query(
        'SELECT 1 FROM '+TABLE+'.native_event_outbox '+
        "WHERE did=$1 AND status='pending' AND blocked_at IS NOT NULL "+
        'LIMIT 1',[did]
      );
      if(blocked.rowCount!==0)fail('REFERENCE_MST_OUTBOX_BLOCKED');
      for(const [blockCid,bytes] of blocks){
        await client.query(
          'INSERT INTO '+TABLE+'.blocks(did,cid,block) VALUES($1,$2,$3) '+
          'ON CONFLICT(did,cid) DO NOTHING',[did,blockCid,bytes]
        );
        const committed=await client.query(
          'SELECT block FROM '+TABLE+'.blocks WHERE did=$1 AND cid=$2',
          [did,blockCid]
        );
        if(committed.rowCount!==1 ||
           !Buffer.from(committed.rows[0].block).equals(bytes)) {
          fail('REFERENCE_MST_BLOCK_COLLISION');
        }
      }
      if(testFailAfterBlocks)fail('REFERENCE_MST_TEST_INJECTED_FAILURE');
      const generation=prior.generation+1;
      const updated=await client.query(
        'UPDATE '+TABLE+'.repos SET head_cid=$3,root_cid=$4,rev=$5,'+
        'generation=$6 WHERE account_id=$1 AND did=$2 '+
        'AND head_cid=$7 AND generation=$8 RETURNING generation',
        [accountId,did,signed.cid,rootCid,rev,generation,
          prior.commitCid,prior.generation]
      );
      if(updated.rowCount!==1)fail('REFERENCE_MST_STALE_HEAD');
      await client.query(
        'INSERT INTO '+TABLE+'.native_event_outbox(did,commit_cid,rev,kind) '+
        "VALUES($1,$2,$3,'at.commit.v1')",[did,signed.cid,rev]
      );
      await client.query(
        'INSERT INTO '+TABLE+'.record_mutations'+
        '(did,commit_cid,previous_commit_cid,previous_root_cid,'+
        'previous_rev,rev,action,path,previous_record_cid,'+
        'record_cid,generation) '+
        'VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
        [did,signed.cid,prior.commitCid,prior.rootCid,prior.rev,rev,
          action,path,prior.recordCid,newCid,generation]
      );
      if(testFailAfterOutbox)fail('REFERENCE_MST_TEST_INJECTED_FAILURE');
      const reset=await client.query(
        'UPDATE '+TABLE+'.rdf_projection_jobs SET head_cid=$3,'+
        'root_cid=$4,rev=$5,generation=$6,'+
        "state='pending',lease_owner=NULL,lease_until=NULL,"+
        'attempt_count=0,next_attempt_at=clock_timestamp(),'+
        'last_error_code=NULL,applied_at=NULL,updated_at=clock_timestamp() '+
        'WHERE account_id=$1 AND did=$2 AND head_cid=$7 AND root_cid=$8 '+
        "AND rev=$9 AND generation=$10 AND state='applied' "+
        'RETURNING generation,lease_epoch',
        [accountId,did,signed.cid,rootCid,rev,generation,
          prior.commitCid,prior.rootCid,prior.rev,prior.generation]
      );
      if(reset.rowCount!==1)fail('REFERENCE_MST_PROJECTION_NOT_APPLIED');
      commitAttempted=true;
      await client.query('COMMIT');inTransaction=false;
    }catch(e){
      if(commitAttempted){
        discard=true;
        fail('REFERENCE_MST_COMMIT_OUTCOME_UNKNOWN');
      }
      if(inTransaction){
        try{await client.query('ROLLBACK');}
        catch{discard=true;}
      }
      throw e;
    }finally{
      client.release(discard);
    }
    return Object.freeze(await verify({accountId,did,publicKeyPem,path}));
  }
  return Object.freeze({verify,write});
}
