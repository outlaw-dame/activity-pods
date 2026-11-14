/**
 * NONACTIVATED historical native ATProto #commit event proof.
 *
 * An older, still-pending PostgreSQL outbox commit must remain publishable
 * after the repository head has advanced. Uses the official @atproto/repo
 * MST diff and covering proof APIs, rather than exporting the newest head
 * or reconstructing the complete repository for each event.
 */
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import { CID } from 'multiformats/cid';
import { CarWriter } from '@ipld/car';
import * as cbor from '@ipld/dag-cbor';
import { cid, checkRecordPath, checkRecord, decodeCanonical } from './signed-single-record.mjs';
import { checkedCommit } from './reference-mst-writer.mjs';

const TABLE='paper_atproto_repo_proof';
const CID_RE=/^bafyre[a-z2-7]{53}$/u;
const DID=/^did:plc:[a-z2-7]{24}$/u;
const TID=/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const MAX_BYTES=2_000_000;
const MAX_FRAME_BYTES=2_200_000;
const MAX_BLOCK_BYTES=131072;
const MAX_READS=256;
const MAX_READ_BYTES=2_000_000;
const MAX_CAR_BLOCKS=96;

function fail(code) {
  const e=new Error('Native ATProto signed commit proof unavailable');
  e.code=code;
  throw e;
}
function treeError(error, fallback) {
  // Keep cryptographic CID and bounded-I/O failures distinct from an
  // upstream MST shape rejection. Never mask corruption as a missing path.
  if(typeof error?.code==='string' &&
     error.code.startsWith('NATIVE_COMMIT_'))throw error;
  fail(fallback);
}
function gated(fixtureOnly) {
  if(fixtureOnly!==true || process.env.NODE_ENV==='production' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed') {
    fail('NATIVE_COMMIT_NOT_RELEASED');
  }
}
function parseCid(value) {
  if(typeof value!=='string'||!CID_RE.test(value)) {
    fail('NATIVE_COMMIT_CID_INVALID');
  }
  return CID.parse(value);
}
function checkedKey(pem) {
  if(typeof pem!=='string'||pem.length>4096)fail('NATIVE_COMMIT_KEY_INVALID');
  try{
    const key=crypto.createPublicKey(pem);
    if(key.asymmetricKeyType!=='ec' ||
       key.asymmetricKeyDetails?.namedCurve!=='secp256k1') {
      fail('NATIVE_COMMIT_KEY_INVALID');
    }
    return key;
  }catch{fail('NATIVE_COMMIT_KEY_INVALID');}
}
function checkedAccount(value) {
  if(typeof value!=='string'||value.length>2048)fail('NATIVE_COMMIT_ACCOUNT_INVALID');
  let u;
  try{u=new URL(value);}catch{fail('NATIVE_COMMIT_ACCOUNT_INVALID');}
  if(u.protocol!=='https:'||u.href!==value||!u.hostname||
     u.username||u.password||u.search||u.hash)fail('NATIVE_COMMIT_ACCOUNT_INVALID');
}
function checkReference(reference) {
  if(typeof reference?.MST?.load!=='function' ||
     typeof reference?.DataDiff?.of!=='function' ||
     typeof reference?.ReadableBlockstore!=='function' ||
     typeof reference?.BlockMap!=='function') {
    fail('NATIVE_COMMIT_REFERENCE_REQUIRED');
  }
}
async function carFromBlocks(blocks,maxBytes) {
  if(blocks.length<1||blocks.length>MAX_CAR_BLOCKS)fail('NATIVE_COMMIT_BLOCK_LIMIT');
  const estimate=128+blocks.reduce((sum,b)=>sum+b.bytes.length+96,0);
  if(estimate>maxBytes)fail('NATIVE_COMMIT_TOO_LARGE');
  const {writer,out}=CarWriter.create([blocks[0].cid]);
  let size=0;
  const parts=[];
  const collector=(async()=>{
    for await(const chunk of out){
      size+=chunk.byteLength;
      parts.push(Buffer.from(chunk));
    }
  })();
  try{for(const block of blocks)await writer.put(block);}
  finally{await writer.close();}
  await collector;
  if(size>maxBytes)fail('NATIVE_COMMIT_TOO_LARGE');
  return Buffer.concat(parts,size);
}
/**
 * The provider supplies current hosting/SAI authorization and an explicitly
 * pinned official reference library. Neither service is activated by this
 * candidate. No public caller can choose a SQL table or signing key.
 */
export function createNativeCommitProof({
  pool,reference,authorize,fixtureOnly=false
}={}) {
  if(fixtureOnly!==true||process.env.NODE_ENV==='production'||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'){
    return Object.freeze({materialize:async()=>fail('NATIVE_COMMIT_NOT_RELEASED')});
  }
  checkReference(reference);
  if(typeof pool?.query!=='function'||typeof authorize!=='function'){
    fail('NATIVE_COMMIT_CONFIGURATION_INVALID');
  }
  async function materialize({
    accountId,did,commitCid,rev,publicKeyPem,maxBytes=MAX_BYTES
  }) {
    gated(fixtureOnly);checkedAccount(accountId);
    if(!DID.test(did||'')||!TID.test(rev||'')||
       !Number.isSafeInteger(maxBytes)||maxBytes<256||maxBytes>MAX_BYTES){
      fail('NATIVE_COMMIT_SCOPE_INVALID');
    }
    parseCid(commitCid);
    const op=Object.freeze({accountId,did,commitCid,rev,scope:'atproto:native-event'});
    async function permitted(){
      if((await authorize(op))!==true)fail('NATIVE_COMMIT_NOT_AUTHORIZED');
    }
    await permitted();
    const key=checkedKey(publicKeyPem);
    const owner=await pool.query(
      'SELECT head_cid,generation FROM '+TABLE+
      '.repos WHERE account_id=$1 AND did=$2',[accountId,did]
    );
    if(owner.rowCount!==1)fail('NATIVE_COMMIT_IDENTITY_MISMATCH');
    const maxGeneration=Number(owner.rows[0].generation);
    if(!Number.isSafeInteger(maxGeneration)||maxGeneration<1){
      fail('NATIVE_COMMIT_HEAD_INVALID');
    }
    const out=await pool.query(
      'SELECT id,did,commit_cid,rev,kind,status,created_at,blocked_at '+
      'FROM '+TABLE+'.native_event_outbox WHERE did=$1 AND commit_cid=$2',
      [did,commitCid]
    );
    if(out.rowCount!==1)fail('NATIVE_COMMIT_OUTBOX_MISSING');
    const row=out.rows[0],seq=Number(row.id);
    if(!Number.isSafeInteger(seq)||seq<1 ||
       row.did!==did||row.commit_cid!==commitCid ||
       row.rev!==rev||row.kind!=='at.commit.v1' ||
       !['pending','delivered'].includes(row.status)||
       row.blocked_at!==null ||
       !(row.created_at instanceof Date)||
       !Number.isFinite(row.created_at.getTime())) {
      fail('NATIVE_COMMIT_OUTBOX_INVALID');
    }
    const blocked=await pool.query(
      'SELECT 1 FROM '+TABLE+'.native_event_outbox '+
      "WHERE did=$1 AND status='pending' AND blocked_at IS NOT NULL LIMIT 1",
      [did]
    );
    if(blocked.rowCount!==0)fail('NATIVE_COMMIT_OUTBOX_BLOCKED');

    // One shared budget for both immutable MST generations, old/new record,
    // and the covering-proof CAR. Never enumerate all Pod accounts.
    let readCount=0,totalRead=0;
    const cache=new Map();
    async function getBytes(c) {
      const k=c.toString();parseCid(k);
      if(++readCount>MAX_READS)fail('NATIVE_COMMIT_READ_BUDGET');
      if(cache.has(k))return cache.get(k);
      const result=await pool.query(
        'SELECT block FROM '+TABLE+'.blocks WHERE did=$1 AND cid=$2',
        [did,k]
      );
      if(result.rowCount!==1)fail('NATIVE_COMMIT_BLOCK_MISSING');
      const bytes=Buffer.from(result.rows[0].block);
      totalRead+=bytes.length;
      if(bytes.length<1||bytes.length>MAX_BLOCK_BYTES ||
         totalRead>MAX_READ_BYTES||!(await cid(bytes)).equals(c)){
        fail('NATIVE_COMMIT_BLOCK_INVALID');
      }
      cache.set(k,bytes);
      return bytes;
    }
    const storage=new (class extends reference.ReadableBlockstore {
      async getBytes(c){return getBytes(c);}
      async has(c){
        const k=c.toString();parseCid(k);
        if(++readCount>MAX_READS)fail('NATIVE_COMMIT_READ_BUDGET');
        if(cache.has(k))return true;
        const result=await pool.query(
          'SELECT 1 FROM '+TABLE+'.blocks WHERE did=$1 AND cid=$2',
          [did,k]
        );
        return result.rowCount===1;
      }
      async getBlocks(links){
        if(!Array.isArray(links)||links.length>MAX_READS){
          fail('NATIVE_COMMIT_READ_BUDGET');
        }
        const blocks=new reference.BlockMap();
        for(const link of links)blocks.set(link,await getBytes(link));
        return {blocks,missing:[]};
      }
    })();

    async function signedCommit(c,revision,rootText=null) {
      const bytes=await getBytes(parseCid(c));
      const commit=decodeCanonical(bytes);
      const root=commit?.data?.toString?.();
      if(!root|| (rootText!==null && rootText!==root)) {
        fail('NATIVE_COMMIT_SIGNED_ROOT_MISMATCH');
      }
      parseCid(root);
      checkedCommit(bytes,{did,headCid:c,rev:revision,rootCid:root,publicKey:key});
      return {commit,root};
    }
    const signed=await signedCommit(commitCid,rev);
    const rootCid=signed.root;
    const currTree=reference.MST.load(storage,parseCid(rootCid));
    try{await currTree.getEntries();}
    catch(error){treeError(error,'NATIVE_COMMIT_ROOT_INVALID');}

    // Audit is a unique (DID,commit CID) indexed record and captures the
    // exact predecessor. The CURRENT head need not be this event's head.
    const auditRows=await pool.query(
      'SELECT action,path,record_cid,previous_record_cid,'+
      'previous_commit_cid,previous_root_cid,previous_rev,rev,generation '+
      'FROM '+TABLE+'.record_mutations WHERE did=$1 AND commit_cid=$2',
      [did,commitCid]
    );
    if(auditRows.rowCount>1)fail('NATIVE_COMMIT_AUDIT_INVALID');
    let since=null,prevData=null,ops=[];
    if(auditRows.rowCount===1){
      const m=auditRows.rows[0];
      if(!['create','update','delete'].includes(m.action) ||
         m.rev!==rev || !Number.isSafeInteger(Number(m.generation)) ||
         Number(m.generation)<2 || Number(m.generation)>maxGeneration ||
         !TID.test(m.previous_rev||'') || m.previous_rev>=rev) {
        fail('NATIVE_COMMIT_AUDIT_INVALID');
      }
      checkRecordPath(m.path);
      parseCid(m.previous_commit_cid);parseCid(m.previous_root_cid);
      await signedCommit(m.previous_commit_cid,m.previous_rev,m.previous_root_cid);
      const prevTree=reference.MST.load(storage,parseCid(m.previous_root_cid));
      let oldValue,newValue;
      try{
        oldValue=await prevTree.get(m.path);
        newValue=await currTree.get(m.path);
      }catch(error){treeError(error,'NATIVE_COMMIT_TREE_INVALID');}
      const oldCid=oldValue?.toString()??null;
      const newCid=newValue?.toString()??null;
      if(oldCid!==m.previous_record_cid ||
         newCid!==m.record_cid ||
         (m.action==='create' && (oldCid!==null||newCid===null)) ||
         (m.action==='update' && (oldCid===null||newCid===null||oldCid===newCid)) ||
         (m.action==='delete' && (oldCid===null||newCid!==null))) {
        fail('NATIVE_COMMIT_AUDIT_MISMATCH');
      }
      for(const recordCid of [oldCid,newCid]){
        if(recordCid!==null){
          checkRecord(decodeCanonical(await getBytes(parseCid(recordCid))),m.path);
        }
      }
      let diff;
      try{diff=await reference.DataDiff.of(currTree,prevTree);}
      catch(error){treeError(error,'NATIVE_COMMIT_DIFF_INVALID');}
      const created=Object.values(diff.adds);
      const updated=Object.values(diff.updates);
      const deleted=Object.values(diff.deletes);
      if(created.length+updated.length+deleted.length!==1 ||
         (m.action==='create'&&(created[0]?.key!==m.path ||
           created[0]?.cid.toString()!==newCid)) ||
         (m.action==='update'&&(updated[0]?.key!==m.path ||
           updated[0]?.cid.toString()!==newCid ||
           updated[0]?.prev.toString()!==oldCid)) ||
         (m.action==='delete'&&(deleted[0]?.key!==m.path ||
           deleted[0]?.cid.toString()!==oldCid))){
        fail('NATIVE_COMMIT_DIFF_MISMATCH');
      }
      since=m.previous_rev;
      prevData=parseCid(m.previous_root_cid);
      ops=[{
        action:m.action,path:m.path,cid:newCid===null?null:parseCid(newCid),
        ...(oldCid!==null?{prev:parseCid(oldCid)}:{})
      }];
    }else{
      // Prove an unaudited event is genuine genesis, not an orphan signed
      // commit. Both probes are indexed, even for a very old genesis.
      const genesis=maxGeneration===1?
        owner.rows[0].head_cid===commitCid:
        (await pool.query(
          'SELECT 1 FROM '+TABLE+'.record_mutations '+
          'WHERE did=$1 AND generation=2 AND previous_commit_cid=$2',
          [did,commitCid]
        )).rowCount===1;
      if(!genesis)fail('NATIVE_COMMIT_GENESIS_INVALID');
    }

    const archive=new Map();
    async function addBlock(value,bytes=null){
      const c=parseCid(value),k=c.toString();
      if(archive.has(k))return;
      if(archive.size>=MAX_CAR_BLOCKS)fail('NATIVE_COMMIT_BLOCK_LIMIT');
      const data=bytes??await getBytes(c);
      if(!(data instanceof Uint8Array) || !(await cid(data)).equals(c)){
        fail('NATIVE_COMMIT_BLOCK_INVALID');
      }
      archive.set(k,Buffer.from(data));
    }
    await addBlock(commitCid);
    if(ops.length===0){
      await addBlock(rootCid);
    }else{
      let proof;
      try{proof=await currTree.getCoveringProof(ops[0].path);}
      catch(error){treeError(error,'NATIVE_COMMIT_COVERING_PROOF_INVALID');}
      for(const [c,bytes] of proof)await addBlock(c.toString(),bytes);
      if(ops[0].cid!==null)await addBlock(ops[0].cid.toString());
    }
    if(!archive.has(rootCid))fail('NATIVE_COMMIT_ROOT_NOT_PROVED');
    const blocks=[{cid:parseCid(commitCid),bytes:archive.get(commitCid)}];
    for(const [k,bytes] of archive){
      if(k!==commitCid)blocks.push({cid:parseCid(k),bytes});
    }
    const carBytes=await carFromBlocks(blocks,maxBytes);
    const message={
      seq,repo:did,time:row.created_at.toISOString(),
      rev,since,commit:parseCid(commitCid),
      rebase:false,tooBig:false,blobs:[],
      blocks:new Uint8Array(carBytes),ops,
      ...(prevData!==null?{prevData}:{})
    };
    const header=Buffer.from(cbor.encode({op:1,t:'#commit'}));
    const payload=Buffer.from(cbor.encode(message));
    if(header.length+payload.length>MAX_FRAME_BYTES) {
      fail('NATIVE_COMMIT_FRAME_TOO_LARGE');
    }
    const eventBytes=Buffer.concat([header,payload],header.length+payload.length);
    await permitted();
    const confirm=await pool.query(
      'SELECT blocked_at,rev,kind FROM '+TABLE+
      '.native_event_outbox WHERE did=$1 AND commit_cid=$2',
      [did,commitCid]
    );
    if(confirm.rowCount!==1||confirm.rows[0].blocked_at!==null||
       confirm.rows[0].rev!==rev||confirm.rows[0].kind!=='at.commit.v1'){
      fail('NATIVE_COMMIT_OUTBOX_CHANGED');
    }
    return Object.freeze({
      verified:true,did,commitCid,rev,seq,
      idempotencyKey:'at.commit.v1:'+did+':'+commitCid,
      eventBytes,carBytes,
      event:Object.freeze(message),blockCount:blocks.length
    });
  }
  return Object.freeze({materialize});
}
