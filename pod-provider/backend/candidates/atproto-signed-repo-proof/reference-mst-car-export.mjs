/**
 * NONACTIVATED full-snapshot CARv1 proof for a bounded ATProto repository.
 *
 * Walk the maintained upstream MST from a trusted signed PostgreSQL head,
 * verify each CID-addressed node/record, then encode a complete CAR with
 * the signed commit as its sole root. This is a buffer-returning disposable
 * acceptance candidate: large production repos require streaming output,
 * snapshot isolation and SAI/hosting authority at the actual HTTP edge.
 */
import { Buffer } from 'node:buffer';
import { CID } from 'multiformats/cid';
import { CarWriter } from '@ipld/car';
import { checkRecordPath, checkRecord, decodeCanonical, cid } from './signed-single-record.mjs';

const TABLE='paper_atproto_repo_proof';
const DID=/^did:plc:[a-z2-7]{24}$/u;
const CID_RE=/^bafyre[a-z2-7]{53}$/u;
const MAX_CAR_BYTES=2_000_000;
const MAX_RECORDS=512;
const MAX_NODES=1024;
const MAX_BLOCKS=MAX_RECORDS+MAX_NODES+1;
const MAX_BLOCK_BYTES=131072;

function deny(code) {
  const err=new Error('Managed ATProto complete repository export is unavailable');
  err.code=code;
  throw err;
}
function allowedFixture(fixtureOnly) {
  if(fixtureOnly!==true || process.env.NODE_ENV==='production' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed') {
    deny('REFERENCE_CAR_EXPORT_NOT_RELEASED');
  }
}
function checkedCid(value) {
  if(typeof value!=='string' || !CID_RE.test(value)){
    deny('REFERENCE_CAR_CID_INVALID');
  }
  return CID.parse(value);
}
function validateProof(input,proof) {
  if(!proof || proof.verified!==true ||
     proof.accountId!==input.accountId || proof.did!==input.did ||
     !CID_RE.test(proof.commitCid||'') ||
     !CID_RE.test(proof.rootCid||'') ||
     !Number.isSafeInteger(proof.generation) ||
     proof.generation<1 ||
     typeof proof.rev!=='string' ||
     !/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u.test(proof.rev) ||
     !['pending','delivered'].includes(proof.outboxStatus)){
    deny('REFERENCE_CAR_SIGNED_HEAD_INVALID');
  }
}
async function checkCurrent(pool,proof) {
  const r=await pool.query(
    'SELECT repo.head_cid,repo.root_cid,repo.rev,repo.generation,'+
    'project.state,project.head_cid AS projected_head,'+
    'project.root_cid AS projected_root,project.rev AS projected_rev,'+
    'project.generation AS projected_generation '+
    'FROM '+TABLE+'.repos repo JOIN '+TABLE+
    '.rdf_projection_jobs project ON project.account_id=repo.account_id '+
    'AND project.did=repo.did WHERE repo.account_id=$1 AND repo.did=$2',
    [proof.accountId,proof.did]
  );
  if(r.rowCount!==1)deny('REFERENCE_CAR_HEAD_CHANGED');
  const row=r.rows[0];
  if(row.head_cid!==proof.commitCid || row.root_cid!==proof.rootCid ||
     row.rev!==proof.rev ||
     Number(row.generation)!==proof.generation ||
     row.state!=='applied' || row.projected_head!==proof.commitCid ||
     row.projected_root!==proof.rootCid ||
     row.projected_rev!==proof.rev ||
     Number(row.projected_generation)!==proof.generation){
    deny('REFERENCE_CAR_PROJECTION_NOT_APPLIED');
  }
  const blocked=await pool.query(
    'SELECT 1 FROM '+TABLE+'.native_event_outbox '+
    "WHERE did=$1 AND status='pending' AND blocked_at IS NOT NULL LIMIT 1",
    [proof.did]
  );
  if(blocked.rowCount!==0)deny('REFERENCE_CAR_OUTBOX_BLOCKED');
}

/** Immutable block retrieval with a fixed account+CID predicate and SHA-256. */
async function loadBlock(pool,did,link) {
  const cidText=link.toString();
  checkedCid(cidText);
  const result=await pool.query(
    'SELECT block FROM '+TABLE+'.blocks WHERE did=$1 AND cid=$2',
    [did,cidText]
  );
  if(result.rowCount!==1)deny('REFERENCE_CAR_BLOCK_MISSING');
  const bytes=Buffer.from(result.rows[0].block);
  if(bytes.length<1 || bytes.length>MAX_BLOCK_BYTES ||
     !(await cid(bytes)).equals(link)){
    deny('REFERENCE_CAR_BLOCK_INVALID');
  }
  return bytes;
}
async function encodeCar(blocks,maxBytes) {
  // Bound BEFORE starting async CAR generation. The varint/CID+header
  // allowance is deliberately conservative; avoids backpressure deadlock
  // if a downstream collector refuses to drain an oversized stream.
  const estimate=blocks.reduce((n,b)=>n+b.bytes.length+96,128);
  if(estimate>maxBytes)deny('REFERENCE_CAR_TOO_LARGE');
  const {writer,out}=CarWriter.create([blocks[0].cid]);
  const parts=[];
  let size=0;
  const collect=(async()=>{
    for await (const chunk of out){
      size+=chunk.byteLength;
      parts.push(Buffer.from(chunk));
    }
  })();
  try {
    for(const block of blocks)await writer.put(block);
  }finally{
    await writer.close();
  }
  await collect;
  if(size>maxBytes)deny('REFERENCE_CAR_TOO_LARGE');
  return Buffer.concat(parts,size);
}

/**
 * Only a trusted provider process can inject verifySignedHead and authorize.
 * No user-selectable record store, arbitrary dataset, signer or URI.
 */
export function createReferenceMstCarExporter({
  pool,reference,verifySignedHead,authorize,fixtureOnly=false
}={}) {
  if(fixtureOnly!==true || process.env.NODE_ENV==='production' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed') {
    return Object.freeze({exportSnapshot:async()=>deny('REFERENCE_CAR_EXPORT_NOT_RELEASED')});
  }
  if(typeof pool?.query!=='function' ||
     typeof reference?.MST?.load!=='function' ||
     typeof reference?.ReadableBlockstore!=='function' ||
     typeof reference?.BlockMap!=='function' ||
     typeof verifySignedHead!=='function' || typeof authorize!=='function'){
    deny('REFERENCE_CAR_CONFIGURATION_INVALID');
  }
  async function exportSnapshot({
    accountId,did,publicKeyPem,maxBytes=MAX_CAR_BYTES
  }) {
    allowedFixture(fixtureOnly);
    if(!DID.test(did||'') ||
       !Number.isSafeInteger(maxBytes) || maxBytes<256 ||
       maxBytes>MAX_CAR_BYTES)deny('REFERENCE_CAR_SCOPE_INVALID');
    const operation=Object.freeze({accountId,did,scope:'atproto:repo-export'});
    if((await authorize(operation))!==true)deny('REFERENCE_CAR_NOT_AUTHORIZED');
    // A separate production binding/SAI verifier must own this callback;
    // never rely on an unverified caller-supplied "ready" flag.
    const proof=await verifySignedHead({accountId,did,publicKeyPem});
    validateProof({accountId,did},proof);
    await checkCurrent(pool,proof);

    const blocks=[];
    const visited=new Set();
    let leafCount=0,nodeCount=0;
    let payloadBytes=0;
    async function append(link,{recordPath=null,mst=false}={}){
      const text=link.toString();
      checkedCid(text);
      if(visited.has(text))return;
      if(blocks.length>=MAX_BLOCKS)deny('REFERENCE_CAR_BLOCK_LIMIT');
      const bytes=await loadBlock(pool,did,link);
      payloadBytes+=bytes.length+96;
      if(payloadBytes+128>maxBytes)deny('REFERENCE_CAR_TOO_LARGE');
      if(recordPath!==null){
        const record=decodeCanonical(bytes);
        checkRecord(record,recordPath);
      }
      if(mst){
        const value=decodeCanonical(bytes);
        if(!value || !Array.isArray(value.e) || !('l' in value)){
          deny('REFERENCE_CAR_MST_INVALID');
        }
      }
      visited.add(text);
      blocks.push({cid:link,bytes});
    }
    // Root commit must be first in the CAR block ordering as well as the
    // CARv1 header roots list. The signer/commit bytes were already
    // independently checked by verifySignedHead.
    await append(checkedCid(proof.commitCid));
    const poolReader=new (class extends reference.ReadableBlockstore {
      async getBytes(link){
        return loadBlock(pool,did,link);
      }
      async has(link){
        const bytes=await this.getBytes(link);
        return Boolean(bytes);
      }
      async getBlocks(links){
        const output=new reference.BlockMap();
        const missing=[];
        for(const link of links){
          try{output.set(link,await this.getBytes(link));}
          catch(error){
            if(error?.code!=='REFERENCE_CAR_BLOCK_MISSING')throw error;
            missing.push(link);
          }
        }
        return {blocks:output,missing};
      }
    })();
    const tree=reference.MST.load(poolReader,checkedCid(proof.rootCid));
    try {
      // Upstream walk has cycle/duplicate-tree-node protection. Every
      // recorded node and leaf is verified against its CID and type.
      for await (const entry of tree.walk()){
        if(entry.isTree()){
          if(++nodeCount>MAX_NODES)deny('REFERENCE_CAR_NODE_LIMIT');
          await append(await entry.getPointer(),{mst:true});
        }else{
          if(++leafCount>MAX_RECORDS)deny('REFERENCE_CAR_RECORD_LIMIT');
          const path=checkRecordPath(entry.key);
          await append(entry.value,{recordPath:path});
        }
      }
    }catch(error){
      if(typeof error?.code==='string' &&
         error.code.startsWith('REFERENCE_CAR_'))throw error;
      deny('REFERENCE_CAR_TREE_INVALID');
    }
    // Both the exact head and applied Jena intent must remain current
    // throughout the bounded export. Never return a mixed-generation CAR.
    await checkCurrent(pool,proof);
    if((await authorize(operation))!==true)deny('REFERENCE_CAR_NOT_AUTHORIZED');
    const carBytes=await encodeCar(blocks,maxBytes);
    return Object.freeze({
      verified:true,releaseAuthorized:false,accountId,did,
      commitCid:proof.commitCid,rootCid:proof.rootCid,
      rev:proof.rev,generation:proof.generation,
      carBytes,recordCount:leafCount,nodeCount,blockCount:blocks.length
    });
  }
  return Object.freeze({exportSnapshot});
}
