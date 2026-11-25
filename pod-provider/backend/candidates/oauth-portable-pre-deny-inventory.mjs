/**
 * NONACTIVATED, read-only S3-compatible pre-denial evidence inventory.
 *
 * Detects already retained PRE-DENY receipts after a restored canonical/witness
 * PostgreSQL may have forgotten revocation. A missing receipt is NEVER proof
 * that authorization is current. No production OAuth/PDS service imports this.
 *
 * Complete, tamper-resistant latest-head availability requires an independent
 * signer/administrator and externally certified storage. Two scans limit
 * observable read races but do not serialize with concurrent PREPARE/PUT.
 */
import crypto from 'node:crypto';
import {inspectPortableS3ObjectLock} from './oauth-portable-s3-custody-readonly.mjs';
import {assertReceipt} from './oauth-s3-compliance-archive.mjs';

const HEX=/^[a-f0-9]{64}$/u;
const UUID='[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}';
const RECEIPT_KEY=new RegExp('^paper/oauth-witness/pre-deny/v1/([a-f0-9]{64})/([0-9]{19})/('+UUID+')$','u');
const MAX_BYTES=1024;

function refuse(code){
 const e=new Error('Independent pre-denial archive inventory unavailable');
 e.code=code;
 throw e;
}
function gate(fixtureOnly){
 if(fixtureOnly!==true||process.env.NODE_ENV!=='test'||
    process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE!=='confirmed')
  refuse('PRE_DENY_INVENTORY_NOT_RELEASED');
}
function versionOk(value){
 return typeof value==='string'&&value.length>0&&value.length<=512&&
  value!=='null'&&[...value].every(c=>{
   const n=c.codePointAt(0);return n>32&&n!==127;
  });
}
async function bytesOf(body){
 if(Buffer.isBuffer(body)||body instanceof Uint8Array){
  if(body.length<1||body.length>MAX_BYTES)refuse('PRE_DENY_INVENTORY_BODY_UNSAFE');
  return Buffer.from(body);
 }
 if(!body||typeof body[Symbol.asyncIterator]!=='function')
  refuse('PRE_DENY_INVENTORY_BODY_UNSAFE');
 const chunks=[];let count=0;
 try{
  for await(const part of body){
   if(!(part instanceof Uint8Array))refuse('PRE_DENY_INVENTORY_BODY_UNSAFE');
   count+=part.length;
   if(count>MAX_BYTES)refuse('PRE_DENY_INVENTORY_BODY_UNSAFE');
   chunks.push(Buffer.from(part));
  }
 }catch{refuse('PRE_DENY_INVENTORY_BODY_UNSAFE')}
 if(count===0)refuse('PRE_DENY_INVENTORY_BODY_UNSAFE');
 return Buffer.concat(chunks,count);
}
/**
 * The caller's subject MUST come from the independently authenticated
 * owner/client binding; never from client JSON.
 * This is an evidence collector, not an "allow" verdict.
 */
export async function inspectDisposablePortablePreDenyInventory({
  provider,endpoint,approvedEndpoint=null,bucket,reader,commands,subject,
  clock=()=>Date.now(),fixtureOnly=false
}={}){
 gate(fixtureOnly);
 if(!HEX.test(subject||'')||typeof reader?.send!=='function'||
    typeof commands?.ListObjectVersionsCommand!=='function'||
    typeof commands?.GetObjectCommand!=='function'||
    typeof clock!=='function')
  refuse('PRE_DENY_INVENTORY_CONFIGURATION_UNSAFE');
 const scope={
  provider,endpoint,approvedEndpoint,bucket,reader,commands,
  clock,minRetentionDays:400,minRemainingDays:30
 };
 const prefix='paper/oauth-witness/pre-deny/v1/'+subject+'/';
 async function list(){
  let response;
  try{
   response=await reader.send(new commands.ListObjectVersionsCommand({
    Bucket:bucket,Prefix:prefix,MaxKeys:64
   }),{abortSignal:AbortSignal.timeout(7000)});
  }catch{refuse('PRE_DENY_INVENTORY_LIST_UNAVAILABLE')}
  if(!response||response.IsTruncated!==false||
     !Array.isArray(response.Versions)||
     !Array.isArray(response.DeleteMarkers??[])||
     response.DeleteMarkers?.length||
     (response.CommonPrefixes??[]).length||
     response.Versions.length>1)
    refuse('PRE_DENY_INVENTORY_FORK_OR_INCOMPLETE');
  const entries=response.Versions.map(v=>{
   const parsed=RECEIPT_KEY.exec(v?.Key||'');
   if(!parsed||parsed[1]!==subject||parsed[2]==='0000000000000000000'||
      BigInt(parsed[2])>9223372036854775807n||
      !versionOk(v.VersionId)||v.IsLatest!==true||
      !Number.isSafeInteger(v.Size)||v.Size<32||v.Size>MAX_BYTES)
    refuse('PRE_DENY_INVENTORY_FORK_OR_INCOMPLETE');
   return Object.freeze({key:v.Key,versionId:v.VersionId,size:v.Size,
    revision:BigInt(parsed[2]).toString()});
  });
  return entries;
 }
 // The same independently credentialed reader must first prove that the
 // bucket enforces default COMPLIANCE and versioning.
 const policy=await inspectPortableS3ObjectLock(scope);
 if(policy.configurationObserved!==true||policy.releaseAccepted!==false)
  refuse('PRE_DENY_INVENTORY_BUCKET_UNVERIFIED');
 const first=await list();
 let retained=null;
 if(first.length){
  const entry=first[0];
  let response;
  try{
   response=await reader.send(new commands.GetObjectCommand({
    Bucket:bucket,Key:entry.key,VersionId:entry.versionId
   }),{abortSignal:AbortSignal.timeout(7000)});
  }catch{refuse('PRE_DENY_INVENTORY_BODY_UNAVAILABLE')}
  if(response?.VersionId!==entry.versionId)
   refuse('PRE_DENY_INVENTORY_VERSION_CHANGED');
  const body=await bytesOf(response.Body);
  if(body.length!==entry.size)
   refuse('PRE_DENY_INVENTORY_BODY_UNSAFE');
  try{assertReceipt(entry.key,body)}
  catch{refuse('PRE_DENY_INVENTORY_BODY_UNSAFE')}
  const parsed=JSON.parse(body.toString('utf8'));
  if(parsed.revision!==entry.revision||
     parsed.subject!==subject)
   refuse('PRE_DENY_INVENTORY_BODY_UNSAFE');
  const sha256=crypto.createHash('sha256').update(body).digest('hex');
  // Reuse the existing strict exact-version HEAD, retention, GET, history,
  // digest and repeated bucket-policy checks. Do not duplicate WORM logic.
  let proof;
  try{
   proof=await inspectPortableS3ObjectLock({
    ...scope,sample:{key:entry.key,versionId:entry.versionId,sha256}
   });
  }catch{refuse('PRE_DENY_INVENTORY_READBACK_UNVERIFIED')}
  if(proof.receiptVerified!==true||proof.releaseAccepted!==false||
     proof.versionId!==entry.versionId||proof.payloadSha256!==sha256)
   refuse('PRE_DENY_INVENTORY_READBACK_UNVERIFIED');
  retained=Object.freeze({
   subject,revision:entry.revision,operationId:parsed.operationId,
   grantSha256:parsed.grantSha256,receiptSha256:sha256,
   versionId:entry.versionId
  });
 }
 const second=await list();
 if(JSON.stringify(first)!==JSON.stringify(second))
  refuse('PRE_DENY_INVENTORY_CHANGED_DURING_READ');
 // For an empty inventory, redo the policy read too. A signed monotonic
 // latest-head and independent PG row-lock fence are mandatory regardless.
 if(!retained)await inspectPortableS3ObjectLock(scope);
 return Object.freeze({
  retainedDenialObserved:retained!==null,
  retainedDenial:retained,
  absenceAuthorizes:false,
  operatorIndependenceVerified:false,
  monotonicLatestHeadVerified:false,
  releaseAccepted:false
 });
}
