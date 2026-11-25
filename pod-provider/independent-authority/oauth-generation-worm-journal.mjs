/**
 * NONACTIVATED, provider-neutral, independent custody generation journal.
 *
 * Exactly one ACTIVE genesis and one terminal BLOCKED transition can be
 * retained in v1. BLOCKED requires the separately retained PRE-DENY v7
 * receipt; a rollback of Paper PG, witness PG, Redis, Jena, PDS or a signer
 * cache is NOT a source of authority. No production issuance is possible.
 *
 * One complete single-page S3 ListObjectVersions is only an OBSERVATION;
 * it is NOT an independently nonrewindable head or a distributed CAS lock.
 * Even a recovered ACTIVE is never an allow. An external owned sequencer,
 * independent signed high-water and audited real provider remain P0.
 */
import {createHash} from 'node:crypto';
import {Buffer} from 'node:buffer';
import {inspectPortableS3ObjectLock} from
 '../backend/candidates/oauth-portable-s3-custody-readonly.mjs';
import {inspectDisposablePortablePreDenyInventory} from
 '../backend/candidates/oauth-portable-pre-deny-inventory.mjs';
import {assertReceipt} from '../backend/candidates/oauth-s3-compliance-archive.mjs';

const HEX=/^[a-f0-9]{64}$/u;
const VERSION=/^[^\x00-\x20\x7f]{1,512}$/u;
const REV=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
const ZERO='0'.repeat(64);
const BASE='paper/oauth-authority/generations/v1/';
const KEY=/^paper\/oauth-authority\/generations\/v1\/([a-f0-9]{64})\/([0-9]{19})$/u;
const LIMIT=16;
function fail(code){
 const error=new Error('Independent authorization generation evidence unavailable');
 error.code=code;throw error;
}
function gate(fixtureOnly){
 if(process.env.NODE_ENV!=='test'||fixtureOnly!==true||
    process.env.PAPER_OAUTH_GENERATION_JOURNAL_DISPOSABLE!=='confirmed'||
    process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE!=='confirmed')
  fail('GENERATION_JOURNAL_NOT_RELEASED');
}
async function oneAttempt(client){
 try{return typeof client?.config?.maxAttempts==='function'&&
   (await client.config.maxAttempts())===1}
 catch{return false}
}
function sha(bytes){
 return createHash('sha256').update(bytes).digest('hex');
}
function safeRevision(x){
 return typeof x==='string'&&REV.test(x)&&BigInt(x)<=MAX;
}
function strictRecord(x,subject){
 if(!x||typeof x!=='object'||Array.isArray(x)||x.subject!==subject||
    !safeRevision(x.sequence)||!safeRevision(x.oauthRevision)||
    !safeRevision(x.credentialEpoch)||!safeRevision(x.saiRevision))
  fail('GENERATION_JOURNAL_TRANSITION_INVALID');
}
function validateTransition(previous,record){
 strictRecord(record,record.subject);
 if(!previous){
  if(record.sequence!=='1'||record.status!=='active'||
     record.previousSha256!==ZERO||
     record.preDenyReceiptSha256!==ZERO)
   fail('GENERATION_JOURNAL_TRANSITION_INVALID');
  return;
 }
 if(BigInt(record.sequence)!==BigInt(previous.record.sequence)+1n||
    record.previousSha256!==previous.sha256||
    record.epochSubject!==previous.record.epochSubject||
    record.operationId===previous.record.operationId||
    previous.record.status!=='active'||
    record.status!=='blocked'||
    record.grantSha256!==previous.record.grantSha256||
    record.scopeSha256!==previous.record.scopeSha256||
    record.ownerProofSha256!==previous.record.ownerProofSha256||
    record.oauthRevision!==previous.record.oauthRevision||
    record.credentialEpoch!==previous.record.credentialEpoch||
    record.saiRevision!==previous.record.saiRevision||
    record.preDenyReceiptSha256===ZERO)
  fail('GENERATION_JOURNAL_TRANSITION_INVALID');
}
async function boundedBody(body){
 if(Buffer.isBuffer(body)||body instanceof Uint8Array){
  if(body.length<32||body.length>1024)
   fail('GENERATION_JOURNAL_BODY_UNSAFE');
  return Buffer.from(body);
 }
 if(!body||typeof body[Symbol.asyncIterator]!=='function')
  fail('GENERATION_JOURNAL_BODY_UNSAFE');
 const chunks=[];let size=0;
 try{
  for await(const part of body){
   if(!(part instanceof Uint8Array))
    fail('GENERATION_JOURNAL_BODY_UNSAFE');
   size+=part.byteLength;
   if(size>1024)fail('GENERATION_JOURNAL_BODY_UNSAFE');
   chunks.push(Buffer.from(part));
  }
 }catch{fail('GENERATION_JOURNAL_BODY_UNSAFE')}
 if(size<32)fail('GENERATION_JOURNAL_BODY_UNSAFE');
 return Buffer.concat(chunks,size);
}
export function createDisposableGenerationWormJournal({
  provider,endpoint,approvedEndpoint=null,bucket,reader,writer,commands,
  clock=()=>Date.now(),fixtureOnly=false
}={}){
 gate(fixtureOnly);
 const required=['ListObjectVersionsCommand','GetObjectCommand','PutObjectCommand',
  'GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
  'HeadObjectCommand','GetObjectRetentionCommand'];
 if(!reader||!writer||reader===writer||
    typeof reader.send!=='function'||typeof writer.send!=='function'||
    required.some(n=>typeof commands?.[n]!=='function')||
    typeof clock!=='function')
  fail('GENERATION_JOURNAL_CONFIGURATION_UNSAFE');
 const base={provider,endpoint,approvedEndpoint,bucket,reader,commands,clock,
  minRetentionDays:400,minRemainingDays:30};
 async function send(name,args){
  try{
   return await reader.send(new commands[name]({Bucket:bucket,...args}),{
    abortSignal:globalThis.AbortSignal.timeout(7000)
   });
  }catch{fail('GENERATION_JOURNAL_REMOTE_UNAVAILABLE')}
 }
 async function scan(subject){
  gate(fixtureOnly);
  if(typeof subject!=='string'||!HEX.test(subject))
   fail('GENERATION_JOURNAL_SCOPE_INVALID');
  if(!(await oneAttempt(reader)))
   fail('GENERATION_JOURNAL_RETRY_UNSAFE');
  const policy=await inspectPortableS3ObjectLock(base);
  if(policy.releaseAccepted!==false||policy.configurationObserved!==true)
   fail('GENERATION_JOURNAL_POLICY_UNSAFE');
  const prefix=BASE+subject+'/';
  async function manifest(){
   const list=await send('ListObjectVersionsCommand',{
    Prefix:prefix,MaxKeys:64
   });
   if(list?.IsTruncated!==false||!Array.isArray(list.Versions)||
      !Array.isArray(list.DeleteMarkers??[])||
      (list.DeleteMarkers??[]).length!==0||
      !Array.isArray(list.CommonPrefixes??[])||
      (list.CommonPrefixes??[]).length!==0||
      list.Versions.length>LIMIT)
    fail('GENERATION_JOURNAL_HISTORY_INCOMPLETE');
   const result=list.Versions.map(v=>{
    const match=KEY.exec(v?.Key||'');
    if(!match||match[1]!==subject||
       match[2]==='0000000000000000000'||
       BigInt(match[2])>MAX||
       typeof v.VersionId!=='string'||!VERSION.test(v.VersionId)||
       v.VersionId==='null'||v.IsLatest!==true||
       !Number.isSafeInteger(v.Size)||v.Size<32||v.Size>1024)
     fail('GENERATION_JOURNAL_HISTORY_INVALID');
    return {key:v.Key,seq:BigInt(match[2]).toString(),
     versionId:v.VersionId,size:v.Size};
   }).sort((a,b)=>BigInt(a.seq)<BigInt(b.seq)?-1:
    BigInt(a.seq)>BigInt(b.seq)?1:0);
   for(let i=0;i<result.length;i++)
    if(result[i].seq!==(BigInt(i)+1n).toString())
     fail('GENERATION_JOURNAL_GAP_OR_FORK');
   return result;
  }
  const first=await manifest();
  const retained=[];
  for(const entry of first){
   const get=await send('GetObjectCommand',{
    Key:entry.key,VersionId:entry.versionId
   });
   if(get?.VersionId!==entry.versionId)
    fail('GENERATION_JOURNAL_VERSION_CHANGED');
   const bytes=await boundedBody(get.Body);
   if(bytes.length!==entry.size)
    fail('GENERATION_JOURNAL_BODY_UNSAFE');
   try{assertReceipt(entry.key,bytes)}
   catch{fail('GENERATION_JOURNAL_BODY_UNSAFE')}
   const record=JSON.parse(bytes.toString('utf8'));
   if(record.sequence!==entry.seq||record.subject!==subject)
    fail('GENERATION_JOURNAL_BODY_UNSAFE');
   const expectedSha=sha(bytes);
   let proof;
   try{proof=await inspectPortableS3ObjectLock({
    ...base,sample:{key:entry.key,sha256:expectedSha,versionId:entry.versionId}
   })}catch{fail('GENERATION_JOURNAL_OBJECT_UNVERIFIED')}
   if(proof.receiptVerified!==true||proof.releaseAccepted!==false||
      proof.payloadSha256!==expectedSha||proof.versionId!==entry.versionId)
    fail('GENERATION_JOURNAL_OBJECT_UNVERIFIED');
   const previous=retained.at(-1)||null;
   validateTransition(previous,record);
   retained.push(Object.freeze({record,sha256:expectedSha,
    versionId:entry.versionId}));
  }
  const second=await manifest();
  if(JSON.stringify(first)!==JSON.stringify(second))
   fail('GENERATION_JOURNAL_CHANGED_DURING_READ');
  if(retained.at(-1)?.record.status==='blocked')
   await checkPreDeny(retained.at(-1).record);
  // A fresh source-of-truth head requires a separately administered
  // high-water signer. The journal cannot certify absence of a hidden tail.
  return Object.freeze({
   observedGenerations:retained.length,
   head:retained.at(-1)||null,
   retainedBlocked:retained.at(-1)?.record.status==='blocked',
   activeAuthorizes:false,completeExternallyVerified:false,
   operatorIndependenceVerified:false,releaseAccepted:false
  });
 }
 async function checkPreDeny(record){
  let evidence;
  try{evidence=await inspectDisposablePortablePreDenyInventory({
   ...base,subject:record.subject,fixtureOnly:true
  })}catch{fail('GENERATION_JOURNAL_PRE_DENY_UNVERIFIED')}
  const r=evidence.retainedDenial;
  if(evidence.retainedDenialObserved!==true||
     evidence.absenceAuthorizes!==false||
     r?.subject!==record.subject||r?.revision!==record.oauthRevision||
     r?.grantSha256!==record.grantSha256||
     r?.operationId!==record.operationId||
     r?.receiptSha256!==record.preDenyReceiptSha256)
   fail('GENERATION_JOURNAL_PRE_DENY_UNVERIFIED');
 }
 async function append(record){
  gate(fixtureOnly);
  if(!(await oneAttempt(writer))||!(await oneAttempt(reader)))
   fail('GENERATION_JOURNAL_RETRY_UNSAFE');
  // Never choose owner, SAI or grant from a browser payload. The calling
  // independent operator must certify owner lifecycle before a genesis.
  // This candidate cannot authorize ACTIVE even when the record verifies.
  if(!record||typeof record!=='object'||Array.isArray(record)||
     typeof record.subject!=='string'||!HEX.test(record.subject))
   fail('GENERATION_JOURNAL_TRANSITION_INVALID');
  const key=BASE+record.subject+'/'+String(record.sequence).padStart(19,'0');
  const bytes=Buffer.from(JSON.stringify(record),'utf8');
  try{assertReceipt(key,bytes)}
  catch{fail('GENERATION_JOURNAL_TRANSITION_INVALID')}
  const before=await scan(record.subject);
  validateTransition(before.head,record);
  // Even genesis must check independent PRE-DENY to reject an old
  // active grant replay after canonical / witness / signer PITR.
  if(record.status==='blocked')await checkPreDeny(record);
  if(record.status==='active'){
   let evidence;
   try{evidence=await inspectDisposablePortablePreDenyInventory({
    ...base,subject:record.subject,fixtureOnly:true
   })}catch{fail('GENERATION_JOURNAL_PRE_DENY_UNVERIFIED')}
   if(evidence.retainedDenialObserved!==false||
      evidence.absenceAuthorizes!==false)
    fail('GENERATION_JOURNAL_PRE_DENY_UNVERIFIED');
  }
  let ack;
  try{ack=await writer.send(new commands.PutObjectCommand({
   Bucket:bucket,Key:key,Body:Buffer.from(bytes),IfNoneMatch:'*',
   ContentType:'application/octet-stream'
  }),{abortSignal:globalThis.AbortSignal.timeout(7000)})}
  catch{
   // Lost ACK OR 412 is ambiguous; NEVER retry. Reconcile from complete
   // independently read version history and immutable content only.
  }
  const after=await scan(record.subject);
  if(after.observedGenerations!==before.observedGenerations+1||
     after.head?.record.sequence!==record.sequence||
     after.head?.sha256!==sha(bytes)||
     (ack?.VersionId!==undefined&&
      ack.VersionId!==after.head.versionId))
   fail('GENERATION_JOURNAL_COMMIT_AMBIGUOUS');
  if(record.status==='blocked')await checkPreDeny(record);
  // A successful append does not prove S3 conditional-write race behavior,
  // independent operator custody or nonrewindable high-water. All results
  // are **evidence**, never an active token / PDS permit.
  return Object.freeze({
   observedGeneration:record.sequence,versionId:after.head.versionId,
   receiptSha256:after.head.sha256,
   retainedBlocked:after.retainedBlocked,activeAuthorizes:false,
   conditionalCreateOnlyVerified:false,externalHighWaterVerified:false,
   operatorIndependenceVerified:false,releaseAccepted:false
  });
 }
 return Object.freeze({inspect:scan,append,releaseAccepted:false});
}
