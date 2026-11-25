/**
 * NONACTIVATED WORM PRE-DENIAL staging only.
 *
 * The existing ActivityPods owner/credential/SAI reader derives all subject
 * fields from an authenticated browser. A portable COMPLIANCE writer retains
 * a canonical denial BEFORE ANY PG/Redis/Jena/Witness mutation.
 * A separately administered signer must acknowledge its latest retained
 * denial through an independently nonce-signed readback.
 *
 * Critically this adapter does NOT call a SQL revoker, touch Redis, update a
 * session, mint a code/token or authorize production. All OAuth/PDS/token
 * admission paths must consult that monotonic head BEFORE source activation.
 */
import crypto from 'node:crypto';
import {assertReceipt} from './oauth-s3-compliance-archive.mjs';
const SHA=/^[0-9a-f]{64}$/u;
const REV=/^[1-9][0-9]{0,18}$/u;
const GRANT=/^[A-Za-z0-9_-]{32}$/u;
const MAX=9223372036854775807n;
function refuse(code){
 const e=new Error('Pre-revocation immutable denial unavailable');
 e.code=code;
 throw e;
}
function gate(){
 if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_PRE_DENY_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_PORTABLE_WORM_DISPOSABLE!=='confirmed')
  refuse('PRE_DENY_NOT_RELEASED');
}
function https(x){
 if(typeof x!=='string'||x.length<8||x.length>2048)return false;
 try{
  const u=new URL(x);
  return u.protocol==='https:'&&!!u.hostname&&!u.username&&
   !u.password&&!u.search&&!u.hash&&u.href===x;
 }catch{return false}
}
function epoch(x){return typeof x==='string'&&REV.test(x)&&BigInt(x)<=MAX}
function valid(record,clientId,expectedGrantId){
 return record&&typeof record==='object'&&!Array.isArray(record)&&
  https(record.ownerWebId)&&record.clientId===clientId&&
  https(record.appUri)&&GRANT.test(record.grantId||'')&&
  record.grantId===expectedGrantId&&epoch(record.oauthRevision)&&
  epoch(record.saiRevision)&&epoch(record.credentialEpoch)&&
  SHA.test(record.scopeSha256||'');
}
function subjectHash(owner,client){
 return crypto.createHash('sha256').update('paper:witness:subject:v1\0')
  .update(owner).update('\0').update(client).digest('hex');
}
function operationId(subject,grantHash,revision){
 // Deterministic for EXACT owner/grant/revision: no unbounded duplicate
 // retained objects on an ambiguous lost ACK. Still require conditional
 // create-only enforcement by independent operator before production.
 const b=crypto.createHash('sha256')
  .update('paper:oauth:pre-deny:operation:v1\0')
  .update(subject).update('\0').update(grantHash).update('\0')
  .update(revision).digest().subarray(0,16);
 const v=Buffer.from(b);
 v[6]=(v[6]&0x0f)|0x40;
 v[8]=(v[8]&0x3f)|0x80;
 const h=v.toString('hex');
 return [h.slice(0,8),h.slice(8,12),h.slice(12,16),
  h.slice(16,20),h.slice(20)].join('-');
}
async function bounded(fn,ms){
 let timer;
 try{return await Promise.race([
  Promise.resolve().then(fn),
  new Promise((_,reject)=>{timer=setTimeout(
   ()=>reject(Error('Independent denial dependency timed out')),ms)})
 ])}finally{clearTimeout(timer)}
}
export function createDisposablePreDenyIntentCoordinator({
 ownerReader,portableWriter,headPublisher,signedHead,
 timeoutMs=15000,fixtureOnly=false
}={}){
 gate();
 if(fixtureOnly!==true||
    typeof ownerReader?.inspectForDeny!=='function'||
    typeof portableWriter?.putAndVerify!=='function'||
    typeof headPublisher?.publish!=='function'||
    typeof signedHead?.assertDenied!=='function'||
    !Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>20000)
  refuse('PRE_DENY_CONFIGURATION_UNSAFE');
 return Object.freeze({
  async retainBeforeMutation({context,clientId,expectedGrantId}={}){
   gate();
   if(!https(clientId)||!GRANT.test(expectedGrantId||''))
    refuse('PRE_DENY_SCOPE_INVALID');
   let r;
   try{
    r=await bounded(()=>ownerReader.inspectForDeny({
      context,clientId,expectedGrantId
    }),timeoutMs);
   }catch{refuse('PRE_DENY_OWNER_NOT_CURRENT')}
   if(!valid(r,clientId,expectedGrantId))
    refuse('PRE_DENY_OWNER_NOT_CURRENT');
   // No caller-controlled owner, app, revision, scope or operation id.
   const subject=subjectHash(r.ownerWebId,clientId);
   const grantSha256=crypto.createHash('sha256')
    .update(r.grantId,'utf8').digest('hex');
   const revision=r.oauthRevision;
   const op=operationId(subject,grantSha256,revision);
   const body=Buffer.from(JSON.stringify({
    kind:'paper.oauth.pre-deny.v1',subject,revision,operationId:op,
    grantSha256,credentialEpoch:r.credentialEpoch,
    saiRevision:r.saiRevision,scopeSha256:r.scopeSha256
   }),'utf8');
   const key='paper/oauth-witness/pre-deny/v1/'+subject+
    '/'+revision.padStart(19,'0')+'/'+op;
   try{assertReceipt(key,body)}
   catch{refuse('PRE_DENY_FORMAT_INVALID')}
   const sha256=crypto.createHash('sha256').update(body).digest('hex');
   let archived;
   try{
    archived=await bounded(()=>portableWriter.putAndVerify({
     key,bytes:Buffer.from(body)
    }),timeoutMs);
   }catch{
    // A lost conditional PUT ACK MAY already have committed. Never issue
    // an unbound second write or continue without independent confirmation.
    refuse('PRE_DENY_ARCHIVE_AMBIGUOUS');
   }
   if(archived?.key!==key||archived?.sha256!==sha256||
      archived?.contentVersionObserved!==true||
      archived?.retentionObserved!==true||
      archived?.releaseAccepted!==false||
      typeof archived?.versionId!=='string'||
      archived.versionId.length<1||archived.versionId.length>512)
    refuse('PRE_DENY_ARCHIVE_UNVERIFIED');

   const expected=Object.freeze({
    subject,grantSha256,revision,operationId:op,receiptSha256:sha256
   });
   try{
    // A separate signer MUST atomically reject any stale/rewound head,
    // publish a WORM-backed monotonic pre-deny high-water and never
    // permit ordinary app/primary/witness credentials to sign or clear.
    const published=await bounded(()=>headPublisher.publish(Object.freeze({
      ...expected,archiveKey:key,archiveVersion:archived.versionId
    })),timeoutMs);
    if(published!==true)refuse('PRE_DENY_HEAD_AMBIGUOUS');
   }catch{refuse('PRE_DENY_HEAD_AMBIGUOUS')}
   try{
    if(await bounded(()=>signedHead.assertDenied(expected),timeoutMs)!==true)
     refuse('PRE_DENY_HEAD_UNVERIFIED');
   }catch{refuse('PRE_DENY_HEAD_UNVERIFIED')}
   // This is a *retention-proof candidate*, not a revoke ACK. Until ALL
   // token/PDS/browser admission paths consult this head and the real
   // independent signer/custody are proven, no production mutation follows.
   return Object.freeze({
    retained:true,subject,revision,operationId:op,
    receiptSha256:sha256,archiveVersion:archived.versionId,
    releaseAccepted:false
   });
  }
 });
}
