/**
 * NONACTIVATED deny-first admission contract for all OAuth/PDS grant uses.
 * Does not sign, issue, authorize, revoke, authenticate or change state.
 *
 * Requires canonical ActivityPods state, an independent PG18 sealed witness,
 * the immutable epoch/archive evidence and a separately checkpointed
 * generation head. A public-only pinned Ed25519 verifier authenticates the
 * fresh, nonce-bound monotonic checkpoint.
 *
 * This is a test-only interface. An S3 version or a signed historical
 * statement is NOT nonrewindable on its own. A deployed independent,
 * monotonically advancing signer, genuine COMPLIANCE storage with separately
 * governed credentials, and a coordinated mutation fence remain release
 * prerequisites. No positive result returned here is a production permit.
 */
import crypto from 'node:crypto';
import {verifyDisposableSignedGenerationHighWater} from
 '../../independent-authority/signed-generation-high-water.mjs';
import {subjectHash} from './oauth-pre-deny-intent-coordinator.mjs';

const HEX=/^[a-f0-9]{64}$/u;
const REV=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const GRANT=/^[A-Za-z0-9_-]{32}$/u;
const AUTH=/^[a-z0-9._:-]{3,128}$/u;
const ZERO='0'.repeat(64);
const SURFACES=Object.freeze([
  'authorization-code-issue',
  'authorization-code-redeem',
  'access-token-sign',
  'access-token-introspect',
  'refresh-token-issue',
  'refresh-token-rotate',
  'refresh-token-introspect',
  'dpop-protected-resource',
  'signed-pds-reserve',
  'signed-pds-commit',
  'owner-consent-approve',
  'owner-consent-revoke',
  'owner-consent-replace',
  'owner-app-uninstall',
  'owner-grant-session-admit'
]);
const SUPPORTED=new Set(SURFACES);
function fail(code){
 const error=new Error('Independent OAuth/PDS denial authority unavailable');
 error.code=code;
 throw error;
}
function enabled(){
 if(process.env.NODE_ENV!=='test'||
    process.env.PAPER_OAUTH_PRE_DENY_ADMISSION_DISPOSABLE!=='confirmed'||
    process.env.PAPER_OAUTH_PRE_DENY_DISPOSABLE!=='confirmed'||
    process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE!=='confirmed'||
    process.env.PAPER_OAUTH_WITNESS_DISPOSABLE!=='confirmed'||
    process.env.PAPER_OAUTH_SIGNED_HIGHWATER_DISPOSABLE!=='confirmed')
   fail('OAUTH_DENIAL_NOT_RELEASED');
}
function https(x){
 if(typeof x!=='string'||x.length<8||x.length>2048)return false;
 try{
  const url=new URL(x);
  return url.protocol==='https:'&&!!url.hostname&&
   !url.username&&!url.password&&!url.search&&!url.hash&&
   url.href===x&&Buffer.byteLength(x,'utf8')===x.length;
 }catch{return false}
}
function epoch(x){return typeof x==='string'&&REV.test(x)&&BigInt(x)<=MAX;}
function same(a,b,fields){return fields.every(k=>a[k]===b[k]);}
function validGrant(x){
 return x&&typeof x==='object'&&!Array.isArray(x)&&
   x.authenticated===true&&
   https(x.ownerWebId)&&https(x.clientId)&&
   GRANT.test(x.grantId||'')&&HEX.test(x.scopeSha256||'')&&
   HEX.test(x.authProofSha256||'')&&
   epoch(x.oauthRevision)&&epoch(x.credentialEpoch)&&
   epoch(x.saiRevision);
}
const GRANT_FIELDS=[
 'ownerWebId','clientId','grantId','scopeSha256','authProofSha256',
 'oauthRevision','credentialEpoch','saiRevision'
];
function trustedGrant(x){
 if(!validGrant(x))fail('OAUTH_DENIAL_AUTHENTICATION_INVALID');
 return Object.freeze(Object.fromEntries(GRANT_FIELDS.map(k=>[k,x[k]])));
}
function validState(x,subject,epochSubject,grantSha256,revision){
 return x&&typeof x==='object'&&!Array.isArray(x)&&
  x.subject===subject&&x.epochSubject===epochSubject&&
  x.grantSha256===grantSha256&&
  x.revision===revision&&HEX.test(x.witnessEventSha256||'')&&
  HEX.test(x.receiptSha256||'')&&UUID.test(x.operationId||'')&&
  ['active','blocked'].includes(x.status);
}
function pgGrant(x,r){
 return x&&typeof x==='object'&&!Array.isArray(x)&&
   x.state==='active'&&same(x,r,GRANT_FIELDS.filter(k=>k!=='authProofSha256'));
}
function witnessState(x,subject,epochSubject,grantHash,revision){
 return validState(x,subject,epochSubject,grantHash,revision);
}
function archiveState(x,subject,epochSubject,grantHash,revision){
 return validState(x,subject,epochSubject,grantHash,revision)&&
   x.receiptVerified===true&&x.retentionVerified===true&&
   x.versionHistoryComplete===true&&x.latestConfirmed===true&&
   typeof x.archiveVersion==='string'&&x.archiveVersion.length>=1&&
   x.archiveVersion.length<=512&&
   !Array.from(x.archiveVersion).some(ch=>ch.codePointAt(0)<=32||
     ch.codePointAt(0)===127);
}
const GENERATION_FIELDS=[
 'subject','epochSubject','sequence','status','headSha256','previousSha256',
 'grantSha256','scopeSha256','ownerProofSha256','oauthRevision',
 'credentialEpoch','saiRevision','operationId','preDenyReceiptSha256',
 'objectVersion'
];
const GENERATION_RECORD_FIELDS=[
 'kind','subject','epochSubject','sequence','status','grantSha256',
 'scopeSha256','ownerProofSha256','oauthRevision','credentialEpoch',
 'saiRevision','operationId','previousSha256','preDenyReceiptSha256'
];
function generationState(e,r,subject,epochSubject,grantSha256){
 const h=e?.head,record=h?.record;
 if(!e||e.releaseAccepted!==false||e.activeAuthorizes!==false||
    e.completeExternallyVerified!==false||
    e.operatorIndependenceVerified!==false||
    e.retainedBlocked!==false||e.observedGenerations!==1||
    !h||!record||typeof record!=='object'||Array.isArray(record)||
    Object.keys(record).sort().join(',')!==
      [...GENERATION_RECORD_FIELDS].sort().join(',')||
    record.kind!=='paper.oauth.authority-generation.v1'||
    record.subject!==subject||record.epochSubject!==epochSubject||
    record.sequence!=='1'||record.status!=='active'||
    h.sha256?.match(HEX)?.[0]!==h.sha256||
    typeof h.versionId!=='string'||h.versionId.length<1||
    h.versionId.length>512||h.versionId==='null'||
    [...h.versionId].some(ch=>ch.codePointAt(0)<=32||
      ch.codePointAt(0)===127)||
    record.previousSha256!==ZERO||record.grantSha256!==grantSha256||
    record.scopeSha256!==r.scopeSha256||
    record.ownerProofSha256!==r.authProofSha256||
    record.oauthRevision!==r.oauthRevision||
    record.credentialEpoch!==r.credentialEpoch||
    record.saiRevision!==r.saiRevision||
    !UUID.test(record.operationId||'')||
    record.preDenyReceiptSha256!==ZERO)
  return null;
 return Object.freeze({
  subject,epochSubject,sequence:record.sequence,status:record.status,
  headSha256:h.sha256,previousSha256:record.previousSha256,
  grantSha256,scopeSha256:record.scopeSha256,
  ownerProofSha256:record.ownerProofSha256,
  oauthRevision:record.oauthRevision,
  credentialEpoch:record.credentialEpoch,saiRevision:record.saiRevision,
  operationId:record.operationId,
  preDenyReceiptSha256:record.preDenyReceiptSha256,
  objectVersion:h.versionId
 });
}
async function limited(task,timeoutMs){
 const controller=new AbortController();
 let timer;
 try{
  return await Promise.race([
   Promise.resolve().then(()=>task(controller.signal)),
   new Promise((_,reject)=>{timer=setTimeout(
    ()=>reject(Error('Independent denial read exceeded time budget')),
    timeoutMs)})
  ]);
 }finally{clearTimeout(timer);controller.abort();}
}
export const DENIAL_SURFACES=SURFACES;
export function createDisposableIndependentPreDenyAdmission({
 authenticateGrant,readCanonical,readWitness,readLatestArchive,
 readGenerationHead,readPreDenyInventory=null,readSignedHead,
 trustedPublicKeys,minimumKeyEpoch='1',authority,
 now=()=>Math.floor(Date.now()/1000),
 timeoutMs=2500,fixtureOnly=false
}={}){
 enabled();
 if(fixtureOnly!==true||
    typeof authenticateGrant!=='function'||
    typeof readCanonical!=='function'||typeof readWitness!=='function'||
    typeof readLatestArchive!=='function'||
    typeof readGenerationHead!=='function'||typeof readSignedHead!=='function'||
    new Set([authenticateGrant,readCanonical,readWitness,
      readLatestArchive,readGenerationHead,readSignedHead]).size!==6||
    typeof now!=='function'||!AUTH.test(authority||'')||
    !Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>5000)
  fail('OAUTH_DENIAL_CONFIGURATION_INVALID');
 // When the concrete portable S3 pre-deny inventory is supplied, insist on
 // a distinct independently credentialed read capability. Its ABSENCE is
 // NEVER an allow, and even observed absence cannot override signed-head
 // and writer-reservation requirements.
 const inventoryFlag=process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE;
 if((inventoryFlag!==undefined||readPreDenyInventory!==null)&&
    (inventoryFlag!=='confirmed'||
     typeof readPreDenyInventory!=='function'||
     [authenticateGrant,readCanonical,readWitness,readLatestArchive,
      readGenerationHead,readSignedHead].includes(readPreDenyInventory)))
  fail('OAUTH_DENIAL_INVENTORY_CONFIG_INVALID');
 const inventoryEnabled=inventoryFlag==='confirmed';
 async function independentRead(fn,record,code){
  let result;
  try{result=await limited(signal=>fn(Object.freeze({...record,signal})),
    timeoutMs);}
  catch{fail(code)}
  return result;
 }
 async function vetoArchivedDeny(probe){
  if(!inventoryEnabled)return;
  if(process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE!=='confirmed')
   fail('OAUTH_DENIAL_INVENTORY_NOT_RELEASED');
  // The external archive reader needs only the hashed subject. Never pass
  // owner WebID, OAuth grant, scopes, credential epoch or browser context.
  const evidence=await independentRead(readPreDenyInventory,
   Object.freeze({subject:probe.subject}),
   'OAUTH_DENIAL_INVENTORY_UNAVAILABLE');
  if(!evidence||evidence.releaseAccepted!==false||
     evidence.absenceAuthorizes!==false||
     ![true,false].includes(evidence.retainedDenialObserved))
   fail('OAUTH_DENIAL_INVENTORY_UNSAFE');
  if(evidence.retainedDenialObserved===true)
   fail('OAUTH_DENIAL_RETAINED_PRE_DENY');
 }
 return Object.freeze({
  releaseAccepted:false,
  async inspect({surface,context}={}){
   enabled();
   if(!SUPPORTED.has(surface)||typeof context!=='object'||!context)
    fail('OAUTH_DENIAL_SURFACE_INVALID');
   let r;
   try{r=trustedGrant(await limited(signal=>authenticateGrant({
    context, surface,signal
   }),timeoutMs));}
   catch{fail('OAUTH_DENIAL_AUTHENTICATION_INVALID')}
   // Epoch v1 Object Lock receipts use NUL-separated subject bytes;
   // signed-write v5 and new PRE-DENY use SQL length framing. Both must
   // be attested; conflating the two lets a stale epoch look current.
   const epochSubject=crypto.createHash('sha256')
    .update('paper:witness:subject:v1\0').update(r.ownerWebId)
    .update('\0').update(r.clientId).digest('hex');
   const subject=subjectHash(r.ownerWebId,r.clientId);
   if(subject===epochSubject)
    fail('OAUTH_DENIAL_SUBJECT_DOMAIN_INVALID');
   const grantSha256=crypto.createHash('sha256')
    .update(r.grantId,'utf8').digest('hex');
   const probe=Object.freeze({
    ownerWebId:r.ownerWebId,clientId:r.clientId,
    grantId:r.grantId,scopeSha256:r.scopeSha256,
    oauthRevision:r.oauthRevision,credentialEpoch:r.credentialEpoch,
    saiRevision:r.saiRevision,subject,epochSubject,grantSha256,surface
   });
   const firstCanonical=await independentRead(readCanonical,probe,
    'OAUTH_DENIAL_CANONICAL_UNAVAILABLE');
   if(!pgGrant(firstCanonical,r))
    fail('OAUTH_DENIAL_CANONICAL_STALE');
   const firstWitness=await independentRead(readWitness,probe,
    'OAUTH_DENIAL_WITNESS_UNAVAILABLE');
   if(!witnessState(firstWitness,subject,epochSubject,
      grantSha256,r.oauthRevision)||
      firstWitness.status!=='active')
    fail('OAUTH_DENIAL_WITNESS_STALE');
   await vetoArchivedDeny(probe);
   const archive=await independentRead(readLatestArchive,probe,
    'OAUTH_DENIAL_ARCHIVE_UNAVAILABLE');
   if(!archiveState(archive,subject,epochSubject,
      grantSha256,r.oauthRevision))
    fail('OAUTH_DENIAL_ARCHIVE_INVALID');
   if(archive.status!=='active')
    fail('OAUTH_DENIAL_BLOCKED');
   if(!same(firstWitness,archive,
    ['status','subject','epochSubject','grantSha256','revision',
     'witnessEventSha256','receiptSha256','operationId']))
    fail('OAUTH_DENIAL_ARCHIVE_STALE');
   const firstGenerationEvidence=await independentRead(readGenerationHead,probe,
    'OAUTH_DENIAL_GENERATION_UNAVAILABLE');
   const firstGeneration=generationState(firstGenerationEvidence,r,
    subject,epochSubject,grantSha256);
   if(!firstGeneration)
    fail('OAUTH_DENIAL_GENERATION_INVALID');
   const nonce=crypto.randomBytes(32).toString('base64url');
   let signature;
   try{
    signature=await limited(signal=>readSignedHead(Object.freeze({
      kind:'paper.oauth.generation-high-water.challenge.v1',
      subject,nonce,surface,signal
    })),timeoutMs);
   }catch{fail('OAUTH_DENIAL_SIGNER_UNAVAILABLE')}
   let signed;
   try{signed=verifyDisposableSignedGenerationHighWater({
    reply:signature,nonce,expected:firstGeneration,authority,
    trustedPublicKeys,minimumKeyEpoch,now,fixtureOnly:true
   })}catch{fail('OAUTH_DENIAL_HIGH_WATER_INVALID')}
   // A signed BLOCKED or mismatching response cannot authorize an old
   // JWT, DPoP proof, refresh family or signed repository write.
   if(signed.status!=='active')
    fail('OAUTH_DENIAL_BLOCKED');
   if(signed.status!==archive.status||
      signed.oauthRevision!==archive.revision)
    fail('OAUTH_DENIAL_SIGNER_STALE');

   const secondCanonical=await independentRead(readCanonical,probe,
    'OAUTH_DENIAL_CANONICAL_UNAVAILABLE');
   if(!pgGrant(secondCanonical,r)||
      !same(firstCanonical,secondCanonical,
       GRANT_FIELDS.filter(k=>k!=='authProofSha256').concat('state')))
    fail('OAUTH_DENIAL_CANONICAL_STALE');
   const secondWitness=await independentRead(readWitness,probe,
    'OAUTH_DENIAL_WITNESS_UNAVAILABLE');
   if(!witnessState(secondWitness,subject,epochSubject,
      grantSha256,r.oauthRevision)||
      !same(firstWitness,secondWitness,[
       'status','subject','epochSubject','grantSha256','revision',
       'witnessEventSha256','receiptSha256','operationId'])||
      secondWitness.status!=='active')
    fail('OAUTH_DENIAL_WITNESS_STALE');
   const finalArchive=await independentRead(readLatestArchive,probe,
    'OAUTH_DENIAL_ARCHIVE_UNAVAILABLE');
   if(!archiveState(finalArchive,subject,epochSubject,
      grantSha256,r.oauthRevision)||
      !same(archive,finalArchive,[
       'status','subject','epochSubject','grantSha256','revision',
       'witnessEventSha256','receiptSha256','operationId',
       'archiveVersion'])||finalArchive.status!=='active')
    fail('OAUTH_DENIAL_ARCHIVE_STALE');
   const finalGenerationEvidence=await independentRead(readGenerationHead,probe,
    'OAUTH_DENIAL_GENERATION_UNAVAILABLE');
   const finalGeneration=generationState(finalGenerationEvidence,r,
    subject,epochSubject,grantSha256);
   if(!finalGeneration||!same(firstGeneration,finalGeneration,
      GENERATION_FIELDS))
    fail('OAUTH_DENIAL_GENERATION_STALE');
   // Recheck retained denial after independent archive and signer network
   // reads; a pre-deny found in either scan vetoes even restored PG state.
   await vetoArchivedDeny(probe);
   let last;
   try{last=trustedGrant(await limited(signal=>authenticateGrant({
    context,surface,signal
   }),timeoutMs));}
   catch{fail('OAUTH_DENIAL_AUTHENTICATION_INVALID')}
   if(!same(r,last,GRANT_FIELDS))
    fail('OAUTH_DENIAL_AUTHENTICATION_STALE');
   // This snapshot is useful for discovering mismatches, NOT a permit
   // to issue a code, access JWT, refresh, or commit a PDS write. Those
   // require the independent writer's durable reservation and canonical
   // transaction lock to serialize a concurrent pre-denial publication.
   return Object.freeze({
    checked:true,surface,subject,
    oauthRevision:r.oauthRevision,
    generationSequence:firstGeneration.sequence,
    generationHeadSha256:firstGeneration.headSha256,
    witnessEventSha256:archive.witnessEventSha256,
    releaseAccepted:false
   });
  }
 });
}
