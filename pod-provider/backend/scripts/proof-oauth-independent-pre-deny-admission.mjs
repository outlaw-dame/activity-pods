/** NONACTIVATED, deterministic adversarial current-head admission proof. */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {DENIAL_SURFACES,createDisposableIndependentPreDenyAdmission} from
 '../candidates/oauth-independent-pre-deny-admission.mjs';
import {subjectHash} from '../candidates/oauth-pre-deny-intent-coordinator.mjs';
import {SIGNED_GENERATION_HIGH_WATER_DOMAIN} from
 '../../independent-authority/signed-generation-high-water.mjs';

if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_PRE_DENY_ADMISSION_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_PRE_DENY_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_WITNESS_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_SIGNED_HIGHWATER_DISPOSABLE!=='confirmed')
 throw Error('Refusing nondisposable independent pre-deny admission proof');

const OWNER='https://paper.example.org/users/admission-owner';
const OTHER='https://paper.example.org/users/other';
const CLIENT='https://paper-client.example.org/oauth';
const GRANT='p'.repeat(32);
const SCOPE='9'.repeat(64);
const AUTH_PROOF='a'.repeat(64);
const REVISION='7';
const FIXED_TIME=1800000000;
const SUBJECT=subjectHash(OWNER,CLIENT);
const EPOCH_SUBJECT=crypto.createHash('sha256')
 .update('paper:witness:subject:v1\0').update(OWNER)
 .update('\0').update(CLIENT).digest('hex');
const GRANT_HASH=crypto.createHash('sha256').update(GRANT).digest('hex');
const EVENT='e'.repeat(64);
const RECEIPT='f'.repeat(64);
const OPERATION='a7d75d7d-403a-4940-8e42-f5c352eef572';
const GENERATION_OPERATION='b8e86e8e-514b-4a51-9f53-1b5d463f0683';
const GENERATION_HEAD='1'.repeat(64);
const ZERO='0'.repeat(64);
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
const denied=(fn,code)=>assert.rejects(fn,e=>e?.code===code,
  'Expected fail-closed error '+code);
const baseGrant=()=>({
 authenticated:true,ownerWebId:OWNER,clientId:CLIENT,
 grantId:GRANT,scopeSha256:SCOPE,authProofSha256:AUTH_PROOF,
 oauthRevision:REVISION,saiRevision:'4',credentialEpoch:'11'
});
const baseEvent=()=>({
 status:'active',subject:SUBJECT,epochSubject:EPOCH_SUBJECT,
 grantSha256:GRANT_HASH,
 revision:REVISION,witnessEventSha256:EVENT,
 receiptSha256:RECEIPT,operationId:OPERATION
});
const baseGeneration=()=>({
 observedGenerations:1,activeAuthorizes:false,
 completeExternallyVerified:false,operatorIndependenceVerified:false,
 retainedBlocked:false,releaseAccepted:false,
 head:{
  sha256:GENERATION_HEAD,versionId:'generation-object-v1',
  record:{kind:'paper.oauth.authority-generation.v1',
   subject:SUBJECT,epochSubject:EPOCH_SUBJECT,sequence:'1',status:'active',
   grantSha256:GRANT_HASH,scopeSha256:SCOPE,
   ownerProofSha256:AUTH_PROOF,oauthRevision:REVISION,
   credentialEpoch:'11',saiRevision:'4',operationId:GENERATION_OPERATION,
   previousSha256:ZERO,preDenyReceiptSha256:ZERO}
 }
});
function fixture(faults={}){
 const hits={authenticate:0,canonical:0,witness:0,archive:0,generation:0,signer:0,
  sideEffects:0};
 const env={...faults,rewound:false};
 let cachedResponse=null;
 let lastGeneration=baseGeneration();
 const authenticateGrant=async()=>{
  hits.authenticate++;
  if(env.authOffline)throw Error('Owner/token proof unavailable');
  if(env.malformedAuth)return {...baseGrant(),authenticated:false};
  const g=baseGrant();
  if(env.ownerDrift&&hits.authenticate>1)g.ownerWebId=OTHER;
  if(env.authDrift&&hits.authenticate>1)
   g.authProofSha256='b'.repeat(64);
  if(env.credentialDrift&&hits.authenticate>1)g.credentialEpoch='12';
  return g;
 };
 const readCanonical=async()=>{
  hits.canonical++;
  if(env.pgOffline)throw Error('Canonical PG unavailable');
  const g=baseGrant();
  delete g.authenticated;delete g.authProofSha256;
  if(env.pgStale)g.oauthRevision='6';
  if(env.pgRevoked||env.pgRevokedOnRead===hits.canonical)
    g.state='blocked';
  else g.state='active';
  if(env.saiDrift&&hits.canonical>1)g.saiRevision='5';
  return g;
 };
 const readWitness=async()=>{
  hits.witness++;
  if(env.witnessOffline)throw Error('PG18 witness unavailable');
  const event=baseEvent();
  if(env.witnessRevoked||env.witnessRevokedOnRead===hits.witness)
   event.status='blocked';
  if(env.witnessRewind)event.revision='6';
  if(env.witnessWrongEpochSubject)event.epochSubject='0'.repeat(64);
  if(env.witnessEventDrift&&hits.witness>1)
   event.witnessEventSha256='1'.repeat(64);
  return event;
 };
 const readLatestArchive=async()=>{
  hits.archive++;
  if(env.archiveOffline)throw Error('WORM readback unavailable');
  if(env.archiveHang)return await new Promise(()=>{});
  const event={...baseEvent(),receiptVerified:true,
   retentionVerified:true,versionHistoryComplete:true,
   latestConfirmed:true,archiveVersion:'opaque-v1'};
  if(env.archiveRevoked||env.archiveRevokedOnRead===hits.archive)
   event.status='blocked';
  if(env.archiveRewind)event.revision='6';
  if(env.archiveWrongEpochSubject)event.epochSubject='0'.repeat(64);
  if(env.historyTruncated)event.versionHistoryComplete=false;
  if(env.archiveRetentionLost)event.retentionVerified=false;
  if(env.archiveVersionDrift&&hits.archive>1)
   event.archiveVersion='opaque-v2';
  if(env.archiveDigestDrift)event.receiptSha256='0'.repeat(64);
  return event;
 };
 const readGenerationHead=async()=>{
  hits.generation++;
  if(env.generationOffline)throw Error('generation journal unavailable');
  const result=structuredClone(baseGeneration());
  if(env.generationBlocked)result.head.record.status='blocked';
  if(env.generationStale)result.head.record.oauthRevision='6';
  if(env.generationHiddenTail)result.observedGenerations=2;
  if(env.generationOwnerProofDrift)
   result.head.record.ownerProofSha256='2'.repeat(64);
  if(env.generationDrift&&hits.generation>1)
   result.head.sha256='2'.repeat(64);
  lastGeneration=result;
  return result;
 };
 const readSignedHead=async({nonce})=>{
  hits.signer++;
  if(env.signerOffline)throw Error('Independent signer unavailable');
  const g=lastGeneration.head;
  const payload={
   kind:'paper.oauth.generation-high-water.v1',
   authority:'independent-signing.test',keyId:'kms-key-v1',keyEpoch:'1',
   subject:g.record.subject,epochSubject:g.record.epochSubject,
   sequence:g.record.sequence,status:g.record.status,
   headSha256:g.sha256,previousSha256:g.record.previousSha256,
   grantSha256:g.record.grantSha256,scopeSha256:g.record.scopeSha256,
   ownerProofSha256:g.record.ownerProofSha256,
   oauthRevision:g.record.oauthRevision,
   credentialEpoch:g.record.credentialEpoch,saiRevision:g.record.saiRevision,
   operationId:g.record.operationId,
   preDenyReceiptSha256:g.record.preDenyReceiptSha256,
   objectVersion:g.versionId,nonce,issuedAt:FIXED_TIME
  };
  if(env.signerOldRevision)payload.oauthRevision='6';
  if(env.signerWrongSubject)payload.subject='0'.repeat(64);
  if(env.signerWrongEpochSubject)payload.epochSubject='0'.repeat(64);
  if(env.signerWrongGrant)payload.grantSha256='2'.repeat(64);
  if(env.signerWrongNonce)payload.nonce='q'.repeat(43);
  if(env.signerOldClock)payload.issuedAt=FIXED_TIME-180;
  if(env.signerNewClock)payload.issuedAt=FIXED_TIME+180;
  if(env.signerBlocked)payload.status='blocked';
  if(env.signerExtraField)payload.extra='untrusted';
  const body=env.signerNoncanonical?
   Buffer.from(JSON.stringify(payload,null,2)):Buffer.from(JSON.stringify(payload));
  if(env.signerReplay&&cachedResponse)return cachedResponse;
  const key=env.signerWrongKey?
   crypto.generateKeyPairSync('ed25519').privateKey:privateKey;
  const response={body,signature:crypto.sign(null,
   Buffer.concat([SIGNED_GENERATION_HIGH_WATER_DOMAIN,body]),key)};
  if(env.signerReplay)cachedResponse=response;
  return response;
 };
 const args={
  authenticateGrant,readCanonical,readWitness,
  readLatestArchive,readGenerationHead,readSignedHead,
  trustedPublicKeys:[{keyId:'kms-key-v1',keyEpoch:'1',publicKey}],
  minimumKeyEpoch:'1',authority:'independent-signing.test',
  fixtureOnly:true,now:()=>FIXED_TIME,timeoutMs:150
 };
 const gate=createDisposableIndependentPreDenyAdmission(args);
 const check=(surface='access-token-introspect',context={})=>
  gate.inspect({surface,context});
 return {gate,check,hits,env,args};
}
test('historical epoch and signed-write pre-deny subjects are independent cryptographic domains',()=>{
 assert.notEqual(EPOCH_SUBJECT,SUBJECT);
 assert.equal(SUBJECT,crypto.createHash('sha256').update(
  'paper:witness:subject:v1:'+OWNER.length+':'+OWNER+':'+CLIENT).digest('hex'));
 assert.equal(EPOCH_SUBJECT,crypto.createHash('sha256')
  .update('paper:witness:subject:v1\0').update(OWNER)
  .update('\0').update(CLIENT).digest('hex'));
});
test('all 15 grant-consuming surfaces require current independently signed authority',async()=>{
 assert.equal(DENIAL_SURFACES.length,15);
 assert.equal(new Set(DENIAL_SURFACES).size,DENIAL_SURFACES.length);
 for(const surface of DENIAL_SURFACES){
  const f=fixture();
  const result=await f.check(surface,{
   // This JSON is a decoy; the trusted server callback never selects
   // the owner from the request's custom account identifier.
   ownerWebId:OTHER,clientId:'https://attacker.example.org/oauth',
   grantId:'z'.repeat(32),scopeSha256:'0'.repeat(64)
  });
  assert.equal(result.checked,true);
  assert.equal(result.surface,surface);
  assert.equal(result.subject,SUBJECT);
  assert.equal(result.oauthRevision,REVISION);
  assert.equal(result.generationSequence,'1');
  assert.equal(result.generationHeadSha256,GENERATION_HEAD);
  assert.equal(result.releaseAccepted,false);
  assert.deepEqual(f.hits,{
   authenticate:2,canonical:2,witness:2,archive:2,generation:2,signer:1,
   sideEffects:0
  });
 }
});
test('archive verified blocked state denies every grant-consuming surface',async()=>{
 for(const surface of DENIAL_SURFACES){
  const f=fixture({archiveRevoked:true});
  await denied(()=>f.check(surface),'OAUTH_DENIAL_BLOCKED');
  assert.equal(f.hits.signer,0);
  assert.equal(f.hits.sideEffects,0);
 }
});
test('no direct production activation, unrecognized surfaces or missing proof',async()=>{
 const f=fixture();
 await denied(()=>f.check('oauth.test.run'),
  'OAUTH_DENIAL_SURFACE_INVALID');
 await denied(()=>f.gate.inspect({surface:'access-token-sign',context:null}),
  'OAUTH_DENIAL_SURFACE_INVALID');
 const prior=process.env.NODE_ENV;
 process.env.NODE_ENV='production';
 try{
  await denied(()=>f.check('access-token-sign'),
   'OAUTH_DENIAL_NOT_RELEASED');
  assert.throws(()=>createDisposableIndependentPreDenyAdmission(f.args),
   e=>e?.code==='OAUTH_DENIAL_NOT_RELEASED');
 }finally{process.env.NODE_ENV=prior}
 assert.equal(f.hits.sideEffects,0);
});
test('missing or revoked canonical PG/SAI denies before signed-head call',async()=>{
 for(const [faults,code] of [
  [{pgOffline:true},'OAUTH_DENIAL_CANONICAL_UNAVAILABLE'],
  [{pgStale:true},'OAUTH_DENIAL_CANONICAL_STALE'],
  [{pgRevoked:true},'OAUTH_DENIAL_CANONICAL_STALE'],
  [{malformedAuth:true},'OAUTH_DENIAL_AUTHENTICATION_INVALID'],
  [{authOffline:true},'OAUTH_DENIAL_AUTHENTICATION_INVALID']
 ]){
  const f=fixture(faults);
  await denied(()=>f.check(),code);
  assert.equal(f.hits.signer,0);
 }
});
test('stale witness or unavailable independent recovery witness denies',async()=>{
 for(const [faults,code] of [
  [{witnessOffline:true},'OAUTH_DENIAL_WITNESS_UNAVAILABLE'],
  [{witnessRevoked:true},'OAUTH_DENIAL_WITNESS_STALE'],
  [{witnessRewind:true},'OAUTH_DENIAL_WITNESS_STALE'],
  [{witnessWrongEpochSubject:true},'OAUTH_DENIAL_WITNESS_STALE']
 ]){
  const f=fixture(faults);
  await denied(()=>f.check(),code);
  assert.equal(f.hits.signer,0);
 }
});
test('missing, incomplete or rewound WORM history prevents signer consultation',async()=>{
 for(const [faults,code] of [
  [{archiveOffline:true},'OAUTH_DENIAL_ARCHIVE_UNAVAILABLE'],
  [{archiveRewind:true},'OAUTH_DENIAL_ARCHIVE_INVALID'],
  [{historyTruncated:true},'OAUTH_DENIAL_ARCHIVE_INVALID'],
  [{archiveRetentionLost:true},'OAUTH_DENIAL_ARCHIVE_INVALID'],
  [{archiveDigestDrift:true},'OAUTH_DENIAL_ARCHIVE_STALE'],
  [{archiveWrongEpochSubject:true},'OAUTH_DENIAL_ARCHIVE_INVALID']
 ]){
  const f=fixture(faults);
  await denied(()=>f.check(),code);
  assert.equal(f.hits.signer,0);
 }
});
test('Ed25519 signer must be current, correctly scoped, nonreplayed and public-key-only',async()=>{
 for(const [faults,code] of [
  [{signerOffline:true},'OAUTH_DENIAL_SIGNER_UNAVAILABLE'],
  [{signerWrongKey:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerOldRevision:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerWrongSubject:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerWrongEpochSubject:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerWrongGrant:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerWrongNonce:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerOldClock:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerNewClock:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerExtraField:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerNoncanonical:true},'OAUTH_DENIAL_HIGH_WATER_INVALID'],
  [{signerBlocked:true},'OAUTH_DENIAL_HIGH_WATER_INVALID']
 ]){
  const f=fixture(faults);
  await denied(()=>f.check(),code);
  assert.equal(f.hits.sideEffects,0);
 }
 const f=fixture({signerReplay:true});
 await f.check();
 await denied(()=>f.check(),'OAUTH_DENIAL_HIGH_WATER_INVALID');
 const unsafe=createDisposableIndependentPreDenyAdmission({
  ...f.args,trustedPublicKeys:[{
   keyId:'kms-key-v1',keyEpoch:'1',publicKey:privateKey
  }]
 });
 await denied(()=>unsafe.inspect({surface:'access-token-sign',context:{}}),
  'OAUTH_DENIAL_HIGH_WATER_INVALID');
});
test('generation journal must bind live owner proof and remain stable around signing',async()=>{
 for(const [faults,code] of [
  [{generationOffline:true},'OAUTH_DENIAL_GENERATION_UNAVAILABLE'],
  [{generationBlocked:true},'OAUTH_DENIAL_GENERATION_INVALID'],
  [{generationStale:true},'OAUTH_DENIAL_GENERATION_INVALID'],
  [{generationHiddenTail:true},'OAUTH_DENIAL_GENERATION_INVALID'],
  [{generationOwnerProofDrift:true},'OAUTH_DENIAL_GENERATION_INVALID'],
  [{generationDrift:true},'OAUTH_DENIAL_GENERATION_STALE']
 ]){
  const f=fixture(faults);
  await denied(()=>f.check(),code);
  assert.equal(f.hits.sideEffects,0);
 }
});
test('logout, credential rotation, canonical revoke and witness revoke during reads deny',async()=>{
 for(const [faults,code] of [
  [{ownerDrift:true},'OAUTH_DENIAL_AUTHENTICATION_STALE'],
  [{authDrift:true},'OAUTH_DENIAL_AUTHENTICATION_STALE'],
  [{credentialDrift:true},'OAUTH_DENIAL_AUTHENTICATION_STALE'],
  [{pgRevokedOnRead:2},'OAUTH_DENIAL_CANONICAL_STALE'],
  [{saiDrift:true},'OAUTH_DENIAL_CANONICAL_STALE'],
  [{witnessRevokedOnRead:2},'OAUTH_DENIAL_WITNESS_STALE'],
  [{witnessEventDrift:true},'OAUTH_DENIAL_WITNESS_STALE'],
  [{archiveRevokedOnRead:2},'OAUTH_DENIAL_ARCHIVE_STALE'],
  [{archiveVersionDrift:true},'OAUTH_DENIAL_ARCHIVE_STALE']
 ]){
  const f=fixture(faults);
  await denied(()=>f.check(),code);
  assert.equal(f.hits.sideEffects,0);
 }
});
test('bounded unavailable immutable archive fails closed and cannot mint',async()=>{
 const f=fixture({archiveHang:true});
 await denied(()=>f.check(),'OAUTH_DENIAL_ARCHIVE_UNAVAILABLE');
 assert.equal(f.hits.signer,0);
 assert.equal(f.hits.sideEffects,0);
});
test('reject swapped identities for independently supplied callbacks and keys',()=>{
 const f=fixture();
 assert.throws(()=>createDisposableIndependentPreDenyAdmission({
  ...f.args,readWitness:f.args.readCanonical
 }),e=>e?.code==='OAUTH_DENIAL_CONFIGURATION_INVALID');
 assert.throws(()=>createDisposableIndependentPreDenyAdmission({
  ...f.args,timeoutMs:30000
 }),e=>e?.code==='OAUTH_DENIAL_CONFIGURATION_INVALID');
 const invalid=createDisposableIndependentPreDenyAdmission({
  ...f.args,trustedPublicKeys:[{
   keyId:'kms-key-v1',keyEpoch:'1',publicKey:'not a real public key'
  }]
 });
 assert.rejects(()=>invalid.inspect({surface:'access-token-sign',context:{}}),
  e=>e?.code==='OAUTH_DENIAL_HIGH_WATER_INVALID');
});


test('independent S3 retained PRE-DENY vetoes rewound active grant before and after signer',async()=>{
 const f=fixture(); // Existing authenticated/canonical/witness/signer fixture.
 const examples=Array.from({length:4},()=>fixture());
 const ok=fixture();
 const prior=process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE;
 process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE='confirmed';
 try{
  assert.throws(()=>createDisposableIndependentPreDenyAdmission(f.args),
   e=>e?.code==='OAUTH_DENIAL_INVENTORY_CONFIG_INVALID');
  const cases=[
   {seenAt:1,code:'OAUTH_DENIAL_RETAINED_PRE_DENY',signer:0},
   {seenAt:2,code:'OAUTH_DENIAL_RETAINED_PRE_DENY',signer:1},
   {offline:true,code:'OAUTH_DENIAL_INVENTORY_UNAVAILABLE',signer:0},
   {unsafe:true,code:'OAUTH_DENIAL_INVENTORY_UNSAFE',signer:0}
  ];
  for(const [i,item] of cases.entries()){
   const x=examples[i];
   let reads=0;
   const readPreDenyInventory=async (challenge)=>{
    reads++;
    assert.equal(challenge.subject,SUBJECT);
    assert.deepEqual(Object.keys(challenge).sort(),['signal','subject'],
     'External S3 inventory never receives owner WebID, grant or token');
    if(item.offline)throw Error('Independent S3 unavailable');
    return {retainedDenialObserved:reads===item.seenAt,
     absenceAuthorizes:item.unsafe?true:false,releaseAccepted:false};
   };
   const gate=createDisposableIndependentPreDenyAdmission({
    ...x.args,readPreDenyInventory
   });
   await denied(()=>gate.inspect({surface:'access-token-sign',context:{}}),
    item.code);
   assert.equal(x.hits.signer,item.signer);
   assert.equal(x.hits.sideEffects,0);
  }
  let calls=0;
  const readPreDenyInventory=async()=>{
   calls++;
   return {retainedDenialObserved:false,
    absenceAuthorizes:false,releaseAccepted:false};
  };
  const gate=createDisposableIndependentPreDenyAdmission({
   ...ok.args,readPreDenyInventory
  });
  const result=await gate.inspect({surface:'signed-pds-commit',context:{}});
  assert.equal(calls,2,'Two complete archive inventories required');
  assert.equal(result.checked,true);
  assert.equal(result.releaseAccepted,false,
   'Even empty inventory cannot give production authorization');
  delete process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE;
  await denied(()=>gate.inspect({surface:'signed-pds-commit',context:{}}),
   'OAUTH_DENIAL_INVENTORY_NOT_RELEASED');
 }finally{
  if(prior===undefined)delete process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE;
  else process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE=prior;
 }
});
