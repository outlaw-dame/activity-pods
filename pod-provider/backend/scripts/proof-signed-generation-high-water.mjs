/** NONACTIVATED adversarial signed generation high-water proof. */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
 createDisposableSignedGenerationHighWaterAuthority,
 verifyDisposableSignedGenerationHighWater,
 SIGNED_GENERATION_HIGH_WATER_DOMAIN
} from '../../independent-authority/signed-generation-high-water.mjs';

if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_SIGNED_HIGHWATER_DISPOSABLE!=='confirmed')
 throw Error('Refusing nondisposable signed generation high-water proof');

const SUBJECT='a'.repeat(64),EPOCH_SUBJECT='b'.repeat(64);
const GRANT='c'.repeat(64),SCOPE='d'.repeat(64),OWNER_PROOF='e'.repeat(64);
const ZERO='0'.repeat(64),FIXED_TIME=1800000000;
const OP1='a7d75d7d-403a-4940-8e42-f5c352eef572';
const OP2='b8e86e8e-514b-4a51-9f53-1b5d463f0683';
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
const rotated=crypto.generateKeyPairSync('ed25519');
const SHA=value=>crypto.createHash('sha256').update(value).digest('hex');
const denied=(fn,code)=>assert.rejects(fn,e=>e?.code===code,
 'Expected fail-closed error '+code);

function generation(sequence='1',status='active',previousSha256=ZERO,
 objectVersion='object-version-'+sequence){
 const record={
  kind:'paper.oauth.authority-generation.v1',subject:SUBJECT,
  epochSubject:EPOCH_SUBJECT,sequence,status,grantSha256:GRANT,
  scopeSha256:SCOPE,ownerProofSha256:OWNER_PROOF,oauthRevision:'7',
  credentialEpoch:'11',saiRevision:'4',
  operationId:sequence==='1'?OP1:OP2,previousSha256,
  preDenyReceiptSha256:status==='active'?ZERO:'f'.repeat(64)
 };
 const bytes=Buffer.from(JSON.stringify(record));
 return Object.freeze({record:Object.freeze(record),sha256:SHA(bytes),
  versionId:objectVersion});
}
const ACTIVE=generation();
const BLOCKED=generation('2','blocked',ACTIVE.sha256);
function checkpoint(head){
 const r=head.record;
 return Object.freeze({
  subject:r.subject,epochSubject:r.epochSubject,sequence:r.sequence,
  status:r.status,headSha256:head.sha256,
  previousSha256:r.previousSha256,grantSha256:r.grantSha256,
  scopeSha256:r.scopeSha256,ownerProofSha256:r.ownerProofSha256,
  oauthRevision:r.oauthRevision,credentialEpoch:r.credentialEpoch,
  saiRevision:r.saiRevision,operationId:r.operationId,
  preDenyReceiptSha256:r.preDenyReceiptSha256,
  objectVersion:head.versionId
 });
}
function evidence(head){
 return Object.freeze({observedGenerations:Number(head.record.sequence),head,
  retainedBlocked:head.record.status==='blocked',activeAuthorizes:false,
  completeExternallyVerified:false,operatorIndependenceVerified:false,
  releaseAccepted:false});
}
function fixture(options={}){
 const state={head:ACTIVE,checkpoint:null,reads:0,writes:0,signs:0,
  ...options.state};
 const inspectJournal=async({subject})=>{
  state.reads++;
  assert.equal(subject,SUBJECT);
  if(options.journalOffline)throw Error('archive offline');
  if(options.journalHang)return await new Promise(()=>{});
  const selected=options.changeJournalAfterSign&&state.signs>0?BLOCKED:
   options.rewoundJournal&&state.checkpoint?.sequence==='2'?ACTIVE:state.head;
  if(options.malformedJournal)return {...evidence(selected),activeAuthorizes:true};
  if(options.unsafeOperator)
   return {...evidence(selected),operatorIndependenceVerified:true};
  if(options.retainedMismatch)
   return {...evidence(selected),retainedBlocked:true};
  if(options.badRecordKind)
   return {...evidence(selected),head:{...selected,
    record:{...selected.record,kind:'paper.oauth.authority-generation.v0'}}};
  if(options.extraRecordField)
   return {...evidence(selected),head:{...selected,
    record:{...selected.record,unexpected:true}}};
  return evidence(selected);
 };
 const checkpointStore={
  read:async({subject})=>{
   assert.equal(subject,SUBJECT);state.reads++;
   if(options.checkpointOffline)throw Error('checkpoint offline');
   if(options.checkpointHang)return await new Promise(()=>{});
   if(options.malformedCheckpoint&&state.checkpoint)
    return {...state.checkpoint,unknown:true};
   if(options.changeCheckpointAfterSign&&state.signs>0)
    return checkpoint(BLOCKED);
   return state.checkpoint;
  },
  compareAndSet:async({subject,expected,desired})=>{
   assert.equal(subject,SUBJECT);state.writes++;
   if(options.casBeforeCommit)throw Error('lost before commit');
   const current=state.checkpoint;
   assert.equal(expected?.headSha256??null,current?.headSha256??null);
   state.checkpoint=Object.freeze({...desired});
   if(options.casAfterCommit)throw Error('lost after commit');
   return true;
  }
 };
 const signingKey=options.signingKey??privateKey;
 const args={inspectJournal,checkpointStore,
  signBytes:async bytes=>{
   state.signs++;
   if(options.signerOffline)throw Error('kms unavailable');
   if(options.signerHang)return await new Promise(()=>{});
   return crypto.sign(null,bytes,signingKey);
  },
  trustedPublicKeys:[{keyId:'kms-key-v1',keyEpoch:'1',publicKey}],
  authority:'independent-authority.test',keyId:'kms-key-v1',keyEpoch:'1',
  now:()=>FIXED_TIME,timeoutMs:options.timeoutMs??300,fixtureOnly:true
 };
 const authority=createDisposableSignedGenerationHighWaterAuthority(args);
 const nonce=crypto.randomBytes(32).toString('base64url');
 const respond=()=>authority.respond({
  kind:'paper.oauth.generation-high-water.challenge.v1',subject:SUBJECT,nonce
 });
 const verify=(reply,overrides={})=>verifyDisposableSignedGenerationHighWater({
  reply,nonce,expected:checkpoint(state.head),
  authority:'independent-authority.test',
  trustedPublicKeys:args.trustedPublicKeys,minimumKeyEpoch:'1',
  now:()=>FIXED_TIME,fixtureOnly:true,...overrides
 });
 return {state,args,authority,nonce,respond,verify};
}

test('ACTIVE checkpoint is atomically created, signed and independently verified',async()=>{
 const f=fixture();
 const reply=await f.respond();
 const verified=f.verify(reply);
 assert.equal(verified.sequence,'1');
 assert.equal(verified.status,'active');
 assert.equal(verified.headSha256,ACTIVE.sha256);
 assert.equal(verified.externallySigned,true);
 assert.equal(verified.releaseAccepted,false);
 assert.equal(f.state.writes,1);
 assert.equal(f.state.signs,1);
 assert.ok(crypto.verify(null,
  Buffer.concat([SIGNED_GENERATION_HIGH_WATER_DOMAIN,reply.body]),
  publicKey,reply.signature));
 assert.equal(Object.hasOwn(reply,'privateKey'),false);
});

test('accepted multibyte object-version boundary always round trips',async()=>{
 const boundaryVersion='界'.repeat(170)+'aa';
 assert.equal(Buffer.byteLength(boundaryVersion,'utf8'),512);
 const boundaryHead=generation('1','active',ZERO,boundaryVersion);
 const f=fixture({state:{head:boundaryHead}});
 const reply=await f.respond();
 assert.ok(reply.body.length<=2048);
 assert.equal(f.verify(reply).objectVersion,boundaryVersion);

 const oversizedHead=generation('1','active',ZERO,boundaryVersion+'界');
 const oversized=fixture({state:{head:oversizedHead}});
 await denied(()=>oversized.respond(),'GENERATION_HIGH_WATER_JOURNAL_INVALID');
 assert.equal(oversized.state.writes,0);
 assert.equal(oversized.state.signs,0);
});

test('BLOCKED advances exactly one hash-linked checkpoint and hidden tail is detected',async()=>{
 const f=fixture();
 await f.respond();
 f.state.head=BLOCKED;
 const reply=await f.respond();
 const verified=f.verify(reply);
 assert.equal(verified.sequence,'2');
 assert.equal(verified.status,'blocked');
 assert.equal(f.state.writes,2);
 const hidden=fixture({state:{head:ACTIVE,checkpoint:checkpoint(BLOCKED)}});
 await denied(()=>hidden.respond(),'GENERATION_HIGH_WATER_JOURNAL_REWOUND');
 assert.equal(hidden.state.signs,0);
});

test('checkpoint rollback, gaps and same-sequence forks fail before signing',async()=>{
 const rollback=fixture({state:{head:BLOCKED,checkpoint:null}});
 await denied(()=>rollback.respond(),'GENERATION_HIGH_WATER_GAP');
 const forked={...checkpoint(ACTIVE),headSha256:'9'.repeat(64)};
 const fork=fixture({state:{head:ACTIVE,checkpoint:forked}});
 await denied(()=>fork.respond(),'GENERATION_HIGH_WATER_FORK');
 const badPrevious={...BLOCKED,record:{...BLOCKED.record,
  previousSha256:'8'.repeat(64)}};
 const gap=fixture({state:{head:badPrevious,checkpoint:checkpoint(ACTIVE)}});
 await denied(()=>gap.respond(),'GENERATION_HIGH_WATER_GAP');
 for(const f of [rollback,fork,gap])assert.equal(f.state.signs,0);
});

test('lost CAS acknowledgement is reconciled without retry',async()=>{
 const after=fixture({casAfterCommit:true});
 assert.equal((await after.respond()).releaseAccepted,false);
 assert.equal(after.state.writes,1);
 const before=fixture({casBeforeCommit:true});
 await denied(()=>before.respond(),'GENERATION_HIGH_WATER_COMMIT_AMBIGUOUS');
 assert.equal(before.state.writes,1);
 assert.equal(before.state.signs,0);
});

test('concurrent callers converge on one checkpoint without a second transition',async()=>{
 const f=fixture();
 // Serialize the in-memory CAS like a remote conditional transaction while
 // allowing both requests to observe an initially empty checkpoint.
 let locked=false;
 f.args.checkpointStore.compareAndSet=async({expected,desired})=>{
  while(locked)await new Promise(resolve=>{setImmediate(resolve)});
  locked=true;
  try{
   f.state.writes++;
   if((f.state.checkpoint?.headSha256??null)!==(expected?.headSha256??null))
    throw Error('conditional conflict');
   f.state.checkpoint=Object.freeze({...desired});
  }finally{locked=false}
 };
 const authority=createDisposableSignedGenerationHighWaterAuthority(f.args);
 const challenge=()=>authority.respond({
  kind:'paper.oauth.generation-high-water.challenge.v1',subject:SUBJECT,
  nonce:crypto.randomBytes(32).toString('base64url')
 });
 const results=await Promise.allSettled([challenge(),challenge()]);
 assert.equal(results.filter(x=>x.status==='fulfilled').length,2);
 assert.equal(f.state.checkpoint.headSha256,ACTIVE.sha256);
 assert.equal(f.state.checkpoint.sequence,'1');
});

test('malformed evidence, outages and bounded dependency timeouts fail closed',async()=>{
 for(const [options,code] of [
  [{malformedJournal:true},'GENERATION_HIGH_WATER_JOURNAL_INVALID'],
  [{unsafeOperator:true},'GENERATION_HIGH_WATER_JOURNAL_INVALID'],
  [{retainedMismatch:true},'GENERATION_HIGH_WATER_JOURNAL_INVALID'],
  [{badRecordKind:true},'GENERATION_HIGH_WATER_JOURNAL_INVALID'],
  [{extraRecordField:true},'GENERATION_HIGH_WATER_JOURNAL_INVALID'],
  [{journalOffline:true},'GENERATION_HIGH_WATER_JOURNAL_UNAVAILABLE'],
  [{checkpointOffline:true},'GENERATION_HIGH_WATER_CHECKPOINT_UNAVAILABLE'],
  [{journalHang:true,timeoutMs:250},'GENERATION_HIGH_WATER_JOURNAL_UNAVAILABLE'],
  [{checkpointHang:true,timeoutMs:250},'GENERATION_HIGH_WATER_CHECKPOINT_UNAVAILABLE']
 ]){
  const f=fixture(options);
  await denied(()=>f.respond(),code);
  assert.equal(f.state.signs,0);
 }
 const malformed=fixture({malformedCheckpoint:true,
  state:{head:ACTIVE,checkpoint:checkpoint(ACTIVE)}});
 await denied(()=>malformed.respond(),'GENERATION_HIGH_WATER_CHECKPOINT_INVALID');
});

test('signature, nonce, scope, clock and minimum key epoch are enforced',async()=>{
 const f=fixture();const reply=await f.respond();
 assert.throws(()=>f.verify(reply,{nonce:'q'.repeat(43)}),
  e=>e?.code==='GENERATION_HIGH_WATER_SCOPE_INVALID');
 assert.throws(()=>f.verify(reply,{now:()=>FIXED_TIME+60}),
  e=>e?.code==='GENERATION_HIGH_WATER_CLOCK_INVALID');
 assert.throws(()=>f.verify(reply,{minimumKeyEpoch:'2'}),
  e=>e?.code==='GENERATION_HIGH_WATER_SCOPE_INVALID');
 const forged={...reply,signature:crypto.sign(null,
  Buffer.concat([SIGNED_GENERATION_HIGH_WATER_DOMAIN,reply.body]),
  rotated.privateKey)};
 assert.throws(()=>f.verify(forged),
  e=>e?.code==='GENERATION_HIGH_WATER_SIGNATURE_INVALID');
 const wrong=fixture({signingKey:rotated.privateKey});
 await denied(()=>wrong.respond(),'GENERATION_HIGH_WATER_SIGNATURE_INVALID');
});

test('configured key rotation rejects retired epoch and accepts pinned new key',async()=>{
 const f=fixture();const oldReply=await f.respond();
 const keys=[
  {keyId:'kms-key-v1',keyEpoch:'1',publicKey},
  {keyId:'kms-key-v2',keyEpoch:'2',publicKey:rotated.publicKey}
 ];
 assert.throws(()=>verifyDisposableSignedGenerationHighWater({
  reply:oldReply,nonce:f.nonce,expected:checkpoint(ACTIVE),
  authority:'independent-authority.test',trustedPublicKeys:keys,
  minimumKeyEpoch:'2',now:()=>FIXED_TIME,fixtureOnly:true
 }),e=>e?.code==='GENERATION_HIGH_WATER_SCOPE_INVALID');
 const next=createDisposableSignedGenerationHighWaterAuthority({
  ...f.args,keyId:'kms-key-v2',keyEpoch:'2',trustedPublicKeys:keys,
  signBytes:async bytes=>crypto.sign(null,bytes,rotated.privateKey)
 });
 const nonce=crypto.randomBytes(32).toString('base64url');
 const reply=await next.respond({
  kind:'paper.oauth.generation-high-water.challenge.v1',subject:SUBJECT,nonce
 });
 const verified=verifyDisposableSignedGenerationHighWater({
  reply,nonce,expected:checkpoint(ACTIVE),
  authority:'independent-authority.test',trustedPublicKeys:keys,
  minimumKeyEpoch:'2',now:()=>FIXED_TIME,fixtureOnly:true
 });
 assert.equal(verified.keyEpoch,'2');
});

test('journal or checkpoint mutation during signing suppresses the response',async()=>{
 for(const [options,code] of [
  [{changeJournalAfterSign:true},'GENERATION_HIGH_WATER_CHANGED_DURING_SIGN'],
  [{changeCheckpointAfterSign:true},'GENERATION_HIGH_WATER_CHANGED_DURING_SIGN']
 ]){
  const f=fixture(options);
  await denied(()=>f.respond(),code);
 }
});

test('challenge schema and production activation remain closed',async()=>{
 const f=fixture();
 await denied(()=>f.authority.respond({
  kind:'paper.oauth.generation-high-water.challenge.v1',
  subject:SUBJECT,nonce:f.nonce,ownerWebId:'https://attacker.example/'
 }),'GENERATION_HIGH_WATER_CHALLENGE_INVALID');
 const previous=process.env.NODE_ENV;process.env.NODE_ENV='production';
 try{
  await denied(()=>f.respond(),'GENERATION_HIGH_WATER_NOT_RELEASED');
  assert.throws(()=>createDisposableSignedGenerationHighWaterAuthority(f.args),
   e=>e?.code==='GENERATION_HIGH_WATER_NOT_RELEASED');
 }finally{process.env.NODE_ENV=previous}
});
