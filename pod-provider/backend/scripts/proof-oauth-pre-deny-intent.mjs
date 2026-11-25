/** NONACTIVATED deterministic pre-deny writer/signing contract. */
import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import {assertReceipt} from '../candidates/oauth-s3-compliance-archive.mjs';
import {createDisposablePreDenySignedHead} from
 '../candidates/oauth-pre-deny-signed-head.mjs';
import {createDisposablePreDenyIntentCoordinator,subjectHash} from
 '../candidates/oauth-pre-deny-intent-coordinator.mjs';

if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_PRE_DENY_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_PORTABLE_WORM_DISPOSABLE!=='confirmed')
 throw Error('Refusing non-disposable pre-denial proof');

const OWNER='https://paper.example.org/users/pre-deny-owner';
const CLIENT='https://paper-client.example.org/oauth';
const APP='https://paper.example.org/apps/paper';
const GRANT='g'.repeat(32);
const REV='7';
const EPOCH='11';
const SAI='9';
const SCOPE_HASH='f'.repeat(64);
const AUTHORITY='pre_deny.independent.test';
const CLOCK=1800000000;
const DOMAIN=Buffer.from('paper:oauth:pre-deny:head:v1\0');
// Independent PG18 witness v5 uses length-framed canonical WebID and client.
const SUBJECT=crypto.createHash('sha256').update(
 'paper:witness:subject:v1:'+OWNER.length+':'+OWNER+':'+CLIENT,
 'utf8').digest('hex');
const HASH=crypto.createHash('sha256').update(GRANT).digest('hex');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const grantRecord=()=>({
 ownerWebId:OWNER,clientId:CLIENT,appUri:APP,grantId:GRANT,
 oauthRevision:REV,saiRevision:SAI,credentialEpoch:EPOCH,
 scopeSha256:SCOPE_HASH,authProofSha256:'a'.repeat(64)
});
const denied=async(fn,code)=>assert.rejects(fn,e=>e?.code===code);
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
let latest=null;
let attacks={replay:false,mutate:null,foreignSigner:false,unavailable:false,
 staleClock:false};
let captured=null;
let replay=null;
const signatureReply=(challenge)=>{
 if(attacks.unavailable)throw Error('Signer disconnected');
 const head={kind:'paper.oauth.pre-deny.head.v1',authority:AUTHORITY,
  subject:challenge.subject,grantSha256:latest.grantSha256,
  revision:latest.revision,operationId:latest.operationId,
  receiptSha256:latest.receiptSha256,nonce:challenge.nonce,
  issuedAt:CLOCK+(attacks.staleClock?120:0)};
 if(attacks.mutate)Object.assign(head,attacks.mutate);
 const body=Buffer.from(JSON.stringify(head));
 const key=attacks.foreignSigner?
  crypto.generateKeyPairSync('ed25519').privateKey:privateKey;
 return {body,signature:crypto.sign(null,Buffer.concat([DOMAIN,body]),key)};
};
const readHead=async challenge=>{
 if(!latest)throw Error('No durable head');
 if(attacks.replay&&replay)return replay;
 const out=signatureReply(challenge);
 if(attacks.replay)replay=out;
 return out;
};
const signedHead=()=>createDisposablePreDenySignedHead({
 readHead,trustedPublicKey:publicKey,authority:AUTHORITY,
 fixtureOnly:true,now:()=>CLOCK
});
function fixture(options={}){
 latest=null;captured=null;replay=null;
 attacks={replay:false,mutate:null,foreignSigner:false,unavailable:false,
  staleClock:false};
 const state={owner:0,put:0,publish:0,signature:0,mutations:0};
 const ownerReader={async inspectForDeny({clientId,expectedGrantId}){
   state.owner++;
   if(options.ownerUnavailable)throw Error('Invalid browser');
   const record=grantRecord();
   if(options.corruptOwner)record.grantId='z'.repeat(32);
   if(options.oldCredential)record.credentialEpoch='0';
   if(options.ownerChangedAfterArchive&&state.owner>1)
     record.credentialEpoch='12';
   if(options.sessionRotatedAfterArchive&&state.owner>1)
     record.authProofSha256='b'.repeat(64);
   if(options.badAuthProof)record.authProofSha256='not-a-sha256';
   if(options.logoutAfterArchive&&state.owner>1)
     throw Error('Signed browser session expired during archival');
   assert.equal(clientId,CLIENT);
   assert.equal(expectedGrantId,GRANT);
   return record;
 }};
 const archive={async putAndVerify({key,bytes}){
   state.put++;
   assertReceipt(key,bytes);
   const b=Buffer.from(bytes);
   captured={key,bytes:b};
   if(options.putLostBefore)throw Error('Unknown S3 outcome');
   const result={key,versionId:'opaque-version-1',
    sha256:crypto.createHash('sha256').update(b).digest('hex'),
    contentVersionObserved:true,retentionObserved:true,
    conditionalCreateOnlyVerified:false,
    operatorIndependenceVerified:false,latestHeadVerified:false,
    releaseAccepted:false};
   if(options.badRetention)result.retentionObserved=false;
   if(options.badDigest)result.sha256='0'.repeat(64);
   if(options.badReleaseFlag)result.releaseAccepted=true;
   if(options.badVersion)result.versionId='';
   return result;
 }};
 const publisher={async publish(receipt){
   state.publish++;
   if(options.publisherLostBefore)throw Error('Signer not reachable');
   if(options.publisherMismatch){
     latest={...receipt,grantSha256:'0'.repeat(64)};
   }else latest={...receipt};
   if(options.publisherLostAfter)throw Error('Lost sign ACK');
   return options.publisherRefused?false:true;
 }};
 const reader=signedHead();
 const evidence={async assertDenied(expected){
   state.signature++;
   if(options.headUnavailable)throw Error('Signer temporarily offline');
   return reader.assertDenied(expected);
 }};
 return {state,ownerReader,archive,publisher,reader,
  coordinator:createDisposablePreDenyIntentCoordinator({
   ownerReader,portableWriter:archive,headPublisher:publisher,
   signedHead:evidence,fixtureOnly:true,timeoutMs:200
  })};
}
const call=f=>f.coordinator.retainBeforeMutation({
 context:Object.freeze({untrustedOwner:'https://attacker.invalid'}),
 clientId:CLIENT,expectedGrantId:GRANT
});

test('pre-denial owner/client subject is length-framed and canonical',()=>{
 assert.equal(subjectHash(OWNER,CLIENT),SUBJECT);
 assert.equal(subjectHash(OWNER,CLIENT),
  crypto.createHash('sha256').update('paper:witness:subject:v1:'+
   OWNER.length+':'+OWNER+':'+CLIENT,'utf8').digest('hex'));
 assert.notEqual(subjectHash(OWNER,CLIENT),
  crypto.createHash('sha256').update('paper:witness:subject:v1\0')
   .update(OWNER).update('\0').update(CLIENT).digest('hex'),
  'Legacy NUL-framed v1 was incompatible with independent PG18');
 assert.notEqual(subjectHash(OWNER,CLIENT),
  subjectHash(OWNER+'/different-owner',CLIENT));
 assert.notEqual(subjectHash(OWNER,CLIENT),
  subjectHash(OWNER,'https://another-client.example.org/oauth'));
 for(const bad of ['https://paper.example.org/users/raw space',
   'https://paper.example.org/users/é','http://paper.example.org/owner',
   'https://paper.example.org/owner#fragment',
   'https://paper.example.org/owner?query=x']){
  assert.throws(()=>subjectHash(bad,CLIENT),
   e=>e?.code==='PRE_DENY_SCOPE_INVALID');
 }
});

test('strict pre-denial receipt key, typed revisions, exact canonical JSON',()=>{
 const op='a7d75d7d-403a-4940-8e42-f5c352eef572';
 const key='paper/oauth-witness/pre-deny/v1/'+SUBJECT+
  '/0000000000000000007/'+op;
 const obj={kind:'paper.oauth.pre-deny.v1',subject:SUBJECT,
  revision:REV,operationId:op,grantSha256:HASH,
  credentialEpoch:EPOCH,saiRevision:SAI,scopeSha256:SCOPE_HASH};
 const valid=Buffer.from(JSON.stringify(obj));
 assert.doesNotThrow(()=>assertReceipt(key,valid));
 for(const bad of [
  {...obj,revision:7},{...obj,revision:null},
  {...obj,credentialEpoch:11},{...obj,saiRevision:null},
  {...obj,grantSha256:'z'.repeat(64)},
  {...obj,operationId:'00000000-0000-0000-0000-000000000000'},
  {...obj,unexpected:true}
 ])assert.throws(()=>assertReceipt(key,Buffer.from(JSON.stringify(bad))),
  e=>e?.code==='S3_RECEIPT_FORMAT_INVALID');
 assert.throws(()=>assertReceipt(key.replace(SUBJECT,'b'.repeat(64)),valid),
  e=>e?.code==='S3_RECEIPT_FORMAT_INVALID');
 assert.throws(()=>assertReceipt(key.replace('0000000000000000007','0000000000000000008'),valid),
  e=>e?.code==='S3_RECEIPT_FORMAT_INVALID');
 assert.throws(()=>assertReceipt(key,Buffer.from(JSON.stringify({
  ...obj,subject:SUBJECT.toUpperCase()
 }))),e=>e?.code==='S3_RECEIPT_FORMAT_INVALID');
 const shuffled=Buffer.from(JSON.stringify({
  revision:REV,kind:'paper.oauth.pre-deny.v1',subject:SUBJECT,
  operationId:op,grantSha256:HASH,credentialEpoch:EPOCH,
  saiRevision:SAI,scopeSha256:SCOPE_HASH
 }));
 assert.doesNotThrow(()=>assertReceipt(key,shuffled),
  'Canonical JSON means input order is fixed by writer contract, not JSON sort');
});

test('exact owner-bound pre-deny archive is retained before independent signer readback',async()=>{
 const f=fixture(),result=await call(f);
 assert.equal(result.retained,true);
 assert.equal(result.releaseAccepted,false);
 assert.equal(result.subject,SUBJECT);
 assert.equal(result.revision,REV);
 assert.equal(f.state.owner,2);
 assert.equal(f.state.put,1);
 assert.equal(f.state.publish,1);
 assert.equal(f.state.signature,1);
 assert.equal(f.state.mutations,0);
 assert.match(result.operationId,UUID);
 assert.equal(captured.key,'paper/oauth-witness/pre-deny/v1/'+
   SUBJECT+'/0000000000000000007/'+result.operationId);
 assert.deepEqual(JSON.parse(captured.bytes.toString('utf8')),{
  kind:'paper.oauth.pre-deny.v1',subject:SUBJECT,
  revision:REV,operationId:result.operationId,grantSha256:HASH,
  credentialEpoch:EPOCH,saiRevision:SAI,scopeSha256:SCOPE_HASH
 });
 const same=await call(f);
 assert.equal(same.operationId,result.operationId,'Deterministic exact-gen key');
 assert.equal(f.state.mutations,0);
});

test('refuse wrong owner grant, absent browser or weak credential epoch before any write',async()=>{
 for(const [options,expected] of [
  [{ownerUnavailable:true},'PRE_DENY_OWNER_NOT_CURRENT'],
  [{corruptOwner:true},'PRE_DENY_OWNER_NOT_CURRENT'],
  [{oldCredential:true},'PRE_DENY_OWNER_NOT_CURRENT'],
  [{badAuthProof:true},'PRE_DENY_OWNER_NOT_CURRENT']
 ]){
  const f=fixture(options);
  await denied(()=>call(f),expected);
  assert.equal(f.state.put,0);
  assert.equal(f.state.publish,0);
 }
});

test('unsafe S3 receipt/readback cannot reach signer or revoker',async()=>{
 for(const options of [
  {putLostBefore:true},{badRetention:true},{badDigest:true},
  {badReleaseFlag:true},{badVersion:true}
 ]){
  const f=fixture(options);
  await denied(()=>call(f),options.putLostBefore?
   'PRE_DENY_ARCHIVE_AMBIGUOUS':'PRE_DENY_ARCHIVE_UNVERIFIED');
  assert.equal(f.state.put,1);
  assert.equal(f.state.publish,0);
  assert.equal(f.state.mutations,0);
 }
});

test('logout, session replacement or credential rotation during archive prevents denial-head publish',async()=>{
 for(const options of [
   {logoutAfterArchive:true},{ownerChangedAfterArchive:true},
   {sessionRotatedAfterArchive:true}
 ]){
  const f=fixture(options);
  await denied(()=>call(f),'PRE_DENY_OWNER_NOT_CURRENT');
  assert.equal(f.state.owner,2);
  assert.equal(f.state.put,1);
  assert.equal(f.state.publish,0);
  assert.equal(f.state.signature,0);
  assert.equal(f.state.mutations,0);
 }
});

test('signer lost ACK, incorrect signed head and offline reader never authorize',async()=>{
 for(const [options,expected] of [
  [{publisherLostBefore:true},'PRE_DENY_HEAD_AMBIGUOUS'],
  [{publisherLostAfter:true},'PRE_DENY_HEAD_AMBIGUOUS'],
  [{publisherRefused:true},'PRE_DENY_HEAD_AMBIGUOUS'],
  [{publisherMismatch:true},'PRE_DENY_HEAD_UNVERIFIED'],
  [{headUnavailable:true},'PRE_DENY_HEAD_UNVERIFIED']
 ]){
  const f=fixture(options);
  await denied(()=>call(f),expected);
  assert.equal(f.state.put,1);
  assert.equal(f.state.mutations,0);
 }
});

test('pre-denial Ed25519 signature rejects foreign signer, wrong scope and timestamp',async()=>{
 const f=fixture();const r=await call(f);
 const expected={subject:SUBJECT,grantSha256:HASH,revision:REV,
  operationId:r.operationId,receiptSha256:r.receiptSha256};
 attacks.foreignSigner=true;
 await denied(()=>signedHead().assertDenied(expected),'PRE_DENY_HEAD_SIGNATURE_INVALID');
 attacks.foreignSigner=false;attacks.mutate={subject:'0'.repeat(64)};
 await denied(()=>signedHead().assertDenied(expected),'PRE_DENY_HEAD_SCOPE_INVALID');
 attacks.mutate=null;attacks.staleClock=true;
 await denied(()=>signedHead().assertDenied(expected),'PRE_DENY_HEAD_CLOCK_INVALID');
 attacks.staleClock=false;
 attacks.mutate={unexpected:true};
 await denied(()=>signedHead().assertDenied(expected),'PRE_DENY_HEAD_SCOPE_INVALID');
});

test('pre-denial signature is fresh; replays, private-key credentials and rewinds deny',async()=>{
 const f=fixture(),r=await call(f);
 const expected={subject:SUBJECT,grantSha256:HASH,revision:REV,
  operationId:r.operationId,receiptSha256:r.receiptSha256};
 attacks.replay=true;
 await signedHead().assertDenied(expected);
 await denied(()=>signedHead().assertDenied(expected),'PRE_DENY_HEAD_SCOPE_INVALID');
 attacks.replay=false;
 const pem=privateKey.export({format:'pem',type:'pkcs8'});
 assert.throws(()=>createDisposablePreDenySignedHead({
  readHead,trustedPublicKey:pem,authority:AUTHORITY,fixtureOnly:true,
  now:()=>CLOCK
 }),e=>e?.code==='PRE_DENY_HEAD_KEY_UNSAFE');
 latest={...latest,revision:'6'};
 await denied(()=>signedHead().assertDenied(expected),'PRE_DENY_HEAD_SCOPE_INVALID');
});

test('no env flag enables the independent pre-denial candidate in production',async()=>{
 const old=process.env.NODE_ENV;
 process.env.NODE_ENV='production';
 try{
  assert.throws(()=>fixture(),
   e=>e?.code==='PRE_DENY_HEAD_NOT_RELEASED');
  assert.throws(()=>createDisposablePreDenyIntentCoordinator({
   fixtureOnly:true
  }),e=>e?.code==='PRE_DENY_NOT_RELEASED');
 }finally{process.env.NODE_ENV=old}
});
