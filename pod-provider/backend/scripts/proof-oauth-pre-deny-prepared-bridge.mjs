/** NONACTIVATED pre-denial coordinator -> PG18 prepare / WORM / seal order. */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {assertReceipt} from '../candidates/oauth-s3-compliance-archive.mjs';
import {subjectHash,createDisposablePreDenyIntentCoordinator} from
 '../candidates/oauth-pre-deny-intent-coordinator.mjs';
if(process.env.NODE_ENV!=='test'||
 process.env.PAPER_OAUTH_PRE_DENY_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_PORTABLE_WORM_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_PRE_DENY_WITNESS_DISPOSABLE!=='confirmed')
 throw Error('Refusing non-disposable prepared-denial order proof');

const OWNER='https://paper.example.org/users/prepared-witness';
const CLIENT='https://paper-client.example.org/oauth';
const GRANT='x'.repeat(32);
const OP=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HASH=crypto.createHash('sha256').update(GRANT).digest('hex');
const SHA=/^[a-f0-9]{64}$/u;
const reject=async(fn,code)=>assert.rejects(fn,e=>e?.code===code);
function fixture(fault={}){
 const events=[],objects=new Map();
 let prepared=false,sealed=false,published=false,mutations=0;
 const ownerReader={async inspectForDeny(){
  events.push('owner');
  if(fault.logoutAfterArchive&&prepared&&objects.size)throw Error('Owner gone');
  return {ownerWebId:OWNER,clientId:CLIENT,
   appUri:'https://paper.example.org/apps/paper',grantId:GRANT,
   oauthRevision:'3',saiRevision:'5',credentialEpoch:'11',
   scopeSha256:'b'.repeat(64),authProofSha256:
    (fault.sessionRotatedAfterArchive&&prepared&&objects.size)?
     'c'.repeat(64):'a'.repeat(64)};
 }};
 const portableWriter={async putAndVerify({key,bytes}){
  events.push('put');
  assert.equal(prepared,true,'Immutable writer cannot outrun PG denial');
  assertReceipt(key,bytes);
  if(fault.putLost)throw Error('Ambiguous S3 PUT ACK');
  if(objects.has(key))throw Error('Duplicate immutable S3 key');
  objects.set(key,Buffer.from(bytes));
  return {key,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),
   versionId:'version-1',contentVersionObserved:true,
   retentionObserved:true,releaseAccepted:false};
 }};
 const prepareIndependentFence=async input=>{
  events.push('prepare');
  assert.equal(input.ownerWebId,OWNER);
  assert.equal(input.clientId,CLIENT);
  assert.equal(input.subject,subjectHash(OWNER,CLIENT));
  assert.equal(input.grantSha256,HASH);
  assert.equal(input.revision,'3');
  assert.equal(input.credentialEpoch,'11');
  assert.equal(input.saiRevision,'5');
  assert.equal(input.scopeSha256,'b'.repeat(64));
  assert.match(input.operationId,OP);
  assert.match(input.receiptSha256,SHA);
  if(fault.prepareLost)throw Error('Lost PG COMMIT ACK');
  if(fault.prepareRefused)return false;
  prepared=true;
  return true;
 };
 const sealIndependentFence=async input=>{
  events.push('seal');
  assert.equal(prepared,true);
  assert.equal(input.ownerWebId,OWNER);
  assert.equal(input.clientId,CLIENT);
  assert.match(input.operationId,OP);
  const key=input.archiveKey;
  const stored=objects.get(key);
  assert.ok(Buffer.isBuffer(stored));
  assert.equal(crypto.createHash('sha256')
   .update(stored).digest('hex'),input.receiptSha256);
  if(fault.sealLost)throw Error('Independent attestor ACK lost');
  if(fault.sealRefused)return false;
  sealed=true;
  return true;
 };
 const headPublisher={async publish(){
  events.push('publish');
  assert.equal(sealed,true,'Head cannot publish without exact WORM seal');
  if(fault.publishLost)throw Error('Monotonic signer ACK lost');
  published=true;
  return true;
 }};
 const signedHead={async assertDenied(){
  events.push('head');
  assert.equal(published,true);
  if(fault.badHead)return false;
  return true;
 }};
 const args={ownerReader,portableWriter,
  prepareIndependentFence,sealIndependentFence,
  headPublisher,signedHead,fixtureOnly:true,timeoutMs:200};
 const make=()=>createDisposablePreDenyIntentCoordinator(args);
 const invoke=c=>c.retainBeforeMutation({
  context:{untrustedOwner:'https://evil.example.org'},
  clientId:CLIENT,expectedGrantId:GRANT
 });
 return {make,invoke,args,events,objects,get mutations(){return mutations;}};
}
test('independent PG18 prepared-deny happens before WORM, and exact seal before signer',async()=>{
 const f=fixture();
 const r=await f.invoke(f.make());
 assert.deepEqual(f.events,
  ['owner','prepare','put','owner','seal','publish','head']);
 assert.equal(r.releaseAccepted,false);
 assert.equal(r.retained,true);
 assert.equal(f.mutations,0);
});
test('PG prepare refusal or lost ACK cannot issue any S3 object',async()=>{
 for(const [fault,code] of [
  [{prepareRefused:true},'PRE_DENY_WITNESS_NOT_PREPARED'],
  [{prepareLost:true},'PRE_DENY_WITNESS_PREPARE_AMBIGUOUS']
 ]){
  const f=fixture(fault);
  await reject(()=>f.invoke(f.make()),code);
  assert.deepEqual(f.events,['owner','prepare']);
  assert.equal(f.objects.size,0);
  assert.equal(f.mutations,0);
 }
});
test('ambiguous archive after independent prepare leaves witness denial prepared',async()=>{
 const f=fixture({putLost:true});
 await reject(()=>f.invoke(f.make()),'PRE_DENY_ARCHIVE_AMBIGUOUS');
 assert.deepEqual(f.events,['owner','prepare','put']);
 assert.equal(f.mutations,0);
});
test('owner logout or session replacement after WORM PUT denies seal and publication',async()=>{
 for(const fault of [{logoutAfterArchive:true},{sessionRotatedAfterArchive:true}]){
  const f=fixture(fault);
  await reject(()=>f.invoke(f.make()),'PRE_DENY_OWNER_NOT_CURRENT');
  assert.deepEqual(f.events,['owner','prepare','put','owner']);
  assert.equal(f.objects.size,1);
 }
});
test('failed separate WORM seal never reaches independent signer',async()=>{
 for(const [fault,code] of [
  [{sealRefused:true},'PRE_DENY_WITNESS_UNSEALED'],
  [{sealLost:true},'PRE_DENY_WITNESS_SEAL_AMBIGUOUS']
 ]){
  const f=fixture(fault);
  await reject(()=>f.invoke(f.make()),code);
  assert.deepEqual(f.events,['owner','prepare','put','owner','seal']);
  assert.equal(f.mutations,0);
 }
});
test('ambiguous signer or invalid head cannot mutate owner grant',async()=>{
 for(const [fault,code] of [
  [{publishLost:true},'PRE_DENY_HEAD_AMBIGUOUS'],
  [{badHead:true},'PRE_DENY_HEAD_UNVERIFIED']
 ]){
  const f=fixture(fault);
  await reject(()=>f.invoke(f.make()),code);
  assert.equal(f.mutations,0);
 }
});
test('reject missing or shared prepare/seal capabilities in witness mode',()=>{
 const f=fixture();
 assert.throws(()=>createDisposablePreDenyIntentCoordinator({
  ...f.args,sealIndependentFence:null
 }),e=>e?.code==='PRE_DENY_WITNESS_CONFIGURATION_UNSAFE');
 assert.throws(()=>createDisposablePreDenyIntentCoordinator({
  ...f.args,prepareIndependentFence:f.args.sealIndependentFence
 }),e=>e?.code==='PRE_DENY_WITNESS_CONFIGURATION_UNSAFE');
});
test('witness gate removal after constructor denies invocation',async()=>{
 const f=fixture(),c=f.make();
 const old=process.env.PAPER_OAUTH_PRE_DENY_WITNESS_DISPOSABLE;
 delete process.env.PAPER_OAUTH_PRE_DENY_WITNESS_DISPOSABLE;
 try{
  await reject(()=>f.invoke(c),'PRE_DENY_WITNESS_NOT_RELEASED');
 }finally{process.env.PAPER_OAUTH_PRE_DENY_WITNESS_DISPOSABLE=old}
 assert.deepEqual(f.events,[]);
});
test('witness adapter cannot be constructed or invoked outside disposable process',async()=>{
 const f=fixture(),c=f.make();
 const old=process.env.NODE_ENV;process.env.NODE_ENV='production';
 try{
  assert.throws(()=>f.make(),e=>e?.code==='PRE_DENY_NOT_RELEASED');
  await reject(()=>f.invoke(c),'PRE_DENY_NOT_RELEASED');
 }finally{process.env.NODE_ENV=old}
});
