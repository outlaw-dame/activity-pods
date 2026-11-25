/** NONACTIVATED S3 Object Lock -> external KMS -> client Ed25519 proof. */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {createDisposableImmutableDenialHeadSigner} from
 '../../independent-authority/immutable-denial-head-signer.mjs';
import {createDisposablePreDenySignedHead} from
 '../candidates/oauth-pre-deny-signed-head.mjs';

if(process.env.NODE_ENV!=='test'||
 process.env.PAPER_INDEPENDENT_DENIAL_SIGNER_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_PRE_DENY_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE!=='confirmed')
 throw Error('Non-disposable signer test is forbidden');

const NOW=Date.UTC(2026,10,25,17,0,0),DAY=86_400_000,AT=Math.floor(NOW/1000);
const SUB='a'.repeat(64),GRANT='b'.repeat(64),SCOPE='c'.repeat(64);
const OP='a7d75d7d-403a-4940-8e42-f5c352eef572';
const KEY='paper/oauth-witness/pre-deny/v1/'+SUB+'/0000000000000000007/'+OP;
const RECEIPT=Buffer.from(JSON.stringify({
 kind:'paper.oauth.pre-deny.v1',subject:SUB,revision:'7',
 operationId:OP,grantSha256:GRANT,credentialEpoch:'11',
 saiRevision:'4',scopeSha256:SCOPE
}));
const SHA=crypto.createHash('sha256').update(RECEIPT).digest('hex');
const {privateKey:KMS,publicKey:PUBLIC}=crypto.generateKeyPairSync('ed25519');
const alternate=crypto.generateKeyPairSync('ed25519');
const commandsList=['ListObjectVersionsCommand','GetObjectCommand',
 'GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
 'GetObjectRetentionCommand','HeadObjectCommand'];
let commands=Object.fromEntries(commandsList.map(name=>[name,class {
 constructor(input){this.kind=name;this.input=input;}
}]));
if(process.env.PAPER_OAUTH_S3_SDK_ENTRY){
 const path=process.env.PAPER_OAUTH_S3_SDK_ENTRY;
 if(!path.startsWith('/'))throw Error('Refusing relative S3 SDK path');
 const sdk=await import(pathToFileURL(path).href);
 const exported=sdk.default??sdk;
 for(const kind of commandsList)
  assert.equal(typeof exported[kind],'function','Real SDK '+kind);
 commands=exported;
}
function fixture(fault={}){
 const state={bytes:Buffer.from(RECEIPT),version:'immutable-version-a',
  stored:true,deleted:false,s3Reads:0,signs:0,commands:[],
  restoredProviderEpoch:'1',oldSignerCachedState:'ACTIVE'};
 const reader={send:async command=>{
  const kind=command.kind??command.constructor.name,input=command.input;
  state.s3Reads++;
  state.commands.push({kind,input});
  assert.equal(input.Bucket,'independent-authority-bucket');
  if(fault.s3Offline)throw Error('External reader unreachable');
  switch(kind){
   case 'GetBucketVersioningCommand':
    return {Status:fault.suspended?'Suspended':'Enabled'};
   case 'GetObjectLockConfigurationCommand':
    return {ObjectLockConfiguration:{ObjectLockEnabled:'Enabled',
     Rule:{DefaultRetention:{Mode:fault.governance?'GOVERNANCE':'COMPLIANCE',
      Days:450}}}};
   case 'ListObjectVersionsCommand':{
    assert.equal(input.Prefix, input.MaxKeys===64?
     'paper/oauth-witness/pre-deny/v1/'+SUB+'/':KEY);
    const versions=state.stored?[{
     Key:KEY,VersionId:state.version,IsLatest:true,Size:state.bytes.length
    }]:[];
    if(fault.fork&&versions.length)versions.push({...versions[0],
     VersionId:'forked-version'});
    return {IsTruncated:fault.truncated===true,Versions:versions,
     DeleteMarkers:state.deleted||fault.marker?[{Key:KEY,VersionId:'marker'}]:[],
     CommonPrefixes:[]};
   }
   case 'HeadObjectCommand':
    if(!state.stored)throw Error('Not found');
    return {VersionId:state.version,ContentLength:state.bytes.length,
     DeleteMarker:state.deleted};
   case 'GetObjectRetentionCommand':
    return {Retention:{Mode:fault.objectGovernance?'GOVERNANCE':'COMPLIANCE',
     RetainUntilDate:new Date(NOW+(fault.expiring?1:450)*DAY)}};
   case 'GetObjectCommand':
    return {VersionId:state.version,Body:(async function*(){
     yield fault.corrupted?Buffer.from('untrusted data'):state.bytes;
    })()};
   default:throw Error('Unexpected S3 command '+kind);
  }
 }};
 const storage={provider:'backblaze-b2',
  endpoint:'https://s3.us-west-004.backblazeb2.com/',
  bucket:'independent-authority-bucket',
  reader,commands,clock:()=>NOW};
 const calls=[];
 const signBytes=async (bytes,{signal})=>{
  state.signs++;
  assert.ok(Buffer.isBuffer(bytes));
  assert.equal(bytes.subarray(0,
   Buffer.from('paper:oauth:pre-deny:head:v1\0').length).toString('hex'),
    Buffer.from('paper:oauth:pre-deny:head:v1\0').toString('hex'));
  assert.equal(typeof signal.aborted,'boolean');
  calls.push(Buffer.from(bytes));
  if(fault.kmsOffline)throw Error('KMS offline');
  if(fault.kmsHang)return new Promise(()=>{});
  if(fault.abortDuringSign)fault.abortDuringSign.abort();
  const signature=crypto.sign(null,bytes,
   fault.forgedKms?alternate.privateKey:KMS);
  if(fault.changeAfterSign)state.version='immutable-version-b';
  if(fault.disappearAfterSign)state.stored=false;
  if(fault.markerAfterSign)state.deleted=true;
  return signature;
 };
 const opts={storage,signBytes,trustedPublicKey:PUBLIC,
  authority:'paper-external-custodian.test',now:()=>AT,fixtureOnly:true,
  timeoutMs:fault.timeoutMs??1500};
 const signer=createDisposableImmutableDenialHeadSigner(opts);
 const readHead=challenge=>signer.respond(challenge);
 const verifier=createDisposablePreDenySignedHead({
  readHead,trustedPublicKey:PUBLIC,
  authority:'paper-external-custodian.test',now:()=>AT,
  timeoutMs:2000,fixtureOnly:true
 });
 const expected={subject:SUB,grantSha256:GRANT,revision:'7',
  operationId:OP,receiptSha256:SHA};
 const request=()=>signer.respond({
  kind:'paper.oauth.pre-deny.challenge.v1',subject:SUB,
  nonce:crypto.randomBytes(32).toString('base64url')
 });
 return {state,calls,signer,verifier,expected,request,opts};
}
const refused=(p,code)=>assert.rejects(p,e=>e?.code===code,
 'Expected precise error '+code);
test('separately signed BLOCKED head reconstructed from retained WORM after both restores',async()=>{
 const f=fixture();
 assert.equal(await f.verifier.assertDenied(f.expected),true);
 assert.equal(f.state.signs,1);
 assert.ok(f.state.s3Reads>10);
 assert.equal(f.state.restoredProviderEpoch,'1');
 assert.equal(f.state.oldSignerCachedState,'ACTIVE');
 assert.equal(f.calls.length,1);
 const raw=await f.request();
 const again=await f.request();
 assert.notEqual(JSON.parse(raw.body).nonce,JSON.parse(again.body).nonce,
  'New independent signer challenges cannot replay a previous head');
 assert.equal(raw.denied,true);
 assert.equal(raw.releaseAccepted,false);
 const head=JSON.parse(raw.body);
 assert.equal(head.receiptSha256,SHA);
 assert.equal(head.revision,'7');
 assert.equal(head.operationId,OP);
 assert.equal(head.grantSha256,GRANT);
 assert.equal(head.subject,SUB);
 assert.equal(head.kind,'paper.oauth.pre-deny.head.v1');
 assert.equal(f.signer.releaseAccepted,false);
 assert.deepEqual(new Set(f.state.commands.map(x=>x.kind)),
  new Set(commandsList));
 assert.equal(f.state.commands.some(x=>
  /^(Put|Delete|Copy|Upload)/.test(x.kind)),false);
});
test('old signer replay and independently rotated private key cannot forge current reply',async()=>{
 const f=fixture();
 const first=await f.request();
 const original=f.signer.respond;
 const stale=fixture();
 await refused(()=>stale.verifier.assertDenied({
  ...stale.expected,revision:'6'
 }), 'PRE_DENY_HEAD_SCOPE_INVALID');
 // Signed valid historical nonce is never accepted as a new nonce.
 const oldVerifier=createDisposablePreDenySignedHead({
  readHead:async()=>first,trustedPublicKey:PUBLIC,
  authority:'paper-external-custodian.test',now:()=>AT,
  timeoutMs:2000,fixtureOnly:true
 });
 await refused(()=>oldVerifier.assertDenied(f.expected),
  'PRE_DENY_HEAD_SCOPE_INVALID');
 const forged=fixture({forgedKms:true});
 await refused(()=>forged.request(),'DENIAL_SIGNER_SIGNATURE_INVALID');
 assert.equal(forged.state.signs,1);
 assert.equal(typeof original,'function');
});
test('missing WORM never signs ACTIVE, including restored signer cache',async()=>{
 const f=fixture();
 f.state.stored=false;
 await refused(()=>f.request(),'DENIAL_SIGNER_IMMUTABLE_HEAD_MISSING');
 assert.equal(f.state.signs,0);
 assert.equal(f.state.oldSignerCachedState,'ACTIVE');
});
test('fail closed on S3 object-lock degradation, missing, corrupted or forked history',async()=>{
 for(const fault of [
  {governance:true},{suspended:true},{objectGovernance:true},
  {truncated:true},{fork:true},{marker:true},{corrupted:true},
  {s3Offline:true},{expiring:true}
 ]){
  const f=fixture(fault);
  await refused(()=>f.request(),'DENIAL_SIGNER_WORM_UNAVAILABLE');
  assert.equal(f.state.signs,0);
 }
});
test('reconcile WORM again AFTER KMS signing; changed or deleted head cannot escape',async()=>{
 for(const fault of [
  {changeAfterSign:true},{disappearAfterSign:true},
  {markerAfterSign:true}
 ]){
  const f=fixture(fault);
  await refused(()=>f.request(),fault.changeAfterSign?
   'DENIAL_SIGNER_HEAD_CHANGED':'DENIAL_SIGNER_POST_SIGN_WORM_UNAVAILABLE');
  assert.equal(f.state.signs,1);
 }
});
test('bad external signing key, lost KMS and expired deadline cannot release signatures',async()=>{
 const bad=fixture({kmsOffline:true});
 await refused(()=>bad.request(),'DENIAL_SIGNER_KMS_UNAVAILABLE');
 const wrong=fixture({forgedKms:true});
 await refused(()=>wrong.request(),'DENIAL_SIGNER_SIGNATURE_INVALID');
 const hang=fixture({kmsHang:true,timeoutMs:500});
 await refused(()=>hang.request(),'DENIAL_SIGNER_KMS_UNAVAILABLE');
 const f=fixture();
 assert.throws(()=>createDisposableImmutableDenialHeadSigner({
  ...f.opts,trustedPublicKey:KMS
 }),e=>e?.code==='DENIAL_SIGNER_KEY_UNSAFE');
 assert.throws(()=>createDisposableImmutableDenialHeadSigner({
  ...f.opts,trustedPublicKey:'-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----'
 }),e=>e?.code==='DENIAL_SIGNER_KEY_UNSAFE');
});
test('in-flight caller cancellation after KMS prevents a late denial-head response',async()=>{
 const controller=new AbortController();
 const f=fixture({abortDuringSign:controller});
 await refused(()=>f.signer.respond({
  kind:'paper.oauth.pre-deny.challenge.v1',subject:SUB,
  nonce:crypto.randomBytes(32).toString('base64url'),
  signal:controller.signal
 }), 'DENIAL_SIGNER_CHALLENGE_ABORTED');
 assert.equal(f.state.signs,1);
});
test('strict challenge scope, abort and post-construction production gate',async()=>{
 const f=fixture();
 await refused(()=>f.signer.respond({
  kind:'paper.oauth.pre-deny.challenge.v1',subject:SUB,
  nonce:'user-selected'
 }), 'DENIAL_SIGNER_CHALLENGE_UNSAFE');
 await refused(()=>f.signer.respond({
  kind:'paper.oauth.pre-deny.challenge.v1',subject:SUB,
  nonce:crypto.randomBytes(32).toString('base64url'),
  ownerWebId:'https://wrong.example'
 }), 'DENIAL_SIGNER_CHALLENGE_UNSAFE');
 await refused(()=>f.signer.respond({
  kind:'paper.oauth.pre-deny.challenge.v1',subject:{toString:()=>SUB},
  nonce:crypto.randomBytes(32).toString('base64url')
 }), 'DENIAL_SIGNER_CHALLENGE_UNSAFE');
 await refused(()=>f.signer.respond({
  kind:'paper.oauth.pre-deny.challenge.v1',subject:SUB,
  nonce:crypto.randomBytes(32).toString('base64url'),
  signal:null
 }), 'DENIAL_SIGNER_CHALLENGE_UNSAFE');
 const stopped=new AbortController();stopped.abort();
 await refused(()=>f.signer.respond({
  kind:'paper.oauth.pre-deny.challenge.v1',subject:SUB,
  nonce:crypto.randomBytes(32).toString('base64url'),
  signal:stopped.signal
 }), 'DENIAL_SIGNER_CHALLENGE_UNSAFE');
 const key=f.request;
 const prev=process.env.NODE_ENV;
 process.env.NODE_ENV='production';
 try{
  await refused(()=>key(),'DENIAL_SIGNER_NOT_RELEASED');
  assert.throws(()=>createDisposableImmutableDenialHeadSigner(f.opts),
   e=>e?.code==='DENIAL_SIGNER_NOT_RELEASED');
 }finally{process.env.NODE_ENV=prev}
 assert.equal(f.state.signs,0);
});
