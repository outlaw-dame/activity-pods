import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';
import {createR2ReceiptArchive} from '../candidates/oauth-r2-receipt-archive.mjs';
import {createDisposableR2CheckpointAuthority,
 encodeSignedEpochCheckpoint} from '../candidates/oauth-r2-signed-checkpoint.mjs';
process.env.NODE_ENV='test';
process.env.PAPER_OAUTH_R2_DISPOSABLE='confirmed';
const owner='https://paper.example/users/alice';
const clientId='https://client.example/oidc';
const subject=crypto.createHash('sha256').update(
 'paper:witness:subject:v1\0'+owner+'\0'+clientId).digest('hex');
const keys=crypto.generateKeyPairSync('ed25519');
const other=crypto.generateKeyPairSync('ed25519');
const authorityId='independent-witness-one';
const rules=[{id:'paper',enabled:true,prefix:'paper/oauth-witness/',
 condition:{type:'Age',maxAgeSeconds:2592000}}];
const commands=Object.fromEntries(['PutObjectCommand','HeadObjectCommand',
 'GetObjectCommand','ListObjectsV2Command'].map(n=>[n,class{
 constructor(input){this.type=n;this.input=input}
}]));
const buildEpoch=(n)=>{
 const key='paper/oauth-witness/epochs/v1/'+subject+'/'+
  String(n).padStart(19,'0');
 const bytes=Buffer.from(JSON.stringify({kind:'paper.witness.epoch.v1',
  subject,revision:String(n),operationId:'11111111-1111-4111-8111-111111111111',
  eventSha256:crypto.createHash('sha256').update('event-'+n).digest('hex')}));
 return {key,bytes};
};
const signed=(e,privateKey=keys.privateKey)=>encodeSignedEpochCheckpoint({
 authority:authorityId,subject,revision:JSON.parse(e.bytes).revision,
 sha256:crypto.createHash('sha256').update(e.bytes).digest('hex'),
 privateKey
});
function fixture(){
 const objects=new Map(),calls=[];
 const writer={async send(c){
  calls.push(c.type);
  if(c.type!=='PutObjectCommand'||objects.has(c.input.Key))throw Error('denied');
  objects.set(c.input.Key,Buffer.from(c.input.Body));return {};
 }};
 const reader={async send(c){
  calls.push(c.type);
  if(c.type==='HeadObjectCommand'){
   if(!objects.has(c.input.Key))throw Error('missing');
   return {ContentLength:objects.get(c.input.Key).length};
  }
  if(c.type==='GetObjectCommand'){
   if(!objects.has(c.input.Key))throw Error('missing');
   return {Body:Buffer.from(objects.get(c.input.Key))};
  }
  // Never allow a history scan on this admission path.
  if(c.type==='ListObjectsV2Command')throw Error('history scan forbidden');
  throw Error('unexpected command');
 }};
 const archive=createR2ReceiptArchive({
  writer,reader,commands,bucket:'paper-witness-disposable-tests',
  accountId:'a'.repeat(32),getLockRules:async()=>({rules}),
  fixtureOnly:true
 });
 let response=null,reads=0,updateAfterFirst=null;
 const authority=createDisposableR2CheckpointAuthority({
  authority:authorityId,trustedPublicKey:keys.publicKey,
  readHead:async()=>{
   reads++;
   if(reads===2&&updateAfterFirst)response=updateAfterFirst;
   return response;
  },
  fixtureOnly:true
 });
 return {objects,calls,archive,authority,reads:()=>reads,
  setHead:v=>{response=v},advanceAtSecond:v=>{updateAfterFirst=v}};
}
const params=f=>({owner,clientId,authority:f.authority});
async function denied(fn,code){await assert.rejects(fn,e=>e?.code===code)}
test('actual pinned Ed25519 identity and exact canonical detached signature',async()=>{
 const f=fixture(),e=buildEpoch(1);
 await f.archive.putAndVerify(e);
 f.setHead(signed(e));
 const bytes=await f.archive.readCertifiedLatestEpoch(params(f));
 assert.deepEqual(bytes,e.bytes);
 assert.equal(f.reads(),2);
 assert.equal(f.calls.includes('ListObjectsV2Command'),false);
 assert.equal(f.calls.filter(x=>x==='HeadObjectCommand').length,2);
});
test('restored old R2 record rejected by externally signed latest epoch',async()=>{
 const f=fixture(),a=buildEpoch(1),b=buildEpoch(2);
 await f.archive.putAndVerify(a);
 f.setHead(signed(b));
 await denied(()=>f.archive.readCertifiedLatestEpoch(params(f)),
  'R2_RECEIPT_HEAD_UNAVAILABLE');
});
test('authority advances during R2 read: stale generation is rejected',async()=>{
 const f=fixture(),a=buildEpoch(1),b=buildEpoch(2);
 await f.archive.putAndVerify(a);
 f.setHead(signed(a));f.advanceAtSecond(signed(b));
 await denied(()=>f.archive.readCertifiedLatestEpoch(params(f)),
  'R2_CERT_CONCURRENT_ADVANCE');
});
test('missing/forged/malformed certificate and wrong authority deny',async()=>{
 const e=buildEpoch(1);
 for(const [response,code] of [
  [null,'R2_CERT_FORMAT_INVALID'],
  [signed(e,other.privateKey),'R2_CERT_SIGNATURE_INVALID'],
  [{...signed(e),signature:Buffer.alloc(64)},'R2_CERT_SIGNATURE_INVALID'],
  [{...signed(e),body:Buffer.concat([signed(e).body,Buffer.from(' ')])},
   'R2_CERT_SCOPE_INVALID'],
  [signed({...e,bytes:Buffer.from(e.bytes.toString().replace(subject,'f'.repeat(64))) }),
   'R2_CERT_RECEIPT_MISMATCH']
 ]){
  const f=fixture();await f.archive.putAndVerify(e);f.setHead(response);
  await denied(()=>f.archive.readCertifiedLatestEpoch(params(f)),code);
 }
});
test('different audience owner or client cannot reuse a signed checkpoint',async()=>{
 const f=fixture(),e=buildEpoch(1);
 await f.archive.putAndVerify(e);f.setHead(signed(e));
 await denied(()=>f.archive.readCertifiedLatestEpoch({
  owner:'https://paper.example/users/mallory',clientId,authority:f.authority
 }),'R2_CERT_SCOPE_INVALID');
});
test('unbranded caller-supplied readVerified cannot spoof authority',async()=>{
 const f=fixture(),e=buildEpoch(1);
 await f.archive.putAndVerify(e);
 await denied(()=>f.archive.readCertifiedLatestEpoch({owner,clientId,
  authority:{readVerified:async()=>({
   subject,revision:'1',sha256:'f'.repeat(64)
  })}
 }),'R2_CERT_AUTHORITY_REQUIRED');
});
test('explicit test gate refuses production signer/reader',()=>{
 const f=fixture();
 assert.equal(f.authority.releaseAccepted,false);
 assert.throws(()=>createDisposableR2CheckpointAuthority({
  authority:authorityId,trustedPublicKey:keys.publicKey,
  readHead:()=>{},fixtureOnly:false
 }),e=>e?.code==='R2_CERT_NOT_RELEASED');
});
test('cannot accept signer from arbitrary runtime or invalid key algorithms',()=>{
 assert.throws(()=>createDisposableR2CheckpointAuthority({
  authority:authorityId,trustedPublicKey:'unsafe key',readHead:()=>{},
  fixtureOnly:true
 }),e=>e?.code==='R2_CERT_KEY_INVALID');
 const rsa=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
 assert.throws(()=>createDisposableR2CheckpointAuthority({
  authority:authorityId,trustedPublicKey:rsa.publicKey,
  readHead:()=>{},fixtureOnly:true
 }),e=>e?.code==='R2_CERT_CONFIG_INVALID');
});
