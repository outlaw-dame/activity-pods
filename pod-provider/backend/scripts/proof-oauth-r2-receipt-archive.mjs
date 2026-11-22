import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';
import {createR2ReceiptArchive} from '../candidates/oauth-r2-receipt-archive.mjs';

process.env.NODE_ENV='test';
process.env.PAPER_OAUTH_R2_DISPOSABLE='confirmed';
const owner='https://paper.example/users/alice';
const clientId='https://client.example/oidc';
const subject=crypto.createHash('sha256')
 .update('paper:witness:subject:v1\0'+owner+'\0'+clientId).digest('hex');
const prefix='paper/oauth-witness/epochs/v1/'+subject+'/';
const rules=[{id:'paper-witness-test-30-day-lock',enabled:true,
 prefix:'paper/oauth-witness/',condition:{type:'Age',maxAgeSeconds:2592000}}];
const commands=Object.fromEntries(['PutObjectCommand','HeadObjectCommand',
 'GetObjectCommand','ListObjectsV2Command'].map(n=>[n,class{
 constructor(input){this.input=input;this.type=n}
}]));
function epoch(n){
 const key=prefix+String(n).padStart(19,'0');
 const bytes=Buffer.from(JSON.stringify({kind:'paper.witness.epoch.v1',
  subject,revision:String(n),operationId:'11111111-1111-4111-8111-111111111111',
  eventSha256:crypto.createHash('sha256').update('event-'+n).digest('hex')}));
 return {key,bytes};
}
function fixture(options={}){
 const objects=new Map();
 const calls=[];
 const writer={async send(c){
  calls.push(c);
  if(c.type!=='PutObjectCommand')throw Error('writer not allowed to read');
  if(options.noWrite)throw Error('timeout before upload');
  const {Key,Body,IfNoneMatch}=c.input;
  assert.equal(IfNoneMatch,'*');
  if(objects.has(Key)||options.rejectWrite)throw Error('precondition failed');
  objects.set(Key,Buffer.from(Body));
  if(options.lostAck)throw Error('connection lost after commit');
  return {ETag:'"immutable"'};
 }};
 const reader={async send(c){
  calls.push(c);
  const key=c.input.Key;
  if(c.type==='HeadObjectCommand'){
   if(!objects.has(key))throw Error('NoSuchKey');
   return {ContentLength:objects.get(key).length};
  }
  if(c.type==='GetObjectCommand'){
   if(!objects.has(key))throw Error('NoSuchKey');
   return {Body:Buffer.from(objects.get(key))};
  }
  if(c.type==='ListObjectsV2Command'){
   const keys=[...objects.keys()].filter(k=>k.startsWith(c.input.Prefix)).sort();
   const shown=options.hideLatest?keys.slice(0,-1):keys;
   const pagesize=options.pageSize||1000;
   const page=Number(c.input.ContinuationToken||0);
   const slice=shown.slice(page,page+pagesize);
   return {Contents:slice.map(k=>({Key:k,Size:objects.get(k).length})),
    IsTruncated:page+pagesize<shown.length,
    NextContinuationToken:page+pagesize<shown.length?
     String(options.badToken?'0':page+pagesize):undefined};
  }
  throw Error('unsupported command');
 }};
 let lockRules=options.rules===undefined?rules:options.rules;
 const archive=createR2ReceiptArchive({writer,reader,commands,bucket:
  'paper-witness-disposable-tests',
  accountId:'a'.repeat(32),
  getLockRules:async()=>({rules:lockRules}),
  fixtureOnly:true,clock:()=>1795393000000});
 return {archive,calls,objects,setRules:r=>{lockRules=r}};
}
const checkpoint=o=>({subject,revision:JSON.parse(o.bytes).revision,
 sha256:crypto.createHash('sha256').update(o.bytes).digest('hex')});
async function denies(fn,code){
 await assert.rejects(fn,e=>e?.code===code);
}
test('explicit disposable test gate prevents accidental service activation',()=>{
 const f=fixture();
 assert.equal(f.archive.releaseAccepted,false);
 assert.equal(f.archive.independentlyImmutable,false);
 const config={writer:{send(){}},reader:{send(){}},commands,
  bucket:'paper-witness-disposable-tests',accountId:'a'.repeat(32),
  getLockRules:async()=>({rules}),fixtureOnly:false};
 assert.throws(()=>createR2ReceiptArchive(config),e=>e?.code==='R2_RECEIPT_NOT_RELEASED');
});
test('create-only canonical epoch, independently read; no unchecked overwrite',async()=>{
 const f=fixture();
 const e=epoch(1);
 const first=await f.archive.putAndVerify(e);
 assert.equal(first.sha256,checkpoint(e).sha256);
 assert.equal(first.independentlyImmutable,false);
 assert.equal(f.objects.size,1);
 // A duplicate write with identical bytes is idempotently read back.
 await f.archive.putAndVerify(e);
 await denies(()=>f.archive.putAndVerify({
  key:e.key,bytes:Buffer.from(e.bytes.toString().replace('eventSha256','eventHash'))
 }), 'S3_RECEIPT_FORMAT_INVALID');
 assert.equal(f.objects.size,1);
 assert.ok(f.calls.filter(c=>c.type==='PutObjectCommand')
  .every(c=>c.input.IfNoneMatch==='*'));
});
test('lost ACK recovers with exact readback, pre-write failure denies',async()=>{
 const e=epoch(1);
 const f=fixture({lostAck:true});
 await f.archive.putAndVerify(e);
 assert.equal(f.objects.size,1);
 const bad=fixture({noWrite:true});
 await denies(()=>bad.archive.putAndVerify(e),'R2_RECEIPT_HEAD_UNAVAILABLE');
});
test('30-day policy must cover entire witness prefix; no deletable bypass',async()=>{
 const e=epoch(1);
 const cases=[[{...rules[0],enabled:false}],
  [{...rules[0],prefix:'paper/oauth-witness/epochs/'}],
  [{...rules[0],condition:{type:'Age',maxAgeSeconds:3600}}],
  [{...rules[0],condition:{type:'Indefinite'}}],[]];
 for(const rules of cases){
  const f=fixture({rules});
  await denies(()=>f.archive.putAndVerify(e),'R2_RECEIPT_LOCK_UNVERIFIED');
  assert.equal(f.objects.size,0);
 }
 const f=fixture();
 await f.archive.putAndVerify(e);
 f.setRules([]);
 await denies(()=>f.archive.readLatestEpoch({owner,clientId,
  checkpoint:checkpoint(e)}),'R2_RECEIPT_LOCK_UNVERIFIED');
});
test('independently supplied external high-water detects missing latest',async()=>{
 const f=fixture();
 const a=epoch(1),b=epoch(2),c=epoch(3);
 for(const item of [a,b,c])await f.archive.putAndVerify(item);
 const proof=await f.archive.readLatestEpoch({owner,clientId,
  checkpoint:checkpoint(c)});
 assert.deepEqual(proof,c.bytes);
 await denies(()=>f.archive.readLatestEpoch({owner,clientId,
  checkpoint:checkpoint(b)}),'R2_HIGHWATER_CHECKPOINT_MISMATCH');
 f.objects.delete(c.key);
 await denies(()=>f.archive.readLatestEpoch({owner,clientId,
  checkpoint:checkpoint(c)}),'R2_HIGHWATER_CHECKPOINT_MISMATCH');
});
test('missing, forged or reconstructed checkpoints never approve',async()=>{
 const f=fixture();const a=epoch(1);
 await f.archive.putAndVerify(a);
 for(const cp of [null,{...checkpoint(a),subject:'f'.repeat(64)},
  {...checkpoint(a),sha256:'0'.repeat(64)}]){
  await denies(()=>f.archive.readLatestEpoch({owner,clientId,
   checkpoint:cp}),cp?.sha256==='0'.repeat(64)?
    'R2_HIGHWATER_CHECKPOINT_MISMATCH':'R2_HIGHWATER_CHECKPOINT_REQUIRED');
 }
});
test('hole, pagination, bad listing and unexpected scope reject',async()=>{
 const f=fixture({pageSize:1});
 await f.archive.putAndVerify(epoch(1));
 await f.archive.putAndVerify(epoch(2));
 await f.archive.putAndVerify(epoch(3));
 assert.equal(JSON.parse(await f.archive.readLatestEpoch({owner,clientId,
  checkpoint:checkpoint(epoch(3))})).revision,'3');
 f.objects.delete(epoch(2).key);
 await denies(()=>f.archive.readLatestEpoch({owner,clientId,
  checkpoint:checkpoint(epoch(3))}),'R2_HIGHWATER_GAP_OR_CAPACITY');
 const b=fixture();
 await b.archive.putAndVerify(epoch(1));
 await denies(()=>b.archive.readLatestEpoch({owner:'https://evil.example',clientId,
  checkpoint:checkpoint(epoch(1))}),'R2_HIGHWATER_CHECKPOINT_REQUIRED');
});
test('S3 exact canonical validator rejects invalid receipts and private text',async()=>{
 const f=fixture();
 await denies(()=>f.archive.putAndVerify({key:epoch(1).key,
  bytes:Buffer.from('some private user content')}),'S3_RECEIPT_FORMAT_INVALID');
});
