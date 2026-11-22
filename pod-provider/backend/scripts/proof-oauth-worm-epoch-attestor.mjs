/** Disposable in-memory transport proof; NOT a real immutable R2/S3 bucket. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import {createDisposableWormEpochAttestor} from
 '../candidates/oauth-worm-epoch-attestor.mjs';

if(process.env.NODE_ENV!=='test' ||
   process.env.PAPER_OAUTH_WITNESS_DISPOSABLE!=='confirmed' ||
   process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE!=='confirmed')
 throw Error('Refusing immutable receipt test outside disposable gate');

const input=Object.freeze({
 owner:'https://paper.example.org/users/worm-test',
 clientId:'https://paper-client.example.org/oauth',
 revision:'1',operationId:'ddfdf4a5-7fcd-48b9-948c-ec1b79f6e0a2'
});
const digest=crypto.createHash('sha256').update('event-proof').digest();
function createFixture({
 retention=true,afterWriteRetention=true,
 writeMode='normal',readMode='normal',sealMode='ok'
}={}){
 const objects=new Map(),history=[];
 let checks=0;
 const callbacks={
  fixtureOnly:true,
  readUnsealed:async()=>Buffer.from(digest),
  putIfAbsent:async(key,bytes,conditions)=>{
   history.push(['put',key,conditions]);
   assert.equal(conditions.ifNoneMatch,'*');
   if(writeMode==='fail-before')throw Error('Write unavailable');
   if(objects.has(key))throw Error('Already exists');
   objects.set(key,Buffer.from(bytes));
   if(writeMode==='fail-after')throw Error('ACK lost after commit');
  },
  getIndependent:async key=>{
   history.push(['get',key]);
   if(readMode==='error')throw Error('Independent GET unavailable');
   if(readMode==='missing')return null;
   if(readMode==='corrupt')return Buffer.from('different');
   return Buffer.from(objects.get(key)??[]);
  },
  verifyRetention:async key=>{
   history.push(['retention',key]);
   checks++;
   return checks===1?retention:afterWriteRetention;
  },
  seal:async args=>{
   history.push(['seal',args.operationId]);
   assert.equal(args.owner,input.owner);
   assert.equal(args.clientId,input.clientId);
   assert.equal(args.revision,input.revision);
   assert.ok(args.eventHash.equals(digest));
   if(sealMode==='throw')throw Error('Independent witness unavailable');
   return sealMode==='ok';
  }
 };
 return {objects,history,callbacks,
  attestor:createDisposableWormEpochAttestor(callbacks)};
}
function called(f,name){return f.history.filter(i=>i[0]===name).length}
async function denies(f,code,params=input){
 await assert.rejects(f.attestor.attestEpoch(params),e=>e?.code===code);
 assert.equal(called(f,'seal'),0,'No witness seal on unverified receipt');
}

test('fail closed outside explicit fixture-only mode',async()=>{
 const a=createDisposableWormEpochAttestor({
  ...createFixture().callbacks,fixtureOnly:false
 });
 await assert.rejects(a.attestEpoch(input),e=>e?.code==='WORM_RECEIPT_NOT_RELEASED');
});
test('successful epoch is immutable, read back and privacy pseudonymized',async()=>{
 const f=createFixture();
 assert.equal(await f.attestor.attestEpoch(input),true);
 assert.equal(called(f,'retention'),2);
 assert.equal(called(f,'put'),1);
 assert.equal(called(f,'get'),1);
 assert.equal(called(f,'seal'),1);
 const [[key,payload]]=f.objects;
 assert.match(key,/^paper\/oauth-witness\/epochs\/v1\/[a-f0-9]{64}\/0{18}1$/u);
 assert.ok(!key.includes(input.owner)&&!key.includes(input.clientId));
 const text=payload.toString('utf8');
 assert.ok(!text.includes(input.owner)&&!text.includes(input.clientId));
 assert.equal(JSON.parse(text).eventSha256,digest.toString('hex'));
 await assert.rejects(f.callbacks.putIfAbsent(key,Buffer.from('overwrite'),
  {ifNoneMatch:'*'}));
 assert.equal(f.objects.get(key).toString('utf8'),text);
});
test('denies unverified retention before any write',async()=>{
 const f=createFixture({retention:false});
 await denies(f,'WORM_RECEIPT_RETENTION_UNVERIFIED');
 assert.equal(called(f,'put'),0);
});
test('denies policy removal after write and before seal',async()=>{
 const f=createFixture({afterWriteRetention:false});
 await denies(f,'WORM_RECEIPT_RETENTION_UNVERIFIED');
 assert.equal(called(f,'get'),1);
});
test('denies missing, corrupt or unreachable independent readback',async()=>{
 for(const mode of ['missing','corrupt','error']){
  const f=createFixture({readMode:mode});
  await denies(f,mode==='error'?'WORM_RECEIPT_READBACK_UNAVAILABLE':
   'WORM_RECEIPT_READBACK_MISMATCH');
 }
});
test('an ambiguous PUT ACK cannot authorize unless independent GET matches',async()=>{
 const lost=createFixture({writeMode:'fail-after'});
 assert.equal(await lost.attestor.attestEpoch(input),true);
 assert.equal(called(lost,'seal'),1);
 const absent=createFixture({writeMode:'fail-before'});
 await denies(absent,'WORM_RECEIPT_READBACK_MISMATCH');
});
test('sealing errors are never treated as authorization',async()=>{
 await denies(createFixture({sealMode:'no'}),'WORM_RECEIPT_SEAL_REFUSED');
 await denies(createFixture({sealMode:'throw'}),'WORM_RECEIPT_SEAL_UNAVAILABLE');
});
test('refuses forged identity, operation and noncanonical revision',async()=>{
 for(const params of [
  {...input,owner:'http://paper.example.org/users/worm-test'},
  {...input,clientId:'https://paper.example.org/oauth?q=1'},
  {...input,operationId:'not-uuid'}
 ]){
  await denies(createFixture(),'WORM_RECEIPT_IDENTITY_INVALID',params);
 }
 for(const revision of ['0','01','-1','9223372036854775808',1]){
  await denies(createFixture(),'WORM_RECEIPT_REVISION_INVALID',
   {...input,revision});
 }
});
test('does not trust malformed or missing witness digest',async()=>{
 for(const value of [null,Buffer.from('wrong')]){
  const f=createFixture();
  f.callbacks.readUnsealed=async()=>value;
  const attestor=createDisposableWormEpochAttestor(f.callbacks);
  await assert.rejects(attestor.attestEpoch(input),
   e=>e?.code==='WORM_RECEIPT_EVENT_INVALID');
  assert.equal(called(f,'put'),0);
 }
});
