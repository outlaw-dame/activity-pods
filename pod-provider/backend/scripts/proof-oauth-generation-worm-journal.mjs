/** NONACTIVATED hostile external S3 generation-journal transitions and recovery. */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {createDisposableGenerationWormJournal} from
 '../../independent-authority/oauth-generation-worm-journal.mjs';
import {assertReceipt} from '../candidates/oauth-s3-compliance-archive.mjs';

if(process.env.NODE_ENV!=='test'||
 process.env.PAPER_OAUTH_GENERATION_JOURNAL_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE!=='confirmed')
 throw Error('Non-disposable generation journal proof is forbidden');

const SHA=x=>crypto.createHash('sha256').update(x).digest('hex');
const DAY=86400000,NOW=Date.UTC(2026,10,25,18,0,0);
const SUB='a'.repeat(64),EPOCH_SUB='d'.repeat(64);
const GRANT='b'.repeat(64),SCOPE='c'.repeat(64),OWNER='e'.repeat(64);
const ZERO='0'.repeat(64);
const OP1='a7d75d7d-403a-4940-8e42-f5c352eef572';
const OP2='b8e86e8e-514b-4a51-9f53-1b5d463f0683';
const GENERATION_BASE='paper/oauth-authority/generations/v1/'+SUB+'/';
const PRE_KEY='paper/oauth-witness/pre-deny/v1/'+SUB+
 '/0000000000000000001/'+OP2;
const PRE_BYTES=Buffer.from(JSON.stringify({
 kind:'paper.oauth.pre-deny.v1',subject:SUB,revision:'1',
 operationId:OP2,grantSha256:GRANT,credentialEpoch:'11',
 saiRevision:'9',scopeSha256:SCOPE
}));
const GENESIS={
 kind:'paper.oauth.authority-generation.v1',
 subject:SUB,epochSubject:EPOCH_SUB,sequence:'1',oauthRevision:'1',
 status:'active',grantSha256:GRANT,scopeSha256:SCOPE,
 credentialEpoch:'11',saiRevision:'9',ownerProofSha256:OWNER,
 preDenyReceiptSha256:ZERO,previousSha256:ZERO,operationId:OP1
};
const GENESIS_BYTES=Buffer.from(JSON.stringify(GENESIS));
const BLOCK={
 ...GENESIS,sequence:'2',status:'blocked',operationId:OP2,
 previousSha256:SHA(GENESIS_BYTES),preDenyReceiptSha256:SHA(PRE_BYTES)
};
const names=['ListObjectVersionsCommand','GetObjectCommand',
 'PutObjectCommand','GetBucketVersioningCommand',
 'GetObjectLockConfigurationCommand','HeadObjectCommand',
 'GetObjectRetentionCommand'];
let commands=Object.fromEntries(names.map(kind=>
 [kind,class {constructor(input){this.kind=kind;this.input=input}}]));
if(process.env.PAPER_OAUTH_S3_SDK_ENTRY){
 const path=process.env.PAPER_OAUTH_S3_SDK_ENTRY;
 if(!path.startsWith('/'))throw Error('Refuse relative S3 SDK entry');
 const sdk=await import(pathToFileURL(path).href);
 const exports=sdk.default??sdk;
 for(const name of names)assert.equal(typeof exports[name],'function');
 commands=exports;
}
const code=cmd=>cmd.kind??cmd.constructor.name;
const denied=(fn,expected)=>assert.rejects(fn,e=>e?.code===expected,
 'Expected exact rejection '+expected);
function fixture(opts={}){
 const stored=new Map();
 const state={stored,puts:0,reads:[],calls:[],versionCount:0,
  lostAck:opts.lostAck??null,ownerRevokedInPg:false,
  restoredCanonicalPg:'active',restoredSignerCache:'active'};
 function add(key,bytes){
  const versions=stored.get(key)||[];
  const v={Key:key,VersionId:'object-v'+(++state.versionCount),
   IsLatest:true,Size:bytes.length,Body:Buffer.from(bytes)};
  for(const x of versions)x.IsLatest=false;
  versions.push(v);stored.set(key,versions);
  return v;
 }
 if(opts.preDeny!==false)add(PRE_KEY,PRE_BYTES);
 function versions(prefix){
  let entries=[...stored.entries()]
   .flatMap(([key,items])=>key.startsWith(prefix)?items:[])
   .map(x=>({...x}));
  if(opts.reversed)entries.reverse();
  if(opts.duplicateVersion&&entries.length)
   entries.push({...entries[0],VersionId:'duplicate-version'});
  if(opts.hideLast&&entries.length)entries=entries.slice(0,-1);
  if(opts.gap&&entries.some(e=>e.Key.endsWith('0000000000000000002')))
   entries=entries.filter(e=>!e.Key.endsWith('0000000000000000001'));
  return entries;
 }
 const reader={config:{maxAttempts:async()=>opts.readerAttempts??1},
  send:async command=>{
   const name=code(command),input=command.input;
   assert.equal(input.Bucket,'independent-custody-fixture');
   state.reads.push(name);
   if(opts.readerOffline)throw Error('Unreachable independent S3');
   const entries=input.Key?stored.get(input.Key)||[]:[];
   const latest=entries.find(x=>x.IsLatest);
   switch(name){
    case 'GetBucketVersioningCommand':
     return {Status:opts.suspended?'Suspended':'Enabled'};
    case 'GetObjectLockConfigurationCommand':
     return {ObjectLockConfiguration:{ObjectLockEnabled:'Enabled',
      Rule:{DefaultRetention:{Mode:opts.governance?'GOVERNANCE':'COMPLIANCE',
       Days:430}}}};
    case 'ListObjectVersionsCommand':{
     let v=versions(input.Prefix);
     if(input.MaxKeys===10&&opts.historyFork&&v.length)
      v=[...v,{...v[0],VersionId:'unexpected'}];
     return {IsTruncated:opts.truncated===true,
      Versions:v.map(x=>({Key:x.Key,VersionId:x.VersionId,
       IsLatest:x.IsLatest,Size:x.Size})),
      DeleteMarkers:opts.marker?[{Key:input.Prefix,VersionId:'delete'}]:[],
      CommonPrefixes:[]};
    }
    case 'HeadObjectCommand':
     if(!latest)throw Error('Not found');
     return {VersionId:opts.headMismatched?'unknown':latest.VersionId,
      ContentLength:latest.Size,DeleteMarker:false};
    case 'GetObjectRetentionCommand':
     return {Retention:{Mode:opts.retentionGovernance?'GOVERNANCE':'COMPLIANCE',
      RetainUntilDate:new Date(NOW+(opts.expired?1:430)*DAY)}};
    case 'GetObjectCommand':{
     const v=entries.find(x=>x.VersionId===input.VersionId);
     if(!v)throw Error('No such version');
     return {VersionId:v.VersionId,Body:(async function*(){
      yield opts.corrupt?Buffer.from('bad'):v.Body;
     })()};
    }
    default:throw Error('Unexpected read '+name);
   }
  }};
 const writer={config:{maxAttempts:async()=>opts.writerAttempts??1},
  send:async command=>{
   const name=code(command),input=command.input;
   assert.equal(name,'PutObjectCommand');
   assert.equal(input.Bucket,'independent-custody-fixture');
   assert.equal(input.IfNoneMatch,'*');
   assert.equal(input.ContentType,'application/octet-stream');
   assert.equal(input.Key.startsWith(GENERATION_BASE),true);
   assert.ok(Buffer.isBuffer(input.Body));
   state.puts++;state.calls.push({name,input});
   if(opts.beforeLostAck)throw Error('Unknown before physical write');
   const v=stored.get(input.Key);
   if(v&&!opts.ignoreCondition)throw Error('Precondition failed');
   const result=add(input.Key,input.Body);
   if(opts.afterLostAck)throw Error('Unknown after durable write');
   return {VersionId:opts.wrongAck?'not-the-version':result.VersionId};
  }};
 const args={provider:'custom-s3',
  endpoint:'https://archive.identity-operator.example/',
  approvedEndpoint:'https://archive.identity-operator.example/',
  bucket:'independent-custody-fixture',
  reader,writer,commands,clock:()=>NOW,fixtureOnly:true};
 return {args,state,read:()=>createDisposableGenerationWormJournal(args).inspect(SUB),
  journal:createDisposableGenerationWormJournal(args),add};
}
test('canonical dual-status schema binds legacy epoch and v5 subject, chain hash, consent and PRE-DENY',()=>{
 const key=GENERATION_BASE+'0000000000000000001';
 assert.doesNotThrow(()=>assertReceipt(key,GENESIS_BYTES));
 assert.doesNotThrow(()=>assertReceipt(GENERATION_BASE+'0000000000000000002',
  Buffer.from(JSON.stringify(BLOCK))));
 for(const value of [
  {...GENESIS,epochSubject:SUB},
  {...GENESIS,sequence:1},
  {...GENESIS,ownerProofSha256:ZERO},
  {...GENESIS,preDenyReceiptSha256:SHA(PRE_BYTES)},
  {...GENESIS,previousSha256:SHA(PRE_BYTES)},
  {...GENESIS,extraField:'untrusted'},
  {...GENESIS,oauthRevision:'0'},
  {...GENESIS,subject:{toString:()=>SUB}},
  {...GENESIS,status:'blocked'},
  {...GENESIS,operationId:'anything'}
 ]){
  assert.throws(()=>assertReceipt(key,Buffer.from(JSON.stringify(value))),
   e=>e?.code==='S3_RECEIPT_FORMAT_INVALID');
 }
});
test('genesis ACTIVE and retained BLOCKED are observed but NEVER authorize restored login',async()=>{
 const f=fixture({reversed:true});
 let r=await f.journal.inspect(SUB);
 assert.equal(r.observedGenerations,0);
 assert.equal(r.activeAuthorizes,false);
 assert.equal(r.releaseAccepted,false);
 const initial=await f.journal.append(GENESIS);
 assert.equal(initial.observedGeneration,'1');
 assert.equal(initial.retainedBlocked,false);
 assert.equal(initial.activeAuthorizes,false);
 assert.equal(initial.conditionalCreateOnlyVerified,false);
 r=await f.journal.inspect(SUB);
 assert.equal(r.head.record.status,'active');
 assert.equal(r.activeAuthorizes,false,'Positive is not usable as access proof');
 assert.equal(r.completeExternallyVerified,false);
 const deniedHead=await f.journal.append(BLOCK);
 assert.equal(deniedHead.observedGeneration,'2');
 assert.equal(deniedHead.retainedBlocked,true);
 r=await f.read();
 assert.equal(r.observedGenerations,2);
 assert.equal(r.head.record.status,'blocked');
 assert.equal(r.head.sha256,SHA(Buffer.from(JSON.stringify(BLOCK))));
 assert.equal(r.activeAuthorizes,false);
 assert.equal(r.completeExternallyVerified,false);
 assert.equal(f.state.restoredCanonicalPg,'active');
 assert.equal(f.state.restoredSignerCache,'active');
 assert.equal(f.state.puts,2);
 assert.ok(f.state.reads.includes('GetObjectRetentionCommand'));
 assert.equal(f.state.reads.includes('DeleteObjectCommand'),false);
});
test('PRE-DENY must independently exist with matching operation and grant',async()=>{
 for(const fault of [{preDeny:false},{corrupt:true},{marker:true}]){
  const f=fixture(fault);
  await f.journal.append(GENESIS).catch(()=>{});
  // Separate corruption/marker faults may refuse earlier genesis;
  // absence itself must refuse the BLOCKED transition.
  await denied(()=>f.journal.append(BLOCK),
   'GENERATION_JOURNAL_PRE_DENY_UNVERIFIED');
 }
 const mismatch=fixture();
 await mismatch.journal.append(GENESIS);
 await denied(()=>mismatch.journal.append({
  ...BLOCK,operationId:OP1
 }), 'GENERATION_JOURNAL_TRANSITION_INVALID');
 await denied(()=>mismatch.journal.append({
  ...BLOCK,preDenyReceiptSha256:'f'.repeat(64)
 }), 'GENERATION_JOURNAL_PRE_DENY_UNVERIFIED');
});
test('replaying a block or trying to reactivate a revoked consent is denied',async()=>{
 const f=fixture();
 await f.journal.append(GENESIS);await f.journal.append(BLOCK);
 await denied(()=>f.journal.append(BLOCK),
  'GENERATION_JOURNAL_TRANSITION_INVALID');
 await denied(()=>f.journal.append({
  ...GENESIS,sequence:'3',oauthRevision:'2',
  operationId:'c9f97f9f-625c-4b62-8f64-2c6e57401994',
  previousSha256:SHA(Buffer.from(JSON.stringify(BLOCK))),
  grantSha256:'f'.repeat(64),ownerProofSha256:'f'.repeat(64),
  credentialEpoch:'12',saiRevision:'10'
 }), 'GENERATION_JOURNAL_TRANSITION_INVALID');
 assert.equal(f.state.puts,2);
});
test('ambiguous conditional PUT ACK never retries and reconciles exact object',async()=>{
 const after=fixture({afterLostAck:true});
 const result=await after.journal.append(GENESIS);
 assert.equal(result.observedGeneration,'1');
 assert.equal(after.state.puts,1);
 const before=fixture({beforeLostAck:true});
 await denied(()=>before.journal.append(GENESIS),
  'GENERATION_JOURNAL_COMMIT_AMBIGUOUS');
 assert.equal(before.state.puts,1);
 const wrong=fixture({wrongAck:true});
 await denied(()=>wrong.journal.append(GENESIS),
  'GENERATION_JOURNAL_COMMIT_AMBIGUOUS');
 assert.equal(wrong.state.puts,1);
});
test('forks, gaps, delete markers and unsafe historical retention fail closed',async()=>{
 for(const [fault,expected] of [
  [{truncated:true},'GENERATION_JOURNAL_HISTORY_INCOMPLETE'],
  [{suspended:true},'PORTABLE_WORM_BUCKET_NOT_COMPLIANT'],
  [{governance:true},'PORTABLE_WORM_BUCKET_NOT_COMPLIANT'],
  [{readerOffline:true},'PORTABLE_WORM_REMOTE_UNAVAILABLE'],
  [{marker:true},'GENERATION_JOURNAL_HISTORY_INCOMPLETE'],
  [{retentionGovernance:true},'GENERATION_JOURNAL_OBJECT_UNVERIFIED'],
  [{expired:true},'GENERATION_JOURNAL_OBJECT_UNVERIFIED'],
  [{corrupt:true},'GENERATION_JOURNAL_BODY_UNSAFE']
 ]){
  const f=fixture(fault);
  f.add(GENERATION_BASE+'0000000000000000001',GENESIS_BYTES);
  await denied(()=>f.read(),expected);
 }
 const duplicate=fixture({duplicateVersion:true});
 duplicate.add(GENERATION_BASE+'0000000000000000001',GENESIS_BYTES);
 await denied(()=>duplicate.read(),'GENERATION_JOURNAL_GAP_OR_FORK');
 const missing=fixture({gap:true});
 missing.add(GENERATION_BASE+'0000000000000000001',GENESIS_BYTES);
 missing.add(GENERATION_BASE+'0000000000000000002',
  Buffer.from(JSON.stringify(BLOCK)));
 await denied(()=>missing.read(),'GENERATION_JOURNAL_GAP_OR_FORK');
});
test('S3 gateways that ignore If-None-Match cannot hide a second version',async()=>{
 const f=fixture({ignoreCondition:true});
 await f.journal.append(GENESIS);
 // Both PUTs can write, but the second must fail after detecting the fork.
 await denied(()=>f.journal.append(GENESIS),
  'GENERATION_JOURNAL_TRANSITION_INVALID');
 // Hostile out-of-band write attempts are caught by ListObjectVersions.
 f.add(GENERATION_BASE+'0000000000000000001',GENESIS_BYTES);
 await denied(()=>f.read(),'GENERATION_JOURNAL_GAP_OR_FORK');
});
test('single-attempt SDK, exact scope and disabled-production boundary',async()=>{
 const retries=fixture({writerAttempts:3});
 await denied(()=>retries.journal.append(GENESIS),
  'GENERATION_JOURNAL_RETRY_UNSAFE');
 assert.equal(retries.state.puts,0);
 const reads=fixture({readerAttempts:4});
 await denied(()=>reads.read(),'GENERATION_JOURNAL_RETRY_UNSAFE');
 const f=fixture();
 await denied(()=>f.journal.inspect('ownerWebId'),
  'GENERATION_JOURNAL_SCOPE_INVALID');
 const old=process.env.NODE_ENV;process.env.NODE_ENV='production';
 try{
  await denied(()=>f.read(),'GENERATION_JOURNAL_NOT_RELEASED');
  await denied(()=>f.journal.append(GENESIS),
   'GENERATION_JOURNAL_NOT_RELEASED');
  assert.throws(()=>createDisposableGenerationWormJournal(f.args),
   e=>e?.code==='GENERATION_JOURNAL_NOT_RELEASED');
 }finally{process.env.NODE_ENV=old}
 assert.equal(f.state.puts,0);
});
