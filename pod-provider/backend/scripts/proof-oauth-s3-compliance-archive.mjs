/** NONACTIVATED real S3 command contract; isolated deterministic fake transport. */
import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {createS3ComplianceReceiptArchive} from
 '../candidates/oauth-s3-compliance-archive.mjs';

if(process.env.NODE_ENV!=='test'||
 process.env.PAPER_OAUTH_S3_COMPLIANCE_DISPOSABLE!=='confirmed')
 throw Error('Refusing non-disposable S3 COMPLIANCE regression');

const uuid='a7d75d7d-403a-4940-8e42-f5c352eef572';
const subject='a'.repeat(64);
const head1='bafyre'+'a'.repeat(53),head2='bafyre'+'b'.repeat(53);
const epochKey='paper/oauth-witness/epochs/v1/'+subject+'/0000000000000000001';
const epochBody=Buffer.from(JSON.stringify({
 kind:'paper.witness.epoch.v1',subject,revision:'1',
 operationId:uuid,eventSha256:'c'.repeat(64)
}));
const intentKey='paper/oauth-witness/signed-intents/v1/'+uuid+'/pending';
const intentBody=Buffer.from([
 'paper:witness:signed-intent:v1',subject,uuid,'1',
 'd'.repeat(64),'e'.repeat(64),head1,head2,'pending','pending','-',''
].join('\n'));
const resolvedKey=intentKey.replace('/pending','/resolved');
const resolvedBody=Buffer.from([
 'paper:witness:signed-intent:v1',subject,uuid,'1',
 'd'.repeat(64),'e'.repeat(64),head1,head2,'resolved','committed',head2,''
].join('\n'));
const now=Date.UTC(2026,10,22),DAY=86400000;
const commandNames=['PutObjectCommand','HeadObjectCommand','GetObjectCommand',
 'GetObjectRetentionCommand','GetBucketVersioningCommand',
 'GetObjectLockConfigurationCommand'];
let commands=Object.fromEntries(commandNames.map(kind=>
 [kind,class {constructor(input){this.kind=kind;this.input=input}}]));
if(process.env.PAPER_OAUTH_S3_SDK_ENTRY){
 const path=process.env.PAPER_OAUTH_S3_SDK_ENTRY;
 if(!path.startsWith('/'))throw Error('S3 SDK proof requires an absolute pin');
 const sdk=await import(pathToFileURL(path).href);
 const exports=sdk.default??sdk;
 for(const kind of commandNames)
  assert.equal(typeof exports[kind],'function','Missing published SDK '+kind);
 commands=exports;
}
function fixture(opts={}){
 const state={map:new Map(),reads:[],writes:[],headReads:0,mode:opts.mode??'COMPLIANCE',
  versioning:opts.versioning??'Enabled',enabled:opts.enabled??'Enabled',
  years:opts.years??0,days:opts.days??401,
  expiry:Object.hasOwn(opts,'expiry')?opts.expiry:new Date(now+401*DAY)};
 const writer={send:async cmd=>{
  assert.equal(cmd.kind??cmd.constructor.name,'PutObjectCommand');
  assert.equal(cmd.input.Bucket,'paper-immutable-archive');
  assert.equal(cmd.input.IfNoneMatch,'*');
  assert.equal(cmd.input.ContentMD5,
   crypto.createHash('md5').update(cmd.input.Body).digest('base64'));
  assert.equal(cmd.input.ChecksumSHA256,
   crypto.createHash('sha256').update(cmd.input.Body).digest('base64'));
  state.writes.push(cmd.kind??cmd.constructor.name);
  if(opts.write==='fail-before')throw Error('lost before write');
  if(state.map.has(cmd.input.Key))throw Error('PreconditionFailed');
  const version='s3-version-'+state.map.size;
  state.map.set(cmd.input.Key,{
   bytes:Buffer.from(cmd.input.Body),version
  });
  if(opts.write==='lost-after')throw Error('lost response after successful PUT');
  return {VersionId:version};
 }};
 const reader={send:async cmd=>{
  const kind=cmd.kind??cmd.constructor.name;
  state.reads.push(kind);
  const obj=state.map.get(cmd.input.Key);
  switch(kind){
   case 'GetBucketVersioningCommand':
    if(opts.policyUnavailable)throw Error('Denied lock policy');
    return {Status:state.versioning};
   case 'GetObjectLockConfigurationCommand':
    if(opts.policyUnavailable)throw Error('Policy hidden');
    return {ObjectLockConfiguration:{ObjectLockEnabled:state.enabled,
      Rule:{DefaultRetention:{Mode:state.mode,Days:state.days,
       Years:state.years}}}};
   case 'HeadObjectCommand':
    state.headReads++;
    if(opts.missing||!obj)throw Error('NoSuchKey');
    if(opts.headDenied)throw Error('AccessDenied');
    return {VersionId:opts.changeVersion&&state.headReads>=2?
       'changed-version':obj.version,
      ContentLength:obj.bytes.length,DeleteMarker:opts.deleteMarker??false};
   case 'GetObjectRetentionCommand':
    if(!obj)throw Error('NoSuchKey');
    if(opts.retentionUnavailable)throw Error('Denied retention read');
    return {Retention:{Mode:opts.retentionMode??'COMPLIANCE',
      RetainUntilDate:state.expiry}};
   case 'GetObjectCommand':
    if(!obj)throw Error('NoSuchKey');
    if(opts.getUnavailable)throw Error('Denied content read');
    if(opts.readVersionMismatch)return {VersionId:'wrong',Body:obj.bytes};
    if(opts.overlong){
      return {VersionId:obj.version,Body:(async function*(){
       yield Buffer.alloc(1025,1);
      })()};
    }
    const bytes=opts.corrupt?Buffer.from('bad-contents'):obj.bytes;
    return {VersionId:obj.version,Body:(async function*(){
     yield bytes.subarray(0,9);yield bytes.subarray(9);
    })()};
   default:throw Error('Unsupported command '+kind);
  }
 }};
 const archive=createS3ComplianceReceiptArchive({
  writer,reader,commands,bucket:'paper-immutable-archive',
  minRetentionDays:400,clock:()=>now,fixtureOnly:true
 });
 return {archive,state,writer,reader};
}
async function denies({archive},key,bytes,code){
 await assert.rejects(archive.putAndVerify({key,bytes}),
  e=>e?.code===code,'Expected fail-closed '+code);
}
test('real S3 compliance contract: conditional PUT, exact locked version, independent readback',async()=>{
 const f=fixture();
 const result=await f.archive.putAndVerify({key:epochKey,bytes:epochBody});
 assert.equal(result.versionId,'s3-version-0');
 assert.equal(result.sha256,crypto.createHash('sha256').update(epochBody).digest('hex'));
 assert.equal(f.state.reads.filter(x=>x==='GetObjectLockConfigurationCommand').length,3);
 assert.equal(f.state.reads.filter(x=>x==='GetBucketVersioningCommand').length,3);
 assert.equal(f.state.reads.filter(x=>x==='HeadObjectCommand').length,2);
 assert.equal(f.state.reads.filter(x=>x==='GetObjectRetentionCommand').length,1);
 assert.equal(f.state.writes.length,1);
 assert.equal((await f.archive.putAndVerify({key:epochKey,bytes:epochBody})).versionId,result.versionId,
  'Conditional PUT conflict is safe only with independently verified identical object');
 assert.equal(f.state.map.size,1);
});
test('both pending and committed receipts can be archived but cannot be overwritten',async()=>{
 const f=fixture();
 await f.archive.putAndVerify({key:intentKey,bytes:intentBody});
 await f.archive.putAndVerify({key:resolvedKey,bytes:resolvedBody});
 assert.equal(f.state.map.size,2);
 await denies(f,intentKey,Buffer.from(intentBody.toString().replace('d'.repeat(64),'f'.repeat(64))),
  'S3_RECEIPT_BYTES_MISMATCH');
});
test('ambiguous PUT ACK reconciles only through independent exact locked read',async()=>{
 const f=fixture({write:'lost-after'});
 await f.archive.putAndVerify({key:epochKey,bytes:epochBody});
 assert.equal(f.state.map.size,1);
 await denies(f,epochKey,Buffer.from(JSON.stringify({
  kind:'paper.witness.epoch.v1',subject,revision:'1',
  operationId:uuid,eventSha256:'d'.repeat(64)
 })), 'S3_RECEIPT_BYTES_MISMATCH');
 const absent=fixture({write:'fail-before'});
 await denies(absent,epochKey,epochBody,'S3_RECEIPT_HEAD_UNAVAILABLE');
});
test('rejects governance, no default COMPLIANCE, missing versioning and disabled lock',async()=>{
 for(const options of [
  {mode:'GOVERNANCE'},{mode:undefined,days:40},{days:350},
  {versioning:'Suspended'},{enabled:'Disabled'},
  {policyUnavailable:true}
 ]){
  const f=fixture(options);
  await denies(f,epochKey,epochBody,'S3_RECEIPT_LOCK_UNVERIFIED');
  assert.equal(f.state.writes.length,0);
 }
});
test('rejects wrong object retention mode or insufficient per-version retention',async()=>{
 for(const o of [
  {retentionMode:'GOVERNANCE'},
  {expiry:new Date(now+390*DAY)},
  {expiry:'not-a-date'},
  {expiry:null},
  {retentionUnavailable:true}
 ]){
  const f=fixture(o);
  await denies(f,epochKey,epochBody,o.retentionUnavailable?
   'S3_RECEIPT_RETENTION_UNAVAILABLE':'S3_RECEIPT_RETENTION_UNVERIFIED');
 }
});
test('rejects byte tamper, version swap, delete marker and oversized stream',async()=>{
 for(const [o,code] of [
  [{corrupt:true},'S3_RECEIPT_BYTES_MISMATCH'],
  [{changeVersion:true},'S3_RECEIPT_VERSION_CHANGED'],
  [{readVersionMismatch:true},'S3_RECEIPT_VERSION_MISMATCH'],
  [{deleteMarker:true},'S3_RECEIPT_HEAD_INVALID'],
  [{overlong:true},'S3_RECEIPT_READBACK_TOO_LARGE'],
  [{getUnavailable:true},'S3_RECEIPT_READBACK_UNAVAILABLE'],
  [{headDenied:true},'S3_RECEIPT_HEAD_UNAVAILABLE']
 ]){
  await denies(fixture(o),epochKey,epochBody,code);
 }
});
test('rejects foreign identifiers, altered receipt encoding, and owner/client PII',async()=>{
 const variants=[
  {key:epochKey.replace(subject,'f'.repeat(64)),bytes:epochBody},
  {key:epochKey,bytes:Buffer.from(epochBody.toString()+'\n')},
  {key:epochKey,bytes:Buffer.from('https://paper.example.org/secrets')},
  {key:intentKey.replace('/pending','/resolved'),bytes:intentBody},
  {key:intentKey,bytes:Buffer.from(intentBody.toString().replace(head2,head1))},
  {key:resolvedKey,bytes:Buffer.from(resolvedBody.toString().replace(head2,'-'))},
  {key:intentKey,bytes:Buffer.from(intentBody.toString().replace(uuid,'abcd'))},
  {key:'paper/oauth-witness/highwater/current',bytes:epochBody},
  {key:epochKey,bytes:Buffer.alloc(1025)}
 ];
 for(const v of variants)
  await denies(fixture(),v.key,v.bytes,'S3_RECEIPT_FORMAT_INVALID');
});
test('rejects missing explicit test gate and privilege aliases',async()=>{
 assert.throws(()=>createS3ComplianceReceiptArchive({
  ...fixtureConfig(),fixtureOnly:false
 }),e=>e?.code==='S3_RECEIPT_NOT_RELEASED');
 const f=fixture();
 assert.throws(()=>createS3ComplianceReceiptArchive({
  writer:f.reader,reader:f.reader,commands,
  bucket:'paper-immutable-archive',minRetentionDays:400,
  fixtureOnly:true
 }),e=>e?.code==='S3_RECEIPT_CONFIGURATION_INVALID');
});
function fixtureConfig(){
 const f=fixture();
 return {writer:f.writer,reader:f.reader,commands,
  bucket:'paper-immutable-archive',minRetentionDays:400,clock:()=>now};
}
