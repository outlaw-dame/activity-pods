/** NONACTIVATED portable S3 pre-denial inventory adversarial proof. */
import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {inspectDisposablePortablePreDenyInventory} from
 '../candidates/oauth-portable-pre-deny-inventory.mjs';

if(process.env.NODE_ENV!=='test'||
 process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE!=='confirmed')
 throw Error('Refusing non-disposable immutable inventory test');

const subject='a'.repeat(64),uuid='a7d75d7d-403a-4940-8e42-f5c352eef572';
const key='paper/oauth-witness/pre-deny/v1/'+subject+
 '/0000000000000000007/'+uuid;
const validBody=Buffer.from(JSON.stringify({
 kind:'paper.oauth.pre-deny.v1',subject,revision:'7',
 operationId:uuid,grantSha256:'b'.repeat(64),credentialEpoch:'11',
 saiRevision:'5',scopeSha256:'c'.repeat(64)
}));
const currentDate=Date.UTC(2026,10,25),DAY=86400000;
const kinds=['ListObjectVersionsCommand','GetObjectCommand',
 'GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
 'GetObjectRetentionCommand','HeadObjectCommand'];
let commands=Object.fromEntries(kinds.map(kind=>
 [kind,class {constructor(input){this.kind=kind;this.input=input}}]));
if(process.env.PAPER_OAUTH_S3_SDK_ENTRY){
 const path=process.env.PAPER_OAUTH_S3_SDK_ENTRY;
 if(!path.startsWith('/'))throw Error('SDK entry must be absolute');
 const sdk=await import(pathToFileURL(path).href);
 const exports=sdk.default??sdk;
 for(const kind of kinds)assert.equal(typeof exports[kind],'function');
 commands=exports;
}
function fixture(fault={}){
 const reads=[],version='s3-exact-version',body=fault.corrupt?
  Buffer.from('corrupted receipt'):validBody;
 let outerList=0;
 const reader={send:async command=>{
  const kind=command.kind??command.constructor.name;
  const input=command.input;
  reads.push(kind);
  assert.equal(input.Bucket,'paper-archive-disposable');
  switch(kind){
   case 'GetBucketVersioningCommand':
    return {Status:fault.versioningOff?'Suspended':'Enabled'};
   case 'GetObjectLockConfigurationCommand':
    return {ObjectLockConfiguration:{ObjectLockEnabled:'Enabled',
     Rule:{DefaultRetention:{Mode:fault.governance?'GOVERNANCE':'COMPLIANCE',
      Days:401}}}};
   case 'ListObjectVersionsCommand':{
    if(fault.listLost)throw Error('simulated unavailable listing');
    if(input.MaxKeys===64)outerList++;
    const empty=fault.empty===true;
    const isOuter=input.MaxKeys===64;
    const changed=fault.changeDuringRead&&outerList>=2;
    const filename=fault.foreignKey?key.replace(subject,'d'.repeat(64)):key;
    const entries=empty?[]:[{
     Key:filename,VersionId:changed?'new-version':version,
     IsLatest:true,Size:validBody.length
    }];
    if(fault.duplicate)entries.push({...entries[0],VersionId:'second-version'});
    return {
     Versions:entries,DeleteMarkers:fault.deleteMarker?[{Key:key,VersionId:'marker'}]:[],
     CommonPrefixes:[],IsTruncated:fault.truncated===true
    };
   }
   case 'HeadObjectCommand':
    return {VersionId:fault.headWrong?'wrong-version':version,
     ContentLength:validBody.length,DeleteMarker:false};
   case 'GetObjectRetentionCommand':
    return {Retention:{Mode:fault.retentionGovernance?'GOVERNANCE':'COMPLIANCE',
     RetainUntilDate:new Date(currentDate+(fault.expired?1:401)*DAY)}};
   case 'GetObjectCommand':
    if(fault.getLost)throw Error('read lost');
    return {VersionId:fault.getWrong?'wrong-version':version,
     Body:(async function*(){yield body;})()};
   default:throw Error('Unexpected S3 command '+kind);
  }
 }};
 const args={provider:'backblaze-b2',
  endpoint:'https://s3.us-west-004.backblazeb2.com/',
  bucket:'paper-archive-disposable',reader,commands,subject,
  clock:()=>currentDate,fixtureOnly:true};
 return {args,reads,call:()=>inspectDisposablePortablePreDenyInventory(args)};
}
async function deny(f,code){
 await assert.rejects(f.call(),e=>e?.code===code,
  'Expected fail-closed code '+code);
}
test('retained immutable PRE-DENY blocks a rewound SQL grant; no enable verdict',async()=>{
 const f=fixture(),v=await f.call();
 assert.equal(v.retainedDenialObserved,true);
 assert.equal(v.retainedDenial.subject,subject);
 assert.equal(v.retainedDenial.revision,'7');
 assert.equal(v.retainedDenial.operationId,uuid);
 assert.equal(v.retainedDenial.versionId,'s3-exact-version');
 assert.equal(v.retainedDenial.receiptSha256,
  crypto.createHash('sha256').update(validBody).digest('hex'));
 assert.equal(v.absenceAuthorizes,false);
 assert.equal(v.monotonicLatestHeadVerified,false);
 assert.equal(v.operatorIndependenceVerified,false);
 assert.equal(v.releaseAccepted,false);
 assert.ok(f.reads.filter(x=>x==='ListObjectVersionsCommand').length>=3);
});
test('empty S3 inventory does NOT prove permission to issue a JWT or sign a PDS write',async()=>{
 const result=await fixture({empty:true}).call();
 assert.equal(result.retainedDenialObserved,false);
 assert.equal(result.retainedDenial,null);
 assert.equal(result.absenceAuthorizes,false);
 assert.equal(result.releaseAccepted,false);
});
test('deny incomplete, hidden, ambiguous or forked pre-denial inventory',async()=>{
 for(const fault of [
  {truncated:true},{duplicate:true},{deleteMarker:true},{foreignKey:true}
 ]){
  await deny(fixture(fault),'PRE_DENY_INVENTORY_FORK_OR_INCOMPLETE');
 }
 await deny(fixture({changeDuringRead:true}),
  'PRE_DENY_INVENTORY_CHANGED_DURING_READ');
 await deny(fixture({listLost:true}),
  'PRE_DENY_INVENTORY_LIST_UNAVAILABLE');
});
test('exact-version receipt must remain readable, canonical, retained and current',async()=>{
 for(const [fault,code] of [
  [{getLost:true},'PRE_DENY_INVENTORY_BODY_UNAVAILABLE'],
  [{getWrong:true},'PRE_DENY_INVENTORY_VERSION_CHANGED'],
  [{corrupt:true},'PRE_DENY_INVENTORY_BODY_UNSAFE'],
  [{headWrong:true},'PRE_DENY_INVENTORY_READBACK_UNVERIFIED'],
  [{retentionGovernance:true},'PRE_DENY_INVENTORY_READBACK_UNVERIFIED'],
  [{expired:true},'PRE_DENY_INVENTORY_READBACK_UNVERIFIED']
 ])await deny(fixture(fault),code);
});
test('refuse unsafe bucket compliance and unsupported external endpoints',async()=>{
 for(const fault of [{governance:true},{versioningOff:true}]){
  await assert.rejects(fixture(fault).call(),
   e=>e?.code==='PORTABLE_WORM_BUCKET_NOT_COMPLIANT');
 }
 const f=fixture();f.args.endpoint='https://attacker.invalid/';
 await assert.rejects(f.call(),
  e=>e?.code==='PORTABLE_WORM_ENDPOINT_UNSAFE');
});
test('read-only inventory rejects untrusted subject and non-disposable execution',async()=>{
 const f=fixture();
 f.args.subject='NOT-HEX';
 await deny(f,'PRE_DENY_INVENTORY_CONFIGURATION_UNSAFE');
 const g=fixture();
 const before=process.env.NODE_ENV;
 process.env.NODE_ENV='production';
 try{await deny(g,'PRE_DENY_INVENTORY_NOT_RELEASED')}
 finally{process.env.NODE_ENV=before}
 assert.deepEqual(g.reads,[]);
});
