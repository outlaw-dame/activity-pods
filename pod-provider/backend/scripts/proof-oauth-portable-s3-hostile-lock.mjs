/**
 * Disposable hostile S3 COMPLIANCE object-version qualification proof.
 * No actual external storage, real account or irreversible mutation.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {probeDisposableS3HostileObjectLock} from
 '../candidates/oauth-portable-s3-hostile-lock-probe.mjs';

const DAY=86400000;
const NOW=Date.UTC(2026,10,25,18,0,0);
const SUBJECT='a'.repeat(64);
const KEY='paper/oauth-witness/epochs/v1/'+SUBJECT+'/0000000000000000001';
const BUCKET='paper-worm-disposable-hostilefixture';
const VERSION='version-001';
const endpoint='https://objects.vendor-domain.com/';
const payload=Buffer.from(JSON.stringify({
 kind:'paper.witness.epoch.v1',subject:SUBJECT,revision:'1',
 operationId:'a7d75d7d-403a-4940-8e42-f5c352eef572',
 eventSha256:'d'.repeat(64)
 }));
const SHA=crypto.createHash('sha256').update(payload).digest('hex');
const sample=Object.freeze({key:KEY,versionId:VERSION,sha256:SHA});
const names=['GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
 'ListObjectVersionsCommand','HeadObjectCommand','GetObjectRetentionCommand',
 'GetObjectCommand','DeleteObjectCommand','PutObjectRetentionCommand'];
let commands=Object.fromEntries(names.map(kind=>[kind,
 class {constructor(input){this.kind=kind;this.input=input}}
]));
if(process.env.PAPER_OAUTH_S3_SDK_ENTRY){
 const sdk=await import(pathToFileURL(process.env.PAPER_OAUTH_S3_SDK_ENTRY).href);
 const exports=sdk.default??sdk;
 for(const name of names)assert.equal(typeof exports[name],'function');
 commands=exports;
}
function kind(cmd){return cmd.kind??cmd.constructor.name}
function fault(code){return e=>e?.code===code}
async function refused(fn,code){await assert.rejects(fn,fault(code))}
function fixture(options={}){
 const bucket=options.bucket??BUCKET;
 const provider=options.provider??'custom-s3';
 const origin=provider==='storj'?'https://gateway.storjshare.io/':endpoint;
 const state={reads:[],mutations:[],retentionReads:0,
  original:NOW+440*DAY,retention:NOW+440*DAY,deleted:false,
  markers:[],versions:1};
 const reader={config:{maxAttempts:async()=>options.readerAttempts??1},
  send:async cmd=>{
   const name=kind(cmd),input=cmd.input;
   state.reads.push({name,input});
   assert.equal(input.Bucket,bucket);
   if(options.offline)throw Error('Simulated offline storage');
   if(name==='GetBucketVersioningCommand')
    return {Status:options.suspended?'Suspended':'Enabled'};
   if(name==='GetObjectLockConfigurationCommand')
    return {ObjectLockConfiguration:{ObjectLockEnabled:'Enabled',
     Rule:{DefaultRetention:{Mode:options.governance?'GOVERNANCE':'COMPLIANCE',
      Days:450}}}};
   if(name==='ListObjectVersionsCommand')
    return {IsTruncated:!!options.truncated,
     Versions:state.deleted?[]:Array.from({length:state.versions},(_,i)=>({
      Key:KEY,VersionId:i===0?VERSION:'unexpected-version',
      IsLatest:i===0,Size:payload.length
     })),
     DeleteMarkers:state.markers,CommonPrefixes:[]};
   if(name==='HeadObjectCommand'){
    if(state.deleted)throw Error('Deleted');
    return {VersionId:VERSION,DeleteMarker:false,ContentLength:payload.length};
   }
   if(name==='GetObjectRetentionCommand'){
    state.retentionReads++;
    if(options.retriableReadOnce&&state.retentionReads===2)
     throw Object.assign(Error('Retryable'),{
      $metadata:{httpStatusCode:503}});
    return {Retention:{Mode:options.retentionGovernance?'GOVERNANCE':'COMPLIANCE',
     RetainUntilDate:new Date(state.retention)}};
   }
   if(name==='GetObjectCommand')
    return {VersionId:VERSION,Body:(async function*(){
     yield options.corrupt?Buffer.from('tampered'):Buffer.from(payload);
    })()};
   throw Error('Invalid reader command: '+name);
  }};
 const adversary={config:{maxAttempts:async()=>options.adversaryAttempts??1},
  send:async cmd=>{
   const name=kind(cmd),input=cmd.input;
   assert.ok(['DeleteObjectCommand','PutObjectRetentionCommand'].includes(name));
   assert.deepEqual(Object.keys(input).sort(),name==='DeleteObjectCommand'?
    ['Bucket','Key','VersionId']:[
     'Bucket','Key','Retention','VersionId'
    ]);
   assert.equal(input.Bucket,bucket);
   assert.equal(input.Key,KEY);
   assert.equal(input.VersionId,VERSION);
   if(name==='PutObjectRetentionCommand'){
    assert.equal(input.Retention.Mode,'COMPLIANCE');
    assert.equal(input.Retention.RetainUntilDate.getTime(),
     state.original-DAY);
   }
   state.mutations.push({name,input});
   if(name==='DeleteObjectCommand'&&options.acceptDelete){
    state.deleted=true;return {$metadata:{httpStatusCode:204}};
   }
   if(name==='PutObjectRetentionCommand'&&options.acceptShortening){
    state.retention=input.Retention.RetainUntilDate.getTime();
    return {$metadata:{httpStatusCode:200}};
   }
   if(name==='DeleteObjectCommand'&&options.createMarkerOnDenial)
    state.markers.push({Key:KEY,VersionId:'delete-marker'});
   if(name==='PutObjectRetentionCommand'&&options.changeOnDenial)
    state.retention-=DAY;
   if(options.transientMutations)
    throw Object.assign(Error('Offline'),{$metadata:{httpStatusCode:503},
     name:'ServiceUnavailable'});
   if(options.ambiguous409)
    throw Object.assign(Error('Conflict'),{$metadata:{httpStatusCode:409},
     name:'OperationAborted'});
   return Promise.reject(Object.assign(Error('Denied by provider'),{
    name:options.denialName??'AccessDenied',
    $metadata:{httpStatusCode:options.denialStatus??403}
   }));
  }};
 const args={provider,endpoint:origin,
  approvedEndpoint:provider==='custom-s3'?origin:null,
  bucket,reader,adversary:null,
  commands,sample,phase:'preflight',clock:()=>NOW,
  plannedAdversaryProfile:'dedicated-hostile-principal'};
 const observe=()=>probeDisposableS3HostileObjectLock(args);
 const hostile=async approval=>probeDisposableS3HostileObjectLock({
  ...args,phase:'hostile',adversary,explicitApproval:approval});
 return {args,adversary,reader,state,observe,hostile};
}
async function approval(f){
 const first=await f.observe();
 return 'hostile-locked-version:'+first.approvalChallenge;
}
async function withGate(task){
 const original=process.env.PAPER_PORTABLE_WORM_HOSTILE_DISPOSABLE;
 process.env.PAPER_PORTABLE_WORM_HOSTILE_DISPOSABLE='confirmed';
 try{return await task()}finally{
  if(original===undefined)delete process.env.PAPER_PORTABLE_WORM_HOSTILE_DISPOSABLE;
  else process.env.PAPER_PORTABLE_WORM_HOSTILE_DISPOSABLE=original;
 }
}
test('existing bare Storj bucket passes preflight and keeps hostile approval scoped',async()=>{
 await withGate(async()=>{
  const bucket='paper-worm-disposable';
  const f=fixture({bucket,provider:'storj'});
  const preflight=await f.observe();
  assert.equal(preflight.phase,'preflight');
  assert.equal(f.state.mutations.length,0);
  const result=await f.hostile('hostile-locked-version:'+preflight.approvalChallenge);
  assert.equal(result.exactVersionDeleteRejected,true);
  assert.equal(result.shorteningRejected,true);
  assert.equal(result.releaseAccepted,false);
  assert.equal(f.state.mutations.length,2);
  for(const entry of f.state.mutations)
   assert.equal(entry.input.Bucket,bucket);
  const wrong=fixture({bucket,provider:'storj'});
  const suffixChallenge=await approval(fixture());
  await refused(()=>wrong.hostile(suffixChallenge),
   'PORTABLE_WORM_HOSTILE_OPERATOR_APPROVAL_REQUIRED');
  assert.equal(wrong.state.mutations.length,0);
 });
});
test('bare disposable bucket cannot be re-used on other S3 providers',async()=>{
 for(const provider of ['custom-s3','backblaze-b2']){
  const f=fixture({provider,bucket:'paper-worm-disposable'});
  await refused(f.observe,'PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
  assert.equal(f.state.reads.length,0);
  assert.equal(f.state.mutations.length,0);
 }
});
test('lookalike bare Storj bucket labels remain invalid before any read',async()=>{
 for(const bucket of [
  'paper-worm-disposable-','paper-worm-disposablex',
  'paper-worm-disposable.test','paper-worm-disposable-foo',
  'paper-worm-disposable--evil','production-authority'
 ]){
  const f=fixture({bucket});
  await refused(f.observe,'PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
  assert.equal(f.state.reads.length,0);
  assert.equal(f.state.mutations.length,0);
 }
});
test('preflight verifies real-shaped COMPLIANCE version without invoking any writer',async()=>{
 const f=fixture();
 const result=await f.observe();
 assert.equal(result.phase,'preflight');
 assert.match(result.approvalChallenge,/^[a-f0-9]{64}$/u);
 assert.equal(result.retentionUntil,new Date(f.state.original).toISOString());
 assert.equal(result.exactVersionObserved,true);
 assert.equal(result.releaseAccepted,false);
 assert.equal(result.iamEnforcementProven,false);
 assert.equal(result.independentAdministrationVerified,false);
 assert.equal(f.state.mutations.length,0);
 assert.ok(f.state.reads.some(x=>x.name==='ListObjectVersionsCommand'));
 assert.ok(f.state.reads.some(x=>x.name==='GetObjectRetentionCommand'));
});
test('exact S3 VersionId delete and one-day retention shortening each denied and independently reverified',async()=>{
 await withGate(async()=>{
  const f=fixture();
  const result=await f.hostile(await approval(f));
  assert.equal(result.exactVersionDeleteRejected,true);
  assert.equal(result.shorteningRejected,true);
  assert.equal(result.noDeleteMarkerObserved,true);
  assert.equal(result.originalBytesVerifiedAfterMutations,true);
  assert.equal(result.iamEnforcementProven,false);
  assert.equal(result.releaseAccepted,false);
  assert.deepEqual(f.state.mutations.map(x=>x.name),[
   'DeleteObjectCommand','PutObjectRetentionCommand'
  ]);
  assert.equal(f.state.retention,f.state.original);
 });
});
test('hostile mutation is denied without exact first-phase approval; zero writes',async()=>{
 const f=fixture();
 await refused(()=>f.hostile('hostile-locked-version:'+'1'.repeat(64)),
  'PORTABLE_WORM_HOSTILE_OPERATOR_APPROVAL_REQUIRED');
 assert.equal(f.state.mutations.length,0);
 await withGate(async()=>{
  await refused(()=>f.hostile('hostile-locked-version:'+'2'.repeat(64)),
   'PORTABLE_WORM_HOSTILE_OPERATOR_APPROVAL_REQUIRED');
  assert.equal(f.state.mutations.length,0);
 });
});
test('preflight and hostile refuse unsafe bucket, synthetic key, roles, SDK retries and transport',async()=>{
 const f=fixture();
 await refused(()=>probeDisposableS3HostileObjectLock({
  ...f.args,bucket:'production-oauth-archive'}),
 'PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
 await refused(()=>probeDisposableS3HostileObjectLock({
  ...f.args,sample:{...sample,key:'paper/real-production-token'}}),
 'PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
 await refused(()=>probeDisposableS3HostileObjectLock({
  ...f.args,sample:{...sample,versionId:'\u0080'.repeat(400)}}),
 'PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
 await refused(()=>probeDisposableS3HostileObjectLock({
  ...f.args,phase:'hostile',adversary:f.reader}),
 'PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
 const retries=fixture({readerAttempts:3});
 await refused(retries.observe,'PORTABLE_WORM_HOSTILE_RETRY_UNSAFE');
 const hostileRetries=fixture({adversaryAttempts:3});
 await withGate(async()=>{
  const token=await approval(hostileRetries);
  await refused(()=>hostileRetries.hostile(token),
   'PORTABLE_WORM_HOSTILE_RETRY_UNSAFE');
 });
 assert.equal(f.state.mutations.length,0);
});
test('operator challenge binds the planned adversarial principal label',async()=>{
 await withGate(async()=>{
  const f=fixture();
  const token=await approval(f);
  await refused(()=>probeDisposableS3HostileObjectLock({
   ...f.args,plannedAdversaryProfile:'swapped-credentials',
   phase:'hostile',adversary:f.adversary,explicitApproval:token
  }), 'PORTABLE_WORM_HOSTILE_OPERATOR_APPROVAL_REQUIRED');
  assert.equal(f.state.mutations.length,0);
  await refused(()=>probeDisposableS3HostileObjectLock({
   ...f.args,plannedAdversaryProfile:'',phase:'preflight'
  }), 'PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
 });
});
test('unsafe policy, expiry, tampering, altered version history and missing provider fail before mutation',async()=>{
 for(const fault of [
  {suspended:true},{governance:true},{retentionGovernance:true},
  {offline:true},{truncated:true},{corrupt:true}
 ]){
  const f=fixture(fault);
  await refused(f.observe,'PORTABLE_WORM_HOSTILE_EVIDENCE_UNVERIFIED');
  assert.equal(f.state.mutations.length,0);
 }
});
test('a successful exact version delete is a critical failure, never do next mutation',async()=>{
 await withGate(async()=>{
  const f=fixture({acceptDelete:true});
  await refused(async()=>f.hostile(await approval(f)),
   'PORTABLE_WORM_HOSTILE_MUTATION_ACCEPTED');
  assert.deepEqual(f.state.mutations.map(x=>x.name),['DeleteObjectCommand']);
 });
});
test('a successful retention shortening is a critical failure after successful denied exact delete',async()=>{
 await withGate(async()=>{
  const f=fixture({acceptShortening:true});
  await refused(async()=>f.hostile(await approval(f)),
   'PORTABLE_WORM_HOSTILE_MUTATION_ACCEPTED');
  assert.equal(f.state.mutations.length,2);
 });
});
test('403 or 400 mutations cannot conceal marker or changed retention',async()=>{
 await withGate(async()=>{
  const marker=fixture({createMarkerOnDenial:true});
  await refused(async()=>marker.hostile(await approval(marker)),
   'PORTABLE_WORM_HOSTILE_EVIDENCE_UNVERIFIED');
  assert.equal(marker.state.mutations.length,1);
  const shortened=fixture({changeOnDenial:true});
  await refused(async()=>shortened.hostile(await approval(shortened)),
   'PORTABLE_WORM_HOSTILE_RETENTION_CHANGED');
  assert.equal(shortened.state.mutations.length,2);
 });
});
test('ambiguous 409 and 503 are not accepted as Object Lock evidence and NEVER retried',async()=>{
 await withGate(async()=>{
  for(const fault of [{ambiguous409:true},{transientMutations:true}]){
   const f=fixture(fault);
   await refused(async()=>f.hostile(await approval(f)),
    'PORTABLE_WORM_HOSTILE_MUTATION_AMBIGUOUS');
   assert.equal(f.state.mutations.length,1);
  }
 });
});
test('read-only 503 is retried with bounded backoff, not an S3 write',async()=>{
 const f=fixture({retriableReadOnce:true});
 const result=await f.observe();
 assert.equal(result.phase,'preflight');
 assert.equal(f.state.retentionReads,3);
 assert.equal(f.state.mutations.length,0);
});
test('unexpected denied status or errors cannot masquerade as compliance',async()=>{
 await withGate(async()=>{
  for(const fault of [
   {denialStatus:404},{denialStatus:403,denialName:'NoSuchKey'},
   {denialStatus:429,denialName:'AccessDenied'}
  ]){
   const f=fixture(fault);
   await refused(async()=>f.hostile(await approval(f)),
    'PORTABLE_WORM_HOSTILE_MUTATION_AMBIGUOUS');
   assert.equal(f.state.mutations.length,1);
  }
 });
});
test('phase separation is strict; unknown extra profile or approval never enables preflight mutation',async()=>{
 const f=fixture();
 await refused(()=>probeDisposableS3HostileObjectLock({
  ...f.args,phase:'hostile',adversary:f.adversary,
  explicitApproval:'hostile-locked-version:'+'a'.repeat(64)
 }), 'PORTABLE_WORM_HOSTILE_OPERATOR_APPROVAL_REQUIRED');
 await refused(()=>probeDisposableS3HostileObjectLock({
  ...f.args,phase:'preflight',adversary:f.adversary
 }), 'PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
 assert.equal(f.state.mutations.length,0);
});
