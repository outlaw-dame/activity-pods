/**
 * Deterministic AWS S3/STS command proof for operator-only custody.
 * NONACTIVATED: all transport fake, no AWS credentials or live bucket.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import path from 'node:path';
import test from 'node:test';
import {inspectIndependentS3Custody} from
 '../candidates/oauth-s3-independent-custody.mjs';

if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_S3_COMPLIANCE_DISPOSABLE!=='confirmed')
  throw Error('Refusing nondisposable S3 custody test');

const provider='111122223333',archive='999988887777';
const now=Date.UTC(2026,10,22),DAY=86400000;
const subject='a'.repeat(64);
const key='paper/oauth-witness/epochs/v1/'+subject+'/0000000000000000001';
const bytes=Buffer.from(JSON.stringify({
  kind:'paper.witness.epoch.v1',
  subject,revision:'1',
  operationId:'a7d75d7d-403a-4940-8e42-f5c352eef572',
  eventSha256:'b'.repeat(64)
}));
const sample={
  key,versionId:'real-s3-version-1',
  sha256:crypto.createHash('sha256').update(bytes).digest('hex')
};
const names=['GetCallerIdentityCommand','GetBucketVersioningCommand',
  'GetObjectLockConfigurationCommand','GetPublicAccessBlockCommand',
  'ListObjectVersionsCommand','HeadObjectCommand','GetObjectRetentionCommand',
  'GetObjectCommand'];
let commands=Object.fromEntries(names.map(name=>[
  name,class {constructor(input){this.input=input;this.kind=name;}}
]));
if(process.env.PAPER_WORM_SDK_ROOT){
  const require=createRequire(path.join(process.env.PAPER_WORM_SDK_ROOT,'package.json'));
  const servicePackages=['@aws-sdk/client-s3','@aws-sdk/client-sts'];
  const sdk={...require(servicePackages[0]),...require(servicePackages[1])};
  for(const name of names){
    assert.equal(typeof sdk[name],'function','Missing real AWS constructor '+name);
  }
  commands=sdk;
}
function make(options={}){
  const activity={writer:[],reader:[],s3:[]};
  const kind=cmd=>cmd.kind??cmd.constructor.name;
  const writerSts={send:async cmd=>{
    activity.writer.push(kind(cmd));
    if(kind(cmd)!=='GetCallerIdentityCommand')throw Error('Unexpected writer capability');
    return {Account:options.writerAccount??provider,
      Arn:options.writerArn??'arn:aws:sts::'+provider+':assumed-role/PaperRestrictedWriter/session',
      UserId:'AROAWRITER:session'};
  }};
  const readerSts={send:async cmd=>{
    activity.reader.push(kind(cmd));
    if(kind(cmd)!=='GetCallerIdentityCommand')throw Error('Unexpected reader capability');
    return {Account:options.readerAccount??archive,
      Arn:options.readerArn??'arn:aws:sts::'+archive+':assumed-role/IndependentReadOnly/session',
      UserId:'AROAREADER:session'};
  }};
  const readerS3={send:async cmd=>{
    const name=kind(cmd),p=cmd.input;
    activity.s3.push(name);
    assert.equal(p.Bucket,'paper-worm-independent');
    assert.equal(p.ExpectedBucketOwner,archive,
      'Bucket ownership must be checked by AWS on every operation');
    if(options.remoteFailure)throw Error('AccessDenied');
    switch(name){
      case 'GetBucketVersioningCommand':
        return {Status:options.versioning??'Enabled'};
      case 'GetObjectLockConfigurationCommand':
        return {ObjectLockConfiguration:{ObjectLockEnabled:options.enabled??'Enabled',
          Rule:{DefaultRetention:{Mode:options.mode??'COMPLIANCE',
            Days:options.days??401}}}};
      case 'GetPublicAccessBlockCommand':
        return {PublicAccessBlockConfiguration:{
          BlockPublicAcls:true,IgnorePublicAcls:true,
          BlockPublicPolicy:options.publicPolicy??true,RestrictPublicBuckets:true}};
      case 'ListObjectVersionsCommand':
        assert.equal(p.KeyMarker,undefined);
        assert.equal(p.Prefix,key);
        return {Versions:options.duplicate?[
          {Key:key,VersionId:sample.versionId,IsLatest:true,Size:bytes.length},
          {Key:key,VersionId:'old',IsLatest:false,Size:bytes.length}
        ]:[{Key:key,VersionId:options.listVersion??sample.versionId,
          IsLatest:true,Size:bytes.length}],
          DeleteMarkers:options.deleteMarkers?[{Key:key,VersionId:'deleted'}]:[],
          IsTruncated:options.truncated??false};
      case 'HeadObjectCommand':
        assert.equal(p.Key,key);
        return {VersionId:options.headVersion??sample.versionId,
          ContentLength:bytes.length,DeleteMarker:options.headDeleted??false};
      case 'GetObjectRetentionCommand':
        assert.equal(p.VersionId,sample.versionId);
        return {Retention:{Mode:options.retentionMode??'COMPLIANCE',
          RetainUntilDate:options.retentionUntil??new Date(now+401*DAY)}};
      case 'GetObjectCommand':
        assert.equal(p.VersionId,sample.versionId);
        return {VersionId:options.responseVersion??sample.versionId,
          Body:(async function*(){
            const contents=options.body??bytes;
            if(options.overlong)yield Buffer.alloc(1025);
            else{yield contents.subarray(0,13);yield contents.subarray(13);}
          })()};
      default:throw Error('Unrecognized AWS capability '+name);
    }
  }};
  return {activity,arguments:{
    writerSts,readerSts,readerS3,commands,
    bucket:'paper-worm-independent',
    expectedProviderAccount:provider,
    expectedBucketOwner:archive,clock:()=>now
  }};
}
async function denied(f,code,sampleArgument=sample){
  await assert.rejects(inspectIndependentS3Custody({
    ...f.arguments,sample:sampleArgument
  }),e=>e?.code===code,code);
}
test('read-only independently controlled cross-account bucket preflight is NOT release acceptance',async()=>{
  const f=make();
  const result=await inspectIndependentS3Custody(f.arguments);
  assert.deepEqual(result,{
    configurationVerified:true,receiptVerified:false,
    releaseAccepted:false,retentionDays:401
  });
  assert.deepEqual(f.activity.writer,['GetCallerIdentityCommand']);
  assert.deepEqual(f.activity.reader,['GetCallerIdentityCommand']);
  assert.deepEqual(f.activity.s3.sort(),[
    'GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
    'GetPublicAccessBlockCommand'
  ].sort());
});
test('verified independent owner and retained receipt is STILL not signed release',async()=>{
  const f=make();
  const result=await inspectIndependentS3Custody({...f.arguments,sample});
  assert.equal(result.configurationVerified,true);
  assert.equal(result.receiptVerified,true);
  assert.equal(result.releaseAccepted,false);
  assert.equal(result.payloadSha256,sample.sha256);
  assert.equal(f.activity.s3.filter(x=>x==='HeadObjectCommand').length,2);
  assert.equal(f.activity.s3.filter(x=>x==='GetBucketVersioningCommand').length,2);
  assert.ok(!f.activity.s3.some(x=>/Put|Delete|Change|RetentionSet/.test(x)));
});
test('refuses provider and archive in one AWS account, weak owner IDs, malformed clients',async()=>{
  const f=make();
  for(const override of [
    {expectedProviderAccount:archive},
    {expectedProviderAccount:'not-an-aws-account'},
    {expectedBucketOwner:'99998888777a'},
    {bucket:'bad-name/'},
    {writerSts:null}
  ])await assert.rejects(inspectIndependentS3Custody({
    ...f.arguments,...override
  }),e=>e?.code==='WORM_CUSTODY_CONFIGURATION_INVALID');
  assert.equal(f.activity.s3.length,0);
});
test('rejects same-account STS credentials, root principal, wrong role and unverified STS',async()=>{
  for(const opts of [
    {writerAccount:archive},
    {readerAccount:provider},
    {writerArn:'arn:aws:iam::111122223333:root'},
    {readerArn:'arn:aws:iam::999988887777:user/Administrator'},
    {writerArn:'arn:aws:sts::999988887777:assumed-role/Owner/session'},
    {remoteFailure:true}
  ])await denied(make(opts),opts.remoteFailure?
    'WORM_CUSTODY_REMOTE_UNAVAILABLE':'WORM_CUSTODY_PRINCIPALS_NOT_INDEPENDENT');
});
test('refuses governance, no versioning, missing public block or weak default retention',async()=>{
  for(const opts of [
    {mode:'GOVERNANCE'},{versioning:'Suspended'},{enabled:'Disabled'},
    {days:90},{publicPolicy:false}
  ])await denied(make(opts),'WORM_CUSTODY_BUCKET_UNSAFE');
});
test('rejects unexpected historical versions, delete markers and truncated lists',async()=>{
  for(const opts of [
    {duplicate:true},{deleteMarkers:true},{truncated:true},
    {listVersion:'not-the-expected-version'}
  ])await denied(make(opts),'WORM_CUSTODY_VERSION_HISTORY_UNSAFE');
});
test('denies wrong head, expired/noncompliant retention, or rewritten object',async()=>{
  const attempts=[
    [{headVersion:'foreign'},'WORM_CUSTODY_RECEIPT_HEAD_INVALID'],
    [{headDeleted:true},'WORM_CUSTODY_RECEIPT_HEAD_INVALID'],
    [{retentionMode:'GOVERNANCE'},'WORM_CUSTODY_RETENTION_INVALID'],
    [{retentionUntil:new Date(now+2*DAY)},'WORM_CUSTODY_RETENTION_INVALID'],
    [{responseVersion:'different'},'WORM_CUSTODY_VERSION_CHANGED'],
    [{overlong:true},'WORM_CUSTODY_BODY_TOO_LARGE'],
    [{body:Buffer.from('a'.repeat(bytes.length))},'WORM_CUSTODY_BODY_INVALID']
  ];
  for(const [opts,code] of attempts)await denied(make(opts),code);
});
test('receipt hash must be independently supplied and exact',async()=>{
  const f=make();
  await denied(f,'WORM_CUSTODY_RECEIPT_HASH_MISMATCH',{
    ...sample,sha256:'0'.repeat(64)
  });
  await denied(make(),'WORM_CUSTODY_RECEIPT_INPUT_INVALID',{
    ...sample,key:'paper/oauth-witness/epochs/v1/not-a-key'
  });
  await denied(make(),'WORM_CUSTODY_RECEIPT_INPUT_INVALID',{
    ...sample,versionId:'null'
  });
});
