import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
 inspectPortableS3ObjectLock,
 validatePortableS3Endpoint
} from '../candidates/oauth-portable-s3-custody-readonly.mjs';

const day=86400000;
const now=Date.UTC(2026,10,23);
const subject='a'.repeat(64);
const key='paper/oauth-witness/epochs/v1/'+subject+'/0000000000000000001';
const bytes=Buffer.from(JSON.stringify({
  kind:'paper.witness.epoch.v1',subject,revision:'1',
  operationId:'a7d75d7d-403a-4940-8e42-f5c352eef572',
  eventSha256:'b'.repeat(64)
}));
const sample={key,versionId:'revision-v1',
  sha256:crypto.createHash('sha256').update(bytes).digest('hex')};
const types=[
 'GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
 'ListObjectVersionsCommand','HeadObjectCommand',
 'GetObjectRetentionCommand','GetObjectCommand'
];
const commands=Object.fromEntries(types.map(n=>[n,class {
  constructor(input){this.kind=n;this.input=input;}
}]));
const endpointFor={
 'backblaze-b2':'https://s3.us-west-004.backblazeb2.com/',
 'storj':'https://gateway.storjshare.io/'
};
const base=()=>({
  version:{Status:'Enabled'},
  config:{ObjectLockConfiguration:{ObjectLockEnabled:'Enabled',
    Rule:{DefaultRetention:{Mode:'COMPLIANCE',Days:430}}}},
  history:{IsTruncated:false,
    Versions:[{Key:key,VersionId:sample.versionId,IsLatest:true,Size:bytes.length}],
    DeleteMarkers:[]},
  head:{VersionId:sample.versionId,ContentLength:bytes.length,DeleteMarker:false},
  retain:{Retention:{Mode:'COMPLIANCE',
    RetainUntilDate:new Date(now+500*day)}},
  content:{VersionId:sample.versionId,Body:bytes}
});
function createMock(provider,mutate=()=>{}){
  const values=base();mutate(values);
  const calls=[];
  const reader={send:async cmd=>{
    calls.push({kind:cmd.kind,args:cmd.input});
    const dict={
      GetBucketVersioningCommand:values.version,
      GetObjectLockConfigurationCommand:values.config,
      ListObjectVersionsCommand:values.history,
      HeadObjectCommand:values.head,
      GetObjectRetentionCommand:values.retain,
      GetObjectCommand:values.content
    };
    if(!Object.hasOwn(dict,cmd.kind))throw Error('Unexpected SDK action');
    return dict[cmd.kind];
  }};
  return {
    opts:{provider,endpoint:endpointFor[provider],reader,commands,
      bucket:'custody-proof-bucket',sample,clock:()=>now},
    calls
  };
}
const refuses=async (fn,code)=>assert.rejects(fn,e=>e?.code===code);
test('B2 and Storj demand explicit versioned COMPLIANCE proof and never authorize',async()=>{
  for(const provider of ['backblaze-b2','storj']){
    const {opts,calls}=createMock(provider);
    const inspected=await inspectPortableS3ObjectLock(opts);
    assert.equal(inspected.provider,provider);
    assert.equal(inspected.configurationObserved,true);
    assert.equal(inspected.receiptVerified,true);
    assert.equal(inspected.operatorIndependenceVerified,false);
    assert.equal(inspected.conditionalCreateOnlyVerified,false);
    assert.equal(inspected.latestHeadVerified,false);
    assert.equal(inspected.releaseAccepted,false);
    assert.equal(inspected.versionId,sample.versionId);
    assert.deepEqual(calls.map(x=>x.kind),[
      'GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
      'ListObjectVersionsCommand','HeadObjectCommand',
      'GetObjectRetentionCommand','GetObjectCommand',
      'HeadObjectCommand',
      'GetBucketVersioningCommand','GetObjectLockConfigurationCommand'
    ]);
    assert.ok(calls.every(x=>x.args.Bucket==='custody-proof-bucket'));
    assert.equal(calls[5].args.VersionId,sample.versionId);
    const cfg=await inspectPortableS3ObjectLock({...opts,sample:null});
    assert.equal(cfg.receiptVerified,false);
    assert.equal(cfg.releaseAccepted,false);
  }
});
test('Filebase and arbitrary endpoints are NEVER accepted for WORM',async()=>{
  const {opts}=createMock('storj');
  for(const provider of ['filebase','cloudflare-r2','aws','minio',null]){
    await refuses(()=>inspectPortableS3ObjectLock({...opts,provider}),
      'PORTABLE_WORM_PROVIDER_UNSUPPORTED');
  }
  const bad=[
    'http://gateway.storjshare.io/',
    'https://gateway.storjshare.io.evil.test/',
    'https://username:secret@gateway.storjshare.io/',
    'https://gateway.storjshare.io:443/',
    'https://gateway.storjshare.io/test',
    'https://gateway.storjshare.io/?credential=secret',
    'https://127.0.0.1/',
    'https://s3.us-west-004.backblazeb2.com/',
    'https://s3.us-west-004.backblazeb2.com.evil.test/'
  ];
  for(const endpoint of bad)
    await refuses(()=>inspectPortableS3ObjectLock({...opts,endpoint}),
      'PORTABLE_WORM_ENDPOINT_UNSAFE');
  assert.equal(validatePortableS3Endpoint('storj',endpointFor.storj).provider,'storj');
  assert.equal(validatePortableS3Endpoint('backblaze-b2',
    endpointFor['backblaze-b2']).provider,'backblaze-b2');
  await refuses(()=>inspectPortableS3ObjectLock({...opts,provider:'backblaze-b2'}),
    'PORTABLE_WORM_ENDPOINT_UNSAFE');
});
test('unsafe or unverifiable bucket lock state is never called compliant',async()=>{
  const mutations=[
    v=>{v.version.Status='Suspended'},
    v=>{v.config.ObjectLockConfiguration.ObjectLockEnabled='Disabled'},
    v=>{v.config.ObjectLockConfiguration.Rule.DefaultRetention.Mode='GOVERNANCE'},
    v=>{v.config.ObjectLockConfiguration.Rule.DefaultRetention.Days=30},
    v=>{delete v.config.ObjectLockConfiguration.Rule},
    v=>{v.config.ObjectLockConfiguration.Rule.DefaultRetention.Days='430'},
  ];
  for(const change of mutations){
    const {opts}=createMock('storj',change);
    await refuses(()=>inspectPortableS3ObjectLock(opts),
      'PORTABLE_WORM_BUCKET_NOT_COMPLIANT');
  }
});
test('hidden, changed or ambiguous version histories never authorize',async()=>{
  const mutations=[
    v=>{v.history.IsTruncated=true},
    v=>{v.history.DeleteMarkers=[{Key:key,VersionId:'hide'}]},
    v=>{v.history.Versions[0].IsLatest=false},
    v=>{v.history.Versions[0].Key=key+'-shadow'},
    v=>{v.history.Versions[0].VersionId='wrong'},
    v=>{v.history.Versions.push({...v.history.Versions[0]})}
  ];
  for(const change of mutations)
    await refuses(()=>inspectPortableS3ObjectLock(createMock('storj',change).opts),
      'PORTABLE_WORM_VERSION_HISTORY_UNSAFE');
  await refuses(()=>inspectPortableS3ObjectLock(createMock('storj',
    v=>{v.head.VersionId='stale'}).opts),'PORTABLE_WORM_CURRENT_VERSION_UNSAFE');
  await refuses(()=>inspectPortableS3ObjectLock(createMock('storj',
    v=>{v.retain.Retention.Mode='GOVERNANCE'}).opts),'PORTABLE_WORM_RETENTION_UNSAFE');
  await refuses(()=>inspectPortableS3ObjectLock(createMock('storj',
    v=>{v.retain.Retention.RetainUntilDate=new Date(now+day)}).opts),
    'PORTABLE_WORM_RETENTION_UNSAFE');
});
test('exact-version bytes, canonical receipt and operator pin must match',async()=>{
  const {opts}=createMock('backblaze-b2');
  await refuses(()=>inspectPortableS3ObjectLock({...opts,sample:{
    ...sample,sha256:'c'.repeat(64)}}),'PORTABLE_WORM_DIGEST_MISMATCH');
  await refuses(()=>inspectPortableS3ObjectLock({...opts,sample:{
    ...sample,key:'other/prefix/v1'}}),'PORTABLE_WORM_SAMPLE_INVALID');
  await refuses(()=>inspectPortableS3ObjectLock(createMock('storj',
    v=>{v.content.VersionId='different'}).opts),'PORTABLE_WORM_VERSION_CHANGED');
  await refuses(()=>inspectPortableS3ObjectLock(createMock('storj',
    v=>{v.content.Body=Buffer.from('forged')} ).opts),'PORTABLE_WORM_BODY_UNSAFE');
});
test('TLS verification bypass or environment endpoint override denies',async()=>{
  const {opts}=createMock('storj');
  for(const name of ['NODE_TLS_REJECT_UNAUTHORIZED','AWS_ENDPOINT_URL_S3',
      'AWS_ENDPOINT_URL','AWS_CA_BUNDLE','NODE_EXTRA_CA_CERTS']){
    const saved=process.env[name];
    process.env[name]=name==='NODE_TLS_REJECT_UNAUTHORIZED'?'0':'https://fake.example';
    try{await refuses(()=>inspectPortableS3ObjectLock(opts),
      'PORTABLE_WORM_TRANSPORT_UNSAFE');}
    finally{
      if(saved===undefined)delete process.env[name];
      else process.env[name]=saved;
    }
  }
});
