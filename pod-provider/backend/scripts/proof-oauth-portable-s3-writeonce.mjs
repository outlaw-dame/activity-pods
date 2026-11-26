import test from 'node:test';
import assert from 'node:assert/strict';
import {probeDisposableS3ConditionalCreate} from
 '../candidates/oauth-portable-s3-writeonce-probe.mjs';

const NOW=Date.UTC(2026,10,23), DAY=86400000;
const BUCKET='paper-worm-disposable-qafixture';
const endpoint='https://gateway.storjshare.io/';
const names=['PutObjectCommand','GetBucketVersioningCommand',
  'GetObjectLockConfigurationCommand','ListObjectVersionsCommand',
  'HeadObjectCommand','GetObjectRetentionCommand','GetObjectCommand'];
const commands=Object.fromEntries(names.map(name=>[name,class {
  constructor(input){this.name=name;this.input=input;}
}]));
const conflict=()=>Object.assign(new Error('already exists'),{
  name:'PreconditionFailed',$metadata:{httpStatusCode:412}
});
function mock({behavior='one',delMarker=false,wrongRetain=false,
  versioning=true,bucket=BUCKET}={}){
  const writes=[],reads=[];let stored=null;
  const writer={send:async command=>{
    assert.equal(command.name,'PutObjectCommand');
    const a=command.input;
    writes.push(a);
    assert.equal(a.Bucket,bucket);
    assert.equal(a.IfNoneMatch,'*');
    assert.equal(a.ContentType,'application/octet-stream');
    assert.ok(a.Body instanceof Uint8Array);
    assert.equal(typeof a.ContentMD5,'string');
    assert.equal(typeof a.ChecksumSHA256,'string');
    if(behavior==='ambiguous'&&writes.length===2)
      throw Error('Lost ACK; outcome unknown');
    if(behavior==='both-refuse')throw conflict();
    if(behavior==='both-accept'){
      stored={key:a.Key,bytes:Buffer.from(a.Body),version:'v'+writes.length};
      return {VersionId:stored.version,$metadata:{httpStatusCode:200}};
    }
    if(stored)throw conflict();
    stored={key:a.Key,bytes:Buffer.from(a.Body),version:'immutable-version-1'};
    return {VersionId:stored.version,$metadata:{httpStatusCode:200}};
  }};
  const reader={send:async command=>{
    reads.push(command.name);
    const args=command.input;
    assert.equal(args.Bucket,bucket);
    switch(command.name){
      case 'GetBucketVersioningCommand':
        return {Status:versioning?'Enabled':'Suspended'};
      case 'GetObjectLockConfigurationCommand':
        return {ObjectLockConfiguration:{ObjectLockEnabled:'Enabled',
          Rule:{DefaultRetention:{Mode:'COMPLIANCE',Days:440}}}};
      case 'ListObjectVersionsCommand':
        return {IsTruncated:false,Versions:stored?[{
          Key:stored.key,VersionId:stored.version,IsLatest:true,
          Size:stored.bytes.length}]:[],DeleteMarkers:delMarker?[{
          Key:stored.key,VersionId:'hidden'}]:[]};
      case 'HeadObjectCommand':
        return {VersionId:stored?.version,
          ContentLength:stored?.bytes?.length,DeleteMarker:false};
      case 'GetObjectRetentionCommand':
        return {Retention:{Mode:wrongRetain?'GOVERNANCE':'COMPLIANCE',
          RetainUntilDate:new Date(NOW+500*DAY)}};
      case 'GetObjectCommand':
        return {VersionId:stored?.version,Body:stored?.bytes};
      default:throw Error('Unexpected read operation');
    }
  }};
  const options={provider:'storj',endpoint,bucket,reader,writer,
    commands,clock:()=>NOW,explicitBucketApproval:'permanently-retain:'+bucket};
  return {options,writes,reads};
}
async function refused(call,code){
  await assert.rejects(call,e=>e?.code===code);
}
function withGate(ready){
  const old=process.env.PAPER_PORTABLE_WORM_WRITE_DISPOSABLE;
  if(ready)process.env.PAPER_PORTABLE_WORM_WRITE_DISPOSABLE='confirmed';
  else delete process.env.PAPER_PORTABLE_WORM_WRITE_DISPOSABLE;
  return ()=>old===undefined?
    delete process.env.PAPER_PORTABLE_WORM_WRITE_DISPOSABLE:
    (process.env.PAPER_PORTABLE_WORM_WRITE_DISPOSABLE=old);
}
test('genuine single-winner conditional race and exact COMPLIANCE readback',async()=>{
  const restore=withGate(true);
  try{
    const {options,writes,reads}=mock();
    const result=await probeDisposableS3ConditionalCreate(options);
    assert.equal(writes.length,2);
    assert.equal(writes[0].Key,writes[1].Key);
    assert.notDeepEqual(writes[0].Body,writes[1].Body);
    assert.equal(result.schema,'paper.portable-s3.conditional-create-observation.v1');
    assert.equal(result.observedConditionalConflict,true);
    assert.equal(result.observedOneVersionReadback,true);
    assert.equal(result.confirmedObjectRetention,true);
    assert.equal(result.independentlyAdministered,false);
    assert.equal(result.hostileDeleteRetentionVerified,false);
    assert.equal(result.monotonicLatestHeadVerified,false);
    assert.equal(result.releaseAccepted,false);
    assert.equal(result.bucket,BUCKET);
    assert.ok(result.key.startsWith('paper/oauth-witness/epochs/v1/'));
    assert.equal(result.versionId,'immutable-version-1');
    assert.ok(reads.includes('GetObjectRetentionCommand'));
    assert.ok(reads.filter(x=>x==='GetBucketVersioningCommand').length>=3);
  }finally{restore()}
});
test('operator existing bare Storj disposable bucket is accepted without loosening approval',async()=>{
  const restore=withGate(true);
  try{
    const exact='paper-worm-disposable';
    const {options,writes}=mock({bucket:exact});
    const result=await probeDisposableS3ConditionalCreate(options);
    assert.equal(result.bucket,exact);
    assert.equal(result.releaseAccepted,false);
    assert.equal(writes.length,2);
    const wrong=mock({bucket:exact});
    await refused(()=>probeDisposableS3ConditionalCreate({
      ...wrong.options,explicitBucketApproval:
        'permanently-retain:paper-worm-disposable-qafixture'
    }), 'PORTABLE_WORM_WRITE_CONFIGURATION_UNSAFE');
    assert.equal(wrong.writes.length,0);
  }finally{restore()}
});
test('the unsuffixed bucket name is scoped to Storj, not arbitrary S3',async()=>{
  const restore=withGate(true);
  try{
    const {options,writes}=mock({bucket:'paper-worm-disposable'});
    await refused(()=>probeDisposableS3ConditionalCreate({
      ...options,provider:'custom-s3'
    }), 'PORTABLE_WORM_WRITE_CONFIGURATION_UNSAFE');
    await refused(()=>probeDisposableS3ConditionalCreate({
      ...options,provider:'backblaze-b2'
    }), 'PORTABLE_WORM_WRITE_CONFIGURATION_UNSAFE');
    assert.equal(writes.length,0);
  }finally{restore()}
});
test('similar non-disposable bucket spellings fail even with matching approvals',async()=>{
  const restore=withGate(true);
  try{
    for(const bucket of [
      'paper-worm-disposable-',
      'paper-worm-disposablex',
      'paper-worm-disposable.test',
      'paper-worm-disposable-foo',
      'paper-worm-disposable--evil',
      'production-oauth-archive'
    ]){
      const {options,writes}=mock({bucket});
      await refused(()=>probeDisposableS3ConditionalCreate(options),
        'PORTABLE_WORM_WRITE_CONFIGURATION_UNSAFE');
      assert.equal(writes.length,0);
    }
  }finally{restore()}
});
test('safety gates refuse prod-looking buckets and any absent human acknowledgement',async()=>{
  const {options,writes}=mock();
  await refused(()=>probeDisposableS3ConditionalCreate(options),
    'PORTABLE_WORM_WRITE_CONFIGURATION_UNSAFE');
  const restore=withGate(true);
  try{
    for(const overrides of [
      {bucket:'paper-auth-production'},
      {bucket:'paper-worm-disposable-prod'},
      {explicitBucketApproval:'yes'},
      {writer:options.reader},
      {reader:options.writer}
    ]){
      await refused(()=>probeDisposableS3ConditionalCreate({...options,...overrides}),
        'PORTABLE_WORM_WRITE_CONFIGURATION_UNSAFE');
    }
    assert.equal(writes.length,0);
  }finally{restore()}
});
test('versioning and COMPLIANCE preflight reject BEFORE any PUT',async()=>{
  const restore=withGate(true);
  try{
    const {options,writes}=mock({versioning:false});
    await refused(()=>probeDisposableS3ConditionalCreate(options),
      'PORTABLE_WORM_BUCKET_NOT_COMPLIANT');
    assert.equal(writes.length,0);
  }finally{restore()}
});
test('never retry ambiguous PutObject ACK, even if one write succeeded',async()=>{
  const restore=withGate(true);
  try{
    const {options,writes}=mock({behavior:'ambiguous'});
    await refused(()=>probeDisposableS3ConditionalCreate(options),
      'PORTABLE_WORM_WRITE_AMBIGUOUS');
    assert.equal(writes.length,2,'there must be no retry or third write');
  }finally{restore()}
});
test('two successful PUTs prove broken conditional semantics and fail',async()=>{
  const restore=withGate(true);
  try{
    const {options,writes}=mock({behavior:'both-accept'});
    await refused(()=>probeDisposableS3ConditionalCreate(options),
      'PORTABLE_WORM_WRITE_CONDITIONAL_NOT_PROVEN');
    assert.equal(writes.length,2);
  }finally{restore()}
});
test('both conflicting PUTs do not imply success or a safe current head',async()=>{
  const restore=withGate(true);
  try{
    const {options,writes}=mock({behavior:'both-refuse'});
    await refused(()=>probeDisposableS3ConditionalCreate(options),
      'PORTABLE_WORM_WRITE_CONDITIONAL_NOT_PROVEN');
    assert.equal(writes.length,2);
  }finally{restore()}
});
test('a delete marker or non-COMPLIANCE exact version refuses acceptance',async()=>{
  const restore=withGate(true);
  try{
    for(const [variant,code] of [
      [{delMarker:true},'PORTABLE_WORM_VERSION_HISTORY_UNSAFE'],
      [{wrongRetain:true},'PORTABLE_WORM_RETENTION_UNSAFE']
    ]){
      const {options,writes}=mock(variant);
      await refused(()=>probeDisposableS3ConditionalCreate(options),code);
      assert.equal(writes.length,2);
    }
  }finally{restore()}
});
