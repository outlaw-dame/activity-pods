import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {createPortableS3ReceiptWriter} from
 '../candidates/oauth-portable-s3-receipt-writer.mjs';

if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_PORTABLE_WORM_DISPOSABLE!=='confirmed')
  throw Error('Portable S3 writer proof is not released');

const now=Date.UTC(2026,10,23), DAY=86400000;
const subject='a'.repeat(64);
const key='paper/oauth-witness/epochs/v1/'+subject+'/0000000000000000001';
const data=(hash)=>Buffer.from(JSON.stringify({
  kind:'paper.witness.epoch.v1',subject,revision:'1',
  operationId:'a7d75d7d-403a-4940-8e42-f5c352eef572',
  eventSha256:hash.repeat(64)
}));
const bytes=data('b');
const commands=Object.fromEntries([
 'PutObjectCommand','ListObjectVersionsCommand',
 'GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
 'HeadObjectCommand','GetObjectRetentionCommand','GetObjectCommand'
].map(name=>[name,class{
  constructor(input){this.kind=name;this.input=input;}
}]));
const denied=(fn,code)=>assert.rejects(fn,e=>e?.code===code);
function setup(options={}){
  const versions=[],calls=[];
  const controls={...options,putCount:0};
  let active=null;
  const lookup=(version)=>versions.find(x=>x.VersionId===version);
  const reply=(cmd)=>{
    const name=cmd.kind,params=cmd.input;
    calls.push({role:'reader',name,params});
    if(params.Bucket!=='immutable-custody-fixture')throw Error('Unexpected bucket');
    if(name==='GetBucketVersioningCommand')
      return {Status:controls.suspended?'Suspended':'Enabled'};
    if(name==='GetObjectLockConfigurationCommand')
      return {ObjectLockConfiguration:{ObjectLockEnabled:'Enabled',
        Rule:{DefaultRetention:{Mode:controls.governance?'GOVERNANCE':'COMPLIANCE',
          Days:430}}}};
    if(name==='ListObjectVersionsCommand'){
      return {IsTruncated:controls.truncated===true,
        Versions:versions.map(x=>({...x})),
        DeleteMarkers:controls.marker?[{Key:key,VersionId:'marker'}]:[]};
    }
    if(name==='HeadObjectCommand'){
      if(!active)throw Error('Missing object');
      return {VersionId:active.VersionId,
        ContentLength:active.Size,DeleteMarker:false};
    }
    if(name==='GetObjectRetentionCommand'){
      if(!lookup(params.VersionId))throw Error('Missing version');
      return {Retention:{Mode:controls.governance?'GOVERNANCE':'COMPLIANCE',
        RetainUntilDate:new Date(now+480*DAY)}};
    }
    if(name==='GetObjectCommand'){
      const found=lookup(params.VersionId);
      if(!found)throw Error('Missing version');
      return {VersionId:found.VersionId,Body:controls.corrupt?
        data('c'):Buffer.from(found.payload)};
    }
    throw Error('Unexpected reader operation');
  };
  const reader={
    config:{maxAttempts:async()=>controls.readerRetries??1},
    send:async cmd=>reply(cmd)
  };
  const writer={
    config:{maxAttempts:async()=>controls.writerRetries??1},
    send:async cmd=>{
      calls.push({role:'writer',name:cmd.kind,params:cmd.input});
      assert.equal(cmd.kind,'PutObjectCommand');
      assert.equal(cmd.input.Bucket,'immutable-custody-fixture');
      assert.equal(cmd.input.Key,key);
      assert.equal(cmd.input.IfNoneMatch,'*');
      assert.equal(cmd.input.ContentType,'application/octet-stream');
      assert.ok(Buffer.isBuffer(cmd.input.Body));
      controls.putCount++;
      if(controls.lostBefore)throw Error('No ACK before durable store');
      if(active&&!controls.ignoreCondition)throw Error('412 Precondition Failed');
      if(active)active.IsLatest=false;
      const next={Key:key,VersionId:'version-'+controls.putCount,
        IsLatest:true,Size:cmd.input.Body.length,
        payload:Buffer.from(cmd.input.Body)};
      active=next;versions.push(next);
      if(controls.lostAfter)throw Error('Network ACK lost');
      return {VersionId:controls.wrongAck?'wrong-version':next.VersionId};
    }
  };
  const args={provider:options.provider||'custom-s3',
    endpoint:'https://objects.vendor-domain.com/',
    approvedEndpoint:'https://objects.vendor-domain.com/',
    bucket:'immutable-custody-fixture',writer,reader,commands,
    clock:()=>now,fixtureOnly:true};
  const create=()=>createPortableS3ReceiptWriter(args);
  return {create,reader,writer,versions,calls,controls,args};
}

test('write-once receipt is independently verified without AWS bucket-owner ID',async()=>{
  const h=setup();
  const transport=h.create();
  const result=await transport.putAndVerify({key,bytes});
  assert.equal(result.key,key);
  assert.equal(result.versionId,'version-1');
  assert.equal(result.sha256,crypto.createHash('sha256').update(bytes).digest('hex'));
  assert.equal(result.retentionObserved,true);
  assert.equal(result.contentVersionObserved,true);
  assert.equal(result.conditionalCreateOnlyVerified,false);
  assert.equal(result.operatorIndependenceVerified,false);
  assert.equal(result.latestHeadVerified,false);
  assert.equal(result.releaseAccepted,false);
  assert.equal(transport.releaseAccepted,false);
  assert.equal(h.controls.putCount,1);
  assert.equal(h.calls.filter(x=>x.role==='writer').length,1);
  const again=await transport.putAndVerify({key,bytes});
  assert.equal(again.versionId,'version-1',
    'Already committed exact receipt can be reconciled without another version');
  assert.equal(h.versions.length,1);
  await denied(()=>transport.putAndVerify({key,bytes:data('c')}),
    'PORTABLE_WORM_DIGEST_MISMATCH');
  assert.equal(h.versions.length,1);
});

test('lost ACK is reconciled exactly once without unbounded or implicit retry',async()=>{
  const lost=setup({lostAfter:true});
  const result=await lost.create().putAndVerify({key,bytes});
  assert.equal(result.versionId,'version-1');
  assert.equal(lost.controls.putCount,1);
  assert.equal(lost.versions.length,1);
  const absent=setup({lostBefore:true});
  await denied(()=>absent.create().putAndVerify({key,bytes}),
    'PORTABLE_RECEIPT_HISTORY_UNSAFE');
  assert.equal(absent.controls.putCount,1);
  assert.equal(absent.versions.length,0);
});

test('S3 gateways ignoring If-None-Match are detected by immutable version history',async()=>{
  const h=setup({ignoreCondition:true});
  await h.create().putAndVerify({key,bytes});
  await denied(()=>h.create().putAndVerify({key,bytes}),
    'PORTABLE_RECEIPT_HISTORY_UNSAFE');
  assert.equal(h.versions.length,2,'unsafe overwrite must NOT be mistaken for WORM');
});

test('bad ACK, missing lock, stale version or delete markers never authorize',async()=>{
  const wrong=setup({wrongAck:true});
  await denied(()=>wrong.create().putAndVerify({key,bytes}),
    'PORTABLE_RECEIPT_ACK_VERSION_CONFLICT');
  const policy=setup({governance:true});
  await denied(()=>policy.create().putAndVerify({key,bytes}),
    'PORTABLE_WORM_BUCKET_NOT_COMPLIANT');
  assert.equal(policy.controls.putCount,0);
  const suspended=setup({suspended:true});
  await denied(()=>suspended.create().putAndVerify({key,bytes}),
    'PORTABLE_WORM_BUCKET_NOT_COMPLIANT');
  assert.equal(suspended.controls.putCount,0);
  const corrupt=setup({corrupt:true});
  await denied(()=>corrupt.create().putAndVerify({key,bytes}),
    'PORTABLE_WORM_DIGEST_MISMATCH');
  const deleted=setup({marker:true});
  await denied(()=>deleted.create().putAndVerify({key,bytes}),
    'PORTABLE_RECEIPT_HISTORY_UNSAFE');
  const truncated=setup({truncated:true});
  await denied(()=>truncated.create().putAndVerify({key,bytes}),
    'PORTABLE_RECEIPT_HISTORY_UNSAFE');
});

test('unsafe SDK retries and unapproved endpoints are rejected without a PUT',async()=>{
  for(const options of [{writerRetries:3},{readerRetries:3}]){
    const h=setup(options);
    await denied(()=>h.create().putAndVerify({key,bytes}),
      'PORTABLE_RECEIPT_RETRY_UNSAFE');
    assert.equal(h.controls.putCount,0);
  }
  const h=setup();
  const bad=createPortableS3ReceiptWriter({...h.args,approvedEndpoint:null});
  await denied(()=>bad.putAndVerify({key,bytes}),
    'PORTABLE_WORM_ENDPOINT_NOT_PINNED');
  assert.equal(h.controls.putCount,0);
  await denied(()=>h.create().putAndVerify({key,bytes:Buffer.from('untrusted')}),
    'PORTABLE_RECEIPT_FORMAT_INVALID');
  const prev=process.env.NODE_ENV;
  process.env.NODE_ENV='production';
  try{
    await denied(()=>h.create().putAndVerify({key,bytes}),
      'PORTABLE_RECEIPT_NOT_RELEASED');
  }finally{process.env.NODE_ENV=prev;}
  assert.equal(h.controls.putCount,0);
});

test('reject shared writer/reader roles and missing required SDK commands',()=>{
  const h=setup();
  assert.throws(()=>createPortableS3ReceiptWriter({
    ...h.args,reader:h.writer
  }),e=>e?.code==='PORTABLE_RECEIPT_CONFIGURATION_UNSAFE');
  assert.throws(()=>createPortableS3ReceiptWriter({
    ...h.args,commands:{}
  }),e=>e?.code==='PORTABLE_RECEIPT_CONFIGURATION_UNSAFE');
});
