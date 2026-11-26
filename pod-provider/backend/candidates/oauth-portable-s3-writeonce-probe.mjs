/**
 * NONACTIVATED external S3-compatible conditional-create acceptance probe.
 * Creates TWO competing attempts at ONE random synthetic receipt key.
 *
 * Irreversible retention: the winning version is expected to remain locked
 * for >=400 days. Use only an empty, deliberately disposable bucket, under
 * a separately approved operator profile; this is NEVER an auth service.
 *
 * This tests conditional creation, not external signer independence,
 * comprehensive WORM deletion enforcement, or fresh monotonic authority.
 */
import crypto from 'node:crypto';
import {inspectPortableS3ObjectLock,validatePortableS3Endpoint} from
 './oauth-portable-s3-custody-readonly.mjs';
import {assertReceipt} from './oauth-s3-compliance-archive.mjs';

// Explicitly allow the operator's existing bare Storj bucket name, or the
// previously supported random-suffix disposable names. No generic buckets.
const BUCKET=/^paper-worm-disposable(?:-[a-z0-9](?:[a-z0-9-]{3,33}[a-z0-9]))?$/u;
const HEX=/^[a-f0-9]{64}$/u;
const VERSION=/^\S{1,512}$/u;
const REQUIRED=['PutObjectCommand','GetBucketVersioningCommand',
 'GetObjectLockConfigurationCommand','ListObjectVersionsCommand',
 'HeadObjectCommand','GetObjectRetentionCommand','GetObjectCommand'];
const BASE='paper/oauth-witness/epochs/v1/';
const REVISION='0000000000000000001';

function deny(code){
  const error=new Error('Disposable S3 write-once acceptance refused');
  error.code=code;
  throw error;
}
function denyResponse(e){
  return (e?.name==='PreconditionFailed'&&e?.$metadata?.httpStatusCode===412)||
    (e?.name==='ConditionalRequestConflict'&&e?.$metadata?.httpStatusCode===409);
}
function syntheticReceipt(subject,hash){
  return Buffer.from(JSON.stringify({
    kind:'paper.witness.epoch.v1',subject,revision:'1',
    operationId:crypto.randomUUID(),eventSha256:hash
  }));
}
function validVersion(version){
  return typeof version==='string'&&VERSION.test(version)&&
    version!=='null'&&[...version].every(ch=>{
      const n=ch.codePointAt(0);
      return n>32&&n!==127;
    });
}
/**
 * Both PutObject calls are attempted exactly once, concurrently. There is
 * NO retry on lost acknowledgment. If either outcome is ambiguous, refuse,
 * even if an eventual read could identify one object version.
 *
 * We do not attempt DELETE or PUT ObjectRetention from this tool: the
 * separately administered security operator must run that adversarial
 * compliance procedure with a different principal and a sacrificial bucket.
 */
export async function probeDisposableS3ConditionalCreate({
  provider,endpoint,approvedEndpoint=null,bucket,writer,reader,commands,
  explicitBucketApproval,clock=()=>Date.now()
}={}){
  if(process.env.PAPER_PORTABLE_WORM_WRITE_DISPOSABLE!=='confirmed'||
     !BUCKET.test(bucket||'')||
     explicitBucketApproval!=='permanently-retain:'+bucket||
     !writer||!reader||writer===reader||
     typeof writer.send!=='function'||typeof reader.send!=='function'||
     !commands||REQUIRED.some(n=>typeof commands[n]!=='function')||
     typeof clock!=='function')
    deny('PORTABLE_WORM_WRITE_CONFIGURATION_UNSAFE');
  validatePortableS3Endpoint(provider,endpoint,approvedEndpoint);
  // No mutating commands are issued before independent restricted reader
  // positively verifies bucket versioning, COMPLIANCE and required duration.
  const config={
    provider,endpoint,approvedEndpoint,bucket,reader,commands,
    clock,minRetentionDays:400,minRemainingDays:30
  };
  const before=await inspectPortableS3ObjectLock(config);
  if(before.configurationObserved!==true||before.releaseAccepted!==false)
    deny('PORTABLE_WORM_WRITE_POLICY_UNVERIFIED');

  const subject=crypto.randomBytes(32).toString('hex');
  const key=BASE+subject+'/'+REVISION;
  const first=syntheticReceipt(subject,crypto.randomBytes(32).toString('hex'));
  const second=syntheticReceipt(subject,crypto.randomBytes(32).toString('hex'));
  if(first.equals(second))deny('PORTABLE_WORM_WRITE_CONFIGURATION_UNSAFE');
  assertReceipt(key,first);
  assertReceipt(key,second);
  async function attempt(bytes){
    try{
      const result=await writer.send(new commands.PutObjectCommand({
        Bucket:bucket,Key:key,Body:bytes,IfNoneMatch:'*',
        ContentType:'application/octet-stream',
        ContentMD5:crypto.createHash('md5').update(bytes).digest('base64'),
        ChecksumSHA256:crypto.createHash('sha256').update(bytes).digest('base64')
      }),{abortSignal:AbortSignal.timeout(7000)});
      if(![200,201].includes(result?.$metadata?.httpStatusCode)||
         !validVersion(result?.VersionId))
        deny('PORTABLE_WORM_WRITE_ACK_UNVERIFIED');
      return {type:'accepted',version:result.VersionId};
    }catch(error){
      if(error?.code?.startsWith('PORTABLE_WORM_WRITE_'))throw error;
      if(denyResponse(error))return {type:'conflict'};
      deny('PORTABLE_WORM_WRITE_AMBIGUOUS');
    }
  }
  // One random key and at most TWO PutObject invocations, no retries.
  // Promise.allSettled waits for both requests, even if one is ambiguous.
  const results=await Promise.allSettled([attempt(first),attempt(second)]);
  if(results.some(x=>x.status!=='fulfilled'))
    deny('PORTABLE_WORM_WRITE_AMBIGUOUS');
  const firstResult=results[0].value,secondResult=results[1].value;
  const approved=firstResult.type==='accepted'&&secondResult.type==='conflict'?
    {bytes:first,version:firstResult.version}:
    secondResult.type==='accepted'&&firstResult.type==='conflict'?
      {bytes:second,version:secondResult.version}:null;
  if(!approved)deny('PORTABLE_WORM_WRITE_CONDITIONAL_NOT_PROVEN');
  const sha256=crypto.createHash('sha256').update(approved.bytes).digest('hex');
  if(!HEX.test(sha256))deny('PORTABLE_WORM_WRITE_BODY_UNVERIFIED');
  const certified=await inspectPortableS3ObjectLock({
    ...config,sample:{key,versionId:approved.version,sha256}
  });
  if(certified.receiptVerified!==true||certified.versionId!==approved.version||
     certified.payloadSha256!==sha256||certified.retentionDays<400||
     certified.releaseAccepted!==false)
    deny('PORTABLE_WORM_WRITE_READBACK_UNVERIFIED');

  return Object.freeze({
    schema:'paper.portable-s3.conditional-create-observation.v1',
    provider,bucket,key,versionId:approved.version,payloadSha256:sha256,
    observedConditionalConflict:true,
    observedOneVersionReadback:true,
    confirmedObjectRetention:true,
    independentlyAdministered:false,
    hostileDeleteRetentionVerified:false,
    monotonicLatestHeadVerified:false,
    releaseAccepted:false
  });
}
