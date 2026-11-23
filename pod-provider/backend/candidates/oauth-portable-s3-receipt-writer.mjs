/**
 * NONACTIVATED provider-neutral S3 COMPLIANCE receipt writer.
 *
 * This transport is designed to run with independently governed archive
 * credentials, NOT Paper/Memory application credentials. Its S3 data plane
 * does NOT require AWS STS, AWS numeric account IDs or AWS-only endpoints.
 * The independent signer, S3 principal custody, permanent latest-head
 * storage and real conditional-PUT enforcement are separate release gates.
 *
 * No application tokens or permission grants may depend on this output.
 */
import {createHash} from 'node:crypto';
import {Buffer} from 'node:buffer';
import {assertReceipt} from './oauth-s3-compliance-archive.mjs';
import {inspectPortableS3ObjectLock} from './oauth-portable-s3-custody-readonly.mjs';

const MAX_READ=1024;
const HEX=/^[0-9a-f]{64}$/u;
const VERSION=/^[^\s]{1,512}$/u;
const ALL=[
  'PutObjectCommand','ListObjectVersionsCommand',
  'GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
  'HeadObjectCommand','GetObjectRetentionCommand','GetObjectCommand'
];
function fail(code){
  const err=new Error('S3 receipt persistence cannot authorize production');
  err.code=code;
  throw err;
}
function gated(fixtureOnly){
  return fixtureOnly===true&&process.env.NODE_ENV==='test'&&
    process.env.PAPER_OAUTH_PORTABLE_WORM_DISPOSABLE==='confirmed';
}
async function oneAttempt(client){
  // AWS SDK internally retries network failures unless explicitly
  // configured with maxAttempts=1. Retrying a lost ACK is forbidden for
  // write-once key admission, even when the S3 gateway is "compatible".
  try{
    const fn=client?.config?.maxAttempts;
    return typeof fn==='function'&&(await fn())===1;
  }catch{return false}
}
export function createPortableS3ReceiptWriter({
  provider,endpoint,approvedEndpoint=null,bucket,
  writer,reader,commands,minRetentionDays=400,minRemainingDays=30,
  clock=()=>Date.now(),fixtureOnly=false
}={}){
  if(!gated(fixtureOnly))fail('PORTABLE_RECEIPT_NOT_RELEASED');
  if(!writer||!reader||writer===reader||
     typeof writer.send!=='function'||typeof reader.send!=='function'||
     !commands||ALL.some(n=>typeof commands[n]!=='function')||
     typeof bucket!=='string'||typeof clock!=='function'||
     !Number.isSafeInteger(minRetentionDays)||minRetentionDays<365||
     minRetentionDays>3000||
     !Number.isSafeInteger(minRemainingDays)||minRemainingDays<1||
     minRemainingDays>minRetentionDays)
    fail('PORTABLE_RECEIPT_CONFIGURATION_UNSAFE');

  const base={provider,endpoint,approvedEndpoint,bucket,reader,commands,
    minRetentionDays,minRemainingDays,clock};

  async function inspect(sample){
    // The existing read-only inspector validates official/pinned origin,
    // actual COMPLIANCE rule, bucket versioning, exact retained version,
    // SHA256 payload, retained expiry and absence of DELETE markers.
    return inspectPortableS3ObjectLock({...base,sample});
  }
  async function listOne(key){
    let response;
    try{
      response=await reader.send(
        new commands.ListObjectVersionsCommand({Bucket:bucket,Prefix:key,MaxKeys:10}),
        {abortSignal:AbortSignal.timeout(7000)});
    }catch{fail('PORTABLE_RECEIPT_HISTORY_UNAVAILABLE')}
    if(response?.IsTruncated!==false||
       !Array.isArray(response.Versions)||response.Versions.length!==1||
       !Array.isArray(response.DeleteMarkers??[])||
       (response.DeleteMarkers??[]).length!==0||
       response.Versions[0]?.Key!==key||
       response.Versions[0]?.IsLatest!==true||
       typeof response.Versions[0]?.VersionId!=='string'||
       !VERSION.test(response.Versions[0].VersionId)||
       response.Versions[0].VersionId==='null'||
       !Number.isSafeInteger(response.Versions[0]?.Size)||
       response.Versions[0].Size<32||
       response.Versions[0].Size>MAX_READ)
      fail('PORTABLE_RECEIPT_HISTORY_UNSAFE');
    return response.Versions[0];
  }

  async function putAndVerify({key,bytes}={}){
    if(!gated(fixtureOnly))fail('PORTABLE_RECEIPT_NOT_RELEASED');
    if(!Buffer.isBuffer(bytes)||bytes.length<32||bytes.length>MAX_READ)
      fail('PORTABLE_RECEIPT_FORMAT_INVALID');
    try{assertReceipt(key,bytes)}
    catch{fail('PORTABLE_RECEIPT_FORMAT_INVALID')}
    if(!(await oneAttempt(writer))||!(await oneAttempt(reader)))
      fail('PORTABLE_RECEIPT_RETRY_UNSAFE');
    await inspect(null); // fail before ANY write when policy is unsafe
    const expectedSha=createHash('sha256').update(bytes).digest('hex');
    if(!HEX.test(expectedSha))fail('PORTABLE_RECEIPT_FORMAT_INVALID');
    let ack;
    try{
      ack=await writer.send(new commands.PutObjectCommand({
        Bucket:bucket,Key:key,Body:Buffer.from(bytes),
        IfNoneMatch:'*',ContentType:'application/octet-stream'
      }),{abortSignal:AbortSignal.timeout(7000)});
    }catch{
      // A precondition conflict OR a lost ACK is ambiguous. Never retry.
      // Reconcile independently, including all versions and markers.
    }
    const exactlyOne=await listOne(key);
    if(ack?.VersionId!==undefined && ack.VersionId!==exactlyOne.VersionId)
      fail('PORTABLE_RECEIPT_ACK_VERSION_CONFLICT');
    if(exactlyOne.Size!==bytes.length)
      fail('PORTABLE_RECEIPT_LENGTH_MISMATCH');
    const observed=await inspect({
      key,versionId:exactlyOne.VersionId,sha256:expectedSha
    });
    if(observed.receiptVerified!==true||
       observed.payloadSha256!==expectedSha||
       observed.releaseAccepted!==false)
      fail('PORTABLE_RECEIPT_UNVERIFIED');
    // Critical: one retained copy, even with clean readback, does NOT prove
    // that the storage gateway honored If-None-Match. A separate live
    // conflicting PUT and destructive/retention test must be performed
    // against a disposable object under independent operator supervision.
    return Object.freeze({
      key,versionId:exactlyOne.VersionId,sha256:expectedSha,
      contentVersionObserved:true,retentionObserved:true,
      conditionalCreateOnlyVerified:false,
      operatorIndependenceVerified:false,latestHeadVerified:false,
      releaseAccepted:false
    });
  }
  return Object.freeze({putAndVerify,releaseAccepted:false});
}
