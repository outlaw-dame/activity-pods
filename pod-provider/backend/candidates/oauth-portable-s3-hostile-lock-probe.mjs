/**
 * OPERATOR-ONLY S3 COMPLIANCE hostile-version qualification (NONACTIVATED).
 *
 * Read-only preflight produces an exact-object, retention-bound approval
 * challenge. Only a separate explicit challenge approval on a disposable
 * bucket allows TWO potentially destructive requests: DELETE of the exact
 * retained VersionId and shortening its COMPLIANCE retention by one day.
 *
 * NEVER issue an unversioned DELETE (which can create a delete marker),
 * overwrite the current object, retry a mutation or grant authorization.
 * A 403 may be due to IAM rather than COMPLIANCE: external IAM/operator
 * custody review remains mandatory. No production service may import this.
 */
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';
import {setTimeout as sleep} from 'node:timers/promises';
import {inspectPortableS3ObjectLock,validatePortableS3Endpoint} from
 './oauth-portable-s3-custody-readonly.mjs';

// Only Storj's exact existing test bucket may omit the random suffix.
// Other providers keep the prior strict disposable-bucket pattern.
const BUCKET=/^paper-worm-disposable-[a-z0-9](?:[a-z0-9-]{3,33}[a-z0-9])$/u;
function disposableBucket(provider,bucket){
 return (provider==='storj'&&bucket==='paper-worm-disposable')||
  BUCKET.test(bucket||'');
}
const KEY=/^paper\/oauth-witness\/epochs\/v1\/[a-f0-9]{64}\/0000000000000000001$/u;
const HEX=/^[a-f0-9]{64}$/u;
const PROFILE=/^[A-Za-z0-9_.-]{1,128}$/u;
const DAY=86400000;
const REQUIRED=['GetBucketVersioningCommand',
 'GetObjectLockConfigurationCommand','ListObjectVersionsCommand',
 'HeadObjectCommand','GetObjectRetentionCommand','GetObjectCommand'];
const MUTATIONS=['DeleteObjectCommand','PutObjectRetentionCommand'];
function fail(code){
 const error=new Error('Operator-only hostile Object Lock proof refused');
 error.code=code;throw error;
}
function opaqueVersion(s){
 return typeof s==='string'&&s!=='null'&&Buffer.byteLength(s,'utf8')<=512&&
  Buffer.byteLength(s,'utf8')>0&&[...s].every(ch=>{
   const x=ch.codePointAt(0);
   return x>32&&!(x>=127&&x<=159);
  });
}
function validSample(s){
 return s&&typeof s==='object'&&!Array.isArray(s)&&
  Object.keys(s).sort().join(',')==='key,sha256,versionId'&&
  KEY.test(s.key||'')&&HEX.test(s.sha256||'')&&
  opaqueVersion(s.versionId);
}
async function singleAttempt(client){
 try{return typeof client?.config?.maxAttempts==='function'&&
  (await client.config.maxAttempts())===1}
 catch{return false}
}
function retainUntil(response,now){
 const d=response?.Retention?.RetainUntilDate;
 const t=d instanceof Date?d.getTime():NaN;
 if(response?.Retention?.Mode!=='COMPLIANCE'||!Number.isSafeInteger(t)||
    t<=now+32*DAY||t>now+3000*DAY)
  fail('PORTABLE_WORM_HOSTILE_RETENTION_INVALID');
 return t;
}
function allowedDenial(error){
 const status=error?.$metadata?.httpStatusCode;
 return (status===400||status===403)&&
  ['AccessDenied','Forbidden','InvalidRequest','InvalidArgument',
   'OperationNotAllowed','NotAllowed'].includes(error?.name);
}
function approvalHash({provider,endpoint,bucket,sample,retentionUntil,plannedAdversaryProfile}){
 return crypto.createHash('sha256').update(JSON.stringify({
  kind:'paper.portable-s3.hostile-retention-approval.v1',
  provider,endpoint,bucket,plannedAdversaryProfile,
  key:sample.key,versionId:sample.versionId,
  sha256:sample.sha256,retentionUntil
 })).digest('hex');
}
/**
 * Mutations are strictly operator-enabled. The first call performs no
 * mutation and returns an approval challenge bound to observed retention.
 * For a hostile call, both separate read and adversary client SDKs must
 * have maxAttempts=1; ambiguity is terminal and never retried.
 */
export async function probeDisposableS3HostileObjectLock({
 provider,endpoint,approvedEndpoint=null,bucket,reader,adversary=null,
 commands,sample,phase='preflight',explicitApproval=null,
 plannedAdversaryProfile,
 clock=()=>Date.now()
}={}){
 if(phase!=='preflight'&&phase!=='hostile')
  fail('PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
 if(!disposableBucket(provider,bucket)||!validSample(sample)||
    !PROFILE.test(plannedAdversaryProfile||'')||
    !reader||typeof reader.send!=='function'||!commands||
    REQUIRED.some(name=>typeof commands[name]!=='function')||
    typeof clock!=='function'||
    (phase==='preflight'&&(adversary!==null||explicitApproval!==null))||
    (phase==='hostile'&&(
      !adversary||adversary===reader||
      typeof adversary.send!=='function'||
      MUTATIONS.some(name=>typeof commands[name]!=='function'))))
  fail('PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE');
 validatePortableS3Endpoint(provider,endpoint,approvedEndpoint);
 if(!(await singleAttempt(reader))||
   (phase==='hostile'&&!(await singleAttempt(adversary))))
  fail('PORTABLE_WORM_HOSTILE_RETRY_UNSAFE');
 if(process.env.AWS_ENDPOINT_URL||process.env.AWS_ENDPOINT_URL_S3||
    process.env.AWS_CA_BUNDLE||process.env.NODE_EXTRA_CA_CERTS||
    process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')
  fail('PORTABLE_WORM_HOSTILE_TRANSPORT_UNSAFE');
 const now=clock();
 if(!Number.isSafeInteger(now)||now<=0||
    now>Number.MAX_SAFE_INTEGER-3001*DAY)
  fail('PORTABLE_WORM_HOSTILE_CLOCK_UNSAFE');
 const config={provider,endpoint,approvedEndpoint,bucket,reader,commands,
  sample,minRetentionDays:400,minRemainingDays:32,clock:()=>now};
 async function inspect(){
  let observation;
  try{observation=await inspectPortableS3ObjectLock(config)}
  catch{fail('PORTABLE_WORM_HOSTILE_EVIDENCE_UNVERIFIED')}
  if(observation.receiptVerified!==true||
     observation.versionId!==sample.versionId||
     observation.payloadSha256!==sample.sha256||
     observation.retentionDays<400||
     observation.releaseAccepted!==false)
    fail('PORTABLE_WORM_HOSTILE_EVIDENCE_UNVERIFIED');
 }
 // Bounded exponential backoff with jitter applies ONLY to idempotent
 // read-only retention observations (429/503/504); never to mutations.
 async function getRetention(){
  for(let attempt=0;attempt<3;attempt++){
   try{
    return await reader.send(new commands.GetObjectRetentionCommand({
     Bucket:bucket,Key:sample.key,VersionId:sample.versionId
    }),{abortSignal:globalThis.AbortSignal.timeout(7000)});
   }catch(e){
    if(attempt===2||![429,503,504].includes(
     e?.$metadata?.httpStatusCode))
     fail('PORTABLE_WORM_HOSTILE_READ_UNAVAILABLE');
    const delay=Math.min(1000,150*2**attempt)+crypto.randomInt(0,65);
    await sleep(delay);
   }
  }
  fail('PORTABLE_WORM_HOSTILE_READ_UNAVAILABLE');
 }
 await inspect();
 const original=retainUntil(await getRetention(),now);
 const challenge=approvalHash({
  provider,endpoint,bucket,sample,plannedAdversaryProfile,
  retentionUntil:new Date(original).toISOString()
 });
 if(phase==='preflight')
  return Object.freeze({
   schema:'paper.portable-s3.hostile-retention.v1',phase,
   approvalChallenge:challenge,retentionUntil:new Date(original).toISOString(),
   exactVersionObserved:true,complianceRetentionObserved:true,
   exactVersionDeleteRejected:false,shorteningRejected:false,
   iamEnforcementProven:false,independentAdministrationVerified:false,
   releaseAccepted:false
  });
 if(process.env.PAPER_PORTABLE_WORM_HOSTILE_DISPOSABLE!=='confirmed'||
    explicitApproval!=='hostile-locked-version:'+challenge)
  fail('PORTABLE_WORM_HOSTILE_OPERATOR_APPROVAL_REQUIRED');
 async function recheck(){
  await inspect();
  const after=retainUntil(await getRetention(),now);
  if(after!==original)fail('PORTABLE_WORM_HOSTILE_RETENTION_CHANGED');
 }
 async function hostileAttempt(name,args){
  let rejected=false;
  try{
   await adversary.send(new commands[name]({
    Bucket:bucket,Key:sample.key,VersionId:sample.versionId,...args
   }),{abortSignal:globalThis.AbortSignal.timeout(7000)});
  }catch(error){
   if(!allowedDenial(error))
    fail('PORTABLE_WORM_HOSTILE_MUTATION_AMBIGUOUS');
   rejected=true;
  }
  if(!rejected)fail('PORTABLE_WORM_HOSTILE_MUTATION_ACCEPTED');
  // A denial is NOT proof of S3 COMPLIANCE versus insufficient IAM.
  await recheck();
 }
 await hostileAttempt('DeleteObjectCommand',{});
 await hostileAttempt('PutObjectRetentionCommand',{
  Retention:{Mode:'COMPLIANCE',RetainUntilDate:new Date(original-DAY)}
 });
 return Object.freeze({
  schema:'paper.portable-s3.hostile-retention.v1',phase,
  approvalChallenge:challenge,retentionUntil:new Date(original).toISOString(),
  exactVersionObserved:true,complianceRetentionObserved:true,
  exactVersionDeleteRejected:true,shorteningRejected:true,
  noDeleteMarkerObserved:true,originalBytesVerifiedAfterMutations:true,
  iamEnforcementProven:false,independentAdministrationVerified:false,
  monotonicLatestHeadVerified:false,releaseAccepted:false
 });
}
