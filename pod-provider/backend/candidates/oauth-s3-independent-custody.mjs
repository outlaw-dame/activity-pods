/**
 * NONACTIVATED, READ-ONLY AWS S3 COMPLIANCE custody acceptance probe.
 *
 * This module cannot mutate the bucket or enable the Paper signup fuse.
 * Both AWS accounts and the independent receipt version must be supplied
 * by an independently appointed operator, never copied from a restored DB.
 * A green probe proves only the observed controls, NOT IAM policy safety,
 * independence of human administrators or live cross-store recovery.
 */
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';

const ACCOUNT=/^[0-9]{12}$/u;
const BUCKET=/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u;
const HEX=/^[a-f0-9]{64}$/u;
const EPOCH=/^paper\/oauth-witness\/epochs\/v1\/([a-f0-9]{64})\/([0-9]{19})$/u;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DAY=86400000;
const MAX_READ=1024;

function deny(code){
  const e=new Error('External immutable archive custody was not verified');
  e.code=code;
  throw e;
}
function validRole(identity,account){
  const arn=identity?.Arn;
  return identity?.Account===account&&
    typeof arn==='string'&&arn.length<=512&&
    !/[\s\u0000-\u001f]/u.test(arn)&&
    (arn.startsWith('arn:aws:iam::'+account+':role/')||
     arn.startsWith('arn:aws:sts::'+account+':assumed-role/'))&&
    !arn.endsWith('/')&&
    typeof identity?.UserId==='string'&&identity.UserId.length>0;
}
function bytesOf(body){
  if(Buffer.isBuffer(body)||body instanceof Uint8Array)
    return Promise.resolve(Buffer.from(body));
  if(!body||typeof body[Symbol.asyncIterator]!=='function')
    deny('WORM_CUSTODY_BODY_INVALID');
  return (async()=>{
    const chunks=[];let size=0;
    try{
      for await(const chunk of body){
        if(!(chunk instanceof Uint8Array))deny('WORM_CUSTODY_BODY_INVALID');
        size+=chunk.length;
        if(size>MAX_READ)deny('WORM_CUSTODY_BODY_TOO_LARGE');
        chunks.push(Buffer.from(chunk));
      }
    }catch(e){
      if(e?.code?.startsWith('WORM_CUSTODY_'))throw e;
      deny('WORM_CUSTODY_BODY_UNAVAILABLE');
    }
    return Buffer.concat(chunks,size);
  })();
}
function exactReceipt(key,bytes){
  if(bytes.length<32||bytes.length>MAX_READ)
    deny('WORM_CUSTODY_BODY_INVALID');
  const text=bytes.toString('utf8');
  if(!Buffer.from(text).equals(bytes))deny('WORM_CUSTODY_BODY_INVALID');
  let value;
  try{value=JSON.parse(text)}catch{deny('WORM_CUSTODY_BODY_INVALID')}
  const match=EPOCH.exec(key);
  if(!match||!value||
     Object.keys(value).sort().join(',')!==
       'eventSha256,kind,operationId,revision,subject'||
     value.kind!=='paper.witness.epoch.v1'||
     value.subject!==match[1]||
     !HEX.test(value.eventSha256)||
     !UUID.test(value.operationId)||
     typeof value.revision!=='string'||
     !/^[1-9][0-9]{0,18}$/u.test(value.revision)||
     BigInt(value.revision)>9223372036854775807n||
     value.revision.padStart(19,'0')!==match[2]||
     JSON.stringify(value)!==text)
     deny('WORM_CUSTODY_BODY_INVALID');
}
const required=['GetCallerIdentityCommand','GetBucketVersioningCommand',
  'GetObjectLockConfigurationCommand','GetPublicAccessBlockCommand',
  'ListObjectVersionsCommand','HeadObjectCommand','GetObjectRetentionCommand',
  'GetObjectCommand'];

/**
 * writerSts must use provider-account write credentials; readerSts and
 * readerS3 use the independently administered archive-account read role.
 * All S3 operations carry ExpectedBucketOwner. This probe has no PUT, DELETE,
 * policy-edit, retention-edit, or rollback operations.
 *
 * The optional sample is a pre-existing independently supplied receipt.
 * No sample => configuration-only preflight, NOT retention readback.
 */
export async function inspectIndependentS3Custody({
  writerSts,readerSts,readerS3,commands,bucket,
  expectedProviderAccount,expectedBucketOwner,
  sample=null,minRetentionDays=400,minRemainingDays=30,
  clock=()=>Date.now()
}={}){
  if(!writerSts?.send||!readerSts?.send||!readerS3?.send||
     !commands||required.some(x=>typeof commands[x]!=='function')||
     typeof bucket!=='string'||!BUCKET.test(bucket)||
     typeof expectedProviderAccount!=='string'||
     !ACCOUNT.test(expectedProviderAccount)||
     typeof expectedBucketOwner!=='string'||!ACCOUNT.test(expectedBucketOwner)||
     expectedProviderAccount===expectedBucketOwner||
     !Number.isSafeInteger(minRetentionDays)||minRetentionDays<365||
     minRetentionDays>3650||
     !Number.isSafeInteger(minRemainingDays)||minRemainingDays<30||
     minRemainingDays>minRetentionDays||
     typeof clock!=='function')
    deny('WORM_CUSTODY_CONFIGURATION_INVALID');
  const now=clock();
  if(!Number.isSafeInteger(now)||now<=0||
     !Number.isSafeInteger(now+minRetentionDays*DAY))
    deny('WORM_CUSTODY_CLOCK_INVALID');

  const send=async(client,name,args={})=>{
    try{return await client.send(new commands[name](args),{
      abortSignal:AbortSignal.timeout(7000)
    })}catch{deny('WORM_CUSTODY_REMOTE_UNAVAILABLE')}
  };
  const s3=(name,args={})=>send(readerS3,name,{
    Bucket:bucket,ExpectedBucketOwner:expectedBucketOwner,...args
  });
  const [writer,reader]=await Promise.all([
    send(writerSts,'GetCallerIdentityCommand'),
    send(readerSts,'GetCallerIdentityCommand')
  ]);
  if(!validRole(writer,expectedProviderAccount)||
     !validRole(reader,expectedBucketOwner)||
     writer.Arn===reader.Arn)
    deny('WORM_CUSTODY_PRINCIPALS_NOT_INDEPENDENT');

  async function policy(){
    const [version,lock,access]=await Promise.all([
      s3('GetBucketVersioningCommand'),
      s3('GetObjectLockConfigurationCommand'),
      s3('GetPublicAccessBlockCommand')
    ]);
    const b=lock?.ObjectLockConfiguration;
    const r=b?.Rule?.DefaultRetention;
    const days=Number(r?.Days??0)+Number(r?.Years??0)*365;
    const a=access?.PublicAccessBlockConfiguration;
    if(version?.Status!=='Enabled'||b?.ObjectLockEnabled!=='Enabled'||
       r?.Mode!=='COMPLIANCE'||!Number.isSafeInteger(days)||
       days<minRetentionDays||!a||![
         a.BlockPublicAcls,a.IgnorePublicAcls,
         a.BlockPublicPolicy,a.RestrictPublicBuckets
       ].every(x=>x===true))
      deny('WORM_CUSTODY_BUCKET_UNSAFE');
    return days;
  }
  const retentionDays=await policy();

  if(sample===null)return Object.freeze({
    configurationVerified:true,receiptVerified:false,
    releaseAccepted:false,retentionDays
  });
  if(!sample||typeof sample.key!=='string'||!EPOCH.test(sample.key)||
     typeof sample.sha256!=='string'||!HEX.test(sample.sha256)||
     typeof sample.versionId!=='string'||sample.versionId.length<1||
     sample.versionId.length>1024||sample.versionId==='null'||
     /[\s\u0000-\u001f]/u.test(sample.versionId))
    deny('WORM_CUSTODY_RECEIPT_INPUT_INVALID');

  const history=await s3('ListObjectVersionsCommand',{
    Prefix:sample.key,MaxKeys:10
  });
  if(history?.IsTruncated!==false||
     !Array.isArray(history.Versions)||
     history.Versions.length!==1||
     !Array.isArray(history.DeleteMarkers??[])||
     (history.DeleteMarkers??[]).length!==0||
     history.Versions[0]?.Key!==sample.key||
     history.Versions[0]?.VersionId!==sample.versionId||
     history.Versions[0]?.IsLatest!==true||
     !Number.isSafeInteger(history.Versions[0]?.Size)||
     history.Versions[0].Size<32||history.Versions[0].Size>MAX_READ)
    deny('WORM_CUSTODY_VERSION_HISTORY_UNSAFE');

  const head=await s3('HeadObjectCommand',{Key:sample.key});
  if(head?.VersionId!==sample.versionId||
     head?.DeleteMarker===true||
     head?.ContentLength!==history.Versions[0].Size)
    deny('WORM_CUSTODY_RECEIPT_HEAD_INVALID');

  const retention=await s3('GetObjectRetentionCommand',{
    Key:sample.key,VersionId:sample.versionId
  });
  const expiry=retention?.Retention?.RetainUntilDate;
  const retainUntil=expiry instanceof Date?expiry.getTime():Date.parse(expiry);
  if(retention?.Retention?.Mode!=='COMPLIANCE'||
     !Number.isFinite(retainUntil)||
     retainUntil<now+minRemainingDays*DAY)
    deny('WORM_CUSTODY_RETENTION_INVALID');

  const result=await s3('GetObjectCommand',{
    Key:sample.key,VersionId:sample.versionId
  });
  if(result?.VersionId!==sample.versionId)
    deny('WORM_CUSTODY_VERSION_CHANGED');
  const bytes=await bytesOf(result.Body);
  if(bytes.length!==head.ContentLength)
    deny('WORM_CUSTODY_BODY_INVALID');
  exactReceipt(sample.key,bytes);
  const digest=crypto.createHash('sha256').update(bytes).digest('hex');
  if(!crypto.timingSafeEqual(Buffer.from(digest,'hex'),
     Buffer.from(sample.sha256,'hex')))
    deny('WORM_CUSTODY_RECEIPT_HASH_MISMATCH');

  const again=await s3('HeadObjectCommand',{Key:sample.key});
  if(again?.VersionId!==sample.versionId||again?.DeleteMarker===true)
    deny('WORM_CUSTODY_VERSION_CHANGED');
  await policy();
  return Object.freeze({
    configurationVerified:true,receiptVerified:true,
    // A single historical receipt is NOT latest high-water, IAM policy
    // certification, or cross-database restore acceptance.
    releaseAccepted:false,retentionDays,versionVerified:true,
    payloadSha256:digest
  });
}
