/**
 * NONACTIVATED provider-neutral, strictly READ-ONLY S3 Object Lock
 * qualification. AWS STS/ExpectedBucketOwner is NOT simulated here.
 * No application grant/signature/access token may depend on this result.
 *
 * The provider's immutable S3 object versions are not, by themselves,
 * an independently operated monotonically advancing head.
 */
import {createHash,timingSafeEqual} from 'node:crypto';
import {Buffer} from 'node:buffer';
import {isIP} from 'node:net';
import {assertReceipt} from './oauth-s3-compliance-archive.mjs';

const BUCKET=/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u;
const HEX=/^[a-f0-9]{64}$/u;
const VERSION=/^.{1,512}$/u;
// Avoid control characters without relying on a control-character regexp.
function validVersion(value){
  return typeof value==='string'&&VERSION.test(value)&&
    !Array.from(value).some(ch=>{
      const code=ch.codePointAt(0);
      return code<=32||code===127;
    });
}
const KEY=/^paper\/oauth-witness\/epochs\/v1\/[a-f0-9]{64}\/[0-9]{19}$/u;
const DAY=86_400_000;
const MAX_READ=1024;
const REQUIRED=[
  'GetBucketVersioningCommand','GetObjectLockConfigurationCommand',
  'ListObjectVersionsCommand','HeadObjectCommand',
  'GetObjectRetentionCommand','GetObjectCommand'
];
function deny(code){
  const e=new Error('External S3-compatible immutable custody not qualified');
  e.code=code;throw e;
}
function validateEndpoint(provider,endpoint,approvedEndpoint=null){
  // Known providers receive hard-pinned vendor origins. A *different*
  // S3 implementation may be inspected only against an operator-pinned
  // exact HTTPS origin and still NEVER counts as trusted release custody.
  if(!['backblaze-b2','storj','custom-s3'].includes(provider))
    deny('PORTABLE_WORM_PROVIDER_UNSUPPORTED');
  if(typeof endpoint!=='string'||endpoint.length>256)
    deny('PORTABLE_WORM_ENDPOINT_UNSAFE');
  let u;
  try{u=new URL(endpoint);}catch{deny('PORTABLE_WORM_ENDPOINT_UNSAFE');}
  if(u.href!==endpoint||u.protocol!=='https:'||u.username||
      u.password||u.port||u.pathname!=='/'||u.search||u.hash)
    deny('PORTABLE_WORM_ENDPOINT_UNSAFE');
  if(provider==='storj'){
    if(u.hostname!=='gateway.storjshare.io')
      deny('PORTABLE_WORM_ENDPOINT_UNSAFE');
  }else if(provider==='backblaze-b2'){
    if(!/^s3\.[a-z0-9]+(?:-[a-z0-9]+)*\.backblazeb2\.com$/u.test(u.hostname))
      deny('PORTABLE_WORM_ENDPOINT_UNSAFE');
  }else{
    if(typeof approvedEndpoint!=='string'||approvedEndpoint!==endpoint)
      deny('PORTABLE_WORM_ENDPOINT_NOT_PINNED');
    // Restrict custom S3 endpoints to operator-reviewed public DNS names,
    // not IP literals, local-only DNS suffixes, IDN edge cases or wildcards.
    // The CLI is read-only. This is not a substitute for operator DNS/TLS
    // review, a signed manifest, or an independent immutable signer.
    if(isIP(u.hostname)!==0||
       !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(u.hostname)||
       /\.(?:local|localhost|internal|invalid|test|example|onion)$/u.test(u.hostname))
      deny('PORTABLE_WORM_ENDPOINT_UNSAFE');
  }
  return Object.freeze({provider,endpoint});
}
function makeClock(clock){
  if(typeof clock!=='function')deny('PORTABLE_WORM_CONFIGURATION_UNSAFE');
  const now=clock();
  if(!Number.isSafeInteger(now)||now<=0||now>Number.MAX_SAFE_INTEGER-3650*DAY)
    deny('PORTABLE_WORM_CLOCK_UNSAFE');
  return now;
}
function retentionDuration(retention){
  const r=retention?.ObjectLockConfiguration?.Rule?.DefaultRetention;
  if(r?.Mode!=='COMPLIANCE')return 0;
  const days=(r.Days??0)+365*(r.Years??0);
  return Number.isSafeInteger(days)&&days>0?days:0;
}
async function readBytes(body){
  if(Buffer.isBuffer(body)||body instanceof Uint8Array){
    if(body.length<1||body.length>MAX_READ)
      deny('PORTABLE_WORM_BODY_UNSAFE');
    return Buffer.from(body);
  }
  if(!body||typeof body[Symbol.asyncIterator]!=='function')
    deny('PORTABLE_WORM_BODY_UNSAFE');
  const parts=[];let size=0;
  try{
    for await(const part of body){
      if(!(part instanceof Uint8Array))deny('PORTABLE_WORM_BODY_UNSAFE');
      size+=part.length;
      if(size>MAX_READ)deny('PORTABLE_WORM_BODY_UNSAFE');
      parts.push(Buffer.from(part));
    }
  }catch(e){
    if(e?.code?.startsWith('PORTABLE_WORM_'))throw e;
    deny('PORTABLE_WORM_REMOTE_UNAVAILABLE');
  }
  if(size<1)deny('PORTABLE_WORM_BODY_UNSAFE');
  return Buffer.concat(parts,size);
}
/**
 * Supports pinned Backblaze/Storj origins or an explicitly operator-pinned
 * custom S3 HTTPS origin. None supplies universal AWS STS/IAM identity.
 * Checks bucket versioning, COMPLIANCE default retention and, if supplied,
 * a historical exact-version receipt against an operator-pinned SHA256.
 *
 * Does NOT claim account isolation, delete/overwrite refusal, conditional
 * PutObject support, key-custody integrity, signed latest state or release.
 */
export async function inspectPortableS3ObjectLock({
  provider,endpoint,approvedEndpoint=null,reader,commands,bucket,sample=null,
  minRetentionDays=400,minRemainingDays=30,clock=()=>Date.now()
}={}){
  validateEndpoint(provider,endpoint,approvedEndpoint);
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||
     process.env.AWS_ENDPOINT_URL||process.env.AWS_ENDPOINT_URL_S3||
     process.env.AWS_CA_BUNDLE||process.env.NODE_EXTRA_CA_CERTS)
    deny('PORTABLE_WORM_TRANSPORT_UNSAFE');
  if(!reader||typeof reader.send!=='function'||!commands||
     REQUIRED.some(n=>typeof commands[n]!=='function')||
     !BUCKET.test(bucket||'')||
     !Number.isSafeInteger(minRetentionDays)||minRetentionDays<365||
     minRetentionDays>3000||
     !Number.isSafeInteger(minRemainingDays)||minRemainingDays<1||
     minRemainingDays>minRetentionDays)
    deny('PORTABLE_WORM_CONFIGURATION_UNSAFE');
  const now=makeClock(clock);
  const call=async(name,args={})=>{
    try {
      return await reader.send(new commands[name]({Bucket:bucket,...args}),{
        abortSignal:AbortSignal.timeout(7000)
      });
    }catch{deny('PORTABLE_WORM_REMOTE_UNAVAILABLE')}
  };
  async function policy(){
    const [v,l]=await Promise.all([
      call('GetBucketVersioningCommand'),
      call('GetObjectLockConfigurationCommand')
    ]);
    const days=retentionDuration(l);
    if(v?.Status!=='Enabled'||l?.ObjectLockConfiguration?.ObjectLockEnabled!=='Enabled'||
       days<minRetentionDays)
      deny('PORTABLE_WORM_BUCKET_NOT_COMPLIANT');
    return days;
  }
  const days=await policy();
  if(sample===null)return Object.freeze({
    provider,configurationObserved:true,receiptVerified:false,
    operatorIndependenceVerified:false,conditionalCreateOnlyVerified:false,
    latestHeadVerified:false,releaseAccepted:false,retentionDays:days
  });
  if(typeof sample!=='object'||Array.isArray(sample)||!sample||
     !KEY.test(sample.key||'')||!HEX.test(sample.sha256||'')||
     !validVersion(sample.versionId))
    deny('PORTABLE_WORM_SAMPLE_INVALID');
  const history=await call('ListObjectVersionsCommand',{
    Prefix:sample.key,MaxKeys:10
  });
  // One version; no newer delete marker. A locked old version is not
  // the current credential generation if someone hides it.
  if(history?.IsTruncated!==false||!Array.isArray(history.Versions)||
     history.Versions.length!==1||
     !Array.isArray(history.DeleteMarkers??[])||
     (history.DeleteMarkers??[]).length!==0||
     history.Versions[0]?.Key!==sample.key||
     history.Versions[0]?.VersionId!==sample.versionId||
     history.Versions[0]?.IsLatest!==true||
     !Number.isSafeInteger(history.Versions[0]?.Size)||
     history.Versions[0].Size<32||history.Versions[0].Size>MAX_READ)
    deny('PORTABLE_WORM_VERSION_HISTORY_UNSAFE');
  const head=await call('HeadObjectCommand',{Key:sample.key});
  if(head?.VersionId!==sample.versionId||head?.DeleteMarker===true||
     head?.ContentLength!==history.Versions[0].Size)
    deny('PORTABLE_WORM_CURRENT_VERSION_UNSAFE');
  const r=await call('GetObjectRetentionCommand',{
    Key:sample.key,VersionId:sample.versionId
  });
  const until=r?.Retention?.RetainUntilDate instanceof Date?
    r.Retention.RetainUntilDate.getTime():
    Date.parse(r?.Retention?.RetainUntilDate);
  if(r?.Retention?.Mode!=='COMPLIANCE'||!Number.isFinite(until)||
     until<now+minRemainingDays*DAY)
    deny('PORTABLE_WORM_RETENTION_UNSAFE');
  const content=await call('GetObjectCommand',{
    Key:sample.key,VersionId:sample.versionId
  });
  if(content?.VersionId!==sample.versionId)
    deny('PORTABLE_WORM_VERSION_CHANGED');
  const bytes=await readBytes(content.Body);
  if(bytes.length!==head.ContentLength)
    deny('PORTABLE_WORM_BODY_UNSAFE');
  try{assertReceipt(sample.key,bytes)}
  catch{deny('PORTABLE_WORM_BODY_UNSAFE')}
  const digest=createHash('sha256').update(bytes).digest();
  if(!timingSafeEqual(digest,Buffer.from(sample.sha256,'hex')))
    deny('PORTABLE_WORM_DIGEST_MISMATCH');
  const latest=await call('HeadObjectCommand',{Key:sample.key});
  if(latest?.VersionId!==sample.versionId||latest?.DeleteMarker===true)
    deny('PORTABLE_WORM_VERSION_CHANGED');
  await policy();
  return Object.freeze({
    provider,configurationObserved:true,receiptVerified:true,
    operatorIndependenceVerified:false,conditionalCreateOnlyVerified:false,
    latestHeadVerified:false,releaseAccepted:false,retentionDays:days,
    versionId:sample.versionId,payloadSha256:sample.sha256
  });
}
export {validateEndpoint as validatePortableS3Endpoint};
