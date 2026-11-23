/**
 * NONACTIVATED Cloudflare R2 S3-compatible receipt transport.
 * This adapter proves create-only receipt durability and a configured R2
 * bucket lock. It is NEVER an independent COMPLIANCE witness by itself.
 *
 * The lock reader must use the Cloudflare account-scoped management API,
 * not AWS GetObjectLockConfiguration (unsupported by R2).
 */
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';
import {assertReceipt} from './oauth-s3-compliance-archive.mjs';

const PREFIX='paper/oauth-witness/';
const EPOCH=/^paper\/oauth-witness\/epochs\/v1\/([a-f0-9]{64})\/([0-9]{19})$/u;
const BUCKET=/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u;
const ACCOUNT=/^[a-f0-9]{32}$/u;
const DAY=86400000;
const MAX_BYTES=1024;
function deny(code){
 const e=new Error('R2 receipt evidence cannot authorize Paper production');
 e.code=code;
 throw e;
}
function sha(bytes){return crypto.createHash('sha256').update(bytes).digest('hex')}
function validateRules(rules,minRetentionSeconds){
 if(!Array.isArray(rules)||rules.length>1000)return false;
 // R2 is not AWS Object Lock: the authorized account administrator can
 // remove even an indefinite bucket rule. Check the narrow witness prefix.
 return rules.some(r=>r?.enabled===true&&typeof r.id==='string'&&
  r.id.length>0&&(r.prefix===''||r.prefix===PREFIX||r.prefix===undefined)&&
  r.condition?.type==='Age'&&
  Number.isSafeInteger(r.condition.maxAgeSeconds)&&
  r.condition.maxAgeSeconds>=minRetentionSeconds);
}
async function readBounded(body){
 if(Buffer.isBuffer(body)||body instanceof Uint8Array){
  if(body.length>MAX_BYTES)deny('R2_RECEIPT_TOO_LARGE');
  return Buffer.from(body);
 }
 if(!body||typeof body[Symbol.asyncIterator]!=='function')
  deny('R2_RECEIPT_READBACK_INVALID');
 const parts=[];let size=0;
 try{
  for await(const part of body){
   if(!(part instanceof Uint8Array))deny('R2_RECEIPT_READBACK_INVALID');
   size+=part.length;
   if(size>MAX_BYTES)deny('R2_RECEIPT_TOO_LARGE');
   parts.push(Buffer.from(part));
  }
 }catch(e){
  if(e?.code?.startsWith('R2_'))throw e;
  deny('R2_RECEIPT_READBACK_UNAVAILABLE');
 }
 return Buffer.concat(parts,size);
}
export function createR2ReceiptArchive({
 writer,reader,commands,bucket,accountId,getLockRules,
 minRetentionDays=30,clock=()=>Date.now(),fixtureOnly=false
}={}){
 if(fixtureOnly!==true||process.env.NODE_ENV!=='test'||
    process.env.PAPER_OAUTH_R2_DISPOSABLE!=='confirmed')
  deny('R2_RECEIPT_NOT_RELEASED');
 if(!writer?.send||!reader?.send||writer===reader||
    !BUCKET.test(bucket||'')||!ACCOUNT.test(accountId||'')||
    typeof getLockRules!=='function'||typeof clock!=='function'||
    !Number.isSafeInteger(minRetentionDays)||minRetentionDays<1||
    minRetentionDays>3650||
    ['PutObjectCommand','HeadObjectCommand','GetObjectCommand','ListObjectsV2Command']
     .some(n=>typeof commands?.[n]!=='function'))
  deny('R2_RECEIPT_CONFIG_INVALID');
 const send=async(client,name,args)=>{
  try{return await client.send(new commands[name](args),{
   abortSignal:AbortSignal.timeout(7000)
  })}catch{deny('R2_RECEIPT_REMOTE_UNAVAILABLE')}
 };
 async function locked(){
  let policy;
  try{policy=await getLockRules({accountId,bucket})}
  catch{deny('R2_RECEIPT_LOCK_UNVERIFIED')}
  if(!validateRules(policy?.rules,minRetentionDays*DAY/1000))
   deny('R2_RECEIPT_LOCK_UNVERIFIED');
 }
 async function readExact(key){
  let head;
  try{head=await send(reader,'HeadObjectCommand',{Bucket:bucket,Key:key})}
  catch{deny('R2_RECEIPT_HEAD_UNAVAILABLE')}
  if(!Number.isSafeInteger(head?.ContentLength)||head.ContentLength<32||
     head.ContentLength>MAX_BYTES)deny('R2_RECEIPT_HEAD_INVALID');
  let obj;
  try{obj=await send(reader,'GetObjectCommand',{Bucket:bucket,Key:key})}
  catch{deny('R2_RECEIPT_READBACK_UNAVAILABLE')}
  const bytes=await readBounded(obj?.Body);
  if(bytes.length!==head.ContentLength)deny('R2_RECEIPT_BYTES_MISMATCH');
  assertReceipt(key,bytes);
  return bytes;
 }
 async function write({key,bytes}={}){
  assertReceipt(key,bytes);
  const time=clock();
  if(!Number.isSafeInteger(time)||time<=0)deny('R2_RECEIPT_CLOCK_INVALID');
  await locked();
  // A lost response is ambiguous: never retry unconditionally.
  try{await send(writer,'PutObjectCommand',{
   Bucket:bucket,Key:key,Body:Buffer.from(bytes),IfNoneMatch:'*',
   ContentType:'application/octet-stream',
   ChecksumSHA256:crypto.createHash('sha256').update(bytes).digest('base64')
  })}catch{/* verify readback below; never overwrite */}
  const actual=await readExact(key);
  if(!crypto.timingSafeEqual(actual,bytes))deny('R2_RECEIPT_BYTES_MISMATCH');
  await locked();
  return Object.freeze({key,sha256:sha(actual),
   independentlyImmutable:false,releaseAccepted:false});
 }
 async function readCertifiedLatestEpoch({owner,clientId,authority}={}){
  // No externally trusted *latest* proof => NO authorization. The
  // caller cannot pass a certificate directly: authority must acquire
  // it from a separately operated source using a pinned signer.
  if(typeof authority?.readVerified!=='function'||
     typeof owner!=='string'||typeof clientId!=='string')
   deny('R2_CERT_AUTHORITY_REQUIRED');
  // Do not weaken the identity parser to a mere https:// string prefix.
  const valid=(value)=>{
   if(value.length<8||value.length>2048)return false;
   try{
    const u=new URL(value);
    return u.protocol==='https:'&&!!u.hostname&&!u.username&&
     !u.password&&!u.search&&!u.hash&&u.href===value;
   }catch{return false}
  };
  if(!valid(owner)||!valid(clientId))deny('R2_HIGHWATER_SCOPE_INVALID');
  const subject=sha(Buffer.from('paper:witness:subject:v1\\0'+owner+'\\0'+clientId));
  const first=await authority.readVerified(Object.freeze({owner,clientId}));
  if(first?.subject!==subject||
     typeof first.revision!=='string'||
     !/^[1-9][0-9]{0,18}$/u.test(first.revision)||
     BigInt(first.revision)>9223372036854775807n||
     !/^[a-f0-9]{64}$/u.test(first.sha256||''))
   deny('R2_CERT_SCOPE_INVALID');
  const key=PREFIX+'epochs/v1/'+subject+'/'+first.revision.padStart(19,'0');
  await locked();
  const bytes=await readExact(key);
  const data=JSON.parse(bytes.toString('utf8'));
  if(data.subject!==subject||data.revision!==first.revision||
     sha(bytes)!==first.sha256)
   deny('R2_CERT_RECEIPT_MISMATCH');
  await locked();
  // A revocation that advances while R2 is read must never authorize
  // the previous generation. Compare exact signed authority heads.
  const second=await authority.readVerified(Object.freeze({owner,clientId}));
  if(second?.subject!==first.subject||
     second.revision!==first.revision||
     second.sha256!==first.sha256||
     second.authority!==first.authority)
   deny('R2_CERT_CONCURRENT_ADVANCE');
  // O(1) exact-key R2 reads, vs O(all epochs) fixture enumeration.
  // Historical continuity belongs to a separate offline proof/audit.
  return Buffer.from(bytes);
 }
 async function readLatestEpoch({owner,clientId,checkpoint}={}){
  // This is an externally supplied checkpoint REQUIREMENT, not proof
  // of the checkpoint's provenance. Callers must independently certify it.
  if(typeof owner!=='string'||typeof clientId!=='string'||
     !owner.startsWith('https://')||!clientId.startsWith('https://')||
     owner.length>2048||clientId.length>2048)
    deny('R2_HIGHWATER_SCOPE_INVALID');
  const subject=sha(Buffer.from('paper:witness:subject:v1\0'+owner+'\0'+clientId));
  if(checkpoint?.subject!==subject||
     typeof checkpoint.revision!=='string'||
     !/^[1-9][0-9]{0,18}$/u.test(checkpoint.revision)||
     BigInt(checkpoint.revision)>9223372036854775807n||
     !/^[a-f0-9]{64}$/u.test(checkpoint.sha256||''))
    deny('R2_HIGHWATER_CHECKPOINT_REQUIRED');
  await locked();
  const prefix=PREFIX+'epochs/v1/'+subject+'/';
  let token,previous='',last=null,count=0;
  const seen=new Set();
  // ListObjectsV2 has no retained version history. If a writer or admin
  // hides the latest key, an independently retained head must detect it.
  for(let page=0;page<8;page++){
   const args={Bucket:bucket,Prefix:prefix,MaxKeys:1000};
   if(token!==undefined)args.ContinuationToken=token;
   let listing;
   try{listing=await send(reader,'ListObjectsV2Command',args)}
   catch{deny('R2_HIGHWATER_LIST_UNAVAILABLE')}
   if(!listing||typeof listing.IsTruncated!=='boolean'||
      !Array.isArray(listing.Contents)||!listing.Contents.length)
     deny('R2_HIGHWATER_LIST_INVALID');
   for(const e of listing.Contents){
    const key=e?.Key;
    if(typeof key!=='string'||key<=previous||
       !EPOCH.test(key)||!key.startsWith(prefix)||
       !Number.isSafeInteger(e.Size)||e.Size<32||e.Size>MAX_BYTES)
      deny('R2_HIGHWATER_LIST_INVALID');
    count++;
    if(count>4096||BigInt(key.slice(-19))!==BigInt(count))
      deny('R2_HIGHWATER_GAP_OR_CAPACITY');
    previous=key;last=key;
   }
   if(listing.IsTruncated===false){
    if(BigInt(count)!==BigInt(checkpoint.revision))
      deny('R2_HIGHWATER_CHECKPOINT_MISMATCH');
    const bytes=await readExact(last);
    const event=JSON.parse(bytes.toString('utf8'));
    if(event.subject!==subject||event.revision!==checkpoint.revision||
       sha(bytes)!==checkpoint.sha256)
      deny('R2_HIGHWATER_CHECKPOINT_MISMATCH');
    await locked();
    return Buffer.from(bytes);
   }
   const next=listing.NextContinuationToken;
   if(typeof next!=='string'||!next||seen.has(next))
    deny('R2_HIGHWATER_PAGINATION_INVALID');
   seen.add(next);token=next;
  }
  deny('R2_HIGHWATER_GAP_OR_CAPACITY');
 }
 return Object.freeze({putAndVerify:write,readLatestEpoch,readCertifiedLatestEpoch,
  independentlyImmutable:false,releaseAccepted:false});
}
