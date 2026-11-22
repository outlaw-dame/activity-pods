/**
 * NONACTIVATED independent immutable epoch-receipt attestor candidate.
 *
 * No production storage adapter or credentials are present. The attestor role
 * MUST be separate from the writer, primary account DB, witness issuer,
 * revoker, restore administrator and bucket-lock administrator. A bucket-lock
 * claim from the PUT response is not independent evidence.
 */
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const REV=/^[1-9][0-9]{0,18}$/u;
const MAX_REV=9223372036854775807n;
function deny(code){
 const e=new Error('Independent immutable witness receipt unavailable');
 e.code=code;
 throw e;
}
function enabled(){
 return process.env.NODE_ENV==='test'&&
  process.env.PAPER_OAUTH_WITNESS_DISPOSABLE==='confirmed'&&
  process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE==='confirmed';
}
function validUrl(s){
 if(typeof s!=='string'||s.length<8||s.length>2048)return false;
 try{
  const u=new URL(s);
  return u.protocol==='https:'&&!!u.hostname&&!u.username&&!u.password&&
   !u.search&&!u.hash&&u.href===s;
 }catch{return false}
}
function revisionString(input){
 if(typeof input!=='string' || !REV.test(input))deny('WORM_RECEIPT_REVISION_INVALID');
 if(BigInt(input)>MAX_REV)deny('WORM_RECEIPT_REVISION_INVALID');
 return input;
}
function subjectHash(owner,client){
 return crypto.createHash('sha256')
  .update('paper:witness:subject:v1\0').update(owner).update('\0').update(client)
  .digest('hex');
}
function equal(a,b){
 return Buffer.isBuffer(a)&&Buffer.isBuffer(b)&&
  a.length===b.length&&crypto.timingSafeEqual(a,b);
}
/**
 * All four capabilities are provisioned by the private attestor process,
 * never from a request:
 *  - readUnsealed: restricted witness get_unsealed_receipt;
 *  - putIfAbsent: ONLY create immutable bytes with If-None-Match: *;
 *  - getIndependent: independently credentialed, uncached object GET;
 *  - verifyRetention: independent lock-controller read proving the exact
 *    prefix remains covered by an adequate policy that writer and attestor
 *    CANNOT alter; must fail closed on inaccessible policy information;
 *  - seal: restricted witness seal() after confirmed readback.
 * This is a disposal-only protocol proof, NOT a deployed storage adapter.
 */
export function createDisposableWormEpochAttestor({
 readUnsealed,putIfAbsent,getIndependent,verifyRetention,seal,
 fixtureOnly=false
}={}){
 if(!enabled()||fixtureOnly!==true){
  return Object.freeze({attestEpoch:async()=>deny('WORM_RECEIPT_NOT_RELEASED')});
 }
 if([readUnsealed,putIfAbsent,getIndependent,verifyRetention,seal]
     .some(fn=>typeof fn!=='function'))
  deny('WORM_RECEIPT_CONFIGURATION_INVALID');
 async function attestEpoch({owner,clientId,revision,operationId}={}){
  if(!enabled())deny('WORM_RECEIPT_NOT_RELEASED');
  if(!validUrl(owner)||!validUrl(clientId)||!UUID.test(operationId||''))
   deny('WORM_RECEIPT_IDENTITY_INVALID');
  const rev=revisionString(revision);
  let eventHash;
  try{
   eventHash=await readUnsealed(Object.freeze({owner,clientId,
    revision:rev,operationId}));
  }catch{deny('WORM_RECEIPT_WITNESS_UNAVAILABLE')}
  if(!Buffer.isBuffer(eventHash)||eventHash.length!==32)
   deny('WORM_RECEIPT_EVENT_INVALID');
  const subject=subjectHash(owner,clientId);
  const key='paper/oauth-witness/epochs/v1/'+subject+'/'+rev.padStart(19,'0');
  const body=Buffer.from(JSON.stringify({
   kind:'paper.witness.epoch.v1',subject,revision:rev,
   operationId,eventSha256:eventHash.toString('hex')
  }),'utf8');
  if(body.length>512)deny('WORM_RECEIPT_SIZE_INVALID');

  // A regular S3 object, ordinary R2 bucket or ETag alone is NOT WORM.
  // The separate policy reader must attest lock coverage before the PUT,
  // and again immediately before the witness seal.
  try{
   if(await verifyRetention(key)!==true)
    deny('WORM_RECEIPT_RETENTION_UNVERIFIED');
  }catch{deny('WORM_RECEIPT_RETENTION_UNVERIFIED')}
  try{
   // No overwrite or delete permission. A lost PUT ACK is ambiguous.
   await putIfAbsent(key,Buffer.from(body),
    Object.freeze({ifNoneMatch:'*'}));
  }catch{
   // Never assume a failed PUT means absence: only independent exact
   // readback can distinguish a valid committed object from uncertainty.
  }
  let readback;
  try{readback=await getIndependent(key)}
  catch{deny('WORM_RECEIPT_READBACK_UNAVAILABLE')}
  if(!equal(readback,body))deny('WORM_RECEIPT_READBACK_MISMATCH');
  try{
   if(await verifyRetention(key)!==true)
    deny('WORM_RECEIPT_RETENTION_UNVERIFIED');
  }catch{deny('WORM_RECEIPT_RETENTION_UNVERIFIED')}
  try{
   if(await seal(Object.freeze({owner,clientId,revision:rev,
    operationId,eventHash:Buffer.from(eventHash)}))!==true)
    deny('WORM_RECEIPT_SEAL_REFUSED');
  }catch(e){
   if(e?.code==='WORM_RECEIPT_SEAL_REFUSED')throw e;
   deny('WORM_RECEIPT_SEAL_UNAVAILABLE');
  }
  return true;
 }
 return Object.freeze({attestEpoch});
}
