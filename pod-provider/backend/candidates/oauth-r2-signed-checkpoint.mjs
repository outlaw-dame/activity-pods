/**
 * NONACTIVATED verifier for an independently held, SIGNED latest-epoch head.
 * Ed25519 authenticates the statement. It does NOT make a replayed old
 * statement fresh: readHead must be an independently operated, nonrewindable
 * *latest* checkpoint authority, not a caller argument or local DB snapshot.
 */
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';

const HEX=/^[a-f0-9]{64}$/u;
const REV=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
const AUTH=/^[a-zA-Z0-9._:-]{1,128}$/u;
function deny(code){
 const e=new Error('Independent signed epoch checkpoint unavailable');
 e.code=code;
 throw e;
}
function validUrl(value){
 if(typeof value!=='string'||value.length<8||value.length>2048)return false;
 try{
  const u=new URL(value);
  return u.protocol==='https:'&&!!u.hostname&&!u.username&&
   !u.password&&!u.search&&!u.hash&&u.href===value;
 }catch{return false}
}
function subjectHash(owner,clientId){
 return crypto.createHash('sha256')
  .update('paper:witness:subject:v1\0').update(owner)
  .update('\0').update(clientId).digest('hex');
}
function canonical(value){
 if(!value||Array.isArray(value)||typeof value!=='object'||
    Object.keys(value).sort().join(',')!==
     'authority,kind,revision,sha256,subject')
  deny('R2_CERT_FORMAT_INVALID');
 const {kind,authority,subject,revision,sha256}=value;
 if(kind!=='paper.witness.latest-checkpoint.v1'||!AUTH.test(authority)||
    !HEX.test(subject)||!REV.test(revision)||BigInt(revision)>MAX||
    !HEX.test(sha256))deny('R2_CERT_FORMAT_INVALID');
 // Signature covers a domain separator and strict canonical JSON, which
 // prevents a valid signature from being transplanted to another protocol.
 return Buffer.from('paper:witness:latest-checkpoint:v1\0'+JSON.stringify({
  kind,authority,subject,revision,sha256
 }), 'utf8');
}
export function createDisposableR2CheckpointAuthority({
 readHead,trustedPublicKey,authority,fixtureOnly=false
}={}){
 if(fixtureOnly!==true||process.env.NODE_ENV!=='test'||
    process.env.PAPER_OAUTH_R2_DISPOSABLE!=='confirmed')
  deny('R2_CERT_NOT_RELEASED');
 let key;
 try{key=crypto.createPublicKey(trustedPublicKey)}
 catch{deny('R2_CERT_KEY_INVALID')}
 if(key.asymmetricKeyType!=='ed25519'||typeof readHead!=='function'||
    !AUTH.test(authority||''))
  deny('R2_CERT_CONFIG_INVALID');
 async function readVerified({owner,clientId}={}){
  if(!validUrl(owner)||!validUrl(clientId))
   deny('R2_CERT_SCOPE_INVALID');
  let response;
  try{
   response=await Promise.race([
    Promise.resolve().then(()=>readHead(Object.freeze({owner,clientId}))),
    new Promise((_,reject)=>setTimeout(()=>reject(Error('timeout')),3000))
   ]);
  }catch{deny('R2_CERT_AUTHORITY_UNAVAILABLE')}
  // The transport returns canonical bytes and detached binary Ed25519
  // signature. No attacker-provided public keys, PEM or account credentials.
  if(!Buffer.isBuffer(response?.body)||response.body.length<100||
     response.body.length>512||!Buffer.isBuffer(response.signature)||
     response.signature.length!==64)
   deny('R2_CERT_FORMAT_INVALID');
  let value;
  try{value=JSON.parse(response.body.toString('utf8'))}
  catch{deny('R2_CERT_FORMAT_INVALID')}
  const message=canonical(value);
  const expected=message.subarray(Buffer.byteLength('paper:witness:latest-checkpoint:v1\0'));
  if(!expected.equals(response.body)||value.authority!==authority||
     value.subject!==subjectHash(owner,clientId))
   deny('R2_CERT_SCOPE_INVALID');
  if(!crypto.verify(null,message,key,response.signature))
   deny('R2_CERT_SIGNATURE_INVALID');
  return Object.freeze({
   subject:value.subject,revision:value.revision,
   sha256:value.sha256,authority:value.authority
  });
 }
 return Object.freeze({readVerified,releaseAccepted:false});
}

/** Test/offline attestor helper. Private signing key must never be
 * present in the Paper provider, R2 reader/writer or browser process. */
export function encodeSignedEpochCheckpoint({authority,subject,revision,sha256,
 privateKey}={}){
 const value={kind:'paper.witness.latest-checkpoint.v1',
  authority,subject,revision,sha256};
 const message=canonical(value);
 let key;
 try{key=crypto.createPrivateKey(privateKey)}
 catch{deny('R2_CERT_KEY_INVALID')}
 if(key.asymmetricKeyType!=='ed25519')deny('R2_CERT_KEY_INVALID');
 return Object.freeze({
  body:Buffer.from(message.subarray(
   Buffer.byteLength('paper:witness:latest-checkpoint:v1\0'))),
  signature:crypto.sign(null,message,key)
 });
}
