/**
 * NONACTIVATED independent custody-side one-way DENIAL head signer.
 *
 * A restored signer cache or Paper PostgreSQL must never determine the head.
 * For each fresh nonce, reconstruct a retained PRE-DENY from a separate
 * S3-compatible COMPLIANCE archive, sign BLOCKED only, then re-verify WORM
 * evidence before releasing the signature. NEVER sign ACTIVE, and never
 * interpret absence of a retained denial as permission.
 *
 * This library belongs in an independently administered service. No HTTP
 * endpoint, credentials, key export, production import or release switch.
 * Real account isolation, S3 guarantees, external KMS and deployment are
 * still mandatory. The signer is a fail-closed candidate, not certified
 * nonrewindable custody.
 */
import crypto from 'node:crypto';
import {inspectDisposablePortablePreDenyInventory} from
 '../backend/candidates/oauth-portable-pre-deny-inventory.mjs';

const HEX=/^[a-f0-9]{64}$/u;
const EPOCH=/^[1-9][0-9]{0,18}$/u;
const MAX_EPOCH=9223372036854775807n;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const NONCE=/^[A-Za-z0-9_-]{43}$/u;
const AUTHORITY=/^[a-z0-9._:-]{3,128}$/u;
const DOMAIN=Buffer.from('paper:oauth:pre-deny:head:v1\0');
function deny(code){
 const error=new Error('Independent retained-denial signer unavailable');
 error.code=code;throw error;
}
function gated(fixtureOnly){
 if(process.env.NODE_ENV!=='test'||fixtureOnly!==true||
    process.env.PAPER_INDEPENDENT_DENIAL_SIGNER_DISPOSABLE!=='confirmed'||
    process.env.PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE!=='confirmed')
  deny('DENIAL_SIGNER_NOT_RELEASED');
}
function publicKey(input){
 if(typeof input!=='string'&&!(input instanceof crypto.KeyObject))
  deny('DENIAL_SIGNER_KEY_UNSAFE');
 if(typeof input==='string'&&(Buffer.byteLength(input)>512||
  !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u.test(input)))
  deny('DENIAL_SIGNER_KEY_UNSAFE');
 let key;
 try{key=typeof input==='string'?crypto.createPublicKey(input):input}
 catch{deny('DENIAL_SIGNER_KEY_UNSAFE')}
 if(key.type!=='public'||key.asymmetricKeyType!=='ed25519')
  deny('DENIAL_SIGNER_KEY_UNSAFE');
 return key;
}
function receipt(x,subject){
 return x&&typeof x==='object'&&!Array.isArray(x)&&
  x.subject===subject&&typeof x.revision==='string'&&
  EPOCH.test(x.revision)&&BigInt(x.revision)<=MAX_EPOCH&&
  typeof x.grantSha256==='string'&&HEX.test(x.grantSha256)&&
  typeof x.receiptSha256==='string'&&HEX.test(x.receiptSha256)&&
  typeof x.operationId==='string'&&UUID.test(x.operationId)&&
  typeof x.versionId==='string'&&x.versionId.length>0&&
  x.versionId.length<=512&&x.versionId!=='null'&&
  [...x.versionId].every(ch=>ch.codePointAt(0)>32&&ch.codePointAt(0)!==127);
}
function certified(evidence,subject){
 if(!evidence||evidence.retainedDenialObserved!==true||
    evidence.absenceAuthorizes!==false||evidence.releaseAccepted!==false||
    !receipt(evidence.retainedDenial,subject))
  deny('DENIAL_SIGNER_IMMUTABLE_HEAD_MISSING');
 return evidence.retainedDenial;
}
function same(a,b){
 return ['subject','revision','grantSha256','receiptSha256',
  'operationId','versionId'].every(field=>a[field]===b[field]);
}
async function limited(task,ms){
 const controller=new AbortController();
 let timer;
 try{
  return await Promise.race([
   Promise.resolve().then(()=>task(controller.signal)),
   new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(Error('Signer deadline exceeded')),ms);
   })
  ]);
 }finally{clearTimeout(timer);controller.abort()}
}
export function createDisposableImmutableDenialHeadSigner({
 storage,signBytes,trustedPublicKey,authority,fixtureOnly=false,
 now=()=>Math.floor(Date.now()/1000),timeoutMs=25000
}={}){
 gated(fixtureOnly);
 if(!storage||typeof storage!=='object'||Array.isArray(storage)||
    typeof storage.reader?.send!=='function'||
    typeof signBytes!=='function'||typeof now!=='function'||
    !AUTHORITY.test(authority||'')||
    !Number.isSafeInteger(timeoutMs)||timeoutMs<500||timeoutMs>30000)
  deny('DENIAL_SIGNER_CONFIG_UNSAFE');
 const key=publicKey(trustedPublicKey);
 // Intentionally no local mutable head, PG client, Redis, Jena, owner WebID
 // or Paper control-plane cache. Every challenge is rebuilt from WORM.
 const read=subject=>limited(()=>inspectDisposablePortablePreDenyInventory({
  ...storage,subject,fixtureOnly:true
 }),timeoutMs);
 async function respond(challenge){
  gated(fixtureOnly);
  const fields=challenge&&typeof challenge==='object'&&!Array.isArray(challenge)?
   Object.keys(challenge).sort().join(','):'';
  if(!challenge||!['kind,nonce,subject','kind,nonce,signal,subject'].includes(fields)||
     (challenge.signal!==undefined&&(
      !challenge.signal||typeof challenge.signal.aborted!=='boolean'||
      challenge.signal.aborted||
      typeof challenge.signal.addEventListener!=='function'))||
     challenge.kind!=='paper.oauth.pre-deny.challenge.v1'||
     typeof challenge.subject!=='string'||!HEX.test(challenge.subject)||
     typeof challenge.nonce!=='string'||!NONCE.test(challenge.nonce))
   deny('DENIAL_SIGNER_CHALLENGE_UNSAFE');
  const subject=challenge.subject;
  let first;
  try{first=certified(await read(subject),subject)}
  catch(e){if(e?.code==='DENIAL_SIGNER_IMMUTABLE_HEAD_MISSING')throw e;
   deny('DENIAL_SIGNER_WORM_UNAVAILABLE')}
  let instant;
  try{instant=now()}catch{deny('DENIAL_SIGNER_CLOCK_UNSAFE')}
  if(!Number.isSafeInteger(instant)||instant<=0)
   deny('DENIAL_SIGNER_CLOCK_UNSAFE');
  const body=Buffer.from(JSON.stringify({
   kind:'paper.oauth.pre-deny.head.v1',
   authority,subject,grantSha256:first.grantSha256,
   revision:first.revision,operationId:first.operationId,
   receiptSha256:first.receiptSha256,nonce:challenge.nonce,issuedAt:instant
  }), 'utf8');
  if(body.length<170||body.length>1024)
   deny('DENIAL_SIGNER_FORMAT_UNSAFE');
  const signed=Buffer.concat([DOMAIN,body]);
  // A separately held Ed25519 signer/KMS receives canonical bytes only,
  // never S3 keys, user consent, private credentials or browser context.
  let signature;
  try{signature=await limited(signal=>signBytes(Buffer.from(signed),
   Object.freeze({signal})),timeoutMs)}
  catch{deny('DENIAL_SIGNER_KMS_UNAVAILABLE')}
  if(!(signature instanceof Uint8Array)||signature.length!==64||
     !crypto.verify(null,signed,key,signature))
   deny('DENIAL_SIGNER_SIGNATURE_INVALID');
  let second;
  try{second=certified(await read(subject),subject)}
  catch{deny('DENIAL_SIGNER_POST_SIGN_WORM_UNAVAILABLE')}
  if(!same(first,second))
   deny('DENIAL_SIGNER_HEAD_CHANGED');
  if(challenge.signal?.aborted)
   deny('DENIAL_SIGNER_CHALLENGE_ABORTED');
  // Only a DENIAL attestation. The consumer must verify the pinned key,
  // receipt/hash/operation, new random nonce and bounded issuance time.
  return Object.freeze({body,signature:Buffer.from(signature),
   denied:true,releaseAccepted:false});
 }
 return Object.freeze({respond,releaseAccepted:false});
}
