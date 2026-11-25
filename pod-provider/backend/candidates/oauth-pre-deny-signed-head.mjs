/**
 * NONACTIVATED. Independently challenge-signed latest pre-denial head.
 * A signature prevents response replay, but ONLY an independently operated,
 * nonrewindable signer + independently archived head prevents signer PITR.
 * No private signer material is accepted, stored or returned here.
 */
import crypto from 'node:crypto';

const SHA=/^[0-9a-f]{64}$/u;
const REV=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const NONCE=/^[A-Za-z0-9_-]{43}$/u;
const AUTHORITY=/^[a-z0-9._:-]{3,128}$/u;
const DOMAIN=Buffer.from('paper:oauth:pre-deny:head:v1\0');
const FIELDS='authority,grantSha256,issuedAt,kind,nonce,operationId,receiptSha256,revision,subject';
function deny(code){
 const e=new Error('Independent pre-denial head unavailable');
 e.code=code;
 throw e;
}
function gate(){
 if(process.env.NODE_ENV!=='test'||
    process.env.PAPER_OAUTH_PRE_DENY_DISPOSABLE!=='confirmed'||
    process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE!=='confirmed')
  deny('PRE_DENY_HEAD_NOT_RELEASED');
}
function epoch(v){
 return typeof v==='string'&&REV.test(v)&&BigInt(v)<=MAX;
}
function validExpected(e){
 return e&&typeof e==='object'&&!Array.isArray(e)&&
  SHA.test(e.subject||'')&&SHA.test(e.grantSha256||'')&&
  SHA.test(e.receiptSha256||'')&&epoch(e.revision)&&
  UUID.test(e.operationId||'');
}
export function createDisposablePreDenySignedHead({
 readHead,trustedPublicKey,authority,
 now=()=>Math.floor(Date.now()/1000),timeoutMs=2500,
 fixtureOnly=false
}={}){
 gate();
 if(fixtureOnly!==true||typeof readHead!=='function'||
    typeof now!=='function'||!AUTHORITY.test(authority||'')||
    !Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>5000)
  deny('PRE_DENY_HEAD_CONFIG_INVALID');
 if(typeof trustedPublicKey==='string'&&(
    Buffer.byteLength(trustedPublicKey)>512||
    !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u.test(trustedPublicKey)))
  deny('PRE_DENY_HEAD_KEY_UNSAFE');
 if(typeof trustedPublicKey!=='string'&&
    !(trustedPublicKey instanceof crypto.KeyObject))
  deny('PRE_DENY_HEAD_KEY_UNSAFE');
 let key;
 try{key=typeof trustedPublicKey==='string'?
   crypto.createPublicKey(trustedPublicKey):trustedPublicKey}
 catch{deny('PRE_DENY_HEAD_KEY_UNSAFE')}
 if(key.type!=='public'||key.asymmetricKeyType!=='ed25519')
  deny('PRE_DENY_HEAD_KEY_UNSAFE');
 async function assertDenied(expected){
  gate();
  if(!validExpected(expected))deny('PRE_DENY_HEAD_SCOPE_INVALID');
  const nonce=crypto.randomBytes(32).toString('base64url');
  const controller=new AbortController();
  let timer,reply;
  try{
   reply=await Promise.race([
    Promise.resolve().then(()=>readHead(Object.freeze({
     kind:'paper.oauth.pre-deny.challenge.v1',
     subject:expected.subject,nonce,signal:controller.signal
    }))),
    new Promise((_,reject)=>{timer=setTimeout(
     ()=>reject(Error('Independent latest head timed out')),timeoutMs)})
   ]);
  }catch{deny('PRE_DENY_HEAD_UNAVAILABLE')}
  finally{clearTimeout(timer);controller.abort()}
  if(!Buffer.isBuffer(reply?.body)||!Buffer.isBuffer(reply?.signature)||
     reply.body.length<170||reply.body.length>1024||
     reply.signature.length!==64)
   deny('PRE_DENY_HEAD_FORMAT_INVALID');
  if(!crypto.verify(null,Buffer.concat([DOMAIN,reply.body]),
      key,reply.signature))
   deny('PRE_DENY_HEAD_SIGNATURE_INVALID');
  let data;
  try{data=JSON.parse(reply.body.toString('utf8'))}
  catch{deny('PRE_DENY_HEAD_FORMAT_INVALID')}
  if(!data||Array.isArray(data)||
     Object.keys(data).sort().join(',')!==FIELDS||
     data.kind!=='paper.oauth.pre-deny.head.v1'||
     data.authority!==authority||data.subject!==expected.subject||
     data.grantSha256!==expected.grantSha256||
     data.receiptSha256!==expected.receiptSha256||
     data.revision!==expected.revision||
     data.operationId!==expected.operationId||
     !NONCE.test(data.nonce||'')||data.nonce!==nonce||
     !Number.isSafeInteger(data.issuedAt)||data.issuedAt<=0)
   deny('PRE_DENY_HEAD_SCOPE_INVALID');
  const canonical=Buffer.from(JSON.stringify({
   kind:data.kind,authority:data.authority,subject:data.subject,
   grantSha256:data.grantSha256,revision:data.revision,
   operationId:data.operationId,receiptSha256:data.receiptSha256,
   nonce:data.nonce,issuedAt:data.issuedAt
  }),'utf8');
  if(!crypto.timingSafeEqual(canonical,reply.body))
   deny('PRE_DENY_HEAD_CANONICAL_INVALID');
  let timestamp;
  try{timestamp=now()}catch{deny('PRE_DENY_HEAD_CLOCK_INVALID')}
  if(!Number.isSafeInteger(timestamp)||timestamp<=0||
     Math.abs(data.issuedAt-timestamp)>20)
   deny('PRE_DENY_HEAD_CLOCK_INVALID');
  return true;
 }
 return Object.freeze({assertDenied,releaseAccepted:false});
}
