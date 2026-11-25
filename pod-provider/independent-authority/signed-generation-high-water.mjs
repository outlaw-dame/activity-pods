/**
 * NONACTIVATED independent monotonic generation high-water authority.
 *
 * The authority reconciles an immutable generation-journal observation with
 * a separately persisted compare-and-set checkpoint before asking an
 * external Ed25519/KMS adapter to sign. It has no local fallback checkpoint,
 * private key, OAuth session, account database or production endpoint.
 *
 * This protocol can detect an S3-compatible provider returning a coherent
 * stale journal prefix after the checkpoint has advanced. It cannot prove
 * that the injected checkpoint store, signer or operators are independent or
 * nonrewindable. Those are deployment properties and remain release gates.
 */
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';
import {setTimeout,clearTimeout} from 'node:timers';

const HEX=/^[a-f0-9]{64}$/u;
const REV=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const NONCE=/^[A-Za-z0-9_-]{43}$/u;
const AUTHORITY=/^[a-z0-9._:-]{3,128}$/u;
const KEY_ID=/^[A-Za-z0-9._:-]{3,128}$/u;
const ZERO='0'.repeat(64);
const MAX_OBJECT_VERSION_BYTES=512;
export const SIGNED_GENERATION_HIGH_WATER_DOMAIN=Buffer.from(
 'paper:oauth:generation-high-water:v1\0');
const BODY_FIELDS='authority,credentialEpoch,epochSubject,grantSha256,headSha256,issuedAt,keyEpoch,keyId,kind,nonce,oauthRevision,objectVersion,operationId,ownerProofSha256,preDenyReceiptSha256,previousSha256,saiRevision,scopeSha256,sequence,status,subject';
const CHECKPOINT_FIELDS=[
 'subject','epochSubject','sequence','status','headSha256','previousSha256',
 'grantSha256','scopeSha256','ownerProofSha256','oauthRevision',
 'credentialEpoch','saiRevision','operationId','preDenyReceiptSha256',
 'objectVersion'
];
const RECORD_FIELDS=[
 'kind','subject','epochSubject','sequence','status','grantSha256',
 'scopeSha256','ownerProofSha256','oauthRevision','credentialEpoch',
 'saiRevision','operationId','previousSha256','preDenyReceiptSha256'
];

function fail(code){
 const error=new Error('Independent signed generation high-water unavailable');
 error.code=code;throw error;
}
function gate(fixtureOnly){
 if(process.env.NODE_ENV!=='test'||fixtureOnly!==true||
    process.env.PAPER_OAUTH_SIGNED_HIGHWATER_DISPOSABLE!=='confirmed')
  fail('GENERATION_HIGH_WATER_NOT_RELEASED');
}
function revision(x){
 return typeof x==='string'&&REV.test(x)&&BigInt(x)<=MAX;
}
function version(x){
 return typeof x==='string'&&x.length>0&&x!=='null'&&
  Buffer.byteLength(x,'utf8')<=MAX_OBJECT_VERSION_BYTES&&
  [...x].every(ch=>{
   const point=ch.codePointAt(0);
   return point>32&&!(point>=127&&point<=159);
  });
}
function publicKey(input){
 if(typeof input!=='string'&&!(input instanceof crypto.KeyObject))
  fail('GENERATION_HIGH_WATER_KEY_UNSAFE');
 if(typeof input==='string'&&(Buffer.byteLength(input)>512||
  !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u.test(input)))
  fail('GENERATION_HIGH_WATER_KEY_UNSAFE');
 let key;
 try{key=typeof input==='string'?crypto.createPublicKey(input):input}
 catch{fail('GENERATION_HIGH_WATER_KEY_UNSAFE')}
 if(key.type!=='public'||key.asymmetricKeyType!=='ed25519')
  fail('GENERATION_HIGH_WATER_KEY_UNSAFE');
 return key;
}
function trustedKeys(entries){
 if(!Array.isArray(entries)||entries.length<1||entries.length>8)
  fail('GENERATION_HIGH_WATER_KEY_UNSAFE');
 const result=new Map();
 for(const entry of entries){
  if(!entry||typeof entry!=='object'||Array.isArray(entry)||
     !KEY_ID.test(entry.keyId||'')||!revision(entry.keyEpoch)||
     result.has(entry.keyId))
   fail('GENERATION_HIGH_WATER_KEY_UNSAFE');
  result.set(entry.keyId,Object.freeze({
   keyEpoch:entry.keyEpoch,publicKey:publicKey(entry.publicKey)
  }));
 }
 return result;
}
function recordFromInspection(evidence,subject){
 const head=evidence?.head;
 const source=head?.record;
 if(!source||typeof source!=='object'||Array.isArray(source)||
    Object.keys(source).sort().join(',')!==[...RECORD_FIELDS].sort().join(','))
  fail('GENERATION_HIGH_WATER_JOURNAL_INVALID');
 const record=Object.freeze(Object.fromEntries(
  RECORD_FIELDS.map(field=>[field,source[field]])));
 if(!evidence||evidence.releaseAccepted!==false||
    evidence.activeAuthorizes!==false||
    evidence.completeExternallyVerified!==false||
    evidence.operatorIndependenceVerified!==false||
    !Number.isSafeInteger(evidence.observedGenerations)||
    evidence.observedGenerations<1||evidence.observedGenerations>2||
    !head||record.kind!=='paper.oauth.authority-generation.v1'||
    record.subject!==subject||!HEX.test(record.epochSubject||'')||
    record.epochSubject===subject||!revision(record.sequence)||
    BigInt(record.sequence)!==BigInt(evidence.observedGenerations)||
    !['active','blocked'].includes(record.status)||
    evidence.retainedBlocked!==(record.status==='blocked')||
    (record.sequence==='1'&&record.status!=='active')||
    (record.sequence==='2'&&record.status!=='blocked')||
    !HEX.test(head.sha256||'')||!version(head.versionId)||
    !HEX.test(record.previousSha256||'')||
    !HEX.test(record.grantSha256||'')||!HEX.test(record.scopeSha256||'')||
    !HEX.test(record.ownerProofSha256||'')||
    record.ownerProofSha256===ZERO||!revision(record.oauthRevision)||
    !revision(record.credentialEpoch)||!revision(record.saiRevision)||
    !UUID.test(record.operationId||'')||
    !HEX.test(record.preDenyReceiptSha256||'')||
    (record.sequence==='1'&&record.previousSha256!==ZERO)||
    (record.status==='active'&&record.preDenyReceiptSha256!==ZERO)||
    (record.status==='blocked'&&record.preDenyReceiptSha256===ZERO))
  fail('GENERATION_HIGH_WATER_JOURNAL_INVALID');
 return Object.freeze({
  subject,epochSubject:record.epochSubject,sequence:record.sequence,
  status:record.status,headSha256:head.sha256,
  previousSha256:record.previousSha256,
  grantSha256:record.grantSha256,scopeSha256:record.scopeSha256,
  ownerProofSha256:record.ownerProofSha256,
  oauthRevision:record.oauthRevision,
  credentialEpoch:record.credentialEpoch,saiRevision:record.saiRevision,
  operationId:record.operationId,
  preDenyReceiptSha256:record.preDenyReceiptSha256,
  objectVersion:head.versionId
 });
}
function validCheckpoint(value,subject){
 if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.keys(value).sort().join(',')!==[...CHECKPOINT_FIELDS].sort().join(','))
  return false;
 try{return recordFromInspection({
  head:{record:{
   kind:'paper.oauth.authority-generation.v1',
   subject:value.subject,epochSubject:value.epochSubject,
   sequence:value.sequence,status:value.status,
   previousSha256:value.previousSha256,grantSha256:value.grantSha256,
   scopeSha256:value.scopeSha256,ownerProofSha256:value.ownerProofSha256,
   oauthRevision:value.oauthRevision,credentialEpoch:value.credentialEpoch,
   saiRevision:value.saiRevision,operationId:value.operationId,
   preDenyReceiptSha256:value.preDenyReceiptSha256
  },sha256:value.headSha256,versionId:value.objectVersion},
  observedGenerations:Number(value.sequence),
  retainedBlocked:value.status==='blocked',activeAuthorizes:false,
  completeExternallyVerified:false,operatorIndependenceVerified:false,
  releaseAccepted:false
 },subject)&&true}catch{return false}
}
function checkpointSnapshot(value,subject){
 if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.keys(value).sort().join(',')!==[...CHECKPOINT_FIELDS].sort().join(','))
  fail('GENERATION_HIGH_WATER_CHECKPOINT_INVALID');
 const snapshot=Object.freeze(Object.fromEntries(
  CHECKPOINT_FIELDS.map(field=>[field,value[field]])));
 if(!validCheckpoint(snapshot,subject))
  fail('GENERATION_HIGH_WATER_CHECKPOINT_INVALID');
 return snapshot;
}
function same(a,b){
 return CHECKPOINT_FIELDS.every(field=>a?.[field]===b?.[field]);
}
async function limited(task,timeoutMs){
 const controller=new globalThis.AbortController();
 let timer;
 try{return await Promise.race([
  Promise.resolve().then(()=>task(controller.signal)),
  new Promise((_,reject)=>{timer=setTimeout(
   ()=>reject(Error('Generation high-water dependency deadline exceeded')),
   timeoutMs)})
 ])}finally{clearTimeout(timer);controller.abort()}
}
function canonicalBody(checkpoint,{authority,keyId,keyEpoch,nonce,issuedAt}){
 return Buffer.from(JSON.stringify({
  kind:'paper.oauth.generation-high-water.v1',authority,keyId,keyEpoch,
  subject:checkpoint.subject,epochSubject:checkpoint.epochSubject,
  sequence:checkpoint.sequence,status:checkpoint.status,
  headSha256:checkpoint.headSha256,
  previousSha256:checkpoint.previousSha256,
  grantSha256:checkpoint.grantSha256,
  scopeSha256:checkpoint.scopeSha256,
  ownerProofSha256:checkpoint.ownerProofSha256,
  oauthRevision:checkpoint.oauthRevision,
  credentialEpoch:checkpoint.credentialEpoch,
  saiRevision:checkpoint.saiRevision,
  operationId:checkpoint.operationId,
  preDenyReceiptSha256:checkpoint.preDenyReceiptSha256,
  objectVersion:checkpoint.objectVersion,nonce,issuedAt
 }),'utf8');
}
function challenge(value){
 return value&&typeof value==='object'&&!Array.isArray(value)&&
  Object.keys(value).sort().join(',')==='kind,nonce,subject'&&
  value.kind==='paper.oauth.generation-high-water.challenge.v1'&&
  HEX.test(value.subject||'')&&NONCE.test(value.nonce||'');
}
function parseBody(body){
 if(!Buffer.isBuffer(body)||body.length<500||body.length>2048)
  fail('GENERATION_HIGH_WATER_FORMAT_INVALID');
 let value;
 try{value=JSON.parse(body.toString('utf8'))}
 catch{fail('GENERATION_HIGH_WATER_FORMAT_INVALID')}
 if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.keys(value).sort().join(',')!==BODY_FIELDS)
  fail('GENERATION_HIGH_WATER_FORMAT_INVALID');
 const checkpoint=Object.fromEntries(CHECKPOINT_FIELDS.map(k=>[k,value[k]]));
 if(value.kind!=='paper.oauth.generation-high-water.v1'||
    !AUTHORITY.test(value.authority||'')||!KEY_ID.test(value.keyId||'')||
    !revision(value.keyEpoch)||!NONCE.test(value.nonce||'')||
    !Number.isSafeInteger(value.issuedAt)||value.issuedAt<=0||
    !validCheckpoint(checkpoint,value.subject))
  fail('GENERATION_HIGH_WATER_FORMAT_INVALID');
 const canonical=canonicalBody(checkpoint,value);
 if(canonical.length!==body.length||!crypto.timingSafeEqual(canonical,body))
  fail('GENERATION_HIGH_WATER_CANONICAL_INVALID');
 return Object.freeze({...value,checkpoint:Object.freeze(checkpoint)});
}

export function verifyDisposableSignedGenerationHighWater({
 reply,nonce,expected,authority,trustedPublicKeys,minimumKeyEpoch='1',
 now=()=>Math.floor(Date.now()/1000),fixtureOnly=false
}={}){
 gate(fixtureOnly);
 const keys=trustedKeys(trustedPublicKeys);
 let expectedCheckpoint;
 try{expectedCheckpoint=checkpointSnapshot(expected,expected?.subject)}
 catch{fail('GENERATION_HIGH_WATER_VERIFY_CONFIG_INVALID')}
 if(!AUTHORITY.test(authority||'')||!NONCE.test(nonce||'')||
    !revision(minimumKeyEpoch)||typeof now!=='function'||
    !Buffer.isBuffer(reply?.signature)||reply.signature.length!==64)
  fail('GENERATION_HIGH_WATER_VERIFY_CONFIG_INVALID');
 const parsed=parseBody(reply.body);
 const trusted=keys.get(parsed.keyId);
 if(parsed.authority!==authority||parsed.nonce!==nonce||!trusted||
    parsed.keyEpoch!==trusted.keyEpoch||
    BigInt(parsed.keyEpoch)<BigInt(minimumKeyEpoch)||
    !same(parsed.checkpoint,expectedCheckpoint))
  fail('GENERATION_HIGH_WATER_SCOPE_INVALID');
 if(!crypto.verify(null,
   Buffer.concat([SIGNED_GENERATION_HIGH_WATER_DOMAIN,reply.body]),
   trusted.publicKey,reply.signature))
  fail('GENERATION_HIGH_WATER_SIGNATURE_INVALID');
 let instant;
 try{instant=now()}catch{fail('GENERATION_HIGH_WATER_CLOCK_INVALID')}
 if(!Number.isSafeInteger(instant)||instant<=0||
    Math.abs(instant-parsed.issuedAt)>15)
  fail('GENERATION_HIGH_WATER_CLOCK_INVALID');
 return Object.freeze({...parsed.checkpoint,keyId:parsed.keyId,
  keyEpoch:parsed.keyEpoch,issuedAt:parsed.issuedAt,
  externallySigned:true,releaseAccepted:false});
}

export function createDisposableSignedGenerationHighWaterAuthority({
 inspectJournal,checkpointStore,signBytes,trustedPublicKeys,
 authority,keyId,keyEpoch,now=()=>Math.floor(Date.now()/1000),
 timeoutMs=5000,fixtureOnly=false
}={}){
 gate(fixtureOnly);
 const keys=trustedKeys(trustedPublicKeys);
 const signingKey=keys.get(keyId);
 if(typeof inspectJournal!=='function'||
    typeof checkpointStore?.read!=='function'||
    typeof checkpointStore?.compareAndSet!=='function'||
    checkpointStore.read===checkpointStore.compareAndSet||
    typeof signBytes!=='function'||!AUTHORITY.test(authority||'')||
    !signingKey||signingKey.keyEpoch!==keyEpoch||
    typeof now!=='function'||!Number.isSafeInteger(timeoutMs)||
    timeoutMs<250||timeoutMs>30000)
  fail('GENERATION_HIGH_WATER_CONFIGURATION_INVALID');
 async function inspect(subject){
  try{return recordFromInspection(await limited(
   signal=>inspectJournal(Object.freeze({subject,signal})),timeoutMs),subject)}
  catch(e){if(e?.code?.startsWith('GENERATION_HIGH_WATER_'))throw e;
   return fail('GENERATION_HIGH_WATER_JOURNAL_UNAVAILABLE')}
 }
 async function read(subject){
  let value;
  try{value=await limited(
   signal=>checkpointStore.read(Object.freeze({subject,signal})),timeoutMs)}
  catch{fail('GENERATION_HIGH_WATER_CHECKPOINT_UNAVAILABLE')}
  if(value===null)return null;
  return checkpointSnapshot(value,subject);
 }
 async function reconcile(observed){
  const prior=await read(observed.subject);
  if(prior&&BigInt(prior.sequence)>BigInt(observed.sequence))
   fail('GENERATION_HIGH_WATER_JOURNAL_REWOUND');
  if(prior&&BigInt(prior.sequence)===BigInt(observed.sequence)){
   if(!same(prior,observed))fail('GENERATION_HIGH_WATER_FORK');
   return prior;
  }
  if((!prior&&observed.sequence!=='1')||
     (prior&&(BigInt(observed.sequence)!==BigInt(prior.sequence)+1n||
      observed.previousSha256!==prior.headSha256)))
   fail('GENERATION_HIGH_WATER_GAP');
  try{
   await limited(signal=>checkpointStore.compareAndSet(Object.freeze({
    subject:observed.subject,expected:prior,
    desired:observed,signal
   })),timeoutMs);
  }catch{
   // A timeout, conflict or lost ACK is ambiguous. Never retry the CAS;
   // reconcile from the independently persisted checkpoint below.
  }
  const after=await read(observed.subject);
  if(!same(after,observed))
   fail('GENERATION_HIGH_WATER_COMMIT_AMBIGUOUS');
  return after;
 }
 async function respond(value){
  gate(fixtureOnly);
  if(!challenge(value))fail('GENERATION_HIGH_WATER_CHALLENGE_INVALID');
  const first=await inspect(value.subject);
  const checkpoint=await reconcile(first);
  const second=await inspect(value.subject);
  if(!same(first,second)||!same(checkpoint,second))
   fail('GENERATION_HIGH_WATER_JOURNAL_CHANGED');
  let issuedAt;
  try{issuedAt=now()}catch{fail('GENERATION_HIGH_WATER_CLOCK_INVALID')}
  if(!Number.isSafeInteger(issuedAt)||issuedAt<=0)
   fail('GENERATION_HIGH_WATER_CLOCK_INVALID');
  const body=canonicalBody(checkpoint,{authority,keyId,keyEpoch,
   nonce:value.nonce,issuedAt});
  let signature;
  try{signature=await limited(signal=>signBytes(
   Buffer.concat([SIGNED_GENERATION_HIGH_WATER_DOMAIN,body]),
   Object.freeze({keyId,keyEpoch,signal})),timeoutMs)}
  catch{fail('GENERATION_HIGH_WATER_SIGNER_UNAVAILABLE')}
  if(!(signature instanceof Uint8Array)||signature.length!==64||
     !crypto.verify(null,
      Buffer.concat([SIGNED_GENERATION_HIGH_WATER_DOMAIN,body]),
      signingKey.publicKey,signature))
   fail('GENERATION_HIGH_WATER_SIGNATURE_INVALID');
  const finalJournal=await inspect(value.subject);
  const finalCheckpoint=await read(value.subject);
  if(!same(second,finalJournal)||!same(checkpoint,finalCheckpoint))
   fail('GENERATION_HIGH_WATER_CHANGED_DURING_SIGN');
  return Object.freeze({body,signature:Buffer.from(signature),
   releaseAccepted:false});
 }
 return Object.freeze({respond,releaseAccepted:false});
}
