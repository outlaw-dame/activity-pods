'use strict';

/**
 * Disposable ordinary-provider -> restricted PostgreSQL account coordinator.
 * The provider authenticates a genuine approved-app grant first; the HMAC
 * authenticates its decision to a separate worker, not a client-held grant.
 *
 * No PostgreSQL DSN, Ed25519 issuer key, or Jena admin password is needed
 * by the ordinary provider. Production remains source-controlled NO-GO.
 */
const crypto = require('node:crypto');
const {validateTicket} = require('./atproto-dataset-admin-delegation');

const ENDPOINT = 'http://127.0.0.1:3043/v1/reserve';
const CONSUME_ENDPOINT = 'http://127.0.0.1:3043/v1/consume';
const DOMAIN = 'activitypods:account-coordinator:v1\0';
const KEYS = Object.freeze([
  'version','appScope','username','idempotencyKey',
  'requestFingerprint','dailyLimit','issuedAtMs','nonce'
]);
const FORBIDDEN_ENV = Object.freeze([
  'ATPROTO_REPO_PROOF_DSN','DATASET_ADMIN_FUSEKI_PASSWORD',
  'DATASET_ADMIN_SIGNER_PRIVATE_KEY','ACCOUNT_ISSUER_DSN',
  'ACCOUNT_ISSUER_SIGNING_PEM_B64','ACCOUNT_COORDINATOR_WORKER_DSN',
  'SEMAPPS_JENA_PASSWORD','PGPASSWORD'
]);
const USERNAME = /^claimtest-[a-z0-9]{8,24}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const KEY = /^[A-Za-z0-9._:-]{8,128}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function reject(code) {
  const error = new Error('Account coordination is not available');
  error.code = code;
  error.status = code === 'ACCOUNT_COORDINATOR_CONFLICT' ? 409 : 503;
  throw error;
}
function assertDisposable(env = process.env) {
  if (env.NODE_ENV !== 'test' ||
      env.APODS_ACCOUNT_COORDINATOR_DISPOSABLE !== 'confirmed' ||
      env.APODS_ACCOUNT_RESERVATION_DISPOSABLE !== 'confirmed' ||
      env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
      env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE !== 'confirmed' ||
      env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE !== 'confirmed' ||
      env.FUSEKI_ISOLATION_URL !== 'http://127.0.0.1:3041' ||
      FORBIDDEN_ENV.some(key => typeof env[key] === 'string' && env[key].length)) {
    reject('ACCOUNT_COORDINATOR_NOT_RELEASED');
  }
}
function parseSecret(secret) {
  if (typeof secret !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/u.test(secret)) reject('ACCOUNT_COORDINATOR_AUTH_UNAVAILABLE');
  const bytes = Buffer.from(secret, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== secret)
    reject('ACCOUNT_COORDINATOR_AUTH_UNAVAILABLE');
  return bytes;
}
function isExact(value, keys) {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === keys.length &&
    keys.every((key, index) => Object.keys(value)[index] === key);
}
function validateMessage(message, now = Date.now()) {
  if (!isExact(message, KEYS) || message.version !== 1 ||
      !HASH.test(message.appScope) || !USERNAME.test(message.username) ||
      !KEY.test(message.idempotencyKey) || !HASH.test(message.requestFingerprint) ||
      !Number.isInteger(message.dailyLimit) ||
      message.dailyLimit < 1 || message.dailyLimit > 100000 ||
      !Number.isSafeInteger(message.issuedAtMs) ||
      Math.abs(now - message.issuedAtMs) > 30000 ||
      typeof message.nonce !== 'string' || !UUID.test(message.nonce)) {
    reject('ACCOUNT_COORDINATOR_REQUEST_INVALID');
  }
}
function computeMac(secret, domain, raw) {
  if (!['client','issuer','issuer-response','worker-response',
      'consume','consume-response'].includes(domain) || typeof raw !== 'string')
    reject('ACCOUNT_COORDINATOR_REQUEST_INVALID');
  return crypto.createHmac('sha256', parseSecret(secret))
    .update(DOMAIN + domain + '\0', 'utf8')
    .update(raw, 'utf8').digest('base64url');
}
function verifyMac(secret, domain, raw, mac) {
  if (typeof mac !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(mac)) return false;
  const expected = computeMac(secret,domain,raw);
  return crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(mac));
}
async function boundedResponse(response) {
  if (!response?.body?.getReader) reject('ACCOUNT_COORDINATOR_RESPONSE_INVALID');
  const reader = response.body.getReader();
  const parts=[]; let size=0;
  try {
    for (;;) {
      const {done,value}=await reader.read();
      if (done) break;
      size+=value.byteLength;
      if (size>2048) reject('ACCOUNT_COORDINATOR_RESPONSE_INVALID');
      parts.push(Buffer.from(value));
    }
  } finally {
    await reader.cancel().catch(()=>{});
    reader.releaseLock();
  }
  const raw=Buffer.concat(parts, size).toString('utf8');
  try {return {raw,value:JSON.parse(raw)};}
  catch { reject('ACCOUNT_COORDINATOR_RESPONSE_INVALID'); }
}
async function reserveCoordinatedDataset({
  grant, username, appClientId, env=process.env,
  fetchImpl=globalThis.fetch, now=Date.now()
} = {}) {
  assertDisposable(env);
  if (!grant || grant.allowed !== true || grant.approvedApp !== true ||
      grant.verifiedUser !== true || grant.capabilityId !== 'provider.account.provisioning' ||
      grant.appClientId !== appClientId || grant.username !== username ||
      !HASH.test(grant.requestFingerprint || '') ||
      !KEY.test(grant.idempotencyKey || '') ||
      !Number.isInteger(grant.dailyLimit) ||
      !USERNAME.test(username) || typeof appClientId !== 'string' ||
      appClientId.length < 1 || appClientId.length > 256 ||
      typeof fetchImpl !== 'function') reject('ACCOUNT_COORDINATOR_REQUEST_INVALID');
  const message = {
    version: 1,
    appScope: crypto.createHash('sha256')
      .update('activitypods:approved-app:v1\0').update(appClientId).digest('hex'),
    username,
    idempotencyKey: grant.idempotencyKey,
    requestFingerprint: grant.requestFingerprint,
    dailyLimit: grant.dailyLimit,
    issuedAtMs: now,
    nonce: crypto.randomUUID()
  };
  validateMessage(message,now);
  const raw=JSON.stringify(message);
  if (Buffer.byteLength(raw)>2048) reject('ACCOUNT_COORDINATOR_REQUEST_INVALID');
  const signature=computeMac(env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,'client',raw);
  const ctl=new AbortController();
  const timeout=setTimeout(()=>ctl.abort(),6000);
  try{
    const response=await fetchImpl(ENDPOINT,{
      method:'POST',redirect:'manual',signal:ctl.signal,
      headers:{'content-type':'application/json','x-paper-auth':signature},
      body:raw
    });
    if(response.status!==200){
      await response.body?.cancel?.().catch(()=>{});
      reject(response.status===409 ?
        'ACCOUNT_COORDINATOR_CONFLICT' : 'ACCOUNT_COORDINATOR_UNAVAILABLE');
    }
    const body=await boundedResponse(response);
    const data=body.value;
    if (!verifyMac(env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,
      'worker-response',body.raw,response.headers?.get('x-paper-auth'))) {
      reject('ACCOUNT_COORDINATOR_RESPONSE_INVALID');
    }
    if(!isExact(data,['ticket','admission','requestSha256','nonce']) ||
        data.requestSha256!==crypto.createHash('sha256')
          .update(raw,'utf8').digest('hex') ||
        data.nonce!==message.nonce ||
        !isExact(data.admission,[
          'appScope','username','idempotencyKey','requestFingerprint','reservationId'
        ]) ||
        data.admission.appScope!==message.appScope ||
        data.admission.username!==username ||
        data.admission.idempotencyKey!==message.idempotencyKey ||
        data.admission.requestFingerprint!==message.requestFingerprint ||
        !UUID.test(data.admission.reservationId) ||
        !isExact(data.ticket,['claim','signature']) ||
        !isExact(data.ticket.claim,[
          'version','issuer','audience','dataset','ownerWebid',
          'reservationId','nonce','issuedAtMs','expiresAtMs'
        ]) ||
        data.ticket.claim.dataset!==username ||
        data.ticket.claim.reservationId!==data.admission.reservationId ||
        data.ticket.claim.ownerWebid!=='https://paper.example.org/users/'+username ||
        typeof data.ticket.signature!=='string' ||
        !/^[A-Za-z0-9_-]{86}$/u.test(data.ticket.signature)) {
      reject('ACCOUNT_COORDINATOR_RESPONSE_INVALID');
    }
    // Same strict schema/scope/expiry admission as the real downstream
    // dataset-provisioning service. The Ed25519 signature is independently
    // verified by the separate dataset administrator.
    try{ validateTicket(username,data.ticket,now); }
    catch{ reject('ACCOUNT_COORDINATOR_RESPONSE_INVALID'); }
    return Object.freeze({ticket:data.ticket,admission:data.admission});
  }catch(e){
    if(typeof e?.code==='string' && e.code.startsWith('ACCOUNT_COORDINATOR_')) throw e;
    reject('ACCOUNT_COORDINATOR_UNAVAILABLE');
  }finally{clearTimeout(timeout);}
}
async function consumeCoordinatedSignup({
  ticket,admission,dataset,env=process.env,
  fetchImpl=globalThis.fetch,now=Date.now()
}={}){
  assertDisposable(env);
  if (!isExact(admission,[
      'appScope','username','idempotencyKey','requestFingerprint','reservationId'
    ]) || !HASH.test(admission.appScope) ||
      !KEY.test(admission.idempotencyKey) ||
      !HASH.test(admission.requestFingerprint) ||
      !UUID.test(admission.reservationId) ||
      !USERNAME.test(dataset) || admission.username!==dataset ||
      ticket?.claim?.reservationId!==admission.reservationId ||
      typeof fetchImpl!=='function') {
    reject('ACCOUNT_COORDINATOR_INVOCATION_INVALID');
  }
  try{validateTicket(dataset,ticket,now);}
  catch{reject('ACCOUNT_COORDINATOR_INVOCATION_INVALID');}
  const message={
    version:1,appScope:admission.appScope,username:dataset,
    idempotencyKey:admission.idempotencyKey,
    requestFingerprint:admission.requestFingerprint,
    reservationId:admission.reservationId,
    ticket,issuedAtMs:now,nonce:crypto.randomUUID()
  };
  const raw=JSON.stringify(message);
  if(Buffer.byteLength(raw,'utf8')>2048)reject('ACCOUNT_COORDINATOR_INVOCATION_INVALID');
  const mac=computeMac(env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,'consume',raw);
  const ctl=new AbortController();
  const timer=setTimeout(()=>ctl.abort(),6000);
  try{
    const response=await fetchImpl(CONSUME_ENDPOINT,{
      method:'POST',redirect:'manual',signal:ctl.signal,
      headers:{'content-type':'application/json','x-paper-auth':mac},
      body:raw
    });
    if(response.status!==200){
      await response.body?.cancel?.().catch(()=>{});
      reject(response.status===409 ?
        'ACCOUNT_COORDINATOR_INVOCATION_ALREADY_CLAIMED':
        'ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED');
    }
    const {raw:body,value}=await boundedResponse(response);
    if(!verifyMac(env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,
      'consume-response',body,response.headers?.get('x-paper-auth')) ||
      !isExact(value,[
        'admitted','requestSha256','reservationId','nonce'
      ]) || value.admitted!==true ||
      value.requestSha256!==crypto.createHash('sha256')
        .update(raw,'utf8').digest('hex') ||
      value.reservationId!==admission.reservationId ||
      value.nonce!==message.nonce) {
      reject('ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED');
    }
    return Object.freeze({admitted:true});
  }catch(e){
    if(typeof e?.code==='string'&&e.code.startsWith('ACCOUNT_COORDINATOR_'))throw e;
    reject('ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED');
  }finally{clearTimeout(timer);}
}

module.exports={
  assertDisposable,parseSecret,validateMessage,
  computeMac,verifyMac,reserveCoordinatedDataset,
  consumeCoordinatedSignup
};
