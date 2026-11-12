'use strict';

/**
 * NON-ACTIVATED candidate for cross-Moleculer-node native SAI owner proofs.
 * The trusted auth-agent issues a short-lived random capability only after
 * Solid owner authentication. A separate SAI replica checks Redis + HMAC,
 * never ctx.meta alone. This module has no implicit connection or HTTP route.
 *
 * Redis ACLs must restrict the namespace to dedicated trusted credentials.
 * The HMAC key must be a separately provisioned >=256-bit secret, not the
 * OIDC cookie key, an application token, or a Fuseki password.
 */
const crypto=require('node:crypto');
const PROOF_KEY='apodsNativeSaiOwnerProof';
const PREFIX='paper:sai:owner:';
const MAX_IN_FLIGHT=4096;
const TTL_MS=120000;
const HEX=/^[a-f0-9]{64}$/u;
const TOKEN=/^[a-zA-Z0-9_-]{43}$/u;

function fail(code) {
  const e=new Error('SAI owner authorization could not be established');
  e.code=code;
  throw e;
}
function canonicalHttps(input) {
  if(typeof input!=='string'||input.length>2048||input.length<8){
    fail('SAI_DISTRIBUTED_SCOPE_INVALID');
  }
  let u;
  try{u=new URL(input)}catch{fail('SAI_DISTRIBUTED_SCOPE_INVALID')}
  if(u.protocol!=='https:'||u.href!==input||u.username||u.password||
      u.search||u.hash||!u.hostname){
    fail('SAI_DISTRIBUTED_SCOPE_INVALID');
  }
  return input;
}
function validContext(ctx,owner,app) {
  canonicalHttps(owner);
  canonicalHttps(app);
  if(!ctx||!ctx.meta||typeof ctx.meta!=='object'||
      typeof ctx.requestID!=='string'||ctx.requestID.length===0||
      ctx.requestID.length>256) fail('SAI_DISTRIBUTED_SCOPE_INVALID');
}
function sign(key,nonce,requestId,owner,app) {
  // Array serialization unambiguously separates fields, including symbols
  // that might occur in a valid owner URI or Moleculer request ID.
  return crypto.createHmac('sha256',key)
    .update(JSON.stringify([nonce,requestId,owner,app]))
    .digest('hex');
}
function createSaiDistributedOwnerProof({redis,secret,clock=Date.now,
  maxInFlight=MAX_IN_FLIGHT,ttlMs=TTL_MS}={}) {
  if(!redis||typeof redis.get!=='function'||typeof redis.set!=='function'||
      typeof redis.del!=='function') fail('SAI_DISTRIBUTED_STORE_REQUIRED');
  const key=Buffer.isBuffer(secret)?Buffer.from(secret):
    typeof secret==='string'&&TOKEN.test(secret)?Buffer.from(secret,'base64url'):null;
  if(!key||key.length<32||key.length>64)fail('SAI_DISTRIBUTED_SECRET_REQUIRED');
  if(!Number.isSafeInteger(ttlMs)||ttlMs<1000||ttlMs>120000||
      !Number.isSafeInteger(maxInFlight)||maxInFlight<1||maxInFlight>MAX_IN_FLIGHT||
      typeof clock!=='function')fail('SAI_DISTRIBUTED_CONFIG_INVALID');
  // Only issuers retain entries, bounded per Node process. Verifier workers
  // have no growing local cache. Redis TTL bounds cross-process state.
  const issued=new Map();
  function reclaimExpired(){
    if(issued.size<maxInFlight)return;
    const now=clock();
    for(const [nonce,until] of issued)if(until<=now)issued.delete(nonce);
  }
  async function issue(ctx,{owner,app}={}){
    validContext(ctx,owner,app);
    if(ctx.meta.webId!==owner||ctx.meta.impersonatedUser||
        Object.prototype.hasOwnProperty.call(ctx.meta,PROOF_KEY)){
      fail('SAI_DISTRIBUTED_ISSUER_NOT_OWNER');
    }
    reclaimExpired();
    if(issued.size>=maxInFlight)fail('SAI_DISTRIBUTED_BUSY');
    const nonce=crypto.randomBytes(32).toString('base64url');
    const redisKey=PREFIX+nonce;
    const mac=sign(key,nonce,ctx.requestID,owner,app);
    const until=clock()+ttlMs;
    // Reserve BEFORE Redis I/O, otherwise many simultaneous issues can
    // exceed the local cap while awaiting the same external connection.
    issued.set(nonce,until);
    try{
      const ok=await redis.set(redisKey,mac,'PX',ttlMs,'NX');
      if(ok!=='OK')fail('SAI_DISTRIBUTED_COLLISION');
      ctx.meta[PROOF_KEY]=nonce;
    }catch{
      issued.delete(nonce);
      fail('SAI_DISTRIBUTED_STORE_UNAVAILABLE');
    }
    let finished=false;
    return async()=>{
      if(finished)return;
      finished=true;
      issued.delete(nonce);
      if(ctx.meta[PROOF_KEY]===nonce)delete ctx.meta[PROOF_KEY];
      try{await redis.del(redisKey)}
      catch{fail('SAI_DISTRIBUTED_STORE_UNAVAILABLE')}
    };
  }
  async function verify(ctx,{owner,app}={}){
    validContext(ctx,owner,app);
    const nonce=ctx.meta[PROOF_KEY];
    if(typeof nonce!=='string'||!TOKEN.test(nonce))return false;
    const expected=sign(key,nonce,ctx.requestID,owner,app);
    let stored;
    try{stored=await redis.get(PREFIX+nonce)}
    catch{fail('SAI_DISTRIBUTED_STORE_UNAVAILABLE')}
    if(typeof stored!=='string'||!HEX.test(stored))return false;
    // Constant-time digest comparison even when Redis contains a forged or
    // stale value. The owner/app/requestID never appear in the Redis key.
    return crypto.timingSafeEqual(Buffer.from(expected,'hex'),
      Buffer.from(stored,'hex'));
  }
  function inFlight(){return issued.size}
  return Object.freeze({issue,verify,inFlight});
}
module.exports={createSaiDistributedOwnerProof,PROOF_KEY,TTL_MS,MAX_IN_FLIGHT};
