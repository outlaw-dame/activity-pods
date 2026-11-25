'use strict';

// NONACTIVATED first-grant coordinator. Never a production authorization
// service. Only the authenticated enrollment journal can issue the initial
// PG epoch; independent witness readback must precede Redis persistence.
// General post-enrollment grant/reapproval/revocation needs an independent
// pre-transition denial-intent protocol and is deliberately NOT supported.
const crypto=require('node:crypto');
const {KEY_PREFIX,digest,sessionKey,SESSION_ID,
  UPSERT_CONSENT_IF_SESSION_LIVE}=require('../utils/oauth-browser-session-policy');
const {consentKey}=require('../utils/oauth-refresh-atomic-policy');
const {SCOPE}=require('./oauth-initial-owner-epoch-issuer.cjs');
const GRANT=/^[A-Za-z0-9_-]{32}$/u;
const REVISION='1';
const TTL=60*60*24*30;

function deny(code){
  const e=new Error('Initial owner-bound OAuth consent not authorized');
  e.code=code;
  throw e;
}
function https(value){
  if(typeof value!=='string'||value.length<8||value.length>2048)return false;
  try{
    const u=new URL(value);
    return u.protocol==='https:'&&!!u.hostname&&!u.username&&!u.password&&
      !u.search&&!u.hash&&u.href===value;
  }catch{return false}
}
function gate(){
  if(process.env.NODE_ENV!=='test'||
     process.env.PAPER_ACCOUNTS_DISPOSABLE!=='confirmed'||
     process.env.PAPER_JOURNAL_BOUND_SAI_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_PG_EPOCH_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_WITNESS_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_WORM_HIGHWATER_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_WORM_READBACK_DISPOSABLE!=='confirmed')
    deny('OWNER_INITIAL_CONSENT_NOT_RELEASED');
}
function validOwner(x) {
  return x&&typeof x==='object'&&!Array.isArray(x)&&
    https(x.canonicalAccountId)&&typeof x.sessionId==='string'&&
    SESSION_ID.test(x.sessionId)&&
    Buffer.isBuffer(x.enrollmentTokenHash)&&x.enrollmentTokenHash.length===32;
}
function sameOwner(a,b){
  return validOwner(a)&&validOwner(b)&&
    a.canonicalAccountId===b.canonicalAccountId&&
    a.sessionId===b.sessionId&&
    crypto.timingSafeEqual(a.enrollmentTokenHash,b.enrollmentTokenHash);
}
// Bound dependency waits. If a non-idempotent call times out it may still
// commit later; that is an ambiguous result and MUST NOT be retried.
async function limited(work,ms){
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(work),
      new Promise((_,reject)=>{
        timer=setTimeout(()=>reject(Error('Owner consent dependency timed out')),ms);
      })
    ]);
  }finally{clearTimeout(timer)}
}
function createDisposableInitialConsentCoordinator({
  verifyLiveOwner,epochIssuer,canonicalReader,witnessAttestor,
  immutableWitnessReader,redis,approvedClientId,
  grantTtlSec=TTL,operationTimeoutMs=5000,fixtureOnly=false
}={}){
  gate();
  if(fixtureOnly!==true||!https(approvedClientId)||
     !Number.isSafeInteger(grantTtlSec)||grantTtlSec<300||
     grantTtlSec>60*60*24*180||
     !Number.isSafeInteger(operationTimeoutMs)||
     operationTimeoutMs<20||operationTimeoutMs>15000||
     typeof verifyLiveOwner!=='function'||
     typeof epochIssuer?.issueFirst!=='function'||
     typeof canonicalReader?.verify!=='function'||
     typeof witnessAttestor?.attestFirst!=='function'||
     typeof immutableWitnessReader?.verify!=='function'||
     typeof redis?.eval!=='function')
    deny('OWNER_INITIAL_CONSENT_CONFIG_INVALID');

  async function owner(context){
    gate();
    let proof;
    try{proof=await limited(()=>verifyLiveOwner(context),operationTimeoutMs)}catch{
      deny('OWNER_INITIAL_CONSENT_OWNER_NOT_CURRENT');
    }
    if(!validOwner(proof))deny('OWNER_INITIAL_CONSENT_OWNER_NOT_CURRENT');
    // Snapshot the trusted claim. A caller must not be able to mutate a
    // shared enrollment-hash Buffer while the PG/WORM writes are pending.
    return Object.freeze({
      canonicalAccountId:proof.canonicalAccountId,
      sessionId:proof.sessionId,
      enrollmentTokenHash:Buffer.from(proof.enrollmentTokenHash)
    });
  }
  function recordFor(proof,grantId){
    return Object.freeze({
      canonicalAccountId:proof.canonicalAccountId,
      clientId:approvedClientId,consentGrantId:grantId,scope:SCOPE,
      oauthPgRevision:REVISION
    });
  }
  async function readCanonical(record){
    let allowed;
    try {allowed=await limited(()=>canonicalReader.verify(record),operationTimeoutMs)}catch{
      deny('OWNER_INITIAL_CONSENT_CANONICAL_UNAVAILABLE');
    }
    if(allowed!==true)deny('OWNER_INITIAL_CONSENT_EPOCH_NOT_CURRENT');
  }
  async function readWitness(record){
    let allowed;
    try {allowed=await limited(()=>immutableWitnessReader.verify(record),operationTimeoutMs)}catch{
      deny('OWNER_INITIAL_CONSENT_WITNESS_UNAVAILABLE');
    }
    if(allowed!==true)deny('OWNER_INITIAL_CONSENT_WITNESS_NOT_CURRENT');
  }
  return Object.freeze({
    async approveFirst({context}={}){
      gate();
      const initial=await owner(context);
      // The untrusted caller cannot supply owner, app, client, scope,
      // grant ID or epoch. The issuer derives owner/app/client from the PG
      // enrollment journal; the canonical reader rejects any mismatch.
      const grantId=crypto.randomBytes(24).toString('base64url');
      if(!GRANT.test(grantId))deny('OWNER_INITIAL_CONSENT_CONFIG_INVALID');
      const bound=recordFor(initial,grantId);
      let revision;
      try{
        revision=await limited(()=>epochIssuer.issueFirst({
          tokenHash:Buffer.from(initial.enrollmentTokenHash),
          grantId,scope:SCOPE
        }),operationTimeoutMs);
      }catch{
        // A lost PG ACK might have committed. Never blindly retry.
        deny('OWNER_INITIAL_CONSENT_COMMIT_AMBIGUOUS');
      }
      if(revision!==REVISION)
        deny('OWNER_INITIAL_CONSENT_COMMIT_AMBIGUOUS');

      // PG success alone is NEVER authority: it may be rewound via PITR.
      // Fail closed until the independently controlled latest WORM receipt
      // is sealed, read back, and compared to the canonical current epoch.
      await readCanonical(bound);
      let sealed;
      try{sealed=await limited(()=>witnessAttestor.attestFirst(bound),operationTimeoutMs)}catch{
        deny('OWNER_INITIAL_CONSENT_WITNESS_COMMIT_AMBIGUOUS');
      }
      if(sealed!==true)
        deny('OWNER_INITIAL_CONSENT_WITNESS_COMMIT_AMBIGUOUS');
      await readCanonical(bound);
      await readWitness(bound);
      const stillLive=await owner(context);
      if(!sameOwner(initial,stillLive))
        deny('OWNER_INITIAL_CONSENT_OWNER_NOT_CURRENT');

      const now=Math.floor(Date.now()/1000);
      const stored={
        canonicalAccountId:bound.canonicalAccountId,
        clientId:approvedClientId,scope:SCOPE,
        grantId,oauthPgRevision:REVISION,
        grantedAt:now,updatedAt:now,revoked:false
      };
      let persisted;
      try{
        // This is the *existing* browser-session-aware Lua CAS, NOT a
        // second read/modify/write path. Logout races serialize with it.
        persisted=await limited(()=>redis.eval(UPSERT_CONSENT_IF_SESSION_LIVE,2,
          consentKey('oauth:grant',bound.canonicalAccountId,approvedClientId),
          sessionKey(KEY_PREFIX,stillLive.sessionId),
          digest(bound.canonicalAccountId),JSON.stringify(stored),
          String(grantTtlSec)),operationTimeoutMs);
      }catch{
        // Redis may have committed before losing the ACK; no retries.
        deny('OWNER_INITIAL_CONSENT_REDIS_AMBIGUOUS');
      }
      if(persisted!==1)
        deny('OWNER_INITIAL_CONSENT_OWNER_NOT_CURRENT');
      // A concurrent PG revoke or witness change makes this grant
      // unusable. No browser redirect/authorization code before both reads.
      await readCanonical(bound);
      await readWitness(bound);
      return Object.freeze({...stored});
    }
  });
}
module.exports={createDisposableInitialConsentCoordinator};
