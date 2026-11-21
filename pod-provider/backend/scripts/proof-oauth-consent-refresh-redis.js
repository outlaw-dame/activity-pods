'use strict';
// Real Redis 8.2 acceptance for the new-account OAuth and PDS consent epoch.
// Two separately connected workers contend for authorization-code and
// refresh-token consumption. No production secrets or database flushes.
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const Redis=require('ioredis');
const {generateKeyPair,exportJWK}=require('jose');
const consent=require('../services/oauth/oauth-consent.service');
const code=require('../services/oauth/oauth-code-store.service');
const refresh=require('../services/oauth/oauth-refresh-session.service');
const access=require('../services/oauth/oauth-token.service');
const {FAMILY_MAX_TOKENS,consentKey}=require('../services/oauth/oauth-refresh-atomic-policy');

const url='redis://127.0.0.1:6398';
if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_EPOCH_REDIS_URL!==url){
  throw Error('Refusing OAuth epoch test without disposable Redis 8.2');
}
const ns='paper:epoch-proof:'+crypto.randomBytes(10).toString('hex');
const clients=[new Redis(url,{enableOfflineQueue:false,autoResendUnfulfilledCommands:false,
  maxRetriesPerRequest:1,connectTimeout:2500,lazyConnect:true}),
 new Redis(url,{enableOfflineQueue:false,autoResendUnfulfilledCommands:false,
  maxRetriesPerRequest:1,connectTimeout:2500,lazyConnect:true})];
const [one,two]=clients;
const webId='https://paper.example.org/owners/oauth-epoch';
const clientId='https://client.paper.example.org/oauth';
const did='did:plc:'+'v'.repeat(24);
const scope='atproto repo:app.bsky.feed.post?action=create';
const dpopJkt='j'.repeat(43);
const jwtConfig={issuer:'https://paper.example.org',
 audience:'https://pds.paper.example.org',accessTtlSec:1800};
const consents={redis:one,settings:{keyPrefix:ns+':consent',ttlSec:7200}};
const codeSettings={keyPrefix:ns+':code',usedPrefix:ns+':used',codeTtlSec:120};
const secret=crypto.randomBytes(32);
const refreshSettings={
 tokenPrefix:ns+':refresh',familyPrefix:ns+':family',
 revokedPrefix:ns+':family-revoked',consentPrefix:consents.settings.keyPrefix,
 ttlSec:7200
};
const methods=refresh.methods;
function worker(redis){
 const state={redis,settings:refreshSettings,encKey:secret,...methods};
 state.actions={revokeFamily:params=>refresh.actions.revokeFamily.handler.call(state,{params})};
 return state;
}
const w1=worker(one),w2=worker(two);
const grant=async()=>consent.actions.upsert.handler.call(consents,{
  params:{canonicalAccountId:webId,clientId,scope}
});
const readGrant=async()=>consent.actions.get.handler.call(consents,{
  params:{canonicalAccountId:webId,clientId}
});
const revoke=async()=>consent.actions.revoke.handler.call(consents,{
  params:{canonicalAccountId:webId,clientId}
});
const session=id=>({sub:did,canonicalAccountId:webId,clientId,scope,
  consentGrantId:id,dpopJkt});
const issue=async(current,state=w1)=>refresh.actions.issueRefreshToken.handler.call(
 state,{params:{did,canonicalAccountId:webId,clientId,scope,
  consentGrantId:current.grantId,dpopJkt}}
);
const rotate=async(state,token)=>refresh.actions.rotateRefreshToken.handler.call(
 state,{params:{refreshToken:token,dpopJkt}}
);
const introspect=async(state,token)=>refresh.actions.introspectRefreshToken.handler.call(
 state,{params:{refreshToken:token}}
);
function refused(promise,codeName){
 return assert.rejects(promise,e=>e?.type===codeName||e?.code===codeName);
}
async function cleanup(){
 for(const redis of [one]){
  if(redis.status!=='ready')return;
  let cursor='0',pages=0;
  do{
   if(++pages>128)throw Error('OAuth cleanup key scan limit exceeded');
   const [next,keys]=await redis.scan(cursor,'MATCH',ns+':*','COUNT',256);
   cursor=next;
   if(keys.length)await redis.unlink(...keys);
  }while(cursor!=='0');
  break;
 }
}
async function main(){
 // With offline queue disabled, a command before READY must fail rather
 // than queue. Make readiness explicit; do not retry a write on reconnect.
 await Promise.all(clients.map(async c=>{
  await c.connect();
  assert.equal(c.status,'ready');
  assert.equal(await c.ping(),'PONG');
 }));
 const info=String(await one.info('server'));
 assert.match(info,/redis_version:8\.2\./u,'Require real Redis 8.2');
 const {privateKey,publicKey}=await generateKeyPair('ES256');
 const privateJwk=await exportJWK(privateKey),publicJwk=await exportJWK(publicKey);
 privateJwk.alg='ES256';publicJwk.alg='ES256';
 const issuerCtx={async call(name,args){
  if(name==='jwk.get')return {privateJwk,publicJwk};
  if(name==='oauth-consent.get')return readGrant();
  assert.fail('Unexpected credential authority '+name);
 }};
 const jwt=consentGrantId=>access.methods.issueAccessToken.call(
  {settings:jwtConfig},session(consentGrantId),issuerCtx
 );
 const verify=token=>access.actions.introspectAccessToken.handler.call(
  {settings:jwtConfig},{params:{token},call:issuerCtx.call}
 );
 // The old colon-joined format could alias two different owner/client
 // pairs. Domain-separated tuple hashes prevent that security collision.
 assert.notEqual(
  consentKey(ns,'https://a:b','https://c'),
  consentKey(ns,'https://a','b:https://c')
 );
 const old=await grant();
 console.log('PHASE: owner consent written');
 assert.match(old.grantId,/^[A-Za-z0-9_-]{32}$/u);
 const oldJwt=await jwt(old.grantId);
 assert.equal((await verify(oldJwt)).consent_grant_id,old.grantId);

 // Authorization codes store the exact generation, and GETDEL admits one
 // consumer among independent Redis connections (no check-then-delete).
 const codeParams={
  clientId,redirectUri:'https://client.paper.example.org/cb',
  canonicalAccountId:webId,did,scope,consentGrantId:old.grantId,
  dpopJkt,codeChallenge:'a'.repeat(43),codeChallengeMethod:'S256'
 };
 const issued=await code.actions.issueCode.handler.call(
  {redis:one,settings:codeSettings},{params:codeParams}
 );
 console.log('PHASE: competing authorization-code redemption');
 const redeemed=await Promise.allSettled([one,two].map(redis=>
  code.actions.consumeCode.handler.call({redis,settings:codeSettings},{
   params:{code:issued.code}
  })
 ));
 assert.equal(redeemed.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(redeemed.filter(x=>x.status==='rejected').length,1);
 assert.equal(redeemed.find(x=>x.status==='fulfilled').value.consentGrantId,old.grantId);
 const delayedCode=await code.actions.issueCode.handler.call(
  {redis:one,settings:codeSettings},{params:codeParams}
 );

 // Old access tokens stay cryptographically signed and unexpired, yet
 // become unauthorized immediately on revoke and never revive on regrant.
 assert.deepEqual(await revoke(),{revoked:true});
 assert.equal((await verify(oldJwt)).active,false);
 const fresh=await grant();
 assert.notEqual(fresh.grantId,old.grantId);
 assert.equal((await verify(oldJwt)).active,false);
 // A code created before revocation can be redeemed only once, but its
 // embedded old generation cannot produce a new access/refresh token.
 const late=await code.actions.consumeCode.handler.call(
  {redis:two,settings:codeSettings},{params:{code:delayedCode.code}});
 assert.equal(late.consentGrantId,old.grantId);
 await refused(jwt(late.consentGrantId),'INVALID_GRANT');
 await refused(jwt(old.grantId),'INVALID_GRANT');
 const freshJwt=await jwt(fresh.grantId);
 assert.equal((await verify(freshJwt)).active,true);
 console.log('PHASE: revoke/reapprove access JWT epoch passed');

 const first=await issue(fresh);
 assert.equal((await introspect(w1,first.refreshToken)).active,true);
 console.log('PHASE: initial refresh rotation');
 const next=await rotate(w1,first.refreshToken);
 assert.equal((await introspect(w1,first.refreshToken)).active,false);
 assert.equal((await introspect(w2,next.refreshToken)).active,true);

 // Two independent provider cells racing on one successor MUST NOT
 // return two valid descendants. Replay atomically poisons its family.
 console.log('PHASE: competing refresh CAS');
 const races=await Promise.allSettled([
  rotate(w1,next.refreshToken),rotate(w2,next.refreshToken)
 ]);
 assert.equal(races.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(races.filter(x=>x.status==='rejected').length,1);
 const winner=races.find(x=>x.status==='fulfilled').value;
 assert.equal((await introspect(w1,winner.refreshToken)).active,false);
 assert.equal(await one.exists(w1.revokedKey(first.familyId)),1);
 await refused(rotate(w1,winner.refreshToken),'REFRESH_FAMILY_REVOKED');

 const independent=await issue(fresh);
 assert.equal((await introspect(w2,independent.refreshToken)).active,true);
 const revokedFamily=await refresh.actions.revokeFamily.handler.call(w1,{
  params:{familyId:independent.familyId}
 });
 assert.equal(revokedFamily.revoked,true);
 assert.equal((await introspect(w1,independent.refreshToken)).active,false);
 await refused(refresh.actions.issueRefreshToken.handler.call(w1,{
  params:{...session(fresh.grantId),did,consentGrantId:fresh.grantId,
    familyId:independent.familyId}
 }), 'REFRESH_FAMILY_REVOKED');

 // A revoked owner grant blocks even a fresh family before encryption or
 // refresh lookup is stored. Reapproving changes generation permanently.
 console.log('PHASE: family revoke and reapproval');
 const existing=await issue(fresh);
 await revoke();
 assert.equal((await introspect(w1,existing.refreshToken)).active,false);
 await refused(rotate(w2,existing.refreshToken),'INVALID_GRANT');
 await refused(issue(fresh),'INVALID_GRANT');
 const newest=await grant();
 assert.notEqual(newest.grantId,fresh.grantId);
 assert.equal((await introspect(w1,existing.refreshToken)).active,false);
 await refused(rotate(w1,existing.refreshToken),'INVALID_GRANT');
 const newborn=await issue(newest);
 assert.equal((await introspect(w2,newborn.refreshToken)).active,true);

 // Bounded memory per refresh family: a saturated historical index cannot
 // accept more descendants or force an unbounded SMEMBERS/decrypt scan.
 const cappedFamily=crypto.randomBytes(18).toString('base64url');
 await one.sadd(w1.familyKey(cappedFamily),
  ...Array.from({length:FAMILY_MAX_TOKENS},(_,i)=>'bounded-'+i));
 await refused(refresh.actions.issueRefreshToken.handler.call(w2,{params:{
  did,canonicalAccountId:webId,clientId,scope,consentGrantId:newest.grantId,
  dpopJkt,familyId:cappedFamily
 }}),'REFRESH_FAMILY_LIMIT');

 console.log('PHASE: family cap/refresh replay passed');
 // Production may never start with the historical public example key.
 const oldEnv=process.env.NODE_ENV;
 try{
  process.env.NODE_ENV='production';
  assert.throws(()=>refresh.created.call({
   settings:{...refreshSettings,encKeyHex:
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'}
  }),/unique 32-byte OAuth refresh encryption key/u);
 }finally{process.env.NODE_ENV=oldEnv;}
 console.log('PASS: Redis 8.2 atomic auth-code consumption, consent epochs, JWT revoke/regrant, two-worker refresh CAS/replay, family revocation and bounded index');
}
(async()=>{
 // A logic regression must not consume a whole hosted runner indefinitely.
 const watchdog=setTimeout(()=>{
  console.error('FAIL: bounded OAuth Redis acceptance watchdog expired');
  process.exit(1);
 },90000);
 try{await main()}
 catch(error){process.exitCode=1;console.error(error?.stack||String(error))}
 finally{
  try{await cleanup()}catch(e){process.exitCode=1;console.error('Own-key cleanup failed',e?.message)}
  await Promise.allSettled(clients.map(async c=>{
   if(c.status==='ready')await c.quit();
   else c.disconnect();
  }));
  clearTimeout(watchdog);
 }
})();
