'use strict';
// Disposable live Redis8.2 proof. Never connects to a production authority.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const registrySchema = require('../services/oauth/oauth-session-registry.service');
const consentSchema = require('../services/oauth/oauth-consent.service');
const challengeSchema = require('../services/oauth/oauth-consent-challenge.service');
const { consentKey } = require('../utils/oauth-refresh-atomic-policy');
const apiSchema = require('../services/oauth/oauth-api.service');

if (process.env.NODE_ENV !== 'test' ||
    process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE !== 'confirmed' ||
    !/^redis:\/\/127\.0\.0\.1:6398\/?$/u.test(process.env.PAPER_OAUTH_EPOCH_REDIS_URL || '')) {
  throw Error('Disposable Redis marker and loopback URL are required');
}
const webId = 'https://paper.example.org/users/session-owner';
const alien = 'https://paper.example.org/users/attacker';
const passwordHash = '$2b$10$'+'a'.repeat(53);
const replacementHash = '$2b$10$'+'b'.repeat(53);
const prefix = 'oauth:browser-session:proof:' + crypto.randomBytes(16).toString('hex') + ':';
const reg = () => ({
  settings: {...registrySchema.settings,
    redisUrl: process.env.PAPER_OAUTH_EPOCH_REDIS_URL, keyPrefix: prefix}
});
const a = reg(), b = reg();
const consent = {settings:{...consentSchema.settings,
  redisUrl:process.env.PAPER_OAUTH_EPOCH_REDIS_URL,
  keyPrefix:'oauth:grant:proof:'+crypto.randomBytes(16).toString('hex'),
  sessionKeyPrefix:prefix}};
const grantParams={canonicalAccountId:webId,clientId:'https://paper.example.org/oauth-test-app',
  scope:'atproto'};
const challenges = {settings:{...challengeSchema.settings,
  redisUrl:process.env.PAPER_OAUTH_EPOCH_REDIS_URL,
  keyPrefix:'oauth:consent-challenge:owner-proof:'+crypto.randomBytes(16).toString('hex')}};
const service = {
  settings: {...apiSchema.settings, sessionSecret: crypto.randomBytes(32).toString('hex'),
    issuer: 'https://paper.example.org', sessionTtlSec: 3600,
    sessionCookieName: 'oauth_session'},
  ...apiSchema.methods
};
const ids = [];
const key = id => prefix + crypto.createHash('sha256').update(id).digest('hex');
async function action(instance, name, params) {
  return registrySchema.actions[name].handler.call(instance, {params});
}
function context(instance, cookie, options={}) {
  const calls=[];
  const ctx={
    params: options.params || {},
    meta: {$headers: {origin:'https://paper.example.org',
      'content-type':'application/json','sec-fetch-site':'same-origin',
      ...(cookie ? {cookie: 'oauth_session='+encodeURIComponent(cookie)} : {}),
      ...(options.headers || {})},$query:options.query||{}},
    calls,
    async call(name, p){
      calls.push(name);
      if(name==='auth.account.verify')return {webId,hashedPassword:options.passwordHash||passwordHash};
      if(name==='auth.account.findByWebId')return {webId,hashedPassword:options.passwordHash||passwordHash};
      if(name.startsWith('oauth-consent-challenge.')) {
        if(options.outage)throw Error('Redis challenge authority unavailable');
        return challengeSchema.actions[name.split('.')[1]].handler.call(challenges,{params:p});
      }
      if(name.startsWith('oauth-consent.')) {
        if(options.outage)throw Error('Redis consent authority unavailable');
        return consentSchema.actions[name.split('.')[1]].handler.call(consent,{params:p});
      }
      if(name.startsWith('oauth-session-registry.')) {
        if(options.outage)throw Error('Redis registry unavailable');
        return action(instance,name.split('.')[1],p);
      }
      throw Error('Unexpected OAuth action: '+name);
    }
  };
  return ctx;
}
async function rejected(fn, code) {
  await assert.rejects(fn(), e=>e?.code===code,
    'OAuth approval/issuance must fail closed on missing session authority');
}
async function main(){
  registrySchema.created.call(a);
  registrySchema.created.call(b);
  consentSchema.created.call(consent);
  challengeSchema.created.call(challenges);
  try{
    await Promise.all([registrySchema.started.call(a), registrySchema.started.call(b),
      consentSchema.started.call(consent),challengeSchema.started.call(challenges)]);
    const stolenLogin=context(a,null,{params:{username:'session-owner@example.org',password:'correct'},
      headers:{origin:'https://attacker.example.org'}});
    await rejected(()=>apiSchema.actions.loginSession.call(service,stolenLogin),403);
    assert.equal(stolenLogin.calls.length,0,
      'Cross-site form must be refused before password verification');
    const login=context(a,null,{params:{username:'session-owner@example.org',password:'correct'}});
    const result=await apiSchema.actions.loginSession.call(service,login);
    assert.equal(result.ok,true);
    assert.ok(login.calls.includes('auth.account.verify'));
    assert.ok(login.calls.includes('oauth-session-registry.create'));
    const setCookie=login.meta.$responseHeaders['Set-Cookie'];
    assert.match(setCookie,/HttpOnly/u);
    assert.match(setCookie,/SameSite=Lax/u);
    assert.match(setCookie,/Secure/u);
    const raw=decodeURIComponent(setCookie.match(/^oauth_session=([^;]+)/u)[1]);
    const signed=service.getSession(context(b,raw));
    assert.equal(signed.webId,webId);
    assert.match(signed.sessionId,/^[A-Za-z0-9_-]{43}$/u);
    ids.push(signed.sessionId);
    const stored=await a.redis.get(key(signed.sessionId));
    assert.equal(stored, crypto.createHash('sha256').update(webId).digest('hex'));
    const ttl=await a.redis.ttl(key(signed.sessionId));
    assert.ok(ttl>0 && ttl<=3600);
    assert.equal(await service.requireUserWebId(context(b,raw)),webId,
      'Second independent provider replica must admit live session');
    // A password change invalidates copied cookies without waiting for
    // Redis TTL, even while the Redis session key is still present.
    await rejected(()=>service.requireUserWebId(
      context(b,raw,{passwordHash:replacementHash})),401);
    assert.equal(await service.isCurrentBrowserSessionAccount(
      context(b,raw,{passwordHash:replacementHash}),signed),false);
    assert.equal(await service.isCurrentBrowserSessionAccount(context(b,raw),signed),true);
    assert.equal(await action(b,'verify',{sessionId:signed.sessionId,webId:alien}),false);
    const ownerAttack=await action(b,'revoke',{sessionId:signed.sessionId,webId:alien});
    assert.equal(ownerAttack.revoked,false);
    assert.equal(await service.requireUserWebId(context(b,raw)),webId);
    const grantBefore=await consentSchema.actions.upsert.handler.call(consent,
      {params:{...grantParams,ownerSessionId:signed.sessionId}});
    assert.equal(grantBefore.revoked,false);
    assert.equal(grantBefore.canonicalAccountId,webId);
    // Real two-client post-enrollment owner consent management. The client
    // cannot enumerate another owner's grant, mint a bearer-only session,
    // replay a one-use CSRF challenge or revoke a newer grant generation.
    const ownerRead=()=>context(b,raw,{
      query:{client_id:grantParams.clientId}
    });
    const ownerPost=(proof,headers={})=>context(b,raw,{
      params:{
        client_id:grantParams.clientId,grant_id:proof.grant_id,
        challenge_id:proof.challenge_id,csrf_token:proof.csrf_token
      },
      headers:{origin:'https://paper.example.org',
        'content-type':'application/json','sec-fetch-site':'same-origin',
        ...headers}
    });
    await rejected(()=>apiSchema.actions.getOwnerGrant.call(
      service,context(b,null,{query:{client_id:grantParams.clientId}})),401);
    const otherClient=await apiSchema.actions.getOwnerGrant.call(service,
      context(b,raw,{query:{client_id:'https://other.example.org/app'}}));
    assert.deepEqual(otherClient,{client_id:'https://other.example.org/app',consented:false});
    const queriedClient='https://other.example.org/app?tenant=one';
    assert.equal((await apiSchema.actions.getOwnerGrant.call(service,
      context(b,raw,{query:{client_id:queriedClient}}))).consented,false);
    await rejected(()=>apiSchema.actions.getOwnerGrant.call(service,
      context(b,raw,{query:{client_id:'http://other.example.org/app'}})),400);
    const grantView=await apiSchema.actions.getOwnerGrant.call(service,ownerRead());
    assert.equal(grantView.consented,true);
    assert.equal(grantView.grant_id,grantBefore.grantId);
    assert.equal(grantView.scope,grantBefore.scope);
    assert.match(grantView.challenge_id,/^[A-Za-z0-9_-]{32}$/u);
    assert.match(grantView.csrf_token,/^[A-Za-z0-9_-]{32}$/u);
    const badOrigin=ownerPost(grantView,{origin:'https://attacker.example.org'});
    await rejected(()=>apiSchema.actions.revokeOwnerGrant.call(service,badOrigin),403);
    await rejected(()=>apiSchema.actions.revokeOwnerGrant.call(service,
      ownerPost(grantView,{'sec-fetch-site':'cross-site'})),403);
    const invalidBearer=ownerPost(grantView,{authorization:'Bearer forged'});
    await rejected(()=>apiSchema.actions.revokeOwnerGrant.call(service,invalidBearer),401);
    const revoked=await apiSchema.actions.revokeOwnerGrant.call(
      service,ownerPost(grantView));
    assert.deepEqual(revoked,{revoked:true,client_id:grantParams.clientId});
    const revokedGrant=await consentSchema.actions.get.handler.call(consent,
      {params:{canonicalAccountId:webId,clientId:grantParams.clientId}});
    assert.equal(revokedGrant.revoked,true);
    await rejected(()=>apiSchema.actions.revokeOwnerGrant.call(
      service,ownerPost(grantView)),403);
    assert.equal((await apiSchema.actions.getOwnerGrant.call(
      service,ownerRead())).consented,false);

    // Stale GET read must never overwrite/revoke a subsequent reapproval.
    const nextGrant=await consentSchema.actions.upsert.handler.call(consent,
      {params:{...grantParams,ownerSessionId:signed.sessionId}});
    const oldView=await apiSchema.actions.getOwnerGrant.call(service,ownerRead());
    assert.equal(oldView.grant_id,nextGrant.grantId);
    const latestGrant=await consentSchema.actions.upsert.handler.call(consent,
      {params:{...grantParams,ownerSessionId:signed.sessionId}});
    const staleAttempt=ownerPost(oldView);
    const conflict=await apiSchema.actions.revokeOwnerGrant.call(service,staleAttempt);
    assert.deepEqual(conflict,{revoked:false,error:'consent_changed',
      client_id:grantParams.clientId});
    assert.equal(staleAttempt.meta.$statusCode,409);
    const retained=await consentSchema.actions.get.handler.call(consent,
      {params:{canonicalAccountId:webId,clientId:grantParams.clientId}});
    assert.equal(retained.grantId,latestGrant.grantId);
    assert.equal(retained.revoked,false);
    const currentView=await apiSchema.actions.getOwnerGrant.call(service,ownerRead());
    // Password update/refreshed account disables even a still-live Redis
    // owner session before its one-use revocation challenge is consumed.
    const outdated=ownerPost(currentView);
    outdated.call=async(name,params)=>{
      if(name==='auth.account.findByWebId')return {webId,hashedPassword:replacementHash};
      if(name.startsWith('oauth-session-registry.'))
        return action(b,name.split('.')[1],params);
      throw Error('Unexpected changed-password action '+name);
    };
    await rejected(()=>apiSchema.actions.revokeOwnerGrant.call(service,outdated),401);
    // A bad CSRF hash burns its challenge, so a later replay cannot succeed.
    const tampered=ownerPost(currentView);
    tampered.params.csrf_token=crypto.randomBytes(24).toString('base64url');
    await rejected(()=>apiSchema.actions.revokeOwnerGrant.call(service,tampered),403);
    await rejected(()=>apiSchema.actions.revokeOwnerGrant.call(
      service,ownerPost(currentView)),403);
    const freshView=await apiSchema.actions.getOwnerGrant.call(service,ownerRead());
    assert.equal((await apiSchema.actions.revokeOwnerGrant.call(
      service,ownerPost(freshView))).revoked,true);
    const finalGrant=await consentSchema.actions.get.handler.call(consent,
      {params:{canonicalAccountId:webId,clientId:grantParams.clientId}});
    assert.equal(finalGrant.revoked,true);

    const outageApproval=context(a,raw,{outage:true});
    await rejected(()=>service.requireUserWebId(outageApproval),401);
    const outageLogout=context(a,raw,{outage:true});
    await rejected(()=>apiSchema.actions.logoutSession.call(service,outageLogout),503);
    assert.equal(outageLogout.meta.$responseHeaders?.['Set-Cookie'],undefined,
      'Unacknowledged logout must not claim revocation');
    const forgedLogout=context(b,raw,{headers:{origin:'https://attacker.example.org'}});
    await rejected(()=>apiSchema.actions.logoutSession.call(service,forgedLogout),403);
    assert.equal(await action(a,'verify',{sessionId:signed.sessionId,webId}),true,
      'Cross-origin logout may not revoke an innocent owner session');
    assert.equal(forgedLogout.meta.$responseHeaders?.['Set-Cookie'],undefined);
    const signedOut=context(b,raw);
    const signedOutResult=await apiSchema.actions.logoutSession.call(service,signedOut);
    assert.equal(signedOutResult.ok,true);
    assert.match(signedOut.meta.$responseHeaders['Set-Cookie'],/Max-Age=0/u);
    assert.equal(await action(a,'verify',{sessionId:signed.sessionId,webId}),false);
    await rejected(()=>service.requireUserWebId(context(a,raw)),401);
    // The grant writer and logout share a Redis serialization boundary;
    // an earlier positive HTTP session check cannot write a new grant.
    for (let i=0;i<8;i++) {
      await rejected(()=>consentSchema.actions.upsert.handler.call(consent,
        {params:{...grantParams,ownerSessionId:signed.sessionId}}),403);
    }
    const persistedGrant=await consentSchema.actions.get.handler.call(consent,
      {params:{canonicalAccountId:webId,clientId:grantParams.clientId}});
    assert.equal(persistedGrant.grantId,finalGrant.grantId,
      'Logout must not rewrite the final owner-revoked consent generation');
    assert.equal(persistedGrant.revoked,true,
      'Logout and stale session must never reactivate revoked consent');
    assert.equal(await service.isActiveBrowserSession(context(b,raw),signed),false);
    const repeat=context(a,raw);
    const repeated=await apiSchema.actions.logoutSession.call(service,repeat);
    assert.equal(repeated.ok,true);
    const absent=context(b,null);
    assert.equal((await apiSchema.actions.logoutSession.call(service,absent)).ok,true);

    // An account or Redis outage cannot produce a useable browser cookie.
    const noAck=context(a,null,{params:{username:'owner',password:'correct'},outage:true});
    await rejected(()=>apiSchema.actions.loginSession.call(service,noAck),503);
    assert.equal(noAck.meta.$responseHeaders?.['Set-Cookie'],undefined);

    // A valid HMAC from the old stateless scheme must not bypass Redis.
    const legacyPayload=Buffer.from(JSON.stringify({webId,exp:Math.floor(Date.now()/1000)+3600})).toString('base64url');
    const legacy=legacyPayload+'.'+service.signSessionPayload(legacyPayload);
    assert.equal(service.getSession(context(a,legacy)),null);
    await rejected(()=>service.requireUserWebId(context(a,legacy)),401);
    console.log('PASS: two independent Redis-backed OAuth session replicas; login ACK before cookie, owner-bound NX, cross-cell logout, absent/malformed/stale legacy cookie denial, registry outage fail-closed');
  } finally {
    try { if(a.redis?.status==='ready' && ids.length)
      await a.redis.del(...ids.map(key)); } catch { /* Disposable cleanup must not mask security assertion failures. */ }
    try { if(consent.redis?.status==='ready')
      await consent.redis.del(consentKey(consent.settings.keyPrefix,
        webId,grantParams.clientId)); } catch { /* Disposable cleanup must not mask security assertion failures. */ }
    await Promise.allSettled([
      registrySchema.stopped.call(a),registrySchema.stopped.call(b),
      consentSchema.stopped.call(consent),challengeSchema.stopped.call(challenges)
    ]);
  }
}
main().catch(e=>{console.error(e?.stack||e);process.exitCode=1;});
