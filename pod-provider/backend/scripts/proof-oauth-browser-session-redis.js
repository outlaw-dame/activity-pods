'use strict';
// Disposable live Redis8.2 proof. Never connects to a production authority.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const registrySchema = require('../services/oauth/oauth-session-registry.service');
const consentSchema = require('../services/oauth/oauth-consent.service');
const { consentKey } = require('../utils/oauth-refresh-atomic-policy');
const apiSchema = require('../services/oauth/oauth-api.service');

if (process.env.NODE_ENV !== 'test' ||
    process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE !== 'confirmed' ||
    !/^redis:\/\/127\.0\.0\.1:6398\/?$/u.test(process.env.PAPER_OAUTH_EPOCH_REDIS_URL || '')) {
  throw Error('Disposable Redis marker and loopback URL are required');
}
const webId = 'https://paper.example.org/users/session-owner';
const alien = 'https://paper.example.org/users/attacker';
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
    meta: {$headers: cookie ? {cookie: 'oauth_session='+encodeURIComponent(cookie)} : {}},
    calls,
    async call(name, p){
      calls.push(name);
      if(name==='auth.account.verify')return {webId};
      if(name==='auth.account.findByWebId')return {webId};
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
  try{
    await Promise.all([registrySchema.started.call(a), registrySchema.started.call(b),
      consentSchema.started.call(consent)]);
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
    assert.equal(await action(b,'verify',{sessionId:signed.sessionId,webId:alien}),false);
    const ownerAttack=await action(b,'revoke',{sessionId:signed.sessionId,webId:alien});
    assert.equal(ownerAttack.revoked,false);
    assert.equal(await service.requireUserWebId(context(b,raw)),webId);
    const grantBefore=await consentSchema.actions.upsert.handler.call(consent,
      {params:{...grantParams,ownerSessionId:signed.sessionId}});
    assert.equal(grantBefore.revoked,false);
    assert.equal(grantBefore.canonicalAccountId,webId);
    const outageApproval=context(a,raw,{outage:true});
    await rejected(()=>service.requireUserWebId(outageApproval),401);
    const outageLogout=context(a,raw,{outage:true});
    await rejected(()=>apiSchema.actions.logoutSession.call(service,outageLogout),503);
    assert.equal(outageLogout.meta.$responseHeaders?.['Set-Cookie'],undefined,
      'Unacknowledged logout must not claim revocation');
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
    assert.equal(persistedGrant.grantId,grantBefore.grantId,
      'Revoked session must not overwrite last authorized consent generation');
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
      consentSchema.stopped.call(consent)
    ]);
  }
}
main().catch(e=>{console.error(e?.stack||e);process.exitCode=1;});
