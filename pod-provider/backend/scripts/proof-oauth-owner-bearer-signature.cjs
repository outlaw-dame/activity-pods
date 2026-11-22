'use strict';
// Authentic cryptographic regression for the OAuth owner authorization path.
// SemApps auth.jwt.decodeToken is UNVERIFIED and must NEVER establish WebID.
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const schema=require('../services/oauth/oauth-api.service');

const keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const attacker=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const webId='https://paper.example.org/users/alice';
const now=Math.floor(Date.now()/1000);
const sessionId=crypto.randomBytes(32).toString('base64url');
const passwordHash='$2b$10$'+'a'.repeat(53);
const replacementHash='$2b$10$'+'b'.repeat(53);
const service={
 settings:{...schema.settings,sessionSecret:crypto.randomBytes(32).toString('hex'),
  sessionTtlSec:3600,sessionCookieName:'oauth_session',
  issuer:'https://paper.example.org'},
 ...schema.methods
};
function token(payload,privateKey=keys.privateKey,alg='RS256'){
 const enc=obj=>Buffer.from(JSON.stringify(obj)).toString('base64url');
 const signed=enc({alg,typ:'JWT'})+'.'+enc(payload);
 if(alg==='none')return signed+'.';
 return signed+'.'+crypto.sign('RSA-SHA256',Buffer.from(signed),privateKey)
  .toString('base64url');
}
// Mimic the contract of the *upstream* SemApps auth.jwt.verifyServerSignedToken
// with a real RS256 verifier; reject forged, expired and unsigned credentials.
function verifyServerToken(value){
 try{
  const parts=value.split('.');
  if(parts.length!==3)return false;
  const header=JSON.parse(Buffer.from(parts[0],'base64url'));
  const payload=JSON.parse(Buffer.from(parts[1],'base64url'));
  if(header.alg!=='RS256'||!crypto.verify('RSA-SHA256',
   Buffer.from(parts[0]+'.'+parts[1]),keys.publicKey,
   Buffer.from(parts[2],'base64url')))return false;
  if(typeof payload.exp==='number'&&payload.exp<=now)return false;
  return payload;
 }catch{return false}
}
function context(header,cookie,{account={webId,hashedPassword:passwordHash},accountThrows=false}={}){
 const headers={};
 if(header!==undefined)headers.authorization=header;
 if(cookie!==undefined)headers.cookie='oauth_session='+encodeURIComponent(cookie);
 return {meta:{$headers:headers},calls:[],
  async call(action,p){
   this.calls.push(action);
   assert.notEqual(action,'auth.jwt.decodeToken',
    'Never use unverified JWT claims to establish an OAuth owner');
   if(action==='auth.jwt.verifyServerSignedToken'){
    assert.deepEqual(Object.keys(p),['token']);
    return verifyServerToken(p.token);
   }
   if(action==='oauth-session-registry.verify'){
    assert.deepEqual(p,{webId,sessionId});
    return true;
   }
   if(action==='auth.account.findByWebId'){
    assert.equal(p.webId,webId);
    if(accountThrows)throw Error('Account directory unavailable');
    return account;
   }
   throw Error('Unexpected provider OAuth action '+action);
  }
 };
}
async function rejected(ctx){
 await assert.rejects(service.requireUserWebId.call(service,ctx),e=>
  e?.code===401&&e?.type==='LOGIN_REQUIRED',
  'Attacker-supplied bearer may not be used or fall back to a cookie');
 assert.ok(!ctx.calls.includes('auth.jwt.decodeToken'));
}
async function main(){
 const good=token({webId,iat:now,exp:now+300});
 const cookie=service.buildSessionToken(webId,sessionId,
  service.credentialSealForAccount({webId,hashedPassword:passwordHash}));
 const ok=context('Bearer '+good);
 assert.equal(await service.requireUserWebId.call(service,ok),webId);
 assert.deepEqual(ok.calls,['auth.jwt.verifyServerSignedToken',
  'auth.account.findByWebId']);
 const forged=token({webId:'https://paper.example.org/users/victim',
  iat:now,exp:now+300},attacker.privateKey);
 await rejected(context('Bearer '+forged,cookie));
 await rejected(context('Bearer '+token({webId,iat:now,exp:now-10}),cookie));
 await rejected(context('Bearer '+token({webId,iat:now-3601}),cookie));
 await rejected(context('Bearer '+token({webId,iat:now+61}),cookie));
 await rejected(context('Bearer '+token({webId,exp:now+300}),cookie));
 await rejected(context('Bearer '+token({webId,exp:now+300},null,'none'),cookie));
 await rejected(context('Basic '+good,cookie));
 await rejected(context('Bearer '+good+' garbage',cookie));
 await rejected(context('Bearer '+good+'.extra',cookie));
 await rejected(context('',cookie));
 await rejected(context(['Bearer '+good],cookie));
 await rejected(context('Bearer '+'A'.repeat(8193),cookie));
 const conflicting=context('Bearer '+good,cookie);
 conflicting.meta.$headers.Authorization='Bearer '+forged;
 await rejected(conflicting);
 for(const payload of [
  {id:webId,exp:now+300},
  {webid:webId,exp:now+300},
  {webId:'http://paper.example.org/alice',exp:now+300},
  {webId:'https://attacker@paper.example.org/alice',exp:now+300},
  {webId:'https://paper.example.org/alice?x=1',exp:now+300},
  {webId:{url:webId},exp:now+300},
  {webId:'anon',exp:now+300}
 ]){
  // Include a fresh valid iat so each case really tests its identity
  // failure, rather than passing solely because timestamp is absent.
  payload.iat=now;
  await rejected(context('Bearer '+token(payload),cookie));
 }
 const signatureFailure=context('Bearer '+good,cookie);
 signatureFailure.call=async()=>{throw Error('Verifier unavailable')};
 await rejected(signatureFailure);
 // Cookie fallback is allowed only when there is *no* Authorization header.
 const cookieOnly=context(undefined,cookie);
 assert.equal(await service.requireUserWebId.call(service,cookieOnly),webId);
 // Password set/reset/updateAccountSettings all replace the verifier;
 // a copied but live Redis cookie must immediately fail owner approval.
 await rejected(context(undefined,cookie,{account:{webId,hashedPassword:replacementHash}}));
 await rejected(context(undefined,cookie,{account:{webId}}));
 assert.deepEqual(cookieOnly.calls,['oauth-session-registry.verify',
  'auth.account.findByWebId']);

 // Historic, valid SemApps RS256 tokens have no credential version; an
 // already issued token must never approve a fresh post-password-change
 // OAuth consent. The Authorization Interface requires a live owner cookie.
 const withCsrf=(header,accountCookie,options={})=>{
  const ctx=context(header,accountCookie,options);
  Object.assign(ctx.meta.$headers,{
   origin:'https://paper.example.org',
   'content-type':'application/x-www-form-urlencoded',
   'sec-fetch-site':'same-origin'
  });
  ctx.meta.$headers.cookie=(ctx.meta.$headers.cookie ?
   ctx.meta.$headers.cookie+'; ' : '')+'oauth_csrf=one-use-proof';
  ctx.params={request_uri:'urn:ietf:params:oauth:request_uri:proof',
   decision:'approve',consent_challenge:'proof'};
  return ctx;
 };
 for(const header of ['Bearer '+good,'Bearer '+forged,
   'Bearer '+token({webId,iat:now-3599})]){
  const bearerApproval=withCsrf(header,cookie);
  await assert.rejects(
   schema.actions.postAuthorizeUser.call(service,bearerApproval),
   e=>e?.code===401&&e?.type==='LOGIN_REQUIRED');
  assert.ok(!bearerApproval.calls.includes('oauth-authorization.authorize'),
   'Even a cryptographically verified old bearer must not create consent');
 }
 for(const headers of [
  {origin:'https://attacker.example.org'},
  {origin:undefined},
  {'sec-fetch-site':'cross-site'},
  {'content-type':'text/plain'},
  {Origin:'https://conflict.example.org'}
 ]){
  const crossSiteApproval=withCsrf(undefined,cookie);
  Object.assign(crossSiteApproval.meta.$headers,headers);
  await assert.rejects(
   schema.actions.postAuthorizeUser.call(service,crossSiteApproval),
   e=>e?.code===403&&e?.type==='LOGIN_REQUIRED');
  assert.deepEqual(crossSiteApproval.calls,[]);
 }
 const changedApproval=withCsrf(undefined,cookie,
  {account:{webId,hashedPassword:replacementHash}});
 await assert.rejects(
  schema.actions.postAuthorizeUser.call(service,changedApproval),
  e=>e?.code===401&&e?.type==='LOGIN_REQUIRED');
 const validApproval=withCsrf(undefined,cookie);
 const originalCall=validApproval.call.bind(validApproval);
 validApproval.call=async(action,p)=>{
  if(action==='oauth-authorization.authorize'){
   assert.equal(p.canonicalAccountId,webId);
   assert.equal(p.ownerSessionId,sessionId,
    'Public approval must carry the live browser id into Redis grant CAS');
   assert.equal(p.csrfToken,'one-use-proof');
   assert.equal(p.request_uri,validApproval.params.request_uri);
   assert.equal(p.decision,'approve');
   return {redirect_uri:'https://client.example.org/callback?code=proof'};
  }
  return originalCall(action,p);
 };
 const accepted=await schema.actions.postAuthorizeUser.call(service,validApproval);
 assert.equal(accepted.redirect,'https://client.example.org/callback?code=proof');
 assert.equal(validApproval.meta.$statusCode,302);
 assert.equal(validApproval.meta.$location,accepted.redirect);

 await rejected(context('Bearer invalid',cookie));

 // A correctly signed bearer or HMAC cookie is NOT proof of an active
 // account after deletion. Upstream SemApps findByWebId exposes tombstones.
 for(const authHeader of [undefined,'Bearer '+good]){
  for(const account of [
   null,{webId,deletedAt:'2026-11-22T01:00:00Z'},
   {webId:'https://paper.example.org/users/someone-else'},
   {webId,deletedAt:''}
  ]){
   await rejected(context(authHeader,cookie,{account}));
  }
  await rejected(context(authHeader,cookie,{accountThrows:true}));
 }
 // Login must trust ONLY the verified record, never a later unscoped
 // findByUsername (which breaks email-based sign-ins and may race a delete).
 async function runLogin(record,headers={}){
  const calls=[];
  const ctx={params:{username:'alice@example.org',password:'correct-password'},
   meta:{$headers:{origin:'https://paper.example.org',
    'content-type':'application/json','sec-fetch-site':'same-origin',
    ...headers}},calls,async call(action,p){
    calls.push(action);
    if(action==='auth.account.verify'){
     assert.deepEqual(p,{username:'alice@example.org',password:'correct-password'});
     return record;
    }
    if(action==='oauth-session-registry.create'){
     assert.equal(p.webId,webId);
     assert.match(p.sessionId,/^[A-Za-z0-9_-]{43}$/u);
     assert.equal(p.ttlSec,3600);
     return true;
    }
    throw Error('Unexpected login action '+action);
   }};
  return {ctx,login:()=>schema.actions.loginSession.call(service,ctx)};
 }
 // Prevent login-CSRF account confusion: an attacker cannot set a
 // signed-in browser cookie using a hidden cross-origin POST.
 for(const headers of [
  {origin:'https://attacker.example.org'},
  {origin:undefined},
  {'sec-fetch-site':'cross-site'},
  {'content-type':'text/plain'},
  {Origin:'https://conflict.example.org'}
 ]){
  const attack=await runLogin({webId,hashedPassword:passwordHash},headers);
  await assert.rejects(attack.login(),
   e=>e?.code===403&&e?.type==='LOGIN_REQUIRED');
  assert.deepEqual(attack.ctx.calls,[],
   'Origin/content gate runs before any password verification');
  assert.ok(!attack.ctx.meta.$responseHeaders?.['Set-Cookie']);
 }
 const activeLogin=await runLogin({webId,hashedPassword:passwordHash});
 const result=await activeLogin.login();
 assert.equal(result.ok,true);
 assert.equal(result.webId,webId);
 assert.deepEqual(activeLogin.ctx.calls,['auth.account.verify',
  'oauth-session-registry.create']);
 assert.match(activeLogin.ctx.meta.$responseHeaders['Set-Cookie'],
  /oauth_session=/u);
 for(const record of [
  null,{webId,deletedAt:'2026-11-22T01:00:00Z'},
  {webId:'http://paper.example.org/users/alice'},
  {webId,deletedAt:''}
 ]){
  const invalidLogin=await runLogin(record);
  await assert.rejects(invalidLogin.login(),
   e=>e?.code===401&&e?.type==='LOGIN_REQUIRED');
  assert.ok(!invalidLogin.ctx.meta.$responseHeaders?.['Set-Cookie'],
   'Refused/tombstoned account must never receive a session cookie');
 }

 console.log('PASS: verified bearer signature isolation, cookie password-version and owner tombstone, browser-only public grant approvals, no stale RS256 consent replay, verified email login');
}
main().catch(e=>{console.error(e?.stack||e);process.exitCode=1});
