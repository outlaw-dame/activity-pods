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
function context(header,cookie){
 const headers={};
 if(header!==undefined)headers.authorization=header;
 if(cookie!==undefined)headers.cookie='oauth_session='+encodeURIComponent(cookie);
 return {meta:{$headers:headers},calls:[],
  async call(action,p){
   this.calls.push(action);
   assert.equal(action,'auth.jwt.verifyServerSignedToken',
    'Never use auth.jwt.decodeToken to establish an OAuth owner identity');
   assert.deepEqual(Object.keys(p),['token']);
   return verifyServerToken(p.token);
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
 const cookie=service.buildSessionToken(webId);
 const ok=context('Bearer '+good);
 assert.equal(await service.requireUserWebId.call(service,ok),webId);
 assert.deepEqual(ok.calls,['auth.jwt.verifyServerSignedToken']);
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
 assert.deepEqual(cookieOnly.calls,[]);
 await rejected(context('Bearer invalid',cookie));
 console.log('PASS: OAuth bearer owner RS256 verified and <=1h old; forged, stale, unsigned, malformed and wrong identity claims denied; no invalid-bearer cookie fallback');
}
main().catch(e=>{console.error(e?.stack||e);process.exitCode=1});
