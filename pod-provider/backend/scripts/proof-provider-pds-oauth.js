'use strict';
/**
 * Real provider OAuth/DPoP + Redis 8.2 resource authorization proof.
 * Uses ACTUAL oauth-token.introspectAccessToken, oauth-dpop-nonce.verifyProof
 * and oauth-consent.get. The canonical PG grant is a fixture; the separate
 * signed PG18 writer proof owns concurrent SQL/revocation verification.
 */
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const Redis=require('ioredis');
const {
  SignJWT,generateKeyPair,exportJWK
}=require('jose');
const oauthToken=require('../services/oauth/oauth-token.service.js');
const oauthDpop=require('../services/oauth/oauth-dpop-nonce.service.js');
const oauthConsent=require('../services/oauth/oauth-consent.service.js');
const {pathToFileURL}=require('node:url');
const {resolve}=require('node:path');
const repo=process.env.ATPROTO_PDS_OAUTH_REDIS_URL||'';
if(process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_PDS_WRITE_TEST_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_PDS_OAUTH_TEST_DISPOSABLE!=='confirmed'||
   repo!=='redis://127.0.0.1:6398'){
  throw Error('Provider OAuth proof is restricted to disposable Redis 8.2');
}
const origin='https://pds.paper.example.org';
const clientId='https://writer.paper.example.org/oauth-client';
const appUri='https://writer.paper.example.org/app';
const webId='https://paper.example.org/users/oauth-proof';
const did='did:plc:'+'v'.repeat(24);
const collection='app.bsky.feed.post';
const allowedScope='atproto repo:'+collection+'?action=create&action=update&action=delete';
const path='/xrpc/com.atproto.repo.createRecord';
const htu=origin+path;
const grantUri=webId+'/data/grants/writer';
const error=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
const sha=token=>crypto.createHash('sha256').update(token,'ascii').digest('base64url');
async function main(){
 const redis=new Redis(repo,{
   connectTimeout:2500,maxRetriesPerRequest:1,
   retryStrategy:()=>null,lazyConnect:true
 });
 try{
   await redis.connect();
   assert.equal(await redis.ping(),'PONG');
   const version=String((await redis.info('server')).match(/redis_version:([^\r\n]+)/u)?.[1]||'');
   assert(version.startsWith('8.2.'),'Require real Redis 8.2 GETDEL/SET NX semantics');
   const namespace='paper:pds:oauth:proof:'+crypto.randomBytes(10).toString('hex');
   const dpopState={
     redis,
     settings:{
       noncePrefix:namespace+':nonce',
       replayPrefix:namespace+':jti',
       nonceTtlSec:120,replayTtlSec:300
     }
   };
   dpopState.consumeNonce=params=>oauthDpop.methods.consumeNonce.call(dpopState,params);
   const oauthState={redis,settings:{
     keyPrefix:namespace+':consent',ttlSec:1800
   }};
   const {privateKey:issuerKey,publicKey:issuerPub}=await generateKeyPair('ES256');
   const {privateKey:dpopKey,publicKey:dpopPub}=await generateKeyPair('ES256');
   const {privateKey:otherDpopKey,publicKey:otherDpopPub}=await generateKeyPair('ES256');
   const dpopJwk=await exportJWK(dpopPub);
   const otherJwk=await exportJWK(otherDpopPub);
   const {calculateJwkThumbprint}=require('jose');
   const jkt=await calculateJwkThumbprint(dpopJwk,'sha256');
   const issuerJwk=await exportJWK(issuerKey);
   const pubJwk=await exportJWK(issuerPub);
   issuerJwk.alg='ES256';pubJwk.alg='ES256';
   const issuer='https://paper.example.org';
   const tokenState={settings:{issuer,audience:origin,accessTtlSec:3600}};
   const jwkCtx={call:async name=>{
     assert.equal(name,'jwk.get');
     return {privateJwk:issuerJwk,publicJwk:pubJwk};
   }};
   const issue=async(scope=allowedScope,client=clientId,keyThumbprint=jkt,
     audienceOverride=origin,issuerOverride=issuer)=>{
     const session={
       sub:did,canonicalAccountId:webId,clientId:client,scope,
       dpopJkt:keyThumbprint
     };
     return oauthToken.methods.issueAccessToken.call({
       settings:{issuer:issuerOverride,audience:audienceOverride,accessTtlSec:3600}
     },session,jwkCtx);
   };
   const introspect=token=>oauthToken.actions.introspectAccessToken.handler.call(
     tokenState,{params:{token},call:jwkCtx.call});
   const nonce=async()=>(
     await oauthDpop.actions.mintNonce.handler.call(dpopState,{
       params:{audience:origin}
     })
   ).nonce;
   const sign=async({
     token,proofNonce,proofKey=dpopKey,jwk=dpopJwk,
     endpoint=htu,verb='POST',accessHash=sha(token),id=crypto.randomUUID()
   })=>new SignJWT({
     htm:verb,htu:endpoint,iat:Math.floor(Date.now()/1000),
     jti:id,nonce:proofNonce,ath:accessHash
   }).setProtectedHeader({typ:'dpop+jwt',alg:'ES256',jwk}).sign(proofKey);
   let pg={
     owner:webId,app:appUri,did,state:'active',
     grantUri,revision:'1'
   };
   const readCanonicalGrant=async({owner,app})=>
     owner===pg.owner&&app===pg.app?{...pg}:null;
   await oauthConsent.actions.upsert.handler.call(oauthState,{
     params:{canonicalAccountId:webId,clientId,scope:allowedScope}
   });
   let introspections=0,proofVerifications=0,grantReads=0;
   const call=async(name,args)=>{
     if(name==='oauth-token.introspectAccessToken'){
       introspections++;return introspect(args.token);
     }
     if(name==='oauth-dpop-nonce.verifyProof'){
       proofVerifications++;
       return oauthDpop.actions.verifyProof.handler.call(dpopState,
         {params:args});
     }
     if(name==='oauth-consent.get'){
       grantReads++;
       return oauthConsent.actions.get.handler.call(oauthState,{params:args});
     }
     throw Error('Unexpected OAuth service call');
   };
   const {createProviderPdsWriteAuthorization}=await import(
     pathToFileURL(resolve(__dirname,
       '../candidates/atproto-signed-repo-proof/provider-pds-write-oauth.mjs')).href
   );
   const candidate=createProviderPdsWriteAuthorization({
     call,readCanonicalGrant,resourceOrigin:origin,
     approvedApps:[{clientId,appUri}],fixtureOnly:true
   });
   const token=await issue();
   assert.equal((await introspect(token)).active,true);
   const params=(value,proof,action='create')=>({
     authorization:'DPoP '+value,dpopProof:proof,
     method:'POST',
     endpoint:'com.atproto.repo.'+
       (action==='put'?'putRecord':action+'Record'),
     did,webId,collection,action,requiredPermission:'atproto:record-write'
   });
   const signedProof=async(value=token,overrides={})=>sign({
     token:value,proofNonce:await nonce(),...overrides
   });
   const goodJti=crypto.randomUUID();
   const goodProof=await signedProof(token,{id:goodJti});
   const auth=await candidate.authorize(params(token,goodProof));
   assert.equal(auth.ownerDid,did);
   assert.equal(auth.ownerWebId,webId);
   assert.equal(auth.consentRevision,'1');
   assert.equal(auth.appUri,appUri);
   assert.equal(auth.grantUri,grantUri);
   assert.equal(auth.collection,collection);
   assert.equal(auth.action,'create');
   assert.equal(typeof auth.recheck,'function');
   const beforeRecheck=proofVerifications;
   assert.equal((await auth.recheck()).verified,true);
   assert.equal(proofVerifications,beforeRecheck,
     'post-commit authorization must not reuse already consumed DPoP proof');
   await error(candidate.authorize(params(token,goodProof)),'INVALID_DPOP_NONCE');
   // An attacker replaying the same jti with a new nonce is also rejected
   // by the separate shared Redis SET NX replay ledger.
   await error(candidate.authorize(params(token,await signedProof(token,{id:goodJti}))),
     'DPOP_REPLAY_DETECTED');

   const noAth=await signedProof(token,{accessHash:'A'.repeat(43)});
   await error(candidate.authorize(params(token,noAth)),'INVALID_DPOP_ATH');
   const forged=await signedProof(token,{proofKey:otherDpopKey,jwk:otherJwk});
   await error(candidate.authorize(params(token,forged)),'INVALID_DPOP_PROOF');
   const wrongTarget=await signedProof(token,{endpoint:origin+'/xrpc/evil'});
   await error(candidate.authorize(params(token,wrongTarget)),'INVALID_DPOP_PROOF');
   const wrongMethod=await signedProof(token,{verb:'GET'});
   await error(candidate.authorize(params(token,wrongMethod)),'INVALID_DPOP_PROOF');

   const onlyAtproto=await issue('atproto');
   await error(candidate.authorize(params(onlyAtproto,
     await signedProof(onlyAtproto))),'PDS_OAUTH_NOT_AUTHORIZED');
   const readOnly=await issue('atproto repo:'+collection+'?action=delete');
   await error(candidate.authorize(params(readOnly,
     await signedProof(readOnly))),'PDS_OAUTH_NOT_AUTHORIZED');
   const otherCollection=await issue('atproto repo:app.bsky.feed.like');
   await error(candidate.authorize(params(otherCollection,
     await signedProof(otherCollection))),'PDS_OAUTH_NOT_AUTHORIZED');

   const putProof=await signedProof(token,{endpoint:origin+'/xrpc/com.atproto.repo.putRecord'});
   assert.equal((await candidate.authorize(params(token,putProof,'put'))).action,'put');
   const deleteProof=await signedProof(token,{endpoint:origin+'/xrpc/com.atproto.repo.deleteRecord'});
   assert.equal((await candidate.authorize(params(token,deleteProof,'delete'))).action,'delete');
   // A revoked canonical PG consent invalidates the request-local closure,
   // regardless of a still cryptographically valid, unexpired token.
   pg={...pg,state:'blocked',revision:'2'};
   await error(auth.recheck(),'PDS_OAUTH_NOT_AUTHORIZED');
   pg={...pg,state:'active',revision:'3'};
   const freshProof=await signedProof();
   assert.equal((await candidate.authorize(params(token,freshProof))).consentRevision,'3');
   await oauthConsent.actions.revoke.handler.call(oauthState,{
     params:{canonicalAccountId:webId,clientId}
   });
   await error(auth.recheck(),'PDS_OAUTH_NOT_AUTHORIZED');
   await error(candidate.authorize(params(token,await signedProof())),
     'PDS_OAUTH_NOT_AUTHORIZED');

   // Atomic across replicas: exactly one can consume the minted nonce.
   const sameNonce=await nonce();
   const concurrent=await Promise.allSettled([
     dpopState.consumeNonce({audience:origin,nonce:sameNonce}),
     dpopState.consumeNonce({audience:origin,nonce:sameNonce})
   ]);
   assert.equal(concurrent.filter(x=>x.status==='fulfilled').length,1);
   assert.equal(concurrent.filter(x=>x.status==='rejected').length,1);

   const originalEnv=process.env.NODE_ENV;
   try{
     process.env.NODE_ENV='production';
     await error(auth.recheck(),'PDS_OAUTH_NOT_RELEASED');
     await error(candidate.authorize(params(token,await signedProof())),
       'PDS_OAUTH_NOT_RELEASED');
   }finally{process.env.NODE_ENV=originalEnv;}
   assert.equal(proofVerifications>=7,true);
   assert.equal(grantReads>1,true);
   console.log('PDS_OAUTH_DPOP_REDIS82_PROOF '+JSON.stringify({
     signedAccessToken:true,realDpopSignature:true,athBound:true,
     issuerAndAudienceVerified:true,nonceAtomicGetdel:true,
     replayAtomicNx:true,granularRepoScopes:true,
     collectionActionChecked:true,clientBound:true,
     canonicalConsentRechecked:true,postCommitDpopNotReplayed:true,
     productionFuseClosed:true,
     version,proofVerifications,introspections,grantReads
   }));
 }finally{
   await redis.quit().catch(()=>redis.disconnect());
 }
}
main().catch(e=>{
  console.error('PDS auth proof failed:',e?.code||e?.name,
    String(e?.message||'').slice(0,160));
  process.exitCode=1;
});
