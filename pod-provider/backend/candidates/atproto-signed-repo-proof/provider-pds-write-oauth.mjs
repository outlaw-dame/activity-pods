/**
 * NON-ACTIVATED trusted ActivityPods PDS write authorization bridge.
 *
 * Reuses the EXISTING provider OAuth token introspection (JWT signature,
 * issuer and audience), the EXISTING Redis-backed DPoP verifier (ath, nonce,
 * JWK thumbprint and jti replay), the EXISTING OAuth consent, and the
 * canonical PostgreSQL SAI grant. No token signer or shadow identity store.
 *
 * The resulting request-local recheck closure reads current OAuth/PG grants
 * without replaying the already-consumed DPoP proof, and is not serializable
 * or accepted from public request data. The PG writer also locks consent
 * in the SAME transaction as the signed repository mutation.
 */
const DID=/^did:plc:[a-z2-7]{24}$/u;
const COLLECTION=/^[a-z][a-z0-9]*(?:\.[a-z0-9][a-z0-9-]*){2,}$/u;
const TOKEN=/^DPoP ([A-Za-z0-9._~+\/-]{20,8192}={0,2})$/u;
const PROOF=/^[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}$/u;
const EPOCH=/^[1-9][0-9]{0,18}$/u;
function deny(code='PDS_OAUTH_NOT_AUTHORIZED'){
  const error=new Error('Provider authorization is unavailable');
  error.code=code;
  throw error;
}
function canonical(value){
  if(typeof value!=='string'||value.length<8||value.length>2048)
    return false;
  try{
    const u=new URL(value);
    return u.protocol==='https:'&&!u.username&&!u.password&&
      !u.search&&!u.hash&&u.hostname&&u.href===value;
  }catch{return false;}
}
function origin(value){
  if(!canonical(value+'/'))return false;
  try{return new URL(value).origin===value;}catch{return false;}
}
function scopeAllows(scope,collection,action){
  if(typeof scope!=='string'||scope.length>8192||
     !scope.split(/\s+/u).includes('atproto')) return false;
  const required=action==='put'?['create','update']:[action];
  if(required.some(x=>!['create','update','delete'].includes(x)))return false;
  const tokens=scope.split(/\s+/u);
  for(const token of tokens){
    if(!token.startsWith('repo:')&&!token.startsWith('repo?'))continue;
    const split=token.indexOf('?');
    const name=split<0?token:token.slice(0,split);
    const query=split<0?'':token.slice(split+1);
    let collections=[];
    if(name.startsWith('repo:')){
      const c=name.slice(5);
      if(!c||c.includes('%')||!(c==='*'||COLLECTION.test(c)))continue;
      collections=[c];
    }else if(name!=='repo')continue;
    const params=new URLSearchParams(query);
    if([...params.keys()].some(k=>k!=='collection'&&k!=='action'))continue;
    const declared=params.getAll('collection');
    if(name==='repo'){
      if(!declared.length||declared.length>32||
         declared.some(c=>c!=='*'&&!COLLECTION.test(c)))continue;
      collections=declared;
    }else if(declared.length)continue;
    const actions=params.getAll('action');
    if(actions.length>3||actions.some(a=>!['create','update','delete'].includes(a)))continue;
    if(collections.some(c=>c==='*'||c===collection)&&
       required.every(a=>actions.length===0||actions.includes(a)))return true;
  }
  return false;
}
export function createProviderPdsWriteAuthorization({
  call,readCanonicalGrant,approvedApps,resourceOrigin,
  fixtureOnly=false
}={}){
  const enabled=()=>fixtureOnly===true&&process.env.NODE_ENV==='test'&&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_PDS_WRITE_TEST_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_PDS_OAUTH_TEST_DISPOSABLE==='confirmed';
  if(!enabled())return Object.freeze({authorize:async()=>deny('PDS_OAUTH_NOT_RELEASED')});
  if(typeof call!=='function'||typeof readCanonicalGrant!=='function'||
     !origin(resourceOrigin)||!Array.isArray(approvedApps)||
     approvedApps.length<1||approvedApps.length>16) {
    deny('PDS_OAUTH_CONFIGURATION_INVALID');
  }
  const apps=new Map();
  for(const a of approvedApps){
    if(!canonical(a?.clientId)||!canonical(a?.appUri)||
       apps.has(a.clientId))deny('PDS_OAUTH_CONFIGURATION_INVALID');
    apps.set(a.clientId,a.appUri);
  }
  async function authorize({
    authorization,dpopProof,method,endpoint,did,webId,
    collection,action,requiredPermission
  }={}){
    if(!enabled())deny('PDS_OAUTH_NOT_RELEASED');
    const match=typeof authorization==='string'?TOKEN.exec(authorization):null;
    if(!match||typeof dpopProof!=='string'||!PROOF.test(dpopProof)||
       method!=='POST'||!DID.test(did||'')||!canonical(webId)||
       !COLLECTION.test(collection||'')||
       !['create','put','delete'].includes(action)||
       requiredPermission!=='atproto:record-write'||
       !['com.atproto.repo.createRecord','com.atproto.repo.putRecord',
         'com.atproto.repo.deleteRecord'].includes(endpoint)||
       endpoint!=='com.atproto.repo.'+(action==='put'?'putRecord':action+'Record')) {
      deny();
    }
    const token=match[1];
    // Signed JWT issuer/audience are checked inside the existing service.
    // Do not trust a decoded client-supplied JWT or an OAuth consent cache
    // alone. The introspection result is bound to the requested local DID.
    const info=await call('oauth-token.introspectAccessToken',{token});
    if(info?.active!==true||info.sub!==did||
       info.canonical_account_id!==webId||
       !apps.has(info.client_id)||typeof info.cnf?.jkt!=='string'||
       info.cnf.jkt.length!==43||!scopeAllows(info.scope,collection,action)){
      deny();
    }
    const clientId=info.client_id;
    const appUri=apps.get(clientId);
    const htu=resourceOrigin+'/xrpc/'+endpoint;
    // This is checked ONCE per real HTTP request. It atomically claims
    // the Redis jti and the issuer-provided nonce and verifies ath + cnf.
    // A second verifyProof call here would reject the valid request as
    // a DPoP replay after the signed commit had already happened.
    const proof=await call('oauth-dpop-nonce.verifyProof',{
      proofJwt:dpopProof,htm:'POST',htu,
      audience:resourceOrigin,accessToken:token,
      expectedJkt:info.cnf.jkt,requireNonce:true
    });
    if(proof?.jkt!==info.cnf.jkt)deny();
    const refresh=async()=>{
      if(!enabled())deny('PDS_OAUTH_NOT_RELEASED');
      const [latest,consent,grant]=await Promise.all([
        call('oauth-token.introspectAccessToken',{token}),
        call('oauth-consent.get',{canonicalAccountId:webId,clientId}),
        readCanonicalGrant({owner:webId,app:appUri})
      ]);
      if(latest?.active!==true||latest.sub!==did||
         latest.canonical_account_id!==webId||
         latest.client_id!==clientId||latest.cnf?.jkt!==proof.jkt||
         !scopeAllows(latest.scope,collection,action)||
         !consent||consent.revoked!==false||
         consent.canonicalAccountId!==webId||
         consent.clientId!==clientId||
         !scopeAllows(consent.scope,collection,action)||
         grant?.state!=='active'||
         grant?.identityState!=='active'||
         !canonical(grant.grantUri)||
         !EPOCH.test(String(grant.revision)))deny();
      return Object.freeze({verified:true,ownerDid:did,ownerWebId:webId,
        permission:'atproto:record-write',dpopVerified:true,
        issuerVerified:true,audienceVerified:true,
        appUri,grantUri:grant.grantUri,
        consentRevision:String(grant.revision),
        collection,action});
    };
    const verified=await refresh();
    return Object.freeze({...verified,recheck:refresh});
  }
  return Object.freeze({authorize});
}
