/**
 * NONACTIVATED, scoped ATProto record-write XRPC acceptance.
 *
 * This HTTP layer deliberately owns NO account, token, signing key, repo
 * or consent state. It requires trusted provider-injected OAuth/DPoP
 * authorization, ActivityPods key custody, canonical PG consent fencing,
 * signed reference-MST writer, and protected Jena projection readback.
 *
 * Restricted rollout: explicit rkey + swapCommit required for every
 * request. This is a safe subset of the ATProto create/put/delete lexicons,
 * NOT a full PDS or a deployed HTTP gateway.
 */
const DID=/^did:plc:[a-z2-7]{24}$/u;
const CID=/^bafyre[a-z2-7]{53}$/u;
const REV=/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const COLL=/^[a-z][a-z0-9]*(?:\.[a-z0-9][a-z0-9-]*){2,}$/u;
const RKEY=/^[A-Za-z0-9._~:-]{1,512}$/u;
const MAX_BODY=96*1024;
const METHODS=new Map([
  ['com.atproto.repo.createRecord','create'],
  ['com.atproto.repo.putRecord','put'],
  ['com.atproto.repo.deleteRecord','delete']
]);
function deny(code,status=503){
  const e=new Error('Hosted repository mutation unavailable');
  e.code=code;e.status=status;throw e;
}
function origin(value){
  try {
    const u=new URL(value);
    if(value!==u.origin||u.protocol!=='https:'||!u.hostname||
       u.username||u.password||u.search||u.hash) {
      deny('PDS_WRITE_CONFIGURATION_INVALID');
    }
    return value;
  }catch{deny('PDS_WRITE_CONFIGURATION_INVALID');}
}
function webId(value){
  try{
    const u=new URL(value);
    return typeof value==='string'&&value.length<=2048&&
      u.protocol==='https:'&&u.hostname&&u.href===value&&
      !u.username&&!u.password&&!u.search&&!u.hash;
  }catch{return false;}
}
function active(account,did,pdsOrigin){
  if(!account)deny('RepoNotFound',404);
  if(account.did!==did||!webId(account.webId)||
     account.activityPubActorId!==account.webId||
     account.pdsUrl!==pdsOrigin||account.atprotoManaged!==true||
     account.atprotoSource!=='local'||typeof account.handle!=='string') {
    deny('PDS_WRITE_HOSTING_NOT_FOUND',404);
  }
  if(account.status!=='active')deny('Forbidden',403);
  return account;
}
function same(a,b){
  return JSON.stringify([a.webId,a.activityPubActorId,a.did,a.handle,a.pdsUrl,
    a.atprotoManaged,a.atprotoSource,a.status])===
    JSON.stringify([b.webId,b.activityPubActorId,b.did,b.handle,b.pdsUrl,
      b.atprotoManaged,b.atprotoSource,b.status]);
}
function requestShape(body,action){
  if(!body||Array.isArray(body)||typeof body!=='object'){
    deny('InvalidRequest',400);
  }
  const allowed=new Set(['repo','collection','rkey','record','swapCommit','swapRecord']);
  if(Object.keys(body).some(k=>!allowed.has(k)) ||
     typeof body.repo!=='string'||!DID.test(body.repo) ||
     typeof body.collection!=='string'||!COLL.test(body.collection)||
     typeof body.rkey!=='string'||!RKEY.test(body.rkey)||
     typeof body.swapCommit!=='string'||!CID.test(body.swapCommit)||
     (body.swapRecord!==undefined&&body.swapRecord!==null&&
      (typeof body.swapRecord!=='string'||!CID.test(body.swapRecord)))) {
    deny('InvalidRequest',400);
  }
  if(action==='delete'){
    if(Object.hasOwn(body,'record'))deny('InvalidRequest',400);
  }else if(!body.record||typeof body.record!=='object'||
    Array.isArray(body.record)||body.record.$type!==body.collection) {
    deny('InvalidRequest',400);
  }
  if(action==='create'&&Object.hasOwn(body,'swapRecord')){
    deny('InvalidRequest',400);
  }
  return body;
}
async function json(req){
  const type=req.headers['content-type']||'';
  if(type!=='application/json'&&type!=='application/json; charset=utf-8') {
    deny('InvalidRequest',415);
  }
  const len=req.headers['content-length'];
  if(len!==undefined&&(!/^[0-9]+$/u.test(len)||Number(len)>MAX_BODY)){
    deny('InvalidRequest',413);
  }
  const chunks=[];let total=0;
  for await(const chunk of req){
    total+=chunk.length;
    if(total>MAX_BODY)deny('InvalidRequest',413);
    chunks.push(chunk);
  }
  if(total===0)deny('InvalidRequest',400);
  try{return JSON.parse(Buffer.concat(chunks,total).toString('utf8'));}
  catch{deny('InvalidRequest',400);}
}
function disabled(){
  deny('PDS_WRITE_NOT_RELEASED');
}
export function createAuthenticatedRecordWriteXrpc({
  pdsOrigin,resolveHostedAccount,authorizeOwner,
  resolveSigner,createFencedWriter,finalizeProjection,
  fixtureOnly=false
}={}){
  const released=()=>fixtureOnly===true&&
    process.env.NODE_ENV==='test'&&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_PDS_WRITE_TEST_DISPOSABLE==='confirmed';
  if(!released()){
    return Object.freeze({handle:async()=>disabled()});
  }
  const hostedOrigin=origin(pdsOrigin);
  if([resolveHostedAccount,authorizeOwner,resolveSigner,
    createFencedWriter,finalizeProjection].some(x=>typeof x!=='function')){
    deny('PDS_WRITE_CONFIGURATION_INVALID');
  }
  async function write(req,method){
    const body=requestShape(await json(req),method);
    const did=body.repo;
    // Actor selection comes only from the signed-in provider identity, NEVER
    // from the client-chosen record, account URL or arbitrary URL parameter.
    const before=active(await resolveHostedAccount({did}),did,hostedOrigin);
    const header=req.headers.authorization;
    const dpopProof=req.headers.dpop;
    if(typeof header!=='string'||
       !/^DPoP [A-Za-z0-9._~+\/-]{20,8192}={0,2}$/u.test(header)||
       typeof dpopProof!=='string'||
       !/^[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}$/u.test(dpopProof)){
      deny('AuthRequired',401);
    }
    // This provider callback MUST do actual OAuth audience/issuer, DPoP,
    // nonce, account and app-grant verification. The XRPC never decodes a
    // self-asserted JWT or trusts caller-provided consentRevision.
    const auth=await authorizeOwner({
      authorization:header,dpopProof,method:'POST',
      endpoint:'com.atproto.repo.'+(method==='put'?'putRecord':method+'Record'),
      did,webId:before.webId,collection:body.collection,
      action:method,requiredPermission:'atproto:record-write'
    });
    if(auth?.verified!==true||auth?.ownerDid!==did||
      auth?.ownerWebId!==before.webId||
      auth?.permission!=='atproto:record-write'||
      auth?.dpopVerified!==true||auth?.issuerVerified!==true||
      auth?.audienceVerified!==true||
      auth?.collection!==body.collection||auth?.action!==method||
      typeof auth?.recheck!=='function'||
      typeof auth?.appUri!=='string'||typeof auth?.grantUri!=='string'||
      typeof auth?.consentRevision!=='string') {
      deny('AuthRequired',401);
    }
    const key=await resolveSigner({accountId:before.webId,did});
    if(typeof key?.publicKeyPem!=='string'||key.publicKeyPem.length>4096||
      typeof key?.signer!=='function')deny('PDS_WRITE_SIGNER_UNAVAILABLE');
    const writer=await createFencedWriter({
      accountId:before.webId,did,appUri:auth.appUri,
      grantUri:auth.grantUri,consentRevision:auth.consentRevision
    });
    if(typeof writer?.verify!=='function'||typeof writer?.write!=='function'){
      deny('PDS_WRITE_WRITER_UNAVAILABLE');
    }
    // Cryptographically re-read actual signed PG head and MST record.
    const prior=await writer.verify({
      accountId:before.webId,did,publicKeyPem:key.publicKeyPem,
      path:body.collection+'/'+body.rkey
    });
    if(prior.commitCid!==body.swapCommit)deny('InvalidSwap',400);
    if(body.swapRecord!==undefined &&
       (body.swapRecord??null)!==(prior.recordCid??null)) {
      deny('InvalidSwap',400);
    }
    const action=method==='put'?(prior.recordCid===null?'create':'update'):method;
    if(action==='create'&&method==='create'&&prior.recordCid!==null){
      deny('RecordAlreadyExists',400);
    }
    if(method==='delete'&&prior.recordCid===null)deny('RecordNotFound',404);
    // Never automatically retry a signed commit after a transport or
    // uncertain COMMIT error. Client's explicit swapCommit makes a retry
    // discover a changed head rather than creating a second record.
    const mutation=await writer.write({
      accountId:before.webId,did,expectedCommitCid:prior.commitCid,
      expectedRev:prior.rev,action,path:body.collection+'/'+body.rkey,
      record:method==='delete'?null:body.record,
      signer:key.signer,publicKeyPem:key.publicKeyPem
    });
    if(mutation?.verified!==true||mutation.accountId!==before.webId||
      mutation.did!==did||!CID.test(mutation.commitCid||'')||
      !REV.test(mutation.rev||'')||
      (method!=='delete'&&!CID.test(mutation.recordCid||''))||
      (method==='delete'&&mutation.recordCid!==null)) {
      deny('PDS_WRITE_COMMIT_VERIFICATION_FAILED');
    }
    // The publisher/outbox & Jena projection are independently fenced.
    // If completion is uncertain, return 503: the mutation may already
    // have committed, but the caller must not retry it without new head CAS.
    const projected=await finalizeProjection({
      accountId:before.webId,did,commitCid:mutation.commitCid,
      rootCid:mutation.rootCid,rev:mutation.rev,
      generation:mutation.generation,appUri:auth.appUri,
      grantUri:auth.grantUri,consentRevision:auth.consentRevision
    });
    if(projected?.ready!==true||
      projected.commitCid!==mutation.commitCid||
      projected.rev!==mutation.rev||
      projected.accountId!==before.webId||projected.did!==did){
      deny('PDS_WRITE_PROJECTION_NOT_READY');
    }
    const after=active(await resolveHostedAccount({did}),did,hostedOrigin);
    if(!same(before,after))deny('PDS_WRITE_HOSTING_CHANGED');
    // The signed DPoP proof was verified ONCE and its jti/nonce consumed
    // atomically before the write. Rechecking the same proof here would
    // incorrectly raise a replay AFTER committing the signed record.
    // The provider returns a request-local closure that rereads token,
    // client consent and canonical PG revision without reusing the proof.
    const renewed=await auth.recheck();
    if(renewed?.verified!==true||renewed?.ownerDid!==did||
      renewed?.ownerWebId!==before.webId||
      renewed?.permission!=='atproto:record-write'||
      renewed?.dpopVerified!==true||renewed?.issuerVerified!==true||
      renewed?.audienceVerified!==true||
      renewed?.collection!==body.collection||
      renewed?.action!==method||
      renewed?.appUri!==auth.appUri||
      renewed?.grantUri!==auth.grantUri||
      renewed?.consentRevision!==auth.consentRevision){
      deny('PDS_WRITE_CONSENT_CHANGED');
    }
    const verified=await writer.verify({
      accountId:before.webId,did,publicKeyPem:key.publicKeyPem,
      path:body.collection+'/'+body.rkey
    });
    if(verified.commitCid!==mutation.commitCid||
      verified.rootCid!==mutation.rootCid||verified.rev!==mutation.rev||
      verified.generation!==mutation.generation||
      verified.recordCid!==mutation.recordCid){
      deny('PDS_WRITE_HEAD_CHANGED');
    }
    const commit={cid:mutation.commitCid,rev:mutation.rev};
    if(method==='delete')return {commit};
    return {uri:'at://'+did+'/'+body.collection+'/'+body.rkey,
      cid:mutation.recordCid,commit,validationStatus:'unknown'};
  }
  async function handle(req,res){
    try{
      if(!released())disabled();
      if(req.method!=='POST'||typeof req.url!=='string'||
         req.url.length>320||req.url.includes('?')||req.url.includes('#')){
        deny('InvalidRequest',400);
      }
      if(!req.url.startsWith('/xrpc/'))deny('MethodNotImplemented',404);
      const lexicon=req.url.slice('/xrpc/'.length);
      if(!METHODS.has(lexicon))deny('MethodNotImplemented',404);
      const result=await write(req,METHODS.get(lexicon));
      res.writeHead(200,{'content-type':'application/json; charset=utf-8',
        'cache-control':'no-store','x-content-type-options':'nosniff'});
      res.end(JSON.stringify(result));
    }catch(e){
      const code=typeof e?.code==='string'&&
        ['InvalidRequest','InvalidSwap','RecordAlreadyExists','RecordNotFound',
          'RepoNotFound','Forbidden',
          'AuthRequired','MethodNotImplemented'].includes(e.code)?e.code:
        'InternalError';
      const status=code==='InternalError'?503:
        Number.isInteger(e.status)?e.status:400;
      if(!res.headersSent){
        res.writeHead(status,{'content-type':'application/json; charset=utf-8',
          'cache-control':'no-store','x-content-type-options':'nosniff'});
      }
      res.end(JSON.stringify({error:code}));
    }
  }
  return Object.freeze({handle});
}
