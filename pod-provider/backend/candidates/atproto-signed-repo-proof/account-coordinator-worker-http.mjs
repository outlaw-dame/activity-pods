/**
 * Separate authenticated PostgreSQL reservation coordinator.
 * HMAC is a provider-to-worker service credential; app authorization was
 * independently performed by provider-capabilities before this request.
 * This process cannot sign Ed25519 tickets or administer Jena.
 */
import { ownerWebId } from '../../services/utils/disposable-provider-identity.js';
import assert from 'node:assert/strict';
import {loadCanonicalCoordinator} from './canonical-coordinator-config.mjs';
import crypto from 'node:crypto';
import {Pool} from 'pg';
import wire from '../../services/utils/atproto-account-coordinator-client.js';
import {makeAccountReservationAuthority,
  assertRestrictedAccountProofLogin} from './account-reservation-authority.mjs';
import {verifyDisposableDatasetClaim} from './dataset-admin-claim-service.mjs';
import {server,readRequest,respond,exact,refuse,checkFixtureEnv}
  from './account-coordinator-http.mjs';

const KEYS=[
 'NODE_ENV','ATPROTO_REPO_PROOF_DISPOSABLE','ATPROTO_FUSEKI_ISOLATION_DISPOSABLE',
 'FUSEKI_ISOLATION_URL','APODS_ACCOUNT_RESERVATION_DISPOSABLE',
 'APODS_DATASET_CLAIM_ISSUER_DISPOSABLE','APODS_ACCOUNT_COORDINATOR_DISPOSABLE',
 'ACCOUNT_COORDINATOR_WORKER_DSN','ACCOUNT_COORDINATOR_SHARED_KEY',
 'ACCOUNT_COORDINATOR_ISSUER_KEY','ACCOUNT_ISSUER_PUBLIC_PEM_B64',
 'ACCOUNT_COORDINATOR_PORT'
];
if(process.env.ACCOUNT_COORDINATOR_CANONICAL_CONFIG) KEYS.push('ACCOUNT_COORDINATOR_CANONICAL_CONFIG','PAPER_ACCOUNTS_DISPOSABLE');
checkFixtureEnv('worker',KEYS);
const canonical=process.env.ACCOUNT_COORDINATOR_CANONICAL_CONFIG
  ? await loadCanonicalCoordinator(process.env.ACCOUNT_COORDINATOR_CANONICAL_CONFIG) : null;
const url=new URL(process.env.ACCOUNT_COORDINATOR_WORKER_DSN);
assert.equal(url.hostname,'127.0.0.1');
assert.equal(url.port,'5548');
assert.equal(url.pathname,'/atproto_signed_repo_proof_test');
assert.equal(url.username,'paper_account_worker_login');
const providerSecret=process.env.ACCOUNT_COORDINATOR_SHARED_KEY;
const issuerSecret=process.env.ACCOUNT_COORDINATOR_ISSUER_KEY;
wire.parseSecret(providerSecret);
wire.parseSecret(issuerSecret);
const publicKey=crypto.createPublicKey({
  key:Buffer.from(process.env.ACCOUNT_ISSUER_PUBLIC_PEM_B64,'base64'),
  format:'pem',type:'spki'
});
const pool=new Pool({connectionString:url.toString(),max:4,
  connectionTimeoutMillis:3000,query_timeout:5000,
  idleTimeoutMillis:2000,allowExitOnIdle:true});
await assertRestrictedAccountProofLogin(pool,'worker');
const authority=makeAccountReservationAuthority({workerPool:pool});
const keys=['version','appScope','username','idempotencyKey',
  'requestFingerprint','dailyLimit','issuedAtMs','nonce'];

async function readIssuerBounded(reply){
  const len=reply.headers.get('content-length');
  if(len!==null && (!/^[0-9]{1,4}$/u.test(len) || Number(len)>2048))refuse();
  if(!reply.body?.getReader)refuse();
  const reader=reply.body.getReader();
  const parts=[];let total=0;
  try{
    for(;;){
      const next=await reader.read();
      if(next.done)break;
      total+=next.value.byteLength;
      if(total>2048)refuse();
      parts.push(Buffer.from(next.value));
    }
  }finally{
    await reader.cancel().catch(()=>{});
    reader.releaseLock();
  }
  if(!total)refuse();
  return Buffer.concat(parts,total).toString('utf8');
}
async function requestIssuer(fence,dataset){
  const body=JSON.stringify({
    version:1,fence,dataset,issuedAtMs:Date.now(),nonce:crypto.randomUUID()
  });
  const mac=wire.computeMac(issuerSecret,'issuer',body);
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),5000);
  try{
    const reply=await fetch('http://127.0.0.1:3045/v1/issue',{
      method:'POST',redirect:'manual',signal:controller.signal,
      headers:{'content-type':'application/json','x-paper-auth':mac},
      body
    });
    if(reply.status!==200)refuse();
    const raw=await readIssuerBounded(reply);
    if(!wire.verifyMac(issuerSecret,'issuer-response',raw,
         reply.headers.get('x-paper-auth')))refuse();
    const parsed=JSON.parse(raw);
    if(!exact(parsed,['ticket']))refuse();
    const verified=verifyDisposableDatasetClaim(parsed.ticket,publicKey);
    if(verified.dataset!==dataset ||
       verified.reservationId!==fence.reservationId)refuse();
    return parsed.ticket;
  }catch{refuse();}finally{clearTimeout(timer);}
}
const workerPort=Number(process.env.ACCOUNT_COORDINATOR_PORT);
assert([3043,3044].includes(workerPort),'Only fixed disposable worker ports are allowed');
const listener=await server({port:workerPort,handler:async(req,res)=>{
  if(req.url==='/v1/consume'){
    const scope=await readRequest(req,{
      domain:'consume',secret:providerSecret,route:'/v1/consume',
      keys:[
        'version','appScope','username','idempotencyKey',
        'requestFingerprint','reservationId','ticket','issuedAtMs','nonce'
      ]
    });
    if(scope.version!==1||!Number.isSafeInteger(scope.issuedAtMs)||
       Math.abs(Date.now()-scope.issuedAtMs)>30000 ||
       !/^[a-f0-9]{64}$/.test(scope.appScope||'') ||
       !/^[a-f0-9]{64}$/.test(scope.requestFingerprint||'') ||
       !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(scope.nonce||'')){
      refuse();
    }
    let verified;
    try{verified=verifyDisposableDatasetClaim(scope.ticket,publicKey);}
    catch{refuse();}
    if(verified.dataset!==scope.username ||
       verified.ownerWebid!==ownerWebId(scope.username) ||
       verified.reservationId!==scope.reservationId)refuse();
    const claimed=await authority.claimSignup({
      appClientId:scope.appScope,
      idempotencyKey:scope.idempotencyKey,
      requestFingerprint:scope.requestFingerprint,
      username:scope.username,reservationId:scope.reservationId
    });
    if(!claimed)refuse(409);
    // The signed acknowledgment is specific to exactly this consumed
    // request. An older successful HTTP response has a valid service MAC,
    // but its request digest and nonce cannot authorize a new attempt.
    respond(res,200,{
      admitted:true,
      requestSha256:crypto.createHash('sha256')
        .update(JSON.stringify(scope),'utf8').digest('hex'),
      reservationId:scope.reservationId,
      nonce:scope.nonce
    },{
      secret:providerSecret,domain:'consume-response'
    });
    return;
  }
  const input=await readRequest(req,{
    domain:'client',secret:providerSecret,
    route:'/v1/reserve',keys
  });
  wire.validateMessage(input);
  const details={
    appClientId:input.appScope,
    username:input.username,
    idempotencyKey:input.idempotencyKey,
    requestFingerprint:input.requestFingerprint,
    dailyLimit:input.dailyLimit
  };
  const first=await authority.reserve(details);
  if(first.outcome!=='reserved' || !first.fenceToken)refuse(409);
  const fence={appClientId:input.appScope,
    idempotencyKey:input.idempotencyKey,
    reservationId:first.reservationId,fenceToken:first.fenceToken};
  if(!(await authority.startSideEffects(fence)))refuse();
  // A crash or request timeout here does NOT release the fence; retry
  // returns 409 pending reconciliation rather than minting a second DID.
  const admission={
    appScope:input.appScope,
    username:input.username,
    idempotencyKey:input.idempotencyKey,
    requestFingerprint:input.requestFingerprint,
    reservationId:first.reservationId
  };
  if(canonical) await canonical.admit(admission);
  if(res.destroyed) return;
  const ticket=await requestIssuer(fence,input.username);
  respond(res,200,{
    ticket,admission,
    requestSha256:crypto.createHash('sha256')
      .update(JSON.stringify(input),'utf8').digest('hex'),
    nonce:input.nonce
  },{
    secret:providerSecret,domain:'worker-response'
  });
}});
process.stdout.write('ACCOUNT_COORDINATOR_READY\n');
for(const signal of ['SIGTERM','SIGINT']){
  process.once(signal,()=>listener.close(()=>Promise.allSettled([pool.end(),canonical?.close()]).finally(()=>process.exit(0))));
}
