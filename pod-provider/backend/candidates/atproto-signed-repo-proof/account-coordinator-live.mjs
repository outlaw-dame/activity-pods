/**
 * Real disposable PG18 + Jena TDB2 authenticated coordinator admission.
 * Independent worker A/B, restricted issuer and dataset admin subprocesses:
 *   app-bound HMAC -> PostgreSQL reserve/start -> issuer SQL admission
 *   -> Ed25519 claim -> Jena admin signature/claim ledger -> ordinary client.
 * A failed issuer RPC leaves the PG reservation irreversibly fenced.
 * No real WebID, SAI grant, or ATProto DID is created in this proof.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {Pool} from 'pg';
import client from '../../services/utils/atproto-account-coordinator-client.js';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {createDelegatedDisposableDataset}=require(
  '../../services/utils/atproto-dataset-admin-delegation.js');
import {verifyDisposableDatasetClaim} from './dataset-admin-claim-service.mjs';

const PHASE=process.argv[2];
const ROOT=process.env.ATPROTO_REPO_PROOF_DSN;
const TEMP=process.env.RUNNER_TEMP;
if(process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed'||
   process.env.FUSEKI_ISOLATION_URL!=='http://127.0.0.1:3041'||
   ROOT!=='postgres://paper_probe:probe_local_only@127.0.0.1:5548/atproto_signed_repo_proof_test'||
   !TEMP||!TEMP.startsWith('/')||
   !['prepare','verify','cleanup'].includes(PHASE)){
  throw Error('Authenticated coordinator proof is not released');
}
const META=path.join(TEMP,'paper-account-coordinator-fixture.json');
const ACCOUNT=path.join(TEMP,'paper-account-reservation-fixture.json');
const ADMIN=path.join(TEMP,'paper-dataset-admin-claim-fixture.json');
const PROVIDER_APP='https://app.paper.example/atlas';
const common=Object.freeze({
  NODE_ENV:'test',
  ATPROTO_REPO_PROOF_DISPOSABLE:'confirmed',
  ATPROTO_FUSEKI_ISOLATION_DISPOSABLE:'confirmed',
  FUSEKI_ISOLATION_URL:'http://127.0.0.1:3041',
  APODS_ACCOUNT_RESERVATION_DISPOSABLE:'confirmed',
  APODS_DATASET_CLAIM_ISSUER_DISPOSABLE:'confirmed',
  APODS_ACCOUNT_COORDINATOR_DISPOSABLE:'confirmed'
});
const pubEnv=secret=>({
  NODE_ENV:'test',ATPROTO_REPO_PROOF_DISPOSABLE:'confirmed',
  ATPROTO_FUSEKI_ISOLATION_DISPOSABLE:'confirmed',
  FUSEKI_ISOLATION_URL:'http://127.0.0.1:3041',
  APODS_ACCOUNT_RESERVATION_DISPOSABLE:'confirmed',
  APODS_ACCOUNT_COORDINATOR_DISPOSABLE:'confirmed',
  APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE:'confirmed',
  APODS_ACCOUNT_COORDINATOR_SHARED_KEY:secret
});
const dsn=(login,password)=>{
  const url=new URL(ROOT);
  url.username=login;url.password=password;
  return url.toString();
};
const fixture=async file=>{
  const value=JSON.parse(await fs.readFile(file,'utf8'));
  assert.equal(value.fixture,true);
  return value;
};
async function startAgent(filename,env,ready){
  const deny=[
    'ATPROTO_REPO_PROOF_DSN','PGUSER','PGPASSWORD','SEMAPPS_JENA_PASSWORD'
  ];
  assert(deny.every(k=>!Object.hasOwn(env,k)),
    'No fixture superuser credentials may enter isolated agents');
  const file=fileURLToPath(new URL(filename,import.meta.url));
  const child=spawn(process.execPath,[file],{
    env,stdio:['ignore','pipe','pipe']
  });
  let stdout='',stderr='',settled=false;
  try{
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{
        child.kill('SIGKILL');reject(Error('Isolated agent readiness timeout'));
      },12000);
      child.stdout.on('data',data=>{
        stdout=(stdout+String(data)).slice(-512);
        if(stdout.includes(ready)&&!settled){
          settled=true;clearTimeout(timer);resolve();
        }
      });
      child.stderr.on('data',data=>{
        stderr=(stderr+String(data)).slice(-512);
      });
      child.once('error',err=>{
        clearTimeout(timer);reject(err);
      });
      child.once('exit',code=>{
        if(!settled){
          clearTimeout(timer);
          reject(Error('Isolated agent exited '+code+': '+stderr.slice(-100)));
        }
      });
    });
    return child;
  }catch(error){
    child.kill('SIGKILL');
    throw error;
  }
}
async function stopAgent(child){
  if(!child||child.exitCode!==null||child.signalCode!==null)return;
  await new Promise(resolve=>{
    const timer=setTimeout(()=>{child.kill('SIGKILL');},3000);
    child.once('exit',()=>{clearTimeout(timer);resolve();});
    child.kill('SIGTERM');
  });
}
function serverEnv(state,account,admin){
  const pem=state.publicPem;
  return {
    issuer:{...common,
      ACCOUNT_ISSUER_DSN:dsn('paper_account_issuer_login',account.issuerPassword),
      ACCOUNT_ISSUER_SIGNING_PEM_B64:state.privatePemB64,
      ACCOUNT_COORDINATOR_ISSUER_KEY:state.issuerKey
    },
    workerA:{...common,
      ACCOUNT_COORDINATOR_WORKER_DSN:dsn('paper_account_worker_login',account.workerPassword),
      ACCOUNT_COORDINATOR_SHARED_KEY:state.providerKey,
      ACCOUNT_COORDINATOR_ISSUER_KEY:state.issuerKey,
      ACCOUNT_ISSUER_PUBLIC_PEM_B64:Buffer.from(pem).toString('base64'),
      ACCOUNT_COORDINATOR_PORT:'3043'
    },
    workerB:{...common,
      ACCOUNT_COORDINATOR_WORKER_DSN:dsn('paper_account_worker_login',account.workerPassword),
      ACCOUNT_COORDINATOR_SHARED_KEY:state.providerKey,
      ACCOUNT_COORDINATOR_ISSUER_KEY:state.issuerKey,
      ACCOUNT_ISSUER_PUBLIC_PEM_B64:Buffer.from(pem).toString('base64'),
      ACCOUNT_COORDINATOR_PORT:'3044'
    },
    datasetAdmin:{
      NODE_ENV:'test',
      ATPROTO_REPO_PROOF_DISPOSABLE:'confirmed',
      ATPROTO_FUSEKI_ISOLATION_DISPOSABLE:'confirmed',
      FUSEKI_ISOLATION_URL:'http://127.0.0.1:3041',
      DATASET_ADMIN_FUSEKI_USER:'fixture-provisioner',
      DATASET_ADMIN_FUSEKI_PASSWORD:'fixture-admin-only',
      PAPER_LOCAL_POD_DATA_PASSWORD:'fixture-ordinary-only',
      DATASET_ADMIN_AGENT_DSN:dsn('paper_dataset_admin_login',admin.password),
      DATASET_ADMIN_ISSUER_PUBLIC_PEM:Buffer.from(pem).toString('base64')
    }
  };
}
async function startAll(state,account,admin){
  const env=serverEnv(state,account,admin),kids=[];
  try{
    kids.push(await startAgent('./account-coordinator-issuer-http.mjs',
      env.issuer,'ACCOUNT_CLAIM_ISSUER_READY'));
    kids.push(await startAgent('./account-coordinator-worker-http.mjs',
      env.workerA,'ACCOUNT_COORDINATOR_READY'));
    kids.push(await startAgent('./account-coordinator-worker-http.mjs',
      env.workerB,'ACCOUNT_COORDINATOR_READY'));
    kids.push(await startAgent('./dataset-admin-claim-child.mjs',
      env.datasetAdmin,'DATASET_ADMIN_AGENT_READY'));
    return kids;
  }catch(e){for(const kid of kids.reverse())await stopAgent(kid);throw e;}
}
const makeGrant=(state,username,key,fp)=>Object.freeze({
  allowed:true,approvedApp:true,verifiedUser:true,
  capabilityId:'provider.account.provisioning',
  appClientId:PROVIDER_APP,username,
  idempotencyKey:key,requestFingerprint:fp,dailyLimit:3
});
const makeInput=label=>({
  username:'claimtest-'+crypto.randomBytes(6).toString('hex'),
  key:crypto.randomBytes(16).toString('hex'),
  fp:crypto.createHash('sha256').update('disposable:'+label+':'+crypto.randomUUID())
    .digest('hex')
});
const pool=new Pool({connectionString:ROOT,max:2,
  connectionTimeoutMillis:3000,query_timeout:8000,allowExitOnIdle:true});
const appScope=crypto.createHash('sha256')
  .update('activitypods:approved-app:v1\0').update(PROVIDER_APP).digest('hex');
async function signedPost(port,message,key,valid=true,route='/v1/reserve',domain='client'){
  const raw=JSON.stringify(message);
  const mac=valid?client.computeMac(key,domain,raw):
    crypto.randomBytes(32).toString('base64url');
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),5000);
  try{
    const resp=await fetch('http://127.0.0.1:'+port+route,{
      method:'POST',redirect:'manual',signal:controller.signal,
      headers:{'content-type':'application/json','x-paper-auth':mac},
      body:raw
    });
    assert(Number.isInteger(resp.status));
    const body=await resp.text();
    assert(Buffer.byteLength(body)<=2048);
    return{status:resp.status,body};
  }finally{clearTimeout(timer);}
}
const msg=(state,item,overrides={})=>({
  version:1,appScope,username:item.username,idempotencyKey:item.key,
  requestFingerprint:item.fp,dailyLimit:3,issuedAtMs:Date.now(),
  nonce:crypto.randomUUID(),...overrides
});
async function readReservation(id){
  const result=await pool.query(
    'SELECT reservation_id,state,username,expected_webid,atproto_did,signup_claimed_at '+
    'FROM paper_account_reservation_proof.reservations '+
    'WHERE reservation_id=$1',[id]);
  assert.equal(result.rowCount,1);
  return result.rows[0];
}
async function verifyJena(ticket,env){
  const result=await createDelegatedDisposableDataset({
    dataset:ticket.claim.dataset,ticket,env,now:Date.now()
  });
  assert.equal(result.created,true);
  return result;
}
async function prepare(){
  const account=await fixture(ACCOUNT),admin=await fixture(ADMIN);
  const keys=crypto.generateKeyPairSync('ed25519');
  const state={
    fixture:true,
    providerKey:crypto.randomBytes(32).toString('base64url'),
    issuerKey:crypto.randomBytes(32).toString('base64url'),
    publicPem:keys.publicKey.export({format:'pem',type:'spki'}).toString(),
    privatePemB64:Buffer.from(keys.privateKey.export({
      format:'pem',type:'pkcs8'})).toString('base64'),
    primary:makeInput('primary'),uncertain:makeInput('uncertain')
  };
  let kids=[];
  try{
    kids=await startAll(state,account,admin);
    const grant=makeGrant(state,state.primary.username,
      state.primary.key,state.primary.fp);
    const result=await client.reserveCoordinatedDataset({
      grant,username:state.primary.username,
      appClientId:PROVIDER_APP,env:pubEnv(state.providerKey)
    });
    assert.equal(result.ticket.claim.dataset,state.primary.username);
    const verified=verifyDisposableDatasetClaim(result.ticket,
      crypto.createPublicKey(state.publicPem));
    state.primary.ticket=result.ticket;
    state.primary.admission=result.admission;
    state.primary.reservationId=verified.reservationId;
    const before=await readReservation(verified.reservationId);
    assert.equal(before.state,'side_effects_started');
    assert.equal(before.username,state.primary.username);
    assert.equal(before.expected_webid,
      'https://paper.example.org/'+state.primary.username);
    assert.equal(before.signup_claimed_at,null,
      'Dataset claim issuance is not itself identity-execution admission');
    // The actual auth.signup calls the same scoped ordinary-provider client
    // to consume this one-time PG CAS before its first identity side effect.
    assert.deepEqual(await client.consumeCoordinatedSignup({
      ticket:result.ticket,admission:result.admission,
      dataset:state.primary.username,env:pubEnv(state.providerKey)
    }),{admitted:true});
    const consumed=await readReservation(verified.reservationId);
    assert(consumed.signup_claimed_at instanceof Date,
      'The actual one-time signup CAS must have become durable');
    await assert.rejects(client.consumeCoordinatedSignup({
      ticket:result.ticket,admission:result.admission,
      dataset:state.primary.username,env:pubEnv(state.providerKey)
    }),e=>e?.code==='ACCOUNT_COORDINATOR_INVOCATION_ALREADY_CLAIMED');
    // Only the separate dataset admin holds Jena credentials; the ordinary
    // client receives this signed ticket and a fixed network endpoint.
    assert.equal((await verifyJena(result.ticket,pubEnv(state.providerKey))).idempotent,false);
    assert.equal((await verifyJena(result.ticket,pubEnv(state.providerKey))).idempotent,true);

    const replay=await signedPost(3044,msg(state,state.primary),state.providerKey);
    assert.equal(replay.status,409,'Other worker cell cannot acquire a new DID fence');
    const scope=state.primary.admission;
    const replayConsume=await signedPost(3044,{
      version:1,appScope:scope.appScope,username:scope.username,
      idempotencyKey:scope.idempotencyKey,
      requestFingerprint:scope.requestFingerprint,
      reservationId:scope.reservationId,ticket:state.primary.ticket,
      issuedAtMs:Date.now(),nonce:crypto.randomUUID()
    },state.providerKey,true,'/v1/consume','consume');
    assert.equal(replayConsume.status,409,
      'Other worker must not execute the same WebID/DID signup a second time');
    const tampered=await signedPost(3044,msg(state,state.primary),state.providerKey,false);
    assert.equal(tampered.status,403,'Missing/incorrect service MAC rejected');
    const forgedInput=msg(state,state.primary,{appScope:'f'.repeat(64)});
    const forgery=await signedPost(3044,forgedInput,state.providerKey,false);
    assert.equal(forgery.status,403,'Untrusted app scope cannot reach PG');
    const badEnv={...pubEnv(state.providerKey),ATPROTO_REPO_PROOF_DSN:ROOT};
    await assert.rejects(
      client.reserveCoordinatedDataset({
        grant,username:state.primary.username,appClientId:PROVIDER_APP,env:badEnv
      }),e=>e?.code==='ACCOUNT_COORDINATOR_NOT_RELEASED');

    // Induce an issuer-outage uncertainty *after* the PG fence commits.
    await stopAgent(kids[0]);kids[0]=null;
    const missing=makeGrant(state,state.uncertain.username,
      state.uncertain.key,state.uncertain.fp);
    await assert.rejects(
      client.reserveCoordinatedDataset({
        grant:missing,username:state.uncertain.username,
        appClientId:PROVIDER_APP,env:pubEnv(state.providerKey)
      }),e=>e?.code==='ACCOUNT_COORDINATOR_UNAVAILABLE');
    const rows=await pool.query(
      'SELECT state,reservation_id FROM paper_account_reservation_proof.reservations '+
      'WHERE username=$1',[state.uncertain.username]);
    assert.equal(rows.rowCount,1);
    assert.equal(rows.rows[0].state,'side_effects_started');
    state.uncertain.reservationId=rows.rows[0].reservation_id;
    await fs.writeFile(META,JSON.stringify(state),{mode:0o600,flag:'wx'});
    console.log('AUTH_COORDINATOR '+JSON.stringify({
      phase:'prepare',independentWorkers:2,
      appAuthenticatedMac:true,realPg18:true,
      separateIssuerKey:true,realJenaDataset:true,
      crossReplicaDuplicateDenied:true,oneTimeSignupExecution:true,
      forgedMacDenied:true,
      issuerFailureFencePreserved:true,productionReleased:false
    }));
  }finally{for(const kid of kids.reverse())await stopAgent(kid);}
}
async function verify(){
  const state=await fixture(META);
  const account=await fixture(ACCOUNT),admin=await fixture(ADMIN);
  let kids=[];
  try{
    kids=await startAll(state,account,admin);
    const replay=await signedPost(3044,msg(state,state.primary),state.providerKey);
    assert.equal(replay.status,409,'A restart must not obtain a second fence');
    const uncertain=await signedPost(3043,msg(state,state.uncertain),state.providerKey);
    assert.equal(uncertain.status,409,
      'Unknown issuer outcome cannot be converted to new identity');
    const first=await readReservation(state.primary.reservationId);
    const second=await readReservation(state.uncertain.reservationId);
    assert.equal(first.state,'side_effects_started');
    assert.equal(second.state,'side_effects_started');
    assert(first.signup_claimed_at instanceof Date);
    assert.equal(second.signup_claimed_at,null);
    assert.equal(first.atproto_did,null);
    assert.equal(second.atproto_did,null);
    assert.equal((await verifyJena(state.primary.ticket,
      pubEnv(state.providerKey))).idempotent,true,
      'Jena must verify identical immutable claim after process restart');
    console.log('AUTH_COORDINATOR '+JSON.stringify({
      phase:'verify',freshIndependentProcesses:true,
      crossReplicaReplayDenied:true,oneTimeSignupReentryDenied:true,
      unknownStateNoTakeover:true,
      persistentJenaTicketIdempotent:true,productionReleased:false
    }));
  }finally{for(const kid of kids.reverse())await stopAgent(kid);}
}
async function cleanup(){
  await fs.rm(META,{force:true});
  console.log('AUTH_COORDINATOR '+JSON.stringify({
    phase:'cleanup',ephemeralCredentialsRemoved:true,
    productionReleased:false
  }));
}
try{
  if(PHASE==='prepare')await prepare();
  if(PHASE==='verify')await verify();
  if(PHASE==='cleanup')await cleanup();
}finally{await pool.end();}
