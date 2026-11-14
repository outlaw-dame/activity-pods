/**
 * Exact-scoped disposable PostgreSQL 18 + Jena admin credential extraction.
 * prepare: issue a real Ed25519 claim and prove concurrent, replay-safe
 *          dataset provisioning in a separate admin-key-holding process.
 * verify:  replay the committed claim in a newly started process after
 *          persistent Jena restart. No user account is created.
 * cleanup: drop temporary SQL identity/claim records and role.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {Pool} from 'pg';
import {signDisposableDatasetClaim,assertRestrictedDatasetAdminLogin} from './dataset-admin-claim-service.mjs';

const PHASE=process.argv[2];
const ROOT='http://127.0.0.1:3042/v1/provision';
const DSN=process.env.ATPROTO_REPO_PROOF_DSN;
const FLAG=process.env.NODE_ENV==='test'&&
 process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE==='confirmed'&&
 process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
 process.env.FUSEKI_ISOLATION_URL==='http://127.0.0.1:3041'&&
 /^postgres:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN||'')&&
 typeof process.env.RUNNER_TEMP==='string'&&
 process.env.RUNNER_TEMP.startsWith('/');
if(!FLAG||!['prepare','verify','cleanup'].includes(PHASE)){
 throw Error('Separate dataset administration proof must stay disposable');
}
const META=path.join(process.env.RUNNER_TEMP,
  'paper-dataset-admin-claim-fixture.json');
const admin=new Pool({connectionString:DSN,max:2,
 connectionTimeoutMillis:3000,query_timeout:8000,
 idleTimeoutMillis:2000,allowExitOnIdle:true});
function role(name){
 if(!/^[a-z][a-z0-9_]{0,62}$/u.test(name))throw Error('Unsafe fixture role');
 return '"'+name+'"';
}
function restrictedDsn(password){
 const u=new URL(DSN);
 u.username='paper_dataset_admin_login';
 u.password=password;
 return u.toString();
}
async function load(){
 const obj=JSON.parse(await fs.readFile(META,'utf8'));
 if(obj.fixture!==true||obj.dataset?.startsWith('claimtest-')!==true||
    !obj.password||!obj.ticket||!obj.publicKey)throw Error('Invalid fixture');
 return obj;
}
async function childProcess(config){
 const file=fileURLToPath(new URL('./dataset-admin-claim-child.mjs',import.meta.url));
 // An admin subprocess must NOT inherit the test harness's superuser
 // PostgreSQL DSN, account-signing keys, transport secrets or provider
 // environment. Build a positive allowlist, never spread process.env.
 const env={
  NODE_ENV:'test',
  ATPROTO_REPO_PROOF_DISPOSABLE:'confirmed',
  ATPROTO_FUSEKI_ISOLATION_DISPOSABLE:'confirmed',
  FUSEKI_ISOLATION_URL:'http://127.0.0.1:3041',
  DATASET_ADMIN_FUSEKI_USER:'admin',
  DATASET_ADMIN_FUSEKI_PASSWORD:'fixture-admin-only',
  DATASET_ADMIN_AGENT_DSN:restrictedDsn(config.password),
  DATASET_ADMIN_ISSUER_PUBLIC_PEM:Buffer.from(config.publicKey).toString('base64')
 };
 const deniedEnvironment=[
  'ATPROTO_REPO_PROOF_DSN','PGPASSWORD','PGUSER','PGHOST',
  'SEMAPPS_JENA_PASSWORD','DATASET_ADMIN_SIGNER_PRIVATE_KEY'
 ];
 assert(deniedEnvironment.every(key=>!Object.hasOwn(env,key)),
   'Privileged fixture credentials must never enter the administrator child');
 const child=spawn(process.execPath,[file],{env,stdio:['ignore','pipe','pipe']});
 let resolved=false,output='',failure='';
 const started=new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(Error('Agent startup timeout')),15000);
  child.stdout.on('data',chunk=>{
   output+=String(chunk).slice(0,512);
   if(output.includes('DATASET_ADMIN_AGENT_READY')&&!resolved){
    resolved=true;clearTimeout(timer);resolve();
   }
  });
  child.stderr.on('data',chunk=>{failure+=String(chunk).slice(0,512);});
  child.once('exit',code=>{
   if(!resolved){clearTimeout(timer);reject(Error(
    'Agent exited before ready; status '+code+' '+failure.slice(0,120)));}
  });
 });
 try{await started;}catch(error){
  child.kill('SIGKILL');throw error;
 }
 return child;
}
async function stop(child){
 if(child.exitCode!==null)return;
 const stopped=new Promise(resolve=>{
  child.once('exit',resolve);
  setTimeout(()=>{if(child.exitCode===null)child.kill('SIGKILL');},3000);
 });
 child.kill('SIGTERM');
 await stopped;
}
async function runOrdinaryProviderClient(config,mode){
 // The ordinary backend cannot inherit the harness PG admin DSN, Jena
 // admin password, issuer private key, trusted attestor, or projector.
 const file=fileURLToPath(new URL(
   './dataset-admin-ordinary-client-child.mjs',import.meta.url));
 const env={
  NODE_ENV:'test',ATPROTO_REPO_PROOF_DISPOSABLE:'confirmed',
  ATPROTO_FUSEKI_ISOLATION_DISPOSABLE:'confirmed',
  FUSEKI_ISOLATION_URL:'http://127.0.0.1:3041',
  APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE:'confirmed',
  DATASET_ADMIN_ORDINARY_MODE:mode,
  DATASET_ADMIN_ORDINARY_TICKET:Buffer.from(
    JSON.stringify(config.ticket),'utf8').toString('base64')
 };
 assert.equal(Object.hasOwn(env,'ATPROTO_REPO_PROOF_DSN'),false);
 assert.equal(Object.hasOwn(env,'DATASET_ADMIN_FUSEKI_PASSWORD'),false);
 assert.equal(Object.hasOwn(env,'DATASET_ADMIN_SIGNER_PRIVATE_KEY'),false);
 const child=spawn(process.execPath,[file],{
  env,stdio:['ignore','pipe','pipe']
 });
 let stdout='',stderr='';
 const result=await new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>{
   child.kill('SIGKILL');
   reject(Error('Ordinary provider request exceeded its 12s bound'));
  },12000);
  child.stdout.on('data',part=>{
   stdout=(stdout+String(part)).slice(-1024);
  });
  child.stderr.on('data',part=>{
   stderr=(stderr+String(part)).slice(-512);
  });
  child.once('error',err=>{clearTimeout(timer);reject(err);});
  child.once('exit',code=>{clearTimeout(timer);resolve(code);});
 });
 assert.equal(result,0,'Ordinary provider proof failed: '+stderr.slice(0,100));
 const proof=stdout.split('\\n').find(line=>
  line.startsWith('ORDINARY_PROVIDER_DATASET_DELEGATION '));
 assert(proof,'Missing ordinary provider admission receipt');
 const observed=JSON.parse(proof.slice(
  'ORDINARY_PROVIDER_DATASET_DELEGATION '.length));
 assert.equal(observed.mode,mode);
 assert.equal(observed.productionStorageReleased,false);
 return observed;
}
async function post(ticket,{method='POST',oversize=false}={}){
 const controller=new AbortController();
 const timer=setTimeout(()=>controller.abort(),8000);
 try{
  const body=JSON.stringify({ticket});
  const res=await fetch(ROOT,{
   method,headers:{'content-type':'application/json'},
   body:method==='POST'?(oversize?'X'.repeat(5000):body):undefined,
   signal:controller.signal,redirect:'manual'
  });
  const response=await res.text();
  assert(response.length<=1000,'No unsafe response body');
  assert(!response.includes('fixture-admin-only'),'Admin password must never appear in responses');
  return {status:res.status,body:response};
 }finally{clearTimeout(timer);}
}
// Construct an internally correctly signed but semantically INVALID claim
// for adversarial authorization tests. Production issuers use only the
// validated signDisposableDatasetClaim helper.
function signUnchecked(claim,privateKey){
 const fields=['version','issuer','audience','dataset','ownerWebid',
  'reservationId','nonce','issuedAtMs','expiresAtMs'];
 const bytes=Buffer.concat([
   Buffer.from('activitypods:dataset-admin:claim:v1\0','utf8'),
   Buffer.from(JSON.stringify(fields.map(k=>claim[k])),'utf8')
 ]);
 return {claim,signature:crypto.sign(null,bytes,privateKey).toString('base64url')};
}
const makeClaim=(dataset,opts={})=>{
 const now=Date.now();
 return {
  version:1,issuer:'https://paper.example.org/provider',
  audience:'urn:activitypods:dataset-admin:v1',
  dataset,ownerWebid:'https://paper.example.org/users/'+dataset,
  reservationId:crypto.randomUUID(),nonce:crypto.randomUUID(),
  issuedAtMs:now,expiresAtMs:now+120000,...opts
 };
};
async function setup(){
 const sql=await fs.readFile(new URL('./pg-dataset-admin-claim.sql',import.meta.url),'utf8');
 const exists=(await admin.query("SELECT to_regclass('paper_dataset_admin_proof.claims') AS claims")).rows[0].claims;
 assert.equal(exists,null,'Fresh disposable PG18 target required');
 await admin.query(sql);
 const password=crypto.randomBytes(18).toString('hex');
 await admin.query("CREATE ROLE paper_dataset_admin_login LOGIN "+
  "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS "+
  "PASSWORD '"+password+"'");
 await admin.query("GRANT paper_dataset_admin_agent TO paper_dataset_admin_login "+
  "WITH INHERIT TRUE,SET FALSE,ADMIN FALSE");
 const dataset='claimtest-'+crypto.randomBytes(6).toString('hex');
 const keys=crypto.generateKeyPairSync('ed25519');
 const publicKey=keys.publicKey.export({format:'pem',type:'spki'}).toString();
 const claim=makeClaim(dataset);
 const ticket=signDisposableDatasetClaim(claim,keys.privateKey);
 const config={fixture:true,dataset,password,publicKey,ticket};
 await fs.writeFile(META,JSON.stringify(config),{mode:0o600,flag:'wx'});
 return {config,privateKey:keys.privateKey};
}
async function prepare(){
 const {config,privateKey}=await setup();
 // Attacker with only the restricted SQL login must not be able to
 // change a consent binding, update its own immutable dataset ticket,
 // or directly forge the ledger's completed state.
 const user=new Pool({connectionString:restrictedDsn(config.password),
  max:1,connectionTimeoutMillis:3000,query_timeout:5000,
  allowExitOnIdle:true});
 try{
  assert.equal(await assertRestrictedDatasetAdminLogin(user),true);
  const injected=[
    {
      grant:"UPDATE (owner_webid) ON paper_dataset_admin_proof.claims",
      label:'mutable canonical owner'
    },
    {
      grant:"INSERT (state) ON paper_dataset_admin_proof.claims",
      label:'precompleted forged claim'
    },
    {
      grant:"SELECT ON paper_dataset_admin_proof.claims",
      label:'unbounded claim table enumeration'
    },
    {
      grant:"pg_monitor",
      label:'unrelated inherited database role'
    }
  ];
  for(const test of injected){
    await admin.query('GRANT '+test.grant+' TO paper_dataset_admin_login');
    try{
      await assert.rejects(assertRestrictedDatasetAdminLogin(user),
        e=>e?.code==='DATASET_ADMIN_SQL_PRIVILEGES_UNSAFE',test.label);
    }finally{
      await admin.query('REVOKE '+test.grant+' FROM paper_dataset_admin_login');
    }
    assert.equal(await assertRestrictedDatasetAdminLogin(user),true,
      'Restore exact restricted PG login after each malicious grant');
  }
  await assert.rejects(user.query(
   "UPDATE paper_dataset_admin_proof.claims SET dataset='forged'"),
   e=>e?.code==='42501');
  await assert.rejects(user.query(
   "INSERT INTO paper_dataset_admin_proof.claims (dataset,state) "+
   "VALUES('claimtest-aaaa1111','created')"),e=>e?.code==='42501');
  await assert.rejects(user.query(
   "SELECT * FROM paper_dataset_admin_proof.claims"),e=>e?.code==='42501');
 }finally{await user.end();}
 const child=await childProcess(config);
 try{
  const [first,second]=await Promise.all([
   post(config.ticket),post(config.ticket)
  ]);
  assert.equal(first.status,200,first.body);
  assert.equal(second.status,200,second.body);
  assert.equal((await post(config.ticket)).status,200,
   'Committed claim must be idempotent');
  const ordinaryValid=await runOrdinaryProviderClient(config,'valid');
  assert.equal(ordinaryValid.signedClaimAccepted,true);
  for(const mode of ['mismatch','missing']){
    const refused=await runOrdinaryProviderClient(config,mode);
    assert.equal(refused.invalidClaimDenied,true);
  }
  const conflict=signDisposableDatasetClaim(
   makeClaim(config.dataset),privateKey);
  assert.equal((await post(conflict)).status,409,
   'Different valid reservation for same dataset must be refused');
  const crossOwner=signUnchecked(
   makeClaim(config.dataset,{
     ownerWebid:'https://paper.example.org/users/another-user'
   }),privateKey);
  assert.equal((await post(crossOwner)).status,403,
   'Signed cross-owner mismatches must be refused');
  const forged={...config.ticket,signature:'A'.repeat(86)};
  assert.equal((await post(forged)).status,403,
   'A third party cannot forge dataset-creation capabilities');
  const expired=signUnchecked(
    makeClaim(config.dataset,{
      issuedAtMs:Date.now()-60000,expiresAtMs:Date.now()-1000
    }),privateKey);
  assert.equal((await post(expired)).status,403,
   'Expired or mutated claims are rejected');
  assert.equal((await post(config.ticket,{oversize:true})).status,413,
   'Request bodies must be hard bounded');
  assert.equal((await post(config.ticket,{method:'GET'})).status,404,
   'Only fixed POST operation is available');
  const actual=await admin.query(
   'SELECT dataset,owner_webid,state,octet_length(signed_ticket_sha256) AS digest '+
   'FROM paper_dataset_admin_proof.claims WHERE dataset=$1',[config.dataset]);
  assert.equal(actual.rowCount,1,'One bounded SQL row across concurrent retries');
  assert.equal(actual.rows[0].owner_webid,config.ticket.claim.ownerWebid);
  assert.equal(actual.rows[0].digest,32);
  assert.equal(actual.rows[0].state,'created');
  console.log('DATASET_ADMIN_SIGNED_PREACCOUNT '+JSON.stringify({
   phase:'prepare',realPg18:true,realFusekiTdb2:true,
   separateAdminProcess:true,immutableReservation:true,
   concurrentSameTicketIdempotent:true,wrongReservationDenied:true,
   forgedExpiredCrossOwnerDenied:true,restrictedSql:true,
   productionStorageReleased:false
  }));
 }finally{await stop(child);}
}
async function verify(){
 const config=await load();
 const child=await childProcess(config);
 try{
  const reply=await post(config.ticket);
  assert.equal(reply.status,200);
  const body=JSON.parse(reply.body);
  assert.equal(body.idempotent,true,
   'Same durable claim must remain idempotent after process/Jena restart');
  assert.equal((await runOrdinaryProviderClient(config,'valid')).signedClaimAccepted,true,
    'Ordinary provider must replay claim after independent admin/Jena restart');
  const count=(await admin.query(
   'SELECT count(*)::int AS count FROM paper_dataset_admin_proof.claims')).rows[0].count;
  assert.equal(count,1);
  console.log('DATASET_ADMIN_SIGNED_PREACCOUNT '+JSON.stringify({
   phase:'verify',jenaRestartPersisted:true,newAdminProcess:true,
   oneClaimRow:true,productionStorageReleased:false
  }));
 }finally{await stop(child);}
}
async function cleanup(){
 let config=null;
 try{config=await load();}catch{}
 await admin.query('DROP SCHEMA IF EXISTS paper_dataset_admin_proof CASCADE');
 await admin.query('DROP ROLE IF EXISTS paper_dataset_admin_login');
 await admin.query('DROP ROLE IF EXISTS paper_dataset_admin_agent');
 await fs.rm(META,{force:true});
 console.log('DATASET_ADMIN_SIGNED_PREACCOUNT '+JSON.stringify({
  phase:'cleanup',cleaned:true,productionStorageReleased:false
 }));
}
try{
 if(PHASE==='prepare')await prepare();
 if(PHASE==='verify')await verify();
 if(PHASE==='cleanup')await cleanup();
}finally{await admin.end();}
