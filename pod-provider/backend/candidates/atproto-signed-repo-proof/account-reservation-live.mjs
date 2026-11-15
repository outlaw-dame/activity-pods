/**
 * Real PostgreSQL 18 disposable proof: two provider cells, separate restricted
 * worker and issuer credentials, persistent crash/restart fences, quota
 * transactions, signed dataset binding, and four direct privilege attacks.
 * prepare and verify run in independent processes separated by a Fuseki restart.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {Pool} from 'pg';
import {makeAccountReservationAuthority,
  assertRestrictedAccountProofLogin} from './account-reservation-authority.mjs';
import {signDisposableDatasetClaim,verifyDisposableDatasetClaim
} from './dataset-admin-claim-service.mjs';

const PHASE = process.argv[2];
const DSN = process.env.ATPROTO_REPO_PROOF_DSN;
const ROOT = 'https://paper.example.org/users/';
const PROVIDER = 'https://paper.example.org/provider';
const ENV_OK = process.env.NODE_ENV === 'test' &&
  process.env.ATPROTO_REPO_PROOF_DISPOSABLE === 'confirmed' &&
  process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE === 'confirmed' &&
  process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE === 'confirmed' &&
  process.env.FUSEKI_ISOLATION_URL === 'http://127.0.0.1:3041' &&
  /^postgres:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN || '') &&
  typeof process.env.RUNNER_TEMP === 'string' && process.env.RUNNER_TEMP.startsWith('/');
if (!ENV_OK || !['prepare', 'verify', 'cleanup'].includes(PHASE)) {
  throw Error('Account reservation proof must remain strictly disposable');
}
const META = path.join(process.env.RUNNER_TEMP, 'paper-account-reservation-fixture.json');
const rootPool = new Pool({connectionString:DSN,max:2,connectionTimeoutMillis:3000,
  query_timeout:8000,idleTimeoutMillis:2000,allowExitOnIdle:true});
function localDsn(user,password) {
  const url = new URL(DSN);
  url.username = user;
  url.password = password;
  return url.toString();
}
function restrictedPool(user,password) {
  return new Pool({connectionString:localDsn(user,password),
    max:2,connectionTimeoutMillis:3000,query_timeout:8000,
    idleTimeoutMillis:2000,allowExitOnIdle:true});
}
async function runRestrictedChild(kind,password,input) {
  const file=fileURLToPath(new URL('./account-reservation-child.mjs',import.meta.url));
  // Positive allowlist, never inherit the privileged PG18 harness environment.
  const env={
    NODE_ENV:'test',
    ATPROTO_REPO_PROOF_DISPOSABLE:'confirmed',
    APODS_ACCOUNT_RESERVATION_DISPOSABLE:'confirmed',
    ACCOUNT_PROOF_CHILD_ROLE:kind,
    ACCOUNT_PROOF_CHILD_DSN:localDsn(
      kind==='worker'?'paper_account_worker_login':'paper_account_issuer_login',
      password),
    ACCOUNT_PROOF_CHILD_INPUT:Buffer.from(JSON.stringify(input||{}),'utf8')
      .toString('base64')
  };
  assert.equal(Object.hasOwn(env,'ATPROTO_REPO_PROOF_DSN'),false);
  assert.equal(Object.hasOwn(env,'DATASET_ADMIN_FUSEKI_PASSWORD'),false);
  assert.equal(Object.hasOwn(env,'DATASET_ADMIN_SIGNER_PRIVATE_KEY'),false);
  const child=spawn(process.execPath,[file],{env,stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';
  const exit=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{
      child.kill('SIGKILL');reject(Error('Isolated SQL child timeout'));
    },12000);
    child.stdout.on('data',chunk=>{stdout=(stdout+String(chunk)).slice(-1000);});
    child.stderr.on('data',chunk=>{stderr=(stderr+String(chunk)).slice(-500);});
    child.once('error',error=>{clearTimeout(timer);reject(error);});
    child.once('exit',code=>{clearTimeout(timer);resolve(code);});
  });
  assert.equal(exit,0,'Restricted '+kind+' child failed: '+stderr.slice(0,120));
  assert(stdout.includes('"inheritedSuperuser":false'),
    'Child must produce explicit credential-isolation proof');
}
function fingerprint(label) {
  return crypto.createHash('sha256').update(label).digest('hex');
}
function account(app,username,key=crypto.randomBytes(12).toString('hex'),dailyLimit=100) {
  return {appClientId:app,username,idempotencyKey:key,
    requestFingerprint:fingerprint(app + ':' + username + ':' + key),dailyLimit};
}
function fence(input,receipt) {
  return {appClientId:input.appClientId,idempotencyKey:input.idempotencyKey,
    reservationId:receipt.reservationId,fenceToken:receipt.fenceToken};
}
const proof = username => ({
  username,webId:ROOT + username,activityPubActorId:ROOT + username,
  atprotoDid:'did:plc:' + Array.from(
    crypto.createHash('sha256').update(username,'utf8').digest().subarray(0,24),
    byte => 'abcdefghijklmnopqrstuvwxyz234567'[byte % 32]).join(''),
  atprotoPdsUrl:'https://pds.paper.example.org',
  evidenceSha256:fingerprint('synthetic-cryptographic-receipt-not-production')
});
async function prepare() {
  const sql = await fs.readFile(new URL('./pg-preaccount-reservations.sql', import.meta.url),'utf8');
  const present = await rootPool.query(
    "SELECT to_regnamespace('paper_account_reservation_proof') AS schema");
  assert.equal(present.rows[0].schema,null,'Must use a fresh PG18 proof schema');
  await rootPool.query(sql);
  const workerPassword = crypto.randomBytes(20).toString('hex');
  const issuerPassword = crypto.randomBytes(20).toString('hex');
  for (const [login,password,role] of [
    ['paper_account_worker_login',workerPassword,'paper_account_proof_worker'],
    ['paper_account_issuer_login',issuerPassword,'paper_account_proof_issuer']
  ]) {
    await rootPool.query('CREATE ROLE '+login+
      " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'");
    await rootPool.query('GRANT '+role+' TO '+login+
      ' WITH INHERIT TRUE, SET FALSE, ADMIN FALSE');
  }
  const workerA = restrictedPool('paper_account_worker_login',workerPassword);
  const workerB = restrictedPool('paper_account_worker_login',workerPassword);
  const issuer = restrictedPool('paper_account_issuer_login',issuerPassword);
  try {
    assert.equal(await assertRestrictedAccountProofLogin(workerA,'worker'),true);
    assert.equal(await assertRestrictedAccountProofLogin(issuer,'issuer'),true);
    const serviceA = makeAccountReservationAuthority({workerPool:workerA,issuerPool:issuer});
    const serviceB = makeAccountReservationAuthority({workerPool:workerB,issuerPool:issuer});
    const username = 'claimtest-' + crypto.randomBytes(5).toString('hex');
    const input = account('paper-app',username,undefined,1);
    const attempts = await Promise.all(Array.from({length:8},(_,index) =>
      (index % 2 ? serviceB : serviceA).reserve(input)));
    assert.equal(attempts.filter(x=>x.outcome==='reserved').length,1,
      'Exactly one first reservation, even across two concurrent PG sessions');
    assert.equal(attempts.filter(x=>x.outcome==='already_reserved').length,7);
    const receipt = attempts.find(x=>x.outcome==='reserved');
    assert(receipt.fenceToken && receipt.reservationId);
    assert(attempts.filter(x=>x.outcome!=='reserved')
      .every(x=>x.fenceToken===null),'Never reissue lease fence on a replay');
    const active = fence(input,receipt);
    await runRestrictedChild('worker',workerPassword,input);
    await runRestrictedChild('issuer',issuerPassword);
    assert.equal(await serviceA.assertDatasetBinding(active,username,ROOT+username),false,
      'Issuer must not sign claims before side effects have been fenced');
    assert.equal(await serviceA.reserve({...input,
      requestFingerprint:fingerprint('mutated account request')}).then(x=>x.outcome),
      'idempotency_conflict');
    assert.equal(await serviceB.reserve({...input,username:username+'x'}).then(x=>x.outcome),
      'idempotency_conflict');
    assert.equal((await serviceA.reserve(account('paper-app',
      'claimtest-'+crypto.randomBytes(5).toString('hex'),undefined,1))).outcome,
      'quota_exceeded','Atomic quota must limit one new account per day');
    assert.equal((await serviceB.reserve(account('other-app',username))).outcome,
      'username_taken','App changes cannot evade the canonical username fence');
    const secondAppCount = (await rootPool.query(
      "SELECT count(*)::int AS n FROM paper_account_reservation_proof.daily_usage "+
      "WHERE app_client_id='other-app'")).rows[0].n;
    assert.equal(secondAppCount,0,'Username conflict must roll back quota increment');

    assert.equal(await serviceA.startSideEffects({...active,
      fenceToken:crypto.randomUUID()}),false);
    assert.equal(await serviceA.startSideEffects(active),true);
    assert.equal(await serviceB.startSideEffects(active),false,
      'No second start after irreversible side effects are permitted');
    const invocation={
      appClientId:input.appClientId,
      idempotencyKey:input.idempotencyKey,
      requestFingerprint:input.requestFingerprint,
      username:input.username,reservationId:active.reservationId
    };
    assert.equal(await serviceA.claimSignup({
      ...invocation,requestFingerprint:fingerprint('different-account-password')
    }),false,'A changed request fingerprint cannot claim signup execution');
    assert.equal(await serviceB.claimSignup(invocation),true,
      'One provider cell can consume the signed account invocation exactly once');
    assert.equal(await serviceA.claimSignup(invocation),false,
      'Another provider cell cannot mint a second DID with the same ticket');
    assert.equal(await serviceA.assertDatasetBinding(active,username,ROOT+username),true);
    assert.equal(await serviceB.assertDatasetBinding(active,username+'x',ROOT+username+'x'),false);
    assert.equal(await serviceB.assertDatasetBinding({...active,
      fenceToken:crypto.randomUUID()},username,ROOT+username),false);
    const keys=crypto.generateKeyPairSync('ed25519');
    const now=Date.now();
    const claim={version:1,issuer:PROVIDER,
      audience:'urn:activitypods:dataset-admin:v1',dataset:username,
      ownerWebid:ROOT+username,reservationId:active.reservationId,
      nonce:crypto.randomUUID(),issuedAtMs:now,expiresAtMs:now+60000};
    // The real short-lived Ed25519 ticket is issued only AFTER the separate
    // issuer role verified the matching durable reservation and fence.
    const ticket=signDisposableDatasetClaim(claim,keys.privateKey);
    assert.equal(verifyDisposableDatasetClaim(ticket,keys.publicKey).reservationId,
      active.reservationId);
    assert.equal(await serviceA.complete({...active,fenceToken:crypto.randomUUID()},
      proof(username)),false,'Wrong fence cannot commit identity');
    assert.equal(await serviceA.complete(active,
      proof('claimtest-unrelated')),false,'Wrong canonical WebID cannot complete');

    const expiredInput=account('third-app',
      'claimtest-'+crypto.randomBytes(5).toString('hex'));
    const expiredResult=await serviceA.reserve(expiredInput);
    assert.equal(expiredResult.outcome,'reserved');
    const expired=fence(expiredInput,expiredResult);
    // Independent supervisor simulation; never provide this UPDATE to the
    // worker or issuer SQL credential.
    await rootPool.query(
      'UPDATE paper_account_reservation_proof.reservations '+
      "SET lease_expires_at=clock_timestamp()-interval '1 second' "+
      'WHERE reservation_id=$1',[expired.reservationId]);
    assert.equal(await serviceB.startSideEffects(expired),false,
      'Expired lease must not start side effects');
    assert.equal((await serviceA.reserve(expiredInput)).outcome,'already_reserved');
    assert.equal((await serviceB.reserve(account('fourth-app',expiredInput.username))).outcome,
      'username_taken','Expiry cannot release a potentially used username');
    assert.equal(await serviceA.assertDatasetBinding(expired,
      expiredInput.username,ROOT+expiredInput.username),false);

    await assert.rejects(workerA.query(
      'SELECT * FROM paper_account_reservation_proof.reservations'),e=>e?.code==='42501');
    await assert.rejects(issuer.query(
      'SELECT * FROM paper_account_reservation_proof.daily_usage'),e=>e?.code==='42501');
    await assert.rejects(workerA.query(
      'SELECT paper_account_reservation_proof.dataset_binding_is_live($1,$2,$3,$4,$5,$6)',
      [PROVIDER,input.appClientId,active.reservationId,active.fenceToken,username,ROOT+username]),
      e=>e?.code==='42501');
    await assert.rejects(issuer.query(
      'SELECT paper_account_reservation_proof.claim_signup_once($1,$2,$3,$4,$5,$6,$7)',
      [PROVIDER,input.appClientId,Buffer.alloc(32),Buffer.alloc(32),
        active.reservationId,input.username,ROOT+input.username]),
      e=>e?.code==='42501',
      'Read-only signer must never claim the account execution lease');
    await assert.rejects(issuer.query(
      'SELECT * FROM paper_account_reservation_proof.reserve($1,$2,$3,$4,$5,$6,$7,$8)',
      [PROVIDER,input.appClientId,Buffer.alloc(32),Buffer.alloc(32),
        username,ROOT+username,1,120]),e=>e?.code==='42501');
    for(const grant of [
      'SELECT ON paper_account_reservation_proof.reservations',
      'UPDATE ON paper_account_reservation_proof.reservations',
      'SELECT ON paper_account_reservation_proof.daily_usage',
      'TRUNCATE ON paper_account_reservation_proof.reservations',
      'MAINTAIN ON paper_account_reservation_proof.daily_usage',
      'SELECT (fence_token) ON paper_account_reservation_proof.reservations',
      'UPDATE (reservation_id) ON paper_account_reservation_proof.reservations',
      'INSERT (reserved_count) ON paper_account_reservation_proof.daily_usage',
      'REFERENCES (username) ON paper_account_reservation_proof.reservations',
      'pg_monitor',
      'pg_read_all_data'
    ]) {
      await rootPool.query('GRANT '+grant+' TO paper_account_worker_login');
      try {
        await assert.rejects(assertRestrictedAccountProofLogin(workerA,'worker'),
          e=>e?.code==='ACCOUNT_RESERVATION_SQL_PRIVILEGES_UNSAFE',grant);
      } finally {
        await rootPool.query('REVOKE '+grant+' FROM paper_account_worker_login');
      }
      assert.equal(await assertRestrictedAccountProofLogin(workerA,'worker'),true);
    }
    const rows=await rootPool.query(
      'SELECT count(*)::int AS n FROM paper_account_reservation_proof.reservations');
    assert.equal(rows.rows[0].n,2,'No retry row amplification or phantom reservations');
    const config={fixture:true,workerPassword,issuerPassword,
      input,active,expiredInput,expired};
    await fs.writeFile(META,JSON.stringify(config),{mode:0o600,flag:'wx'});
    console.log('ACCOUNT_PG_RESERVATION '+JSON.stringify({phase:'prepare',
      realPg18:true,twoConcurrentProviderSessions:true,
      sameKeyOneWriter:true,quotaAtomic:true,usernameFence:true,
      issuerRoleSeparate:true,ed25519ClaimBound:true,
      expiredLeaseNoTakeover:true,privilegeDriftDenied:true,
      productionReleased:false}));
  } finally {
    await Promise.all([workerA.end(),workerB.end(),issuer.end()]);
  }
}
async function verify() {
  const config=JSON.parse(await fs.readFile(META,'utf8'));
  assert.equal(config.fixture,true);
  const worker=restrictedPool('paper_account_worker_login',config.workerPassword);
  const issuer=restrictedPool('paper_account_issuer_login',config.issuerPassword);
  try {
    await assertRestrictedAccountProofLogin(worker,'worker');
    await assertRestrictedAccountProofLogin(issuer,'issuer');
    const service=makeAccountReservationAuthority({workerPool:worker,issuerPool:issuer});
    await runRestrictedChild('worker',config.workerPassword,config.input);
    await runRestrictedChild('issuer',config.issuerPassword);
    assert.equal((await service.reserve(config.input)).outcome,'already_reserved');
    assert.equal((await service.reserve(config.input)).fenceToken,null);
    assert.equal(await service.startSideEffects(config.active),false,
      'No re-entrant identity creator after process/Jena restart');
    assert.equal(await service.claimSignup({
      appClientId:config.input.appClientId,
      idempotencyKey:config.input.idempotencyKey,
      requestFingerprint:config.input.requestFingerprint,
      username:config.input.username,
      reservationId:config.active.reservationId
    }),false,'Completed or restarted signup execution can never be re-entered');
    // The original fenced worker may reconcile and complete; another token,
    // another WebID, or a new lease cannot claim this identity.
    assert.equal(await service.complete(config.active,
      proof(config.input.username)),true);
    assert.equal(await service.complete(config.active,
      proof(config.input.username)),false);
    assert.equal((await service.reserve(config.input)).outcome,'completed');
    const nextInput=account('post-crash-app',
      'claimtest-'+crypto.randomBytes(5).toString('hex'));
    const nextReceipt=await service.reserve(nextInput);
    assert.equal(nextReceipt.outcome,'reserved');
    const nextFence=fence(nextInput,nextReceipt);
    assert.equal(await service.startSideEffects(nextFence),true);
    assert.equal(await service.complete(nextFence,proof(nextInput.username)),false,
      'Account completion requires a previously consumed signup fence');
    assert.equal(await service.claimSignup({
      appClientId:nextInput.appClientId,
      idempotencyKey:nextInput.idempotencyKey,
      requestFingerprint:nextInput.requestFingerprint,
      username:nextInput.username,reservationId:nextFence.reservationId
    }),true);
    await assert.rejects(
      service.complete(nextFence,{...proof(nextInput.username),
        atprotoDid:proof(config.input.username).atprotoDid}),
      e=>e?.code==='23505',
      'PG must reject a second account binding to the same ATProto DID');
    await assert.rejects(
      service.complete(nextFence,{...proof(nextInput.username),
        activityPubActorId:proof(config.input.username).activityPubActorId}),
      e=>e?.code==='23505',
      'PG must reject a second account binding to the same ActivityPub actor');
    assert.equal(await service.complete(nextFence,proof(nextInput.username)),true);
    assert.equal((await service.reserve(account('other-app',
      config.input.username))).outcome,'username_taken');
    assert.equal((await service.reserve(config.expiredInput)).outcome,'already_reserved');
    assert.equal(await service.startSideEffects(config.expired),false);
    const rows=await rootPool.query(
      'SELECT state,count(*)::int AS count FROM paper_account_reservation_proof.reservations '+
      'GROUP BY state ORDER BY state');
    // The independent dataset administrator's ticket now originates from
    // this same canonical pre-account PG ledger, not an unbound test signer.
    const adminMeta=JSON.parse(await fs.readFile(path.join(
      process.env.RUNNER_TEMP,'paper-dataset-admin-claim-fixture.json'),'utf8'));
    assert.equal(adminMeta.ticket.claim.reservationId,
      adminMeta.accountReservationId);
    const binding=await rootPool.query(
      'SELECT state,username,expected_webid FROM '+
      'paper_account_reservation_proof.reservations WHERE reservation_id=$1',
      [adminMeta.accountReservationId]);
    assert.equal(binding.rowCount,1);
    assert.equal(binding.rows[0].state,'side_effects_started',
      'Dataset creation is fenced before any WebID, AP actor or DID can exist');
    assert.equal(binding.rows[0].username,adminMeta.dataset);
    assert.equal(binding.rows[0].expected_webid,ROOT+adminMeta.dataset);
    assert.deepEqual(rows.rows.map(x=>[x.state,x.count]),
      [['completed',2],['reserved',1],['side_effects_started',3]],
      'Post-crash state must remain monotonic and exact');
    console.log('ACCOUNT_PG_RESERVATION '+JSON.stringify({phase:'verify',
      restartedProcess:true,immutableCompletedIdentity:true,
      expiredReservationRetained:true,oneFencedSigner:true,
      storedBearerCredentials:false,productionReleased:false}));
  } finally {
    await Promise.all([worker.end(),issuer.end()]);
  }
}
async function cleanup() {
  await rootPool.query('DROP SCHEMA IF EXISTS paper_account_reservation_proof CASCADE');
  for (const login of ['paper_account_worker_login','paper_account_issuer_login']) {
    await rootPool.query('DROP ROLE IF EXISTS '+login);
  }
  for (const role of ['paper_account_proof_worker','paper_account_proof_issuer']) {
    await rootPool.query('DROP ROLE IF EXISTS '+role);
  }
  await fs.rm(META,{force:true});
  console.log('ACCOUNT_PG_RESERVATION '+JSON.stringify({phase:'cleanup',
    isolatedTablesDestroyed:true,productionReleased:false}));
}
try {
  if (PHASE === 'prepare') await prepare();
  if (PHASE === 'verify') await verify();
  if (PHASE === 'cleanup') await cleanup();
} finally {
  await rootPool.end();
}
