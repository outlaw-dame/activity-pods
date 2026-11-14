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
  atprotoDid:'did:plc:'+'a'.repeat(24),
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
      'SELECT * FROM paper_account_reservation_proof.reserve($1,$2,$3,$4,$5,$6,$7,$8)',
      [PROVIDER,input.appClientId,Buffer.alloc(32),Buffer.alloc(32),
        username,ROOT+username,1,120]),e=>e?.code==='42501');
    for(const grant of [
      'SELECT ON paper_account_reservation_proof.reservations',
      'UPDATE ON paper_account_reservation_proof.reservations',
      'SELECT ON paper_account_reservation_proof.daily_usage',
      'pg_monitor'
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
    assert.equal((await service.reserve(config.input)).outcome,'already_reserved');
    assert.equal((await service.reserve(config.input)).fenceToken,null);
    assert.equal(await service.startSideEffects(config.active),false,
      'No re-entrant identity creator after process/Jena restart');
    // The original fenced worker may reconcile and complete; another token,
    // another WebID, or a new lease cannot claim this identity.
    assert.equal(await service.complete(config.active,
      proof(config.input.username)),true);
    assert.equal(await service.complete(config.active,
      proof(config.input.username)),false);
    assert.equal((await service.reserve(config.input)).outcome,'completed');
    assert.equal((await service.reserve(account('other-app',
      config.input.username))).outcome,'username_taken');
    assert.equal((await service.reserve(config.expiredInput)).outcome,'already_reserved');
    assert.equal(await service.startSideEffects(config.expired),false);
    const rows=await rootPool.query(
      'SELECT state,count(*)::int AS count FROM paper_account_reservation_proof.reservations '+
      'GROUP BY state ORDER BY state');
    assert.deepEqual(rows.rows.map(x=>[x.state,x.count]),
      [['completed',1],['reserved',1]],
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
