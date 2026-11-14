/**
 * Independent issuer process with ONLY the restricted issuer SQL login,
 * Ed25519 private key and one pre-account fence. It cannot create datasets,
 * mutate reservations or access the privileged test harness PostgreSQL DSN.
 * Output is one operation-scoped signed ticket (a bearer capability): the
 * caller must not log, persist or propagate it through Moleculer ctx.meta.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {Pool} from 'pg';
import {makeAccountReservationAuthority,
  assertRestrictedAccountProofLogin} from './account-reservation-authority.mjs';
import {issueBoundDatasetClaim} from './account-reservation-issuer.mjs';

const KEYS=[
  'NODE_ENV','ATPROTO_REPO_PROOF_DISPOSABLE',
  'ATPROTO_FUSEKI_ISOLATION_DISPOSABLE',
  'FUSEKI_ISOLATION_URL',
  'APODS_ACCOUNT_RESERVATION_DISPOSABLE',
  'APODS_DATASET_CLAIM_ISSUER_DISPOSABLE',
  'ACCOUNT_ISSUER_DSN','ACCOUNT_ISSUER_SIGNING_PEM_B64',
  'ACCOUNT_ISSUER_REQUEST_B64'
].sort();
assert.deepEqual(Object.keys(process.env).sort(),KEYS,
  'Issuer child must only inherit explicitly approved environment');
assert.equal(process.env.NODE_ENV,'test');
assert.equal(process.env.ATPROTO_REPO_PROOF_DISPOSABLE,'confirmed');
assert.equal(process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE,'confirmed');
assert.equal(process.env.FUSEKI_ISOLATION_URL,'http://127.0.0.1:3041');
assert.equal(process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE,'confirmed');
assert.equal(process.env.APODS_DATASET_CLAIM_ISSUER_DISPOSABLE,'confirmed');
const dsn=new URL(process.env.ACCOUNT_ISSUER_DSN);
assert.equal(dsn.hostname,'127.0.0.1');
assert.equal(dsn.port,'5548');
assert.equal(dsn.pathname,'/atproto_signed_repo_proof_test');
assert.equal(dsn.username,'paper_account_issuer_login');
const request=JSON.parse(Buffer.from(process.env.ACCOUNT_ISSUER_REQUEST_B64,
  'base64').toString('utf8'));
assert.deepEqual(Object.keys(request).sort(),['dataset','fence']);
const key=crypto.createPrivateKey({
  key:Buffer.from(process.env.ACCOUNT_ISSUER_SIGNING_PEM_B64,'base64'),
  format:'pem',type:'pkcs8'
});
const pool=new Pool({connectionString:dsn.toString(),max:1,
  connectionTimeoutMillis:3000,query_timeout:5000,
  idleTimeoutMillis:2000,allowExitOnIdle:true});
try{
  await assertRestrictedAccountProofLogin(pool,'issuer');
  await assert.rejects(pool.query(
    'SELECT * FROM paper_account_reservation_proof.reservations'),
    e=>e?.code==='42501');
  const authority=makeAccountReservationAuthority({
    workerPool:{query:()=>{throw Error('Worker SQL is forbidden in issuer');}},
    issuerPool:pool
  });
  const ticket=await issueBoundDatasetClaim({
    authority,privateKey:key,fence:request.fence,dataset:request.dataset
  });
  // No SQL credential/key/plaintext password emitted in the receipt.
  process.stdout.write('ACCOUNT_ISSUER_TICKET '+Buffer.from(
    JSON.stringify(ticket),'utf8').toString('base64')+'\n');
}finally{await pool.end();}
