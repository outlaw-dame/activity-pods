/**
 * Separate disposable SQL-login child. Its environment is an explicit
 * allowlist; no PostgreSQL fixture superuser, Jena admin password, signing
 * key, or provider identity credentials may cross into this process.
 */
import assert from 'node:assert/strict';
import {Pool} from 'pg';
import {makeAccountReservationAuthority,
  assertRestrictedAccountProofLogin} from './account-reservation-authority.mjs';

const allowed = [
  'NODE_ENV','ATPROTO_REPO_PROOF_DISPOSABLE',
  'APODS_ACCOUNT_RESERVATION_DISPOSABLE','ACCOUNT_PROOF_CHILD_ROLE',
  'ACCOUNT_PROOF_CHILD_DSN','ACCOUNT_PROOF_CHILD_INPUT'
].sort();
assert.deepEqual(Object.keys(process.env).sort(),allowed,
  'Only explicitly reviewed restricted SQL child environment is permitted');
assert.equal(process.env.NODE_ENV,'test');
assert.equal(process.env.ATPROTO_REPO_PROOF_DISPOSABLE,'confirmed');
assert.equal(process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE,'confirmed');
const kind=process.env.ACCOUNT_PROOF_CHILD_ROLE;
assert(['worker','issuer'].includes(kind));
const url = new URL(process.env.ACCOUNT_PROOF_CHILD_DSN);
assert.equal(url.hostname,'127.0.0.1');
assert.equal(url.port,'5548');
assert.equal(url.pathname,'/atproto_signed_repo_proof_test');
assert.equal(url.username,kind==='worker' ?
  'paper_account_worker_login':'paper_account_issuer_login');
const pool = new Pool({connectionString:url.toString(),max:1,
  connectionTimeoutMillis:3000,query_timeout:5000,allowExitOnIdle:true});
try {
  assert.equal(await assertRestrictedAccountProofLogin(pool,kind),true);
  await assert.rejects(
    pool.query('SELECT * FROM paper_account_reservation_proof.reservations'),
    e=>e?.code==='42501');
  if(kind==='worker') {
    const input=JSON.parse(Buffer.from(
      process.env.ACCOUNT_PROOF_CHILD_INPUT,'base64').toString('utf8'));
    const authority=makeAccountReservationAuthority({workerPool:pool});
    const replay=await authority.reserve(input);
    assert(['already_reserved','completed'].includes(replay.outcome));
    assert.equal(replay.fenceToken,null,
      'Restarted restricted child may not retrieve the original signer fence');
  }
  console.log('ACCOUNT_PROOF_CHILD '+JSON.stringify({kind,
    inheritedSuperuser:false,privilegedTableReadDenied:true,
    signingKeyPresent:false,productionReleased:false}));
} finally {
  await pool.end();
}
