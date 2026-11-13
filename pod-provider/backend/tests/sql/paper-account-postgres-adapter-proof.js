'use strict';
// Isolated live PostgreSQL integration proof. Intentionally does not touch
// auth.signup, production databases, remote PLC, PDS or Jena.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const { createAccountPostgresLifecycleCandidate } =
  require('../../candidates/account-postgres-lifecycle');

const connection = {
  host: '127.0.0.1', port: 15432, database: 'paper_account_disposable',
  user: 'postgres', password: 'disposable-ci-only',
  max: 2, connectionTimeoutMillis: 3000, idleTimeoutMillis: 2000
};
const pa = new Pool(connection);
const pb = new Pool(connection);
const a = createAccountPostgresLifecycleCandidate({pool:pa});
const b = createAccountPostgresLifecycleCandidate({pool:pb});
// Isolated synthetic provider HMAC key. Never reuse an unkeyed SHA-256 digest
// of request fields or client idempotency keys in production.
const fixtureKey = crypto.randomBytes(32);
const h = value => crypto.createHmac('sha256', fixtureKey).update(value).digest();
const newId = () => crypto.randomUUID();
const base = (name, key, client = 'https://client.example') => ({
  operationId: newId(), leaseToken: newId(), providerId: 'provider-candidate',
  appClientId: client, idempotencyDigest: h(key), requestDigest: h('request-'+key),
  usernameKey: name, verifiedEmailHmac: null
});
async function checkReject(operation, code) {
  await assert.rejects(operation, err => err.type === code || err.message?.includes(code));
}
async function main() {
  const input = base('accountcandidatealice', 'candidate-key-1');
  const reserved = await a.reserve(input);
  assert.equal(reserved.state, 'reserved');
  assert.equal(reserved.replay, false);
  await checkReject(a.reserve(input), 'ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
  await checkReject(a.reserve({...input, requestDigest:h('changed')}), 'ACCOUNT_LEDGER_IDEMPOTENCY_MISMATCH');

  await checkReject(a.markAccountCreated({...input,webId:'https://admin:password@pods.example/alice'}), 'ACCOUNT_LEDGER_INVALID_WEBID');
  const webId = 'https://pods.example/alice';
  assert.equal((await a.markAccountCreated({...input,webId})).state,'account_created');
  await checkReject(a.markAccountCreated({...input,webId}), 'ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
  await checkReject(a.markIdentitiesReady({
    ...input,did:'did:web:pods.example',repoRootCid:'bafyreiaaaaa',repoRev:'0',
    signedRepoProofDigest:h('fake')
  }), 'ACCOUNT_LEDGER_UNVERIFIED_IDENTITY');
  assert.equal((await a.markIdentitiesReady({
    ...input, did:'did:plc:abcdefghijklmnopqrstuvwx',
    repoRootCid:'bafy'+'a'.repeat(45),repoRev:'3kskdumj2wv',
    signedRepoProofDigest:h('isolated synthetic proof digest only')
  })).state,'identities_ready');
  assert.equal((await a.complete(input)).state, 'completed');
  assert.equal((await b.reserve(input)).replay, true);
  await checkReject(a.requireReconciliation(input), 'ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');

  const one = base('accountcandidatecontest', 'contest-1', 'https://client-1.example');
  const two = base('accountcandidatecontest', 'contest-2', 'https://client-2.example');
  const results = await Promise.allSettled([a.reserve(one),b.reserve(two)]);
  assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
  assert.equal(results.filter(x=>x.status==='rejected').length,1);
  const fail = results.find(x=>x.status==='rejected');
  assert.equal(fail.reason.type,'ACCOUNT_LEDGER_IDENTITY_RESERVED');
  const winner = results[0].status==='fulfilled' ? one : two;
  await checkReject(a.markAccountCreated({...winner,
    leaseToken:newId(),webId:'https://pods.example/contest'
  }), 'ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');

  await pa.query(
    "UPDATE paper_account_candidate.operations SET lease_expires_at=clock_timestamp()-interval '1 minute' WHERE operation_id=$1",
    [winner.operationId]
  );
  await checkReject(a.markAccountCreated({...winner,webId:'https://pods.example/contest'}),
    'ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
  console.log('account_pg_live_adapter_transactions_passed');
}
main().then(async()=>{await Promise.all([pa.end(),pb.end()])}).catch(async err=>{
  console.error('account_pg_live_adapter_proof_failed',err.type||err.code||err.name);
  await Promise.allSettled([pa.end(),pb.end()]);
  process.exitCode=1;
});
