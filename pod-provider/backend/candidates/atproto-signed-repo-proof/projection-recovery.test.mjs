import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Pool } from 'pg';
import { createSignedRepoProofStore } from './store.mjs';
import { createRdfProjectionRecovery } from './projection-recovery.mjs';
import { createPgLeaseTicketIssuer } from './pg-lease-ticket.mjs';
import { createPodOperationTicketAuthority } from './pod-operation-ticket.mjs';

const DSN = process.env.ATPROTO_REPO_PROOF_DSN || '';
if (process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/.test(DSN)) {
  throw new Error('Projection recovery tests are limited to disposable local PG18');
}
const pool = new Pool({
  connectionString: DSN, max: 4, connectionTimeoutMillis: 3000,
  idleTimeoutMillis: 3000, allowExitOnIdle: true
});
const did = name => 'did:plc:' + name.padEnd(24, 'a').slice(0, 24);
const account = name => 'https://paper.example.org/users/' + name;
const makeKeys = () => {
  const keys = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  return {
    publicKeyPem: keys.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    signer: async bytes => crypto.sign('sha256', bytes, {
      key: keys.privateKey, dsaEncoding: 'ieee-p1363'
    })
  };
};
function rdfRecord(name) {
  return {
    canonicalAccountId: account(name), webId: account(name),
    activityPubActorId: account(name), atprotoDid: did(name),
    atprotoSource: 'local', atprotoManaged: true, status: 'active',
    repoInitialized: false, repoRootCid: null, repoRev: null, repoProjectionFence: null
  };
}
function aFixture(store, name, keys, options = {}) {
  let authorized = true;
  let throwOnApply = null;
  const rdf = new Map([[account(name), rdfRecord(name)]]);
  let writeCount = 0;
  const verifyNativeEvidence = ({ accountId, did: claimedDid }) =>
    store.verify({ accountId, did: claimedDid, publicKeyPem: keys.publicKeyPem });
  const readRdf = async ({ accountId }) => ({ ...rdf.get(accountId) });
  const applyRdfFenced = async ({
    accountId, did: claimedDid, rootCid, rev, fence, expectedIdentity
  }) => {
    if (throwOnApply) throw throwOnApply;
    const current = rdf.get(accountId);
    assert.deepEqual(expectedIdentity, {
      canonicalAccountId: accountId, webId: accountId,
      activityPubActorId: accountId, atprotoDid: claimedDid
    });
    if (current.canonicalAccountId !== accountId || current.webId !== accountId ||
        current.activityPubActorId !== accountId || current.atprotoDid !== claimedDid) {
      const err = new Error('Canonical RDF identity changed');
      err.code = 'PROJECTION_IDENTITY_DRIFT';
      throw err;
    }
    // This models a trusted, atomic SPARQL compare-and-set with a persisted
    // numeric fence. A stale replica must NEVER be able to overwrite it.
    if (BigInt(fence) <= BigInt(current.repoProjectionFence || '0')) {
      const err = new Error('Stale worker cannot overwrite newer RDF projection');
      err.code = 'RDF_FENCE_CONFLICT';
      throw err;
    }
    rdf.set(accountId, { ...current, repoInitialized: true,
      repoRootCid: rootCid, repoRev: rev, repoProjectionFence: fence });
    writeCount += 1;
  };
  const optionsFor = {
    pool,
    verifyNativeEvidence,
    authorize: async () => authorized,
    readRdf, applyRdfFenced, fixtureOnly: true,
    leaseSeconds: options.leaseSeconds || 15,
    maxAttempts: options.maxAttempts || 8
  };
  return {
    worker: () => createRdfProjectionRecovery(optionsFor),
    optionsFor,
    params: { accountId: account(name), did: did(name) },
    rdf, getRecord: () => rdf.get(account(name)),
    setRecord: updates => rdf.set(account(name), { ...rdf.get(account(name)), ...updates }),
    revoke: () => { authorized = false; },
    writes: () => writeCount,
    rejectWrite: error => { throwOnApply = error; }
  };
}
async function bootstrap(store, name, keys, extra = {}) {
  return store.bootstrap({
    accountId: account(name), did: did(name),
    signer: keys.signer, publicKeyPem: keys.publicKeyPem, ...extra
  });
}
async function ledger(name) {
  const r = await pool.query(
    'SELECT * FROM paper_atproto_repo_proof.rdf_projection_jobs WHERE account_id=$1', [account(name)]
  );
  return r.rows[0] || null;
}
async function expire(name) {
  await pool.query(
    "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET lease_until=clock_timestamp()-INTERVAL '1 second' " +
    "WHERE account_id=$1 AND state='leased'", [account(name)]
  );
}
async function releaseBackoff(name) {
  await pool.query(
    "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET next_attempt_at=clock_timestamp()-INTERVAL '1 second' " +
    "WHERE account_id=$1 AND state='pending'", [account(name)]
  );
}

test('PG18 cross-store recovery: atomic intent, fenced lease, CAS, replay, revocation', async t => {
  try {
    const count = await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    );
    assert.equal(count.rows[0].n, 0);
    await pool.query(await fs.readFile(fileURLToPath(new URL('./schema.sql', import.meta.url)), 'utf8'));
    const store = createSignedRepoProofStore({ pool, fixtureOnly: true });

    await t.test('repo, CID blocks, native outbox, and RDF intent commit atomically', async () => {
      const k = makeKeys();
      await assert.rejects(bootstrap(store, 'atomic', k, { testFailAfterOutbox: true }),
        err => err.code === 'ATPROTO_TEST_INJECTED_FAILURE');
      const repos = await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.repos WHERE account_id=$1',
        [account('atomic')]
      );
      const outbox = await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox WHERE did=$1',
        [did('atomic')]
      );
      assert.equal(repos.rows[0].n, 0);
      assert.equal(outbox.rows[0].n, 0);
      assert.equal(await ledger('atomic'), null);
      const proof = await bootstrap(store, 'atomic', k);
      const job = await ledger('atomic');
      assert.equal(job.state, 'pending');
      assert.equal(job.lease_epoch, '0');
      assert.equal(job.did, did('atomic'));
      assert.equal(job.head_cid, proof.commitCid);
      assert.equal(job.root_cid, proof.rootCid);
      assert.equal(job.rev, proof.rev);
      assert.equal((await bootstrap(store, 'atomic', k)).replay, true);
      assert.equal((await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.rdf_projection_jobs WHERE account_id=$1',
        [account('atomic')]
      )).rows[0].n, 1);
    });

    await t.test('projection tickets come from the current PG lease, signed head and SAI grant', async () => {
      const name = 'ticket';
      const k = makeKeys();
      await bootstrap(store, name, k);
      const accountId = account(name);
      const signedDid = did(name);
      const owner = crypto.randomUUID();
      const leased = await pool.query(
        "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET " +
        "state='leased',lease_owner=$2::uuid,lease_epoch=1," +
        "lease_until=clock_timestamp()+INTERVAL '60 seconds',attempt_count=1 " +
        "WHERE account_id=$1 RETURNING root_cid,rev,head_cid",
        [accountId, owner]
      );
      assert.equal(leased.rowCount, 1);
      const appUri = 'https://paper.example.org/apps/writer';
      const grantUri = accountId + '/data/access-grants/approved';
      const authority = createPodOperationTicketAuthority({ secret: crypto.randomBytes(32) });
      let granted = true;
      const issuer = createPgLeaseTicketIssuer({
        pool, tickets: authority, fixtureOnly: true,
        verifySignedHead: params => store.verify({ ...params, publicKeyPem: k.publicKeyPem }),
        verifyCurrentSaiConsent: async params =>
          granted && params.accountId === accountId &&
          params.appUri === appUri && params.grantUri === grantUri &&
          params.consentRevision === '1'
      });
      const claim = { accountId, did: signedDid, leaseOwner: owner, leaseEpoch: '1' };
      const issuance = await issuer.issueForLease({
        claim, appUri, grantUri, consentRevision: '1'
      });
      const expectedScope = {
        accountId, did: signedDid, appUri, grantUri,
        operation: 'project', epoch: '1', projectionFence: '1',
        rootCid: leased.rows[0].root_cid, rev: leased.rows[0].rev,
        generation: 1, previousRootCid: null, previousRev: null
      };
      assert.equal(authority.verify(issuance.ticket, expectedScope).projectionFence, '1');
      await assert.rejects(issuer.issueForLease({
        claim: { ...claim, leaseEpoch: '2' }, appUri, grantUri, consentRevision: '1'
      }), e => e.code === 'PG_TICKET_LEASE_STALE');

      granted = false;
      await assert.rejects(issuer.issueForLease({
        claim, appUri, grantUri, consentRevision: '1'
      }), e => e.code === 'PG_TICKET_SAI_NOT_CURRENT');
      granted = true;

      // A superseded replica cannot mint a new operation ticket, even if it
      // can still present an old claim and the user's SAI grant did not change.
      await pool.query(
        "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET " +
        "lease_epoch=2,lease_owner=$2::uuid WHERE account_id=$1",
        [accountId, crypto.randomUUID()]
      );
      await assert.rejects(issuer.issueForLease({
        claim, appUri, grantUri, consentRevision: '1'
      }), e => e.code === 'PG_TICKET_LEASE_STALE');
    });

    await t.test('readiness fails closed before projection and turns true only after verified RDF CAS + PG ACK', async () => {
      const k = makeKeys();
      await bootstrap(store, 'ready', k);
      const f = aFixture(store, 'ready', k);
      const worker = f.worker();
      await assert.rejects(worker.readiness(f.params), err => err.code === 'PROJECTION_NOT_READY');
      const before = await worker.inspect(f.params);
      assert.equal(before.status, 'pending');
      assert.equal(before.requiresRecovery, true);
      const ready = await worker.reconcile(f.params);
      assert.equal(ready.ready, true);
      assert.equal(ready.fence, '1');
      assert.equal(ready.did, did('ready'));
      assert.equal(f.writes(), 1);
      assert.equal((await ledger('ready')).state, 'applied');
      assert.equal((await worker.inspect(f.params)).requiresRecovery, false);
      const again = await worker.reconcile(f.params);
      assert.equal(again.fence, '1');
      assert.equal(f.writes(), 1);
      f.setRecord({ repoRootCid: 'bafyre' + 'a'.repeat(53) });
      await assert.rejects(worker.readiness(f.params),
        e => e.code === 'RDF_PROJECTION_CONFLICT');
      const drift = await worker.inspect(f.params);
      assert.equal(drift.inconsistentCompletedProjection, true);
      await assert.rejects(worker.reconcile(f.params), e => e.code === 'RDF_PROJECTION_CONFLICT');
      assert.equal(f.writes(), 1, 'a completed projection must not silently self-repair drift');
    });

    await t.test('two independent replica objects claim at most one active lease', async () => {
      const k = makeKeys();
      await bootstrap(store, 'replica', k);
      const f = aFixture(store, 'replica', k);
      const results = await Promise.all(Array.from({ length: 8 }, () => f.worker().reconcile(f.params)));
      assert(results.every(r => r.ready === true || r.status === 'busy'));
      assert.equal(f.writes(), 1);
      const row = await ledger('replica');
      assert.equal(row.state, 'applied');
      assert.equal(row.lease_epoch, '1');
      assert.equal((await f.worker().readiness(f.params)).ready, true);
    });

    await t.test('crash between Jena CAS and PG ACK is recoverable after lease expiry, without duplicate genesis', async () => {
      const k = makeKeys();
      const genesis = await bootstrap(store, 'crash', k);
      const f = aFixture(store, 'crash', k);
      await assert.rejects(
        f.worker().reconcile({ ...f.params, testCrashAfterRdf: true }),
        e => e.code === 'PROJECTION_TEST_CRASH'
      );
      assert.equal((await ledger('crash')).state, 'leased');
      assert.equal(f.getRecord().repoProjectionFence, '1');
      await assert.rejects(f.worker().readiness(f.params), e => e.code === 'PROJECTION_NOT_READY');
      await expire('crash');
      const recovered = await f.worker().reconcile(f.params);
      assert.equal(recovered.ready, true);
      assert.equal(recovered.fence, '2');
      assert.equal(f.writes(), 2);
      assert.equal(recovered.headCid, genesis.commitCid);
      const counts = await Promise.all([
        pool.query('SELECT count(*)::int n FROM paper_atproto_repo_proof.repos WHERE did=$1', [did('crash')]),
        pool.query('SELECT count(*)::int n FROM paper_atproto_repo_proof.blocks WHERE did=$1', [did('crash')]),
        pool.query('SELECT count(*)::int n FROM paper_atproto_repo_proof.native_event_outbox WHERE did=$1', [did('crash')])
      ]);
      assert.deepEqual(counts.map(x => x.rows[0].n), [1, 2, 1]);
    });

    await t.test('stale replica wakes after new replica ACK and must not erase fence or completion', async () => {
      const k = makeKeys();
      await bootstrap(store, 'stale', k);
      const f = aFixture(store, 'stale', k);
      const original = f.optionsFor.applyRdfFenced;
      let unblock;
      let notifyReached;
      const reached = new Promise(resolve => { notifyReached = resolve; });
      const gate = new Promise(resolve => { unblock = resolve; });
      let first = true;
      f.optionsFor.applyRdfFenced = async args => {
        if (first) { first = false; notifyReached(); await gate; }
        return original(args);
      };
      const a = f.worker().reconcile(f.params);
      await reached;
      assert.equal((await ledger('stale')).lease_epoch, '1');
      await expire('stale');
      const b = f.worker().reconcile(f.params);
      const winner = await b;
      assert.equal(winner.fence, '2');
      unblock();
      await assert.rejects(a, e => e.code === 'RDF_FENCE_CONFLICT');
      assert.equal((await ledger('stale')).state, 'applied');
      assert.equal((await ledger('stale')).lease_epoch, '2');
      assert.equal(f.getRecord().repoProjectionFence, '2');
      assert.equal((await f.worker().readiness(f.params)).ready, true);
    });

    await t.test('transient RDF failure schedules bounded retry without false ready', async () => {
      const k = makeKeys();
      await bootstrap(store, 'retry', k);
      const f = aFixture(store, 'retry', k);
      const err = new Error('Transient test network outage');
      err.code = 'ETIMEDOUT';
      f.rejectWrite(err);
      await assert.rejects(f.worker().reconcile(f.params), e => e.code === 'ETIMEDOUT');
      const failed = await ledger('retry');
      assert.equal(failed.state, 'pending');
      assert.equal(failed.attempt_count, 1);
      assert.equal(failed.last_error_code, 'ETIMEDOUT');
      await assert.rejects(f.worker().readiness(f.params), e => e.code === 'PROJECTION_NOT_READY');
      f.rejectWrite(null);
      await releaseBackoff('retry');
      const result = await f.worker().reconcile(f.params);
      assert.equal(result.ready, true);
      assert.equal(result.fence, '2');
      assert.equal(f.writes(), 1);
    });

    await t.test('non-retryable RDF identity collision and exhausted retries require operator review', async () => {
      const k = makeKeys();
      await bootstrap(store, 'collision', k);
      const f = aFixture(store, 'collision', k);
      f.setRecord({ activityPubActorId: account('attacker') });
      await assert.rejects(f.worker().reconcile(f.params),
        e => e.code === 'PROJECTION_IDENTITY_DRIFT');
      assert.equal((await ledger('collision')).state, 'blocked');
      await assert.rejects(f.worker().reconcile(f.params), e => e.code === 'PROJECTION_BLOCKED');
      assert.equal(f.writes(), 0);

      const exhaustedKey = makeKeys();
      await bootstrap(store, 'exhausted', exhaustedKey);
      const limited = aFixture(store, 'exhausted', exhaustedKey, { maxAttempts: 1 });
      const timeout = new Error('temporary outage');
      timeout.code = 'ETIMEDOUT';
      limited.rejectWrite(timeout);
      await assert.rejects(limited.worker().reconcile(limited.params));
      assert.equal((await ledger('exhausted')).state, 'blocked');
      await assert.rejects(limited.worker().reconcile(limited.params),
        e => e.code === 'PROJECTION_BLOCKED');
    });

    await t.test('exhausted pending state becomes blocked rather than perpetual busy', async () => {
      const k = makeKeys();
      await bootstrap(store, 'pendingmax', k);
      const fixture = aFixture(store, 'pendingmax', k, { maxAttempts: 2 });
      // Reproduce a durable pending record left at its configured limit
      // (e.g. after an older worker/version or manual recovery).
      await pool.query(
        "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET attempt_count=2," +
        "state='pending',next_attempt_at=clock_timestamp()-INTERVAL '1 second' " +
        "WHERE account_id=$1",
        [account('pendingmax')]
      );
      await assert.rejects(
        fixture.worker().reconcile(fixture.params),
        e => e.code === 'PROJECTION_BLOCKED'
      );
      const row = await ledger('pendingmax');
      assert.equal(row.state, 'blocked');
      assert.equal(row.lease_owner, null);
      assert.equal(row.last_error_code, 'PROJECTION_RETRY_EXHAUSTED');
      assert.equal(fixture.writes(), 0);
    });

    await t.test('revoked authorization and wrong signature cannot claim a repo projection', async () => {
      const k = makeKeys();
      await bootstrap(store, 'revoked', k);
      const f = aFixture(store, 'revoked', k);
      f.revoke();
      await assert.rejects(f.worker().reconcile(f.params),
        e => e.code === 'PROJECTION_AUTH_REVOKED');
      assert.equal((await ledger('revoked')).state, 'pending');
      assert.equal((await ledger('revoked')).lease_epoch, '0');
      const wrong = makeKeys();
      const mismatched = aFixture(store, 'revoked', wrong);
      await assert.rejects(mismatched.worker().reconcile(mismatched.params));
      assert.equal((await ledger('revoked')).lease_epoch, '0');
    });

    await t.test('candidate cannot be activated in a production context', async () => {
      const locked = createRdfProjectionRecovery({
        pool, fixtureOnly: false, authorize: async () => true
      });
      await assert.rejects(locked.reconcile({ accountId: account('ready'), did: did('ready') }),
        e => e.code === 'PROJECTION_NOT_RELEASED');
      const prior = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        const disabled = createRdfProjectionRecovery({ pool, fixtureOnly: true });
        await assert.rejects(disabled.readiness({ accountId: account('ready'), did: did('ready') }),
          e => e.code === 'PROJECTION_NOT_RELEASED');
      } finally {
        if (prior === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = prior;
      }
    });
  } finally {
    try { await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE'); }
    finally { await pool.end(); }
  }
});
