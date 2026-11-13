import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Pool } from 'pg';
import { createSignedRepoProofStore } from './store.mjs';
import { createSignedSingleRecordWriter } from './single-record-writer.mjs';
import { createRdfProjectionRecovery } from './projection-recovery.mjs';

const DSN = process.env.ATPROTO_REPO_PROOF_DSN || '';
if (process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)) {
  throw Error('Record projection proof requires exact disposable PostgreSQL 18');
}
const pool = new Pool({
  connectionString: DSN, max: 4, connectionTimeoutMillis: 3000,
  idleTimeoutMillis: 3000, allowExitOnIdle: true
});
const accountId = 'https://paper.example.org/users/generation-test';
const did = 'did:plc:' + 'g'.repeat(24);
const path = 'app.bsky.feed.post/3jzm3xwpf342a';
const errors = (promise, code) => assert.rejects(promise, err => err?.code === code);
function keys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  return {
    publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    signer: async bytes => crypto.sign('sha256', bytes, {
      key: privateKey, dsaEncoding: 'ieee-p1363'
    })
  };
}
function record(text) {
  return { $type: 'app.bsky.feed.post', text, createdAt: '2026-11-13T00:00:00.000Z' };
}

test('signed PG generation 1→2→3 recovers through monotone RDF projection CAS', async t => {
  try {
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    )).rows[0].n, 0);
    await pool.query(await fs.readFile(fileURLToPath(new URL('./schema.sql', import.meta.url)), 'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./single-record-mutation.sql', import.meta.url)), 'utf8'));
    const identity = keys();
    const genesis = createSignedRepoProofStore({ pool, fixtureOnly: true });
    let revoked = false;
    const writer = createSignedSingleRecordWriter({
      pool, fixtureOnly: true, authorize: async () => !revoked
    });
    const first = await genesis.bootstrap({ accountId, did, ...identity });
    const params = { accountId, did };
    let projection = {
      canonicalAccountId: accountId, webId: accountId,
      activityPubActorId: accountId, atprotoDid: did,
      atprotoSource: 'local', atprotoManaged: true, status: 'active',
      repoInitialized: false, repoRootCid: null, repoRev: null,
      repoProjectionFence: null
    };
    let rdfWrites = 0;
    let preceding = [];
    const guard = async args => {
      const { rootCid, rev, fence, expectedPreviousRootCid, expectedPreviousRev } = args;
      assert.equal(args.accountId, accountId);
      assert.equal(args.did, did);
      assert(BigInt(fence) > BigInt(projection.repoProjectionFence || '0'));
      if (expectedPreviousRootCid !== null || expectedPreviousRev !== null) {
        assert.equal(typeof expectedPreviousRootCid, 'string');
        assert.equal(typeof expectedPreviousRev, 'string');
        assert(projection.repoProjectionFence !== null);
        const matchesPrior = projection.repoRootCid === expectedPreviousRootCid &&
          projection.repoRev === expectedPreviousRev;
        const matchesNew = projection.repoRootCid === rootCid && projection.repoRev === rev;
        if (!matchesPrior && !matchesNew) {
          const err = Error('Attempt to project a non-parent signed head');
          err.code = 'RDF_PROJECTION_CONFLICT';
          throw err;
        }
      } else if (projection.repoRootCid !== null &&
                 (projection.repoRootCid !== rootCid || projection.repoRev !== rev)) {
        throw Error('Genesis cannot overwrite different immutable head');
      }
      preceding.push({
        previousRootCid: expectedPreviousRootCid, previousRev: expectedPreviousRev,
        newRootCid: rootCid, newRev: rev, fence
      });
      projection = {
        ...projection, repoInitialized: true, repoRootCid: rootCid,
        repoRev: rev, repoProjectionFence: fence
      };
      rdfWrites++;
    };
    const options = {
      pool, fixtureOnly: true, leaseSeconds: 15, maxAttempts: 4,
      verifyNativeEvidence: async () => writer.verify({
        accountId, did, publicKeyPem: identity.publicKeyPem
      }),
      authorize: async () => !revoked,
      readRdf: async () => ({ ...projection }),
      applyRdfFenced: guard
    };
    const worker = () => createRdfProjectionRecovery(options);
    const store = worker();

    await t.test('genesis projection still requires actual signed head and first Jena fence', async () => {
      const ready = await store.reconcile(params);
      assert.equal(ready.ready, true);
      assert.equal(ready.generation, 1);
      assert.equal(ready.fence, '1');
      assert.equal(ready.rootCid, first.rootCid);
      assert.equal(rdfWrites, 1);
      assert.equal(preceding[0].previousRootCid, null);
      assert.equal(preceding[0].previousRev, null);
    });
    let second;
    await t.test('record commit v2 remains blocked until exact parent generation is projected', async () => {
      second = await writer.write({
        ...params, ...identity, expectedCommitCid: first.commitCid,
        expectedRev: first.rev, action: 'create', path, record: record('gen 2')
      });
      assert.equal(second.generation, 2);
      assert.equal(second.previousCommitCid, first.commitCid);
      assert.equal(second.previousRootCid, first.rootCid);
      assert.equal(second.previousRev, first.rev);
      await errors(store.readiness(params), 'PROJECTION_NOT_READY');
      // A genesis-only verifier cannot falsely elevate a mutation, even if
      // it supplies a current CID/Rev but omits signed parent evidence.
      const legacy = createRdfProjectionRecovery({
        ...options,
        verifyNativeEvidence: async () => {
          const { generation, previousRootCid, previousRev, ...old } =
            await writer.verify({ ...params, publicKeyPem: identity.publicKeyPem });
          return old;
        }
      });
      await errors(legacy.reconcile(params), 'PROJECTION_VERIFIED_HEAD_CHANGED');
      revoked = true;
      await errors(store.reconcile(params), 'PROJECTION_AUTH_REVOKED');
      revoked = false;
      const ready = await store.reconcile(params);
      assert.equal(ready.ready, true);
      assert.equal(ready.generation, 2);
      assert.equal(ready.fence, '2');
      assert.equal(ready.rootCid, second.rootCid);
      assert.equal(preceding[1].previousRootCid, first.rootCid);
      assert.equal(preceding[1].previousRev, first.rev);
    });
    await t.test('tampered historical parent CID cannot authorize another projection', async () => {
      const former = (await pool.query(
        'SELECT previous_root_cid FROM paper_atproto_repo_proof.record_mutations ' +
        'WHERE did=$1 AND generation=2', [did]
      )).rows[0].previous_root_cid;
      try {
        await pool.query(
          'UPDATE paper_atproto_repo_proof.record_mutations ' +
          'SET previous_root_cid=$2 WHERE did=$1 AND generation=2',
          [did, second.rootCid]
        );
        await assert.rejects(writer.verify({
          ...params, publicKeyPem: identity.publicKeyPem
        }), /Signed repository mutation unavailable|CID mismatch|Missing/i);
      } finally {
        await pool.query(
          'UPDATE paper_atproto_repo_proof.record_mutations ' +
          'SET previous_root_cid=$2 WHERE did=$1 AND generation=2',
          [did, former]
        );
      }
      assert.equal((await writer.verify({
        ...params, publicKeyPem: identity.publicKeyPem
      })).previousRootCid, first.rootCid);
    });
    await t.test('crash after Jena CAS before PG ACK replays same signed v3 at higher fence', async () => {
      const third = await writer.write({
        ...params, ...identity, expectedCommitCid: second.commitCid,
        expectedRev: second.rev, action: 'update', path, record: record('gen 3')
      });
      assert.equal(third.generation, 3);
      assert.equal(third.previousRootCid, second.rootCid);
      await errors(store.reconcile({ ...params, testCrashAfterRdf: true }),
        'PROJECTION_TEST_CRASH');
      assert.equal(projection.repoRootCid, third.rootCid);
      assert.equal(projection.repoProjectionFence, '3');
      assert.equal((await pool.query(
        'SELECT state FROM paper_atproto_repo_proof.rdf_projection_jobs WHERE account_id=$1',
        [accountId]
      )).rows[0].state, 'leased');
      await errors(store.readiness(params), 'PROJECTION_NOT_READY');
      await pool.query(
        "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET " +
        "lease_until=clock_timestamp()-INTERVAL '1 second' WHERE account_id=$1",
        [accountId]
      );
      const recovered = await worker().reconcile(params);
      assert.equal(recovered.ready, true);
      assert.equal(recovered.generation, 3);
      assert.equal(recovered.fence, '4');
      assert.equal(projection.repoRev, third.rev);
      assert.equal(preceding[2].previousRootCid, second.rootCid);
      assert.equal(preceding[3].previousRootCid, second.rootCid,
        'crash replay cannot select a different parent or signed head');
      assert.equal(rdfWrites, 4);
      assert.equal((await worker().readiness(params)).ready, true);
    });
  } finally {
    try { await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE'); }
    finally { await pool.end(); }
  }
});
