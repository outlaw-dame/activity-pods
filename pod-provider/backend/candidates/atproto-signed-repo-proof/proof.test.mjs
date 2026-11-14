import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Pool } from 'pg';
import * as dagCbor from '@ipld/dag-cbor';
import {
  assertManagedDid, assertTid, makeTid, normalizeK256LowS,
  buildSignedEmptyRepo, verifySignedEmptyRepo
} from './genesis.mjs';
import { createSignedRepoProofStore } from './store.mjs';

const DSN = process.env.ATPROTO_REPO_PROOF_DSN || '';
if (process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/.test(DSN)) {
  throw new Error('Refusing to run signed repository proof outside the exact disposable PostgreSQL target');
}
const pool = new Pool({
  connectionString: DSN, max: 4, connectionTimeoutMillis: 3000,
  idleTimeoutMillis: 3000, allowExitOnIdle: true
});
const did = n => 'did:plc:' + String(n).padEnd(24, 'a').slice(0, 24);
const account = name => 'https://paper.example/users/' + name;
const fixture = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return {
    publicKeyPem: publicKey,
    signer: async cbor => crypto.sign('sha256', cbor, {
      key: privateKey, dsaEncoding: 'ieee-p1363'
    })
  };
};

test('PG18 signed v3 empty repository proof — trusted signing, atomic DB, recovery', async t => {
  try {
    const before = await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    );
    assert.equal(before.rows[0].n, 0, 'disposable schema must be absent at test start');
    await pool.query(await fs.readFile(fileURLToPath(new URL('./schema.sql', import.meta.url)), 'utf8'));

    await t.test('DID and TID checks reject invalid methods/revisions and stay sortable', async () => {
      assert.equal(assertManagedDid(did('abc')), did('abc'));
      assert.throws(() => assertManagedDid('did:web:example.org'));
      assert.throws(() => assertManagedDid('did:plc:wrong'));
      assert.throws(() => assertTid('0'.repeat(13)));
      const prev = makeTid(1000000000000000n, 31);
      const next = makeTid(1000000000000001n, 31);
      assert.equal(prev.length, 13);
      assert.equal(next.length, 13);
      assert(prev < next, 'monotonic TID ordering');
    });

    await t.test('mandatory canonical low-S on all signed commits', async () => {
      const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
      const highS = n - 1n;
      const signature = Buffer.concat([
        Buffer.from('01'.padStart(64, '0'), 'hex'),
        Buffer.from(highS.toString(16).padStart(64, '0'), 'hex')
      ]);
      const normalized = normalizeK256LowS(signature);
      assert.equal(normalized.length, 64);
      assert.equal(normalized.subarray(32).toString('hex'), '01'.padStart(64, '0'));
      assert.deepEqual(normalizeK256LowS(normalized), normalized);
      assert.throws(() => normalizeK256LowS(Buffer.alloc(64)));
      assert.throws(() => normalizeK256LowS(Buffer.alloc(63)));
    });

    await t.test('actual signed CAR has 2 complete CID-verifiable blocks', async () => {
      const f = fixture();
      const id = did('abc');
      const repo = await buildSignedEmptyRepo({
        did: id, rev: makeTid(), ...f
      });
      assert(!repo.commitCid.includes('placeholder'));
      assert(!repo.rootCid.includes('placeholder'));
      const root = dagCbor.decode(repo.rootBytes);
      const commit = dagCbor.decode(repo.commitBytes);
      assert.deepEqual(root, { l: null, e: [] });
      assert.equal(commit.version, 3);
      assert.equal(commit.did, id);
      assert.equal(commit.prev, null);
      assert.equal(commit.sig.length, 64);
      assert.equal(commit.data.toString(), repo.rootCid);
      const verified = await verifySignedEmptyRepo({
        did: id, carBytes: repo.carBytes, publicKeyPem: f.publicKeyPem
      });
      assert.equal(verified.commitCid, repo.commitCid);
      assert.equal(verified.rootCid, repo.rootCid);

      const other = fixture();
      await assert.rejects(
        verifySignedEmptyRepo({ did: id, carBytes: repo.carBytes, publicKeyPem: other.publicKeyPem }),
        /signature/i
      );
      await assert.rejects(
        verifySignedEmptyRepo({ did: did('def'), carBytes: repo.carBytes, publicKeyPem: f.publicKeyPem })
      );
      const corrupted = Buffer.from(repo.carBytes);
      corrupted[corrupted.length - 1] ^= 0x01;
      await assert.rejects(
        verifySignedEmptyRepo({ did: id, carBytes: corrupted, publicKeyPem: f.publicKeyPem })
      );
      await assert.rejects(
        buildSignedEmptyRepo({ did: id, rev: makeTid(), publicKeyPem: f.publicKeyPem, signer: null })
      );
      await assert.rejects(
        buildSignedEmptyRepo({ did: id, rev: makeTid(), publicKeyPem: f.publicKeyPem,
          signer: async () => Buffer.alloc(64) })
      );
    });

    const store = createSignedRepoProofStore({ pool, fixtureOnly: true });
    const locked = createSignedRepoProofStore({ pool });
    await t.test('candidate is not executable as production repository authority', async () => {
      await assert.rejects(
        locked.bootstrap({ accountId: account('blocked'), did: did('blocked') }),
        error => error.code === 'ATPROTO_REPO_PROOF_NOT_RELEASED'
      );
      await assert.rejects(
        locked.verify({ accountId: account('blocked'), did: did('blocked') }),
        error => error.code === 'ATPROTO_REPO_PROOF_NOT_RELEASED'
      );
      const was = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        const denied = createSignedRepoProofStore({ pool, fixtureOnly: true });
        await assert.rejects(
          denied.bootstrap({ accountId: account('blocked'), did: did('blocked') }),
          error => error.code === 'ATPROTO_REPO_PROOF_NOT_RELEASED'
        );
      } finally {
        if (was === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = was;
      }
    });

    await t.test('concurrent signups for same WebID and DID result in exactly one commit/outbox', async () => {
      const f = fixture();
      const acc = account('alice');
      const id = did('alice');
      const results = await Promise.all(Array.from({ length: 8 }, () =>
        store.bootstrap({ accountId: acc, did: id, ...f })
      ));
      assert.equal(results.filter(r => !r.replay).length, 1);
      assert.equal(results.filter(r => r.replay).length, 7);
      assert.equal(new Set(results.map(r => r.commitCid)).size, 1);
      assert.equal(new Set(results.map(r => r.rootCid)).size, 1);
      assert(results.every(r => r.verified === true));
      assert(results.every(r => r.outboxStatus === 'pending'));
      const repos = await pool.query('SELECT count(*)::int AS n FROM paper_atproto_repo_proof.repos WHERE did=$1', [id]);
      const blocks = await pool.query('SELECT count(*)::int AS n FROM paper_atproto_repo_proof.blocks WHERE did=$1', [id]);
      const outbox = await pool.query('SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox WHERE did=$1', [id]);
      assert.equal(repos.rows[0].n, 1);
      assert.equal(blocks.rows[0].n, 2);
      assert.equal(outbox.rows[0].n, 1);
      await assert.rejects(
        store.bootstrap({ accountId: acc, did: did('evil'), ...f }),
        error => error.code === 'ATPROTO_ACCOUNT_DID_CONFLICT'
      );
      await assert.rejects(
        store.bootstrap({ accountId: account('bob'), did: id, ...f }),
        error => error.code === '23505', 'unique DID must not move to second canonical account'
      );
      await assert.rejects(
        store.verify({ accountId: account('bob'), did: id, publicKeyPem: f.publicKeyPem }),
        error => error.code === 'ATPROTO_REPO_NOT_FOUND'
      );
    });


    await t.test('readiness observes repo, signed blocks and event fence in one indexed PG snapshot', async () => {
      const f = fixture();
      const acc = account('snapshot');
      const id = did('snapshot');
      const signed = await store.bootstrap({ accountId: acc, did: id, ...f });
      const statements = [];
      // A wrapper around the REAL PostgreSQL pool counts readiness reads,
      // without replacing its SQL, transaction isolation or cryptographic data.
      const observed = createSignedRepoProofStore({
        pool: {
          connect: () => pool.connect(),
          async query(...args) {
            statements.push(typeof args[0] === 'string' ? args[0] : args[0].text);
            return pool.query(...args);
          }
        },
        fixtureOnly: true
      });
      const result = await observed.verify({
        accountId: acc, did: id, publicKeyPem: f.publicKeyPem
      });
      assert.equal(result.commitCid, signed.commitCid);
      assert.equal(result.rootCid, signed.rootCid);
      assert.equal(result.outboxStatus, 'pending');
      assert.equal(statements.length, 1, 'verified readback must use a single database snapshot');
      assert.match(statements[0], /JOIN paper_atproto_repo_proof\.blocks/i);
      assert.match(statements[0], /JOIN paper_atproto_repo_proof\.native_event_outbox/i);

      // A blocked predecessor must not be hidden by a seemingly valid head.
      await pool.query(
        "UPDATE paper_atproto_repo_proof.native_event_outbox SET blocked_at=clock_timestamp() " +
        "WHERE did=$1 AND commit_cid=$2 AND status='pending'",
        [id, signed.commitCid]
      );
      await assert.rejects(
        observed.verify({ accountId: acc, did: id, publicKeyPem: f.publicKeyPem }),
        error => error.code === 'ATPROTO_REPO_OUTBOX_BLOCKED'
      );
      assert.equal(statements.length, 2, 'blocked readback must also stay single-query');
    });

    await t.test('lost COMMIT reply requires read-only recovery, never a second genesis', async () => {
      const f = fixture();
      const acc = account('commit-unknown');
      const id = did('commitunknown');
      let disconnected = false;
      const lostAcknowledgmentPool = {
        query: (...args) => pool.query(...args),
        async connect() {
          const c = await pool.connect();
          return {
            async query(...args) {
              if (args[0] === 'COMMIT') {
                await c.query(...args); // Truly commit the signed repo and outbox.
                throw new Error('simulated lost PostgreSQL COMMIT acknowledgment');
              }
              return c.query(...args);
            },
            release(discard) {
              disconnected = discard === true;
              c.release(discard);
            }
          };
        }
      };
      const uncertain = createSignedRepoProofStore({
        pool: lostAcknowledgmentPool, fixtureOnly: true
      });
      await assert.rejects(
        uncertain.bootstrap({ accountId: acc, did: id, ...f }),
        error => error.code === 'ATPROTO_REPO_COMMIT_OUTCOME_UNKNOWN'
      );
      assert.equal(disconnected, true, 'unknown COMMIT connection must be discarded');
      const committed = await store.verify({ accountId: acc, did: id, publicKeyPem: f.publicKeyPem });
      assert.equal(committed.verified, true);
      assert.equal(committed.outboxStatus, 'pending');
      const row = await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox WHERE did=$1',
        [id]
      );
      assert.equal(row.rows[0].n, 1);
      const replay = await store.bootstrap({ accountId: acc, did: id, ...f });
      assert.equal(replay.replay, true);
      assert.equal(replay.commitCid, committed.commitCid);
      const after = await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.blocks WHERE did=$1', [id]
      );
      assert.equal(after.rows[0].n, 2, 'replayed genesis must not duplicate CAR blocks');
    });

    await t.test('crash before outbox INSERT rolls back repo and blocks atomically', async () => {
      const f = fixture();
      const id = did('rollback');
      await assert.rejects(
        store.bootstrap({ accountId: account('rollback'), did: id,
          ...f, testFailAfterBlocks: true }),
        error => error.code === 'ATPROTO_TEST_INJECTED_FAILURE'
      );
      const rows = await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.repos WHERE did=$1',
        [id]
      );
      assert.equal(rows.rows[0].n, 0);
      const ret = await store.bootstrap({ accountId: account('rollback'), did: id, ...f });
      assert.equal(ret.replay, false);
      assert.equal(ret.outboxStatus, 'pending');
    });

    await t.test('tampered stored block cannot yield a false readiness proof', async () => {
      const f = fixture();
      const acc = account('tamper');
      const id = did('tamper');
      const ret = await store.bootstrap({ accountId: acc, did: id, ...f });
      const original = (await pool.query(
        'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
        [id, ret.rootCid]
      )).rows[0].block;
      await pool.query(
        'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
        [id, ret.rootCid, Buffer.from('bad root')]
      );
      await assert.rejects(
        store.verify({ accountId: acc, did: id, publicKeyPem: f.publicKeyPem }),
        /CID mismatch|Invalid/i
      );
      await pool.query(
        'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
        [id, ret.rootCid, original]
      );
      const restored = await store.verify({ accountId: acc, did: id, publicKeyPem: f.publicKeyPem });
      assert.equal(restored.commitCid, ret.commitCid);
    });
  } finally {
    try { await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE'); } finally {
      await pool.end();
    }
  }
});
