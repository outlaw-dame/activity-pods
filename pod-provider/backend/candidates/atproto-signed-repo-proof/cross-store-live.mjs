/**
 * Disposable cross-store integration: genuine PG18 signed genesis and real
 * Jena Fuseki/TDB2 fenced RDF projection in one recovery sequence.
 *
 * No live ActivityPods signup, SAI grants, PLC resolution or Pod dataset
 * changes are performed. Synthetic protected identitybindings are seeded
 * inside a newly created isolated Fuseki settings dataset fixture.
 *
 * prepare: generate fixture key only in RUNNER_TEMP (mode 0600), create DB,
 *         test multi-replica CAS, injected cross-store crash and stale worker.
 * verify:  check signed PG and persistent RDF state after Fuseki restart,
 *          then destroy fixture key and disposable PG schema.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Pool } from 'pg';
import { createSignedRepoProofStore } from './store.mjs';
import { createRdfProjectionRecovery } from './projection-recovery.mjs';
import { buildFencedRepoProjectionSparql } from './fuseki-fence.mjs';
const marker = process.env.ATPROTO_REPO_PROOF_DISPOSABLE === 'confirmed' &&
  process.env.ATPROTO_REPO_FUSEKI_PROOF_DISPOSABLE === 'confirmed';
const dsn = process.env.ATPROTO_REPO_PROOF_DSN || '';
if (!marker ||
    !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/.test(dsn) ||
    process.env.FUSEKI_URL !== 'http://127.0.0.1:3040' ||
    process.env.NODE_ENV === 'production') {
  throw new Error('Real cross-store proof requires the exact disposable PG18 + Fuseki loopback targets');
}
const phase = process.argv[2];
if (!['prepare', 'verify'].includes(phase)) throw new Error('Expected prepare or verify');
const prefix = 'PREFIX apods: <http://activitypods.org/ns/core#> ';
const testDataPath = path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'paper-atproto-recovery-ephemeral.json');
const host = process.env.FUSEKI_URL;
const auth = 'Basic ' + Buffer.from('admin:' + (process.env.FUSEKI_PASSWORD || 'admin')).toString('base64');
const account = x => 'https://paper.example.org/users/' + x;
const did = x => 'did:plc:' + x.padEnd(24, 'a').slice(0, 24);
const bindingIri = x => 'urn:paper:atproto:cross-store:binding:' + x;
const cases = ['aclive', 'accrash', 'acstale', 'acrevoked'];
const pool = new Pool({
  connectionString: dsn, max: 4,
  connectionTimeoutMillis: 3000, idleTimeoutMillis: 3000, allowExitOnIdle: true
});
let ephemeral = {};
const workerPools = [];

async function fuseki(kind, query) {
  const response = await fetch(host + '/settings/' + kind, {
    method: 'POST',
    headers: {
      authorization: auth,
      'content-type': kind === 'update' ? 'application/sparql-update' : 'application/sparql-query',
      accept: 'application/sparql-results+json'
    },
    body: query, signal: AbortSignal.timeout(20000)
  });
  const body = await response.text();
  if (!response.ok) throw new Error('Fuseki ' + kind + ' HTTP ' + response.status + ': ' + body.slice(0, 450));
  return kind === 'query' ? JSON.parse(body).results.bindings : null;
}
async function seed(name) {
  const iri = '<' + bindingIri(name) + '>';
  const webId = account(name);
  const rdf = iri + ' a apods:AtprotoIdentityBinding ; ' +
    'apods:canonicalAccountId "' + webId + '" ; ' +
    'apods:webId <' + webId + '> ; apods:activityPubActorId <' + webId + '> ; ' +
    'apods:atprotoDid "' + did(name) + '" ; apods:atprotoSource "local" ; ' +
    'apods:atprotoManaged true ; apods:status "active" ; apods:repoInitialized false . ';
  await fuseki('update', prefix + 'INSERT DATA { ' + rdf + ' }');
}
async function read(name) {
  const rows = await fuseki('query', prefix + 'SELECT ?canonical ?web ?actor ?did ?source ?managed ' +
    '?status ?initialized ?root ?rev ?fence WHERE { <' + bindingIri(name) + '> ' +
    'apods:canonicalAccountId ?canonical ; apods:webId ?web ; ' +
    'apods:activityPubActorId ?actor ; apods:atprotoDid ?did ; ' +
    'apods:atprotoSource ?source ; apods:atprotoManaged ?managed ; ' +
    'apods:status ?status ; apods:repoInitialized ?initialized . ' +
    'OPTIONAL { <' + bindingIri(name) + '> apods:repoRootCid ?root . } ' +
    'OPTIONAL { <' + bindingIri(name) + '> apods:repoRev ?rev . } ' +
    'OPTIONAL { <' + bindingIri(name) + '> apods:repoProjectionFence ?fence . } }');
  assert.equal(rows.length, 1, 'Exactly one protected RDF binding required');
  const row = rows[0];
  const val = key => row[key]?.value || null;
  return {
    canonicalAccountId: val('canonical'),
    webId: val('web'),
    activityPubActorId: val('actor'),
    atprotoDid: val('did'),
    atprotoSource: val('source'),
    atprotoManaged: val('managed') === 'true',
    status: val('status'),
    repoInitialized: val('initialized') === 'true',
    repoRootCid: val('root'),
    repoRev: val('rev'),
    repoProjectionFence: val('fence')
  };
}
function keyFor(name) { return ephemeral[name]; }
function makeFactory(name, options = {}) {
  const keys = keyFor(name);
  const service = createSignedRepoProofStore({ pool, fixtureOnly: true });
  const p = {
    accountId: account(name), did: did(name)
  };
  const verifyNativeEvidence = ({ accountId, did: expectedDid }) =>
    service.verify({ accountId, did: expectedDid, publicKeyPem: keys.publicKeyPem });
  const base = {
    verifyNativeEvidence,
    authorize: async () => options.revoked !== true,
    readRdf: async ({ accountId, did: actualDid }) => {
      assert.equal(accountId, account(name));
      assert.equal(actualDid, did(name));
      return read(name);
    },
    applyRdfFenced: async ({ accountId, did: actualDid, rootCid, rev, fence }) => {
      assert.equal(accountId, account(name));
      assert.equal(actualDid, did(name));
      return fuseki('update', buildFencedRepoProjectionSparql({
        resourceUri: bindingIri(name), accountId, did: actualDid,
        rootCid, rev, fence
      }));
    },
    fixtureOnly: true, leaseSeconds: 15, maxAttempts: 8
  };
  return {
    params: p,
    makeWorker: (override = {}) => {
      const workerPool = new Pool({
        connectionString: dsn, max: 2, connectionTimeoutMillis: 3000,
        idleTimeoutMillis: 2000, allowExitOnIdle: true
      });
      workerPools.push(workerPool);
      return createRdfProjectionRecovery({ ...base, pool: workerPool, ...override });
    }
  };
}
async function rows(name) {
  const result = await pool.query(
    'SELECT state,lease_epoch,attempt_count FROM paper_atproto_repo_proof.rdf_projection_jobs WHERE account_id=$1',
    [account(name)]
  );
  return result.rows[0];
}
async function expire(name) {
  await pool.query(
    "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET lease_until=clock_timestamp()-INTERVAL '1 second' " +
    "WHERE account_id=$1 AND state='leased'", [account(name)]
  );
}
async function bootstrap(name) {
  const keys = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  ephemeral[name] = {
    publicKeyPem: keys.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    privateKeyPem: keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  };
  const store = createSignedRepoProofStore({ pool, fixtureOnly: true });
  await store.bootstrap({
    accountId: account(name), did: did(name),
    publicKeyPem: ephemeral[name].publicKeyPem,
    signer: async bytes => crypto.sign('sha256', bytes, {
      key: ephemeral[name].privateKeyPem, dsaEncoding: 'ieee-p1363'
    })
  });
}
async function prepare() {
  const result = await pool.query(
    "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
  );
  assert.equal(result.rows[0].n, 0);
  const schema = await fs.readFile(new URL('./schema.sql', import.meta.url), 'utf8');
  await pool.query(schema);
  for (const name of cases) {
    await seed(name);
    await bootstrap(name);
  }
  await fs.writeFile(testDataPath, JSON.stringify(ephemeral), { mode: 0o600, flag: 'wx' });
  const make = name => {
    const f = makeFactory(name);
    return { ...f, worker: f.makeWorker() };
  };
  // All independent reconciler objects use independently created PG pools;
  // PostgreSQL arbitrates claims and Fuseki serializes RDF writer updates.
  const live = make('aclive');
  const replicaWorkers = Array.from({ length: 4 }, () => {
    const f = makeFactory('aclive');
    return f.makeWorker();
  });
  const results = await Promise.all(replicaWorkers.map(w => w.reconcile(live.params)));
  assert(results.every(x => x.ready === true || x.status === 'busy'));
  assert.equal((await rows('aclive')).lease_epoch, '1');
  assert.equal((await live.worker.readiness(live.params)).ready, true);

  const crash = make('accrash');
  await assert.rejects(crash.worker.reconcile({ ...crash.params, testCrashAfterRdf: true }),
    e => e.code === 'PROJECTION_TEST_CRASH');
  assert.equal((await rows('accrash')).state, 'leased');
  await expire('accrash');
  const recovered = make('accrash');
  const resultAfterCrash = await recovered.worker.reconcile(recovered.params);
  assert.equal(resultAfterCrash.fence, '2');
  assert.equal((await recovered.worker.readiness(recovered.params)).ready, true);

  // A timed-out replica cannot rewrite or ACK a newer replica's RDF fence.
  const stale = makeFactory('acstale');
  const fastWorker = stale.makeWorker();
  let unblock, reached;
  const entered = new Promise(resolve => { reached = resolve; });
  const gate = new Promise(resolve => { unblock = resolve; });
  // An independent caller's injected CAS blocks at the point where the old
  // instance is about to issue its Jena UPDATE.
  const slow = stale.makeWorker({
    applyRdfFenced: async args => {
      reached();
      await gate;
      return fuseki('update', buildFencedRepoProjectionSparql({
        resourceUri: bindingIri('acstale'), accountId: args.accountId,
        did: args.did, rootCid: args.rootCid, rev: args.rev, fence: args.fence
      }));
    }
  });
  const old = slow.reconcile(stale.params);
  await entered;
  await expire('acstale');
  const newer = await fastWorker.reconcile(stale.params);
  assert.equal(newer.fence, '2');
  unblock();
  await assert.rejects(old, e => e.code === 'RDF_PROJECTION_CONFLICT');
  assert.equal((await rows('acstale')).state, 'applied');
  assert.equal((await fastWorker.readiness(stale.params)).fence, '2');

  const revoked = makeFactory('acrevoked', { revoked: true });
  await assert.rejects(revoked.makeWorker().reconcile(revoked.params),
    e => e.code === 'PROJECTION_AUTH_REVOKED');
  assert.equal((await rows('acrevoked')).lease_epoch, '0');
  process.stdout.write('Cross-store PG18/Fuseki: one-owner lease, crash recovery, stale-writer rejection and revoked grants passed.\n');
}
async function verify() {
  ephemeral = JSON.parse(await fs.readFile(testDataPath, 'utf8'));
  const store = createSignedRepoProofStore({ pool, fixtureOnly: true });
  for (const [name, expectedFence] of [['aclive', '1'], ['accrash', '2'], ['acstale', '2']]) {
    const pgProof = await store.verify({
      accountId: account(name), did: did(name),
      publicKeyPem: keyFor(name).publicKeyPem
    });
    assert.equal(pgProof.verified, true);
    const projected = await read(name);
    assert.equal(projected.repoRootCid, pgProof.rootCid);
    assert.equal(projected.repoRev, pgProof.rev);
    assert.equal(projected.repoProjectionFence, expectedFence);
    assert.equal((await rows(name)).state, 'applied');
  }
  assert.equal((await rows('acrevoked')).state, 'pending');
  await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');
  await fs.unlink(testDataPath);
  process.stdout.write('Combined PG18 signed evidence and actual Fuseki RDF persisted after restart; ephemeral key destroyed.\n');
}
try {
  if (phase === 'prepare') await prepare();
  else await verify();
} finally {
  await Promise.allSettled(workerPools.map(p => p.end()));
  await pool.end();
}
