import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';
import { base58btc } from 'multiformats/bases/base58';

import { createSignedRepoProofStore } from './store.mjs';
import { createProviderManagedRepoAuthority } from './provider-authority.mjs';
import { createRdfProjectionRecovery } from './projection-recovery.mjs';
import { createReadOnlySyncXrpc } from './sync-xrpc-candidate.mjs';
import { verifySignedEmptyRepo } from './genesis.mjs';

const DSN = process.env.ATPROTO_REPO_PROOF_DSN || '';
if (process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)) {
  throw Error('XRPC acceptance requires the exact disposable PostgreSQL 18 target');
}
const pool = new Pool({
  connectionString: DSN, max: 4, connectionTimeoutMillis: 3000,
  idleTimeoutMillis: 3000, allowExitOnIdle: true
});
const did = 'did:plc:' + 'x'.repeat(24);
const accountId = 'https://paper.example.org/new-xrpc';
const handle = 'new-xrpc.paper.example.org';
const pdsOrigin = 'https://pds.paper.example.org';

function signingKeys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1'
  });
  const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const point = publicKey.export({ format: 'der', type: 'spki' }).subarray(-65);
  const compressed = crypto.ECDH.convertKey(
    point, 'secp256k1', undefined, undefined, 'compressed'
  );
  return {
    publicKeyPem,
    publicKeyMultibase: base58btc.encode(Buffer.concat([
      Buffer.from([0xe7,0x01]), compressed
    ])),
    signer: async data => crypto.sign('sha256', data, {
      key: privateKey, dsaEncoding: 'ieee-p1363'
    })
  };
}
async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return 'http://127.0.0.1:' + server.address().port;
}
async function close(server) {
  await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
}

test('nonactivated XRPC exports exact signed empty CAR and current hosting state', async t => {
  let server;
  const originalNodeEnv = process.env.NODE_ENV;
  try {
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    )).rows[0].n, 0);
    await pool.query(await fs.readFile(fileURLToPath(new URL('./schema.sql', import.meta.url)), 'utf8'));
    const key = signingKeys();
    const store = createSignedRepoProofStore({ pool, fixtureOnly: true });
    const signed = await store.bootstrap({
      accountId, did, publicKeyPem: key.publicKeyPem, signer: key.signer
    });
    assert.equal(signed.verified, true);
    const update = await pool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET " +
      "state='applied',lease_epoch=1,applied_at=clock_timestamp() " +
      'WHERE account_id=$1 AND did=$2 RETURNING state', [accountId, did]
    );
    assert.equal(update.rowCount, 1);
    let binding = {
      canonicalAccountId: accountId, webId: accountId, activityPubActorId: accountId,
      atprotoDid: did, atprotoHandle: handle, atprotoPdsUrl: pdsOrigin,
      atprotoSource: 'local', atprotoManaged: true, status: 'active',
      atSigningKeyRef: 'key://signing', atRotationKeyRef: 'key://rotation',
      repoInitialized: true, repoRootCid: signed.rootCid, repoRev: signed.rev,
      repoProjectionFence: '1'
    };
    const repoAuthority = createProviderManagedRepoAuthority({
      store,
      resolveBinding: async () => ({ ...binding }),
      resolveCommitKey: async () => ({
        did, keyId: did + '#atproto', publicKeyMultibase: key.publicKeyMultibase
      }),
      resolveDelegatedIdentity: async () => ({
        resolvedHandleDid: did,
        didDocument: {
          id: did, alsoKnownAs: ['at://' + handle],
          verificationMethod: [{
            id: did + '#atproto', controller: did, type: 'Multikey',
            publicKeyMultibase: key.publicKeyMultibase
          }],
          service: [{
            id: '#atproto_pds', type: 'AtprotoPersonalDataServer',
            serviceEndpoint: pdsOrigin
          }]
        }
      }),
      signCommit: async () => { throw Error('Read-only XRPC must never sign'); }
    });
    let currentGrant = true;
    const projection = createRdfProjectionRecovery({
      pool, fixtureOnly: true,
      verifyNativeEvidence: async () => store.verify({
        accountId, did, publicKeyPem: key.publicKeyPem
      }),
      authorize: async () => currentGrant,
      readRdf: async () => ({ ...binding }),
      applyRdfFenced: async () => { throw Error('Read-only XRPC must not mutate RDF'); }
    });
    let hosted = {
      webId: accountId, activityPubActorId: accountId,
      did, handle, pdsUrl: pdsOrigin,
      atprotoManaged: true, atprotoSource: 'local', status: 'active'
    };
    let lookups = 0;
    const xrpc = createReadOnlySyncXrpc({
      resolveHostedAccount: async ({ did: lookup }) => {
        lookups++;
        return lookup === did ? { ...hosted } : null;
      },
      repositoryAuthority: repoAuthority,
      projectionAuthority: projection,
      signedRepoStore: store,
      resolvePublicKey: async () => key.publicKeyPem,
      pdsOrigin, fixtureOnly: true
    });
    server = http.createServer((req, res) => xrpc.handle(req, res));
    const url = await listen(server);
    const api = (method, target = did) => url + '/xrpc/com.atproto.sync.' +
      method + '?did=' + encodeURIComponent(target);
    const get = async href => {
      const response = await fetch(href, { signal: AbortSignal.timeout(5000) });
      const content = response.headers.get('content-type');
      const bytes = Buffer.from(await response.arrayBuffer());
      return {
        status: response.status, content,
        headers: response.headers,
        bytes, json: content?.startsWith('application/json') ?
          JSON.parse(bytes.toString('utf8')) : null
      };
    };

    await t.test('public getRepo CAR has actual cryptographic v3 commit and MST', async () => {
      const response = await get(api('getRepo'));
      assert.equal(response.status, 200);
      assert.equal(response.content, 'application/vnd.ipld.car');
      assert.equal(response.headers.get('cache-control'), 'no-store');
      const proof = await verifySignedEmptyRepo({
        did, carBytes: response.bytes, publicKeyPem: key.publicKeyPem
      });
      assert.equal(proof.commitCid, signed.commitCid);
      assert.equal(proof.rootCid, signed.rootCid);
      assert.equal(proof.rev, signed.rev);
    });
    await t.test('latest commit and repo status reflect same verified signed head', async () => {
      const latest = await get(api('getLatestCommit'));
      assert.equal(latest.status, 200);
      assert.deepEqual(latest.json, { cid: signed.commitCid, rev: signed.rev });
      const state = await get(api('getRepoStatus'));
      assert.equal(state.status, 200);
      assert.deepEqual(state.json, { did, active: true, rev: signed.rev });
      assert(lookups >= 4, 'each public query must resolve hosted account again');
    });
    await t.test('invalid method/DID, duplicated parameters and unsupported diffs fail closed', async () => {
      const invalid = [
        [url + '/xrpc/com.atproto.sync.getBlocks?did=' + did, 404, 'MethodNotImplemented'],
        [api('getRepo', 'did:web:attacker.example'), 400, 'InvalidRequest'],
        [api('getRepo', 'did:plc:' + 'y'.repeat(24)), 404, 'RepoNotFound'],
        [api('getRepo') + '&did=' + did, 400, 'InvalidRequest'],
        [api('getRepo') + '&ignored=123', 400, 'InvalidRequest'],
        [api('getRepo') + '&since=notatime', 400, 'InvalidRequest'],
        [api('getRepo') + '&since=' + signed.rev, 501, 'NotImplemented']
      ];
      for (const [href, status, error] of invalid) {
        const response = await get(href);
        assert.equal(response.status, status, href);
        assert.equal(response.json?.error, error, href);
        assert(!response.bytes.includes(Buffer.from('key://')),
          'public errors must not reveal signing-key references');
      }
    });
    await t.test('inactive and takendown account status cannot leak an old CAR', async () => {
      for (const status of ['suspended','takendown','deactivated','deleted']) {
        hosted = { ...hosted, status };
        const state = await get(api('getRepoStatus'));
        assert.equal(state.status, 200);
        assert.deepEqual(state.json, { did, active: false, status });
        const repo = await get(api('getRepo'));
        assert.notEqual(repo.status, 200);
        assert.equal(repo.content?.startsWith('application/json'), true);
      }
      hosted = { ...hosted, status: 'active' };
    });
    await t.test('a PDS move, revoked SAI grant or changed RDF identity blocks export', async () => {
      hosted = { ...hosted, pdsUrl: 'https://another.example.org' };
      assert.equal((await get(api('getRepo'))).status, 503);
      hosted = { ...hosted, pdsUrl: pdsOrigin };
      currentGrant = false;
      assert.equal((await get(api('getRepo'))).status, 503);
      currentGrant = true;
      binding = { ...binding, atprotoHandle: 'wrong.paper.example.org' };
      assert.equal((await get(api('getLatestCommit'))).status, 503);
      binding = { ...binding, atprotoHandle: handle };
    });
    await t.test('a corrupt persisted CAR cannot appear as a successful HTTP export', async () => {
      const saved = (await pool.query(
        'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
        [did, signed.rootCid]
      )).rows[0].block;
      try {
        await pool.query(
          'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
          [did, signed.rootCid, Buffer.from('tampered')]
        );
        assert.equal((await get(api('getRepo'))).status, 503);
      } finally {
        await pool.query(
          'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
          [did, signed.rootCid, saved]
        );
      }
      assert.equal((await get(api('getRepo'))).status, 200);
    });
    await t.test('production cannot activate an already-constructed candidate', async () => {
      process.env.NODE_ENV = 'production';
      const denied = await get(api('getRepo'));
      assert.equal(denied.status, 503);
      assert.equal(denied.json.error, 'InternalError');
      process.env.NODE_ENV = 'test';
    });
  } finally {
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
    if (server) await close(server);
    try { await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE'); }
    finally { await pool.end(); }
  }
});
