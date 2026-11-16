/**
 * Local reference PLC + signed PostgreSQL repository acceptance for the real
 * provider PLC builder, signing handlers and submitter. This is identity-directory acceptance, NOT successful signup,
 * real provider key custody, SAI consent or hosted PDS acceptance.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import crypto from 'node:crypto';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createSignedRepoProofStore } from '../candidates/atproto-signed-repo-proof/store.mjs';
import { makeTid } from '../candidates/atproto-signed-repo-proof/genesis.mjs';

const require = createRequire(import.meta.url);
const { submitPlcGenesis } = require('../utils/atproto-plc-submission');
const builder = require('../services/core/atproto-plc-builder.service');
const signingSchema = require('../services/signing.service');
const { Pool } = require('pg');
const reference = process.env.PAPER_LOCAL_PLC_REFERENCE;
const configPath = process.env.PAPER_LOCAL_PLC_CONFIG;
const revision = '29f1a70ee9f6f80a25946cac103b2f745e371334';
assert.equal(process.env.NODE_ENV, 'test');
assert.equal(process.env.PAPER_LOCAL_PLC_DISPOSABLE, 'confirmed');
assert.equal(process.env.ATPROTO_REPO_PROOF_DISPOSABLE, 'confirmed');
assert(reference?.startsWith('/') && configPath?.startsWith('/'));
assert.equal(execFileSync('git', ['-C', reference, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), revision);
const config = JSON.parse(await fs.readFile(configPath, 'utf8'));
const dbUrl = new URL(config.databaseUrl);
assert.equal(dbUrl.protocol, 'postgres:');
assert.equal(dbUrl.hostname, '127.0.0.1');
assert.equal(dbUrl.port, '5549');
assert.equal(dbUrl.pathname, '/paper_local_plc');
assert.equal(dbUrl.username, 'paper_local_plc');
const { PlcServer, PgDatabase } = await import(pathToFileURL(`${reference}/packages/server/dist/index.js`));

// Exercise the actual provider signing handlers and authentication boundary.
// Only the key/binding storage here is a disposable fixture, not Pod key custody.
const makeKey = () => {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  return { privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }) };
};
const commit = makeKey();
const rotation = makeKey();
const token = crypto.randomBytes(32).toString('base64url');
const accountId = 'https://provider.paper.example.org/proof-' + crypto.randomUUID();
const binding = { canonicalAccountId: accountId, atSigningKeyRef: 'fixture-commit', atRotationKeyRef: 'fixture-rotation' };
const signing = { ...signingSchema.methods, settings: { auth: { bearerToken: token } } };
let keyReads = 0;
async function signCall(action, params, options = {}) {
  assert.equal(params.canonicalAccountId, accountId);
  const handler = signingSchema.actions[action.replace('signing.', '')]?.handler;
  assert.equal(typeof handler, 'function');
  return handler.call(signing, { params, meta: options.meta, async call(name, input) {
    if (name === 'identitybindings.getByCanonicalAccountId') {
      assert.equal(input.canonicalAccountId, accountId);
      return binding;
    }
    assert.equal(name, 'keys.getAtprotoKeyPair');
    assert(['fixture-commit', 'fixture-rotation'].includes(input.keyRef));
    keyReads++;
    return input.keyRef === 'fixture-commit' ? commit : rotation;
  } });
}
await assert.rejects(signCall('signing.getAtprotoPublicKey', { canonicalAccountId: accountId, purpose: 'rotation' }),
  error => error.type === 'AUTH_FAILED');
assert.equal(keyReads, 0, 'unauthorized requests cannot read a private key');
const signingMeta = { meta: { $headers: { authorization: `Bearer ${token}` } } };
const operation = await builder.actions.buildAndSign.handler.call({ _signingCallMeta: () => signingMeta }, {
  params: { canonicalAccountId: accountId,
    handle: 'local-plc-proof.paper.example.org', pdsEndpoint: 'https://provider.paper.example.org' },
  call: signCall
});
const commitPublic = await signCall('signing.getAtprotoPublicKey', { canonicalAccountId: accountId, purpose: 'commit' }, signingMeta);

async function start() {
  const db = PgDatabase.create({ url: config.databaseUrl });
  await db.migrateToLatestOrThrow();
  const plc = PlcServer.create({ db });
  // Bind explicitly to loopback; the upstream convenience start() binds all interfaces.
  const server = http.createServer(plc.app);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { db, plc, server, origin: `http://127.0.0.1:${server.address().port}` };
}
async function stop(runtime) {
  runtime.server.closeAllConnections();
  await new Promise((resolve, reject) => runtime.server.close(error => error ? reject(error) : resolve()));
  await runtime.plc.destroy();
}
async function attempt(runtime, signedOp = operation.signedOp) {
  return submitPlcGenesis({ directory: runtime.origin, did: operation.did, signedOp, timeoutMs: 5000 });
}

let runtime;
let repoPool;
try {
  runtime = await start();
  const invalid = { ...operation.signedOp, sig: Buffer.alloc(64).toString('base64url') };
  assert.equal((await attempt(runtime, invalid)).kind, 'failed', 'reference server rejects an invalid signature');
  assert.deepEqual(await attempt(runtime), { kind: 'confirmed' });
  assert.deepEqual(await attempt(runtime), { kind: 'confirmed' }, 'same signed genesis is replayable');
  assert.equal((await runtime.db.opsForDid(operation.did)).length, 1, 'no duplicate genesis');
  const doc = await fetch(`${runtime.origin}/${operation.did}`).then(response => response.json());
  assert.equal(doc.id, operation.did);
  assert.equal(doc.verificationMethod[0].publicKeyMultibase, commitPublic.publicKeyMultibase);
  binding.atprotoDid = operation.did;
  repoPool = new Pool({ connectionString: config.databaseUrl, max: 2,
    connectionTimeoutMillis: 3000, query_timeout: 10000 });
  const installed = await repoPool.query("SELECT to_regnamespace('paper_atproto_repo_proof') AS installed");
  if (!installed.rows[0].installed) {
    await repoPool.query(await fs.readFile(new URL('../candidates/atproto-signed-repo-proof/schema.sql', import.meta.url), 'utf8'));
  }
  const store = createSignedRepoProofStore({ pool: repoPool, fixtureOnly: true });
  const rev = makeTid();
  const repoInput = { accountId, did: operation.did, rev, publicKeyPem: commit.publicKeyPem,
    async signer(bytes) {
      const result = await signCall('signing.signAtprotoCommit', { canonicalAccountId: accountId,
        did: operation.did, rev, unsignedCommitBytesBase64: bytes.toString('base64') }, signingMeta);
      return Buffer.from(result.signatureBase64Url, 'base64url');
    } };
  const head = await store.bootstrap(repoInput);
  assert.equal(head.verified, true);
  assert.equal(head.did, operation.did);
  assert.equal((await store.bootstrap(repoInput)).commitCid, head.commitCid);
  await assert.rejects(signCall('signing.signAtprotoCommit', { canonicalAccountId: accountId,
    did: 'did:plc:' + 'z'.repeat(24), rev, unsignedCommitBytesBase64: 'AA==' }, signingMeta),
  error => error.type === 'INVALID_INPUT');
  await stop(runtime); runtime = undefined;
  runtime = await start();
  assert.deepEqual(await attempt(runtime), { kind: 'confirmed' }, 'registration survives directory restart');
  assert.equal((await runtime.db.opsForDid(operation.did)).length, 1);
  const verified = await store.verify({ accountId, did: operation.did, publicKeyPem: commit.publicKeyPem });
  assert.equal(verified.commitCid, head.commitCid);
  assert.equal(verified.verified, true);
  console.log(JSON.stringify({ accepted: true, referenceRevision: revision,
    invalidSignatureRejected: true, providerSigningHandlersVerified: true,
    signedPostgresRepositoryVerified: true,
    duplicateOperations: 0, directoryRestartVerified: true,
    successfulProviderSignup: false, productionReady: false }));
} finally {
  try { if (runtime) await stop(runtime); }
  finally { if (repoPool) await repoPool.end(); }
}
