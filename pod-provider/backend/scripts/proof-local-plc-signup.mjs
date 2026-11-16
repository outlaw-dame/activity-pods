/**
 * Local reference PLC + PostgreSQL acceptance for the real provider PLC builder
 * and submitter. This is identity-directory acceptance, NOT successful signup,
 * real provider key custody, SAI consent or hosted PDS acceptance.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';

const require = createRequire(import.meta.url);
const { submitPlcGenesis } = require('../utils/atproto-plc-submission');
const builder = require('../services/core/atproto-plc-builder.service');
const reference = process.env.PAPER_LOCAL_PLC_REFERENCE;
const configPath = process.env.PAPER_LOCAL_PLC_CONFIG;
const revision = '29f1a70ee9f6f80a25946cac103b2f745e371334';
assert.equal(process.env.NODE_ENV, 'test');
assert.equal(process.env.PAPER_LOCAL_PLC_DISPOSABLE, 'confirmed');
assert(reference?.startsWith('/') && configPath?.startsWith('/'));
assert.equal(execFileSync('git', ['-C', reference, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), revision);
const config = JSON.parse(await fs.readFile(configPath, 'utf8'));
const dbUrl = new URL(config.databaseUrl);
assert.equal(dbUrl.protocol, 'postgres:');
assert.equal(dbUrl.hostname, '127.0.0.1');
assert.equal(dbUrl.port, '5549');
assert.equal(dbUrl.pathname, '/paper_local_plc');
assert.equal(dbUrl.username, 'paper_local_plc');
const refRequire = createRequire(`${reference}/packages/server/package.json`);
const { Secp256k1Keypair } = await import(pathToFileURL(refRequire.resolve('@atproto/crypto')));
const { PlcServer, PgDatabase } = await import(pathToFileURL(`${reference}/packages/server/dist/index.js`));

// The keys are real and ephemeral; private key material never leaves this test.
const commit = await Secp256k1Keypair.create();
const rotation = await Secp256k1Keypair.create();
const operation = await builder.actions.buildAndSign.handler.call({ _signingCallMeta: () => ({}) }, {
  params: { canonicalAccountId: 'https://provider.paper.example.org/local-plc-proof',
    handle: 'local-plc-proof.paper.example.org', pdsEndpoint: 'https://provider.paper.example.org' },
  async call(action, params) {
    if (action === 'signing.getAtprotoPublicKey') {
      return { publicKeyMultibase: (params.purpose === 'commit' ? commit : rotation).did().slice(8) };
    }
    assert.equal(action, 'signing.signAtprotoPlcOp');
    return { signatureBase64Url: Buffer.from(await rotation.sign(Buffer.from(params.operationBytesBase64, 'base64'))).toString('base64url') };
  }
});

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
try {
  runtime = await start();
  const invalid = { ...operation.signedOp, sig: Buffer.alloc(64).toString('base64url') };
  assert.equal((await attempt(runtime, invalid)).kind, 'failed', 'reference server rejects an invalid signature');
  assert.deepEqual(await attempt(runtime), { kind: 'confirmed' });
  assert.deepEqual(await attempt(runtime), { kind: 'confirmed' }, 'same signed genesis is replayable');
  assert.equal((await runtime.db.opsForDid(operation.did)).length, 1, 'no duplicate genesis');
  const doc = await fetch(`${runtime.origin}/${operation.did}`).then(response => response.json());
  assert.equal(doc.id, operation.did);
  assert.equal(doc.verificationMethod[0].publicKeyMultibase, commit.did().slice(8));
  await stop(runtime); runtime = undefined;
  runtime = await start();
  assert.deepEqual(await attempt(runtime), { kind: 'confirmed' }, 'registration survives directory restart');
  assert.equal((await runtime.db.opsForDid(operation.did)).length, 1);
  console.log(JSON.stringify({ accepted: true, referenceRevision: revision,
    invalidSignatureRejected: true, duplicateOperations: 0, directoryRestartVerified: true,
    successfulProviderSignup: false, productionReady: false }));
} finally {
  if (runtime) await stop(runtime);
}
