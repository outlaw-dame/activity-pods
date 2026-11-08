'use strict';

/**
 * Real Fuseki TDB2 integration proof for the provider's G1 reservation service.
 * Uses an isolated test dataset and direct SPARQL HTTP adapter; intentionally
 * does not start the application, publish Group actors, or mint real grants.
 *
 * Run:
 *   FUSEKI_URL=http://127.0.0.1:3040 node scripts/proof-collective-fuseki.js prepare
 *   # restart the persistent Fuseki container
 *   FUSEKI_URL=http://127.0.0.1:3040 node scripts/proof-collective-fuseki.js verify
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const service = require('../services/collective-reservations.service');

const origin = 'https://groups-proof.example';
const principal = origin + '/users/test-authority';
const app = 'https://group-client.example/application';
const key = 'g1fusekiintegrationidempotent01';
const name = 'G1 Real Fuseki Proof';
const secret = 's'.repeat(48);
const workerSecret = 'w'.repeat(48);
const workerPurpose = 'provider.collective.worker.advance.v1';
const identityKey = 'i'.repeat(48);
const purpose = 'provider.collective.reservation.v1';
const endpoint = (process.env.FUSEKI_URL || 'http://127.0.0.1:3040').replace(/\/+$/u, '');
const auth = 'Basic ' + Buffer.from((process.env.FUSEKI_USER || 'admin') + ':' +
  (process.env.FUSEKI_PASSWORD || 'admin')).toString('base64');

const sha = v => crypto.createHash('sha256').update(v).digest('hex');
function grant(operation, requestHash) {
  const issuedAt = Date.now() - 1000;
  const expiresAt = issuedAt + 60000;
  const fields = [purpose, principal, app, operation, requestHash, issuedAt, expiresAt];
  return { purpose, principal, app, operation, requestHash, issuedAt, expiresAt,
    mac: crypto.createHmac('sha256', secret).update(JSON.stringify(fields)).digest('hex') };
}
function reserveParams(displayName = name) {
  return { principal, app, idempotencyKey: key, displayName,
    grant: grant('reserve', sha(JSON.stringify([principal, app, key, displayName]))) };
}
function advanceParams(id, revision, nextStage) {
  const issuedAt = Date.now() - 1000;
  const expiresAt = issuedAt + 60000;
  const fields = [workerPurpose, id, revision, nextStage, issuedAt, expiresAt];
  return { canonicalGroupId: id, principal, app, expectedRevision: revision, nextStage,
    workerGrant: { purpose: workerPurpose, groupId: id, revision, nextStage, issuedAt, expiresAt,
      mac: crypto.createHmac('sha256', workerSecret).update(JSON.stringify(fields)).digest('hex') } };
}
const id = 'cg_' + crypto.createHmac('sha256', identityKey)
  .update(JSON.stringify([principal, app, key])).digest('hex').slice(0, 32);

async function fuseki(method, query) {
  const url = endpoint + '/settings/' + (method === 'update' ? 'update' : 'query');
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: auth,
      'content-type': method === 'update' ? 'application/sparql-update' : 'application/sparql-query',
      accept: 'application/sparql-results+json'
    },
    body: query,
    signal: AbortSignal.timeout(20000)
  });
  const body = await response.text();
  if (!response.ok) throw new Error('Fuseki ' + method + ' HTTP ' + response.status +
    ': ' + body.slice(0, 600));
  if (method === 'update') return {};
  const result = JSON.parse(body);
  assert.equal(result?.head?.vars?.length > 0, true);
  return result.results.bindings;
}

function instance() {
  const obj = {
    settings: { enabled: true, providerOrigin: origin, secret, identityKey, workerSecret, approvedApps: [app] }
  };
  obj._load = service.methods._load.bind(obj);
  return obj;
}
async function call(instanceObj, actionName, params) {
  const ctx = {
    params,
    call: async (serviceName, args) => {
      // SAI fixtures isolate persistence semantics; live SAI must be verified
      // in a separate authenticated end-to-end integration test.
      if (serviceName === 'auth.account.findByWebId') return { webId: args.webId };
      if (serviceName === 'app-registrations.isRegistered') return true;
      if (serviceName === 'access-authorizations.getSpecialRights') return ['apods:CreateGroup', 'apods:ReadGroups'];
      assert.equal(args.dataset, 'settings');
      assert.equal(args.webId, 'system');
      if (serviceName === 'triplestore.update') return fuseki('update', args.query);
      if (serviceName === 'triplestore.query') return fuseki('query', args.query);
      throw new Error('Unexpected action ' + serviceName);
    }
  };
  return service.actions[actionName].handler.call(instanceObj, ctx);
}
async function count(id) {
  const rows = await fuseki('query', 'SELECT (COUNT(*) AS ?count) WHERE { <urn:apods:collective:' +
    id + '> ?p ?o }');
  return Number(rows[0]?.count?.value || 0);
}

async function prepare() {
  // Concurrent distinct service instances emulate independent Node/Moleculer replicas.
  const tasks = Array.from({ length: 12 }, () => call(instance(), 'reserve', reserveParams()));
  const results = await Promise.all(tasks);
  assert(results.every(v => v.canonicalGroupId === id && v.actorUri === origin + '/groups/' + id));
  assert((await count(id)) >= 9, 'expected durable identity RDF triples');
  const replays = await call(instance(), 'reserve', reserveParams());
  assert.equal(replays.canonicalGroupId, id);
  await assert.rejects(call(instance(), 'reserve', reserveParams('Conflicting Request')),
    e => e.type === 'COLLECTIVE_RESERVATION_CONFLICT');

  const races = await Promise.allSettled(Array.from({ length: 12 },
    () => call(instance(), 'advance', advanceParams(id, 1, 'ap-key-pending'))));
  const wins = races.filter(x => x.status === 'fulfilled');
  assert.equal(wins.length, 1, 'exactly one successful transition across replicas');
  assert(races.filter(x => x.status === 'rejected')
    .every(x => x.reason?.type === 'COLLECTIVE_STALE_REVISION'), 'all losing CAS requests reject');
  const read = await call(instance(), 'get', {
    canonicalGroupId: id, principal, app, grant: grant('read', id)
  });
  assert.equal(read.stage, 'ap-key-pending');
  assert.equal(read.revision, 2);
  console.log(JSON.stringify({ ok: true, phase: 'prepare', groupId: id,
    reservations: results.length, winningCas: wins.length, revision: read.revision }));
}
async function verify() {
  const read = await call(instance(), 'get', {
    canonicalGroupId: id, principal, app, grant: grant('read', id)
  });
  assert.equal(read.canonicalGroupId, id);
  assert.equal(read.stage, 'ap-key-pending');
  assert.equal(read.revision, 2);
  assert((await count(id)) >= 9);
  console.log(JSON.stringify({ ok: true, phase: 'verify-after-restart', groupId: id,
    revision: read.revision }));
}

(async () => {
  const phase = process.argv[2];
  if (phase === 'prepare') return prepare();
  if (phase === 'verify') return verify();
  throw new Error('Expected prepare or verify mode');
})().catch(e => { console.error(e); process.exitCode = 1; });
