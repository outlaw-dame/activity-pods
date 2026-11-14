/**
 * NONACTIVATED, disposable real Fuseki HTTP admission proof.
 * Validates dataset/endpoint isolation against a real Shiro configuration,
 * not per-graph WAC/SAI and not the production ActivityPods storage path.
 *
 * prepare: independent principals can write only their assigned TDB2 dataset.
 * verify: durable projected RDF survives restart; cross-role attempts stay denied.
 */
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';

if (process.env.NODE_ENV === 'production' ||
    process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE !== 'confirmed' ||
    process.env.FUSEKI_ISOLATION_URL !== 'http://127.0.0.1:3041') {
  throw new Error('Disposable loopback Fuseki isolation proof only');
}
const phase = process.argv[2];
if (!['prepare', 'verify'].includes(phase)) throw new Error('Expected prepare or verify');
const origin = process.env.FUSEKI_ISOLATION_URL;
const subjects = Object.freeze({
  protected: '<urn:paper:isolated:identity-binding>',
  ordinary: '<urn:paper:isolated:ordinary>'
});
const predicate = '<urn:paper:isolated:state>';
// Fixed, public test-only passwords. NEVER reuse for deployment.
const credentials = Object.freeze({
  admin: 'admin:fixture-admin-only',
  projector: 'fixture-projector:fixture-projector-only',
  attestor: 'fixture-attestor:fixture-attestor-only',
  ordinary: 'fixture-ordinary:fixture-ordinary-only'
});
const auth = principal => principal === null ? {} : {
  authorization: 'Basic ' + Buffer.from(credentials[principal]).toString('base64')
};
const sparqlType = 'application/sparql-update';
const queryType = 'application/sparql-query';
const denialCodes = new Set([401, 403]);

async function request(route, principal, { method = 'POST', body = null, type = null, accept = null } = {}) {
  // A referenced timer is essential during first-container startup:
  // AbortSignal.timeout alone may let Node exit with an unsettled top-level
  // await while an Undici connection attempt has no referenced handles.
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(origin + route, {
      method,
      headers: {
        ...auth(principal),
        ...(type ? { 'content-type': type } : {}),
        ...(accept ? { accept } : {})
      },
      body,
      signal: controller.signal,
      redirect: 'manual'
    });
    // Do not follow redirects: a 302 to an unprotected endpoint is not denial.
    const responseBody = await response.text();
    return { status: response.status, body: responseBody };
  } finally {
    clearTimeout(deadline);
  }
}
function accepted(reply, label) {
  assert.ok(reply.status >= 200 && reply.status < 300,
    label + ': expected authorized 2xx, got HTTP ' + reply.status +
      ': ' + reply.body.slice(0, 180));
}
function denied(reply, label) {
  assert.ok(denialCodes.has(reply.status),
    label + ': credential must be refused by security layer (401/403), HTTP ' +
      reply.status + ': ' + reply.body.slice(0, 180));
}
async function ready() {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const r = await request('/$/ping', null, { method: 'GET' });
      if (r.status === 200) return;
    } catch { /* service not yet bound */ }
    await sleep(1000);
  }
  throw new Error('Disposable Fuseki failed to become ready within bounded startup');
}
async function createDataset(name) {
  const body = new URLSearchParams({ dbName: name, dbType: 'tdb2' }).toString();
  accepted(await request('/$/datasets', 'admin', {
    type: 'application/x-www-form-urlencoded', body
  }), 'Admin creates isolated ' + name + ' dataset');
}
async function update(name, principal, body) {
  return request('/' + name + '/update', principal, { type: sparqlType, body });
}
async function read(name, principal, subject) {
  const q = 'SELECT ?value WHERE { ' + subject + ' ' + predicate + ' ?value }';
  const r = await request('/' + name + '/query', principal, {
    type: queryType, body: q, accept: 'application/sparql-results+json'
  });
  accepted(r, 'Authorized isolated read of ' + name);
  const parsed = JSON.parse(r.body);
  return (parsed.results?.bindings || []).map(row => row.value?.value);
}
async function proveDenied() {
  const hostileUpdate = 'DELETE WHERE { ' + subjects.protected + ' ' + predicate + ' ?v }';
  const probes = [
    ['attestor direct SPARQL update', '/protected-proof/update', 'attestor',
      { type: sparqlType, body: hostileUpdate }],
    ['attestor Graph Store DELETE', '/protected-proof/data', 'attestor',
      { method: 'DELETE' }],
    ['attestor alternate update route', '/protected-proof/sparql', 'attestor',
      { type: sparqlType, body: hostileUpdate }],
    ['attestor admin access', '/$/datasets', 'attestor',
      { type: 'application/x-www-form-urlencoded',
        body: 'dbName=hostile-proof&dbType=tdb2' }],
    ['ordinary direct SPARQL update', '/protected-proof/update', 'ordinary',
      { type: sparqlType, body: hostileUpdate }],
    ['anonymous SPARQL update', '/protected-proof/update', null,
      { type: sparqlType, body: hostileUpdate }],
    ['ordinary Graph Store PUT', '/protected-proof/data', 'ordinary',
      { method: 'PUT', type: 'text/turtle', body:
        subjects.protected + ' ' + predicate + ' "forged" .' }],
    ['ordinary Graph Store DELETE', '/protected-proof/data', 'ordinary',
      { method: 'DELETE' }],
    ['ordinary alternate SPARQL route', '/protected-proof/sparql', 'ordinary',
      { type: sparqlType, body: hostileUpdate }],
    ['ordinary dataset-root update', '/protected-proof', 'ordinary',
      { type: sparqlType, body: hostileUpdate }],
    ['ordinary dataset-root slash update', '/protected-proof/', 'ordinary',
      { type: sparqlType, body: hostileUpdate }],
    ['ordinary dataset creation', '/$/datasets', 'ordinary',
      { type: 'application/x-www-form-urlencoded',
        body: 'dbName=hostile-proof&dbType=tdb2' }],
    ['ordinary dataset destruction', '/$/datasets/protected-proof', 'ordinary',
      { method: 'DELETE' }],
    ['ordinary backup admission', '/$/backup/protected-proof', 'ordinary', {}],
    ['projector crosses into ordinary dataset', '/ordinary-proof/update', 'projector',
      { type: sparqlType, body: 'DELETE WHERE { ' +
        subjects.ordinary + ' ' + predicate + ' ?v }' }]
  ];
  for (const [label, route, principal, options] of probes) {
    denied(await request(route, principal, options), label);
  }
  denied(await request('/protected-proof/query', 'ordinary', {
    type: queryType, body: 'ASK {}'
  }), 'ordinary protected query');
  denied(await request('/protected-proof/query', null, {
    type: queryType, body: 'ASK {}'
  }), 'anonymous protected query');
  assert.deepEqual(await read('protected-proof', 'attestor', subjects.protected),
    ['signed-baseline'], 'Independent read-only attestor must access protected RDF');
  assert.deepEqual(await read('protected-proof', 'projector', subjects.protected),
    ['signed-baseline'], 'Unauthorized mutations cannot alter protected RDF');
  assert.deepEqual(await read('ordinary-proof', 'ordinary', subjects.ordinary),
    ['ordinary-baseline'], 'Projector cannot alter other datasets');
  return probes.length + 2;
}
await ready();
if (phase === 'prepare') {
  await createDataset('protected-proof');
  await createDataset('ordinary-proof');
  // Bounded authentication matrix: helps distinguish Shiro credential
  // rejection from the SPARQL service's separate update authorization.
  for (const principal of ['projector', 'attestor', 'ordinary', 'admin']) {
    const response = await request('/protected-proof/query', principal, {
      type: queryType, body: 'ASK {}',
      accept: 'application/sparql-results+json'
    });
    process.stdout.write('FUSEKI_PRINCIPAL_PROBE ' +
      JSON.stringify({ principal, endpoint: 'protected-proof/query',
        status: response.status }) + '\n');
  }
  accepted(await update('protected-proof', 'projector',
    'INSERT DATA { ' + subjects.protected + ' ' + predicate +
      ' "signed-baseline" . }'), 'Projection worker writes protected RDF');
  accepted(await update('ordinary-proof', 'ordinary',
    'INSERT DATA { ' + subjects.ordinary + ' ' + predicate +
      ' "ordinary-baseline" . }'), 'Ordinary writer writes its own RDF');
}
const refused = await proveDenied();
process.stdout.write('DISPOSABLE_FUSEKI_DATASET_ISOLATION ' +
  JSON.stringify({ phase, deniedRoutes: refused,
    independentWriters: true, persistedReadback: true,
    productionStorageReleased: false }) + '\n');
