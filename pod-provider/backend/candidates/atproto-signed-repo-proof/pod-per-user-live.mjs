/**
 * Disposable real Fuseki/TDB2 per-username dataset acceptance for the
 * non-activated ActivityPods provider adapter (NOT real deployed SemApps).
 * Requires exact loopback URL and explicit opt-in. No production resources.
 *
 * prepare: create isolated 'alice' dataset; prove provider tickets, OIDC
 * claims, current exact SAI RDF grants, same-dataset CAS, revocation race.
 * verify: after Fuseki restart, verify durable blocked consent and immutable
 * projected root. Deletes the disposable per-user dataset afterwards.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
const { buildIndexPageQuery } = createRequire(import.meta.url)('../../utils/identitybinding-index-query.js');
import { createPodOperationTicketAuthority } from './pod-operation-ticket.mjs';
import { createPodActivityPodsProjection } from './pod-activitypods-adapter.mjs';

if (process.env.NODE_ENV === 'production' ||
    process.env.ATPROTO_REPO_FUSEKI_PROOF_DISPOSABLE !== 'confirmed' ||
    process.env.FUSEKI_URL !== 'http://127.0.0.1:3040') {
  throw new Error('This test only targets explicitly disposable local Fuseki');
}
const phase = process.argv[2];
if (!['prepare','verify'].includes(phase)) throw new Error('Expected prepare or verify');
const origin = 'https://paper.example.org';
const accountId = origin + '/alice';
const storageRoot = accountId + '/data/';
const containerUri = storageRoot + 'identity-bindings/';
const did = 'did:plc:' + 'a'.repeat(24);
const appUri = origin + '/applications/paper';
const grantUri = storageRoot + 'access-grants/ag1';
const dataUri = storageRoot + 'data-grants/dg1';
const shape = origin + '/shapes/atproto-managed-repo';
const rev = '2222222222222';
const rootCid = 'bafyre' + 'a'.repeat(53);
const subjectUri = containerUri + 'atproto-' +
  crypto.createHash('sha256').update(accountId).digest('hex').slice(0, 24);
const host = process.env.FUSEKI_URL;
const auth = 'Basic ' + Buffer.from('admin:' + (process.env.FUSEKI_PASSWORD || 'admin')).toString('base64');
const apods = 'http://activitypods.org/ns/core#';
const interop = 'http://www.w3.org/ns/solid/interop#';
const prefix = 'PREFIX apods: <' + apods + '> PREFIX interop: <' + interop + '> ';
const semapps = 'http://semapps.org/ns/core#';

async function http(url, { method = 'GET', body = null, type = null, accept = null } = {}) {
  const reply = await fetch(url, {
    method, headers: {
      authorization: auth,
      ...(type ? { 'content-type': type } : {}),
      ...(accept ? { accept } : {})
    },
    body, signal: AbortSignal.timeout(20000)
  });
  const response = await reply.text();
  if (!reply.ok) throw Error('Fuseki HTTP ' + reply.status + ': ' + response.slice(0, 500));
  return response;
}
async function sparql(kind, query, dataset = 'alice') {
  assert.ok(['alice', 'settings'].includes(dataset), 'Only canonical Pod or owner index dataset');
  const reply = await http(host + '/' + dataset + '/' + kind, {
    method: 'POST',
    type: kind === 'query' ? 'application/sparql-query' : 'application/sparql-update',
    accept: 'application/sparql-results+json', body: query
  });
  return kind === 'query' ? JSON.parse(reply).results.bindings : undefined;
}
const val = (row, key) => row?.[key]?.value || null;
const iri = value => '<' + value + '>';
const validCredentials = {
  iss: origin + '/', sub: 'fixture-owner-account',
  aud: [appUri, 'solid'], azp: appUri, webid: accountId,
  cnf: { jkt: 'A'.repeat(43) },
  iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 600
};
let failOidc = false, failGrant = false, forgedLocation = false;
const actions = [];
async function call(name, params) {
  actions.push(name);
  if (name === 'solid-storage.getUrl') return forgedLocation ? origin + '/eve/data/' : storageRoot;
  if (name === 'identitybindings.getContainerUri') return containerUri;
  if (name === 'triplestore.dataset.exist') {
    assert.equal(params.dataset, 'alice');
    return true;
  }
  if (name === 'access-grants.getContainerUri') return storageRoot + 'access-grants/';
  if (name === 'data-grants.getContainerUri') return storageRoot + 'data-grants/';
  if (name === 'jwk.verifyToken') {
    assert.equal(params.token, 'synthetic-verified-local-jwk-fixture');
    if (failOidc === 'app-only') return { ...validCredentials, aud: appUri };
    if (failOidc === 'missing-solid') return { ...validCredentials, aud: [appUri, 'unrelated'] };
    if (failOidc === 'missing-dpop') return { ...validCredentials, cnf: undefined };
    return failOidc ? { ...validCredentials, aud: origin + '/evil' } : validCredentials;
  }
  if (name === 'access-grants.get') {
    assert.equal(params.webId, 'system');
    if (failGrant) return null;
    const rows = await sparql('query', prefix +
      'SELECT ?owner ?grantee ?data WHERE { ' + iri(grantUri) +
      ' interop:grantedBy ?owner ; interop:grantee ?grantee ; interop:hasDataGrant ?data . } LIMIT 3');
    if (rows.length !== 1) return null;
    return {
      '@id': grantUri,
      'interop:grantedBy': val(rows[0], 'owner'),
      'interop:grantee': val(rows[0], 'grantee'),
      'interop:hasDataGrant': val(rows[0], 'data')
    };
  }
  if (name === 'data-grants.get') {
    assert.equal(params.webId, 'system');
    const rows = await sparql('query', prefix +
      'SELECT ?owner ?grantee ?shape ?mode WHERE { ' + iri(dataUri) +
      ' interop:dataOwner ?owner ; interop:grantee ?grantee ; ' +
      'interop:registeredShapeTree ?shape ; interop:accessMode ?mode . } LIMIT 3');
    if (rows.length !== 1) return null;
    return {
      '@id': dataUri,
      'interop:dataOwner': val(rows[0], 'owner'),
      'interop:grantee': val(rows[0], 'grantee'),
      'interop:registeredShapeTree': val(rows[0], 'shape'),
      'interop:accessMode': val(rows[0], 'mode')
    };
  }
  if (name === 'identitybindings.getByCanonicalAccountId') {
    assert.equal(params.canonicalAccountId, accountId);
    const rows = await sparql('query', prefix +
      'SELECT ?canonical ?web ?actor ?did ?source ?managed ?status ?initialized ?root ?rev ?fence WHERE { ' +
      iri(subjectUri) + ' a apods:AtprotoIdentityBinding ; ' +
      'apods:canonicalAccountId ?canonical ; apods:webId ?web ; ' +
      'apods:activityPubActorId ?actor ; apods:atprotoDid ?did ; apods:atprotoSource ?source ; ' +
      'apods:atprotoManaged ?managed ; apods:status ?status ; ' +
      'apods:repoInitialized ?initialized . ' +
      'OPTIONAL { ' + iri(subjectUri) + ' apods:repoRootCid ?root . } ' +
      'OPTIONAL { ' + iri(subjectUri) + ' apods:repoRev ?rev . } ' +
      'OPTIONAL { ' + iri(subjectUri) + ' apods:repoProjectionFence ?fence . } } LIMIT 3');
    assert.equal(rows.length, 1, 'One canonical LDP RDF binding');
    return {
      id: subjectUri, canonicalAccountId: val(rows[0], 'canonical'),
      webId: val(rows[0], 'web'), activityPubActorId: val(rows[0], 'actor'),
      atprotoDid: val(rows[0], 'did'), atprotoSource: val(rows[0], 'source'),
      atprotoManaged: val(rows[0], 'managed') === 'true',
      status: val(rows[0], 'status'),
      repoInitialized: val(rows[0], 'initialized') === 'true',
      repoRootCid: val(rows[0], 'root'),
      repoRev: val(rows[0], 'rev'),
      repoProjectionFence: val(rows[0], 'fence')
    };
  }
  if (name === 'triplestore.query' || name === 'triplestore.update') {
    assert.equal(params.webId, 'system');
    if (name === 'triplestore.update') assert.equal(params.dataset, 'alice', 'Owner lookup dataset is read-only');
    return sparql(name.endsWith('query') ? 'query' : 'update', params.query, params.dataset);
  }
  throw Error('Unexpected action: ' + name);
}
const authority = createPodOperationTicketAuthority({ secret: crypto.randomBytes(32) });
const adapter = createPodActivityPodsProjection({
  call, operationTickets: authority, expectedIssuer: origin + '/',
  expectedRepoShapeTree: shape, fixtureOnly: true
});
const ticket = (operation, epoch = '1', head = {}) => authority.issue({
  accountId, did, appUri, grantUri, epoch, operation,
  ...(operation === 'project' ? { rootCid, rev, projectionFence: '1' } : {}), ...head
});
const base = { accountId, did, appUri, grantUri, epoch: '1' };
const oidcToken = 'synthetic-verified-local-jwk-fixture';

async function prepare() {
  // Seed the actual SemApps AuthAccount shape only in the existing settings
  // lookup dataset. This is an indexed, max-2-row read; every repository
  // mutation stays exclusively within the owner 'alice' dataset.
  await sparql('update', 'PREFIX semapps: <' + semapps + '> INSERT DATA { ' +
    '<urn:AuthAccount:alice> a semapps:AuthAccount ; semapps:webId "' + accountId + '" ; ' +
    'semapps:username "alice" . }', 'settings');

  // Pod dataset from actual solid-storage.create naming scheme (username),
  // not the globally shared 'settings' lookup projection.
  const created = await http(host + '/$/datasets', {
    method: 'POST', type: 'application/x-www-form-urlencoded',
    body: new URLSearchParams({ dbName: 'alice', dbType: 'tdb2' }).toString()
  });
  assert.ok(created !== undefined);
  await sparql('update', prefix + 'INSERT DATA { ' +
    iri(subjectUri) + ' a apods:AtprotoIdentityBinding ; ' +
      'apods:canonicalAccountId "' + accountId + '" ; apods:webId ' + iri(accountId) + ' ; ' +
      'apods:activityPubActorId ' + iri(accountId) + ' ; apods:atprotoDid "' + did + '" ; ' +
      'apods:atprotoSource "local" ; apods:atprotoManaged true ; ' +
      'apods:status "active" ; apods:repoInitialized false . ' +
    iri(grantUri) + ' a interop:AccessGrant ; interop:grantedBy ' + iri(accountId) + ' ; ' +
      'interop:grantee ' + iri(appUri) + ' ; interop:hasDataGrant ' + iri(dataUri) + ' . ' +
    iri(dataUri) + ' a interop:DataGrant ; interop:dataOwner ' + iri(accountId) + ' ; ' +
      'interop:grantee ' + iri(appUri) + ' ; interop:registeredShapeTree ' + iri(shape) + ' ; ' +
      'interop:accessMode <http://www.w3.org/ns/auth/acl#Write> . }');

  // Query the same keyset builder on genuine Jena (rather than only string
  // unit tests). This exercises Fuseki's SPARQL parser and stable two-page
  // ordering without scanning every user or materializing a full index.
  const indexSubjects = ['a', 'b', 'c'].map(name =>
    'urn:paper:atproto:index-proof:' + name);
  await sparql('update', prefix + 'INSERT DATA { ' +
    indexSubjects.map((subject, n) =>
      iri(subject) + ' a apods:AtprotoIdentityBindingIndex ; ' +
      'apods:canonicalAccountId "' + origin + '/accounts/' + n + '" ; ' +
      'apods:updatedAt "2026-11-11T12:00:00.000Z" . '
    ).join('') + ' }');
  const ordered = await sparql('query', buildIndexPageQuery({ limit: 3 }));
  assert.deepEqual(ordered.map(row => val(row, 'canonicalAccountId')), [
    origin + '/accounts/0', origin + '/accounts/1', origin + '/accounts/2'
  ]);
  const next = await sparql('query', buildIndexPageQuery({
    cursor: { updatedAt: '2026-11-11T12:00:00.000Z',
      canonicalAccountId: origin + '/accounts/1' },
    limit: 3
  }));
  assert.deepEqual(next.map(row => val(row, 'canonicalAccountId')), [
    origin + '/accounts/2'
  ]);

  // Exact ActivityPods account/storage location, not a user-selected dataset.
  const location = await adapter.locate(accountId);
  assert.equal(location.dataset, 'alice');
  assert.equal(location.resourceUri, subjectUri);

  // Duplicate canonical WebID subjects must not pick one arbitrary owner.
  const poisoned = 'PREFIX semapps: <' + semapps + '> ';
  const rogue = '<urn:AuthAccount:mallory> a semapps:AuthAccount ; ' +
    'semapps:webId "' + accountId + '" ; semapps:username "mallory" . ';
  await sparql('update', poisoned + 'INSERT DATA { ' + rogue + ' }', 'settings');
  await assert.rejects(adapter.locate(accountId), e => e.code === 'POD_PROJECTION_OWNER_UNKNOWN');
  await sparql('update', poisoned + 'DELETE DATA { ' + rogue + ' }', 'settings');

  forgedLocation = true;
  await assert.rejects(adapter.locate(accountId), e => e.code === 'POD_PROJECTION_LOCATION_INVALID');
  forgedLocation = false;

  await assert.rejects(
    adapter.bootstrapConsent({ ...base, ticket: ticket('revoke'), oidcToken }),
    e => e.code === 'POD_PROJECTION_PROVIDER_UNAUTHORIZED'
  );
  failOidc = true;
  await assert.rejects(
    adapter.bootstrapConsent({ ...base, ticket: ticket('bootstrap'), oidcToken }),
    e => e.code === 'POD_PROJECTION_OIDC_INVALID'
  );
  for (const invalidTokenShape of ['app-only', 'missing-solid', 'missing-dpop']) {
    failOidc = invalidTokenShape;
    await assert.rejects(
      adapter.bootstrapConsent({ ...base, ticket: ticket('bootstrap'), oidcToken }),
      e => e.code === 'POD_PROJECTION_OIDC_INVALID'
    );
  }
  failOidc = false;
  failGrant = true;
  await assert.rejects(
    adapter.bootstrapConsent({ ...base, ticket: ticket('bootstrap'), oidcToken }),
    e => e.code === 'POD_PROJECTION_SAI_INVALID'
  );
  failGrant = false;

  assert.equal((await adapter.bootstrapConsent({ ...base, ticket: ticket('bootstrap'), oidcToken })).status, 'active');
  // Replay an identical verified bootstrap: never silently reinitialize.
  assert.equal((await adapter.bootstrapConsent({ ...base, ticket: ticket('bootstrap'), oidcToken })).epoch, '1');

  const projected = await adapter.project({
    ...base, rootCid, rev, projectionFence: '1', oidcToken, ticket: ticket('project')
  });
  assert.equal(projected.projected, true);
  assert.ok(!actions.includes('auth.account.findByWebId'), 'Avoid SemApps unbounded CONSTRUCT');
  assert.ok(!actions.includes('auth.account.find'), 'No account population/fan-out lookup');
  assert.ok(!actions.includes('access-grants.getForApp'));
  assert.ok(!actions.includes('data-grants.getByAccessNeed'));
  assert.equal((await adapter.check({ ...base, rootCid, rev,
    projectionFence: '1', oidcToken })).projectionVerified, true);

  // Simulate a PostgreSQL recovery worker crash AFTER RDF mutation and before
  // durable PG ACK. Its lease_epoch advances from 1 to 2, while the same
  // SAI grant remains active at consent revision 1. The older candidate
  // incorrectly conflated these epochs and could never recover.
  const replay = await adapter.project({
    ...base, projectionFence: '2', rootCid, rev, oidcToken,
    ticket: ticket('project', '1', { projectionFence: '2' })
  });
  assert.equal(replay.projected, true);
  assert.equal(replay.consentRevision, '1');
  assert.equal(replay.projectionFence, '2');
  assert.equal((await adapter.check({
    ...base, rootCid, rev, projectionFence: '2', oidcToken
  })).projectionVerified, true);
  await assert.rejects(
    adapter.project({ ...base, rootCid, rev, projectionFence: '1',
      oidcToken, ticket: ticket('project') }),
    e => e.code === 'POD_PROJECTION_READBACK_MISMATCH'
  );

  // Two independent async request sequences race a live Jena permission
  // revocation and a stale projection. Either could acquire the Jena writer
  // first, but the FINAL state must always be denied, never false-ready.
  const contested = await Promise.allSettled([
    adapter.project({ ...base, rootCid, rev, projectionFence: '2', oidcToken,
      ticket: ticket('project', '1', { projectionFence: '2' }) }),
    adapter.revoke({ ...base, ticket: ticket('revoke') })
  ]);
  assert.equal(contested[1].status, 'fulfilled', 'Revocation must durably win eventual access state');
  assert.equal(contested[1].value.epoch, '2');
  await assert.rejects(
    adapter.project({ ...base, rootCid, rev, projectionFence: '3', oidcToken,
      ticket: ticket('project', '1', { projectionFence: '3' }) }),
    e => e.code === 'POD_CONSENT_NOT_ACTIVE'
  );
  await assert.rejects(
    adapter.check({ ...base, rootCid, rev, projectionFence: '2', oidcToken }),
    e => e.code === 'POD_CONSENT_NOT_ACTIVE'
  );
  await assert.rejects(
    adapter.bootstrapConsent({ ...base, oidcToken, ticket: ticket('bootstrap') }),
    e => e.code === 'POD_CONSENT_CONFLICT'
  );
  console.log('PASS: real username-scoped TDB2 dataset, SAI grant, OIDC claims, CAS, irrevocable block, bounded calls');
}
async function verify() {
  const rows = await sparql('query', prefix + 'SELECT ?root ?rev ?epoch WHERE { ' + iri(subjectUri) +
    ' apods:repoRootCid ?root ; apods:repoRev ?rev ; apods:repoProjectionFence ?epoch . }');
  assert.equal(rows.length, 1);
  assert.equal(val(rows[0], 'root'), rootCid);
  assert.equal(val(rows[0], 'rev'), rev);
  assert.equal(val(rows[0], 'epoch'), '2');
  // Persistent consent is blocked even after Fuseki restart.
  await assert.rejects(
    adapter.check({ ...base, rootCid, rev, projectionFence: '2', oidcToken }),
    e => e.code === 'POD_CONSENT_NOT_ACTIVE'
  );
  await http(host + '/$/datasets/alice', { method: 'DELETE' });
  console.log('PASS: per-user TDB2 projection + SAI revocation persisted across restart');
}
await (phase === 'prepare' ? prepare() : verify());
