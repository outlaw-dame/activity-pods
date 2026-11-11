/**
 * Real, isolated Fuseki/TDB2 proof of the conditional RDF projection writer.
 * Does not exercise live ActivityPods permissions or user Pod datasets.
 *
 * prepare: seed two synthetic protected bindings; concurrent fenced updates.
 * verify: read persisted fences after Fuseki container restart.
 */
import assert from 'node:assert/strict';
import { buildFencedRepoProjectionSparql } from './fuseki-fence.mjs';

if (process.env.ATPROTO_REPO_FUSEKI_PROOF_DISPOSABLE !== 'confirmed') {
  throw new Error('Refusing to use Fuseki without explicit disposable marker');
}
const base = (process.env.FUSEKI_URL || '').replace(/\/+$/, '');
if (base !== 'http://127.0.0.1:3040') {
  throw new Error('Only the loopback test Fuseki endpoint is permitted');
}
const stage = process.argv[2];
if (!['prepare', 'verify'].includes(stage)) throw new Error('Specify prepare or verify');
const auth = 'Basic ' + Buffer.from('admin:' + (process.env.FUSEKI_PASSWORD || 'admin')).toString('base64');
const ds = base + '/settings/';
const prefix = 'PREFIX apods: <http://activitypods.org/ns/core#> ';
const account = 'https://paper.example.org/users/fuseki-proof';
const did = 'did:plc:' + 'p'.repeat(24);
const root = 'bafyre' + 'a'.repeat(53);
const changedRoot = 'bafyre' + 'b'.repeat(53);
const rev = '2222222222222';
const subject = 'urn:paper:atproto:proof:binding';
const namedSubject = 'urn:paper:atproto:proof:named';
const graph = 'urn:paper:atproto:proof:graph';
const badSubject = 'urn:paper:atproto:proof:malformed';
const duplicateSubject = 'urn:paper:atproto:proof:duplicate-identity';
const iri = s => '<' + s + '>';

async function http(kind, query) {
  const reply = await fetch(ds + kind, {
    method: 'POST',
    headers: {
      authorization: auth,
      'content-type': kind === 'query' ? 'application/sparql-query' : 'application/sparql-update',
      accept: 'application/sparql-results+json'
    },
    body: query,
    signal: AbortSignal.timeout(25000)
  });
  const body = await reply.text();
  if (!reply.ok) throw new Error('Fuseki rejected ' + kind + ': HTTP ' + reply.status + ': ' + body.slice(0, 450));
  return kind === 'query' ? JSON.parse(body).results.bindings : null;
}
function bindingTurtle(subjectIri, extras = '') {
  return iri(subjectIri) + ' a apods:AtprotoIdentityBinding ; ' +
    'apods:canonicalAccountId "' + account + '" ; apods:webId <' + account + '> ; ' +
    'apods:activityPubActorId <' + account + '> ; ' +
    'apods:atprotoDid "' + did + '" ; apods:atprotoManaged true ; ' +
    'apods:atprotoSource "local" ; apods:status "active" ; ' +
    'apods:repoInitialized false ' + extras + ' . ';
}
function update(subjectIri, fence, opts = {}) {
  return buildFencedRepoProjectionSparql({
    resourceUri: subjectIri, graphUri: opts.graphUri || null,
    accountId: account, did: opts.did || did, rootCid: opts.rootCid || root,
    rev, fence
  });
}
async function check(subjectIri, opts = {}) {
  const wrapped = x => opts.graphUri ? 'GRAPH ' + iri(opts.graphUri) + ' { ' + x + ' }' : x;
  const rows = await http('query',
    prefix + 'SELECT ?root ?rev ?fence ?did WHERE { ' + wrapped(
      iri(subjectIri) + ' apods:repoRootCid ?root ; apods:repoRev ?rev ; ' +
      'apods:repoProjectionFence ?fence ; apods:atprotoDid ?did . '
    ) + ' }'
  );
  assert.equal(rows.length, 1, 'one authoritative projected RDF binding required');
  return Object.fromEntries(Object.entries(rows[0]).map(([key, value]) => [key, value.value]));
}
async function prepare() {
  assert.throws(() => update(subject + '><INJECT', '1'), e => e.code === 'RDF_FENCE_INPUT_INVALID');
  assert.throws(() => update(subject, '0'), e => e.code === 'RDF_FENCE_INPUT_INVALID');
  assert.throws(() => update(subject, '9223372036854775808'), e => e.code === 'RDF_FENCE_INPUT_INVALID');
  await http('update', prefix + 'INSERT DATA { ' +
    bindingTurtle(subject) +
    ' GRAPH ' + iri(graph) + ' { ' + bindingTurtle(namedSubject) + ' } ' +
    bindingTurtle(badSubject, ' ; apods:repoProjectionFence "nonnumeric"') +
    bindingTurtle(duplicateSubject) +
    iri(duplicateSubject) + ' apods:atprotoDid "did:plc:' + 'q'.repeat(24) + '" . ' +
    ' }');
  await Promise.all(Array.from({ length: 8 }, (_, index) => {
    return http('update', update(subject, String(index + 1)));
  }));
  let row = await check(subject);
  assert.equal(row.fence, '8');
  assert.equal(row.root, root);
  assert.equal(row.rev, rev);
  assert.equal(row.did, did);
  // One SPARQL UPDATE returning 2xx can be a no-op. Explicit read-back
  // verifies stale, malicious and immutable-head writes did not succeed.
  await http('update', update(subject, '7'));
  await http('update', update(subject, '9', { did: 'did:plc:' + 'q'.repeat(24) }));
  await http('update', update(subject, '9', { rootCid: changedRoot }));
  row = await check(subject);
  assert.equal(row.fence, '8');
  assert.equal(row.root, root);

  await http('update', update(namedSubject, '1', { graphUri: graph }));
  const scoped = await check(namedSubject, { graphUri: graph });
  assert.equal(scoped.fence, '1');
  assert.equal(scoped.root, root);
  // Malformed old RDF fence must not be silently overwritten.
  await http('update', update(badSubject, '2'));
  const malformed = await http('query', prefix +
    'SELECT ?fence WHERE { ' + iri(badSubject) + ' apods:repoProjectionFence ?fence }');
  assert.equal(malformed.length, 1);
  assert.equal(malformed[0].fence.value, 'nonnumeric');
  // A binding with both legitimate and attacker-controlled DID values must
  // not pass the identity guard just because ONE triple matches.
  await http('update', update(duplicateSubject, '1'));
  const conflicting = await http('query', prefix +
    'SELECT ?fence WHERE { ' + iri(duplicateSubject) + ' apods:repoProjectionFence ?fence }');
  assert.equal(conflicting.length, 0, 'ambiguous DID must prevent all fenced writes');
  process.stdout.write('Real TDB2 CAS prepare: 8-way writer race, immutable DID/head, malformed and stale fence all checked.\n');
}
async function verify() {
  const row = await check(subject);
  assert.equal(row.fence, '8');
  assert.equal(row.root, root);
  assert.equal(row.rev, rev);
  assert.equal(row.did, did);
  const scoped = await check(namedSubject, { graphUri: graph });
  assert.equal(scoped.fence, '1');
  assert.equal(scoped.root, root);
  process.stdout.write('Real TDB2 CAS verified across persistent Fuseki restart.\n');
}
if (stage === 'prepare') await prepare();
else await verify();
