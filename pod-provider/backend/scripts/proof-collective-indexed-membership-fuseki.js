'use strict';
/**
 * Explicitly disposable TDB2-only Group membership query-cost probe.
 * Never accepts external FUSEKI_URL hosts, writes only to the isolated
 * "settings" dataset, and does NOT assert unmeasured scalability SLAs.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const rdf = require('../utils/collective-membership-rdf');
const index = require('../utils/collective-membership-page-index');
const delta = require('../utils/collective-membership-delta-snapshot');
const { performance } = require('node:perf_hooks');

if (process.env.G2_BENCH_DISPOSABLE !== 'confirmed') {
  throw new Error('G2_BENCH_DISPOSABLE=confirmed required');
}
const base = process.env.FUSEKI_URL;
if (!base || !/^http:\/\/(?:127\.0\.0\.1|localhost):[0-9]+\/?$/u.test(base)) {
  throw new Error('Benchmark requires a disposable localhost FUSEKI_URL');
}
const count = Number(process.env.G2_BENCH_MEMBERS || 1000);
if (![1000, 10000, 100000].includes(count)) throw new Error('Unsupported benchmark cardinality');
const groupId = 'cg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const owner = 'https://paper-benchmark.example/users/owner#me';
const app = 'https://paper-benchmark.example/app';
const subject = rdf.groupSubject(groupId);
const ns = 'http://activitypods.org/ns/core#';
const uri = base.replace(/\/+$/u, '') + '/settings';
const auth = process.env.FUSEKI_PASSWORD
  ? { Authorization: 'Basic ' + Buffer.from(
    (process.env.FUSEKI_USER || 'admin') + ':' + process.env.FUSEKI_PASSWORD
  ).toString('base64') }
  : {};
async function request(kind, statement) {
  const res = await fetch(uri + '/' + kind, {
    method: 'POST',
    headers: {
      ...auth, 'content-type': 'application/sparql-' + kind,
      accept: 'application/sparql-results+json'
    },
    body: statement,
    signal: AbortSignal.timeout(90000)
  });
  if (!res.ok) {
    throw new Error('Disposable Fuseki ' + kind + ' HTTP ' + res.status +
      ': ' + (await res.text()).slice(0, 250));
  }
  return kind === 'query' ? (await res.json()).results.bindings : null;
}
function actor(i) {
  return 'https://remote-benchmark.example/users/u' + String(i).padStart(7, '0');
}
function directTermQuery(params) {
  const original = rdf.listQuery(params);
  assert(original.includes('ORDER BY STR(?actor)'), 'Unexpected canonical query shape');
  const alternative = original
    .replace('ORDER BY STR(?actor)', 'ORDER BY ?actor')
    .replace('FILTER(STR(?actor) > ', 'FILTER(?actor > ');
  assert(alternative !== original, 'Alternative must differ from canonical query');
  return alternative;
}
function semanticRows(rows) {
  return rows.map(row => [
    row.actor?.value, row.role?.value, row.epoch?.value
  ]);
}
function percentile(values, percentileValue) {
  const ordered = [...values].sort((a, b) => a - b);
  return Number(ordered[Math.ceil(percentileValue * ordered.length) - 1].toFixed(2));
}
async function main() {
  // Refuse to seed into any existing Group fixture or reused settings store.
  const prior = await request('query', 'SELECT ?s WHERE { ?s ?p ?o } LIMIT 1');
  assert.equal(prior.length, 0,
    'Refusing to benchmark an existing settings dataset; disposable TDB2 must be empty');
  // Required proof fixture lives only in this disposable settings dataset.
  const account = '<urn:apods:benchmark:owner>';
  const ledger = rdf.consentSubject(owner, app);
  await request('update', 'INSERT DATA { ' + account +
    ' a <http://semapps.org/ns/core#AuthAccount> ; ' +
    '<http://semapps.org/ns/core#webId> ' + JSON.stringify(owner) + ' . ' +
    ledger + ' <' + ns + 'collectiveConsentStatus> "stable" ; ' +
    '<' + ns + 'collectiveConsentRevision> "1" . ' +
    subject + ' a <' + ns + 'CollectiveReservationV1> ; ' +
    '<' + ns + 'collectiveOwner> ' + JSON.stringify(owner) + ' ; ' +
    '<' + ns + 'collectiveApp> ' + JSON.stringify(app) + ' . }');
  await request('update', rdf.initializeQuery({ groupId, owner, app }));
  const batchSize = 250;
  const started = performance.now();
  for (let start = 0; start < count; start += batchSize) {
    let body = 'PREFIX apods: <' + ns + '> INSERT DATA { ';
    for (let i = start; i < Math.min(start + batchSize, count); i++) {
      const user = actor(i);
      body += rdf.memberSubject(groupId, user) +
        ' a apods:CollectiveMembershipV1 ; ' +
        'apods:collectiveMemberGroup ' + JSON.stringify(groupId) + ' ; ' +
        'apods:collectiveMemberActor ' + JSON.stringify(user) + ' ; ' +
        'apods:collectiveMemberRole "member" ; ' +
        'apods:collectiveMemberStatus "active" . ';
    }
    await request('update', body + ' }');
  }
  const seedMs = performance.now() - started;
  // Construct the same owner+member snapshot as authoritative seed. The
  // experiment uses synthetic actors, NOT production membership enumeration.
  const revisionRows = await request('query', rdf.readEpochQuery({
    groupId, owner, app
  }));
  assert.equal(revisionRows.length, 1, 'Canonical membership epoch must be unique');
  const revision = Number(revisionRows[0].epoch.value);
  assert.equal(revision, 1);
  const entries = [{ actorUri: owner, role: 'owner' }, ...Array.from(
    { length: count }, (_, i) => ({ actorUri: actor(i), role: 'member' })
  )].sort((a, b) => a.actorUri < b.actorUri ? -1 : 1);
  const indexStarted = performance.now();
  let previousCursor = null;
  const pages = [];
  for (let start = 0; start < entries.length; start += index.PAGE_LIMIT) {
    const items = entries.slice(start, start + index.PAGE_LIMIT);
    const hasMore = start + index.PAGE_LIMIT < entries.length;
    const page = index.encodePage({
      groupId, revision, cursor: previousCursor, members: items, hasMore
    });
    previousCursor = page.nextCursor;
    pages.push(page);
  }
  const stagePrefix = 'PREFIX apods: <http://activitypods.org/ns/core#> INSERT DATA { ';
  let stageStatements = 0;
  // Batch up to 20 independent immutable page triples per TDB2 request.
  for (let start = 0; start < pages.length; start += 20) {
    const statements = pages.slice(start, start + 20).map(p => {
      const statement = index.stagePageQuery(p);
      assert(statement.startsWith(stagePrefix));
      return statement.slice(stagePrefix.length, -2);
    });
    await request('update', stagePrefix + statements.join(' ') + ' }');
    stageStatements += 1;
  }
  // Stage before publish: readers MUST NOT be able to retrieve unsealed pages.
  const stagedRows = await request('query', index.readPageQuery({
    groupId, owner, app, revision, cursor: null
  }));
  assert.equal(stagedRows.length, 0, 'Staged private page leaked before index publication');
  // All expected deterministic pages must exist once before publication.
  const unique = new Set(pages.map(p => p.subject));
  assert.equal(unique.size, pages.length);
  const countRows = await request('query',
    'PREFIX apods: <http://activitypods.org/ns/core#> ' +
    'SELECT (COUNT(?s) AS ?n) WHERE { ?s apods:collectiveIndexPageJson ?json }');
  assert.equal(Number(countRows[0].n.value), pages.length,
    'Incomplete or duplicate persisted page set');
  await request('update', index.publishQuery({ groupId, owner, app, revision }));
  const indexBuildMs = performance.now() - indexStarted;

  const phases = [
    ['first-page', 0],
    ['middle-page', Math.floor((pages.length - 1) / 2)],
    ['deep-page', Math.max(0, pages.length - 2)]
  ];
  const output = [], alternatives = [], indexMetrics = [];
  for (const [name, pageNumber] of phases) {
    const page = pages[pageNumber];
    const params = { groupId, owner, app, cursor: page.cursor, limit: index.PAGE_LIMIT };
    const durations = { canonical: [], 'direct-term': [], indexed: [] };
    const variants = [
      ['canonical', rdf.listQuery(params)],
      ['direct-term', directTermQuery(params)],
      ['indexed', index.readPageQuery({ groupId, owner, app,
        revision, cursor: page.cursor })]
    ];
    for (let rep = 0; rep < 5; rep++) {
      const sequence = variants.slice(rep % 3).concat(variants.slice(0, rep % 3));
      for (const [variant, sparql] of sequence) {
        const begin = performance.now();
        const rows = await request('query', sparql);
        durations[variant].push(performance.now() - begin);
        const actual = variant === 'indexed'
          ? index.decodeRead(rows, { groupId, revision, cursor: page.cursor }).members
          : rows.slice(0, index.PAGE_LIMIT).map(row => ({
            actorUri: row.actor.value, role: row.role.value
          }));
        assert.deepEqual(actual, page.members,
          'Indexed projection changed authoritative actors, order or roles at ' + name);
        if (variant !== 'indexed') {
          assert.equal(rows.length, page.hasMore ? index.PAGE_LIMIT + 1 : page.members.length);
          for (const row of rows) assert.equal(Number(row.epoch.value), revision);
        }
      }
    }
    function record(variant) {
      const samples = durations[variant];
      return { phase: name, queryCount: samples.length,
        p50Ms: percentile(samples, 0.5), p95Ms: percentile(samples, 0.95),
        maxMs: Number(Math.max(...samples).toFixed(2)) };
    }
    output.push(record('canonical'));
    alternatives.push(record('direct-term'));
    indexMetrics.push(record('indexed'));
  }
  // Index data are private: revoking the stable SAI ledger must deny
  // reads even when the same page and index epoch physically exist.
  await request('update', 'PREFIX apods: <http://activitypods.org/ns/core#> ' +
    'DELETE DATA { ' + ledger + ' apods:collectiveConsentStatus "stable" . }; ' +
    'INSERT DATA { ' + ledger + ' apods:collectiveConsentStatus "blocked" . }');
  assert.equal((await request('query', index.readPageQuery({
    groupId, owner, app, revision, cursor: null
  }))).length, 0, 'Revoked consent exposed indexed members');
  await request('update', 'PREFIX apods: <http://activitypods.org/ns/core#> ' +
    'DELETE DATA { ' + ledger + ' apods:collectiveConsentStatus "blocked" . }; ' +
    'INSERT DATA { ' + ledger + ' apods:collectiveConsentStatus "stable" . }');
  const disabled = '<http://semapps.org/ns/core#disabled>';
  await request('update', 'INSERT DATA { ' + account + ' ' + disabled + ' true . }');
  assert.equal((await request('query', index.readPageQuery({
    groupId, owner, app, revision, cursor: null
  }))).length, 0, 'Disabled owner exposed indexed members');
  await request('update', 'DELETE DATA { ' + account + ' ' + disabled + ' true . }');
  const duplicate = '<urn:apods:benchmark:duplicate-owner>';
  await request('update', 'INSERT DATA { ' + duplicate +
    ' a <http://semapps.org/ns/core#AuthAccount> ; ' +
    '<http://semapps.org/ns/core#webId> ' + JSON.stringify(owner) + ' . }');
  assert.equal((await request('query', index.readPageQuery({
    groupId, owner, app, revision, cursor: null
  }))).length, 0, 'Duplicate owner exposed indexed members');
  await request('update', 'DELETE DATA { ' + duplicate +
    ' a <http://semapps.org/ns/core#AuthAccount> ; ' +
    '<http://semapps.org/ns/core#webId> ' + JSON.stringify(owner) + ' . }');
  assert.equal((await request('query', index.readPageQuery({
    groupId, owner, app, revision, cursor: null
  }))).length, 1, 'Authorized index read did not recover after controls restored');
  // After authoritative epoch changes, the sealed projection must become
  // unreadable even though the old stage records physically remain.
  const before = await request('query', index.readPageQuery({
    groupId, owner, app, revision, cursor: null
  }));
  assert.equal(before.length, 1);
  // Use the REAL canonical same-dataset member CAS plus delta bookkeeping,
  // not an artificial update of the epoch. A failed/stale CAS must not grow
  // the delta count, and a repeat change to the same actor remains one key.
  const readDelta = async () => {
    const result = await request('query', 'PREFIX apods: <' + ns + '> ' +
      'SELECT ?epoch ?count WHERE { ' + subject +
      ' apods:collectiveMembershipEpoch ?epoch ; ' +
      'apods:collectiveIndexDeltaCount ?count . } LIMIT 2');
    assert.equal(result.length, 1);
    return { epoch: Number(result[0].epoch.value), count: Number(result[0].count.value) };
  };
  assert.deepEqual(await readDelta(), { epoch: 1, count: 0 });
  const mutation = (member, status, expectedEpoch) => rdf.mutateQuery({
    groupId, owner, app, member, role: 'member', status,
    expectedEpoch, receipt: crypto.randomUUID(), indexDelta: true
  });
  await request('update', mutation(actor(0), 'banned', 1));
  assert.deepEqual(await readDelta(), { epoch: 2, count: 1 });
  await request('update', mutation(actor(0), 'left', 1));
  assert.deepEqual(await readDelta(), { epoch: 2, count: 1 },
    'Stale expected-epoch changed membership or delta');
  await request('update', mutation(actor(0), 'active', 2));
  assert.deepEqual(await readDelta(), { epoch: 3, count: 1 },
    'Repeated actor transition should not count as another delta key');
  const fresh = 'https://remote-benchmark.example/users/fresh';
  await request('update', mutation(fresh, 'active', 3));
  assert.deepEqual(await readDelta(), { epoch: 4, count: 2 });
  // Direct Group-scoped changed member reads are real TDB2; they must
  // reflect the SAME authenticated settings revision as the CAS updates,
  // with no global member scan or remote actor dereference.
  const deltaQuery = delta.readDeltaSnapshotQuery({ groupId, owner, app });
  const deltaRows = await request('query', deltaQuery);
  const deltaState = delta.decodeDeltaSnapshot(deltaRows, { groupId, owner });
  assert.equal(deltaState.baseRevision, 1);
  assert.equal(deltaState.membershipRevision, 4);
  assert.equal(deltaState.deltaCount, 2);
  assert.deepEqual(deltaState.changes, [
    { actorUri: actor(0), kind: 'upsert', role: 'member' },
    { actorUri: fresh, kind: 'upsert', role: 'member' }
  ].sort((a, b) => a.actorUri < b.actorUri ? -1 : 1));
  const linkRows = await request('query',
    'PREFIX apods: <' + ns + '> SELECT ?member WHERE { ' + subject +
    ' apods:collectiveIndexChangedMember ?member . } LIMIT 514');
  assert.equal(linkRows.length, 2, 'Wrong number of Group-scoped member index pointers');
  assert.deepEqual(
    delta.decodeDeltaSnapshot(await request('query', deltaQuery), { groupId, owner }),
    deltaState, 'Durable delta changed after recreating the query/read snapshot'
  );
  const deltaStart = performance.now();
  for (let i = 0; i < 5; i++) {
    const sample = await request('query', deltaQuery);
    assert.equal(delta.decodeDeltaSnapshot(sample, { groupId, owner }).deltaCount, 2);
  }
  const deltaReadPentaMs = Number((performance.now() - deltaStart).toFixed(2));
  const stale = await request('query', index.readPageQuery({
    groupId, owner, app, revision, cursor: null
  }));
  assert.equal(stale.length, 0, 'Stale index leaked after membership epoch advance');
  const result = {
    proof: 'g2-membership-indexed-page-cost', members: count,
    pageSize: 100, backend: 'disposable-Fuseki-TDB2',
    seedMs: Number(seedMs.toFixed(2)),
    queryMetrics: output,
    alternativeQueryMetrics: alternatives,
    indexedQueryMetrics: indexMetrics,
    indexBuildMs: Number(indexBuildMs.toFixed(2)),
    indexStageHttpRequests: stageStatements,
    indexedPages: pages.length,
    deltaRead5QueriesMs: deltaReadPentaMs,
    deltaPointerCount: linkRows.length,
    totalReadRequests: [...output, ...alternatives, ...indexMetrics].reduce((sum, x) => sum + x.queryCount, 0),
    measuredNodeRssBytes: process.memoryUsage().rss,
    warning: 'Synthetic snapshot materialization; indexed reads are real TDB2, but production mutation/build/recovery costs remain UNPROVEN'
  };
  console.log(JSON.stringify(result));
}
main().catch(e => {
  console.error('G2_MEMBERSHIP_BENCHMARK_FAILED ' + e.message);
  process.exitCode = 1;
});
