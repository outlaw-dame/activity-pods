'use strict';
/**
 * Explicitly disposable TDB2-only Group membership query-cost probe.
 * Never accepts external FUSEKI_URL hosts, writes only to the isolated
 * "settings" dataset, and does NOT assert unmeasured scalability SLAs.
 */
const assert = require('node:assert/strict');
const rdf = require('../utils/collective-membership-rdf');
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
  const phases = [
    ['first-page', null],
    ['middle-page', actor(Math.floor(count / 2))],
    ['deep-page', actor(count - 201)]
  ];
  const output = [];
  const alternatives = [];
  for (const [name, cursor] of phases) {
    const params = { groupId, owner, app, cursor, limit: 100 };
    const plans = [
      ['canonical', rdf.listQuery(params)],
      ['direct-term', directTermQuery(params)]
    ];
    const durations = { canonical: [], 'direct-term': [] };
    let referenceRows = null;
    // Alternate execution order to reduce systematic warm-cache bias.
    for (let rep = 0; rep < 5; rep++) {
      const ordered = rep % 2 === 0 ? plans : [...plans].reverse();
      for (const [variant, sparql] of ordered) {
        const begin = performance.now();
        const rows = await request('query', sparql);
        durations[variant].push(performance.now() - begin);
        assert.equal(rows.length, 101, 'Expected 100 + lookahead: ' + name + '/' + variant);
        for (let i = 1; i < rows.length; i++) {
          assert(rows[i - 1].actor.value < rows[i].actor.value,
            'Nonmonotonic actor key at ' + name + '/' + variant);
        }
        if (cursor) assert(rows[0].actor.value > cursor);
        const currentRows = semanticRows(rows);
        if (referenceRows === null) referenceRows = currentRows;
        else assert.deepEqual(currentRows, referenceRows,
          'Alternative changed actors, roles, order or epoch at ' + name);
      }
    }
    function record(variant) {
      const samples = durations[variant];
      return {
        phase: name, queryCount: samples.length,
        p50Ms: percentile(samples, 0.5), p95Ms: percentile(samples, 0.95),
        maxMs: Number(Math.max(...samples).toFixed(2))
      };
    }
    output.push(record('canonical'));
    alternatives.push(record('direct-term'));
  }
  const result = {
    proof: 'g2-membership-tdb2-page-cost', members: count,
    pageSize: 100, backend: 'disposable-Fuseki-TDB2',
    seedMs: Number(seedMs.toFixed(2)),
    queryMetrics: output,
    alternativeQueryMetrics: alternatives,
    totalReadRequests: [...output, ...alternatives].reduce((sum, x) => sum + x.queryCount, 0),
    measuredNodeRssBytes: process.memoryUsage().rss,
    warning: 'Observed isolated query latency, NOT throughput, provider CPU or production capacity'
  };
  console.log(JSON.stringify(result));
}
main().catch(e => {
  console.error('G2_MEMBERSHIP_BENCHMARK_FAILED ' + e.message);
  process.exitCode = 1;
});
