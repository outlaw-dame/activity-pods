'use strict';

/**
 * Shared settings-dataset multi-writer contention benchmark.
 *
 * Intentionally isolated from runtime; ALL operations require a disposable
 * localhost Fuseki and an initially empty dataset. No external network,
 * no foreign actors dereferenced, no production credentials or output.
 *
 * Compare ordinary one-Group-at-a-time membership CAS against bounded
 * Group-scoped delta CAS across 1,4,16 concurrent Group writers.
 * The scenario is one owner/app with many independent Groups, stressing
 * TDB2's single active dataset writer while preserving exact epoch proofs.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const rdf = require('../utils/collective-membership-rdf');
const index = require('../utils/collective-membership-page-index');

if (process.env.G2_BENCH_DISPOSABLE !== 'confirmed') {
  throw Error('G2_BENCH_DISPOSABLE=confirmed is mandatory');
}
const host = process.env.FUSEKI_URL;
if (!/^http:\/\/(?:localhost|127\.0\.0\.1):[0-9]+\/?$/u.test(host || '')) {
  throw Error('Refusing non-local TDB2 benchmark destination');
}
const count = Number(process.env.G2_WRITE_OPS_PER_WRITER || 24);
if (!Number.isSafeInteger(count) || count < 4 || count > 48) {
  throw Error('Unsupported bounded mutation count');
}
const uri = host.replace(/\/+$/u, '') + '/settings';
const password = process.env.FUSEKI_PASSWORD;
if (!password) throw Error('Disposable Fuseki password required');
const auth = 'Basic ' + Buffer.from((process.env.FUSEKI_USER || 'admin') +
  ':' + password).toString('base64');
const ns = 'http://activitypods.org/ns/core#';
const owner = 'https://paper-benchmark.example/users/owner';
const app = 'https://paper-benchmark.example/app';
let requestCount = 0;
let httpFailures = 0;

async function request(kind, statement) {
  requestCount += 1;
  let res;
  try {
    res = await fetch(uri + '/' + kind, {
      method: 'POST',
      headers: {
        authorization: auth,
        'content-type': 'application/sparql-' + kind,
        accept: 'application/sparql-results+json'
      },
      body: statement,
      signal: AbortSignal.timeout(30000)
    });
  } catch (error) {
    httpFailures++;
    throw error;
  }
  if (!res.ok) {
    httpFailures++;
    throw Error('Fuseki ' + kind + ' HTTP ' + res.status);
  }
  return kind === 'query' ? (await res.json()).results.bindings : null;
}
function groupId(mode, writers, worker) {
  const digest = crypto.createHash('sha256')
    .update(JSON.stringify([mode, writers, worker])).digest('hex');
  return 'cg_' + digest.slice(0, 32);
}
function memberUri(group, seq) {
  return 'https://remote.example/users/' + group.slice(-12) + '-' + seq;
}
async function prepareGroup(group, indexed) {
  const g = rdf.groupSubject(group);
  await request('update',
    'PREFIX apods: <' + ns + '> INSERT DATA { ' + g +
    ' a apods:CollectiveReservationV1 ; ' +
    'apods:collectiveOwner ' + JSON.stringify(owner) + ' ; ' +
    'apods:collectiveApp ' + JSON.stringify(app) + ' . }');
  await request('update', rdf.initializeQuery({groupId:group, owner, app}));
  if (indexed) {
    const page = index.encodePage({
      groupId: group, revision: 1,
      members: [{actorUri:owner,role:'owner'}],
      hasMore: false
    });
    await request('update', index.stagePageQuery(page));
    await request('update', index.publishQuery({groupId:group,owner,app,revision:1}));
  }
}
function pctl(samples, fraction) {
  assert(samples.length > 0);
  const sorted = [...samples].sort((a,b)=>a-b);
  return Number(sorted[Math.ceil(sorted.length * fraction) - 1].toFixed(2));
}
async function runOne(mode, concurrency) {
  const indexed = mode === 'indexed';
  const groups = Array.from({length:concurrency}, (_,i)=>groupId(mode,concurrency,i));
  for (const g of groups) await prepareGroup(g,indexed);
  const elapsed = [], start = performance.now(), errors = [];
  // Each writer owns exactly one Group. Their CAS updates do not race the
  // same Group epoch, so any tail-latency growth is dataset writer contention.
  await Promise.all(groups.map(async g => {
    try {
      for (let i=0;i<count;i++) {
        const started = performance.now();
        await request('update',rdf.mutateQuery({
          groupId:g, owner, app, member:memberUri(g,i),
          role:'member',status:'active',expectedEpoch:i+1,
          receipt:crypto.randomUUID(),indexDelta:indexed
        }));
        elapsed.push(performance.now()-started);
      }
    } catch (e) { errors.push(String(e)); }
  }));
  assert.deepEqual(errors,[], 'Writer errors must not be hidden');
  for (const g of groups) {
    const epoch = await request('query',rdf.readEpochQuery({groupId:g,owner,app}));
    assert.equal(epoch.length,1);
    assert.equal(Number(epoch[0].epoch.value),count+1,
      'Lossy concurrent update in shared TDB2 dataset');
    if (indexed) {
      const details = await request('query',
        'PREFIX apods: <' + ns + '> SELECT ?count WHERE { ' +
        rdf.groupSubject(g) + ' apods:collectiveIndexDeltaCount ?count . } LIMIT 2');
      assert.equal(details.length,1);
      assert.equal(Number(details[0].count.value),count,
        'Unique Group delta pointer count does not match durable writes');
    }
  }
  const ms = performance.now()-start;
  return {
    mode,concurrentGroupWriters:concurrency,mutations:concurrency*count,
    wallMs:Number(ms.toFixed(2)),mutationsPerSecond:Number(
      (concurrency*count*1000/ms).toFixed(2)),
    latencyP50Ms:pctl(elapsed,0.5),latencyP95Ms:pctl(elapsed,0.95),
    latencyP99Ms:pctl(elapsed,0.99),maxMs:Number(Math.max(...elapsed).toFixed(2))
  };
}
async function main() {
  const prior = await request('query','SELECT ?s WHERE { ?s ?p ?o } LIMIT 1');
  assert.equal(prior.length,0,'Refusing to run on a nonempty settings dataset');
  const account = '<urn:apods:benchmark:contention-owner>';
  const ledger = rdf.consentSubject(owner,app);
  await request('update','PREFIX apods: <' + ns + '> INSERT DATA { ' +
    account + ' a <http://semapps.org/ns/core#AuthAccount> ; ' +
    '<http://semapps.org/ns/core#webId> ' + JSON.stringify(owner) + ' . ' +
    ledger + ' apods:collectiveConsentStatus "stable" ; ' +
    'apods:collectiveConsentRevision "1" . }');
  const metrics = [];
  for (const concurrency of [1,4,16]) {
    for (const mode of ['legacy','indexed']) {
      const sample = await runOne(mode,concurrency);
      metrics.push(sample);
      console.log(JSON.stringify({proof:'g2-tdb2-writer-contention',ok:true,...sample}));
    }
  }
  assert.equal(httpFailures,0);
  console.log(JSON.stringify({
    proof:'g2-tdb2-writer-contention-summary',ok:true,requestCount,
    httpFailures,operationsPerWriter:count,metrics,
    limitations:'One hosted Fuseki, synthetic groups, no full ActivityPods workers or Pod writes'
  }));
}
main().catch(e=>{
  console.error('G2_TDB2_CONTENTION_FAILED '+e.message);
  process.exitCode=1;
});
