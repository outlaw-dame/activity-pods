'use strict';

// Benchmark the pure G2 planning kernel, not network/federation throughput.
// No synthetic "production capacity" claims are inferred from CI hardware.
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { planGroupFanout } = require('../utils/collective-fanout-plan');

function recipients(n, kind) {
  return Array.from({ length: n }, (_, i) => kind === 'local'
    ? {
      actorUri: 'https://paper.example/users/u' + i,
      inboxUri: 'https://paper.example/users/u' + i + '/inbox',
      dataset: 'pod' + Math.floor(i / 20)
    }
    : {
      actorUri: 'https://remote.example/users/u' + i,
      inboxUrl: 'https://remote.example/users/u' + i + '/inbox',
      sharedInboxUrl: 'https://remote.example/inbox',
      targetDomain: 'remote.example'
    });
}
const groupActorUri = 'https://paper.example/groups/cg_0123456789abcdef0123456789abcdef';
function run(n, kind, repetitions = 20) {
  const localRecipients = kind === 'local' ? recipients(n, kind) : [];
  const remoteRecipients = kind === 'remote' ? recipients(n, kind) : [];
  const durations = [];
  let batchCount, fingerprint;
  for (let i = 0; i < repetitions; i += 1) {
    const start = performance.now();
    const plan = planGroupFanout({
      intentId: 'paper-g2-benchmark-intent-0001',
      groupActorUri, membershipRevision: 1,
      visibility: 'public', localRecipients, remoteRecipients
    });
    durations.push(performance.now() - start);
    assert.equal(plan.recipientCount, n);
    const total = plan.localBatches.reduce((count, batch) => count + batch.recipients.length, 0) +
      plan.remoteBatches.reduce((count, batch) => count + batch.recipientActors.length, 0);
    assert.equal(total, n, 'recipient coverage must not be lost');
    const currentBatches = plan.localBatches.length + plan.remoteBatches.length;
    if (i > 0) {
      assert.equal(currentBatches, batchCount);
      assert.equal(plan.fingerprint, fingerprint);
    }
    batchCount = currentBatches;
    fingerprint = plan.fingerprint;
  }
  durations.sort((a, b) => a - b);
  const percentile = q => Number(durations[Math.ceil(durations.length * q) - 1].toFixed(3));
  return {
    recipients: n, topology: kind, batches: batchCount,
    planningP50Ms: percentile(0.5), planningP95Ms: percentile(0.95),
    callsToMoleculer: 0, fusekiRequests: 0, remoteHttpRequests: 0
  };
}
const results = [];
for (const n of [1, 10, 100, 1000]) {
  for (const kind of ['local', 'remote']) results.push(run(n, kind));
}
console.log(JSON.stringify({
  workload: 'isolated-g2-planning-only',
  node: process.version,
  rssBytes: process.memoryUsage().rss,
  note: 'Not a live local-delivery, Fedify, TDB2, queue or multi-replica capacity benchmark',
  results
}, null, 2));
