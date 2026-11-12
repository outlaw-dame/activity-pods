'use strict';

// An auditable volume model, not a cloud invoice. Supply actual measured
// unit prices before reporting dollars. Each input is independent of
// GitHub-hosted runner throughput, which is not production hardware.
const assert = require('node:assert/strict');
const DAYS = 30;
const SECONDS = DAYS * 86400;

function price(name) {
  const value = process.env[name];
  if (value === undefined || value === '') return null;
  const n = Number(value);
  assert(Number.isFinite(n) && n >= 0, 'Invalid unit price: ' + name);
  return n;
}
const pricePerMillionJenaCalls = price('ATPROTO_COST_PER_MILLION_JENA_CALLS_USD');
const pricePerMillionMoleculerCalls = price('ATPROTO_COST_PER_MILLION_MOLECULER_CALLS_USD');
const pricePerMillionRedisCalls = price('ATPROTO_COST_PER_MILLION_REDIS_CALLS_USD');

function modeledCost(count, unit) {
  return unit === null ? null : Number((count / 1e6 * unit).toFixed(6));
}
const scenarios = [];
for (const accounts of [100_000, 1_000_000, 10_000_000]) {
  for (const grantMutationsPerAccountPerMonth of [0.1, 1, 5]) {
    const changes = accounts * grantMutationsPerAccountPerMonth;
    // An active grant revocation takes one settings lookup, two consent
    // reads and one consent write. The other three broker calls resolve
    // owner/ACL/containers; all are bounded and exact-scoped.
    const jenaCalls = changes * 4;
    const brokerCalls = changes * 7;
    scenarios.push({
      accounts, grantMutationsPerAccountPerMonth,
      monthlyGrantChanges: changes,
      monthlyJenaCalls: jenaCalls,
      monthlyBrokerCalls: brokerCalls,
      averageJenaCallsPerSecond: Number((jenaCalls / SECONDS).toFixed(4)),
      tenfoldPeakJenaCallsPerSecond: Number((jenaCalls / SECONDS * 10).toFixed(4)),
      estimatedJenaCallCostUsd: modeledCost(jenaCalls, pricePerMillionJenaCalls),
      estimatedBrokerCallCostUsd: modeledCost(brokerCalls, pricePerMillionMoleculerCalls)
    });
  }
}
const dpop = [100, 1_000, 10_000].map(requestsPerSecond => ({
  requestsPerSecond,
  monthlyRedisReplaySetCalls: requestsPerSecond * SECONDS,
  liveReplayKeysApproximately: requestsPerSecond * 130,
  estimatedRedisCommandCostUsd: modeledCost(
    requestsPerSecond * SECONDS, pricePerMillionRedisCalls
  )
}));
console.log(JSON.stringify({
  type: 'volume-model-not-production-benchmark',
  days: DAYS,
  priceInputsProvided: {
    jena: pricePerMillionJenaCalls !== null,
    moleculer: pricePerMillionMoleculerCalls !== null,
    redis: pricePerMillionRedisCalls !== null
  },
  assumption: 'all modeled grant changes affect an approved app with active consent',
  excludes: ['Fuseki IO/cache variance', 'JVM/Node memory', 'storage pricing',
    'CPU hours', 'Redis allocator fragmentation', 'network egress',
    'idle capacity', 'backups', 'multi-region'],
  scenarios, dpop
}));
