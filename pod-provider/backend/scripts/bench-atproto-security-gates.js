'use strict';

const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { assertNotManagedLdpMutation } =
  require('../services/utils/atproto-ldp-write-barrier');
const { allowedOrigin } = require('../config/oidc-cors-policy');

if (process.env.NODE_ENV === 'production' || typeof global.gc !== 'function') {
  throw Error('Run only a disposable benchmark with node --expose-gc');
}

const base = 'https://paper.example.org/';
const ordinary = { params: { resourceUri: base + 'alice/data/articles/post-1' } };
const managed = { params: { resourceUri: base + 'alice/data/identity-bindings/managed-1' } };
const allowedClient = { redirectUris: ['https://writer.example.org/callback'] };
const oldFlag = process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;

function percentile(sorted, q) {
  return Number(sorted[Math.floor(q * (sorted.length - 1))].toFixed(6));
}
function measure(label, action, iterations = 50000) {
  // JIT/cache warmup is separate from measured work.
  for (let i = 0; i < 3000; i++) action();
  global.gc();
  const heapBefore = process.memoryUsage().heapUsed;
  const samples = [];
  const started = performance.now();
  for (let i = 0; i < iterations; i++) {
    if ((i & 31) === 0) {
      const t = performance.now();
      action();
      samples.push(performance.now() - t);
    } else {
      action();
    }
  }
  const durationMs = performance.now() - started;
  global.gc();
  const heapAfter = process.memoryUsage().heapUsed;
  samples.sort((a,b) => a-b);
  return {
    label, iterations,
    operationsPerSecond: Math.round(iterations * 1000 / durationMs),
    durationMs: Number(durationMs.toFixed(2)),
    sampleLatencyMilliseconds: {
      p50: percentile(samples, 0.5),
      p95: percentile(samples, 0.95),
      p99: percentile(samples, 0.99)
    },
    heapBeforeBytes: heapBefore,
    heapAfterGcBytes: heapAfter,
    heapDeltaBytes: heapAfter - heapBefore
  };
}

try {
  delete process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;
  const baseline = measure('disabled', () =>
    assertNotManagedLdpMutation(managed, base));
  process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED = 'true';
  const unrelated = measure('enabled-unrelated-resource', () =>
    assertNotManagedLdpMutation(ordinary, base));
  const blocked = measure('enabled-protected-resource', () => {
    try {
      assertNotManagedLdpMutation(managed, base);
      throw Error('Protected identity unexpectedly accepted');
    } catch (e) {
      if (e.type !== 'ATPROTO_MANAGED_BINDING_WRITE_FENCED') throw e;
    }
  }, 10000);
  const cors = measure('oidc-client-cors', () => {
    assert.equal(allowedOrigin('https://writer.example.org', allowedClient), true);
    assert.equal(allowedOrigin('https://attacker.example.org', allowedClient), false);
  }, 15000);

  // A retained 1-KB object per action would exceed this by far. The
  // endpoint-specific sample is not a substitute for multi-hour heap profiling.
  assert(unrelated.heapDeltaBytes < 8 * 1024 * 1024,
    'Enabled unprotected LDP path retained more than 8 MiB after full GC');
  assert(baseline.heapDeltaBytes < 8 * 1024 * 1024,
    'Disabled LDP path retained more than 8 MiB after full GC');
  console.log(JSON.stringify({
    kind: 'disposable-microbenchmark-not-production-capacity',
    node: process.version,
    cases: [baseline, unrelated, blocked, cors]
  }));
} finally {
  if (oldFlag === undefined) delete process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;
  else process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED = oldFlag;
}
