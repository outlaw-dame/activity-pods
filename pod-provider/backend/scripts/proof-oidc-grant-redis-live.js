'use strict';

// Real Redis acceptance proof. Restrict destructive database operations to
// the disposable container's dedicated DB 15; never run against production.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Redis = require('ioredis');
const RedisAdapter = require('../config/oidc-adapter');
const { MAX_GRANT_TOKENS } = require('../config/oidc-grant-index-policy');

if (process.env.NODE_ENV !== 'test' ||
    process.env.ATPROTO_CAPACITY_PROOF_DISPOSABLE !== 'confirmed') {
  throw Error('OIDC Redis proof requires an explicitly disposable test environment');
}
const input = process.env.SEMAPPS_REDIS_OIDC_PROVIDER_URL || 'redis://redis:6379/13';
const url = new URL(input);
if (!['redis', 'localhost', '127.0.0.1'].includes(url.hostname)) {
  throw Error('Refusing to connect OIDC proof to an unknown Redis host');
}
url.pathname = '/15';
const redis = new Redis(url.toString(), {
  keyPrefix: 'atproto-oidc-test:',
  enableOfflineQueue: false,
  connectTimeout: 3000,
  maxRetriesPerRequest: 1
});
async function main() {
  await redis.ping();
  await redis.flushdb();
  const adapter = new RedisAdapter('AccessToken', redis);
  const grantId = 'grant-' + crypto.randomUUID();
  const basePayload = { grantId, accountId: 'test-user', clientId: 'test-client' };
  const started = performance.now();

  // Several processes can reserve against the same index, but Redis's Lua
  // script guarantees they cannot push the list past the cap.
  const results = await Promise.allSettled(
    Array.from({ length: MAX_GRANT_TOKENS + 24 }, (_, i) =>
      adapter.upsert('token-' + i, { ...basePayload, serial: i }, 1800))
  );
  const fulfilled = results.filter(r => r.status === 'fulfilled').length;
  const rejected = results.filter(r => r.status === 'rejected');
  assert.equal(fulfilled, MAX_GRANT_TOKENS);
  assert.equal(rejected.length, 24);
  assert(rejected.every(r => r.reason?.code === 'OIDC_GRANT_TOKEN_LIMIT'));
  assert.equal(await redis.llen('grant:' + grantId), MAX_GRANT_TOKENS);
  assert((await redis.ttl('grant:' + grantId)) > 0);

  const active = await adapter.find('token-1');
  assert.equal(active.grantId, grantId);
  await adapter.revokeByGrantId(grantId);
  assert.equal(await redis.llen('grant:' + grantId), 0);
  assert.equal(await adapter.find('token-1'), undefined);
  await assert.rejects(
    adapter.upsert('token-reissue', basePayload, 1800),
    e => e.code === 'OIDC_GRANT_ALREADY_REVOKED'
  );

  // Existing deployments can have older, oversized token lists. Revoke
  // those incrementally, without issuing an unbounded LRANGE 0 -1.
  const legacy = 'legacy-' + crypto.randomUUID();
  const list = Array.from({ length: MAX_GRANT_TOKENS + 20 }, (_, i) =>
    'AccessToken:legacy-' + i
  );
  const batch = redis.multi();
  for (const key of list) batch.set(key, '{"legacy":true}');
  batch.rpush('grant:' + legacy, ...list);
  await batch.exec();
  await adapter.revokeByGrantId(legacy);
  assert.equal(await redis.llen('grant:' + legacy), 0);
  assert.equal(await redis.exists(list[0]), 0);
  assert.equal(await redis.exists(list[list.length - 1]), 0);
  const durationMs = Math.round(performance.now() - started);
  console.log(JSON.stringify({
    success: true, name: 'oidc-grant-index-real-redis',
    concurrentAttempts: results.length, accepted: fulfilled, rejected: rejected.length,
    limitPerGrant: MAX_GRANT_TOKENS,
    revokedLegacyTokens: list.length, durationMs,
    heapUsedBytes: process.memoryUsage().heapUsed
  }));
}
main().then(async () => {
  await redis.flushdb();
  redis.disconnect();
}).catch(async error => {
  try { await redis.flushdb(); } catch { /* test Redis unavailable */ }
  redis.disconnect();
  console.error('OIDC grant Redis proof failed:', error.code || error.message);
  process.exitCode = 1;
});
