'use strict';

// Real Redis acceptance proof. Use a unique, bounded test namespace in DB 15.
// Never flush an entire database or remove another test's or app's keys.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Redis = require('ioredis');
const RedisAdapter = require('../config/oidc-adapter');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const path = require('node:path');
const execFileAsync = promisify(execFile);
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
const testKeyPrefix = 'atproto-oidc-test:' + crypto.randomUUID() + ':';
const redisOptions = {
  enableOfflineQueue: false,
  connectTimeout: 3000,
  maxRetriesPerRequest: 1
};
const redis = new Redis(url.toString(), {
  ...redisOptions, keyPrefix: testKeyPrefix
});
// SCAN and UNLINK operate on real Redis keys, not ioredis-prefixed keys.
// Restrict cleanup to the random namespace created for this one test.
const cleanupRedis = new Redis(url.toString(), redisOptions);
async function cleanupOwnKeys() {
  for (let pass = 0; pass < 2; pass++) {
    let cursor = '0';
    let inspectedPages = 0;
    do {
      if (++inspectedPages > 64) throw Error('Disposable Redis cleanup page limit exceeded');
      const [next, keys] = await cleanupRedis.scan(
        cursor, 'MATCH', testKeyPrefix + '*', 'COUNT', 256
      );
      cursor = next;
      if (keys.length) {
        if (keys.length > 512) throw Error('Disposable Redis cleanup batch too large');
        await cleanupRedis.unlink(...keys);
      }
    } while (cursor !== '0');
  }
}
async function waitReady(client) {
  if (client.status === 'ready') return;
  await new Promise((resolve, reject) => {
    const done = (error) => {
      clearTimeout(timer);
      client.removeListener('ready', onReady);
      client.removeListener('error', onError);
      if (error) reject(error);
      else resolve();
    };
    const onReady = () => done();
    const onError = error => done(error);
    const timer = setTimeout(
      () => done(Error('Disposable Redis did not become ready in time')), 5000
    );
    timer.unref?.();
    client.once('ready', onReady);
    client.once('error', onError);
    if (client.status === 'ready') done();
  });
}
async function main() {
  await Promise.all([waitReady(redis), waitReady(cleanupRedis)]);
  await Promise.all([redis.ping(), cleanupRedis.ping()]);
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

  // oidc-provider can upsert an existing token when its metadata changes.
  // Reusing the same ID must not add another revocation pointer or use up
  // more of the fixed per-grant quota.
  await adapter.upsert('token-1', { ...basePayload, serial: 1234 }, 1800);
  assert.equal(await redis.llen('grant:' + grantId), MAX_GRANT_TOKENS);
  await assert.rejects(
    adapter.upsert('token-1', {
      ...basePayload, grantId: 'different-grant', serial: 99
    }, 1800),
    e => e.code === 'OIDC_GRANT_TOKEN_ID_CONFLICT'
  );
  assert.equal(await redis.llen('grant:' + grantId), MAX_GRANT_TOKENS);
  const active = await adapter.find('token-1');
  assert.equal(active.grantId, grantId);
  assert.equal(active.serial, 1234);
  await adapter.revokeByGrantId(grantId);
  assert.equal(await redis.llen('grant:' + grantId), 0);
  assert.equal(await adapter.find('token-1'), undefined);
  await assert.rejects(
    adapter.upsert('token-reissue', basePayload, 1800),
    e => e.code === 'OIDC_GRANT_ALREADY_REVOKED'
  );

  // Four separate Node processes with independent Redis connections all
  // contend for the same grant. Redis, not process-local JavaScript state,
  // must enforce the cap across every worker.
  const sharedGrant = 'grant-mp-' + crypto.randomUUID();
  const workers = await Promise.all(Array.from({ length: 4 }, async (_, i) => {
    const { stdout } = await execFileAsync(process.execPath, [
      path.join(__dirname, 'proof-oidc-grant-worker.js'),
      sharedGrant, String(i), '150'
    ], {
      env: {
        ...process.env,
        ATPROTO_OIDC_REDIS_WORKER: 'confirmed',
        ATPROTO_OIDC_TEST_KEY_PREFIX: testKeyPrefix
      },
      timeout: 12000, maxBuffer: 32 * 1024
    });
    return JSON.parse(stdout.trim());
  }));
  assert.equal(workers.reduce((sum, w) => sum + w.accepted, 0), MAX_GRANT_TOKENS);
  assert.equal(workers.reduce((sum, w) => sum + w.rejected, 0), 600 - MAX_GRANT_TOKENS);
  assert.equal(await redis.llen('grant:' + sharedGrant), MAX_GRANT_TOKENS);
  await adapter.revokeByGrantId(sharedGrant);
  assert.equal(await redis.llen('grant:' + sharedGrant), 0);
  await assert.rejects(
    adapter.upsert('worker-replay', { ...basePayload, grantId: sharedGrant }, 1800),
    e => e.code === 'OIDC_GRANT_ALREADY_REVOKED'
  );

  // Simulate a process killed after committing the revocation marker but
  // before deleting all token keys. A client must not regain access merely
  // because the cleanup worker disappeared.
  const interrupted = 'grant-interrupted-' + crypto.randomUUID();
  await adapter.upsert('interrupted-token', { ...basePayload, grantId: interrupted }, 1800);
  await redis.set('grant-revoked:' + interrupted, '1', 'EX', 86400);
  assert.equal(await adapter.find('interrupted-token'), undefined);
  assert.equal(await redis.exists('AccessToken:interrupted-token'), 1);
  await adapter.revokeByGrantId(interrupted);
  assert.equal(await redis.exists('AccessToken:interrupted-token'), 0);

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

  // Review regression #171: individually destroyed keys must not consume
  // the entire grant quota indefinitely. At the cap, Lua compacts ONLY
  // demonstrably absent Redis token keys, preserving the one live pointer.
  const reusedGrant = 'grant-reused-' + crypto.randomUUID();
  const reusedPayload = { ...basePayload, grantId: reusedGrant };
  const keepId = 'recycle-keep-' + crypto.randomUUID();
  await adapter.upsert(keepId, reusedPayload, 1800);
  const deadIds = Array.from({ length: MAX_GRANT_TOKENS - 1 }, (_, i) =>
    'recycle-dead-' + i + '-' + crypto.randomUUID());
  await Promise.all(deadIds.map(id => adapter.upsert(id, reusedPayload, 1800)));
  assert.equal(await redis.llen('grant:' + reusedGrant), MAX_GRANT_TOKENS);
  await Promise.all(deadIds.map(id => adapter.destroy(id)));
  assert.equal(await redis.exists('AccessToken:' + keepId), 1);
  assert.equal(await redis.llen('grant:' + reusedGrant), MAX_GRANT_TOKENS,
    'deleted/expired keys are still in the old pointer index until admission');
  const replacement = 'recycle-new-' + crypto.randomUUID();
  await adapter.upsert(replacement, reusedPayload, 1800);
  assert.equal(await redis.llen('grant:' + reusedGrant), 2,
    'at-cap compaction keeps live tokens and reclaims dead pointers');
  assert.equal(await redis.exists('AccessToken:' + keepId), 1);
  await adapter.revokeByGrantId(reusedGrant);
  assert.equal(await redis.exists('AccessToken:' + keepId, 'AccessToken:' + replacement), 0);

  // Redis TTL expiry independently leaves stale list entries. Verify that a
  // 1-second token TTL cannot permanently exhaust a long-lived grant.
  const expiredGrant = 'grant-expired-' + crypto.randomUUID();
  const expiredPayload = { ...basePayload, grantId: expiredGrant };
  const survivor = 'expiry-survivor-' + crypto.randomUUID();
  await adapter.upsert(survivor, expiredPayload, 1800);
  const oneSecond = Array.from({ length: MAX_GRANT_TOKENS - 1 }, (_, i) =>
    'expiry-short-' + i + '-' + crypto.randomUUID());
  await Promise.all(oneSecond.map(id => adapter.upsert(id, expiredPayload, 1)));
  await new Promise(resolve => setTimeout(resolve, 1700));
  assert.equal(await redis.exists('AccessToken:' + oneSecond[0]), 0);
  const afterExpiry = 'expiry-new-' + crypto.randomUUID();
  await adapter.upsert(afterExpiry, expiredPayload, 1800);
  assert.equal(await redis.llen('grant:' + expiredGrant), 2);
  await adapter.revokeByGrantId(expiredGrant);
  assert.equal(await redis.exists('AccessToken:' + survivor, 'AccessToken:' + afterExpiry), 0);

  // Review regression #171: revokers on four separate processes previously
  // read the same 128 pointers, then independently trimmed the list. That
  // could orphan live token keys while falsely returning successful cleanup.
  // The Lua batch now selects, deletes and trims atomically.
  const concurrentRevokeGrant = 'grant-mp-' + crypto.randomUUID();
  const concurrentPayload = { ...basePayload, grantId: concurrentRevokeGrant };
  const concurrentIds = Array.from({ length: 384 }, (_, i) =>
    'race-revoke-' + i + '-' + crypto.randomUUID());
  await Promise.all(concurrentIds.map(id => adapter.upsert(id, concurrentPayload, 1800)));
  assert.equal(await redis.llen('grant:' + concurrentRevokeGrant), 384);
  const revokeWorkers = await Promise.all(Array.from({ length: 4 }, async (_, i) => {
    const { stdout } = await execFileAsync(process.execPath, [
      path.join(__dirname, 'proof-oidc-grant-worker.js'),
      concurrentRevokeGrant, String(i), '1', 'revoke'
    ], {
      env: {
        ...process.env,
        ATPROTO_OIDC_REDIS_WORKER: 'confirmed',
        ATPROTO_OIDC_TEST_KEY_PREFIX: testKeyPrefix
      },
      timeout: 12000, maxBuffer: 32 * 1024
    });
    return JSON.parse(stdout.trim());
  }));
  assert(revokeWorkers.every(x => x.mode === 'revoke' && x.remainingPointers === 0));
  assert.equal(await redis.llen('grant:' + concurrentRevokeGrant), 0);
  for (let i = 0; i < concurrentIds.length; i += 128) {
    const batchIds = concurrentIds.slice(i, i + 128).map(id => 'AccessToken:' + id);
    assert.equal(await redis.exists(...batchIds), 0,
      'no token may remain after parallel grant revocation');
  }
  await assert.rejects(
    adapter.upsert('revoke-new-' + crypto.randomUUID(), concurrentPayload, 1800),
    e => e.code === 'OIDC_GRANT_ALREADY_REVOKED'
  );

  // Estimate the storage footprint of the actual DPoP replay-key format.
  // MEMORY USAGE reports Redis allocation for the sample keys, not the
  // process's complete RSS or allocator fragmentation. It cannot be used
  // as a cloud pricing quote.
  const sampleKeys = Array.from({ length: 32 }, () =>
    'atproto:dpop:replay:' + crypto.randomBytes(32).toString('hex')
  );
  for (const key of sampleKeys) {
    assert.equal(await redis.set(key, '1', 'EX', 130, 'NX'), 'OK');
  }
  // MEMORY USAGE is a Redis subcommand whose key argument is not
  // rewritten by ioredis keyPrefix. Inspect the fully qualified key on
  // the unprefixed cleanup connection; do not query the wrong namespace.
  const used = await Promise.all(sampleKeys.map(k =>
    cleanupRedis.memory('USAGE', testKeyPrefix + k)
  ));
  assert(used.every(bytes => Number.isSafeInteger(bytes) && bytes > 0));
  const replaySampleBytesPerKey = Math.round(
    used.reduce((sum, n) => sum + n, 0) / used.length
  );
  await redis.del(...sampleKeys);

  const durationMs = Math.round(performance.now() - started);
  console.log(JSON.stringify({
    success: true, name: 'oidc-grant-index-real-redis',
    concurrentAttempts: results.length, accepted: fulfilled, rejected: rejected.length,
    limitPerGrant: MAX_GRANT_TOKENS,
    multiProcessWorkers: workers.length,
    multiProcessAccepted: workers.reduce((sum, w) => sum + w.accepted, 0),
    multiProcessRejected: workers.reduce((sum, w) => sum + w.rejected, 0),
    revokedLegacyTokens: list.length,
    verifiedExpiredPointerCompaction: true,
    verifiedConcurrentRevokeWorkers: revokeWorkers.length,
    durationMs,
    replaySampleBytesPerKey,
    modeledReplayMegabytesAt1000Rps:
      Number((replaySampleBytesPerKey * 1000 * 130 / 1048576).toFixed(2)),
    heapUsedBytes: process.memoryUsage().heapUsed
  }));
}
main().catch(error => {
  console.error('OIDC grant Redis proof failed:', error.stack || error.message || String(error));
  process.exitCode = 1;
}).finally(async () => {
  try {
    await cleanupOwnKeys();
  } catch (error) {
    console.error('Disposable Redis cleanup failed:', error.code || error.message);
    process.exitCode = 1;
  } finally {
    redis.disconnect();
    cleanupRedis.disconnect();
  }
});
