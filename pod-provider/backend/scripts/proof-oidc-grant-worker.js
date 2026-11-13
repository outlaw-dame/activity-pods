'use strict';

const Redis = require('ioredis');
const RedisAdapter = require('../config/oidc-adapter');

if (process.env.NODE_ENV !== 'test' ||
    process.env.ATPROTO_CAPACITY_PROOF_DISPOSABLE !== 'confirmed' ||
    process.env.ATPROTO_OIDC_REDIS_WORKER !== 'confirmed') {
  throw Error('The grant stress worker is restricted to disposable integration tests');
}
const [grantId, workerId, attemptsText, mode = 'upsert'] = process.argv.slice(2);
const attempts = Number(attemptsText);
if (!/^grant-mp-[0-9a-f-]{36}$/u.test(grantId || '') ||
    !/^[0-3]$/u.test(workerId || '') ||
    !Number.isSafeInteger(attempts) || attempts < 1 || attempts > 200 ||
    !['upsert', 'revoke'].includes(mode)) {
  throw Error('Invalid disposable grant worker inputs');
}
const source = process.env.SEMAPPS_REDIS_OIDC_PROVIDER_URL || 'redis://redis:6379/13';
const url = new URL(source);
if (!['redis','localhost','127.0.0.1'].includes(url.hostname)) throw Error('Unknown Redis host');
url.pathname = '/15';
const testKeyPrefix = process.env.ATPROTO_OIDC_TEST_KEY_PREFIX;
if (!/^atproto-oidc-test:[0-9a-f-]{36}:$/u.test(testKeyPrefix || '')) {
  throw Error('Missing isolated Redis namespace for the disposable worker');
}
const redis = new Redis(url.toString(), {
  keyPrefix: testKeyPrefix,
  connectTimeout: 3000, maxRetriesPerRequest: 1
});
(async () => {
  const adapter = new RedisAdapter('AccessToken', redis);
  if (mode === 'revoke') {
    await adapter.revokeByGrantId(grantId);
    console.log(JSON.stringify({ workerId, mode: 'revoke', remainingPointers:
      await redis.llen('grant:' + grantId) }));
    return;
  }
  const results = await Promise.allSettled(Array.from({ length: attempts }, (_, i) =>
    adapter.upsert('worker-' + workerId + '-' + i, {
      grantId, accountId: 'test-user', clientId: 'test-client',
      workerId, serial: i
    }, 1800)));
  const accepted = results.filter(x => x.status === 'fulfilled').length;
  const rejected = results.filter(x => x.status === 'rejected');
  if (rejected.some(x => x.reason?.code !== 'OIDC_GRANT_TOKEN_LIMIT')) {
    throw Error('A worker encountered an unexpected grant-write failure');
  }
  console.log(JSON.stringify({ workerId, accepted, rejected: rejected.length }));
})().then(() => {
  redis.disconnect();
}).catch(e => {
  redis.disconnect();
  console.error(e.code || e.message);
  process.exitCode = 1;
});
