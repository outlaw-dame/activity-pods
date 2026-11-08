'use strict';

/*
 * Live Redis proof for high-trust collective step-up primitives.
 * Run only against an isolated test Redis database.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Redis = require('ioredis');

const url = process.env.COLLECTIVES_TEST_REDIS_URL || 'redis://127.0.0.1:6379/15';
if (!url.endsWith('/15')) throw new Error('Refusing to run against a non-isolated Redis DB; expected DB 15');

const LME = "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n";
async function proof() {
  const redis = new Redis(url, {
    lazyConnect: true, maxRetriesPerRequest: 2, connectTimeout: 5000,
    retryStrategy: times => (times <= 2 ? Math.min(times * 200, 400) : null)
  });
  const prefix = 'g1-proof-' + crypto.randomBytes(12).toString('hex');
  try {
    await redis.connect();
    const rateKey = prefix + ':rate';
    const attempts = await Promise.all(Array.from({ length: 16 },
      () => redis.eval(LME, 1, rateKey, 60)));
    const ordered = [...attempts].map(Number).sort((a, b) => a - b);
    assert.deepEqual(ordered, Array.from({ length: 16 }, (_, i) => i + 1));
    assert((await redis.ttl(rateKey)) > 0);
    const ticketKey = prefix + ':ticket';
    const claims = await Promise.all(Array.from({ length: 16 },
      () => redis.set(ticketKey, '1', 'EX', 600, 'NX')));
    assert.equal(claims.filter(v => v === 'OK').length, 1,
      'only one concurrent WebAuthn ticket claim');
    assert.equal(await redis.ttl(ticketKey) > 0, true);

    const nonceKey = prefix + ':nonce';
    await redis.set(nonceKey, 'issued', 'EX', 60);
    const consumed = await Promise.all(Array.from({ length: 16 },
      () => redis.call('GETDEL', nonceKey)));
    assert.equal(consumed.filter(v => v === 'issued').length, 1,
      'only one concurrent DPoP nonce consumption');

    const jtiKey = prefix + ':dpop-jti';
    const replayClaims = await Promise.all(Array.from({ length: 16 },
      () => redis.set(jtiKey, '1', 'EX', 300, 'NX')));
    assert.equal(replayClaims.filter(v => v === 'OK').length, 1,
      'DPoP replay JTI is accepted only once');

    console.log(JSON.stringify({ ok: true, kind: 'real-redis', concurrentCalls: 16,
      rateLimitAtomic: true, ticketSingleUse: true, nonceSingleUse: true,
      dpopJtiSingleUse: true }));
  } finally {
    const keys = await redis.keys(prefix + ':*').catch(() => []);
    if (keys.length) await redis.del(...keys).catch(() => {});
    await redis.quit().catch(() => redis.disconnect());
  }
}
proof().catch(e => { console.error(e); process.exitCode = 1; });
