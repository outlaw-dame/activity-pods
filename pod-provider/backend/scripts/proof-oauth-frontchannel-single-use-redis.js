'use strict';
// Live Redis 8.2 proof. Independent clients must never redeem the same
// one-use OAuth front-channel record twice. The adapters forbid nonatomic
// GET/DEL so this catches the former bug deterministically, not by luck.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Redis = require('ioredis');
const par = require('../services/oauth/oauth-par.service');
const challenge = require('../services/oauth/oauth-consent-challenge.service');
const dpop = require('../services/oauth/oauth-dpop-nonce.service');

const url = 'redis://127.0.0.1:6398';
if (process.env.NODE_ENV !== 'test' ||
    process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE !== 'confirmed' ||
    process.env.PAPER_OAUTH_EPOCH_REDIS_URL !== url) {
  throw Error('Refusing front-channel proof without disposable Redis 8.2');
}
const ns = 'paper:frontchannel-proof:' + crypto.randomBytes(10).toString('hex');
const clients = Array.from({ length: 2 }, () => new Redis(url, {
  lazyConnect: true, enableOfflineQueue: false,
  autoResendUnfulfilledCommands: false,
  connectTimeout: 2500, maxRetriesPerRequest: 1
}));
const [a, b] = clients;
const parSettings = { keyPrefix: ns + ':par', parTtlSec: 90 };
const challengeSettings = { keyPrefix: ns + ':challenge', ttlSec: 90 };
const nonceSettings = { noncePrefix: ns + ':nonce', nonceTtlSec: 90 };
const redirect = 'https://client.paper.example.org/callback';
const clientId = 'https://client.paper.example.org';
const scope = 'atproto repo:app.bsky.feed.post?action=create';

function consumeOnly(redis) {
  return {
    getdel: key => redis.getdel(key),
    get() { throw Error('Non-atomic GET used for one-time consumption'); },
    del() { throw Error('Non-atomic DEL used for one-time consumption'); }
  };
}
async function proof() {
  await Promise.all(clients.map(async redis => {
    await redis.connect();
    assert.equal(await redis.ping(), 'PONG');
  }));
  assert.match(await a.info('server'), /redis_version:8\.2\./u);

  const request = await par.actions.create.handler.call(
    { redis: a, settings: parSettings }, {
      params: {
        client_id: clientId, redirect_uri: redirect, response_type: 'code',
        scope, code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256', dpop_jkt: 'j'.repeat(43)
      },
      async call(name, params) {
        assert.equal(name, 'oauth-client-metadata.resolveClientMetadata');
        assert.equal(params.clientId, clientId);
        return { redirect_uris: [redirect], scope };
      }
    }
  );
  assert.equal((await par.actions.get.handler.call(
    { redis: b, settings: parSettings },
    { params: { requestUri: request.request_uri } }
  )).clientId, clientId);
  const parRace = await Promise.all([a, b].map(redis =>
    par.actions.consume.handler.call(
      { redis: consumeOnly(redis), settings: parSettings },
      { params: { requestUri: request.request_uri } }
    )
  ));
  assert.equal(parRace.filter(x => x !== null).length, 1);
  assert.equal(parRace.find(Boolean).requestUri, request.request_uri);
  assert.equal(await a.exists(parSettings.keyPrefix + ':' + request.request_uri), 0);

  const csrfToken = crypto.randomBytes(24).toString('base64url');
  const issued = await challenge.actions.mint.handler.call(
    { redis: a, settings: challengeSettings },
    { params: {
      requestUri: request.request_uri,
      fingerprint: crypto.randomBytes(32).toString('hex'), csrfToken
    } }
  );
  assert.equal(await challenge.actions.verifyCsrf.handler({
    params: { expectedHash: issued.csrfHash, csrfToken }
  }), true);
  const challengeRace = await Promise.all([a, b].map(redis =>
    challenge.actions.consume.handler.call(
      { redis: consumeOnly(redis), settings: challengeSettings },
      { params: { challengeId: issued.challengeId } }
    )
  ));
  assert.equal(challengeRace.filter(x => x !== null).length, 1);
  assert.equal(challengeRace.find(Boolean).challengeId, issued.challengeId);
  assert.equal(await b.exists(challengeSettings.keyPrefix + ':' + issued.challengeId), 0);

  const nonce = await dpop.actions.mintNonce.handler.call(
    { redis: a, settings: nonceSettings },
    { params: { audience: clientId } }
  );
  const nonceRace = await Promise.allSettled([a, b].map(redis =>
    dpop.methods.consumeNonce.call(
      { redis: consumeOnly(redis), settings: nonceSettings },
      { audience: clientId, nonce: nonce.nonce }
    )
  ));
  assert.equal(nonceRace.filter(x => x.status === 'fulfilled').length, 1);
  assert.equal(nonceRace.find(x => x.status === 'rejected')?.reason?.type,
    'INVALID_DPOP_NONCE');
  assert.equal(await a.exists(nonceSettings.noncePrefix + ':' + clientId + ':' + nonce.nonce), 0);

  // A lost write acknowledgment must surface as failure, not a second
  // redeem attempt or a fabricated accepted request.
  await assert.rejects(
    par.actions.consume.handler.call({
      redis: { getdel: async () => { throw Error('ambiguous Redis acknowledgment'); } },
      settings: parSettings
    }, { params: { requestUri: request.request_uri } }),
    /ambiguous Redis acknowledgment/u
  );
  console.log('PASS: Redis 8.2 two-worker single-use PAR/challenge/DPoP nonce, no GET+DEL or ambiguous-ACK replay');
}
async function cleanup() {
  if (a.status !== 'ready') return;
  let cursor = '0', pages = 0;
  do {
    if (++pages > 128) throw Error('Scoped front-channel cleanup exceeded 128 scans');
    const [next, keys] = await a.scan(cursor, 'MATCH', ns + ':*', 'COUNT', 256);
    if (keys.length) await a.unlink(...keys);
    cursor = next;
  } while (cursor !== '0');
}
(async () => {
  const watchdog = setTimeout(() => {
    console.error('FAIL: front-channel proof watchdog exceeded');
    process.exit(1);
  }, 60000);
  try { await proof(); }
  catch (error) {
    process.exitCode = 1;
    console.error(error?.stack || String(error));
  } finally {
    try { await cleanup(); }
    catch (error) {
      process.exitCode = 1;
      console.error('Scoped cleanup failed', error?.message);
    }
    await Promise.allSettled(clients.map(async redis => {
      if (redis.status === 'ready') await redis.quit();
      else redis.disconnect();
    }));
    clearTimeout(watchdog);
  }
})();
