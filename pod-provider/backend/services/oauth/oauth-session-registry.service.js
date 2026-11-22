'use strict';
const Redis = require('ioredis');
const crypto = require('node:crypto');
const { MoleculerError } = require('moleculer').Errors;

// Session ids are 32 CSPRNG bytes, never predictable or user-selected.
// Redis stores only hashes of ids/owner WebIDs and a bounded TTL. A valid
// browser HMAC by itself grants no OAuth owner authority.
const SESSION_ID = /^[A-Za-z0-9_-]{43}$/u;
const OWNER = /^https:\/\/[^\s]+$/u;
const KEY_PREFIX = 'oauth:browser-session:v1:';
const REVOKE_IF_OWNER = [
  "local actual=redis.call('GET',KEYS[1])",
  "if not actual or actual~=ARGV[1] then return 0 end",
  "return redis.call('DEL',KEYS[1])"
].join('\n');
function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}
function inputValid(sessionId, webId) {
  return typeof sessionId === 'string' && SESSION_ID.test(sessionId) &&
    typeof webId === 'string' && webId.length <= 2048 && OWNER.test(webId);
}
function refuse() {
  throw new MoleculerError('Browser session cannot be established', 503, 'SESSION_AUTHORITY_UNAVAILABLE');
}
module.exports = {
  name: 'oauth-session-registry',
  settings: {
    redisUrl: process.env.SEMAPPS_REDIS_CACHE_URL || 'redis://localhost:6379',
    keyPrefix: KEY_PREFIX
  },
  created() {
    this.redis = new Redis(this.settings.redisUrl, {
      lazyConnect: true, enableOfflineQueue: false,
      autoResendUnfulfilledCommands: false, maxRetriesPerRequest: 1,
      connectTimeout: 2500
    });
  },
  async started() {
    await this.redis.connect();
    if (await this.redis.ping() !== 'PONG') {
      throw new Error('OAuth browser session Redis unavailable');
    }
  },
  async stopped() {
    if (!this.redis) return;
    if (this.redis.status !== 'ready') { this.redis.disconnect(); return; }
    await this.redis.quit().catch(() => this.redis.disconnect());
  },
  actions: {
    create: {
      params: {
        webId: { type: 'string', min: 8, max: 2048 },
        sessionId: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' },
        ttlSec: { type: 'number', integer: true, min: 300, max: 86400 }
      },
      async handler(ctx) {
        const { sessionId, webId, ttlSec } = ctx.params;
        if (!inputValid(sessionId, webId)) refuse();
        // NX prevents accidental reuse, including a conflicting owner. No
        // automatic replay after unknown Redis write acknowledgements.
        const acknowledged = await this.redis.set(
          this.settings.keyPrefix + sha256(sessionId),
          sha256(webId), 'EX', ttlSec, 'NX'
        );
        if (acknowledged !== 'OK') refuse();
        return true;
      }
    },
    verify: {
      params: {
        webId: { type: 'string', min: 8, max: 2048 },
        sessionId: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' }
      },
      async handler(ctx) {
        const { sessionId, webId } = ctx.params;
        if (!inputValid(sessionId, webId)) return false;
        // No positive cache. Cross-replica sign-out and expiry must become
        // visible at the Redis authority before a new owner approval.
        const raw = await this.redis.get(this.settings.keyPrefix + sha256(sessionId));
        const expected = sha256(webId);
        return typeof raw === 'string' && raw.length === expected.length &&
          crypto.timingSafeEqual(Buffer.from(raw, 'ascii'), Buffer.from(expected, 'ascii'));
      }
    },
    revoke: {
      params: {
        webId: { type: 'string', min: 8, max: 2048 },
        sessionId: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' }
      },
      async handler(ctx) {
        const { sessionId, webId } = ctx.params;
        if (!inputValid(sessionId, webId)) refuse();
        // Compare and delete in one Redis transaction so an unrelated
        // owner cannot delete another account's session.
        const removed = await this.redis.eval(
          REVOKE_IF_OWNER, 1, this.settings.keyPrefix + sha256(sessionId),
          sha256(webId)
        );
        if (removed !== 0 && removed !== 1) refuse();
        return { revoked: removed === 1 };
      }
    }
  }
};
