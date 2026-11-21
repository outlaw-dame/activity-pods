const Redis = require('ioredis');
const crypto = require('crypto');
const { MoleculerError } = require('moleculer').Errors;
const { randomToken, nowEpochSec, parseIntWithBounds } = require('../../utils/oauth-security');

function sha256(input) {
  return crypto.createHash('sha256').update(String(input), 'utf8').digest('hex');
}

module.exports = {
  name: 'oauth-consent-challenge',

  settings: {
    redisUrl: process.env.SEMAPPS_REDIS_CACHE_URL || 'redis://localhost:6379',
    keyPrefix: 'oauth:consent-challenge',
    ttlSec: parseIntWithBounds(process.env.OAUTH_CONSENT_CHALLENGE_TTL_SECONDS, 300, 30, 900, 'OAUTH_CONSENT_CHALLENGE_TTL_SECONDS')
  },

  created() {
    // Never queue or automatically replay a one-use Redis operation after
    // disconnect or an ambiguously acknowledged write.
    this.redis = new Redis(this.settings.redisUrl, {
      lazyConnect: true, enableOfflineQueue: false,
      autoResendUnfulfilledCommands: false,
      connectTimeout: 2500, maxRetriesPerRequest: 1
    });
  },

  async started() {
    await this.redis.connect();
    if (await this.redis.ping() !== 'PONG') {
      throw new Error('OAuth consent challenge Redis unavailable');
    }
  },

  async stopped() {
    if (!this.redis) return;
    if (this.redis.status !== 'ready') {
      this.redis.disconnect();
      return;
    }
    await this.redis.quit().catch(() => this.redis.disconnect());
  },

  actions: {
    mint: {
      params: {
        requestUri: { type: 'string', min: 1 },
        fingerprint: { type: 'string', min: 8 },
        csrfToken: { type: 'string', min: 16 },
        expiresAt: { type: 'number', integer: true, positive: true, optional: true }
      },
      async handler(ctx) {
        const now = nowEpochSec();
        const challengeId = randomToken(24);
        const expiresAt = ctx.params.expiresAt || (now + this.settings.ttlSec);
        const ttlSec = Math.max(1, Math.min(this.settings.ttlSec, expiresAt - now));
        const record = {
          challengeId,
          requestUri: ctx.params.requestUri,
          fingerprint: ctx.params.fingerprint,
          csrfHash: sha256(ctx.params.csrfToken),
          createdAt: now,
          expiresAt: now + ttlSec
        };
        const persisted = await this.redis.set(
          `${this.settings.keyPrefix}:${challengeId}`,
          JSON.stringify(record), 'EX', ttlSec
        );
        if (persisted !== 'OK') throw new Error('OAuth consent challenge persistence unavailable');
        return record;
      }
    },

    consume: {
      params: {
        challengeId: { type: 'string', min: 8 }
      },
      async handler(ctx) {
        const key = `${this.settings.keyPrefix}:${ctx.params.challengeId}`;
        // Single-use challenge must have one winner across provider replicas.
        // Do not replay GETDEL when its acknowledgment is uncertain.
        const raw = await this.redis.getdel(key);
        if (!raw) return null;
        return JSON.parse(raw);
      }
    },

    verifyCsrf: {
      params: {
        expectedHash: { type: 'string', min: 32 },
        csrfToken: { type: 'string', min: 16 }
      },
      async handler(ctx) {
        const actualHash = sha256(ctx.params.csrfToken);
        return crypto.timingSafeEqual(Buffer.from(actualHash, 'hex'), Buffer.from(ctx.params.expectedHash, 'hex'));
      }
    }
  }
};
