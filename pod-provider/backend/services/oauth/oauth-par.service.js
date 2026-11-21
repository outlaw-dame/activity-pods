const Redis = require('ioredis');
const { MoleculerError } = require('moleculer').Errors;
const { randomToken, nowEpochSec, parseIntWithBounds } = require('../../utils/oauth-security');

module.exports = {
  name: 'oauth-par',
  dependencies: ['oauth-client-metadata', 'oauth-dpop-nonce'],

  settings: {
    redisUrl: process.env.SEMAPPS_REDIS_CACHE_URL || 'redis://localhost:6379',
    keyPrefix: 'oauth:par',
    parTtlSec: parseIntWithBounds(process.env.OAUTH_PAR_TTL_SECONDS, 90, 30, 300, 'OAUTH_PAR_TTL_SECONDS')
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
      throw new Error('OAuth PAR Redis unavailable');
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
    create: {
      params: {
        client_id: { type: 'string', min: 1 },
        redirect_uri: { type: 'string', min: 1 },
        response_type: { type: 'string', min: 1 },
        scope: { type: 'string', min: 1 },
        code_challenge: { type: 'string', min: 43, max: 128 },
        code_challenge_method: { type: 'string', min: 1 },
        state: { type: 'string', optional: true },
        login_hint: { type: 'string', optional: true },
        dpop_jkt: { type: 'string', min: 8 }
      },
      async handler(ctx) {
        const body = ctx.params;
        if (body.response_type !== 'code') {
          throw new MoleculerError('response_type must be code', 400, 'INVALID_PAR_REQUEST');
        }
        if (body.code_challenge_method !== 'S256') {
          throw new MoleculerError('code_challenge_method must be S256', 400, 'INVALID_PAR_REQUEST');
        }

        const metadata = await ctx.call('oauth-client-metadata.resolveClientMetadata', {
          clientId: body.client_id
        });

        if (!metadata.redirect_uris.includes(body.redirect_uri)) {
          throw new MoleculerError('redirect_uri is not registered', 400, 'INVALID_REDIRECT_URI');
        }

        const scopeSet = String(body.scope || '').split(/\s+/).filter(Boolean);
        const allowedScopeSet = String(metadata.scope || '').split(/\s+/).filter(Boolean);
        if (!scopeSet.every(scope => allowedScopeSet.includes(scope))) {
          throw new MoleculerError('requested scope exceeds client metadata scope', 400, 'INVALID_SCOPE');
        }

        const token = randomToken(24);
        const requestUri = `urn:ietf:params:oauth:request_uri:${token}`;
        const now = nowEpochSec();

        const record = {
          requestUri,
          clientId: body.client_id,
          redirectUri: body.redirect_uri,
          responseType: body.response_type,
          scope: body.scope,
          codeChallenge: body.code_challenge,
          codeChallengeMethod: body.code_challenge_method,
          state: body.state || undefined,
          loginHint: body.login_hint || undefined,
          dpopJkt: body.dpop_jkt,
          createdAt: now,
          expiresAt: now + this.settings.parTtlSec
        };

        const persisted = await this.redis.set(
          `${this.settings.keyPrefix}:${requestUri}`, JSON.stringify(record),
          'EX', this.settings.parTtlSec
        );
        if (persisted !== 'OK') throw new Error('OAuth PAR persistence unavailable');

        return {
          request_uri: requestUri,
          expires_in: this.settings.parTtlSec
        };
      }
    },

    get: {
      params: {
        requestUri: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const key = `${this.settings.keyPrefix}:${ctx.params.requestUri}`;
        const payload = await this.redis.get(key);
        if (!payload) return null;
        return JSON.parse(payload);
      }
    },

    consume: {
      params: {
        requestUri: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const key = `${this.settings.keyPrefix}:${ctx.params.requestUri}`;
        // GETDEL linearizes one-time acceptance across all provider replicas.
        // A lost acknowledgment burns the request; never retry the mutation.
        const payload = await this.redis.getdel(key);
        if (!payload) return null;
        return JSON.parse(payload);
      }
    }
  }
};
