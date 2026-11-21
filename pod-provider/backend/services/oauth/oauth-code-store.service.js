const Redis = require('ioredis');
const { MoleculerError } = require('moleculer').Errors;
const { randomToken, nowEpochSec, parseIntWithBounds } = require('../../utils/oauth-security');

module.exports = {
  name: 'oauth-code-store',

  settings: {
    redisUrl: process.env.SEMAPPS_REDIS_CACHE_URL || 'redis://localhost:6379',
    keyPrefix: 'oauth:code',
    usedPrefix: 'oauth:code-used',
    codeTtlSec: parseIntWithBounds(process.env.OAUTH_CODE_TTL_SECONDS, 90, 30, 300, 'OAUTH_CODE_TTL_SECONDS')
  },

  created() {
    this.redis = new Redis(this.settings.redisUrl);
  },

  async stopped() {
    if (this.redis) {
      await this.redis.quit().catch(() => this.redis.disconnect());
    }
  },

  actions: {
    issueCode: {
      params: {
        clientId: { type: 'string', min: 1 },
        redirectUri: { type: 'string', min: 1 },
        canonicalAccountId: { type: 'string', min: 1 },
        did: { type: 'string', min: 1 },
        scope: { type: 'string', min: 1 },
        consentGrantId: { type: 'string', pattern: '^[A-Za-z0-9_-]{32}$' },
        dpopJkt: { type: 'string', min: 8 },
        codeChallenge: { type: 'string', min: 43, max: 128 },
        codeChallengeMethod: { type: 'string', min: 1 },
        state: { type: 'string', optional: true }
      },
      async handler(ctx) {
        const code = randomToken(24);
        const now = nowEpochSec();
        const record = {
          clientId: ctx.params.clientId,
          redirectUri: ctx.params.redirectUri,
          canonicalAccountId: ctx.params.canonicalAccountId,
          did: ctx.params.did,
          scope: ctx.params.scope,
          consentGrantId: ctx.params.consentGrantId,
          dpopJkt: ctx.params.dpopJkt,
          codeChallenge: ctx.params.codeChallenge,
          codeChallengeMethod: ctx.params.codeChallengeMethod,
          state: ctx.params.state || undefined,
          createdAt: now,
          expiresAt: now + this.settings.codeTtlSec
        };

        await this.redis.set(`${this.settings.keyPrefix}:${code}`, JSON.stringify(record), 'EX', this.settings.codeTtlSec);
        return { code, expiresIn: this.settings.codeTtlSec };
      }
    },

    consumeCode: {
      params: {
        code: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const code = String(ctx.params.code).trim();
        const codeKey = `${this.settings.keyPrefix}:${code}`;
        const usedKey = `${this.settings.usedPrefix}:${code}`;

        // GETDEL, not GET then DEL inside a MULTI, is the single-use
        // linearization point for all provider replicas. Lost ACKs burn the
        // code: never mint two refresh-token families from one approval.
        const payload = await this.redis.getdel(codeKey);
        if (!payload) {
          const used=await this.redis.exists(usedKey);
          throw new MoleculerError(
            used===1?'Authorization code already used':'Invalid authorization code',
            400,used===1?'AUTHORIZATION_CODE_ALREADY_USED':'INVALID_AUTHORIZATION_CODE'
          );
        }
        await this.redis.set(usedKey,'1','EX',this.settings.codeTtlSec);
        let record;
        try{record=JSON.parse(payload);}catch{
          throw new MoleculerError('Invalid authorization code',400,'INVALID_AUTHORIZATION_CODE');
        }
        if(!/^[A-Za-z0-9_-]{32}$/u.test(record?.consentGrantId||'')){
          throw new MoleculerError('Unbound authorization code',400,'INVALID_AUTHORIZATION_CODE');
        }
        return record;
      }
    }
  }
};
