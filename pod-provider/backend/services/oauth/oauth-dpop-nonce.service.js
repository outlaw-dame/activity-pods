const Redis = require('ioredis');
const { MoleculerError } = require('moleculer').Errors;
const { importJWK, jwtVerify, calculateJwkThumbprint, decodeProtectedHeader } = require('jose');
const {
  randomToken,
  nowEpochSec,
  parseIntWithBounds,
  parseBoolean
} = require('../../utils/oauth-security');

module.exports = {
  name: 'oauth-dpop-nonce',

  settings: {
    redisUrl: process.env.SEMAPPS_REDIS_CACHE_URL || 'redis://localhost:6379',
    noncePrefix: 'oauth:dpop:nonce',
    replayPrefix: 'oauth:replay:dpop-jti',
    nonceTtlSec: parseIntWithBounds(process.env.OAUTH_DPOP_NONCE_TTL_SECONDS, 120, 30, 600, 'OAUTH_DPOP_NONCE_TTL_SECONDS'),
    replayTtlSec: parseIntWithBounds(process.env.OAUTH_DPOP_REPLAY_TTL_SECONDS, 300, 60, 3600, 'OAUTH_DPOP_REPLAY_TTL_SECONDS'),
    allowLocalhostHttp: parseBoolean(process.env.OAUTH_ENABLE_LOCALHOST_DEV, false)
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
    mintNonce: {
      params: {
        audience: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const audience = String(ctx.params.audience).trim();
        const nonce = randomToken(24);
        const now = nowEpochSec();
        const record = {
          issuedAt: now,
          expiresAt: now + this.settings.nonceTtlSec,
          consumed: false
        };

        const key = `${this.settings.noncePrefix}:${audience}:${nonce}`;
        await this.redis.set(key, JSON.stringify(record), 'EX', this.settings.nonceTtlSec);

        return {
          nonce,
          expires_in: this.settings.nonceTtlSec
        };
      }
    },

    verifyProof: {
      params: {
        proofJwt: { type: 'string', min: 10 },
        htm: { type: 'string', min: 1 },
        htu: { type: 'string', min: 1 },
        audience: { type: 'string', min: 1 },
        nonce: { type: 'string', optional: true },
        expectedJkt: { type: 'string', optional: true },
        expectedAth: { type: 'string', optional: true }
      },
      async handler(ctx) {
        const { proofJwt, htm, htu, audience, nonce, expectedJkt, expectedAth } = ctx.params;

        const protectedHeader = decodeProtectedHeader(proofJwt);
        if (!protectedHeader || protectedHeader.typ !== 'dpop+jwt') {
          throw new MoleculerError('DPoP proof typ must be dpop+jwt', 401, 'INVALID_DPOP_PROOF');
        }
        if (protectedHeader.alg !== 'ES256') {
          throw new MoleculerError('DPoP proof alg must be ES256', 401, 'INVALID_DPOP_PROOF');
        }
        if (!protectedHeader.jwk || typeof protectedHeader.jwk !== 'object') {
          throw new MoleculerError('DPoP proof missing jwk', 401, 'INVALID_DPOP_PROOF');
        }

        // RFC 9449 requires a public JWK in the DPoP protected header.
        // Reject private/symmetric material rather than accepting it as a
        // harmless extra claim that could leak signing-key bytes to the API.
        if (protectedHeader.jwk.kty !== 'EC' || protectedHeader.jwk.crv !== 'P-256' ||
            typeof protectedHeader.jwk.x !== 'string' ||
            typeof protectedHeader.jwk.y !== 'string' ||
            ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']
              .some(field => Object.hasOwn(protectedHeader.jwk, field))) {
          throw new MoleculerError('DPoP JWK must contain public key only', 401, 'INVALID_DPOP_PROOF');
        }

        const key = await importJWK(protectedHeader.jwk, 'ES256');
        const { payload } = await jwtVerify(proofJwt, key, {
          typ: 'dpop+jwt',
          clockTolerance: 60
        });

        if (String(payload.htm || '').toUpperCase() !== String(htm).toUpperCase()) {
          throw new MoleculerError('DPoP htm mismatch', 401, 'INVALID_DPOP_PROOF');
        }

        const expectedUrl = new URL(String(htu));
        const proofUrl = new URL(String(payload.htu || ''));
        if (expectedUrl.origin !== proofUrl.origin || expectedUrl.pathname !== proofUrl.pathname) {
          throw new MoleculerError('DPoP htu mismatch', 401, 'INVALID_DPOP_PROOF');
        }

        const proofJti = typeof payload.jti === 'string' ? payload.jti : '';
        if (!proofJti || Buffer.byteLength(proofJti) > 256 ||
            /[\u0000-\u001f\u007f]/u.test(proofJti)) {
          throw new MoleculerError('DPoP jti missing', 401, 'INVALID_DPOP_PROOF');
        }

        const issuedAt = Number(payload.iat || 0);
        const now = nowEpochSec();
        // A proof may be at most 60 s ahead and 300 s behind. The replay
        // marker must outlive this ENTIRE validity horizon, including skew.
        if (!Number.isSafeInteger(issuedAt) || issuedAt > now + 60 ||
            now - issuedAt > 300) {
          throw new MoleculerError('DPoP iat outside allowed skew', 401, 'INVALID_DPOP_PROOF');
        }

        const jkt = await calculateJwkThumbprint(protectedHeader.jwk, 'sha256');
        if (expectedJkt && String(expectedJkt).trim() !== jkt) {
          throw new MoleculerError('DPoP JKT mismatch', 401, 'INVALID_DPOP_PROOF');
        }

        // For DPoP-bound resource requests, the signed proof must bind the
        // exact access token bytes via the RFC 9449 ath claim.
        if (expectedAth !== undefined &&
            (typeof payload.ath !== 'string' || payload.ath !== expectedAth)) {
          throw new MoleculerError('DPoP token hash mismatch', 401, 'INVALID_DPOP_PROOF');
        }

        if (nonce) {
          const proofNonce = String(payload.nonce || '').trim();
          if (!proofNonce || proofNonce !== String(nonce).trim()) {
            throw new MoleculerError('DPoP nonce is required or invalid', 401, 'INVALID_DPOP_NONCE');
          }

          await this.consumeNonce({ audience, nonce: proofNonce });
        }

        const replayKey = `${this.settings.replayPrefix}:${jkt}:${proofJti}`;
        // Even when an operator configured a shorter historical TTL,
        // never permit the JTI marker to expire while the proof can still
        // satisfy the verifier's asymmetric 60 s future + 300 s past window.
        const replayTtlSec = Math.max(this.settings.replayTtlSec, 420);
        const replaySet = await this.redis.set(replayKey, '1', 'EX', replayTtlSec, 'NX');
        if (replaySet !== 'OK') {
          throw new MoleculerError('DPoP replay detected', 401, 'DPOP_REPLAY_DETECTED');
        }

        return {
          jkt,
          jti: proofJti,
          iat: issuedAt
        };
      }
    }
  },

  methods: {
    async consumeNonce({ audience, nonce }) {
      const key = `${this.settings.noncePrefix}:${audience}:${nonce}`;
      // Atomic one-time consumption (Redis >= 6.2). GET+DEL allowed two
      // parallel requests to consume the same challenge before either deleted.
      // Do not silently downgrade to a non-atomic sequence.
      const payload = await this.redis.call('GETDEL', key);
      if (!payload) {
        throw new MoleculerError('DPoP nonce is invalid or expired', 401, 'INVALID_DPOP_NONCE');
      }
    }
  }
};
