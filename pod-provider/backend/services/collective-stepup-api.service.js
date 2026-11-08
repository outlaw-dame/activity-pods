'use strict';

/**
 * Bridge existing Solid-OIDC application consent and verified user presence
 * into a purpose-limited Group reservation credential.
 *
 * Flow:
 * 1. Existing /auth/passkeys/authentication/options provides a WebAuthn
 *    challenge and signed ticket.
 * 2. Client POSTs /api/collectives/stepup/verify with its ordinary Solid ID
 *    token, a DPoP JWS of the *same token*, ticket and WebAuthn assertion.
 * 3. Provider re-verifies Solid ID token, exact current SAI grants, DPoP
 *    possession, and the actual passkey identity; consumes the ticket once.
 * 4. Only then issues a short-lived, HS256 Group-only token with cnf.jkt.
 *
 * There is no token exchange or change to existing Solid-OIDC clients.
 * Distinct signing keys prevent Group-only tokens from acting as Solid IDs.
 * Off by default, same as the Group reservation API.
 */
const crypto = require('node:crypto');
const Redis = require('ioredis');
const { MoleculerError } = require('moleculer').Errors;
const { approvedBrowserOrigins } = require('./utils/collective-endpoint-policy');
const { assertLiveCollectiveConsent, parseApprovedApps } = require('./utils/collective-access-policy');

function deny(code, status = 401) {
  throw new MoleculerError(code, status, code);
}
function providerOrigin(raw) {
  if (typeof raw !== 'string') deny('COLLECTIVE_STEPUP_DISABLED', 503);
  let u;
  try { u = new URL(raw); } catch { deny('COLLECTIVE_STEPUP_DISABLED', 503); }
  if (u.protocol !== 'https:' || u.pathname !== '/' || u.search || u.hash ||
      u.username || u.password || u.origin !== raw.replace(/\/$/u, '')) {
    deny('COLLECTIVE_STEPUP_DISABLED', 503);
  }
  return u.origin;
}
function oidcClaims(payload, issuer) {
  if (!payload || typeof payload.webid !== 'string' ||
      typeof payload.azp !== 'string' || payload.sub !== payload.webid ||
      payload.iss !== issuer && payload.iss !== issuer + '/' ||
      payload.aud !== payload.azp || !Number.isSafeInteger(payload.exp) ||
      payload.exp <= Math.floor(Date.now() / 1000)) {
    deny('COLLECTIVE_OIDC_AUTH_REQUIRED');
  }
  return { principal: payload.webid, app: payload.azp };
}
function bearer(raw) {
  if (typeof raw !== 'string' || raw.length > 8192 ||
      !/^Bearer [A-Za-z0-9._~-]+$/u.test(raw)) deny('COLLECTIVE_OIDC_AUTH_REQUIRED');
  return raw.slice(7);
}

module.exports = {
  name: 'collective-stepup-api',
  dependencies: ['api', 'jwk', 'passkeys-api', 'oauth-dpop-nonce',
    'collective-stepup-credentials'],
  settings: {
    enabled: process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_STEPUP_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_API_ENABLED === 'true',
    origin: process.env.SEMAPPS_HOME_URL || '',
    approvedApps: parseApprovedApps(process.env.PROVIDER_COLLECTIVES_APPROVED_APPS || ''),
    allowedOriginsConfig: process.env.PROVIDER_COLLECTIVES_ALLOWED_ORIGINS || '',
    redisUrl: process.env.SEMAPPS_REDIS_CACHE_URL || 'redis://localhost:6379',
    ticketPrefix: 'collective:stepup:ticket',
    ticketTtlSeconds: 600,
    maxAttemptsPerMinute: 8,
    ratePrefix: 'collective:stepup:rate'
  },

  created() {
    if (this.settings.enabled) this.redis = new Redis(this.settings.redisUrl);
  },

  async stopped() {
    if (this.redis) await this.redis.quit().catch(() => this.redis.disconnect());
  },

  async started() {
    if (!this.settings.enabled) return;
    await this.broker.call('api.addRoute', {
      route: {
        name: 'collective-stepup-api',
        path: '/api/collectives/stepup',
        // This action verifies an ordinary Solid-OIDC bearer itself; do not
        // interpret a future Group-only credential as a general Solid login.
        authentication: false,
        authorization: false,
        bodyParsers: { json: true },
        cors: {
          origin: approvedBrowserOrigins(this.settings.origin, this.settings.allowedOriginsConfig),
          methods: ['POST', 'OPTIONS'],
          allowedHeaders: ['Authorization', 'DPoP', 'Idempotency-Key', 'Content-Type'],
          credentials: false
        },
        onBeforeCall(ctx, route, req) {
          ctx.meta.$stepupAuthorization = req.headers.authorization;
          ctx.meta.$stepupDpop = req.headers.dpop;
        },
        aliases: { 'POST /verify': 'collective-stepup-api.verify' }
      },
      toBottom: false
    });
  },

  actions: {
    verify: {
      params: {
        ticket: { type: 'string', min: 24, max: 4096 },
        response: { type: 'object', strict: false }
      },
      async handler(ctx) {
        if (!this.settings.enabled || !this.redis) deny('COLLECTIVE_STEPUP_DISABLED', 503);
        const origin = providerOrigin(this.settings.origin);
        const token = bearer(ctx.meta?.$stepupAuthorization);
        const claims = await ctx.call('jwk.verifyToken', { token });
        const { principal, app } = oidcClaims(claims, origin);
        // Check SAI BEFORE spending any one-time challenge.
        await assertLiveCollectiveConsent(ctx, {
          principal, app, operation: 'reserve',
          approvedApps: this.settings.approvedApps
        });

        // Bounded, atomically counted attempts across all provider replicas.
        // A missing Redis dependency must fail closed, never reset a limit.
        const rateIdentity = crypto.createHash('sha256')
          .update(JSON.stringify([principal, app])).digest('hex');
        const attempts = await this.redis.eval(
          "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n",
          1, this.settings.ratePrefix + ':' + rateIdentity, 60
        );
        if (!Number.isSafeInteger(Number(attempts)) ||
            Number(attempts) > this.settings.maxAttemptsPerMinute) {
          deny('COLLECTIVE_STEPUP_RATE_LIMITED', 429);
        }

        const proof = ctx.meta?.$stepupDpop;
        if (typeof proof !== 'string' || proof.length > 8192 ||
            !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(proof)) {
          deny('COLLECTIVE_STEPUP_DPOP_REQUIRED');
        }
        const verifiedProof = await ctx.call('oauth-dpop-nonce.verifyProof', {
          proofJwt: proof, htm: 'POST',
          htu: origin + '/api/collectives/stepup/verify',
          audience: app,
          expectedAth: crypto.createHash('sha256').update(token).digest('base64url')
        });
        const jkt = verifiedProof?.jkt;
        if (typeof jkt !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(jkt)) {
          deny('COLLECTIVE_STEPUP_DPOP_REQUIRED');
        }

        // Atomic SET NX prevents replay even for authenticators with a zero
        // counter. Consume *before* calling WebAuthn to prevent concurrent
        // counter races; a failed attempt requires requesting a fresh ticket.
        const ticketDigest = crypto.createHash('sha256')
          .update(ctx.params.ticket).digest('hex');
        const claimed = await this.redis.set(
          this.settings.ticketPrefix + ':' + ticketDigest, '1',
          'EX', this.settings.ticketTtlSeconds, 'NX'
        );
        if (claimed !== 'OK') deny('COLLECTIVE_STEPUP_REPLAY');
        // Reuse provider's actual WebAuthn validation and credential update,
        // without minting a general-purpose account token.
        const result = await ctx.call('passkeys-api.verifyAssertion', {
          ticket: ctx.params.ticket, response: ctx.params.response
        });
        if (!result || result.webId !== principal) deny('COLLECTIVE_STEPUP_USER_MISMATCH');
        // Revocation might occur while the authenticator validates; check
        // again before minting the short-lived purpose-bound credential.
        await assertLiveCollectiveConsent(ctx, {
          principal, app, operation: 'reserve', approvedApps: this.settings.approvedApps
        });
        const verifiedAt = Math.floor(Date.now() / 1000);
        const issued = await ctx.call('collective-stepup-credentials.mint', {
          principal, app, jkt, verifiedAt
        });
        ctx.meta.$responseHeaders = {
          ...(ctx.meta.$responseHeaders || {}),
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
          'X-Content-Type-Options': 'nosniff'
        };
        return issued;
      }
    }
  }
};
