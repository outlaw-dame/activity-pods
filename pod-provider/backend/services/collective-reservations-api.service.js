'use strict';

/**
 * Provider-mediated, default-off Group reservation ingress.
 *
 * The app never receives the provider's HMAC operation grant and cannot choose
 * a user WebID or app actor URI in the request body. Both are extracted from a
 * dedicated provider-signed, WebAuthn-verified, Group-only credential.
 * Ordinary Solid-OIDC ID tokens cannot authorize this endpoint. The reservation service ALSO checks live
 * SAI app consent and provider allowlisting before writing state.
 *
 * This endpoint reserves an INACTIVE identity only: no Group actor, keys or DID.
 */
const crypto = require('node:crypto');
const { MoleculerError } = require('moleculer').Errors;
const { approvedBrowserOrigins } = require('./utils/collective-endpoint-policy');
const { reserveFingerprint } = require('./utils/collective-grant-claims');

const PURPOSE = 'provider.collective.reservation.v1';
function fail(code, status = 403) {
  throw new MoleculerError(code, status, code);
}
function matchAudience(aud, clientId) {
  return typeof aud === 'string'
    ? aud === clientId
    : Array.isArray(aud) && aud.includes(clientId);
}
function expectedIssuer(origin) {
  if (typeof origin !== 'string') fail('COLLECTIVE_API_DISABLED', 503);
  let url;
  try { url = new URL(origin); } catch { fail('COLLECTIVE_API_DISABLED', 503); }
  if (url.protocol !== 'https:' || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash ||
      url.origin !== origin.replace(/\/$/u, '')) fail('COLLECTIVE_API_DISABLED', 503);
  return url.origin;
}

module.exports = {
  name: 'collective-reservations-api',
  dependencies: ['api', 'collective-stepup-credentials', 'collective-reservations', 'oauth-dpop-nonce'],
  settings: {
    enabled: process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_API_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_STEPUP_ENABLED === 'true',
    providerOrigin: process.env.SEMAPPS_HOME_URL || '',
    grantSecret: process.env.PROVIDER_COLLECTIVES_GRANT_SECRET || '',
    allowedOriginsConfig: process.env.PROVIDER_COLLECTIVES_ALLOWED_ORIGINS || ''
  },

  async started() {
    // Registration is feature-gated as well as each action; no public route
    // exists unless the operator explicitly enables both controls.
    if (!this.settings.enabled) return;
    await this.broker.call('api.addRoute', {
      route: {
        name: 'collective-reservations-api',
        path: '/api/collectives',
        // Independently verify the Group-only credential; the regular
        // Solid gateway must not interpret it as a general Solid identity.
        authentication: false,
        authorization: false,
        bodyParsers: { json: true },
        cors: {
          origin: approvedBrowserOrigins(this.settings.providerOrigin, this.settings.allowedOriginsConfig),
          methods: ['POST', 'OPTIONS'],
          allowedHeaders: ['Authorization', 'DPoP', 'Idempotency-Key', 'Content-Type'],
          credentials: false
        },
        onBeforeCall(ctx, route, req) {
          ctx.meta.$collectivesAuthHeader = req.headers.authorization;
          ctx.meta.$collectivesIdempotencyKey = req.headers['idempotency-key'];
          ctx.meta.$collectivesDpopProof = req.headers.dpop;
        },
        aliases: {
          'POST /reserve': 'collective-reservations-api.reserve'
        }
      },
      toBottom: false
    });
  },

  actions: {
    reserve: {
      params: { displayName: { type: 'string', min: 1 } },
      async handler(ctx) {
        if (!this.settings.enabled || !this.settings.grantSecret ||
            Buffer.byteLength(this.settings.grantSecret) < 32) {
          fail('COLLECTIVE_API_DISABLED', 503);
        }
        const header = ctx.meta?.$collectivesAuthHeader;
        const idempotencyKey = ctx.meta?.$collectivesIdempotencyKey;
        if (typeof header !== 'string' || header.length > 8192 ||
            !/^DPoP [A-Za-z0-9._~-]+$/u.test(header)) {
          fail('COLLECTIVE_AUTHENTICATION_REQUIRED', 401);
        }
        if (typeof idempotencyKey !== 'string' ||
            !/^[A-Za-z0-9_-]{24,128}$/u.test(idempotencyKey)) {
          fail('COLLECTIVE_INVALID_IDEMPOTENCY', 400);
        }

        // Only the purpose-limited step-up signing key validates this token.
        // A year-long ordinary Solid ID token or a generic passkey login token
        // cannot authenticate to this high-trust endpoint.
        const token = header.slice(5);
        const identity = await ctx.call('collective-stepup-credentials.verify', { token });
        if (!identity || typeof identity.principal !== 'string' ||
            typeof identity.app !== 'string' || typeof identity.jkt !== 'string') {
          fail('COLLECTIVE_AUTHENTICATION_REQUIRED', 401);
        }
        const dpop = ctx.meta?.$collectivesDpopProof;
        if (typeof dpop !== 'string' || dpop.length > 8192 ||
            !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(dpop)) {
          fail('COLLECTIVE_DPOP_REQUIRED', 401);
        }
        const issuerOrigin = expectedIssuer(this.settings.providerOrigin);
        const verifiedProof = await ctx.call('oauth-dpop-nonce.verifyProof', {
          proofJwt: dpop, htm: 'POST',
          htu: issuerOrigin + '/api/collectives/reserve',
          audience: identity.app, expectedJkt: identity.jkt,
          expectedAth: crypto.createHash('sha256').update(token).digest('base64url')
        });
        if (!verifiedProof || verifiedProof.jkt !== identity.jkt) {
          fail('COLLECTIVE_DPOP_REQUIRED', 401);
        }
        const principal = identity.principal;
        const app = identity.app;
        const requestHash = reserveFingerprint(principal, app, idempotencyKey, ctx.params.displayName);
        const issuedAt = Date.now();
        const expiresAt = issuedAt + 60000;
        const fields = [PURPOSE, principal, app, 'reserve', requestHash, issuedAt, expiresAt];
        const grant = { purpose: PURPOSE, principal, app, operation: 'reserve', requestHash,
          issuedAt, expiresAt,
          mac: crypto.createHmac('sha256', this.settings.grantSecret)
            .update(JSON.stringify(fields)).digest('hex') };

        const outcome = await ctx.call('collective-reservations.reserve', {
          principal, app, idempotencyKey, displayName: ctx.params.displayName, grant
        });
        ctx.meta.$statusCode = 202;
        ctx.meta.$responseHeaders = {
          ...(ctx.meta.$responseHeaders || {}),
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff'
        };
        return outcome;
      }
    }
  }
};
