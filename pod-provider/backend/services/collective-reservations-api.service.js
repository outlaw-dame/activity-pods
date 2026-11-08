'use strict';

/**
 * Provider-mediated, default-off Group reservation ingress.
 *
 * The app never receives the provider's HMAC operation grant and cannot choose
 * a user WebID or app actor URI in the request body. Both are extracted from a
 * reverified, provider-issued Solid-OIDC JWT and checked against the gateway's
 * authenticated identity projection. The reservation service ALSO checks live
 * SAI app consent and provider allowlisting before writing state.
 *
 * This endpoint reserves an INACTIVE identity only: no Group actor, keys or DID.
 */
const crypto = require('node:crypto');
const { MoleculerError } = require('moleculer').Errors;
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
  dependencies: ['api', 'jwk', 'collective-reservations'],
  settings: {
    enabled: process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_API_ENABLED === 'true',
    providerOrigin: process.env.SEMAPPS_HOME_URL || '',
    grantSecret: process.env.PROVIDER_COLLECTIVES_GRANT_SECRET || ''
  },

  async started() {
    // Registration is feature-gated as well as each action; no public route
    // exists unless the operator explicitly enables both controls.
    if (!this.settings.enabled) return;
    await this.broker.call('api.addRoute', {
      route: {
        name: 'collective-reservations-api',
        path: '/api/collectives',
        authentication: true,
        authorization: true,
        bodyParsers: { json: true },
        onBeforeCall(ctx, route, req) {
          ctx.meta.$collectivesAuthHeader = req.headers.authorization;
          ctx.meta.$collectivesIdempotencyKey = req.headers['idempotency-key'];
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
            !/^Bearer [A-Za-z0-9._~-]+$/u.test(header)) {
          fail('COLLECTIVE_AUTHENTICATION_REQUIRED', 401);
        }
        if (typeof idempotencyKey !== 'string' ||
            !/^[A-Za-z0-9_-]{24,128}$/u.test(idempotencyKey)) {
          fail('COLLECTIVE_INVALID_IDEMPOTENCY', 400);
        }

        // Independent verification prevents caller-forged ctx.meta from acting
        // as proof of a signed user+application identity.
        const verified = await ctx.call('jwk.verifyToken', { token: header.slice(7) });
        if (!verified || typeof verified.azp !== 'string' ||
            typeof verified.webid !== 'string' ||
            verified.azp !== ctx.meta?.webId ||
            verified.webid !== ctx.meta?.impersonatedUser ||
            !matchAudience(verified.aud, verified.azp) ||
            ![expectedIssuer(this.settings.providerOrigin), expectedIssuer(this.settings.providerOrigin) + '/']
              .includes(verified.iss) ||
            ctx.meta?.tokenPayload?.azp !== verified.azp ||
            ctx.meta?.tokenPayload?.webid !== verified.webid) {
          fail('COLLECTIVE_AUTHENTICATION_REQUIRED', 401);
        }
        const principal = verified.webid;
        const app = verified.azp;
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
