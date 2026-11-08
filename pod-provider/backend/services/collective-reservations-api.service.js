'use strict';

/**
 * Provider-mediated G1 reservation, built on the EXISTING Solid-OIDC gateway.
 *
 * The provider authenticates the Solid client token and resolves signed app
 * (azp) and person (webid). This action independently re-verifies the same
 * token and matches the gateway's identity projection. The authoritative
 * reservation service rechecks CURRENT SAI permissions before writing.
 *
 * No new login ceremony, passkeys, Group-only token issuer, or AP/AT issuance.
 * The route remains disabled by default pending live-provider integration and
 * revoke-versus-write transaction fencing.
 */
const crypto = require('node:crypto');
const { MoleculerError } = require('moleculer').Errors;
const { approvedBrowserOrigins, canonicalOrigin } = require('./utils/collective-endpoint-policy');
const { reserveFingerprint } = require('./utils/collective-grant-claims');

const PURPOSE = 'provider.collective.reservation.v1';

function fail(code, status = 403) {
  throw new MoleculerError(code, status, code);
}
function matchAudience(audience, clientId) {
  return typeof audience === 'string' ? audience === clientId
    : Array.isArray(audience) && audience.includes(clientId);
}
function expectedIssuer(origin) {
  const issuer = canonicalOrigin(origin);
  if (!issuer) fail('COLLECTIVE_API_DISABLED', 503);
  return issuer;
}

module.exports = {
  name: 'collective-reservations-api',
  dependencies: ['api', 'jwk', 'collective-reservations'],
  settings: {
    enabled: process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_API_ENABLED === 'true',
    providerOrigin: process.env.SEMAPPS_HOME_URL || '',
    grantSecret: process.env.PROVIDER_COLLECTIVES_GRANT_SECRET || '',
    allowedOriginsConfig: process.env.PROVIDER_COLLECTIVES_ALLOWED_ORIGINS || ''
  },

  async started() {
    if (!this.settings.enabled) return;
    await this.broker.call('api.addRoute', {
      route: {
        name: 'collective-reservations-api',
        path: '/api/collectives',
        // Reuse the provider's current Solid-OIDC authentication, not a new
        // feature-specific credential scheme or passkey flow.
        authentication: true,
        authorization: true,
        bodyParsers: { json: true },
        cors: {
          origin: approvedBrowserOrigins(this.settings.providerOrigin, this.settings.allowedOriginsConfig),
          methods: ['POST', 'OPTIONS'],
          allowedHeaders: ['Authorization', 'Idempotency-Key', 'Content-Type'],
          credentials: false
        },
        onBeforeCall(ctx, route, req) {
          ctx.meta.$collectivesAuthHeader = req.headers.authorization;
          ctx.meta.$collectivesIdempotencyKey = req.headers['idempotency-key'];
        },
        aliases: { 'POST /reserve': 'collective-reservations-api.reserve' }
      },
      toBottom: false
    });
  },

  actions: {
    reserve: {
      params: { displayName: { type: 'string', min: 1 } },
      async handler(ctx) {
        if (!this.settings.enabled || typeof this.settings.grantSecret !== 'string' ||
            Buffer.byteLength(this.settings.grantSecret) < 32) {
          fail('COLLECTIVE_API_DISABLED', 503);
        }
        const authorization = ctx.meta?.$collectivesAuthHeader;
        const idempotencyKey = ctx.meta?.$collectivesIdempotencyKey;
        // Do not propagate the raw bearer token via ctx.meta to unrelated
        // provider services during SAI checks or the Fuseki reservation write.
        if (ctx.meta) delete ctx.meta.$collectivesAuthHeader;
        if (typeof authorization !== 'string' || authorization.length > 8192 ||
            !/^Bearer [A-Za-z0-9._~-]+$/u.test(authorization)) {
          fail('COLLECTIVE_AUTHENTICATION_REQUIRED', 401);
        }
        if (typeof idempotencyKey !== 'string' ||
            !/^[A-Za-z0-9_-]{24,128}$/u.test(idempotencyKey)) {
          fail('COLLECTIVE_INVALID_IDEMPOTENCY', 400);
        }

        // The gateway already authenticated the Solid ID token; verify again
        // to keep direct service calls and forged ctx.meta fail-closed.
        const token = authorization.slice(7);
        const signed = await ctx.call('jwk.verifyToken', { token });
        const issuer = expectedIssuer(this.settings.providerOrigin);
        if (!signed || typeof signed.webid !== 'string' ||
            typeof signed.azp !== 'string' ||
            signed.sub !== signed.webid ||
            ![issuer, issuer + '/'].includes(signed.iss) ||
            !matchAudience(signed.aud, signed.azp) ||
            signed.azp !== ctx.meta?.webId ||
            signed.webid !== ctx.meta?.impersonatedUser ||
            ctx.meta?.tokenPayload?.azp !== signed.azp ||
            ctx.meta?.tokenPayload?.webid !== signed.webid ||
            ctx.meta?.tokenPayload?.sub !== signed.sub) {
          fail('COLLECTIVE_AUTHENTICATION_REQUIRED', 401);
        }

        const principal = signed.webid;
        const app = signed.azp;
        const requestHash = reserveFingerprint(
          principal, app, idempotencyKey, ctx.params.displayName
        );
        const issuedAt = Date.now();
        const expiresAt = issuedAt + 60000;
        const fields = [PURPOSE, principal, app, 'reserve', requestHash, issuedAt, expiresAt];
        const grant = {
          purpose: PURPOSE, principal, app, operation: 'reserve', requestHash,
          issuedAt, expiresAt,
          mac: crypto.createHmac('sha256', this.settings.grantSecret)
            .update(JSON.stringify(fields)).digest('hex')
        };

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
