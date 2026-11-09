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
const { CONSENT_BRIDGE_RELEASED } = require('./utils/collective-release-gate');
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
function makeProviderGrant(secret, principal, app, operation, requestHash) {
  const issuedAt = Date.now();
  const expiresAt = issuedAt + 60000;
  const fields = [PURPOSE, principal, app, operation, requestHash, issuedAt, expiresAt];
  return {
    purpose: PURPOSE, principal, app, operation, requestHash, issuedAt, expiresAt,
    mac: crypto.createHmac('sha256', secret).update(JSON.stringify(fields)).digest('hex')
  };
}

async function authenticatedPrincipal(ctx, providerOrigin) {
  const authorization = ctx.meta?.$collectivesAuthHeader;
  // Remove the secret before calling any downstream action, including the JWK
  // service. JWT bytes are supplied solely as the explicit verifyToken input.
  if (ctx.meta) delete ctx.meta.$collectivesAuthHeader;
  if (typeof authorization !== 'string' || authorization.length > 8192 ||
      !/^Bearer [A-Za-z0-9._~-]+$/u.test(authorization)) {
    fail('COLLECTIVE_AUTHENTICATION_REQUIRED', 401);
  }
  const signed = await ctx.call('jwk.verifyToken', { token: authorization.slice(7) });
  const issuer = expectedIssuer(providerOrigin);
  if (!signed || typeof signed.webid !== 'string' ||
      typeof signed.azp !== 'string' || signed.sub !== signed.webid ||
      ![issuer, issuer + '/'].includes(signed.iss) ||
      !matchAudience(signed.aud, signed.azp) ||
      signed.azp !== ctx.meta?.webId ||
      signed.webid !== ctx.meta?.impersonatedUser ||
      ctx.meta?.tokenPayload?.azp !== signed.azp ||
      ctx.meta?.tokenPayload?.webid !== signed.webid ||
      ctx.meta?.tokenPayload?.sub !== signed.sub) {
    fail('COLLECTIVE_AUTHENTICATION_REQUIRED', 401);
  }
  return { principal: signed.webid, app: signed.azp };
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
    enabled: CONSENT_BRIDGE_RELEASED &&
      process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true' &&
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
          methods: ['GET', 'POST', 'OPTIONS'],
          allowedHeaders: ['Authorization', 'Idempotency-Key', 'Content-Type'],
          credentials: false
        },
        onBeforeCall(ctx, route, req) {
          ctx.meta.$collectivesAuthHeader = req.headers.authorization;
          ctx.meta.$collectivesIdempotencyKey = req.headers['idempotency-key'];
        },
        aliases: {
          'POST /reserve': 'collective-reservations-api.reserve',
          'GET /:canonicalGroupId': 'collective-reservations-api.get'
        }
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
        const idempotencyKey = ctx.meta?.$collectivesIdempotencyKey;
        if (typeof idempotencyKey !== 'string' ||
            !/^[A-Za-z0-9_-]{24,128}$/u.test(idempotencyKey)) {
          // Invalid parameters require no cryptographic work or downstream
          // calls, and the raw bearer must not linger in request metadata.
          if (ctx.meta) delete ctx.meta.$collectivesAuthHeader;
          fail('COLLECTIVE_INVALID_IDEMPOTENCY', 400);
        }
        const { principal, app } = await authenticatedPrincipal(ctx, this.settings.providerOrigin);
        const requestHash = reserveFingerprint(
          principal, app, idempotencyKey, ctx.params.displayName
        );
        const grant = makeProviderGrant(
          this.settings.grantSecret, principal, app, 'reserve', requestHash
        );

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
    },
    get: {
      params: {
        canonicalGroupId: { type: 'string', pattern: '^cg_[a-f0-9]{32}$' }
      },
      async handler(ctx) {
        if (!this.settings.enabled || typeof this.settings.grantSecret !== 'string' ||
            Buffer.byteLength(this.settings.grantSecret) < 32) {
          fail('COLLECTIVE_API_DISABLED', 503);
        }
        const { principal, app } = await authenticatedPrincipal(ctx, this.settings.providerOrigin);
        const canonicalGroupId = ctx.params.canonicalGroupId;
        // Validate at the service boundary too: internal Moleculer calls can
        // bypass route-level FastestValidator declarations.
        if (typeof canonicalGroupId !== 'string' ||
            !/^cg_[a-f0-9]{32}$/u.test(canonicalGroupId)) {
          fail('COLLECTIVE_INVALID_ID', 400);
        }
        const grant = makeProviderGrant(
          this.settings.grantSecret, principal, app, 'read', canonicalGroupId
        );
        const outcome = await ctx.call('collective-reservations.get', {
          principal, app, canonicalGroupId, grant
        });
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
