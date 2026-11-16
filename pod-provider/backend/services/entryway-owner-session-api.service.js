const crypto = require('node:crypto');
const { calculateJwkThumbprint, importJWK, SignJWT } = require('jose');
const { MoleculerError } = require('moleculer').Errors;

const PURPOSE = 'paper.entryway.owner-session.v1';
const AUDIENCE = 'urn:paper:entryway:owner-session:v1';
const MAX_TOKEN_AGE_SECONDS = 300;

function deny(type, code = 401) {
  throw new MoleculerError(
    'A fresh Solid-OIDC owner session is required',
    code,
    type,
    { retryable: false }
  );
}

function canonicalHttps(value, { fragment = false } = {}) {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password ||
        url.search || (!fragment && url.hash) || url.href !== value) return null;
    return value;
  } catch {
    return null;
  }
}

function canonicalHttpsOrigin(value) {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.hostname && !url.username && !url.password &&
      !url.search && !url.hash && url.origin === value ? value : null;
  } catch {
    return null;
  }
}

function exactAudience(value, appClientId) {
  return Array.isArray(value) && value.length >= 2 && value.length <= 8 &&
    value.every(item => typeof item === 'string' && item.length > 0) &&
    new Set(value).size === value.length &&
    value.includes('solid') && value.includes(appClientId);
}

module.exports = {
  name: 'entryway-owner-session-api',
  dependencies: ['api', 'jwk', 'auth.account'],

  settings: {
    enabled: process.env.ENTRYWAY_OWNER_SESSION_PROOF_ENABLED === 'true',
    issuer: process.env.SEMAPPS_HOME_URL || '',
    audience: AUDIENCE,
    ttlSeconds: 120
  },

  created() {
    this.signingKey = null;
    this.keyId = null;
    this.publicJwks = null;
  },

  async started() {
    if (!this.settings.enabled) return;
    const issuer = canonicalHttpsOrigin(this.settings.issuer);
    if (!issuer) {
      throw new MoleculerError(
        'Entryway owner-session issuer must be a canonical HTTPS origin',
        503,
        'ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID',
        { retryable: false }
      );
    }
    const { privateJwk, publicJwk } = await this.broker.call('jwk.get');
    if (!privateJwk || privateJwk.alg !== 'ES256' || privateJwk.kty !== 'EC' ||
        privateJwk.crv !== 'P-256' || typeof privateJwk.d !== 'string' ||
        !publicJwk || publicJwk.kty !== 'EC' || publicJwk.crv !== 'P-256' ||
        typeof publicJwk.x !== 'string' || typeof publicJwk.y !== 'string' || publicJwk.d) {
      throw new MoleculerError(
        'Entryway owner-session signing key is unavailable',
        503,
        'ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID',
        { retryable: false }
      );
    }
    const [privateKeyId, publicKeyId] = await Promise.all([
      calculateJwkThumbprint(privateJwk),
      calculateJwkThumbprint(publicJwk)
    ]);
    if (privateKeyId !== publicKeyId) {
      throw new MoleculerError(
        'Entryway owner-session signing keys do not match',
        503,
        'ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID',
        { retryable: false }
      );
    }
    this.signingKey = await importJWK(privateJwk, 'ES256');
    this.keyId = publicKeyId;
    this.publicJwks = Object.freeze({
      keys: Object.freeze([Object.freeze({ ...publicJwk, alg: 'ES256', use: 'sig', kid: this.keyId })])
    });

    await this.broker.call('api.addRoute', {
      route: {
        name: 'entryway-owner-session-jwks',
        path: '/api/entryway-owner-session/jwks',
        authentication: false,
        authorization: false,
        aliases: {
          'GET /': 'entryway-owner-session-api.jwks'
        }
      },
      toBottom: false
    });

    await this.broker.call('api.addRoute', {
      route: {
        name: 'entryway-owner-session-api',
        path: '/api/entryway-owner-session',
        authentication: true,
        authorization: false,
        bodyParsers: { json: { strict: true } },
        aliases: {
          'POST /proof': 'entryway-owner-session-api.issue'
        }
      },
      toBottom: false
    });
  },

  stopped() {
    this.signingKey = null;
    this.keyId = null;
    this.publicJwks = null;
  },

  actions: {
    jwks: {
      handler() {
        if (!this.settings.enabled || !this.publicJwks) {
          deny('ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID', 503);
        }
        return this.publicJwks;
      }
    },
    issue: {
      params: {
        accountId: {
          type: 'string',
          pattern: /^acct_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        },
        username: { type: 'string', min: 2, max: 64, pattern: /^[a-z0-9][a-z0-9_-]+$/ },
        webId: { type: 'string', min: 8, max: 2048 },
        appClientId: { type: 'string', min: 8, max: 2048 }
      },
      async handler(ctx) {
        if (!this.settings.enabled || !this.signingKey ||
            process.env.APODS_SOLID_OIDC_DPOP_ENFORCE_ENABLED !== 'true' ||
            ctx.meta?.dpopVerified !== true) {
          deny('ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID', 503);
        }
        const webId = canonicalHttps(ctx.params.webId, { fragment: true });
        const appClientId = canonicalHttps(ctx.params.appClientId);
        const claims = ctx.meta?.tokenPayload;
        const now = Math.floor(Date.now() / 1000);
        if (!webId || !appClientId || !claims || claims.webid !== webId ||
            claims.sub !== webId || claims.azp !== appClientId ||
            claims.iss !== this.settings.issuer ||
            !exactAudience(claims.aud, appClientId) ||
            !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) ||
            claims.iat < now - MAX_TOKEN_AGE_SECONDS || claims.iat > now + 5 ||
            claims.exp <= now ||
            typeof claims.cnf?.jkt !== 'string' ||
            !/^[A-Za-z0-9_-]{43}$/u.test(claims.cnf.jkt)) {
          deny('ENTRYWAY_OWNER_SESSION_AUTH_INVALID');
        }
        const account = await ctx.call('auth.account.findByWebId', { webId });
        if (!account || account.disabled === true || account.username !== ctx.params.username) {
          deny('ENTRYWAY_OWNER_SESSION_ACCOUNT_INVALID', 403);
        }

        const ttl = Math.min(180, Math.max(30, Number(this.settings.ttlSeconds) || 120));
        const token = await new SignJWT({
          purpose: PURPOSE,
          account_id: ctx.params.accountId,
          username: ctx.params.username,
          webid: webId,
          app_client_id: appClientId
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: this.keyId })
          .setIssuer(this.settings.issuer)
          .setAudience(this.settings.audience)
          .setSubject(webId)
          .setJti(crypto.randomUUID())
          .setIssuedAt(now)
          .setExpirationTime(now + ttl)
          .sign(this.signingKey);
        return Object.freeze({ proof: token, expiresIn: ttl, tokenType: 'JWT' });
      }
    }
  }
};

module.exports._test = { AUDIENCE, PURPOSE, canonicalHttps, canonicalHttpsOrigin };
