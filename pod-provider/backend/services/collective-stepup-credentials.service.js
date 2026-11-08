'use strict';

/*
 * Dedicated, provider-scoped, short-lived Group reservation credentials.
 * Deliberately NOT a Solid-OIDC ID/access token. The HMAC key is different
 * from the provider's general JWK and ordinary auth.jwt key, preventing these
 * restricted credentials from authenticating to arbitrary Solid endpoints.
 *
 * The caller is responsible for independently verifying a *fresh WebAuthn
 * assertion* for the same WebID, and for current SAI consent, before minting.
 */
const crypto = require('node:crypto');
const { SignJWT, jwtVerify } = require('jose');
const { MoleculerError } = require('moleculer').Errors;

const PURPOSE = 'apods:collective-reservation-stepup:v1';
const LIFETIME_SECONDS = 300;
const JKT = /^[A-Za-z0-9_-]{43}$/u;

function deny(type, status = 401) {
  throw new MoleculerError(type, status, type);
}
function secretKey(secret) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) {
    deny('COLLECTIVE_STEPUP_DISABLED', 503);
  }
  return Buffer.from(secret, 'utf8');
}
function issuerOrigin(value) {
  if (typeof value !== 'string') deny('COLLECTIVE_STEPUP_DISABLED', 503);
  let url;
  try { url = new URL(value); } catch { deny('COLLECTIVE_STEPUP_DISABLED', 503); }
  if (url.protocol !== 'https:' || !url.hostname || url.pathname !== '/' ||
      url.search || url.hash || url.username || url.password ||
      url.origin !== value.replace(/\/$/u, '')) deny('COLLECTIVE_STEPUP_DISABLED', 503);
  return url.origin;
}
function validUri(input, fragment = false) {
  if (typeof input !== 'string' || input.length > 2048 ||
      /[\u0000-\u0020\u007f\\]/u.test(input)) return false;
  try {
    const uri = new URL(input);
    return uri.protocol === 'https:' && !uri.username && !uri.password &&
      uri.href === input && !uri.search && (fragment || !uri.hash);
  } catch {
    return false;
  }
}

module.exports = {
  name: 'collective-stepup-credentials',
  settings: {
    enabled: process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_STEPUP_ENABLED === 'true',
    secret: process.env.PROVIDER_COLLECTIVES_STEPUP_SECRET || '',
    issuer: process.env.SEMAPPS_HOME_URL || ''
  },
  actions: {
    mint: {
      params: { principal: 'string', app: 'string', jkt: 'string', verifiedAt: 'number|integer' },
      async handler(ctx) {
        if (!this.settings.enabled) deny('COLLECTIVE_STEPUP_DISABLED', 503);
        const { principal, app, jkt, verifiedAt } = ctx.params;
        const now = Math.floor(Date.now() / 1000);
        if (!validUri(principal, true) || !validUri(app) || !JKT.test(jkt) ||
            !Number.isSafeInteger(verifiedAt) || verifiedAt > now + 2 ||
            now - verifiedAt > 30) deny('COLLECTIVE_STEPUP_INVALID');
        const issuer = issuerOrigin(this.settings.issuer);
        const token = await new SignJWT({
          purpose: PURPOSE, operation: 'reserve',
          webid: principal, azp: app, auth_time: verifiedAt,
          amr: ['webauthn'], cnf: { jkt }
        }).setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
          .setIssuer(issuer).setSubject(principal).setAudience(app)
          .setIssuedAt(now).setExpirationTime(now + LIFETIME_SECONDS)
          .setJti(crypto.randomUUID())
          .sign(secretKey(this.settings.secret));
        return { token, tokenType: 'DPoP', expiresIn: LIFETIME_SECONDS };
      }
    },
    verify: {
      params: { token: 'string' },
      async handler(ctx) {
        if (!this.settings.enabled) deny('COLLECTIVE_STEPUP_DISABLED', 503);
        const issuer = issuerOrigin(this.settings.issuer);
        let payload;
        try {
          ({ payload } = await jwtVerify(ctx.params.token, secretKey(this.settings.secret), {
            issuer, algorithms: ['HS256'], maxTokenAge: LIFETIME_SECONDS + 's',
            clockTolerance: 5
          }));
        } catch {
          deny('COLLECTIVE_STEPUP_INVALID');
        }
        const now = Math.floor(Date.now() / 1000);
        if (payload.purpose !== PURPOSE || payload.operation !== 'reserve' ||
            !validUri(payload.sub, true) || payload.webid !== payload.sub ||
            !validUri(payload.azp) || payload.aud !== payload.azp ||
            !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) ||
            payload.exp - payload.iat !== LIFETIME_SECONDS ||
            !Number.isSafeInteger(payload.auth_time) ||
            now - payload.auth_time > LIFETIME_SECONDS || payload.auth_time > now + 5 ||
            !Array.isArray(payload.amr) || !payload.amr.includes('webauthn') ||
            !JKT.test(payload.cnf?.jkt || '') || typeof payload.jti !== 'string') {
          deny('COLLECTIVE_STEPUP_INVALID');
        }
        return { principal: payload.sub, app: payload.azp, jkt: payload.cnf.jkt,
          authTime: payload.auth_time };
      }
    }
  }
};
