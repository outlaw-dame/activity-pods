'use strict';

const crypto = require('node:crypto');
const {
  decodeProtectedHeader, importJWK, jwtVerify, calculateJwkThumbprint
} = require('jose');

const JTI = /^[\x21-\x7e]{16,256}$/u;
const JKT = /^[A-Za-z0-9_-]{43}$/u;

function deny() {
  const e = new Error('Invalid or replayed DPoP proof');
  e.code = 'SOLID_DPOP_INVALID';
  throw e;
}

function publicKey(header) {
  if (header?.typ !== 'dpop+jwt' || header?.alg !== 'ES256') deny();
  const jwk = header.jwk;
  // Keep the supported DPoP key profile intentionally narrow until client
  // interoperability tests cover other algorithms.
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' ||
      typeof jwk.x !== 'string' || typeof jwk.y !== 'string' ||
      !JKT.test(jwk.x) || !JKT.test(jwk.y) ||
      ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'].some(k => k in jwk)) deny();
  return jwk;
}
function expectedTarget(method, targetUrl) {
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method)) deny();
  let u;
  try { u = new URL(targetUrl); } catch { deny(); }
  if (u.protocol !== 'https:' || u.username || u.password || !u.hostname ||
      !u.pathname || u.href !== targetUrl || targetUrl.length > 4096) deny();
  return u.origin + u.pathname;
}
function sha256base64(value) {
  return crypto.createHash('sha256').update(value, 'ascii').digest('base64url');
}

/**
 * Validate a signed Solid-OIDC DPoP request proof.
 *
 * reserveReplay must be an atomic, shared-store SET-NX with a short TTL.
 * A process-local Set is not sufficient when Moleculer has multiple workers.
 * The token payload must already have passed issuer signature verification.
 */
async function verifySolidDpop({
  proof, idToken, verifiedToken, method, targetUrl,
  reserveReplay, now = Date.now, expectedIssuer, expectedNonce = null
} = {}) {
  if (typeof proof !== 'string' || proof.length < 50 || proof.length > 8192 ||
      typeof idToken !== 'string' || !idToken || idToken.length > 8192 ||
      typeof reserveReplay !== 'function' ||
      typeof expectedIssuer !== 'string' || !expectedIssuer) deny();

  const htu = expectedTarget(method, targetUrl);
  const time = Math.floor(now() / 1000);
  if (!verifiedToken || verifiedToken.iss !== expectedIssuer ||
      typeof verifiedToken.webid !== 'string' ||
      typeof verifiedToken.azp !== 'string' ||
      !Array.isArray(verifiedToken.aud) ||
      !verifiedToken.aud.includes(verifiedToken.azp) ||
      !verifiedToken.aud.includes('solid') ||
      !JKT.test(verifiedToken?.cnf?.jkt || '') ||
      !Number.isInteger(verifiedToken.iat) ||
      !Number.isInteger(verifiedToken.exp) ||
      verifiedToken.exp <= time) deny();

  let header, verified;
  try {
    header = decodeProtectedHeader(proof);
    const jwk = publicKey(header);
    const key = await importJWK(jwk, 'ES256');
    verified = await jwtVerify(proof, key, {
      algorithms: ['ES256'], currentDate: new Date(now())
    });
  } catch {
    deny();
  }
  const claims = verified.payload;
  const target = claims?.htu;
  let actual;
  try {
    const u = new URL(target);
    actual = u.origin + u.pathname;
    if (u.href !== target || u.search || u.hash) deny();
  } catch { deny(); }

  if (actual !== htu || claims.htm !== method ||
      !Number.isSafeInteger(claims.iat) ||
      claims.iat < time - 120 || claims.iat > time + 5 ||
      typeof claims.jti !== 'string' || !JTI.test(claims.jti) ||
      claims.ath !== sha256base64(idToken) ||
      (expectedNonce !== null && claims.nonce !== expectedNonce)) {
    deny();
  }

  let thumbprint;
  try { thumbprint = await calculateJwkThumbprint(header.jwk); }
  catch { deny(); }
  if (thumbprint !== verifiedToken.cnf.jkt) deny();

  // Hash the replay key rather than storing raw client-supplied identifiers.
  // The verification is complete before writing the key. Deny if Redis is
  // unavailable or has already seen this proof within the acceptance window.
  const replayKey = crypto.createHash('sha256')
    .update(JSON.stringify([thumbprint, claims.jti, claims.htm, htu]))
    .digest('hex');
  try {
    const reserved = await reserveReplay(replayKey, 130);
    if (reserved !== true) deny();
  } catch { deny(); }
  return Object.freeze({
    webId: verifiedToken.webid, appUri: verifiedToken.azp,
    keyThumbprint: thumbprint
  });
}
module.exports = { verifySolidDpop };
