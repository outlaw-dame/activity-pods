'use strict';

const crypto = require('node:crypto');
const api = require('../services/unified-account-api.service').methods;
const { fingerprint } = require('../services/utils/atproto-account-coordinated-signup');
const { MAX_SIGNUP_CHALLENGE_BYTES } = require('../services/utils/signup-challenge');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const purpose = 'activitypods:local-browser-signup-invitation:v1';

function refuse() {
  throw Object.assign(new Error('Local signup verification refused'), { retryable: false });
}
function gate(env) {
  if (
    env.NODE_ENV !== 'test' ||
    env.APODS_ACCOUNT_COORDINATOR_DISPOSABLE !== 'confirmed' ||
    env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed'
  )
    refuse();
}
function message(scope, username, email, key, issuedAt) {
  return Buffer.from(
    JSON.stringify([
      purpose,
      scope.providerId,
      scope.appClientId,
      scope.browserOrigin,
      scope.returnUri,
      username,
      email,
      key,
      issuedAt
    ])
  );
}
function challengeBytes(scope, username, email, idempotencyKey, issuedAtMs, requestFingerprint, nonce) {
  const bytes = Buffer.from(JSON.stringify({
    version: 1, purpose: 'activitypods:new-account:v1', appClientId: scope.appClientId,
    username, email, origin: scope.browserOrigin, redirectUri: scope.returnUri,
    idempotencyKey, requestFingerprint, issuedAtMs, expiresAtMs: issuedAtMs + 120000, nonce
  }));
  if (bytes.length > MAX_SIGNUP_CHALLENGE_BYTES) refuse();
  return bytes;
}
// Operator-side only. The independent operator authorizes this disposable
// identity out of band. The provider receives only the public invitation key.
function issueLocalInvitation({ privateKey, scope, username, email }) {
  gate(process.env);
  if (privateKey?.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') refuse();
  if (typeof username !== 'string' || !/^[a-z][a-z0-9_-]{1,31}$/u.test(username) ||
      typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(email)) refuse();
  const key = crypto.randomUUID(),
    issuedAt = Date.now();
  // Fingerprints and UUID nonces have fixed encoded widths. Measure the exact UTF-8 payload.
  challengeBytes(scope, username, email, key, issuedAt, '0'.repeat(64), key);
  const signature = crypto.sign(null, message(scope, username, email, key, issuedAt), privateKey);
  return [key, issuedAt, signature.toString('base64url')].join('.');
}
function makeLocalSignupVerifier({ publicKey, scope, transaction, env = process.env }) {
  gate(env);
  if (publicKey?.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519' || !transaction?.bindVerified) refuse();
  const configured = Object.freeze({ ...scope });
  const secret = env.APODS_ACCOUNT_VERIFICATION_HMAC_KEY;
  if (typeof secret !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(secret)) refuse();
  const signingKey = Buffer.from(secret, 'base64url');
  if (signingKey.length !== 32 || signingKey.toString('base64url') !== secret) refuse();
  return async function verify({ origin, invitation, account, setCookie }) {
    gate(env);
    if (
      origin !== configured.browserOrigin ||
      typeof invitation !== 'string' ||
      invitation.length !== 137 ||
      !account ||
      Object.keys(account).some(k => !['username', 'email', 'password', 'profile'].includes(k)) ||
      typeof account.username !== 'string' ||
      !/^[a-z][a-z0-9_-]{1,31}$/.test(account.username) ||
      typeof account.email !== 'string' ||
      account.email.length > 254 ||
      account.email !== account.email.trim() ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(account.email) ||
      typeof account.password !== 'string' ||
      account.password.length < 8 ||
      account.password.length > 1024 ||
      !account.profile ||
      Object.keys(account.profile).length !== 1 ||
      account.profile.displayName !== account.username
    )
      refuse();
    const parts = invitation.split('.');
    if (
      parts.length !== 3 ||
      !UUID.test(parts[0]) ||
      !/^\d{13}$/.test(parts[1]) ||
      !/^[A-Za-z0-9_-]{86}$/.test(parts[2])
    )
      refuse();
    const [idempotencyKey] = parts,
      issuedAtMs = Number(parts[1]),
      expiresAtMs = issuedAtMs + 120000;
    const now = Date.now();
    const signature = Buffer.from(parts[2], 'base64url');
    if (
      issuedAtMs > now ||
      now >= expiresAtMs ||
      signature.toString('base64url') !== parts[2] ||
      !crypto.verify(
        null,
        message(configured, account.username, account.email, idempotencyKey, issuedAtMs),
        publicKey,
        signature
      )
    )
      refuse();
    const { appClientId, returnUri: redirectUri } = configured;
    const accountParams = api.normalizeAccountCreateParams.call(api, account);
    const requestFingerprint = fingerprint({
      api,
      appClientId,
      redirectUri,
      accountParams,
      protocols: api.requestedProtocolsFromAccountParams.call(api, accountParams),
      env
    });
    const data = challengeBytes(configured, account.username, account.email, idempotencyKey,
      issuedAtMs, requestFingerprint, crypto.randomUUID()).toString('base64url');
    const mac = crypto
      .createHmac('sha256', signingKey)
      .update('activitypods:durable-user-verification:v1\0')
      .update(data)
      .digest('base64url');
    await transaction.bindVerified({
      idempotencyKey,
      fingerprint: requestFingerprint,
      proof: data + '.' + mac,
      expiresAt: new Date(expiresAtMs),
      setCookie
    });
  };
}
module.exports = { issueLocalInvitation, makeLocalSignupVerifier };
