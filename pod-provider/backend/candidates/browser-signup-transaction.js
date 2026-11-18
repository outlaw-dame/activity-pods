'use strict';

const crypto = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COOKIE = '__Host-paper-signup';

function refuse() {
  throw Object.assign(new Error('Signup transaction unavailable'), { retryable: false });
}
function gate() {
  if (
    process.env.NODE_ENV !== 'test' ||
    process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed' ||
    process.env.APODS_ACCOUNT_COORDINATOR_DISPOSABLE !== 'confirmed'
  )
    refuse();
}
function scope(settings, session, fingerprint) {
  gate();
  if (!/^[\w-]{43}$/u.test(session) || !/^[a-f0-9]{64}$/u.test(fingerprint)) refuse();
  return [crypto.createHash('sha256').update(session).digest(), ...settings, Buffer.from(fingerprint, 'hex')];
}
function makeBrowserSignupTransaction({ pool, encryptionKey, providerId, appClientId, browserOrigin, returnUri }) {
  gate();
  if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== 32 || !pool?.query) refuse();
  const settings = [providerId, appClientId, browserOrigin, returnUri];
  for (const value of settings) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || value.length > 2048) refuse();
  }
  if (new URL(browserOrigin).origin !== browserOrigin) refuse();
  const key = Buffer.from(encryptionKey);
  const aad = values => Buffer.from(JSON.stringify(values.map(v => (Buffer.isBuffer(v) ? v.toString('hex') : v))));
  async function bindVerified({ idempotencyKey, fingerprint, proof, expiresAt, setCookie }) {
    // Callable only by the trusted verifier after authenticating the browser
    // and the app transaction. The coordinator re-verifies the signed proof.
    if (
      !UUID.test(idempotencyKey) ||
      typeof proof !== 'string' ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u.test(proof) ||
      proof.length > 1400 ||
      typeof setCookie !== 'function'
    )
      refuse();
    const session = crypto.randomBytes(32).toString('base64url');
    const values = scope(settings, session, fingerprint);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad([...values, idempotencyKey]));
    const ciphertext = Buffer.concat([cipher.update(proof, 'utf8'), cipher.final()]);
    const encrypted = Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
    const result = await pool.query({
      text: 'SELECT paper_browser_signup.bind_verified($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS ok',
      values: [
        ...values.slice(0, 5),
        idempotencyKey,
        values[5],
        crypto.createHash('sha256').update(proof).digest(),
        encrypted,
        expiresAt
      ],
      query_timeout: 5000
    });
    if (result.rows[0]?.ok !== true) refuse();
    setCookie(COOKIE + '=' + session + '; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=120');
  }
  async function consume({ cookie, origin, fingerprint }) {
    if (origin !== browserOrigin || typeof cookie !== 'string' || cookie.length > 8192) refuse();
    const matches = cookie
      .split(';')
      .map(v => v.trim())
      .filter(v => v.startsWith(COOKIE + '='));
    if (matches.length !== 1) refuse();
    const values = scope(settings, matches[0].slice(COOKIE.length + 1), fingerprint);
    const result = await pool.query({
      text: 'SELECT * FROM paper_browser_signup.consume_verified($1,$2,$3,$4,$5,$6)',
      values,
      query_timeout: 5000
    });
    const encrypted = result.rows[0]?.proof;
    if (!Buffer.isBuffer(encrypted) || encrypted.length < 29) refuse();
    const cipher = crypto.createDecipheriv('aes-256-gcm', key, encrypted.subarray(0, 12));
    cipher.setAAD(aad([...values, result.rows[0].bound_key]));
    cipher.setAuthTag(encrypted.subarray(12, 28));
    return {
      idempotencyKey: result.rows[0].bound_key,
      challengeToken: Buffer.concat([cipher.update(encrypted.subarray(28)), cipher.final()]).toString('utf8')
    };
  }
  return Object.freeze({ bindVerified, consume });
}
module.exports = { makeBrowserSignupTransaction };
