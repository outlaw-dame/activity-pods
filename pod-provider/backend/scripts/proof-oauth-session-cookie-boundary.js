'use strict';
// Isolated security regression: OAuth session cookies cannot forge owner
// identity with an absent production secret or crash HTTP handlers on
// malformed attacker-controlled cookie input.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const schema = require('../services/oauth/oauth-api.service');

const service = {
  settings: { ...schema.settings,
    sessionSecret: crypto.randomBytes(32).toString('hex'),
    sessionCookieName: 'oauth_session',
    sessionTtlSec: 3600,
    issuer: 'https://provider.paper.example.org'
  },
  ...schema.methods
};
function fromCookie(value) {
  return { meta: { $headers: { cookie: 'oauth_session=' + value } } };
}
const webId = 'https://provider.paper.example.org/alice';
const token = service.buildSessionToken(webId);
const good = service.getSession(fromCookie(encodeURIComponent(token)));
assert.equal(good.webId, webId);
assert.ok(good.exp > Date.now() / 1000);

for (const wrong of [
  'x',
  token.replace(/\.[^.]+$/u, '.x'),
  token + '.extra',
  token.split('.')[0] + '.' + '!'.repeat(43),
  '',
  'A'.repeat(4097)
]) {
  assert.equal(service.getSession(fromCookie(encodeURIComponent(wrong))), null,
    'Bad session cookie must be rejected without a thrown exception');
}
assert.equal(service.getSession(fromCookie('%ZZ')), null);
assert.equal(service.getSession(fromCookie('%E0%A4%A')), null);
const mixed = { meta: { $headers: {
  cookie: 'unrelated=%ZZ; oauth_session=' + encodeURIComponent(token)
} } };
assert.equal(service.getSession(mixed).webId, webId,
  'Malformed unrelated cookies must not prevent a valid session');
const map = service.parseCookies({ meta: { $headers: {
  cookie: '__proto__=pollution; constructor=spoofed'
} } });
assert.equal(Object.getPrototypeOf(map), null);

const before = process.env.NODE_ENV;
try {
  process.env.NODE_ENV = 'production';
  for (const weak of ['', 'dev-oauth-session-secret', 'too-short']) {
    assert.throws(() => schema.created.call({
      settings: { ...service.settings, sessionSecret: weak }
    }), /private 32-byte signing secret/u);
  }
  assert.doesNotThrow(() => schema.created.call(service),
    'Provider must accept private high-entropy configured session secret');
} finally {
  if (before === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = before;
}
console.log('PASS: OAuth owner browser session HMAC, malformed cookie handling, production secret fail-closed');
