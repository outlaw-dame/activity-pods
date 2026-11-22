'use strict';
const crypto = require('node:crypto');

// Stable shared format for the browser session registry and the atomic OAuth
// consent grant writer. This module is a pure policy helper, not a service.
const SESSION_ID = /^[A-Za-z0-9_-]{43}$/u;
const WEBID = /^https:\/\/[^\s]+$/u;
const KEY_PREFIX = 'oauth:browser-session:v1:';
const REVOKE_IF_OWNER = [
  "local actual=redis.call('GET',KEYS[1])",
  "if not actual or actual~=ARGV[1] then return 0 end",
  "return redis.call('DEL',KEYS[1])"
].join('\n');
const UPSERT_CONSENT_IF_SESSION_LIVE = [
  "local actual=redis.call('GET',KEYS[2])",
  "if not actual or actual~=ARGV[1] then return 0 end",
  "redis.call('SET',KEYS[1],ARGV[2],'EX',tonumber(ARGV[3]))",
  "return 1"
].join('\n');
function digest(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}
function sessionKey(prefix, sessionId) {
  return prefix + digest(sessionId);
}
function inputValid(sessionId, webId) {
  return typeof sessionId === 'string' && SESSION_ID.test(sessionId) &&
    typeof webId === 'string' && webId.length <= 2048 && WEBID.test(webId);
}
module.exports = {
  SESSION_ID, KEY_PREFIX, REVOKE_IF_OWNER,
  UPSERT_CONSENT_IF_SESSION_LIVE, digest, sessionKey, inputValid
};
