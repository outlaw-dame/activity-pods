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
// The owner can revoke ONLY the grant generation shown to that same live
// session. Re-approval, logout and revoke all serialize in one Redis history.
// Never replace a later consent generation via a stale browser challenge.
const REVOKE_CONSENT_IF_SESSION_AND_GENERATION = [
  "local live=redis.call('GET',KEYS[2])",
  "if not live or live~=ARGV[1] then return -1 end",
  "local raw=redis.call('GET',KEYS[1])",
  "if not raw then return 0 end",
  "local ok,record=pcall(cjson.decode,raw)",
  "if not ok or type(record)~='table' then return redis.error_reply('INVALID_CONSENT') end",
  "if record.canonicalAccountId~=ARGV[2] or record.clientId~=ARGV[3] or type(record.grantId)~='string' or type(record.revoked)~='boolean' then return redis.error_reply('INVALID_CONSENT') end",
  "if record.grantId~=ARGV[4] or record.revoked==true then return 0 end",
  "record.revoked=true",
  "record.updatedAt=tonumber(ARGV[5])",
  "local ttl=redis.call('PTTL',KEYS[1])",
  "if ttl<=0 then ttl=tonumber(ARGV[6])*1000 end",
  "redis.call('SET',KEYS[1],cjson.encode(record),'PX',ttl)",
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
  UPSERT_CONSENT_IF_SESSION_LIVE, REVOKE_CONSENT_IF_SESSION_AND_GENERATION,
  digest, sessionKey, inputValid
};
