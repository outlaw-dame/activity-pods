'use strict';

// The token index is used for real grant revocation, so trimming the list
// would silently leave still-valid tokens behind. Deny excessive issuance
// rather than discarding pointers needed to revoke existing credentials.
const MAX_GRANT_TOKENS = 512;
const MAX_GRANT_TTL_SECONDS = 86400;
const REVOKE_BATCH = 128;
const MAX_REVOKE_BATCHES = 1024;

// Redis executes reservation and persistence atomically. Upsert cannot race
// a revocation marker into existence and leave a fresh valid token behind.
const ATOMIC_GRANT_UPSERT = [
  "if redis.call('EXISTS', KEYS[3]) ~= 0 then return -2 end",
  "if redis.call('LLEN', KEYS[2]) >= tonumber(ARGV[4]) then return -1 end",
  "if ARGV[1] == 'hash' then",
  "  redis.call('HSET', KEYS[1], 'payload', ARGV[2])",
  "else",
  "  redis.call('SET', KEYS[1], ARGV[2])",
  "end",
  "redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))",
  "redis.call('RPUSH', KEYS[2], ARGV[5])",
  "local indexTtl = redis.call('TTL', KEYS[2])",
  "if indexTtl < tonumber(ARGV[3]) then",
  "  redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))",
  "end",
  "if ARGV[6] ~= '' then",
  "  redis.call('SET', KEYS[4], ARGV[7], 'EX', tonumber(ARGV[3]))",
  "end",
  "if ARGV[8] ~= '' then",
  "  redis.call('SET', KEYS[5], ARGV[7], 'EX', tonumber(ARGV[3]))",
  "end",
  "return 1"
].join('\n');

function revokeMarker(grantId) {
  return 'grant-revoked:' + grantId;
}
function validTtl(seconds) {
  return Number.isSafeInteger(seconds) && seconds >= 1 &&
    seconds <= MAX_GRANT_TTL_SECONDS;
}
function cappedError(code) {
  const error = new Error('OIDC grant token index cannot accept this operation');
  error.code = code;
  return error;
}
module.exports = {
  ATOMIC_GRANT_UPSERT, MAX_GRANT_TOKENS, MAX_GRANT_TTL_SECONDS,
  REVOKE_BATCH, MAX_REVOKE_BATCHES, revokeMarker, validTtl, cappedError
};
