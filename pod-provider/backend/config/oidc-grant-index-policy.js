'use strict';

// Token pointers must survive until their credentials expire or are revoked.
// Reclaim only keys Redis proves absent, in a bounded atomic sweep at quota;
// never trim a live token. Fail closed on oversized legacy indexes.
const MAX_GRANT_TOKENS = 512;
const MAX_GRANT_TTL_SECONDS = 86400;
const REVOKE_BATCH = 128;
const MAX_REVOKE_BATCHES = 1024;

// Redis executes reservation and persistence atomically. Upsert cannot race
// a revocation marker into existence and leave a fresh valid token behind.
const ATOMIC_GRANT_UPSERT = [
  "if redis.call('EXISTS', KEYS[3]) ~= 0 then return -2 end",
  "local existing = redis.call('EXISTS', KEYS[1]) == 1",
  "if existing then",
  "  local encoded = ARGV[1] == 'hash' and redis.call('HGET', KEYS[1], 'payload') or redis.call('GET', KEYS[1])",
  "  if not encoded or cjson.decode(encoded).grantId ~= ARGV[9] then return -3 end",
  "  if not redis.call('LPOS', KEYS[2], ARGV[5]) then return -3 end",
  "else",
  "  local cap = tonumber(ARGV[4])",
  "  local used = redis.call('LLEN', KEYS[2])",
  "  if used >= cap then",
  "    if used > cap then return -1 end",
  "    if string.sub(KEYS[1], -#ARGV[5]) ~= ARGV[5] then return -4 end",
  "    local prefix = string.sub(KEYS[1], 1, #KEYS[1] - #ARGV[5])",
  "    local pointers = redis.call('LRANGE', KEYS[2], 0, cap - 1)",
  "    local live = {}",
  "    for _, pointer in ipairs(pointers) do",
  "      if redis.call('EXISTS', prefix .. pointer) == 1 then",
  "        live[#live + 1] = pointer",
  "      end",
  "    end",
  "    if #live < #pointers then",
  "      local previousTtl = redis.call('TTL', KEYS[2])",
  "      redis.call('DEL', KEYS[2])",
  "      if #live > 0 then",
  "        redis.call('RPUSH', KEYS[2], unpack(live))",
  "        if previousTtl > 0 then redis.call('EXPIRE', KEYS[2], previousTtl) end",
  "      end",
  "    end",
  "    if #live >= cap then return -1 end",
  "  end",
  "end",
  "if ARGV[1] == 'hash' then",
  "  redis.call('HSET', KEYS[1], 'payload', ARGV[2])",
  "else",
  "  redis.call('SET', KEYS[1], ARGV[2])",
  "end",
  "redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))",
  "if not existing then redis.call('RPUSH', KEYS[2], ARGV[5]) end",
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

// Select, delete, and remove a grant's next token batch in ONE Redis script.
// A concurrent worker may not trim pointers that it did not itself delete.
// ARGV[2] is the trusted ioredis keyPrefix; index entries remain logical
// (unprefixed) keys for compatibility with already-issued grant records.
const ATOMIC_GRANT_REVOKE_BATCH = [
  "local cap = tonumber(ARGV[1])",
  "local tokens = redis.call('LRANGE', KEYS[1], 0, cap - 1)",
  "for _, token in ipairs(tokens) do",
  "  redis.call('DEL', ARGV[2] .. token)",
  "end",
  "if #tokens > 0 then",
  "  redis.call('LTRIM', KEYS[1], #tokens, -1)",
  "else",
  "  redis.call('DEL', KEYS[1])",
  "end",
  "return #tokens"
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
  ATOMIC_GRANT_UPSERT, ATOMIC_GRANT_REVOKE_BATCH, MAX_GRANT_TOKENS, MAX_GRANT_TTL_SECONDS,
  REVOKE_BATCH, MAX_REVOKE_BATCHES, revokeMarker, validTtl, cappedError
};
