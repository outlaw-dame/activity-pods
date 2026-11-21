'use strict';

// All mutating operations execute atomically in Redis 8.2. Key names are
// supplied through KEYS, never arbitrary ARGV. No transaction is retried
// after an unknown acknowledgment. Strings in the Redis record are encrypted
// by the caller; the current approved OAuth generation remains server-side.
const FAMILY_MAX_TOKENS=512;
const REVOKE_TTL_EXTRA_SECONDS=7200;
const ID=/^[A-Za-z0-9_-]{24}$/u;
const CONSENT_ID=/^[A-Za-z0-9_-]{32}$/u;

const VERIFY_CONSENT=[
  "local raw=redis.call('GET',KEYS[5])",
  "if not raw then return -3 end",
  "local ok,g=pcall(cjson.decode,raw)",
  "if not ok or type(g)~='table' or g.revoked~=false then return -3 end",
  "if g.grantId~=ARGV[4] or g.canonicalAccountId~=ARGV[5] or",
  "   g.clientId~=ARGV[6] or g.scope~=ARGV[7] then return -3 end"
].join('\n');

const ISSUE_REFRESH=[
  "if redis.call('EXISTS',KEYS[4])~=0 then return -2 end",
  VERIFY_CONSENT,
  "if redis.call('EXISTS',KEYS[1],KEYS[2])~=0 then return -4 end",
  "if redis.call('SCARD',KEYS[3])>=tonumber(ARGV[8]) then return -5 end",
  "redis.call('SET',KEYS[1],ARGV[1],'EX',tonumber(ARGV[3]))",
  "redis.call('SET',KEYS[2],ARGV[2],'EX',tonumber(ARGV[3]))",
  "redis.call('SADD',KEYS[3],ARGV[2])",
  "local ttl=redis.call('TTL',KEYS[3])",
  "if ttl<tonumber(ARGV[3]) then redis.call('EXPIRE',KEYS[3],ARGV[3]) end",
  "return 1"
].join('\n');

// KEYS: old token, new token, new lookup, family set, revocation marker,
// current OAuth consent. ARGV: exact old ciphertext, consumed ciphertext,
// successor ciphertext, successor token ID, TTL, marker TTL, grant ID,
// owner WebID, client ID, scope, family item cap.
const ROTATE_REFRESH=[
  "if redis.call('EXISTS',KEYS[5])~=0 then return -2 end",
  "local current=redis.call('GET',KEYS[1])",
  "if not current then return -1 end",
  "if current~=ARGV[1] then",
  "  redis.call('SET',KEYS[5],'1','EX',ARGV[6])",
  "  return -4",
  "end",
  "local raw=redis.call('GET',KEYS[6])",
  "if not raw then return -3 end",
  "local ok,g=pcall(cjson.decode,raw)",
  "if not ok or type(g)~='table' or g.revoked~=false then return -3 end",
  "if g.grantId~=ARGV[7] or g.canonicalAccountId~=ARGV[8] or",
  "   g.clientId~=ARGV[9] or g.scope~=ARGV[10] then return -3 end",
  "if redis.call('EXISTS',KEYS[2],KEYS[3])~=0 then return -5 end",
  "if redis.call('SCARD',KEYS[4])>=tonumber(ARGV[11]) then return -6 end",
  "local oldTtl=redis.call('TTL',KEYS[1])",
  "if oldTtl<=0 then return -1 end",
  "redis.call('SET',KEYS[1],ARGV[2],'EX',oldTtl)",
  "redis.call('SET',KEYS[2],ARGV[3],'EX',ARGV[5])",
  "redis.call('SET',KEYS[3],ARGV[4],'EX',ARGV[5])",
  "redis.call('SADD',KEYS[4],ARGV[4])",
  "local familyTtl=redis.call('TTL',KEYS[4])",
  "if familyTtl<tonumber(ARGV[5]) then",
  "  redis.call('EXPIRE',KEYS[4],ARGV[5])",
  "end",
  "return 1"
].join('\n');

function consentKey(prefix,owner,clientId){
  return prefix+':'+owner+':'+clientId;
}
module.exports={
  ISSUE_REFRESH,ROTATE_REFRESH,
  FAMILY_MAX_TOKENS,REVOKE_TTL_EXTRA_SECONDS,
  ID,CONSENT_ID,consentKey
};
