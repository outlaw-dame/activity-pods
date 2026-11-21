const Redis = require('ioredis');
const crypto = require('node:crypto');
const { parseIntWithBounds, nowEpochSec } = require('../../utils/oauth-security');
const { consentKey } = require('./oauth-refresh-atomic-policy');

// Every owner-approved OAuth consent has an independently unpredictable
// generation. Reapproval can never make an old access/refresh token current.
const GRANT_ID=/^[A-Za-z0-9_-]{32}$/u;
const REVOKE_CURRENT = [
  "local raw=redis.call('GET',KEYS[1])",
  "if not raw then return 0 end",
  "local record=cjson.decode(raw)",
  "if type(record)~='table' then return redis.error_reply('INVALID_CONSENT') end",
  "if record.revoked==true then return 0 end",
  "record.revoked=true",
  "record.updatedAt=tonumber(ARGV[1])",
  "local ttl=redis.call('TTL',KEYS[1])",
  "if ttl<=0 then ttl=tonumber(ARGV[2]) end",
  "redis.call('SET',KEYS[1],cjson.encode(record),'EX',ttl)",
  "return 1"
].join('\n');
function safeGrant(record,owner,clientId){
  return record&&typeof record==='object'&&!Array.isArray(record)&&
    record.canonicalAccountId===owner&&record.clientId===clientId&&
    typeof record.scope==='string'&&record.scope.length<=8192&&
    typeof record.revoked==='boolean'&&GRANT_ID.test(record.grantId||'');
}
module.exports = {
  name: 'oauth-consent',
  settings: {
    redisUrl: process.env.SEMAPPS_REDIS_CACHE_URL || 'redis://localhost:6379',
    keyPrefix: 'oauth:grant',
    ttlSec: parseIntWithBounds(process.env.OAUTH_GRANT_TTL_SECONDS, 60 * 60 * 24 * 30, 60, 60 * 60 * 24 * 180, 'OAUTH_GRANT_TTL_SECONDS')
  },
  created() {
    this.redis = new Redis(this.settings.redisUrl);
  },
  async stopped() {
    if (this.redis) {
      await this.redis.quit().catch(() => this.redis.disconnect());
    }
  },
  actions: {
    upsert: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 },
        clientId: { type: 'string', min: 1 },
        scope: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const {canonicalAccountId,clientId,scope}=ctx.params;
        if(scope.length>8192)throw Error('OAuth consent scope invalid');
        const now = nowEpochSec();
        const key = consentKey(this.settings.keyPrefix,canonicalAccountId,clientId);
        const record = {
          canonicalAccountId, clientId, scope,
          grantId: crypto.randomBytes(24).toString('base64url'),
          grantedAt: now, updatedAt: now, revoked: false
        };
        // One SET linearizes owner approval against concurrent revocation.
        // Only a new authenticated authorization challenge may call upsert.
        const accepted=await this.redis.set(
          key, JSON.stringify(record), 'EX', this.settings.ttlSec
        );
        if(accepted!=='OK')throw Error('OAuth consent persistence unavailable');
        return record;
      }
    },
    get: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 },
        clientId: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const {canonicalAccountId,clientId}=ctx.params;
        const key = consentKey(this.settings.keyPrefix,canonicalAccountId,clientId);
        const raw = await this.redis.get(key);
        if(!raw)return null;
        let record;
        try{record=JSON.parse(raw);}catch{return null;}
        // Legacy grants without a generation cannot reauthorize a stale PDS
        // token: the owner must complete a fresh consent interaction.
        return safeGrant(record,canonicalAccountId,clientId)?record:null;
      }
    },
    revoke: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 },
        clientId: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const key = consentKey(this.settings.keyPrefix,
          ctx.params.canonicalAccountId,ctx.params.clientId);
        // Read/modify/write on separate Redis commands could overwrite a
        // newly authorized generation. Lua makes the revocation atomic.
        const changed=await this.redis.eval(REVOKE_CURRENT,1,key,
          String(nowEpochSec()),String(this.settings.ttlSec));
        if(changed!==0&&changed!==1)throw Error('OAuth consent revocation unavailable');
        return {revoked:changed===1};
      }
    }
  }
};
