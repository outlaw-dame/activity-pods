const Redis = require('ioredis');
const crypto = require('node:crypto');
const { MoleculerError } = require('moleculer').Errors;
const { randomToken, nowEpochSec, parseIntWithBounds } = require('../../utils/oauth-security');
const {
  ISSUE_REFRESH, ROTATE_REFRESH, FAMILY_MAX_TOKENS,
  REVOKE_TTL_EXTRA_SECONDS, ID, CONSENT_ID, consentKey
} = require('../../utils/oauth-refresh-atomic-policy');

function invalid(code='INVALID_GRANT'){
  throw new MoleculerError('Refresh token is invalid or no longer authorized',
    code==='REFRESH_TOKEN_REPLAY_DETECTED'?401:400,code);
}
module.exports = {
  name: 'oauth-refresh-session',
  settings: {
    redisUrl: process.env.SEMAPPS_REDIS_CACHE_URL || 'redis://localhost:6379',
    tokenPrefix: 'oauth:refresh',
    familyPrefix: 'oauth:refresh-family',
    revokedPrefix: 'oauth:refresh-family-revoked',
    consentPrefix: 'oauth:grant',
    ttlSec: parseIntWithBounds(process.env.OAUTH_REFRESH_TTL_SECONDS, 60 * 60 * 24 * 30, 300, 60 * 60 * 24 * 180, 'OAUTH_REFRESH_TTL_SECONDS'),
    encKeyHex: process.env.OAUTH_REFRESH_TOKEN_ENC_KEY_HEX ||
      (process.env.NODE_ENV==='test'?
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef':'')
  },
  created() {
    if(!/^[0-9a-fA-F]{64}$/u.test(this.settings.encKeyHex)||
       (process.env.NODE_ENV==='production'&&
        this.settings.encKeyHex.toLowerCase()===
          '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')){
      throw Error('A unique 32-byte OAuth refresh encryption key is mandatory');
    }
    this.encKey=Buffer.from(this.settings.encKeyHex,'hex');
    // Unknown Redis ACKs must never be replayed automatically after reconnect.
    this.redis=new Redis(this.settings.redisUrl,{
      connectTimeout:2500,enableOfflineQueue:false,
      autoResendUnfulfilledCommands:false,maxRetriesPerRequest:1,
      lazyConnect:true
    });
  },
  async started(){
    // The service may accept actions only after its no-offline-queue Redis
    // session is ready. Do not buffer potentially ambiguous writes.
    await this.redis.connect();
    if(await this.redis.ping()!=='PONG')throw Error('OAuth refresh Redis unavailable');
  },
  async stopped() {
    if(!this.redis)return;
    if(this.redis.status!=='ready'){this.redis.disconnect();return;}
    await this.redis.quit().catch(()=>this.redis.disconnect());
  },
  actions: {
    issueRefreshToken: {
      params: {
        did: { type: 'string', min: 1 },
        canonicalAccountId: { type: 'string', min: 1 },
        clientId: { type: 'string', min: 1 },
        scope: { type: 'string', min: 1 },
        consentGrantId: { type: 'string', pattern: '^[A-Za-z0-9_-]{32}$' },
        dpopJkt: { type: 'string', min: 8 },
        familyId: { type: 'string', optional: true }
      },
      async handler(ctx) {
        const p=ctx.params;
        if(!CONSENT_ID.test(p.consentGrantId||'')||
           (p.familyId!==undefined&&!ID.test(p.familyId))||
           p.scope.length>8192)invalid();
        const refreshToken=randomToken(32);
        const tokenId=randomToken(18);
        const familyId=p.familyId||randomToken(18);
        const now=nowEpochSec();
        const record={
          tokenId,familyId,did:p.did,
          canonicalAccountId:p.canonicalAccountId,
          clientId:p.clientId,scope:p.scope,
          consentGrantId:p.consentGrantId,dpopJkt:p.dpopJkt,
          active:true,createdAt:now,expiresAt:now+this.settings.ttlSec
        };
        const result=await this.redis.eval(ISSUE_REFRESH,5,
          this.tokenKey(tokenId),this.refreshTokenLookupKey(refreshToken),
          this.familyKey(familyId),this.revokedKey(familyId),
          consentKey(this.settings.consentPrefix,p.canonicalAccountId,p.clientId),
          this.encrypt(record),tokenId,String(this.settings.ttlSec),
          p.consentGrantId,p.canonicalAccountId,p.clientId,p.scope,
          String(FAMILY_MAX_TOKENS)
        );
        if(result===-2)invalid('REFRESH_FAMILY_REVOKED');
        if(result===-3)invalid();
        if(result===-5)invalid('REFRESH_FAMILY_LIMIT');
        if(result!==1)invalid('REFRESH_ISSUE_UNAVAILABLE');
        return {refreshToken,tokenId,familyId,expiresIn:this.settings.ttlSec};
      }
    },
    rotateRefreshToken: {
      params: {
        refreshToken: { type: 'string', min: 10 },
        dpopJkt: { type: 'string', min: 8 }
      },
      async handler(ctx) {
        const p=ctx.params;
        const tokenId=await this.redis.get(this.refreshTokenLookupKey(p.refreshToken));
        if(!tokenId||!ID.test(tokenId))invalid();
        const key=this.tokenKey(tokenId);
        const raw=await this.redis.get(key);
        if(!raw)invalid();
        let old;
        try{old=this.decrypt(raw);}catch{invalid();}
        if(old.tokenId!==tokenId||!ID.test(old.familyId||'')||
           !CONSENT_ID.test(old.consentGrantId||'')||
           !Number.isSafeInteger(old.expiresAt)||old.expiresAt<=nowEpochSec()){
          invalid();
        }
        if(!old.active){
          // Reuse of a consumed token revokes the entire token family.
          await this.actions.revokeFamily({familyId:old.familyId});
          invalid('REFRESH_TOKEN_REPLAY_DETECTED');
        }
        if(old.dpopJkt!==p.dpopJkt)invalid('INVALID_DPOP_PROOF');
        const now=nowEpochSec(),ttl=this.settings.ttlSec;
        const refreshToken=randomToken(32),newId=randomToken(18);
        const next={
          tokenId:newId,familyId:old.familyId,did:old.did,
          canonicalAccountId:old.canonicalAccountId,
          clientId:old.clientId,scope:old.scope,
          consentGrantId:old.consentGrantId,dpopJkt:old.dpopJkt,
          active:true,createdAt:now,expiresAt:now+ttl
        };
        const consumed={...old,active:false,rotatedAt:now};
        // CAS old ciphertext AND current consent generation, then write the
        // successor, lookup and family index in the SAME atomic Redis script.
        // If another worker already consumed this token, the script revokes
        // the family before returning a replay denial.
        const result=await this.redis.eval(ROTATE_REFRESH,6,
          key,this.tokenKey(newId),this.refreshTokenLookupKey(refreshToken),
          this.familyKey(old.familyId),this.revokedKey(old.familyId),
          consentKey(this.settings.consentPrefix,old.canonicalAccountId,old.clientId),
          raw,this.encrypt(consumed),this.encrypt(next),newId,String(ttl),
          String(ttl+REVOKE_TTL_EXTRA_SECONDS),old.consentGrantId,
          old.canonicalAccountId,old.clientId,old.scope,String(FAMILY_MAX_TOKENS)
        );
        if(result===-4)invalid('REFRESH_TOKEN_REPLAY_DETECTED');
        if(result===-2)invalid('REFRESH_FAMILY_REVOKED');
        if(result===-3)invalid();
        if(result===-6)invalid('REFRESH_FAMILY_LIMIT');
        if(result!==1)invalid('REFRESH_ROTATION_UNAVAILABLE');
        return {
          previousTokenId:old.tokenId,refreshToken,
          tokenId:newId,familyId:old.familyId,expiresIn:ttl,
          did:old.did,canonicalAccountId:old.canonicalAccountId,
          clientId:old.clientId,scope:old.scope,
          consentGrantId:old.consentGrantId
        };
      }
    },
    revokeFamily: {
      params: {familyId:{type:'string',min:1}},
      async handler(ctx) {
        const familyId=ctx.params.familyId;
        if(!ID.test(familyId))invalid();
        // One durable marker immediately denies old AND successor tokens.
        // No unbounded SMEMBERS/decrypt/update loop or replica race.
        const result=await this.redis.set(this.revokedKey(familyId),'1','EX',
          this.settings.ttlSec+REVOKE_TTL_EXTRA_SECONDS);
        if(result!=='OK')invalid('REFRESH_REVOKE_UNAVAILABLE');
        const count=await this.redis.scard(this.familyKey(familyId));
        return {revoked:true,count};
      }
    },
    introspectRefreshToken: {
      params: {refreshToken:{type:'string',min:10}},
      async handler(ctx) {
        const tokenId=await this.redis.get(
          this.refreshTokenLookupKey(ctx.params.refreshToken));
        if(!tokenId||!ID.test(tokenId))return null;
        const raw=await this.redis.get(this.tokenKey(tokenId));
        if(!raw)return null;
        let r;
        try{r=this.decrypt(raw);}catch{return null;}
        if(r.tokenId!==tokenId||!ID.test(r.familyId||'')||
           !CONSENT_ID.test(r.consentGrantId||''))return null;
        const [blocked,consentRaw]=await Promise.all([
          this.redis.exists(this.revokedKey(r.familyId)),
          this.redis.get(consentKey(this.settings.consentPrefix,
            r.canonicalAccountId,r.clientId))
        ]);
        let consent;
        try{consent=consentRaw?JSON.parse(consentRaw):null;}catch{consent=null;}
        const active=r.active===true&&r.expiresAt>nowEpochSec()&&
          blocked===0&&consent?.revoked===false&&
          consent?.grantId===r.consentGrantId&&
          consent?.canonicalAccountId===r.canonicalAccountId&&
          consent?.clientId===r.clientId&&consent?.scope===r.scope;
        return {
          active,tokenId:r.tokenId,familyId:r.familyId,
          did:r.did,canonicalAccountId:r.canonicalAccountId,
          clientId:r.clientId,scope:r.scope,expiresAt:r.expiresAt,
          consentGrantId:r.consentGrantId
        };
      }
    }
  },
  methods: {
    tokenKey(id){return this.settings.tokenPrefix+':'+id;},
    familyKey(id){return this.settings.familyPrefix+':'+id;},
    revokedKey(id){return this.settings.revokedPrefix+':'+id;},
    refreshTokenLookupKey(token){
      const hash=crypto.createHash('sha256').update(String(token),'utf8').digest('hex');
      return this.settings.tokenPrefix+':lookup:'+hash;
    },
    encrypt(payload){
      const iv=crypto.randomBytes(12);
      const cipher=crypto.createCipheriv('aes-256-gcm',this.encKey,iv);
      const body=Buffer.from(JSON.stringify(payload),'utf8');
      const encrypted=Buffer.concat([cipher.update(body),cipher.final()]);
      const tag=cipher.getAuthTag();
      return JSON.stringify({iv:iv.toString('base64url'),
        tag:tag.toString('base64url'),
        ciphertext:encrypted.toString('base64url')});
    },
    decrypt(value){
      const parsed=JSON.parse(value);
      const decipher=crypto.createDecipheriv('aes-256-gcm',this.encKey,
        Buffer.from(parsed.iv,'base64url'));
      decipher.setAuthTag(Buffer.from(parsed.tag,'base64url'));
      const plaintext=Buffer.concat([
        decipher.update(Buffer.from(parsed.ciphertext,'base64url')),
        decipher.final()
      ]);
      return JSON.parse(plaintext.toString('utf8'));
    }
  }
};
