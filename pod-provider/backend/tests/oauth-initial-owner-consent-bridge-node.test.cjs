'use strict';
const assert=require('node:assert/strict');
const test=require('node:test');
const crypto=require('node:crypto');
const {createDisposableInitialOwnerEpochIssuer,SCOPE}=
  require('../candidates/oauth-initial-owner-epoch-issuer.cjs');
const {createDisposableInitialConsentCoordinator}=
  require('../candidates/oauth-initial-owner-consent-coordinator.cjs');
const {KEY_PREFIX,sessionKey,digest,UPSERT_CONSENT_IF_SESSION_LIVE}=
  require('../utils/oauth-browser-session-policy');
const {consentKey}=require('../utils/oauth-refresh-atomic-policy');

const FLAGS=['NODE_ENV','PAPER_ACCOUNTS_DISPOSABLE',
  'PAPER_JOURNAL_BOUND_SAI_DISPOSABLE','PAPER_OAUTH_PG_EPOCH_DISPOSABLE',
  'PAPER_OAUTH_PG_RESTORE_DISPOSABLE','PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE',
  'PAPER_OAUTH_WITNESS_DISPOSABLE','PAPER_OAUTH_WORM_HIGHWATER_DISPOSABLE',
  'PAPER_OAUTH_WORM_READBACK_DISPOSABLE'];
const old=Object.fromEntries(FLAGS.map(x=>[x,process.env[x]]));
function restore(){
  for(const [k,v] of Object.entries(old)){
    if(v===undefined)delete process.env[k];
    else process.env[k]=v;
  }
}
process.on('exit',restore);
function enable(){
  for(const key of FLAGS)process.env[key]='confirmed';
  process.env.NODE_ENV='test';
}
enable();
const PROVIDER='https://paper.example.org';
const ORIGIN='https://enroll.paper.example.org';
const OWNER='https://paper.example.org/users/safe-owner';
const CLIENT='https://paper-client.example.org/oauth';
const SESSION='v'.repeat(43);
const TOKEN_HASH=crypto.randomBytes(32);
const code=(fn,value)=>assert.rejects(fn(),e=>e?.code===value);
const permission=()=>({
  version:180000,own_login:true,primary_host:true,
  restricted:true,issuer:true,can_switch:false,revoker:false,
  signer:false,reader:false,sai_issuer:false,sai_attestor:false,
  schema_create:false,direct_oauth:false,can_issue_session:true,
  can_issue_raw:false,can_revoke_session:false,memberships:1,
  bad_options:0,parent_roles:0
});
function pgFixture({roles,revision='1',sqlFailure=false}={}){
  let leased=0;
  const calls=[],released=[];
  const pool={async connect(){
    const id=++leased,p=roles?.[id-1]||permission();
    return {
      async query(query){
        const sql=typeof query==='string'?query:query.text;
        calls.push({lease:id,sql,values:query.values||[]});
        if(sql.includes('FROM pg_catalog.pg_roles p'))
          return {rowCount:1,rows:[p]};
        if(sql.includes('issue_session_oauth_generation(')){
          if(sqlFailure)throw Error('Internal SQL failure containing secret DSN');
          return {rowCount:1,rows:[{revision}]};
        }
        assert.fail('Unknown SQL or wrong restricted function');
      },
      release(discard){released.push({lease:id,discard:!!discard})}
    };
  }};
  return {pool,calls,released};
}
function issuer(f){
  return createDisposableInitialOwnerEpochIssuer({
    pool:f.pool,providerId:PROVIDER,browserOrigin:ORIGIN,fixtureOnly:true
  });
}

test('issuer refuses production flags, raw user selectors, wrong scope and stale PG roles',async()=>{
  process.env.NODE_ENV='production';
  assert.throws(()=>issuer(pgFixture()),e=>e.code==='OWNER_OAUTH_EPOCH_NOT_RELEASED');
  enable();
  const f=pgFixture();
  const adapter=issuer(f);
  const grantId='x'.repeat(32);
  for(const request of [
    {tokenHash:Buffer.alloc(31),grantId,scope:SCOPE},
    {tokenHash:Buffer.alloc(33),grantId,scope:SCOPE},
    {tokenHash:'a'.repeat(64),grantId,scope:SCOPE},
    {tokenHash:TOKEN_HASH,grantId:'bad',scope:SCOPE},
    {tokenHash:TOKEN_HASH,grantId,scope:'atproto'}
  ]){
    await code(()=>adapter.issueFirst(request),'OWNER_OAUTH_EPOCH_SCOPE_INVALID');
  }
  assert.equal(f.calls.length,0);
  assert.equal(await adapter.issueFirst({
    tokenHash:TOKEN_HASH,grantId,scope:SCOPE
  }),'1');
  assert.equal(f.calls.length,2);
  assert.deepEqual(f.calls[1].values,[PROVIDER,ORIGIN,TOKEN_HASH,grantId,SCOPE,'0']);
  assert.equal(f.calls[1].sql.includes('issue_oauth_generation('),false);
  assert.deepEqual(f.released,[{lease:1,discard:false}]);
});

test('every PG connection must be a restricted exact-purpose issuer',async()=>{
  enable();
  for(const bad of [
    {version:170000},{own_login:false},{primary_host:false},
    {restricted:false},{issuer:false},{can_switch:true},
    {revoker:true},{signer:true},{reader:true},
    {sai_issuer:true},{sai_attestor:true},{schema_create:true},
    {direct_oauth:true},{can_issue_session:false},{can_issue_raw:true},
    {can_revoke_session:true},{memberships:2},{bad_options:1},
    {parent_roles:1}
  ]){
    const f=pgFixture({roles:[{...permission(),...bad}]});
    await code(()=>issuer(f).issueFirst({
      tokenHash:TOKEN_HASH,grantId:'x'.repeat(32),scope:SCOPE
    }),'OWNER_OAUTH_EPOCH_ROLE_UNSAFE');
    assert.equal(f.calls.length,1,'Do not execute any issuer mutation');
    assert.deepEqual(f.released,[{lease:1,discard:true}]);
  }
  const f=pgFixture({roles:[permission(),{...permission(),revoker:true}]});
  const adapter=issuer(f);
  assert.equal(await adapter.issueFirst({
    tokenHash:TOKEN_HASH,grantId:'x'.repeat(32),scope:SCOPE
  }),'1');
  await code(()=>adapter.issueFirst({
    tokenHash:TOKEN_HASH,grantId:'y'.repeat(32),scope:SCOPE
  }),'OWNER_OAUTH_EPOCH_ROLE_UNSAFE');
  assert.deepEqual(f.released,[{lease:1,discard:false},{lease:2,discard:true}]);
});

test('PG refusal and unknown write ACK do not retry the irreversible CAS',async()=>{
  enable();
  for(const config of [{revision:'0'},{revision:'2'},{sqlFailure:true}]){
    const f=pgFixture(config);
    const adapter=issuer(f);
    await code(()=>adapter.issueFirst({
      tokenHash:TOKEN_HASH,grantId:'x'.repeat(32),scope:SCOPE
    }),config.sqlFailure?'OWNER_OAUTH_EPOCH_UNAVAILABLE':
      'OWNER_OAUTH_EPOCH_JOURNAL_NOT_CURRENT');
    assert.equal(f.calls.length,2);
    assert.deepEqual(f.released,[{lease:1,discard:true}]);
  }
});

function coordinatorFixture(overrides={}){
  enable();
  const state={
    active:true,credentialCurrent:true,canonicalCurrent:true,
    witnessCurrent:false,epoch:0,acceptedGrant:null,attestedGrant:null,
    sessionKey:sessionKey(KEY_PREFIX,SESSION),
    redis:new Map([[sessionKey(KEY_PREFIX,SESSION),digest(OWNER)]]),
    calls:{owner:0,issue:0,canonical:0,attest:0,witness:0,redis:0}
  };
  const verifyLiveOwner=async()=>{
    state.calls.owner++;
    if(!state.active||!state.credentialCurrent)throw Error('Expired credentials');
    return {
      canonicalAccountId:OWNER,sessionId:SESSION,
      enrollmentTokenHash:Buffer.from(TOKEN_HASH)
    };
  };
  const epochIssuer={async issueFirst({tokenHash,grantId,scope}){
    state.calls.issue++;
    assert.deepEqual(tokenHash,TOKEN_HASH);
    assert.equal(scope,SCOPE);
    if(state.epoch!==0)return '0';
    state.epoch=1;
    state.acceptedGrant=grantId;
    return '1';
  }};
  const canonicalReader={async verify(record){
    state.calls.canonical++;
    return state.canonicalCurrent&&state.epoch===1&&
      record.canonicalAccountId===OWNER&&record.clientId===CLIENT&&
      record.consentGrantId===state.acceptedGrant&&
      record.oauthPgRevision==='1'&&record.scope===SCOPE;
  }};
  const witnessAttestor={async attestFirst(record){
    state.calls.attest++;
    if(overrides.onAttest)await overrides.onAttest(state,record);
    state.attestedGrant=record.consentGrantId;
    state.witnessCurrent=true;
    if(overrides.throwAttest)throw Error('Ambiguous remote ACK');
    return overrides.attest===false?false:true;
  }};
  const immutableWitnessReader={async verify(record){
    state.calls.witness++;
    if(overrides.onWitness)await overrides.onWitness(state,record);
    return state.witnessCurrent&&
      state.attestedGrant===record.consentGrantId&&
      state.canonicalCurrent;
  }};
  const redis={async eval(lua,keys,key,sessionKeyValue,ownerDigest,json,ttl){
    state.calls.redis++;
    assert.equal(lua,UPSERT_CONSENT_IF_SESSION_LIVE);
    assert.equal(keys,2);
    assert.equal(key,consentKey('oauth:grant',OWNER,CLIENT));
    assert.equal(sessionKeyValue,state.sessionKey);
    assert.equal(ownerDigest,digest(OWNER));
    assert.equal(ttl,String(60*60*24*30));
    if(state.redis.get(state.sessionKey)!==ownerDigest)return 0;
    state.redis.set(key,json);
    if(overrides.lostRedisAck)throw Error('Redis disconnected after commit');
    if(overrides.onRedis)await overrides.onRedis(state);
    return 1;
  }};
  const options={verifyLiveOwner,epochIssuer,canonicalReader,witnessAttestor,
    immutableWitnessReader,redis,approvedClientId:CLIENT,fixtureOnly:true};
  return {state,options,execute:()=>createDisposableInitialConsentCoordinator(options)
    .approveFirst({context:Object.freeze({})})};
}

test('first grant: owner credential, PG CAS, WORM latest readback and Redis session CAS',async()=>{
  const f=coordinatorFixture();
  const grant=await f.execute();
  assert.match(grant.grantId,/^[A-Za-z0-9_-]{32}$/u);
  assert.equal(grant.oauthPgRevision,'1');
  assert.equal(grant.clientId,CLIENT);
  assert.equal(grant.scope,SCOPE);
  const raw=f.state.redis.get(consentKey('oauth:grant',OWNER,CLIENT));
  assert.deepEqual(JSON.parse(raw),grant);
  assert.equal(f.state.calls.issue,1);
  assert.equal(f.state.calls.attest,1);
  assert.equal(f.state.calls.redis,1);
  assert.ok(f.state.calls.canonical>=3);
  assert.ok(f.state.calls.witness>=2);
  assert.ok(f.state.calls.owner>=2);
  await code(()=>f.execute(),'OWNER_INITIAL_CONSENT_COMMIT_AMBIGUOUS');
  assert.equal(f.state.calls.redis,1,'Never overwrite with a replayed initial grant');
});

test('irreversible SQL ACK loss never retries or calls Redis/witness',async()=>{
  const f=coordinatorFixture();
  f.options.epochIssuer.issueFirst=async()=>{f.state.calls.issue++;throw Error('lost ACK')};
  await code(()=>f.execute(),'OWNER_INITIAL_CONSENT_COMMIT_AMBIGUOUS');
  assert.equal(f.state.calls.issue,1);
  assert.equal(f.state.calls.attest,0);
  assert.equal(f.state.calls.redis,0);
});

test('independent witness failure leaves an unexposed canonical pending epoch',async()=>{
  for(const opts of [{throwAttest:true},{attest:false}]){
    const f=coordinatorFixture(opts);
    await code(()=>f.execute(),'OWNER_INITIAL_CONSENT_WITNESS_COMMIT_AMBIGUOUS');
    assert.equal(f.state.epoch,1);
    assert.equal(f.state.calls.issue,1);
    assert.equal(f.state.calls.redis,0);
  }
  const stale=coordinatorFixture({onWitness:s=>{s.witnessCurrent=false}});
  await code(()=>stale.execute(),'OWNER_INITIAL_CONSENT_WITNESS_NOT_CURRENT');
  assert.equal(stale.state.calls.redis,0);
});

test('credential rotation/logout during WORM readback blocks grant before Redis CAS',async()=>{
  for(const [action,expectedRedisCalls] of [
    [s=>{s.active=false},0],
    [s=>{s.credentialCurrent=false},0],
    [s=>{s.redis.delete(s.sessionKey)},1]
  ]){
    const f=coordinatorFixture({onAttest:action});
    await code(()=>f.execute(),'OWNER_INITIAL_CONSENT_OWNER_NOT_CURRENT');
    assert.equal(f.state.calls.redis,expectedRedisCalls);
    assert.equal(f.state.epoch,1,'No unsafe SQL rollback on unknown edge');
    assert.equal(f.state.redis.has(consentKey('oauth:grant',OWNER,CLIENT)),false);
  }
});

test('lost Redis ACK, PG transition and witness mutation after CAS never report success',async()=>{
  const lost=coordinatorFixture({lostRedisAck:true});
  await code(()=>lost.execute(),'OWNER_INITIAL_CONSENT_REDIS_AMBIGUOUS');
  assert.equal(lost.state.calls.redis,1);
  assert.equal(lost.state.epoch,1);
  const raced=coordinatorFixture({onRedis:s=>{s.canonicalCurrent=false}});
  await code(()=>raced.execute(),'OWNER_INITIAL_CONSENT_EPOCH_NOT_CURRENT');
  assert.equal(raced.state.calls.redis,1);
  const head=coordinatorFixture({onRedis:s=>{s.witnessCurrent=false}});
  await code(()=>head.execute(),'OWNER_INITIAL_CONSENT_WITNESS_NOT_CURRENT');
});

test('no production config flag enables the new approval coordinator',async()=>{
  const f=coordinatorFixture();
  process.env.NODE_ENV='production';
  assert.throws(()=>createDisposableInitialConsentCoordinator(f.options),
    e=>e?.code==='OWNER_INITIAL_CONSENT_NOT_RELEASED');
  enable();
  delete process.env.PAPER_OAUTH_WORM_HIGHWATER_DISPOSABLE;
  assert.throws(()=>createDisposableInitialConsentCoordinator(f.options),
    e=>e?.code==='OWNER_INITIAL_CONSENT_NOT_RELEASED');
  enable();
});

if(process.env.PAPER_OWNER_OAUTH_REDIS_DISPOSABLE==='confirmed') {
  test('real Redis 8.2 DUMP/RESTORE cannot reauthorize signed OAuth token after witness block',async()=>{
    enable();
    process.env.SEMAPPS_AVAILABLE_LOCALES='en';
    process.env.SEMAPPS_AUTH_RESERVED_USER_NAMES='admin,root';
    const Redis=require('ioredis');
    const {SignJWT,generateKeyPair,exportJWK}=require('jose');
    const oauthToken=require('../services/oauth/oauth-token.service.js');
    const oauthConsent=require('../services/oauth/oauth-consent.service.js');
    const redis=new Redis('redis://127.0.0.1:6398',{
      lazyConnect:true,enableOfflineQueue:false,
      autoResendUnfulfilledCommands:false,maxRetriesPerRequest:1,
      connectTimeout:2500
    });
    const grantKey=consentKey('oauth:grant',OWNER,CLIENT);
    const ownerKey=sessionKey(KEY_PREFIX,SESSION);
    try{
      await redis.connect();
      assert.equal(await redis.ping(),'PONG');
      assert.match(await redis.info('server'),/redis_version:8\.2\./u);
      await redis.del(grantKey,ownerKey);
      assert.equal(await redis.set(ownerKey,digest(OWNER),'EX',120),'OK');
      const f=coordinatorFixture();
      f.options.redis=redis;
      const grant=await f.execute();
      const snapshot=await redis.callBuffer('DUMP',grantKey);
      assert.ok(Buffer.isBuffer(snapshot)&&snapshot.length>0);
      const issuer='https://paper.example.org';
      const audience='https://pds.paper.example.org';
      const did='did:plc:'+'b'.repeat(24);
      const {privateKey,publicKey}=await generateKeyPair('ES256');
      const publicJwk={...await exportJWK(publicKey),alg:'ES256'};
      const token=await new SignJWT({
        scope:grant.scope,client_id:grant.clientId,
        canonical_account_id:grant.canonicalAccountId,
        consent_grant_id:grant.grantId,
        oauth_pg_revision:grant.oauthPgRevision,
        cnf:{jkt:'a'.repeat(43)}
      }).setProtectedHeader({alg:'ES256',typ:'at+jwt'})
        .setIssuer(issuer).setAudience(audience).setSubject(did)
        .setIssuedAt().setExpirationTime('2m').sign(privateKey);
      const ctx={params:{token},call:async(name,args)=>{
        if(name==='jwk.get')return {publicJwk};
        if(name==='oauth-consent.get')
          return oauthConsent.actions.get.handler.call({
            redis,settings:{keyPrefix:'oauth:grant'}
          },{params:args});
        if(name==='oauth-pg-epoch.verify')
          return f.options.canonicalReader.verify({
            canonicalAccountId:args.canonicalAccountId,
            clientId:args.clientId,
            consentGrantId:args.consentGrantId,
            scope:args.scope,oauthPgRevision:args.oauthPgRevision
          });
        if(name==='oauth-witness-epoch.verify')
          return f.options.immutableWitnessReader.verify({
            canonicalAccountId:args.canonicalAccountId,
            clientId:args.clientId,
            consentGrantId:args.consentGrantId,scope:SCOPE,
            oauthPgRevision:args.oauthPgRevision
          });
        assert.fail('Unexpected service action: '+name);
      }};
      const introspect=()=>oauthToken.actions.introspectAccessToken.handler.call({
        settings:{issuer,audience}
      },ctx);
      assert.equal((await introspect()).active,true,
        'Baseline validates the actual signed OAuth handler');
      // Revocation advanced canonical and independently retained authority,
      // but the attacker reintroduced the prior Redis grant snapshot.
      f.state.canonicalCurrent=false;
      f.state.witnessCurrent=false;
      await redis.del(grantKey);
      assert.equal(await redis.restore(grantKey,120000,snapshot),'OK');
      assert.equal((await introspect()).active,false,
        'Restored Redis grant cannot override canonical revocation');
      // An administrator also rewound the *primary* database; a separately
      // retained latest independent head still denies. No positive claim of
      // actual PG WAL PITR is made by this callback-only fixture.
      f.state.canonicalCurrent=true;
      assert.equal((await introspect()).active,false,
        'Dual Redis/primary rollback still denied by external high-water');
      f.state.witnessCurrent=false;
      assert.equal((await introspect()).active,false);
    }finally{
      if(redis.status==='ready'){
        await redis.del(grantKey,ownerKey).catch(()=>{});
        await redis.quit().catch(()=>redis.disconnect());
      }else redis.disconnect();
    }
  });
}
