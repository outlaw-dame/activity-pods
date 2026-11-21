// Live PG18 + Redis 8.2, NONACTIVATED OAuth restore-fence candidate.
// No production credentials, user accounts or externally reachable ports.
// Proves rollback of ephemeral Redis state cannot override intact canonical PG.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import Redis from 'ioredis';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import pgEpochReader from '../candidates/oauth-pg-epoch-reader.js';
import oauthToken from '../services/oauth/oauth-token.service.js';
import oauthRefresh from '../services/oauth/oauth-refresh-session.service.js';
import oauthCode from '../services/oauth/oauth-code-store.service.js';
import oauthConsent from '../services/oauth/oauth-consent.service.js';
import oauthPolicy from '../utils/oauth-refresh-atomic-policy.js';

const dsn='postgres://paper_probe:probe_local_only@127.0.0.1:5549/atproto_signed_repo_proof_test';
const redisUrl='redis://127.0.0.1:6398';
if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_PG_RESTORE_DSN!==dsn||
   process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_PG_EPOCH_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_EPOCH_REDIS_URL!==redisUrl)
  throw Error('Refusing OAuth restore-fence proof without disposable PG18/Redis 8.2');

const {Client}=pg;
const admin=new Client({connectionString:dsn,connectionTimeoutMillis:3000,
  query_timeout:10000});
const redis=new Redis(redisUrl,{lazyConnect:true,enableOfflineQueue:false,
  autoResendUnfulfilledCommands:false,maxRetriesPerRequest:1,connectTimeout:2500});
const suffix=crypto.randomBytes(5).toString('hex');
const owner='https://paper.example.org/owners/recovery-'+suffix;
const app='https://paper.example.org/apps/paper';
const clientId='https://paper-client.example.org/oauth';
const did='did:plc:'+'b'.repeat(24);
const grantUri=owner+'/grants/native-sai';
const scope='atproto repo:app.bsky.feed.post?action=create';
const scopeHash=crypto.createHash('sha256').update(scope,'utf8').digest();
const sourceHash=crypto.randomBytes(32);
const redisKey='paper:oauth:restore-proof:'+suffix;
const issueSql='SELECT paper_atproto_authority.issue_oauth_generation($1,$2,$3,$4,$5,$6,$7) AS revision';
const revokeSql='SELECT paper_atproto_authority.revoke_oauth_generation($1,$2,$3,$4) AS revision';
const readSql='SELECT paper_atproto_authority.verify_oauth_generation($1,$2,$3,$4,$5,$6) AS allowed';
const lockSql='SELECT paper_atproto_authority.lock_oauth_generation_for_write($1,$2,$3,$4,$5,$6) AS allowed';
const roles={
  issuer:'paper_oauth_epoch_issuer',
  reader:'paper_oauth_epoch_reader',
  revoker:'paper_oauth_epoch_revoker',
  signer:'paper_oauth_epoch_signer'
};
const clients=[];
let schemaCreated=false;
let createdRoles=[];
const id=value=>'"'+value.replaceAll('"','""')+'"';
const int=x=>BigInt(x).toString();
async function login(kind){
  const name='paper_oauth_probe_'+kind+'_'+suffix+'_'+crypto.randomBytes(3).toString('hex');
  const password=crypto.randomBytes(20).toString('hex');
  await admin.query('CREATE ROLE '+id(name)+
    " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+
    password+"'");
  createdRoles.push(name);
  await admin.query('GRANT '+id(roles[kind])+' TO '+id(name)+
    ' WITH INHERIT TRUE, SET FALSE, ADMIN FALSE');
  const c=new Client({connectionString:dsn.replace('paper_probe:probe_local_only',
    encodeURIComponent(name)+':'+password),connectionTimeoutMillis:3000,
    query_timeout:10000});
  await c.connect();
  clients.push(c);
  const p=(await c.query('SELECT current_user AS login, session_user AS session')).rows[0];
  assert.equal(p.login,name);
  assert.equal(p.session,name);
  const access=(await c.query("SELECT pg_catalog.has_table_privilege(current_user,"+
    "'paper_atproto_authority.oauth_generations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')"+
    " AS table_access, pg_catalog.pg_has_role(current_user,'"+
    roles[kind]+"','SET') AS can_set")).rows[0];
  assert.equal(access.table_access,false);
  assert.equal(access.can_set,false);
  await assert.rejects(c.query('SELECT * FROM paper_atproto_authority.oauth_generations'),
    e=>e?.code==='42501');
  return c;
}
const params=(grant,revision)=>[owner,app,clientId,grant,scopeHash,revision];
async function issue(c,grant,expected,saiRevision=1){
  const r=await c.query(issueSql,[...params(grant,expected),saiRevision]);
  assert.equal(r.rowCount,1);
  return int(r.rows[0].revision);
}
async function verify(c,grant,revision,scopeOverride=scopeHash){
  const r=await c.query(readSql,[owner,app,clientId,grant,scopeOverride,revision]);
  assert.equal(r.rowCount,1);
  return r.rows[0].allowed===true;
}
async function revoke(c,grant,expected){
  const r=await c.query(revokeSql,[owner,clientId,grant,expected]);
  return int(r.rows[0].revision);
}
async function main(){
  await admin.connect();
  await redis.connect();
  assert.equal(await redis.ping(),'PONG');
  assert.match(await redis.info('server'),/redis_version:8\.2\./u);
  assert.equal((await admin.query("SELECT current_setting('server_version_num') AS version"))
    .rows[0].version >= 180000,true);
  if((await admin.query("SELECT to_regnamespace('paper_atproto_authority') AS existing"))
    .rows[0].existing!==null)throw Error('Refusing occupied canonical authority schema');
  const sql1=await readFile(new URL('../sql/paper-atproto-canonical-authority-v1.sql',import.meta.url),'utf8');
  const sql2=await readFile(new URL('../sql/paper-atproto-canonical-authority-v2-owner-consent.sql',import.meta.url),'utf8');
  const sql4=await readFile(new URL('../sql/paper-atproto-canonical-authority-v4-oauth-generations.sql',import.meta.url),'utf8');
  const sql5=await readFile(new URL('../sql/paper-atproto-canonical-authority-v5-oauth-current.sql',import.meta.url),'utf8');
  await admin.query(sql1);
  schemaCreated=true;
  await admin.query(sql2);
  await admin.query(sql4);
  await admin.query(sql5);
  // Synthetic, independently attested v2-style native SAI grant fixture.
  // v3 exact browser-owner journal binding is tested in its own workflow.
  await admin.query(
    'INSERT INTO paper_atproto_authority.identities '+
    '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
    "VALUES ($1,$2,'active',true,1,$3)",[owner,did,sourceHash]);
  await admin.query(
    'INSERT INTO paper_atproto_authority.consents '+
    '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256,'+
    'activation_operation,activation_request_sha256,activation_native_readback_at) '+
    "VALUES ($1,$2,$3,'active',1,$4,$5,$4,clock_timestamp())",
    [owner,app,grantUri,sourceHash,crypto.randomUUID()]);
  // A single admin client must not accept concurrent query() calls:
  // pg@9 removes its implicit queuing. Workers below use independent logins.
  const issuerA=await login('issuer');
  const issuerB=await login('issuer');
  const reader=await login('reader');
  const revokerA=await login('revoker');
  const revokerB=await login('revoker');
  const signer=await login('signer');
  await assert.rejects(reader.query(issueSql,
    [...params(crypto.randomBytes(24).toString('base64url'),0),1]),
    e=>e?.code==='42501');
  await assert.rejects(issuerA.query(revokeSql,[owner,clientId,'x'.repeat(32),1]),
    e=>e?.code==='42501');
  await assert.rejects(revokerA.query(readSql,
    [...params('a'.repeat(32),1)]),e=>e?.code==='42501');

  const one=crypto.randomBytes(24).toString('base64url');
  const contender=crypto.randomBytes(24).toString('base64url');
  const firstRace=await Promise.all([
    issue(issuerA,one,0),issue(issuerB,contender,0)
  ]);
  assert.deepEqual(firstRace.slice().sort(),['0','1']);
  const initial=firstRace[0]==='1'?one:contender;
  assert.equal(await verify(reader,initial,1),true);
  assert.equal(await verify(reader,initial,2),false);
  assert.equal(await verify(reader,initial,1,crypto.randomBytes(32)),false);
  assert.equal(await issue(issuerA,initial,1),'0',
    'Identical grant must not be reissued at a higher revision');


  // ACTUAL OAuth code, JWT and encrypted refresh handlers, rather than a
  // simulated token predicate, read the independent restricted PG LOGIN.
  // The only trust mapping client_id -> SAI app is server-fixed, never from
  // a request parameter. The adapter rechecks role privileges on every call.
  const epochReader=pgEpochReader.createDisposableOauthPgEpochReader({
    pool:{async connect(){return {query:q=>reader.query(q),release(){}}}},
    approvedApps:[{clientId,appUri:app}],fixtureOnly:true
  });
  const consentPrefix='paper:oauth:pg-bridge:'+suffix;
  const consentRedisKey=oauthPolicy.consentKey(consentPrefix,owner,clientId);
  const consentState={redis,settings:{keyPrefix:consentPrefix,ttlSec:7200}};
  const codeState={redis,settings:{
    keyPrefix:'paper:oauth:pg-code:'+suffix,
    usedPrefix:'paper:oauth:pg-code-used:'+suffix,codeTtlSec:120
  }};
  const refreshState={redis,settings:{
    tokenPrefix:'paper:oauth:pg-refresh:'+suffix,
    familyPrefix:'paper:oauth:pg-family:'+suffix,
    revokedPrefix:'paper:oauth:pg-family-blocked:'+suffix,
    consentPrefix,ttlSec:3600
  },encKey:crypto.randomBytes(32),...oauthRefresh.methods};
  refreshState.actions={revokeFamily:p=>
    oauthRefresh.actions.revokeFamily.handler.call(refreshState,{params:p})};
  const {privateKey,publicKey}=await generateKeyPair('ES256',{extractable:true});
  const privateJwk={...await exportJWK(privateKey),alg:'ES256'};
  const publicJwk={...await exportJWK(publicKey),alg:'ES256'};
  const tokenState={settings:{
    issuer:'https://paper.example.org',
    audience:'https://paper.example.org',
    accessTtlSec:300
  },...oauthToken.methods};
  const jkt='a'.repeat(43);
  const verifier='v'.repeat(43);
  const codeChallenge=crypto.createHash('sha256').update(verifier).digest('base64url');
  const pgCall=async(name,args)=>{
    if(name==='oauth-pg-epoch.current')return epochReader.current(args);
    if(name==='oauth-pg-epoch.verify')return epochReader.verify(args);
    if(name==='oauth-consent.get')
      return oauthConsent.actions.get.handler.call(consentState,{params:args});
    if(name==='oauth-code-store.consumeCode')
      return oauthCode.actions.consumeCode.handler.call(codeState,{params:args});
    if(name==='oauth-refresh-session.issueRefreshToken')
      return oauthRefresh.actions.issueRefreshToken.handler.call(refreshState,{params:args,call:pgCall});
    if(name==='oauth-refresh-session.rotateRefreshToken')
      return oauthRefresh.actions.rotateRefreshToken.handler.call(refreshState,{params:args,call:pgCall});
    if(name==='jwk.get')return {privateJwk,publicJwk};
    throw Error('Unexpected OAuth service action '+name);
  };
  const pgCtx={call:pgCall};
  const writeConsent=async(grant)=> {
    const value={canonicalAccountId:owner,clientId,scope,grantId:grant,
      grantedAt:Math.floor(Date.now()/1000),updatedAt:Math.floor(Date.now()/1000),
      revoked:false};
    assert.equal(await redis.set(consentRedisKey,JSON.stringify(value),'EX',7200),'OK');
  };
  const identity=(grant,epoch)=>({sub:did,canonicalAccountId:owner,
    clientId,scope,consentGrantId:grant,dpopJkt:jkt,oauthPgRevision:epoch});
  const introspect=async token=>oauthToken.actions.introspectAccessToken.handler.call(
    tokenState,{...pgCtx,params:{token}});
  const codeArgs=grant=>({clientId,redirectUri:'https://paper-client.example.org/cb',
    canonicalAccountId:owner,did,scope,consentGrantId:grant,dpopJkt:jkt,
    codeChallenge,codeChallengeMethod:'S256'});
  const createCode=async grant=>oauthCode.actions.issueCode.handler.call(
    codeState,{...pgCtx,params:codeArgs(grant)});
  await assert.rejects(epochReader.current({...identity(initial,'1'),
    clientId:'https://attacker.example.org/app'}),e=>e.code==='PG_OAUTH_EPOCH_SCOPE_INVALID');
  await writeConsent(initial);
  assert.equal(await epochReader.current(identity(initial,'1')),'1');
  assert.equal(await epochReader.verify(identity(initial,'1')),true);
  assert.equal(await epochReader.verify(identity(initial,'2')),false);
  const firstCode=await createCode(initial);
  const firstResult=await oauthToken.methods.handleAuthorizationCode.call(
    tokenState,pgCtx,{
      code:firstCode.code,client_id:clientId,
      redirect_uri:'https://paper-client.example.org/cb',
      code_verifier:verifier
    },jkt);
  assert.equal((await introspect(firstResult.access_token)).active,true);
  assert.equal((await introspect(firstResult.access_token)).oauth_pg_revision,'1');
  await assert.rejects(oauthToken.methods.issueAccessToken.call(
    tokenState,{...identity(initial,'1'),oauthPgRevision:undefined},pgCtx),
    e=>e?.type==='INVALID_GRANT',
    'A direct signer call cannot promote an unversioned session');
  const liveRefresh=await oauthRefresh.actions.introspectRefreshToken.handler.call(
    refreshState,{...pgCtx,params:{refreshToken:firstResult.refresh_token}});
  assert.equal(liveRefresh.active,true);
  assert.equal(liveRefresh.oauthPgRevision,'1');
  // A previously successful primary-PG read may never cache "allowed".
  // Losing the PG authority must invalidate the *same* unexpired JWT and
  // prevent new codes/refreshes even while Redis still says active.
  const outageCall=(name,args)=>{
    if(name.startsWith('oauth-pg-epoch.'))throw Error('Injected primary PG outage');
    return pgCall(name,args);
  };
  assert.equal((await oauthToken.actions.introspectAccessToken.handler.call(
    tokenState,{call:outageCall,params:{token:firstResult.access_token}})).active,false);
  await assert.rejects(oauthRefresh.actions.issueRefreshToken.handler.call(
    refreshState,{call:outageCall,params:{...identity(initial,'1'),did}}),
    e=>e?.type==='INVALID_GRANT');
  await assert.rejects(oauthCode.actions.issueCode.handler.call(
    codeState,{call:outageCall,params:codeArgs(initial)}),
    e=>e?.type==='INVALID_GRANT');
  assert.equal((await introspect(firstResult.access_token)).active,true,
    'Healthy primary PG must admit same epoch without stale negative cache');
  // A LOGIN holding the issuer role may not impersonate the reader.
  const wrongRole=pgEpochReader.createDisposableOauthPgEpochReader({
    pool:{async connect(){return {query:q=>issuerA.query(q),release(){}}}},
    approvedApps:[{clientId,appUri:app}],fixtureOnly:true
  });
  await assert.rejects(wrongRole.current(identity(initial,'1')),
    e=>e?.code==='PG_OAUTH_EPOCH_ROLE_UNSAFE');
  const preRevokeCode=await createCode(initial);
  const redisConsentSnapshot=await redis.dumpBuffer(consentRedisKey);
  assert.ok(Buffer.isBuffer(redisConsentSnapshot));

  // Even a correctly signed, unexpired legacy JWT without a PG generation
  // must be rejected during candidate enforcement.
  const legacyJwt=await new SignJWT({
    scope,client_id:clientId,canonical_account_id:owner,
    consent_grant_id:initial,cnf:{jkt}
  }).setProtectedHeader({alg:'ES256',typ:'at+jwt'})
    .setIssuer(tokenState.settings.issuer)
    .setAudience(tokenState.settings.audience)
    .setSubject(did).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  assert.equal((await introspect(legacyJwt)).active,false);
  console.log('PASS: real authorization-code exchange, JWT PG epoch and encrypted refresh admission');

  // Capture a Redis pre-revocation grant snapshot before the PG revoke.
  const priorRedis=JSON.stringify({canonicalAccountId:owner,clientId,scope,
    grantId:initial,revoked:false});
  await redis.set(redisKey,priorRedis,'EX',120);
  const priorSnapshot=await redis.dumpBuffer(redisKey);
  assert.ok(Buffer.isBuffer(priorSnapshot)&&priorSnapshot.length>0,
    'Require actual Redis DUMP backup bytes, not a manually forged fixture');

  // The signer holds an exact-PG-transaction lock through a signed write.
  // OAuth revocation cannot acknowledge ahead of that transaction commit.
  await signer.query('BEGIN');
  const bound=await signer.query(lockSql,params(initial,1));
  assert.equal(bound.rows[0].allowed,true);
  const revoking=revoke(revokerA,initial,1);
  const order=await Promise.race([
    revoking.then(()=> 'revoked'),new Promise(resolve=>setTimeout(()=>resolve('locked'),200))
  ]);
  assert.equal(order,'locked','OAuth revoke must wait for in-flight signed write');
  await signer.query('COMMIT');
  assert.equal(await revoking,'2');
  assert.equal(await verify(reader,initial,1),false);

  // Redis can be restored to a pre-revocation grant without changing the
  // canonical PG generation: its active record must remain unauthorized.
  await redis.set(redisKey,JSON.stringify({canonicalAccountId:owner,
    clientId,scope,grantId:initial,revoked:true}),'EX',120);
  assert.equal(JSON.parse(await redis.get(redisKey)).revoked,true);
  // Use native Redis DUMP/RESTORE after PG revocation. The old Redis
  // snapshot contains an active grant, but must never override intact PG.
  assert.equal(await redis.restore(redisKey,120000,priorSnapshot,'REPLACE'),'OK');
  assert.equal(JSON.parse(await redis.get(redisKey)).revoked,false);
  assert.equal(await verify(reader,initial,1),false,
    'Redis rollback must not resurrect a PG-revoked token');

  // Restore Redis's *real* prior active grant after PG revocation. Both
  // protected JWT admission and encrypted refresh must still deny.
  assert.equal(await redis.restore(consentRedisKey,120000,redisConsentSnapshot,'REPLACE'),'OK');
  assert.equal((await introspect(firstResult.access_token)).active,false);
  const staleRefresh=await oauthRefresh.actions.introspectRefreshToken.handler.call(
    refreshState,{...pgCtx,params:{refreshToken:firstResult.refresh_token}});
  assert.equal(staleRefresh.active,false);
  await assert.rejects(oauthRefresh.actions.rotateRefreshToken.handler.call(
    refreshState,{...pgCtx,params:{refreshToken:firstResult.refresh_token,dpopJkt:jkt}}),
    e=>e?.type==='INVALID_GRANT');
  await assert.rejects(oauthRefresh.actions.issueRefreshToken.handler.call(
    refreshState,{...pgCtx,params:{...identity(initial,'1'),did}}),
    e=>e?.type==='INVALID_GRANT');
  await assert.rejects(oauthToken.methods.handleAuthorizationCode.call(
    tokenState,pgCtx,{
      code:preRevokeCode.code,client_id:clientId,
      redirect_uri:'https://paper-client.example.org/cb',
      code_verifier:verifier
    },jkt),e=>e?.type==='INVALID_GRANT');
  await assert.rejects(createCode(initial),e=>e?.type==='INVALID_GRANT');
  console.log('PASS: Redis rollback fails closed across real JWT introspection, code exchange, refresh issue/rotation/introspection');

  const second=crypto.randomBytes(24).toString('base64url');
  assert.equal(await issue(issuerA,second,2),'3');
  assert.equal(await verify(reader,initial,1),false);
  assert.equal(await verify(reader,second,3),true);
  await writeConsent(second);
  const secondToken=await oauthToken.methods.issueAccessToken.call(
    tokenState,identity(second,'3'),pgCtx);
  assert.equal((await introspect(secondToken)).active,true);
  assert.equal((await introspect(firstResult.access_token)).active,false);
  assert.equal(await redis.get(redisKey),priorRedis,
    'A restored Redis grant may lag; canonical PG still wins');
  // Both independent authorities must agree. A new PG grant must not be
  // admitted while Redis still contains an older restored generation.
  async function bothAgree(grant,revision){
    const r=JSON.parse(await redis.get(redisKey));
    return r.grantId===grant&&r.revoked===false&&r.scope===scope&&
      await verify(reader,grant,revision);
  }
  assert.equal(await bothAgree(initial,1),false);
  assert.equal(await bothAgree(second,3),false);
  await redis.set(redisKey,JSON.stringify({canonicalAccountId:owner,
    clientId,scope,grantId:second,revoked:false}),'EX',120);
  assert.equal(await bothAgree(second,3),true);

  // Two distinct revokers cannot both acknowledge the same revocation.
  const secondRace=await Promise.all([
    revoke(revokerA,second,3),revoke(revokerB,second,3)
  ]);
  assert.deepEqual(secondRace.slice().sort(),['0','4']);
  assert.equal(await verify(reader,second,3),false);
  assert.equal((await introspect(secondToken)).active,false);
  assert.equal(await revoke(revokerB,second,3),'0');

  // A native SAI revoke blocks even a new OAuth reapproval.
  const third=crypto.randomBytes(24).toString('base64url');
  assert.equal(await issue(issuerA,third,4),'5');
  await admin.query("UPDATE paper_atproto_authority.consents SET state='blocked',revision=revision+1 WHERE owner_webid=$1 AND app_uri=$2",[owner,app]);
  assert.equal(await verify(reader,third,5),false);
  await writeConsent(third);
  assert.equal(await epochReader.current(identity(third,'5')),null);
  assert.equal(await epochReader.verify(identity(third,'5')),false);
  assert.equal(await issue(issuerB,crypto.randomBytes(24).toString('base64url'),5,2),'0');
  assert.equal((await signer.query(lockSql,params(third,5))).rows[0].allowed,false);
  assert.equal(await redis.restore(redisKey,120000,priorSnapshot,'REPLACE'),'OK');
  assert.equal(await verify(reader,initial,1),false);
  assert.equal(await verify(reader,second,3),false);
  assert.equal(await verify(reader,third,5),false);
  // A native SAI/owner deletion must not strand a foreign-key-dependent
  // OAuth row or block personal-data removal. It must fail closed afterward.
  await admin.query('DELETE FROM paper_atproto_authority.consents '+
    'WHERE owner_webid=$1 AND app_uri=$2',[owner,app]);
  const residual=await admin.query(
    'SELECT count(*)::integer AS n FROM paper_atproto_authority.oauth_generations WHERE owner_webid=$1',[owner]);
  assert.equal(residual.rows[0].n,0);
  assert.equal(await verify(reader,third,5),false);
  console.log('PASS: PG18 restricted roles, CAS contention, writer row-lock/revoker serialization, Redis DUMP/RESTORE cannot revive real JWT/code/refresh handlers, native SAI block; release CLOSED');
}
let failed;
const watchdog=setTimeout(()=>{console.error('FAIL: PG/Redis recovery watchdog');process.exit(1)},90000);
try{await main()}catch(e){failed=e;process.exitCode=1;console.error(e?.stack||String(e))}
finally{
  const errors=[];
  // Namespace-scoped cleanup: never FLUSHDB or remove another test tenant.
  try {
    let cursor='0';
    do {
      const [next,keys]=await redis.scan(cursor,'MATCH','paper:oauth:pg-*:'+suffix+'*','COUNT',100);
      cursor=next;if(keys.length)await redis.unlink(...keys);
    }while(cursor!=='0');
    await redis.del(oauthPolicy.consentKey('paper:oauth:pg-bridge:'+suffix,owner,clientId));
  }catch(e){errors.push(e)}
  for(const c of clients.reverse())try{await c.end()}catch(e){errors.push(e)}
  if(admin._connected){
    if(schemaCreated)try{await admin.query('DROP SCHEMA IF EXISTS paper_atproto_authority CASCADE')}catch(e){errors.push(e)}
    for(const name of createdRoles.reverse())try{await admin.query('DROP ROLE IF EXISTS '+id(name))}catch(e){errors.push(e)}
    if(schemaCreated)for(const name of [
      'paper_oauth_epoch_signer','paper_oauth_epoch_reader',
      'paper_oauth_epoch_revoker','paper_oauth_epoch_issuer',
      'paper_atproto_consent_issuer','paper_atproto_consent_attestor',
      'paper_atproto_authority_reader','paper_atproto_authority_revoker',
      'paper_atproto_authority_importer'
    ])try{await admin.query('DROP ROLE IF EXISTS '+id(name))}catch(e){errors.push(e)}
  }
  try{await admin.end()}catch(e){errors.push(e)}
  if(redis.status==='ready'){
    try{await redis.del(redisKey)}catch(e){errors.push(e)}
    try{await redis.quit()}catch(e){redis.disconnect();errors.push(e)}
  }else redis.disconnect();
  clearTimeout(watchdog);
  if(errors.length&&!failed){process.exitCode=1;console.error('FAIL: disposable recovery cleanup',errors[0]?.message)}
}
