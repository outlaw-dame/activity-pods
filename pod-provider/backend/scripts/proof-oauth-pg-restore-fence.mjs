// Live PG18 + Redis 8.2, NONACTIVATED OAuth restore-fence candidate.
// No production credentials, user accounts or externally reachable ports.
// Proves rollback of ephemeral Redis state cannot override intact canonical PG.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import Redis from 'ioredis';

const dsn='postgres://paper_probe:probe_local_only@127.0.0.1:5549/atproto_signed_repo_proof_test';
const redisUrl='redis://127.0.0.1:6398';
if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_PG_RESTORE_DSN!==dsn||
   process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE!=='confirmed'||
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
  await admin.query(sql1);
  schemaCreated=true;
  await admin.query(sql2);
  await admin.query(sql4);
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

  // Capture a Redis pre-revocation grant snapshot before the PG revoke.
  const priorRedis=JSON.stringify({canonicalAccountId:owner,clientId,scope,
    grantId:initial,revoked:false});
  await redis.set(redisKey,priorRedis,'EX',120);

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
  // Simulate Redis restoring its older AOF/RDB content after PG revocation.
  await redis.set(redisKey,priorRedis,'EX',120);
  assert.equal(JSON.parse(await redis.get(redisKey)).revoked,false);
  assert.equal(await verify(reader,initial,1),false,
    'Redis rollback must not resurrect a PG-revoked token');
  const second=crypto.randomBytes(24).toString('base64url');
  assert.equal(await issue(issuerA,second,2),'3');
  assert.equal(await verify(reader,initial,1),false);
  assert.equal(await verify(reader,second,3),true);
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
  assert.equal(await revoke(revokerB,second,3),'0');

  // A native SAI revoke blocks even a new OAuth reapproval.
  const third=crypto.randomBytes(24).toString('base64url');
  assert.equal(await issue(issuerA,third,4),'5');
  await admin.query("UPDATE paper_atproto_authority.consents SET state='blocked',revision=revision+1 WHERE owner_webid=$1 AND app_uri=$2",[owner,app]);
  assert.equal(await verify(reader,third,5),false);
  assert.equal(await issue(issuerB,crypto.randomBytes(24).toString('base64url'),5,2),'0');
  assert.equal((await signer.query(lockSql,params(third,5))).rows[0].allowed,false);
  await redis.set(redisKey,priorRedis,'EX',120);
  assert.equal(await verify(reader,initial,1),false);
  assert.equal(await verify(reader,second,3),false);
  assert.equal(await verify(reader,third,5),false);
  console.log('PASS: PG18 restricted roles, CAS contention, writer row-lock/revoker serialization, Redis restore cannot revive PG revocation, native SAI block; release CLOSED');
}
let failed;
const watchdog=setTimeout(()=>{console.error('FAIL: PG/Redis recovery watchdog');process.exit(1)},90000);
try{await main()}catch(e){failed=e;process.exitCode=1;console.error(e?.stack||String(e))}
finally{
  const errors=[];
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
