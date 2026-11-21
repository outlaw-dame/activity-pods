/**
 * DISPOSABLE proof of two physically independent PG18 failure domains:
 * canonical owner/SAI + OAuth and external append-only recovery witness.
 * WORM object readback is a test transport substitute; NO production
 * Object Lock or cloud storage is claimed by this test. Release CLOSED.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import pg from 'pg';
import Redis from 'ioredis';
import {generateKeyPair,exportJWK} from 'jose';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const oauthToken=require('../services/oauth/oauth-token.service.js');
const {createDisposableOauthWitnessReader}=require('../candidates/oauth-external-witness-reader.js');
const mainDsn='postgres://paper_probe:probe_local_only@127.0.0.1:5549/atproto_signed_repo_proof_test';
const witnessDsn='postgres://witness_probe:fixture_witness_only@127.0.0.1:5550/oauth_witness_disposable';
const redisUrl='redis://127.0.0.1:6398';
if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_WITNESS_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_PG_EPOCH_DISPOSABLE!=='confirmed'||
   process.env.PAPER_OAUTH_PG_RESTORE_DSN!==mainDsn||
   process.env.PAPER_OAUTH_WITNESS_DSN!==witnessDsn||
   process.env.PAPER_OAUTH_EPOCH_REDIS_URL!==redisUrl){
  throw Error('Refusing non-disposable recovery witness fixture');
}
const {Client}=pg;
const main=new Client({connectionString:mainDsn,connectionTimeoutMillis:3000,query_timeout:9000});
const root=new Client({connectionString:witnessDsn,connectionTimeoutMillis:3000,query_timeout:9000});
const redis=new Redis(redisUrl,{lazyConnect:true,enableOfflineQueue:false,
 autoResendUnfulfilledCommands:false,maxRetriesPerRequest:1,connectTimeout:2500});
const salt=crypto.randomBytes(7).toString('hex');
const owner='https://paper.example.org/users/witness-'+salt;
const clientId='https://paper-client.example.org/oauth';
const app='https://paper.example.org/apps/paper';
const grantUri=owner+'/data/grants/paper';
const did='did:plc:'+'w'.repeat(24);
const scope='atproto repo:app.bsky.feed.post?action=create';
const scopeHash=crypto.createHash('sha256').update(scope).digest();
const hash=s=>crypto.createHash('sha256').update(s).digest();
const grant1=crypto.randomBytes(24).toString('base64url');
const grant2=crypto.randomBytes(24).toString('base64url');
const redisKey='paper:oauth:witness-proof:'+salt;
const consentKey='paper:oauth:witness:'+salt;
const roles={issuer:'paper_oauth_witness_issuer',
  revoker:'paper_oauth_witness_revoker',
  attestor:'paper_oauth_witness_attestor',
  reader:'paper_oauth_witness_reader',
  ordinary:null};
const clients=[],accounts=[];
const id=s=>'"'+s.replaceAll('"','""')+'"';
const sql=path=>fs.readFile(new URL(path,import.meta.url),'utf8');
let madeMain=false,madeWitness=false,error=null;
const current=(c,grant,rev)=>c.query(
  'SELECT paper_atproto_authority.verify_oauth_generation('+
  '$1,$2,$3,$4,$5,$6::bigint) AS allowed',
  [owner,app,clientId,grant,scopeHash,rev]
).then(r=>r.rows[0].allowed);
const wverify=(c,grant,rev)=>c.query(
  'SELECT paper_oauth_restore_witness.verify('+
  '$1,$2,$3,$4::bigint) AS allowed',
  [owner,clientId,hash(grant),rev]
).then(r=>r.rows[0].allowed);
async function admitted(c,grant,rev) {
  // This is the required two-authority AND, not an OR or cached PG result.
  const [primary,witness]=await Promise.all([
    current(main,grant,rev),wverify(c,grant,rev)
  ]);
  return primary===true&&witness===true;
}
async function actor(kind){
  const name='paper_restore_'+kind+'_'+salt;
  const secret=crypto.randomBytes(18).toString('hex');
  await root.query('CREATE ROLE '+id(name)+
    " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+secret+"'");
  accounts.push(name);
  if(roles[kind])await root.query('GRANT '+roles[kind]+' TO '+id(name)+
    ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
  const dsn=new URL(witnessDsn);dsn.username=name;dsn.password=secret;
  const c=new Client({connectionString:dsn.toString(),connectionTimeoutMillis:3000,query_timeout:9000});
  await c.connect();clients.push(c);
  assert.equal((await c.query('SELECT current_user AS u')).rows[0].u,name);
  if(kind==='ordinary'){
    // The ordinary login has NO schema USAGE. PostgreSQL deliberately
    // refuses a name-resolving privilege query, before table lookup.
    const schema=(await c.query(
      "SELECT has_schema_privilege(current_user,"+
      "'paper_oauth_restore_witness','USAGE') AS allowed")).rows[0];
    assert.equal(schema.allowed,false);
  }else{
    const role=(await c.query(
      "SELECT pg_catalog.has_table_privilege(current_user,"+
      "'paper_oauth_restore_witness.current_epochs','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') AS tables,"+
      "pg_catalog.has_table_privilege(current_user,"+
      "'paper_oauth_restore_witness.events','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') AS events,"+
      "pg_catalog.pg_has_role(current_user,'paper_oauth_witness_issuer','SET') AS can_set"
    )).rows[0];
    assert.equal(role.tables,false);assert.equal(role.events,false);
    assert.equal(role.can_set,false);
  }
  await assert.rejects(c.query('SELECT * FROM paper_oauth_restore_witness.current_epochs'),
    e=>e?.code==='42501');
  return c;
}
async function transition(c,kind,grant,expected,op){
  const fn=kind==='active'?'issue':'block';
  const r=await c.query(
    'SELECT paper_oauth_restore_witness.'+fn+
    '($1,$2,$3,$4::bigint,$5::uuid) AS rev',
    [owner,clientId,hash(grant),expected,op]);
  return String(r.rows[0].rev);
}
async function seal(c,op,revision,eventHash){
  const result=await c.query(
   'SELECT paper_oauth_restore_witness.seal('+
    '$1,$2,$3::bigint,$4::uuid,$5::bytea) AS ok',
    [owner,clientId,revision,op,eventHash]);
  return result.rows[0].ok;
}
async function receipt(c,op,revision){
  const r=await c.query(
    'SELECT paper_oauth_restore_witness.get_unsealed_receipt('+
    '$1,$2,$3::bigint,$4::uuid) AS digest',
    [owner,clientId,revision,op]);
  assert.equal(r.rowCount,1);return r.rows[0].digest;
}
async function mainTest(){
  await main.connect();await root.connect();await redis.connect();
  assert.equal(await redis.ping(),'PONG');
  assert.match(await redis.info('server'),/redis_version:8\.2\./u);
  const primaryId=(await main.query('SELECT system_identifier::text AS id FROM pg_control_system()')).rows[0].id;
  const witnessId=(await root.query('SELECT system_identifier::text AS id FROM pg_control_system()')).rows[0].id;
  assert.notEqual(primaryId,witnessId,'Witness MUST be a different PostgreSQL cluster');
  assert.equal((await main.query("SELECT to_regnamespace('paper_atproto_authority') AS ns")).rows[0].ns,null);
  assert.equal((await root.query("SELECT to_regnamespace('paper_oauth_restore_witness') AS ns")).rows[0].ns,null);
  await main.query(await sql('../sql/paper-atproto-canonical-authority-v1.sql'));madeMain=true;
  await main.query(await sql('../sql/paper-atproto-canonical-authority-v2-owner-consent.sql'));
  await main.query(await sql('../sql/paper-atproto-canonical-authority-v4-oauth-generations.sql'));
  await main.query(await sql('../sql/paper-atproto-canonical-authority-v5-oauth-current.sql'));
  await root.query(await sql('../sql/paper-oauth-external-restore-witness-v1.sql'));madeWitness=true;
  // pg@9 no longer guarantees queued concurrent query() calls on one
  // connection; create each independently authenticated role serially.
  const issuer=await actor('issuer');
  const revoker=await actor('revoker');
  const attestor=await actor('attestor');
  const reader=await actor('reader');
  const ordinary=await actor('ordinary');
  await assert.rejects(ordinary.query(
    'SELECT paper_oauth_restore_witness.verify($1,$2,$3,$4)',
    [owner,clientId,hash(grant1),1]),e=>e?.code==='42501');
  await assert.rejects(issuer.query(
    'SELECT paper_oauth_restore_witness.block($1,$2,$3,$4,$5)',
    [owner,clientId,hash(grant1),1,crypto.randomUUID()]),e=>e?.code==='42501');
  await assert.rejects(revoker.query(
    'SELECT paper_oauth_restore_witness.issue($1,$2,$3,$4,$5)',
    [owner,clientId,hash(grant1),0,crypto.randomUUID()]),e=>e?.code==='42501');
  await assert.rejects(reader.query(
    'SELECT paper_oauth_restore_witness.seal($1,$2,$3,$4,$5)',
    [owner,clientId,1,crypto.randomUUID(),hash(grant1)]),e=>e?.code==='42501');
  await main.query(
    'INSERT INTO paper_atproto_authority.identities '+
    '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
    "VALUES ($1,$2,'active',true,1,$3)",[owner,did,hash(owner)]);
  await main.query(
    'INSERT INTO paper_atproto_authority.consents '+
    '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256,'+
    'activation_operation,activation_request_sha256,activation_native_readback_at) '+
    "VALUES ($1,$2,$3,'active',1,$4,$5,$4,clock_timestamp())",
    [owner,app,grantUri,hash(grantUri),crypto.randomUUID()]);
  const issuePg=async(grant,expected)=>String((await main.query(
    'SELECT paper_atproto_authority.issue_oauth_generation('+
    '$1,$2,$3,$4,$5,$6::bigint,1::bigint) AS rev',
    [owner,app,clientId,grant,scopeHash,expected]
  )).rows[0].rev);
  const revokePg=async(grant,expected)=>String((await main.query(
    'SELECT paper_atproto_authority.revoke_oauth_generation('+
    '$1,$2,$3,$4::bigint) AS rev',
    [owner,clientId,grant,expected]
  )).rows[0].rev);

  const witnessReader=createDisposableOauthWitnessReader({
    pool:{async connect(){return {query:q=>reader.query(q),release(){}}}},
    clientIds:[clientId],fixtureOnly:true
  });
  const unsuitableReader=createDisposableOauthWitnessReader({
    pool:{async connect(){return {query:q=>root.query(q),release(){}}}},
    clientIds:[clientId],fixtureOnly:true
  });
  const identity=(grant,epoch)=>({
    sub:did,canonicalAccountId:owner,clientId,scope,
    consentGrantId:grant,oauthPgRevision:epoch,dpopJkt:'a'.repeat(43)
  });
  await assert.rejects(unsuitableReader.verify(identity(grant1,'1')),
    e=>e?.code==='PG_OAUTH_WITNESS_ROLE_UNSAFE');
  await assert.rejects(witnessReader.verify({...identity(grant1,'1'),
    clientId:'https://attacker.example.org/oauth'}),
    e=>e?.code==='PG_OAUTH_WITNESS_SCOPE_INVALID');
  const {privateKey,publicKey}=await generateKeyPair('ES256',{extractable:true});
  const privateJwk={...await exportJWK(privateKey),alg:'ES256'};
  const publicJwk={...await exportJWK(publicKey),alg:'ES256'};
  const tokenState={
    settings:{issuer:'https://paper.example.org',
      audience:'https://paper.example.org',accessTtlSec:300},
    ...oauthToken.methods
  };
  const pgCall=async(name,p)=>{
    if(name==='jwk.get')return {privateJwk,publicJwk};
    if(name==='oauth-consent.get'){
      const r=await redis.get(consentKey);
      return r?JSON.parse(r):null;
    }
    if(name==='oauth-witness-epoch.verify')return witnessReader.verify(p);
    if(name==='oauth-pg-epoch.current'){
      if(p.canonicalAccountId!==owner||p.clientId!==clientId||
         p.scope!==scope)return null;
      const q=await main.query(
        'SELECT paper_atproto_authority.current_oauth_generation('+
        '$1,$2,$3,$4,$5) AS revision',
        [owner,app,clientId,p.consentGrantId,scopeHash]);
      return q.rows[0].revision===null?null:String(q.rows[0].revision);
    }
    if(name==='oauth-pg-epoch.verify'){
      if(p.canonicalAccountId!==owner||p.clientId!==clientId||
         p.scope!==scope)return false;
      return current(main,p.consentGrantId,p.oauthPgRevision);
    }
    throw Error('Unexpected OAuth witness proof service '+name);
  };
  const pgCtx={call:pgCall};
  const issueToken=async(grant,epoch)=>
    oauthToken.methods.issueAccessToken.call(tokenState,identity(grant,epoch),pgCtx);
  const introspect=async(jwt,ctx=pgCtx)=>
    oauthToken.actions.introspectAccessToken.handler.call(tokenState,
      {call:ctx.call,params:{token:jwt}});
  const redisOld=JSON.stringify({canonicalAccountId:owner,clientId,
    scope,grantId:grant1,revoked:false});
  assert.equal(await redis.set(consentKey,redisOld,'EX',180),'OK');
  const redisSnapshot=await redis.dumpBuffer(consentKey);
  assert.ok(Buffer.isBuffer(redisSnapshot));

  const op1=crypto.randomUUID();
  assert.equal(await transition(issuer,'active',grant1,0,op1),'1');
  assert.equal(await issuePg(grant1,0),'1');
  assert.equal(await admitted(reader,grant1,1),false,'Unsealed witness must never authorize');
  await assert.rejects(issueToken(grant1,'1'),e=>e?.type==='INVALID_GRANT',
    'An unsealed witness must block real signed JWT issuance');
  const digest1=await receipt(attestor,op1,1);
  assert.ok(Buffer.isBuffer(digest1)&&digest1.length===32);
  // WORM readback is test-double logic: immutable and append-only in-process,
  // not a real R2/MinIO bucket. Production must use externally locked receipt.
  const immutable=new Map();
  const objectKey=(rev)=>hash(owner+'\0'+clientId).toString('hex')+'/'+rev;
  const putOnce=(key,value)=>{
    if(immutable.has(key))throw Error('Simulated immutable receipt overwrite');
    immutable.set(key,Buffer.from(value));
  };
  putOnce(objectKey(1),digest1);
  assert.ok(immutable.get(objectKey(1)).equals(digest1));
  assert.equal(await seal(attestor,op1,1,hash('forged receipt')),false);
  assert.equal(await seal(attestor,op1,1,digest1),true);
  assert.equal(await admitted(reader,grant1,1),true);
  const firstJwt=await issueToken(grant1,'1');
  assert.equal((await introspect(firstJwt)).active,true);
  await assert.rejects(issueToken(grant1,undefined),
    e=>e?.type==='INVALID_GRANT');
  const unavailableCtx={call:async(name,p)=>{
    if(name==='oauth-witness-epoch.verify')throw Error('Witness network partition');
    return pgCall(name,p);
  }};
  assert.equal((await introspect(firstJwt,unavailableCtx)).active,false,
    'A cached signed JWT must not survive independent witness outage');
  await assert.rejects(oauthToken.methods.issueAccessToken.call(
    tokenState,identity(grant1,'1'),unavailableCtx),
    e=>e?.type==='INVALID_GRANT');
  assert.equal((await introspect(firstJwt)).active,true,
    'Witness recovery may resume without cached positive authority');

  assert.equal(JSON.parse(await redis.get(consentKey)).revoked,false,
    'Active Redis grant remains the pre-revocation snapshot');

  // ACK revocation in independent witness FIRST, before even attempting
  // canonical PG and ephemeral Redis; no cross-store distributed atomicity.
  const revokeOp=crypto.randomUUID();
  assert.equal(await transition(revoker,'blocked',grant1,1,revokeOp),'2');
  assert.equal(await admitted(reader,grant1,1),false,
    'Independent witness must deny old token immediately');
  assert.equal((await introspect(firstJwt)).active,false,
    'The signed JWT must be denied immediately on witness ACK');
  await assert.rejects(issueToken(grant1,'1'),e=>e?.type==='INVALID_GRANT');
  assert.equal(await revokePg(grant1,1),'2');
  await redis.set(consentKey,JSON.stringify({owner,clientId,grantId:grant1,revoked:true}),'EX',180);
  const digest2=await receipt(attestor,revokeOp,2);
  putOnce(objectKey(2),digest2);
  assert.ok(immutable.get(objectKey(2)).equals(digest2));
  assert.equal(await seal(attestor,revokeOp,2,digest2),true);

  // Model a logically restored pre-revocation PostgreSQL row. This is
  // NOT physical PITR: genuine restore, WAL/failover, and WORM readback
  // are explicit remaining hosted acceptance gates.
  await main.query(
    "UPDATE paper_atproto_authority.oauth_generations SET state='active',"+
    'revision=1,grant_id=$2,scope_sha256=$3 WHERE owner_webid=$1',
    [owner,grant1,scopeHash]);
  assert.equal(await redis.restore(consentKey,120000,redisSnapshot,'REPLACE'),'OK');
  assert.equal(await current(main,grant1,1),true,
    'The restored primary alone would incorrectly accept stale authority');
  assert.equal(JSON.parse(await redis.get(consentKey)).revoked,false);
  assert.equal(await admitted(reader,grant1,1),false,
    'Independently intact witness rejects both restored PG and Redis');
  assert.equal((await introspect(firstJwt)).active,false,
    'Restored PG and Redis cannot reactivate a real signed JWT');
  assert.equal(await transition(issuer,'active',grant2,1,crypto.randomUUID()),'0');
  assert.equal(await transition(revoker,'blocked',grant1,1,crypto.randomUUID()),'0');
  const op3=crypto.randomUUID();
  assert.equal(await transition(issuer,'active',grant2,2,op3),'3');
  assert.equal(await admitted(reader,grant2,3),false,
    'A newer unsealed witness may NOT promote a restored primary');
  // Restore operator first catches up PG to witnessed state; no blind
  // retry or automatic reapproval after PITR without fresh owner login.
  await main.query(
    "UPDATE paper_atproto_authority.oauth_generations SET state='blocked',"+
    'revision=2 WHERE owner_webid=$1',[owner]);
  assert.equal(await issuePg(grant2,2),'3');
  assert.equal(await redis.set(consentKey,JSON.stringify({
    canonicalAccountId:owner,clientId,scope,grantId:grant2,revoked:false
  }),'EX',180),'OK');
  assert.equal(await admitted(reader,grant2,3),false);
  await assert.rejects(issueToken(grant2,'3'),
    e=>e?.type==='INVALID_GRANT',
    'A real JWT signer must reject an unsealed new epoch');
  const digest3=await receipt(attestor,op3,3);
  putOnce(objectKey(3),digest3);
  assert.equal(await seal(attestor,op3,3,digest3),true);
  assert.equal(await admitted(reader,grant2,3),true);
  const secondJwt=await issueToken(grant2,'3');
  assert.equal((await introspect(secondJwt)).active,true);
  assert.equal((await introspect(firstJwt)).active,false);
  assert.equal(await admitted(reader,grant1,1),false);
  const oldOp=crypto.randomUUID();
  assert.equal(await transition(issuer,'active',grant1,3,oldOp),'0',
    'Old grant digest cannot be reused at a later epoch');
  const op4=crypto.randomUUID();
  assert.equal(await transition(revoker,'blocked',grant2,3,op4),'4');
  assert.equal(await admitted(reader,grant2,3),false);
  assert.equal((await introspect(secondJwt)).active,false);
  assert.equal(await transition(revoker,'blocked',grant2,3,crypto.randomUUID()),'0');
  console.log('PASS: two independent PostgreSQL18 clusters, restricted reader, real signed JWT issue/introspection fail closed on witness outage, unsealed transition and restored PG/Redis, stale epoch replay; release CLOSED');
}
const watchdog=setTimeout(()=>{console.error('Witness proof timed out');process.exit(1)},100000);
try{await mainTest()}catch(e){error=e;process.exitCode=1;console.error(e?.stack||String(e))}
finally{
 const errs=[];
 for(const c of clients.reverse())try{await c.end()}catch(e){errs.push(e)}
 if(madeWitness)try{await root.query('DROP SCHEMA paper_oauth_restore_witness CASCADE')}catch(e){errs.push(e)}
 for(const role of accounts.reverse())try{await root.query('DROP ROLE IF EXISTS '+id(role))}catch(e){errs.push(e)}
 if(madeWitness)for(const role of Object.values(roles).filter(Boolean))
  try{await root.query('DROP ROLE IF EXISTS '+id(role))}catch(e){errs.push(e)}
 if(madeMain)try{await main.query('DROP SCHEMA paper_atproto_authority CASCADE')}catch(e){errs.push(e)}
 if(madeMain)for(const role of [
  'paper_oauth_epoch_issuer','paper_oauth_epoch_revoker','paper_oauth_epoch_reader',
  'paper_oauth_epoch_signer','paper_atproto_consent_issuer',
  'paper_atproto_consent_attestor','paper_atproto_authority_importer',
  'paper_atproto_authority_revoker','paper_atproto_authority_reader'
 ])try{await main.query('DROP ROLE IF EXISTS '+id(role))}catch(e){errs.push(e)}
 if(redis.status==='ready'){
  try{await redis.del(redisKey)}catch(e){errs.push(e)}
  try{await redis.quit()}catch(e){errs.push(e);redis.disconnect()}
 }else redis.disconnect();
 for(const c of [root,main])try{await c.end()}catch(e){errs.push(e)}
 clearTimeout(watchdog);
 if(errs.length&&!error){process.exitCode=1;console.error('Witness fixture cleanup failed',errs[0]?.message)}
}
