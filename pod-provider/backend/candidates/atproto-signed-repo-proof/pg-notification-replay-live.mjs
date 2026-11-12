'use strict';

// Disposable PostgreSQL 18 proof: operator replay is audited, credential-
// restricted, one-way from dead -> pending, and capped over the record lifetime.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {Pool,Client} from 'pg';
import ledgerModule from '../../utils/canonical-notification-pg-ledger.js';
const {createCanonicalNotificationLedger}=ledgerModule;

const dsn=process.env.ATPROTO_REPO_PROOF_DSN||'';
if(process.env.NODE_ENV!=='test' ||
   process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
   !/^postgres(?:ql)?:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(dsn)) {
  throw Error('Replay proof requires the exact disposable PostgreSQL 18 fixture');
}
const pool=new Pool({connectionString:dsn,max:3,connectionTimeoutMillis:3000,
  idleTimeoutMillis:3000,query_timeout:8000,allowExitOnIdle:true});
const prefix='paper_notification_ledger';
const name='paper_replay_test_'+crypto.randomBytes(8).toString('hex');
const ordinary='paper_replay_generic_'+crypto.randomBytes(8).toString('hex');
const secrets=[crypto.randomBytes(32).toString('base64url'),
  crypto.randomBytes(32).toString('base64url')];
const quote=s=>{
  if(!/^[a-z_][a-z0-9_]{0,62}$/u.test(s))throw Error('Invalid fixture login');
  return '"'+s+'"';
};
let operator=null,generic=null,roleCreated=[];
const ledger=createCanonicalNotificationLedger({pool});
function asLogin(login,secret){
  const uri=new URL(dsn);uri.username=login;uri.password=secret;
  return new Client({connectionString:uri.toString(),
    connectionTimeoutMillis:3000,query_timeout:8000});
}
async function deadLetter(index){
  const owner='https://paper.example.test/people/replay-'+index;
  const intentId='replay-proof-'+index;
  const actor='https://remote.example.test/verified';
  await ledger.enqueue({
    intentId,kind:'FollowAdd',protocol:'activitypub',
    recipients:[{recipient:owner,actorUri:actor,activity:{
      actor,type:'Follow',id:'https://paper.example.test/events/replay-'+index,
      object:owner
    }}]
  });
  const intentKey=crypto.createHash('sha256').update(intentId).digest('hex');
  for(let i=0;i<8;i++){
    const token=crypto.randomUUID();
    const claimed=await ledger.claim({limit:1,workerToken:token});
    assert.equal(claimed.length,1);
    assert.equal(claimed[0].intent_key,intentKey);
    const result=await ledger.fail({
      intentKey,recipientKey:claimed[0].recipient_key,
      workerToken:token,reasonCode:'PERMANENT_TEST_FAILURE'
    });
    assert.equal(result.attempts,i+1);
    if(i<7)await pool.query(
      'UPDATE '+prefix+".deliveries SET next_attempt_at=clock_timestamp()-interval '1 minute' "+
      'WHERE intent_key=$1',[Buffer.from(intentKey,'hex')]);
  }
  const record=(await pool.query(
    'SELECT encode(recipient_key,\'hex\') AS recipient_key FROM '+
    prefix+'.deliveries WHERE intent_key=$1',[Buffer.from(intentKey,'hex')]
  )).rows[0];
  return {intentKey,recipientKey:record.recipient_key};
}
async function replay(client,keys,operationId){
  return client.query(
    'SELECT was_replayed,replay_count FROM '+prefix+
    '.replay_dead_notification($1::bytea,$2::bytea,$3::uuid)',
    [Buffer.from(keys.intentKey,'hex'),Buffer.from(keys.recipientKey,'hex'),operationId]);
}
async function markDeadAgain(keys){
  for(let i=0;i<8;i++){
    const token=crypto.randomUUID();
    const claimed=await ledger.claim({limit:1,workerToken:token});
    assert.equal(claimed.length,1);
    assert.equal(claimed[0].intent_key,keys.intentKey);
    const result=await ledger.fail({
      intentKey:keys.intentKey,recipientKey:keys.recipientKey,
      workerToken:token,reasonCode:'PERMANENT_TEST_FAILURE'
    });
    assert.equal(result.attempts,i+1);
    if(i<7)await pool.query(
      'UPDATE '+prefix+".deliveries SET next_attempt_at=clock_timestamp()-interval '1 minute' "+
      'WHERE intent_key=$1',[Buffer.from(keys.intentKey,'hex')]);
  }
}
async function main(){
  let schemaCreated=false;
  try{
    const existing=await pool.query("SELECT to_regnamespace('paper_notification_ledger') AS schema");
    assert.equal(existing.rows[0].schema,null,'Do not overwrite existing canonical ledger schema');
    await pool.query(await readFile(new URL('../../sql/paper-canonical-notification-ledger-v1.sql',import.meta.url),'utf8'));
    schemaCreated=true;
    await pool.query(await readFile(new URL('../../sql/paper-notification-quarantine-replay-v2.sql',import.meta.url),'utf8'));
    for(const [index,login] of [name,ordinary].entries()){
      await pool.query('CREATE ROLE '+quote(login)+" LOGIN PASSWORD '"+secrets[index]+"' "+
        'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS');
      roleCreated.push(login);
    }
    await pool.query('GRANT paper_notification_replay_operator TO '+quote(name)+' WITH INHERIT TRUE');
    await pool.query('GRANT paper_notification_runtime TO '+quote(ordinary)+' WITH INHERIT TRUE');
    operator=asLogin(name,secrets[0]);generic=asLogin(ordinary,secrets[1]);
    await Promise.all([operator.connect(),generic.connect()]);
    const work=await deadLetter(1);
    const op=crypto.randomUUID();
    await assert.rejects(replay(generic,work,op),e=>e?.code==='42501');
    await assert.rejects(operator.query(
      'UPDATE '+prefix+".deliveries SET state='pending' WHERE intent_key=$1",
      [Buffer.from(work.intentKey,'hex')]),e=>e?.code==='42501');
    const first=await replay(operator,work,op);
    assert.deepEqual(first.rows[0],{was_replayed:true,replay_count:1});
    const duplicate=await replay(operator,work,op);
    assert.deepEqual(duplicate.rows[0],{was_replayed:false,replay_count:1});
    let state=await pool.query(
      'SELECT state,attempts FROM '+prefix+'.deliveries WHERE intent_key=$1',
      [Buffer.from(work.intentKey,'hex')]);
    assert.equal(state.rows[0].state,'pending');
    assert.equal(state.rows[0].attempts,0);

    await markDeadAgain(work);
    const second=await replay(operator,work,crypto.randomUUID());
    assert.deepEqual(second.rows[0],{was_replayed:true,replay_count:2});
    await markDeadAgain(work);
    const third=await replay(operator,work,crypto.randomUUID());
    assert.deepEqual(third.rows[0],{was_replayed:true,replay_count:3});
    await markDeadAgain(work);
    await assert.rejects(replay(operator,work,crypto.randomUUID()),
      e=>e?.code==='P0001');
    const history=await pool.query(
      'SELECT operation_id,operator_login,previous_attempts FROM '+
      prefix+'.quarantine_replays ORDER BY replayed_at');
    assert.equal(history.rowCount,3);
    assert(history.rows.every(x=>x.operator_login===name && x.previous_attempts===8));
    const quarantine=await pool.query(
      'SELECT count(*)::integer AS n,attempts FROM '+prefix+
      '.quarantine WHERE intent_key=$1 GROUP BY attempts',
      [Buffer.from(work.intentKey,'hex')]);
    assert.equal(quarantine.rows[0].n,1);
    assert.equal(quarantine.rows[0].attempts,8);
    state=await pool.query(
      'SELECT state,attempts FROM '+prefix+'.deliveries WHERE intent_key=$1',
      [Buffer.from(work.intentKey,'hex')]);
    assert.equal(state.rows[0].state,'dead');
    assert.equal(state.rows[0].attempts,8);

    console.log(JSON.stringify({
      success:true,scope:'disposable-pg18-operator-quarantine-replay',
      distinctLogins:2,operatorIdentityRecordedFromSession:true,
      runtimeRoleDeniedReplay:true,directOperatorDmlDenied:true,
      idempotentReplay:true,replayLimit:3,
      quarantineAuditRows:1,replayAuditRows:3,finalState:'dead',
      noPublicHttpEndpoint:true,noProductionActivation:true
    }));
  }finally{
    await operator?.end().catch(()=>{});
    await generic?.end().catch(()=>{});
    if(schemaCreated)await pool.query('DROP SCHEMA IF EXISTS '+prefix+' CASCADE');
    for(const login of roleCreated.reverse()){
      await pool.query('DROP OWNED BY '+quote(login));
      await pool.query('DROP ROLE '+quote(login));
    }
    if(schemaCreated)await pool.query('DROP ROLE IF EXISTS paper_notification_replay_operator');
    await pool.end();
  }
}
main().catch(e=>{
  console.error('Notification replay proof failed:',e?.code||e?.name||'UNKNOWN');
  process.exitCode=1;
});
