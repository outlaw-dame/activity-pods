'use strict';
// Genuine disposable PostgreSQL 18 acceptance. No real account/credential data.
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {Pool}=require('pg');
const {createCandidate}=require('../candidates/postgres-account-lifecycle');
const DSN=process.env.PAPER_ACCOUNTS_TEST_DSN||'';
if(process.env.PAPER_ACCOUNTS_DISPOSABLE!=='confirmed'||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5547\/paper_accounts_test$/.test(DSN)) {
  throw new Error('Refusing non-disposable account database target');
}
const pool=new Pool({connectionString:DSN,max:4,connectionTimeoutMillis:2500,idleTimeoutMillis:3000,allowExitOnIdle:true});
const model=createCandidate({pool,fixtureOnly:true});
const id=()=>crypto.randomUUID();
const provider='https://paper.example';
const other='https://other.example';
const web=(name)=>'https://paper.example/pods/'+name;
const identity=(name)=>({webId:web(name),activityPubActorId:web(name),atprotoDid:'did:plc:'+name.padEnd(24,'a').slice(0,24),atprotoHandle:name+'.paper.example',atprotoPdsUrl:'https://pds.paper.example',repoInitialized:true});
async function rejected(promise,code){
  await assert.rejects(promise,error=>error.code===code,
    'Expected '+code);
}
async function main(){
  try{
    const start=await pool.query("SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_account_candidate'");
    assert.equal(start.rows[0].n,0,'disposable schema must start absent');
    await pool.query(fs.readFileSync(path.resolve(__dirname,'../sql/paper-account-postgres-candidate-v1.sql'),'utf8'));
    const locked=createCandidate({pool});
    await rejected(locked.reserve({providerId:provider,accountId:id(),username:'blocked'}),'ACCOUNT_CANDIDATE_NOT_RELEASED');

    const a=id();
    assert.deepEqual(await model.reserve({providerId:provider,accountId:a,username:'alice'}),
      {accountId:a,generation:1,state:'reserved',replay:false});
    assert.equal((await model.reserve({providerId:provider,accountId:a,username:'alice'})).replay,true);
    await rejected(model.reserve({providerId:provider,accountId:a,username:'bob'}),'ACCOUNT_ID_COLLISION');
    await rejected(model.reserve({providerId:other,accountId:a,username:'alice'}),'ACCOUNT_ID_COLLISION');

    const competing=Array.from({length:8},()=>model.reserve({providerId:provider,accountId:id(),username:'thehandle'}));
    const results=await Promise.allSettled(competing);
    assert.equal(results.filter(x=>x.status==='fulfilled').length,1,'one canonical username winner');
    assert.equal(results.filter(x=>x.status==='rejected'&&x.reason.code==='ACCOUNT_USERNAME_CONFLICT').length,7);
    const b=id();
    assert.equal((await model.reserve({providerId:other,accountId:b,username:'alice'})).state,'reserved');
    assert.equal(await model.read({providerId:other,accountId:a}),null,'tenant isolation');

    const invalid=id();
    await model.reserve({providerId:provider,accountId:invalid,username:'invalid'});
    const base={providerId:provider,accountId:invalid,expectedGeneration:1,kind:'bind_unified_identity'};
    await rejected(model.change({...base,operationId:id(),webId:web('invalid')}),'ACCOUNT_UNIFIED_ACTOR_MISMATCH');
    await rejected(model.change({...base,operationId:id(),...identity('invalid'),activityPubActorId:web('other')}),'ACCOUNT_UNIFIED_ACTOR_MISMATCH');
    await rejected(model.change({...base,operationId:id(),...identity('invalid'),atprotoDid:'did:web:paper.example'}),'ACCOUNT_UNIFIED_DID_REQUIRED');
    await rejected(model.change({...base,operationId:id(),...identity('invalid'),repoInitialized:false}),'ACCOUNT_UNIFIED_REPOSITORY_INCOMPLETE');
    await rejected(model.change({...base,operationId:id(),...identity('invalid'),atprotoPdsUrl:undefined}),'ACCOUNT_UNIFIED_PDS_REQUIRED');
    await rejected(model.change({providerId:provider,accountId:invalid,operationId:id(),expectedGeneration:1,kind:'transition_state',nextState:'ready'}),'ACCOUNT_INVALID_TRANSITION');
    const attach=id();
    const assigned=await model.change({providerId:provider,accountId:a,operationId:attach,expectedGeneration:1,
      kind:'bind_unified_identity',...identity('alice')});
    assert.equal(assigned.generation,2);
    assert.equal((await model.change({providerId:provider,accountId:a,operationId:attach,
      expectedGeneration:1,kind:'bind_unified_identity',...identity('alice')})).replay,true);
    await rejected(model.change({providerId:provider,accountId:a,operationId:attach,expectedGeneration:1,
      kind:'bind_unified_identity',...identity('evil')}),'ACCOUNT_OPERATION_CONFLICT');
    await rejected(model.change({providerId:other,accountId:a,operationId:id(),expectedGeneration:2,
      kind:'transition_state',nextState:'ready'}),'ACCOUNT_NOT_FOUND');
    await rejected(model.change({providerId:provider,accountId:a,operationId:id(),expectedGeneration:1,
      kind:'transition_state',nextState:'ready'}),'ACCOUNT_STALE_GENERATION');

    const second=id();
    await model.reserve({providerId:provider,accountId:second,username:'alice2'});
    await rejected(model.change({providerId:provider,accountId:second,operationId:id(),expectedGeneration:1,
      kind:'bind_unified_identity',...identity('alice')}),'23505');
    assert.equal((await model.read({providerId:provider,accountId:second})).state,'reserved','unique collision rolls back');

    const ready=await model.change({providerId:provider,accountId:a,operationId:id(),expectedGeneration:2,
      kind:'transition_state',nextState:'ready'});
    assert.equal(ready.generation,3);
    const suspend=await model.change({providerId:provider,accountId:a,operationId:id(),expectedGeneration:3,
      kind:'transition_state',nextState:'suspended'});
    assert.equal(suspend.generation,4);
    await rejected(model.change({providerId:provider,accountId:a,operationId:id(),expectedGeneration:4,
      kind:'bind_unified_identity',...identity('replacement')}),'ACCOUNT_INVALID_TRANSITION');
    await model.change({providerId:provider,accountId:a,operationId:id(),expectedGeneration:4,
      kind:'transition_state',nextState:'deleting'});
    await model.change({providerId:provider,accountId:a,operationId:id(),expectedGeneration:5,
      kind:'transition_state',nextState:'deleted'});
    await rejected(model.change({providerId:provider,accountId:a,operationId:id(),expectedGeneration:6,
      kind:'transition_state',nextState:'ready'}),'ACCOUNT_INVALID_TRANSITION');
    const row=await model.read({providerId:provider,accountId:a});
    assert.equal(row.state,'deleted');
    assert.equal(row.webid,row.activitypub_actor_uri);
    assert.equal(row.atproto_did,identity('alice').atprotoDid);
    assert.equal(row.atproto_repo_initialized,true);
    assert.equal(row.generation,6);
    const ledger=await pool.query('SELECT count(*)::int AS n FROM paper_account_candidate.transitions WHERE account_id=$1',[a]);
    assert.equal(ledger.rows[0].n,5,'replay and aborted transactions must not duplicate ledger rows');
    const locks=await pool.query('SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname=current_database() AND state=$1',['idle in transaction']);
    assert.equal(locks.rows[0].n,0);
    process.stdout.write(JSON.stringify({ok:true,schema:'paper.accounts.candidate.v1',postgres:18,
      tests:['disabled-by-default','provider scope','unique username race','idempotency','unified AP/AT identity constraints','WebID conflict',
        'rollback','generation fence','valid transition graph','deletion','no orphaned locks']})+'\n');
  }finally{await pool.end();}
}
main().catch(e=>{console.error('[ACCOUNT-CANDIDATE]',e.code||e.message);process.exitCode=1;});
