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
    await pool.query(fs.readFileSync(path.resolve(__dirname,'../sql/paper-account-postgres-candidate-v2-signup-ledger.sql'),'utf8'));
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
    // New signup operations share the exact same account row and PG
    // transaction. Neither RPC retries nor an expired caller may mint
    // another DID for an already reserved operation.
    const fixtureHmacKey=crypto.randomBytes(32);
    const hmac=(domain,value)=>crypto.createHmac('sha256',fixtureHmacKey)
      .update(domain+'\0'+value).digest();
    const signupId=id(), signupOp=id(), app='https://app.paper.example';
    const signup={
      providerId:provider,accountId:signupId,operationId:signupOp,
      username:'signup-user',appClientId:app,hmacKeyVersion:1,
      idempotencyHmac:hmac('account-signup-idempotency-v1','key-1'),
      requestHmac:hmac('account-signup-request-v1','request-1')
    };
    assert.deepEqual(await model.reserveSignup(signup),{
      operationId:signupOp,accountId:signupId,state:'reserved',generation:1,replay:false
    });
    assert.deepEqual(await model.reserveSignup({...signup,accountId:id(),operationId:id()}),{
      operationId:signupOp,accountId:signupId,state:'reserved',generation:1,replay:true
    });
    await rejected(model.reserveSignup({...signup,
      requestHmac:hmac('account-signup-request-v1','different')}),'ACCOUNT_SIGNUP_IDEMPOTENCY_CONFLICT');
    assert.equal((await model.markSignupMayHaveSideEffects(signup)).state,'reconciliation_required');
    const repeated=await model.markSignupMayHaveSideEffects(signup);
    assert.equal(repeated.replay,true,'repeated remote-RPC fence never authorizes a retry');
    assert.equal(repeated.generation,2,'fence cannot advance twice');
    assert.equal((await model.readSignup(signup)).state,'reconciliation_required');
    assert.equal(await model.readSignup({...signup,providerId:other}),null,'provider scope');
    await rejected(model.markSignupMayHaveSideEffects({...signup,appClientId:'https://foreign.paper.example'}),
      'ACCOUNT_SIGNUP_RECONCILIATION_REQUIRED');
    assert.equal((await model.reserveSignup({...signup,accountId:id(),operationId:id()})).replay,true);

    // A real PostgreSQL journal may ask the authoritative Solid provider
    // to verify one exact new account without importing existing identities.
    const signupBind=await model.change({providerId:provider,accountId:signupId,
      operationId:id(),expectedGeneration:1,kind:'bind_unified_identity',
      ...identity('signup-user')});
    assert.equal(signupBind.generation,2);
    let solidCalls=0;
    const solidCall=async (action,params)=>{
      solidCalls++;
      if(action==='auth.account.findByWebId'){
        assert.equal(params.webId,identity('signup-user').webId);
        return {'@id':params.webId,disabled:false};
      }
      if(action==='identitybindings.getByCanonicalAccountId'){
        assert.equal(params.canonicalAccountId,identity('signup-user').webId);
        return {webId:params.canonicalAccountId,
          activityPubActorId:params.canonicalAccountId,
          atprotoDid:identity('signup-user').atprotoDid,
          atprotoSource:'local',atprotoManaged:true};
      }
      if(action==='auth.awaitBootstrapComplete')return {webId:params.webId,complete:true};
      throw Error('Unexpected Solid proof action');
    };
    const solidProof=await model.verifySignupSolidReadiness({...signup,call:solidCall});
    assert.equal(solidProof.complete,true);
    assert.equal(solidProof.operationId,signupOp);
    assert.equal(solidProof.accountId,signupId);
    assert.equal(solidProof.generation,2);
    assert.equal(solidCalls,3);
    await rejected(model.verifySignupSolidReadiness({...signup,
      call:async (action,params)=>action==='auth.account.findByWebId'
        ? {'@id':'local',disabled:false}
        : action==='identitybindings.getByCanonicalAccountId'
          ? {webId:params.canonicalAccountId,
              activityPubActorId:'https://evil.example/other',
              atprotoDid:identity('signup-user').atprotoDid,
              atprotoSource:'local',atprotoManaged:true}
          : {webId:params.webId,complete:true}
    }), 'SOLID_SIGNUP_PROOF_IDENTITY_MISMATCH');
    assert.equal(await model.readSignup(signup).then(x=>x.state),
      'reconciliation_required','read-only Solid evidence never marks signup completed');

    const sameName=await Promise.allSettled(Array.from({length:6},(_,i)=>model.reserveSignup({
      ...signup,username:'signup-race',accountId:id(),operationId:id(),
      idempotencyHmac:hmac('account-signup-idempotency-v1','race-'+i),
      requestHmac:hmac('account-signup-request-v1','race-'+i)
    })));
    assert.equal(sameName.filter(x=>x.status==='fulfilled').length,1);
    assert.equal(sameName.filter(x=>x.status==='rejected'&&x.reason.code==='ACCOUNT_USERNAME_CONFLICT').length,5);
    const oldCount=await pool.query(
      "SELECT count(*)::int AS n FROM paper_account_candidate.accounts WHERE provider_id=$1 AND username_key='signup-race'",[provider]);
    assert.equal(oldCount.rows[0].n,1);

    // A lost COMMIT reply is not a rolled-back transaction. Execute the
    // actual COMMIT, then simulate transport loss; verify no false retry.
    const lost={
      ...signup,username:'lost-commit',accountId:id(),operationId:id(),
      idempotencyHmac:hmac('account-signup-idempotency-v1','lost'),
      requestHmac:hmac('account-signup-request-v1','lost')
    };
    const ambiguousPool={
      async connect(){
        const c=await pool.connect();
        return {
          query:async (...args)=>{
            if(args[0]==='COMMIT'){
              await c.query(...args);
              throw new Error('simulated lost COMMIT acknowledgement');
            }
            return c.query(...args);
          },
          release:discard=>c.release(discard)
        };
      }
    };
    await rejected(createCandidate({pool:ambiguousPool,fixtureOnly:true}).reserveSignup(lost),
      'ACCOUNT_COMMIT_OUTCOME_UNKNOWN');
    assert.equal((await model.readSignup(lost)).accountId,lost.accountId,
      'database committed despite the lost transport reply');
    assert.equal((await model.reserveSignup({...lost,accountId:id(),operationId:id()})).replay,true,
      'the original operation survives and forbids another account');

    process.stdout.write(JSON.stringify({ok:true,schema:'paper.accounts.candidate.v1',postgres:18,
      tests:['read-only Solid authority proof','durable signup reservation','uncertain remote commit','replay fence','lost PostgreSQL COMMIT','disabled-by-default','provider scope','unique username race','idempotency','unified AP/AT identity constraints','WebID conflict',
        'rollback','generation fence','valid transition graph','deletion','no orphaned locks']})+'\n');
  }finally{await pool.end();}
}
main().catch(e=>{console.error('[ACCOUNT-CANDIDATE]',e.code||e.message);process.exitCode=1;});
