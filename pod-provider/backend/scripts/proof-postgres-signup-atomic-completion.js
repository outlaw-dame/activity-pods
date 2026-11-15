'use strict';
// True PostgreSQL 18 transaction, credential and crash/race acceptance.
// The signed-repository cryptographic CAR is independently verified by the
// existing repo workflow; this proof checks the cross-authority SQL CAS.
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {Pool}=require('pg');
const {createCandidate}=require('../candidates/postgres-account-lifecycle');
const {createDisposableSignupCompletion}=
  require('../candidates/postgres-signup-atomic-completion');
const {createPgBootstrapReadiness}=
  require('../candidates/postgres-bootstrap-readiness');

const dsn=process.env.PAPER_ACCOUNTS_TEST_DSN||'';
if(process.env.NODE_ENV!=='test' ||
    process.env.PAPER_ACCOUNTS_DISPOSABLE!=='confirmed' ||
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
    process.env.PAPER_ACCOUNT_COMPLETION_DISPOSABLE!=='confirmed' ||
    !/^postgres(?:ql)?:\/\/postgres:bench@127\.0\.0\.1:5547\/paper_account_completion_test$/u.test(dsn)) {
  throw Error('Account completion proof is restricted to the disposable PG18 database');
}
const pool=new Pool({connectionString:dsn,max:6,
  connectionTimeoutMillis:3000,idleTimeoutMillis:3000,allowExitOnIdle:true});
let readerPool=null;
const providerId='https://paper.example.org';
const appClientId='https://app.paper.example.org/app';
const appUri='https://writer.paper.example.org/app';
const pdsOrigin='https://pds.paper.example.org';
const cidA='bafyre'+'a'.repeat(53),cidB='bafyre'+'b'.repeat(53);
const rev='2222222222222';
const secret=crypto.randomBytes(32);
const uuid=()=>crypto.randomUUID();
const hmac=(purpose,value)=>crypto.createHmac('sha256',secret)
  .update(purpose+'\0'+value).digest();
const error=(p,code)=>assert.rejects(p,e=>e?.code===code);

async function migrate(){
  const list=[
    'paper-account-postgres-candidate-v1.sql',
    'paper-account-postgres-candidate-v2-signup-ledger.sql',
    'paper-account-postgres-candidate-v3-evidence-seal.sql',
    'paper-account-postgres-candidate-v4-atomic-completion.sql'
  ];
  const check=await pool.query("SELECT to_regnamespace('paper_account_candidate') AS account, "+
    "to_regnamespace('paper_atproto_repo_proof') AS repo, "+
    "to_regnamespace('paper_atproto_authority') AS consent");
  assert.deepEqual(check.rows[0],{account:null,repo:null,consent:null},
    'only an empty disposable PG18 database may run completion proof');
  for(const name of list){
    await pool.query(fs.readFileSync(path.resolve(__dirname,'../sql',name),'utf8'));
  }
  await pool.query(fs.readFileSync(path.resolve(__dirname,
    '../candidates/atproto-signed-repo-proof/schema.sql'),'utf8'));
  await pool.query(fs.readFileSync(path.resolve(__dirname,
    '../sql/paper-atproto-canonical-authority-v1.sql'),'utf8'));
  await pool.query(fs.readFileSync(path.resolve(__dirname,
    '../sql/paper-account-postgres-candidate-v5-bootstrap-proof.sql'),'utf8'));
  // Disposable exact-role acceptance: a real independent LOGIN inherits
  // only the NOLOGIN proof reader, not the migration owner or table roles.
  await pool.query("CREATE ROLE paper_account_bootstrap_runtime_test "+
    "LOGIN PASSWORD 'disposable_reader_local_only' "+
    "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS");
  await pool.query("GRANT paper_account_bootstrap_reader "+
    "TO paper_account_bootstrap_runtime_test");
}
async function setup(label,letter){
  const accountId=uuid(),operationId=uuid();
  const idempotencyKey='entryway:acct_'+uuid()+':'+crypto.randomBytes(12).toString('hex');
  const webId=providerId+'/users/'+label;
  const did='did:plc:'+letter.repeat(24);
  const handle=label+'.paper.example.org';
  const grantUri=webId+'/data/grants/repo';
  const username=label;
  const scope={
    providerId,appClientId,hmacKeyVersion:1,
    idempotencyHmac:hmac('account-signup-idempotency-v1',idempotencyKey),
    requestHmac:hmac('signup.body.v1',label),
    accountId,operationId,username
  };
  const model=createCandidate({pool,fixtureOnly:true});
  assert.equal((await model.reserveSignup(scope)).state,'reserved');
  assert.equal((await model.markSignupMayHaveSideEffects(scope)).state,
    'reconciliation_required');
  const bound=await model.change({
    providerId,accountId,operationId:uuid(),expectedGeneration:1,
    kind:'bind_unified_identity',
    webId,activityPubActorId:webId,atprotoDid:did,
    atprotoHandle:handle,atprotoPdsUrl:pdsOrigin,repoInitialized:true
  });
  assert.equal(bound.generation,2);
  const evidence={
    status:'evidence_only',productionReady:false,
    providerId,operationId,accountId,signupGeneration:2,accountGeneration:2,
    webId,did,pdsOrigin,commitCid:cidA,rootCid:cidB,rev,
    projectionFence:'1',outboxStatus:'pending'
  };
  const sealer=createCandidate({pool,fixtureOnly:true,
    verifyNewSignupEvidence:async()=>evidence});
  assert.equal((await sealer.sealSignupEvidence(scope)).state,'evidence_sealed');
  await pool.query(
    'INSERT INTO paper_atproto_repo_proof.repos '+
    '(account_id,did,rev,head_cid,root_cid) VALUES ($1,$2,$3,$4,$5)',
    [webId,did,rev,cidA,cidB]
  );
  await pool.query(
    'INSERT INTO paper_atproto_repo_proof.blocks(did,cid,block) VALUES '+
    '($1,$2,$4),($1,$3,$5)',[did,cidA,cidB,
      Buffer.from('signed-v3-commit-fixture'),Buffer.from('mst-root-fixture')]
  );
  await pool.query(
    'INSERT INTO paper_atproto_repo_proof.native_event_outbox '+
    '(did,commit_cid,rev,kind) VALUES ($1,$2,$3,$4)',
    [did,cidA,rev,'at.commit.v1']
  );
  await pool.query(
    'INSERT INTO paper_atproto_repo_proof.rdf_projection_jobs '+
    '(account_id,did,head_cid,root_cid,rev,state,lease_epoch,applied_at) '+
    "VALUES ($1,$2,$3,$4,$5,'applied',1,clock_timestamp())",
    [webId,did,cidA,cidB,rev]
  );
  const digest=crypto.createHash('sha256').update(label).digest();
  await pool.query(
    'INSERT INTO paper_atproto_authority.identities '+
    '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
    "VALUES ($1,$2,'active',true,1,$3)",[webId,did,digest]
  );
  await pool.query(
    'INSERT INTO paper_atproto_authority.consents '+
    '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256) '+
    "VALUES ($1,$2,$3,'active',1,$4)",[webId,appUri,grantUri,digest]
  );
  const proof={
    ...evidence,status:'disposable_provider_verified',signedRepoVerified:true,
    solidVerified:true,hostedPdsVerified:true,ownerConsentVerified:true,
    handle,appUri,grantUri,consentRevision:'1'
  };
  return {scope,accountId,operationId,webId,did,grantUri,proof,
    username,handle,idempotencyKey};
}
function completion(fixture,overrides={}){
  return createDisposableSignupCompletion({
    pool:overrides.pool||pool,fixtureOnly:true,
    verifyCurrent:overrides.verifyCurrent||(
      async s=>{
        assert.equal(s.providerId,providerId);
        assert.equal(s.operationId,fixture.operationId);
        assert.equal(s.accountId,fixture.accountId);
        return {...fixture.proof};
      }
    )
  });
}
async function getState(f){
  const [a,s]=await Promise.all([
    pool.query('SELECT state,generation FROM paper_account_candidate.accounts WHERE account_id=$1',[f.accountId]),
    pool.query('SELECT state,generation,completion_proof_digest FROM '+
      'paper_account_candidate.signup_operations WHERE operation_id=$1',[f.operationId])
  ]);
  return {account:a.rows[0],signup:s.rows[0]};
}
async function revoke(f){
  return pool.query(
    'SELECT * FROM paper_atproto_authority.block_consent($1,$2,$3,1::bigint)',
    [f.webId,appUri,f.grantUri]
  );
}
function deferred(){
  let release;const promise=new Promise(r=>{release=r;});
  return {promise,release};
}
async function main(){
  let errorInRun=null;
  try{
    await migrate();
    readerPool=new Pool({
      connectionString:'postgresql://paper_account_bootstrap_runtime_test:'+
        'disposable_reader_local_only@127.0.0.1:5547/paper_account_completion_test',
      max:2,connectionTimeoutMillis:3000,statement_timeout:3000,
      query_timeout:3500,idleTimeoutMillis:3000,allowExitOnIdle:true
    });
    const ok=await setup('good','a');
    let calls=0;
    const allowed=completion(ok,{verifyCurrent:async ()=>{
      calls++;return {...ok.proof};
    }});
    const ready=await allowed.complete(ok.scope);
    assert.equal(ready.state,'ready');assert.equal(ready.replay,false);
    assert.equal(ready.releaseAuthorized,false);
    assert.equal(ready.canAuthenticate,false);
    assert.equal((await getState(ok)).account.state,'ready');
    assert.equal((await getState(ok)).signup.state,'ready');
    // Readiness must be proved against the same PostgreSQL journal and
    // current SAI revocation revision, not a provider process-local Map.
    // The read-only function never creates grants, sessions or identities.
    const bootstrapConfig={
      pool:readerPool,providerId,appClientId,appUri,hmacKey:secret,
      hmacKeyVersion:1,fixtureOnly:true,requireRestrictedReader:true
    };
    const identityClaim=fixture=>({
      idempotencyKey:fixture.idempotencyKey,username:fixture.username,
      webId:fixture.webId,actorId:fixture.webId,
      atprotoDid:fixture.did,atprotoHandle:fixture.handle
    });
    const pgBootstrap=createPgBootstrapReadiness(bootstrapConfig);
    assert.equal(await pgBootstrap.assertReaderRole(),true,
      'the independently authenticated reader LOGIN must have only exact proof access');
    const readiness=await pgBootstrap.assertCurrent(identityClaim(ok));
    assert.equal(readiness.verified,true);
    assert.equal(readiness.accountId,ok.accountId);
    assert.equal(readiness.grantUri,ok.grantUri);
    assert.equal(readiness.consentRevision,'1');
    assert.equal(readiness.canAuthenticate,false);
    assert.equal(readiness.releaseAuthorized,false);
    assert.equal(Object.isFrozen(readiness),true);
    for(const [change,expectedCode] of [
      [{username:'another-owner'},'BOOTSTRAP_PG_NOT_READY'],
      [{webId:providerId+'/users/other',actorId:providerId+'/users/other'},'BOOTSTRAP_PG_NOT_READY'],
      [{atprotoDid:'did:plc:'+'b'.repeat(24)},'BOOTSTRAP_PG_NOT_READY'],
      [{atprotoHandle:'other.paper.example.org'},'BOOTSTRAP_PG_NOT_READY'],
      [{idempotencyKey:'entryway:acct_'+uuid()+':'+crypto.randomBytes(12).toString('hex')},
        'BOOTSTRAP_PG_NOT_READY'],
      [{actorId:providerId+'/users/other'},'BOOTSTRAP_PG_SCOPE_INVALID']
    ]) {
      await error(pgBootstrap.assertCurrent({...identityClaim(ok),...change}),expectedCode);
    }
    await error(createPgBootstrapReadiness({
      ...bootstrapConfig,appClientId:'https://foreign.paper.example.org/app'
    }).assertCurrent(identityClaim(ok)),'BOOTSTRAP_PG_NOT_READY');
    await error(createPgBootstrapReadiness({
      ...bootstrapConfig,appUri:'https://another.paper.example.org/app'
    }).assertCurrent(identityClaim(ok)),'BOOTSTRAP_PG_NOT_READY');
    await error(createPgBootstrapReadiness({
      ...bootstrapConfig,hmacKey:crypto.randomBytes(32)
    }).assertCurrent(identityClaim(ok)),'BOOTSTRAP_PG_NOT_READY');

    // The deployable reader role is limited to EXECUTE on the exact lookup.
    // It cannot enumerate accounts or read raw operation HMACs.
    // A PostgreSQL superuser can execute the SECURITY DEFINER function
    // but must never qualify as the provider-owned runtime reader login.
    await error(createPgBootstrapReadiness({
      ...bootstrapConfig,pool
    }).assertCurrent(identityClaim(ok)),'BOOTSTRAP_PG_ROLE_UNAUTHORIZED');

    const roleClient=await pool.connect();
    try {
      await roleClient.query('BEGIN');
      // A privileged migration login cannot impersonate the correctly
      // permissioned runtime role with SET ROLE: session_user must match.
      await roleClient.query('SET LOCAL ROLE paper_account_bootstrap_runtime_test');
      await error(createPgBootstrapReadiness({
        ...bootstrapConfig,
        pool:{query:(...args)=>roleClient.query(...args)},
        // This is an already-borrowed admin session; call the role probe
        // directly, not the proof path which requires pool.connect().
        requireRestrictedReader:false
      }).assertReaderRole(),'BOOTSTRAP_PG_ROLE_UNAUTHORIZED');
      await roleClient.query('SET LOCAL ROLE paper_account_bootstrap_reader');
      // The NOLOGIN role may exercise the definer's narrow function, but
      // a deployed provider must use a separately verified LOGIN. The
      // runtime role probe intentionally rejects this SET ROLE session.
      const narrow=createPgBootstrapReadiness({
        ...bootstrapConfig,
        pool:{query:(...args)=>roleClient.query(...args)},
        requireRestrictedReader:false
      });
      assert.equal((await narrow.assertCurrent(identityClaim(ok))).verified,true);
      await error(createPgBootstrapReadiness({
        ...bootstrapConfig,
        pool:{query:(...args)=>roleClient.query(...args)},
        // This is an already-borrowed admin session; call the role probe
        // directly, not the proof path which requires pool.connect().
        requireRestrictedReader:false
      }).assertReaderRole(),'BOOTSTRAP_PG_ROLE_UNAUTHORIZED');
      for(const table of [
        'paper_account_candidate.accounts',
        'paper_account_candidate.signup_operations'
      ]) {
        const privilege=await roleClient.query(
          'SELECT has_table_privilege(current_user,$1,$2) AS allowed',
          [table,'SELECT']
        );
        assert.equal(privilege.rows[0].allowed,false,'read role must not have table SELECT: '+table);
      }
      // An inaccessible schema cannot even be resolved as a regclass;
      // test its denial directly rather than raising SQLSTATE 42501 and
      // leaving the transaction aborted before fixture teardown.
      for(const schema of [
        'paper_atproto_authority','paper_atproto_repo_proof'
      ]) {
        const privilege=await roleClient.query(
          'SELECT has_schema_privilege(current_user,$1,$2) AS allowed',
          [schema,'USAGE']
        );
        assert.equal(privilege.rows[0].allowed,false,
          'read role must not browse protected schema: '+schema);
      }
    } finally {
      try { await roleClient.query('ROLLBACK'); } finally { roleClient.release(); }
    }
    const replay=await allowed.complete(ok.scope);
    assert.equal(replay.replay,true);
    assert.equal(calls,1,'already-ready replay never reruns external verification');
    const live=await allowed.readCurrentReady(ok.scope);
    assert.equal(live.state,'ready');
    assert.equal(live.accountId,ok.accountId);
    assert.equal(live.webId,ok.webId);
    assert.equal(live.appUri,appUri);
    assert.equal(live.grantUri,ok.grantUri);
    assert.equal(live.consentRevision,'1');
    assert.equal(live.canAuthenticate,false,'read path never issues auth');
    assert.equal(live.releaseAuthorized,false,'read path never releases signup');
    // Post-completion replay is an online authority check. A historically
    // ready journal must fail when the current repo/projection/outbox drifts.
    const assertReplayBlocked=async()=>{
      await error(allowed.readCurrentReady(ok.scope),'SIGNUP_COMPLETION_CURRENT_AUTHORITY_DENIED');
      await error(allowed.complete(ok.scope),'SIGNUP_COMPLETION_CURRENT_AUTHORITY_DENIED');
      await error(pgBootstrap.assertCurrent(identityClaim(ok)),'BOOTSTRAP_PG_NOT_READY');
    };
    await pool.query('UPDATE paper_atproto_repo_proof.repos SET head_cid=$2 WHERE did=$1',
      [ok.did,cidB]);
    await assertReplayBlocked();
    await pool.query('UPDATE paper_atproto_repo_proof.repos SET head_cid=$2 WHERE did=$1',
      [ok.did,cidA]);
    assert.equal((await allowed.readCurrentReady(ok.scope)).state,'ready');

    await pool.query("UPDATE paper_atproto_repo_proof.rdf_projection_jobs "+
      "SET state='blocked',applied_at=NULL WHERE did=$1",[ok.did]);
    await assertReplayBlocked();
    await pool.query("UPDATE paper_atproto_repo_proof.rdf_projection_jobs "+
      "SET state='applied',applied_at=clock_timestamp() WHERE did=$1",[ok.did]);
    assert.equal((await allowed.readCurrentReady(ok.scope)).state,'ready');

    await pool.query('UPDATE paper_atproto_repo_proof.native_event_outbox '+
      'SET blocked_at=clock_timestamp() WHERE did=$1 AND commit_cid=$2',[ok.did,cidA]);
    await assertReplayBlocked();
    await pool.query('UPDATE paper_atproto_repo_proof.native_event_outbox '+
      'SET blocked_at=NULL WHERE did=$1 AND commit_cid=$2',[ok.did,cidA]);
    assert.equal((await allowed.readCurrentReady(ok.scope)).state,'ready');

    // An older terminally blocked pending event is an authority fence
    // even if the latest signed head and projection are otherwise valid.
    await pool.query('INSERT INTO paper_atproto_repo_proof.native_event_outbox '+
      '(did,commit_cid,rev,kind,blocked_at) '+
      "VALUES ($1,$2,$3,'at.commit.v1',clock_timestamp())",[ok.did,cidB,rev]);
    await assertReplayBlocked();
    await pool.query('DELETE FROM paper_atproto_repo_proof.native_event_outbox '+
      'WHERE did=$1 AND commit_cid=$2',[ok.did,cidB]);
    assert.equal((await allowed.readCurrentReady(ok.scope)).state,'ready');
    assert.equal((await pgBootstrap.assertCurrent(identityClaim(ok))).verified,true);

    await error(allowed.readCurrentReady({
      ...ok.scope,appClientId:'https://foreign-app.example.org'
    }),'SIGNUP_COMPLETION_CURRENT_NOT_READY');
    await error(allowed.readCurrentReady({
      ...ok.scope,idempotencyHmac:crypto.randomBytes(32)
    }),'SIGNUP_COMPLETION_CURRENT_NOT_READY');
    await error(createCandidate({pool,fixtureOnly:true}).change({
      providerId,accountId:ok.accountId,operationId:uuid(),
      expectedGeneration:3,kind:'transition_state',nextState:'ready'
    }),'ACCOUNT_SIGNUP_COMPLETION_SEAL_REQUIRED');
    await createCandidate({pool,fixtureOnly:true}).change({
      providerId,accountId:ok.accountId,operationId:uuid(),
      expectedGeneration:3,kind:'transition_state',nextState:'suspended'
    });
    await error(allowed.complete(ok.scope),'SIGNUP_COMPLETION_ACCOUNT_NOT_ACTIVE');
    assert.equal((await getState(ok)).account.state,'suspended',
      'an old ready journal may not re-activate a suspended account');
    await error(pgBootstrap.assertCurrent(identityClaim(ok)),'BOOTSTRAP_PG_NOT_READY');

    const revoked=await setup('revoked','b');
    const blocked=await revoke(revoked);
    assert.equal(blocked.rowCount,1);
    assert.equal(blocked.rows[0].new_state,'blocked');
    await error(completion(revoked).complete(revoked.scope),
      'SIGNUP_COMPLETION_CONSENT_REVOKED');
    assert.deepEqual((await getState(revoked)).account.state,'provisioning');

    const drift=await setup('repo-drift','c');
    await pool.query(
      "UPDATE paper_atproto_repo_proof.repos SET rev='2222222222223' WHERE did=$1",
      [drift.did]
    );
    await error(completion(drift).complete(drift.scope),'SIGNUP_COMPLETION_REPO_CHANGED');
    assert.equal((await getState(drift)).signup.state,'evidence_sealed');

    const noHost=await setup('no-host','d');
    await error(completion(noHost,{verifyCurrent:async()=>
      ({...noHost.proof,hostedPdsVerified:false})}).complete(noHost.scope),
      'SIGNUP_COMPLETION_PROOF_INVALID');
    assert.equal((await getState(noHost)).account.state,'provisioning');

    // A PDS endpoint is a strict origin, not a resource path or a value
    // normalized opportunistically by URL.href. Refuse ambiguous origins.
    const badOrigin=await setup('bad-origin','k');
    for(const endpoint of [
      'https://pds.paper.example.org/',
      'https://pds.paper.example.org/pds',
      'https://pds.paper.example.org?mode=unsafe',
      'https://user:pass@pds.paper.example.org',
      'http://pds.paper.example.org'
    ]) {
      await error(completion(badOrigin,{verifyCurrent:async()=>({
        ...badOrigin.proof,pdsOrigin:endpoint
      })}).complete(badOrigin.scope),'SIGNUP_COMPLETION_SCOPE_INVALID');
    }
    assert.equal((await getState(badOrigin)).signup.state,'evidence_sealed');

    const racing=await setup('racing','e');
    const racers=await Promise.allSettled([
      completion(racing).complete(racing.scope),
      completion(racing).complete(racing.scope)
    ]);
    assert.equal(racers.filter(x=>x.status==='fulfilled').length,2);
    assert.equal(racers.filter(x=>x.status==='fulfilled'&&!x.value.replay).length,1);
    assert.equal(racers.filter(x=>x.status==='fulfilled'&&x.value.replay).length,1);

    const rolled=await setup('rolled','f');
    const rollbackPool={query:(...args)=>pool.query(...args),
      connect:async()=>{
        const c=await pool.connect();
        return {query:(sql,...args)=>{
          if(typeof sql==='string' && sql.includes("SET state='ready'") &&
             sql.includes('signup_operations')) throw Error('injected fail-before-journal-CAS');
          return c.query(sql,...args);
        },release:(...args)=>c.release(...args)};
      }};
    await assert.rejects(completion(rolled,{pool:rollbackPool}).complete(rolled.scope));
    assert.equal((await getState(rolled)).account.state,'provisioning');
    assert.equal((await getState(rolled)).signup.state,'evidence_sealed');

    const uncertain=await setup('uncertain','g');
    const unknownPool={query:(...args)=>pool.query(...args),
      connect:async()=>{
        const c=await pool.connect();
        return {query:async(sql,...args)=>{
          if(sql==='COMMIT'){
            await c.query(sql,...args);
            throw Error('simulated lost COMMIT reply');
          }
          return c.query(sql,...args);
        },release:(...args)=>c.release(...args)};
      }};
    await error(completion(uncertain,{pool:unknownPool}).complete(uncertain.scope),
      'SIGNUP_COMPLETION_COMMIT_OUTCOME_UNKNOWN');
    assert.equal((await getState(uncertain)).account.state,'ready');
    assert.equal((await getState(uncertain)).signup.state,'ready');
    assert.equal((await completion(uncertain).complete(uncertain.scope)).replay,true);

    const blockedDuringProof=await setup('proof-race','h');
    const raced=completion(blockedDuringProof,{verifyCurrent:async()=>{
      await revoke(blockedDuringProof);
      return {...blockedDuringProof.proof};
    }});
    await error(raced.complete(blockedDuringProof.scope),
      'SIGNUP_COMPLETION_CONSENT_REVOKED');
    assert.equal((await getState(blockedDuringProof)).signup.state,'evidence_sealed');

    const serialization=await setup('serialization','i');
    const reached=deferred(),proceed=deferred();
    const lockPool={query:(...args)=>pool.query(...args),
      connect:async()=>{
        const c=await pool.connect();
        return {query:async(sql,...args)=>{
          const result=await c.query(sql,...args);
          if(typeof sql==='string' && sql.includes('FOR SHARE OF c,i')){
            reached.release();await proceed.promise;
          }
          return result;
        },release:(...args)=>c.release(...args)};
      }};
    const running=completion(serialization,{pool:lockPool})
      .complete(serialization.scope);
    await reached.promise;
    let revokeFinished=false;
    const revoking=revoke(serialization).then(v=>{revokeFinished=true;return v;});
    await new Promise(r=>setTimeout(r,120));
    assert.equal(revokeFinished,false,
      'revocation cannot pass locked active grant during completion CAS');
    proceed.release();
    assert.equal((await running).state,'ready');
    assert.equal((await revoking).rows[0].new_state,'blocked');
    await error(pgBootstrap.assertCurrent(identityClaim(serialization)),
      'BOOTSTRAP_PG_NOT_READY');
    // Historical ready+signed-PDS completion must NOT be replayable as
    // current authorization once the canonical grant is blocked.
    await error(completion(serialization).readCurrentReady(serialization.scope),
      'SIGNUP_COMPLETION_CURRENT_AUTHORITY_DENIED');
    await error(completion(serialization).complete(serialization.scope),
      'SIGNUP_COMPLETION_CURRENT_AUTHORITY_DENIED');
    await error(pool.query(
      "SELECT state FROM paper_atproto_authority.consents WHERE owner_webid=$1",
      [serialization.webId]).then(v=>{
        assert.equal(v.rows[0].state,'blocked');
        const e=Error('canonical consent blocked after COMMIT');e.code='DENIED';throw e;
      }),'DENIED');

    const production=await setup('production','j');
    const beforeEnv=process.env.NODE_ENV;
    try{
      process.env.NODE_ENV='production';
      await error(completion(production).complete(production.scope),
        'SIGNUP_COMPLETION_NOT_RELEASED');
      await error(completion(production).readCurrentReady(production.scope),
        'SIGNUP_COMPLETION_NOT_RELEASED');
      await error(pgBootstrap.assertCurrent(identityClaim(production)),
        'BOOTSTRAP_PG_NOT_RELEASED');
    }finally{process.env.NODE_ENV=beforeEnv;}
    assert.equal((await getState(production)).account.state,'provisioning');

    const stats=await pool.query('SELECT count(*)::int AS n FROM '+
      "paper_account_candidate.signup_operations WHERE state='ready'");
    assert.equal(stats.rows[0].n,4);
    const idle=await pool.query("SELECT count(*)::int AS n FROM pg_stat_activity "+
      "WHERE datname=current_database() AND state='idle in transaction'");
    assert.equal(idle.rows[0].n,0);
    console.log(JSON.stringify({success:true,scope:'disposable-pg18-atomic-new-signup',
      completedAccounts:stats.rows[0].n,missingHostedPdsDenied:true,
      staleSignedHeadDenied:true,revokedConsentDenied:true,
       completedReplayRepoProjectionOutboxFenced:true,
       restrictedProviderReaderProven:true,
       blockedHistoricalOutboxDenied:true,
      serializedConcurrentCompletion:true,transactionRollback:true,
      uncertainCommitRecovered:true,revocationLockSerialized:true,
      productionReleaseClosed:true,idleTransactions:idle.rows[0].n}));
  }catch(e){errorInRun=e;throw e;}
  finally{
    let cleanup=null;
    if(readerPool){
      try{await readerPool.end();}catch(e){cleanup=e;}
    }
    for(const s of ['paper_account_candidate','paper_atproto_repo_proof',
      'paper_atproto_authority']){
      try{await pool.query('DROP SCHEMA IF EXISTS '+s+' CASCADE');}
      catch(e){cleanup=e;}
    }
    for(const role of ['paper_account_bootstrap_runtime_test',
      'paper_account_bootstrap_reader',
      'paper_atproto_authority_importer',
      'paper_atproto_authority_revoker','paper_atproto_authority_reader']){
      try{await pool.query('DROP ROLE IF EXISTS '+role);}catch(e){cleanup=e;}
    }
    await pool.end();
    if(cleanup&&!errorInRun)throw cleanup;
  }
}
main().catch(e=>{
  console.error('Atomic signup proof failed:',e?.code||e?.name||'UNKNOWN',
    String(e?.message||'').slice(0,220),String(e?.stack||'').split('\n').slice(0,5).join(' | '));
  process.exitCode=1;
});
