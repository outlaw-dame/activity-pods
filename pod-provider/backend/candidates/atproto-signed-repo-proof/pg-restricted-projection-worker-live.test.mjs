/**
 * NONACTIVATED real PostgreSQL 18 privilege and recovery acceptance.
 * Independent LOGINs; production release fuse stays closed.
 * The separate persistent Fuseki TDB2 test proves actual Jena CAS.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import {test} from 'node:test';
import {fileURLToPath} from 'node:url';
import {Pool} from 'pg';
import {createSignedRepoProofStore} from './store.mjs';
import {createRdfProjectionRecovery} from './projection-recovery.mjs';
import {createRestrictedPgProjectionOperations}
  from './pg-restricted-projection-ops.mjs';
import {assertRestrictedProjectionWorkerLogin}
  from './pg-projection-worker-role.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
if(process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_PROJECTION_ROLE_TEST_DISPOSABLE!=='confirmed'||
   !/^postgres(?:ql)?:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)){
  throw Error('Restricted projection test requires exact disposable PostgreSQL 18');
}
const admin=new Pool({connectionString:DSN,max:3,connectionTimeoutMillis:3000,
  idleTimeoutMillis:2000,allowExitOnIdle:true});
const suffix=crypto.randomBytes(7).toString('hex');
const worker='paper_project_worker_'+suffix;
const generic='paper_project_generic_'+suffix;
const signer='paper_project_signer_'+suffix;
const revoker='paper_project_revoker_'+suffix;
const names=[worker,generic,signer,revoker];
const passwords=new Map(names.map(n=>[n,crypto.randomBytes(28).toString('hex')]));
const id=n=>{if(!/^[a-z_][a-z0-9_]{0,62}$/u.test(n))throw Error('Role name');return '"'+n+'"';};
const rolePool=n=>{
  const u=new URL(DSN);u.username=n;u.password=passwords.get(n);
  return new Pool({connectionString:u.toString(),max:2,
    connectionTimeoutMillis:3000,query_timeout:6000,
    idleTimeoutMillis:2000,allowExitOnIdle:true});
};
const owner='https://paper.example.org/users/project-worker';
const did='did:plc:'+'w'.repeat(24);
const app='https://paper.example.org/apps/projection';
const grant=owner+'/data/grants/projection';
const hash=v=>crypto.createHash('sha256').update(v).digest();
const forbidden=(p,code='42501')=>assert.rejects(p,e=>e?.code===code);
const sql=p=>fs.readFile(fileURLToPath(new URL(p,import.meta.url)),'utf8');

test('PG18 separately credentialed projection worker refuses stale ACK and forbidden signing/grants',async()=>{
  let workerPool,genericPool,signerPool,revokerPool,schemas=false,cleanupError=null;
  try{
    const initial=await admin.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE "+
      "schemaname IN ('paper_atproto_repo_proof','paper_atproto_authority')"
    );
    assert.equal(initial.rows[0].n,0,'must run on a clean disposable DB');
    await admin.query(await sql('./schema.sql'));
    await admin.query(await sql('./single-record-mutation.sql'));
    await admin.query(await sql('../../sql/paper-atproto-canonical-authority-v1.sql'));
    await admin.query(await sql('./pg-restricted-writer-roles.sql'));
    await admin.query(await sql('./pg-restricted-projection-worker.sql'));
    schemas=true;
    for(const n of names){
      await admin.query('CREATE ROLE '+id(n)+
        " LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS "+
        "PASSWORD '"+passwords.get(n)+"'");
    }
    await admin.query('GRANT paper_atproto_projection_worker TO '+id(worker)+
      ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
    await admin.query('GRANT paper_atproto_repo_writer TO '+id(signer)+
      ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
    await admin.query('GRANT paper_atproto_authority_revoker TO '+id(revoker)+
      ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
    workerPool=rolePool(worker);genericPool=rolePool(generic);
    signerPool=rolePool(signer);revokerPool=rolePool(revoker);
    const admitted=await assertRestrictedProjectionWorkerLogin(workerPool);
    assert.equal(admitted.restricted,true);
    assert.equal(admitted.maySign,false);
    await forbidden(assertRestrictedProjectionWorkerLogin(admin),
      'PROJECTION_WORKER_ROLE_REQUIRED');
    await forbidden(assertRestrictedProjectionWorkerLogin(genericPool),
      'PROJECTION_WORKER_ROLE_REQUIRED');
    await forbidden(assertRestrictedProjectionWorkerLogin(signerPool),
      'PROJECTION_WORKER_ROLE_REQUIRED');

    // Adversarial real column grants: PostgreSQL table-level UPDATE
    // inspection alone misses these. The worker's next startup must
    // refuse every leaked INSERT or UPDATE grant even if narrow.
    for(const grantCase of [
      {priv:'UPDATE',column:'state',table:'paper_atproto_repo_proof.rdf_projection_jobs'},
      {priv:'UPDATE',column:'head_cid',table:'paper_atproto_repo_proof.repos'},
      {priv:'UPDATE',column:'status',table:'paper_atproto_repo_proof.native_event_outbox'},
      {priv:'INSERT',column:'block',table:'paper_atproto_repo_proof.blocks'},
      {priv:'UPDATE',column:'revision',table:'paper_atproto_authority.consents'},
      {priv:'INSERT',column:'source_proof_sha256',table:'paper_atproto_authority.identities'}
    ]){
      const statement=grantCase.priv+' ('+grantCase.column+') ON '+
        grantCase.table;
      await admin.query('GRANT '+statement+' TO '+id(worker));
      try{
        await forbidden(assertRestrictedProjectionWorkerLogin(workerPool),
          'PROJECTION_WORKER_ROLE_REQUIRED');
      }finally{
        await admin.query('REVOKE '+statement+' FROM '+id(worker));
      }
      assert.equal((await assertRestrictedProjectionWorkerLogin(workerPool)).restricted,
        true,'valid restricted privileges restored after adversarial grant');
    }

    for(const permission of [
      'DELETE ON paper_atproto_repo_proof.rdf_projection_jobs',
      'TRUNCATE ON paper_atproto_repo_proof.rdf_projection_jobs',
      'TRIGGER ON paper_atproto_repo_proof.repos',
      'REFERENCES ON paper_atproto_authority.consents'
    ]){
      await admin.query('GRANT '+permission+' TO '+id(worker));
      try{
        await forbidden(assertRestrictedProjectionWorkerLogin(workerPool),
          'PROJECTION_WORKER_ROLE_REQUIRED');
      }finally{
        await admin.query('REVOKE '+permission+' FROM '+id(worker));
      }
      assert.equal((await assertRestrictedProjectionWorkerLogin(workerPool)).restricted,true);
    }
    const extra='paper_project_extra_'+suffix;
    await admin.query('CREATE ROLE '+id(extra)+
      ' NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION');
    try{
      await admin.query('GRANT '+id(extra)+' TO '+id(worker)+
        ' WITH INHERIT FALSE,SET TRUE,ADMIN FALSE');
      try{
        await forbidden(assertRestrictedProjectionWorkerLogin(workerPool),
          'PROJECTION_WORKER_ROLE_REQUIRED');
      }finally{
        await admin.query('REVOKE '+id(extra)+' FROM '+id(worker));
      }
    }finally{await admin.query('DROP ROLE '+id(extra));}
    assert.equal((await assertRestrictedProjectionWorkerLogin(workerPool)).restricted,true);

    const keys=crypto.generateKeyPairSync('ec',{namedCurve:'secp256k1'});
    const key={
      publicKeyPem:keys.publicKey.export({format:'pem',type:'spki'}).toString(),
      signer:async bytes=>crypto.sign('sha256',bytes,{
        key:keys.privateKey,dsaEncoding:'ieee-p1363'
      })
    };
    const genesis=createSignedRepoProofStore({pool:admin,fixtureOnly:true});
    const head=await genesis.bootstrap({accountId:owner,did,...key});
    assert.equal(head.verified,true);
    await admin.query(
      'INSERT INTO paper_atproto_authority.identities '+
      '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
      "VALUES($1,$2,'active',true,1,$3)",
      [owner,did,hash('trusted-webid')]
    );
    await admin.query(
      'INSERT INTO paper_atproto_authority.consents '+
      '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256) '+
      "VALUES($1,$2,$3,'active',1,$4)",[owner,app,grant,hash('trusted-sai')]
    );
    await forbidden(genericPool.query(
      'SELECT * FROM paper_atproto_repo_proof.rdf_projection_jobs LIMIT 1'
    ));
    await forbidden(genericPool.query(
      'SELECT * FROM paper_atproto_authority.consents LIMIT 1'
    ));
    await forbidden(signerPool.query(
      'SELECT * FROM paper_atproto_repo_proof.claim_verified_projection('+
      '$1,$2,$3::uuid,$4,$5,$6,$7,$8::bigint)',
      [owner,did,crypto.randomUUID(),15,8,app,grant,1]
    ));
    await forbidden(workerPool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='applied' "+
      'WHERE account_id=$1',[owner]
    ));
    await forbidden(workerPool.query(
      "UPDATE paper_atproto_repo_proof.repos SET head_cid=$2 WHERE account_id=$1",
      [owner,head.commitCid]
    ));
    await forbidden(workerPool.query(
      'INSERT INTO paper_atproto_repo_proof.blocks(did,cid,block) '+
      'VALUES($1,$2,$3)',[did,head.commitCid,Buffer.from('forged')]
    ));
    await forbidden(workerPool.query(
      "UPDATE paper_atproto_authority.consents SET state='active' "+
      'WHERE owner_webid=$1',[owner]
    ));
    await forbidden(workerPool.query(
      'SELECT * FROM paper_atproto_authority.block_consent($1,$2,$3,1::bigint)',
      [owner,app,grant]
    ));
    await forbidden(workerPool.query('SET ROLE paper_atproto_projection_worker'));
    await forbidden(workerPool.query('SET ROLE paper_atproto_authority_reader'));
    await forbidden(workerPool.query(
      'CREATE TABLE paper_atproto_repo_proof.forbidden(x bigint)'
    ));
    const ops=await createRestrictedPgProjectionOperations({
      pool:workerPool,appUri:app,grantUri:grant,consentRevision:'1',
      fixtureOnly:true
    });
    const opts={accountId:owner,did,leaseSeconds:15,maxAttempts:8};
    const [one,two]=await Promise.all([
      ops.claim({...opts,owner:crypto.randomUUID()}),
      ops.claim({...opts,owner:crypto.randomUUID()})
    ]);
    assert.equal(one.rowCount+two.rowCount,1,
      'concurrent independently fenced PG leases have one winner');
    const live=(one.rowCount===1?one:two).rows[0];
    const failed=await ops.finishFailure({
      accountId:owner,did,claimed:live,
      state:'pending',delay:0,code:'PROJECTION_TRANSIENT_ERROR'
    });
    assert.equal(failed.rowCount,1);
    const second=await ops.claim({...opts,owner:crypto.randomUUID()});
    assert.equal(second.rowCount,1);
    assert(BigInt(second.rows[0].lease_epoch)>BigInt(live.lease_epoch));
    const staleAck=await ops.ack({
      accountId:owner,did,claimed:live,
      proof:{commitCid:head.commitCid,rootCid:head.rootCid,rev:head.rev}
    });
    assert.equal(staleAck.rowCount,0,'superseded lease cannot ACK');
    const wrongHead=await ops.ack({
      accountId:owner,did,claimed:second.rows[0],
      proof:{commitCid:'bafyre'+'f'.repeat(53),rootCid:head.rootCid,rev:head.rev}
    });
    assert.equal(wrongHead.rowCount,0,'false signed head cannot ACK');
    await ops.finishFailure({
      accountId:owner,did,claimed:second.rows[0],
      state:'pending',delay:0,code:'PROJECTION_TRANSIENT_ERROR'
    });

    let rdf={canonicalAccountId:owner,webId:owner,activityPubActorId:owner,
      atprotoDid:did,atprotoSource:'local',atprotoManaged:true,status:'active',
      repoInitialized:false,repoRootCid:null,repoRev:null,repoProjectionFence:null};
    let casWrites=0;
    const evidence=()=>genesis.verify({
      accountId:owner,did,publicKeyPem:key.publicKeyPem
    });
    const recovery=createRdfProjectionRecovery({
      pool:workerPool,fixtureOnly:true,leaseSeconds:15,maxAttempts:8,
      restrictedOperations:ops,verifyNativeEvidence:evidence,
      authorize:async ({accountId,did:requested})=>{
        const r=await workerPool.query(
          'SELECT c.state AS consent,i.state AS identity_state,i.did FROM '+
          'paper_atproto_authority.consents AS c JOIN '+
          'paper_atproto_authority.identities AS i ON i.owner_webid=c.owner_webid '+
          'WHERE c.owner_webid=$1 AND c.app_uri=$2',
          [accountId,app]
        );
        return accountId===owner&&requested===did&&r.rowCount===1&&
          r.rows[0].did===did&&r.rows[0].consent==='active'&&
          r.rows[0].identity_state==='active';
      },
      readRdf:async()=>({...rdf}),
      applyRdfFenced:async({accountId,did:requested,rootCid,rev,fence,expectedIdentity})=>{
        assert.equal(accountId,owner);assert.equal(requested,did);
        assert.deepEqual(expectedIdentity,{
          canonicalAccountId:owner,webId:owner,
          activityPubActorId:owner,atprotoDid:did
        });
        assert(BigInt(fence)>BigInt(rdf.repoProjectionFence||'0'),
          'monotonic RDF CAS never accepts stale epoch');
        casWrites++;
        rdf={...rdf,repoInitialized:true,repoRootCid:rootCid,
          repoRev:rev,repoProjectionFence:fence};
      }
    });
    const ready=await recovery.reconcile({accountId:owner,did});
    assert.equal(ready.ready,true);
    assert.equal(ready.headCid,head.commitCid);
    assert.equal(casWrites,1);
    const row=(await workerPool.query(
      'SELECT state,lease_owner,lease_until,lease_epoch,applied_at FROM '+
      'paper_atproto_repo_proof.rdf_projection_jobs WHERE account_id=$1',
      [owner]
    )).rows[0];
    assert.equal(row.state,'applied');
    assert.equal(row.lease_owner,null);
    assert.equal(row.lease_until,null);
    assert(row.applied_at);
    assert.equal((await ops.claim({
      ...opts,owner:crypto.randomUUID()
    })).rowCount,0,'an applied projection cannot be claimed again');
    const revoked=await revokerPool.query(
      'SELECT * FROM paper_atproto_authority.block_consent('+
      '$1,$2,$3,1::bigint)',[owner,app,grant]
    );
    assert.equal(revoked.rowCount,1);
    await assert.rejects(recovery.readiness({accountId:owner,did}),
      e=>e?.code==='PROJECTION_AUTH_REVOKED');
    await admin.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
      "state='pending',applied_at=NULL,lease_owner=NULL,lease_until=NULL,"+
      "next_attempt_at=clock_timestamp() WHERE account_id=$1",[owner]
    );
    assert.equal((await ops.claim({...opts,owner:crypto.randomUUID()})).rowCount,0,
      'blocked canonical consent cannot claim new projection');
    const status=(await workerPool.query(
      'SELECT state FROM paper_atproto_repo_proof.rdf_projection_jobs '+
      'WHERE account_id=$1',[owner]
    )).rows[0].state;
    assert.equal(status,'pending');
    // The provider storage release boundary remains source-controlled,
    // independent of synthetic role/lease success.
    const prev=process.env.NODE_ENV;
    try{
      process.env.NODE_ENV='production';
      await forbidden(ops.blockExhausted({accountId:owner,did,maxAttempts:8}),
        'PROJECTION_PG_ROLE_NOT_RELEASED');
    }finally{process.env.NODE_ENV=prev;}
    console.log('RESTRICTED_PROJECTION_PG18_PROOF '+JSON.stringify({
      independentLogins:true,roleAttestation:true,
      noSigning:true,noRegrant:true,noDirectProjectionUpdate:true,
      injectedColumnGrantRefusal:true,
      unexpectedTableGrantRefusal:true,unexpectedSetRoleRefusal:true,
      noSetRole:true,singleLeaseWinner:true,staleAckDenied:true,
      wrongHeadAckDenied:true,readbackBeforeAck:true,
      verifiedSignedGenesis:true,canonicalRevocationDenied:true,
      casWrites,productionAuthorization:false
    }));
  }finally{
    for(const pool of [workerPool,genericPool,signerPool,revokerPool]){
      if(pool)try{await pool.end();}catch(e){cleanupError=e;}
    }
    if(schemas){
      for(const schema of ['paper_atproto_repo_proof','paper_atproto_authority']){
        try{await admin.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE');}
        catch(e){cleanupError=e;}
      }
    }
    for(const n of names){
      try{await admin.query('DROP ROLE IF EXISTS '+id(n));}
      catch(e){cleanupError=e;}
    }
    for(const n of ['paper_atproto_projection_worker','paper_atproto_repo_writer',
      'paper_atproto_authority_revoker','paper_atproto_authority_reader',
      'paper_atproto_authority_importer']){
      try{await admin.query('DROP ROLE IF EXISTS '+id(n));}
      catch(e){cleanupError=e;}
    }
    await admin.end();
  }
  if(cleanupError)throw cleanupError;
});
