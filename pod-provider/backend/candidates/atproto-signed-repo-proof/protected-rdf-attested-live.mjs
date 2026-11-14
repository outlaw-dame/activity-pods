/**
 * Independent real PG18/Jena TDB2, NONACTIVATED cross-store authority proof.
 *
 * Separate ephemeral login roles: projection worker, read-only RDF attestor,
 * canonical revoker, and unprivileged ordinary app. The attestor reads an
 * isolated Shiro-protected TDB2 dataset, not a worker-provided RDF object.
 * "prepare" commits proof state; "verify" executes after Fuseki restart.
 * "cleanup" destroys disposable DB roles and schemas even on CI failure.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {Pool} from 'pg';
import {createSignedRepoProofStore} from './store.mjs';
import {createRdfProjectionRecovery} from './projection-recovery.mjs';
import {buildFencedRepoProjectionSparql} from './fuseki-fence.mjs';
import {assertRestrictedRdfAttestorLogin} from './pg-protected-rdf-attestor-role.mjs';
import {createIndependentProtectedRdfAttestor,
  makeDisposableProtectedFusekiReader} from './protected-rdf-attestor.mjs';
import {createAttestedPgProjectionOperations} from './pg-attested-projection-ops.mjs';

const phase=process.argv[2];
const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
const flags=process.env.NODE_ENV==='test'&&
 process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
 process.env.ATPROTO_PROJECTION_ROLE_TEST_DISPOSABLE==='confirmed'&&
 process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE==='confirmed'&&
 process.env.FUSEKI_ISOLATION_URL==='http://127.0.0.1:3041';
if(!flags||!['prepare','verify','cleanup'].includes(phase)||
 !/^postgres(?:ql)?:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)||
 typeof process.env.RUNNER_TEMP!=='string'||
 !process.env.RUNNER_TEMP.startsWith('/')){
 throw Error('Refusing non-disposable cross-store proof target');
}
const META=path.join(process.env.RUNNER_TEMP,'paper-rdf-attestation-disposable.json');
const accountId='https://paper.example.org/users/rdf-attested';
const did='did:plc:'+'z'.repeat(24);
const appUri='https://paper.example.org/apps/atproto-projection';
const grantUri=accountId+'/data/grants/repository';
const subject='urn:paper:atproto:proof:attested-binding';
const prefix='PREFIX apods: <http://activitypods.org/ns/core#> ';
const admin=new Pool({connectionString:DSN,max:3,
 connectionTimeoutMillis:3000,query_timeout:8000,idleTimeoutMillis:2000,
 allowExitOnIdle:true});
const sqlBase=new URL('./',import.meta.url);
const readSql=async name=>fs.readFile(new URL(name,sqlBase),'utf8');
const hashed=s=>crypto.createHash('sha256').update(s).digest();
const id=value=>{if(!/^[a-z_][a-z0-9_]{0,62}$/u.test(value))throw Error('Unsafe role name');
 return '"'+value+'"';};
const credentials=Object.freeze({
 projector: 'fixture-projector:fixture-projector-only',
 ordinary: 'fixture-ordinary:fixture-ordinary-only'
});
const denied=async promise=>assert.rejects(promise,e=>e?.code==='42501');
function rolePool(name,password){
 const url=new URL(DSN);url.username=name;url.password=password;
 return new Pool({connectionString:url.toString(),max:2,
  connectionTimeoutMillis:3000,query_timeout:6000,
  idleTimeoutMillis:2000,allowExitOnIdle:true});
}
async function fuseki(kind,body,principal='projector'){
 const controller=new AbortController();
 const timeout=setTimeout(()=>controller.abort(),8000);
 try{
  const r=await fetch(process.env.FUSEKI_ISOLATION_URL+
   '/protected-proof/'+kind,{
    method:'POST',headers:{
      authorization:'Basic '+Buffer.from(credentials[principal]).toString('base64'),
      'content-type':kind==='update'?'application/sparql-update':'application/sparql-query',
      accept:'application/sparql-results+json'
    },body,signal:controller.signal,redirect:'manual'
  });
  const responseBody=await r.text();
  assert.ok(kind==='update'?r.status===200||r.status===204:r.status===200,
    'Authorized protected '+kind+' expected 200/204; HTTP '+r.status+
    ': '+responseBody.slice(0,180));
  return kind==='query'?JSON.parse(responseBody).results.bindings:null;
 }finally{clearTimeout(timeout);}
}
async function seedProtected(){
 const s='<'+subject+'>';
 await fuseki('update',prefix+'INSERT DATA { '+s+
  ' a apods:AtprotoIdentityBinding ;'+
  ' apods:canonicalAccountId "'+accountId+'" ;'+
  ' apods:webId <'+accountId+'> ;'+
  ' apods:activityPubActorId <'+accountId+'> ;'+
  ' apods:atprotoDid "'+did+'" ;'+
  ' apods:atprotoManaged true ;'+
  ' apods:atprotoSource "local" ; apods:status "active" ;'+
  ' apods:repoInitialized false . }');
}
async function project(rootCid,rev,fence){
 await fuseki('update',buildFencedRepoProjectionSparql({
  resourceUri:subject,accountId,did,rootCid,rev,fence
 }));
}
async function readBinding(){
 // The normal worker callback reads the real Jena projection. The separate
 // attestor still verifies complete typed terms on its own read-only login.
 const rows=await fuseki('query',prefix+
  'SELECT ?p ?o WHERE { <'+subject+'> ?p ?o } LIMIT 30');
 const field=name=>{
  const values=rows.filter(row=>row.p?.value==='http://activitypods.org/ns/core#'+name);
  assert.equal(values.length,1,'Expected unique Jena field '+name);
  return values[0].o.value;
 };
 return {
  canonicalAccountId:field('canonicalAccountId'),
  webId:field('webId'),activityPubActorId:field('activityPubActorId'),
  atprotoDid:field('atprotoDid'),atprotoManaged:field('atprotoManaged')==='true',
  atprotoSource:field('atprotoSource'),status:field('status'),
  repoInitialized:field('repoInitialized')==='true',
  repoRootCid:field('repoRootCid'),repoRev:field('repoRev'),
  repoProjectionFence:field('repoProjectionFence')
 };
}
async function rewriteProtectedRoot(value){
 // Adversarial fixture writer, never a provider recovery fallback.
 // Simulates an independently privileged process tampering after PG ACK.
 assert(/^[a-z0-9]+$/u.test(value));
 await fuseki('update',prefix+'DELETE { <'+subject+'> apods:repoRootCid ?old } '+
   'INSERT { <'+subject+'> apods:repoRootCid "'+value+'" } '+
   'WHERE { <'+subject+'> apods:repoRootCid ?old }');
}
const reader=()=>makeDisposableProtectedFusekiReader({
 origin:process.env.FUSEKI_ISOLATION_URL,password:'fixture-attestor-only'
});
async function pools(meta){
 const pool={
  worker:rolePool(meta.names.worker,meta.passwords.worker),
  attestor:rolePool(meta.names.attestor,meta.passwords.attestor),
  revoker:rolePool(meta.names.revoker,meta.passwords.revoker),
  ordinary:rolePool(meta.names.ordinary,meta.passwords.ordinary)
 };
 return pool;
}
async function endPools(p){
 await Promise.allSettled(Object.values(p||{}).map(pool=>pool.end()));
}
async function loadMeta(){
 const file=await fs.readFile(META,'utf8');
 const m=JSON.parse(file);
 if(m.accountId!==accountId||m.did!==did||m.fixture!==true||
    !m.names||!m.passwords)throw Error('Unexpected disposable fixture metadata');
 return m;
}
const queryClaim=(p,head,record)=>({
 accountId,did,leaseOwner:record.lease_owner,
 leaseEpoch:String(record.lease_epoch),
 commitCid:head.commitCid,rootCid:head.rootCid,rev:head.rev,
 generation:Number(record.generation)
});
async function prepare(){
 const n=(await admin.query("SELECT count(*)::int AS n FROM pg_catalog.pg_tables "+
 "WHERE schemaname IN ('paper_atproto_repo_proof','paper_atproto_authority')")).rows[0].n;
 assert.equal(n,0,'Require freshly provisioned disposable PostgreSQL 18');
 await admin.query(await readSql('./schema.sql'));
 await admin.query(await readSql('./single-record-mutation.sql'));
 await admin.query(await readSql('../../sql/paper-atproto-canonical-authority-v1.sql'));
 await admin.query(await readSql('./pg-restricted-writer-roles.sql'));
 await admin.query(await readSql('./pg-restricted-projection-worker.sql'));
 await admin.query(await readSql('./pg-protected-rdf-attestation.sql'));
 const suffix=crypto.randomBytes(6).toString('hex');
 const names=Object.fromEntries(['worker','attestor','revoker','ordinary']
  .map(k=>[k,'paper_rdf_'+k+'_'+suffix]));
 const passwords=Object.fromEntries(Object.keys(names)
  .map(k=>[k,crypto.randomBytes(24).toString('hex')]));
 const meta={fixture:true,accountId,did,names,passwords};
 for(const [name,role] of Object.entries(names)){
   await admin.query('CREATE ROLE '+id(role)+
     " LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS "+
     "PASSWORD '"+passwords[name]+"'");
 }
 for(const [name,role] of [
   ['worker','paper_atproto_projection_worker'],
   ['attestor','paper_atproto_rdf_attestor'],
   ['revoker','paper_atproto_authority_revoker']
 ]){
   await admin.query('GRANT '+role+' TO '+id(names[name])+
     ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
 }
 await fs.writeFile(META,JSON.stringify(meta),{mode:0o600,flag:'wx'});
 const p=await pools(meta);
 try{
  const admitted=await assertRestrictedRdfAttestorLogin(p.attestor);
  assert.equal(admitted.independent,true);
  const ops=await createAttestedPgProjectionOperations({
   pool:p.worker,appUri,grantUri,consentRevision:'1',fixtureOnly:true
  });
  const attestor=await createIndependentProtectedRdfAttestor({
   pool:p.attestor,readProtectedRdf:reader(),appUri,grantUri,
   consentRevision:'1',fixtureOnly:true
  });
  // The newly introduced attestation table is an eighth SQL relation:
  // a stray column grant here would defeat the separate-credential barrier.
  // Exercise actual PG18 column grants, whole-table reads/deletes and both
  // startup admissions, then remove every privilege before use.
  const receiptTable='paper_atproto_repo_proof.rdf_attestations';
  for(const bad of [
    {principal:'worker',permission:'INSERT (rdf_sha256)'},
    {principal:'worker',permission:'UPDATE (lease_epoch)'},
    {principal:'worker',permission:'SELECT'},
    {principal:'attestor',permission:'INSERT (rdf_sha256)'},
    {principal:'attestor',permission:'DELETE'},
    {principal:'attestor',permission:'SELECT'}
  ]){
    const sql=bad.permission+' ON '+receiptTable;
    await admin.query('GRANT '+sql+' TO '+id(names[bad.principal]));
    try{
      if(bad.principal==='worker'){
        await assert.rejects(createAttestedPgProjectionOperations({
          pool:p.worker,appUri,grantUri,consentRevision:'1',fixtureOnly:true
        }),e=>e?.code==='PROJECTION_WORKER_ROLE_REQUIRED');
      }else{
        await assert.rejects(assertRestrictedRdfAttestorLogin(p.attestor),
          e=>e?.code==='PROTECTED_RDF_ATTESTOR_ROLE_REQUIRED');
      }
    }finally{
      await admin.query('REVOKE '+sql+' FROM '+id(names[bad.principal]));
    }
    if(bad.principal==='worker'){
      await createAttestedPgProjectionOperations({
        pool:p.worker,appUri,grantUri,consentRevision:'1',fixtureOnly:true
      });
    }else{
      assert.equal((await assertRestrictedRdfAttestorLogin(p.attestor)).independent,true);
    }
  }
  await denied(p.worker.query(
    'SELECT count(*) FROM '+receiptTable));

  // Temporarily inject unauthorized column DML and prove real admission
  // fails, then restore exact privileges before touching canonical identity.
  await admin.query('GRANT UPDATE(state) ON '+
    'paper_atproto_repo_proof.rdf_projection_jobs TO '+id(names.attestor));
  await assert.rejects(assertRestrictedRdfAttestorLogin(p.attestor),
    e=>e?.code==='PROTECTED_RDF_ATTESTOR_ROLE_REQUIRED');
  await admin.query('REVOKE UPDATE(state) ON '+
    'paper_atproto_repo_proof.rdf_projection_jobs FROM '+id(names.attestor));
  assert.equal((await assertRestrictedRdfAttestorLogin(p.attestor)).independent,true);

  await denied(p.worker.query(
    'SELECT * FROM paper_atproto_repo_proof.ack_verified_projection('+
    '$1,$2,$3::uuid,$4::bigint,$5,$6,$7,$8::bigint,$9,$10,$11::bigint)',
    [accountId,did,crypto.randomUUID(),1,'x','x','x',1,appUri,grantUri,1]
  ));
  await denied(p.worker.query(
    'SELECT paper_atproto_repo_proof.attest_protected_rdf('+
    '$1,$2,$3::uuid,$4::bigint,$5,$6,$7,$8::bigint,$9,$10,$11::bigint,$12::bytea)',
    [accountId,did,crypto.randomUUID(),1,'x','x','x',1,appUri,grantUri,1,
     Buffer.alloc(32)]
  ));
  await denied(p.attestor.query(
    'SELECT * FROM paper_atproto_repo_proof.ack_attested_projection('+
    '$1,$2,$3::uuid,$4::bigint,$5,$6,$7,$8::bigint,$9,$10,$11::bigint)',
    [accountId,did,crypto.randomUUID(),1,'x','x','x',1,appUri,grantUri,1]
  ));
  await denied(p.ordinary.query(
    'SELECT * FROM paper_atproto_repo_proof.rdf_attestations'));
  await denied(p.attestor.query(
    'UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state=$1', ['applied']));

  const key=crypto.generateKeyPairSync('ec',{namedCurve:'secp256k1'});
  const store=createSignedRepoProofStore({pool:admin,fixtureOnly:true});
  const head=await store.bootstrap({
   accountId,did,
   publicKeyPem:key.publicKey.export({format:'pem',type:'spki'}).toString(),
   signer:async bytes=>crypto.sign('sha256',bytes,{
    key:key.privateKey,dsaEncoding:'ieee-p1363'
   })
  });
  assert.equal(head.verified,true);
  await admin.query('INSERT INTO paper_atproto_authority.identities '+
   '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
   "VALUES($1,$2,'active',true,1,$3)",[accountId,did,hashed('webid-verified')]);
  await admin.query('INSERT INTO paper_atproto_authority.consents '+
   '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256) '+
   "VALUES($1,$2,$3,'active',1,$4)",[accountId,appUri,grantUri,hashed('sai-verified')]);
  await seedProtected();

  const opts={accountId,did,leaseSeconds:90,maxAttempts:8};
  const [first,other]=await Promise.all([
   ops.claim({...opts,owner:crypto.randomUUID()}),
   ops.claim({...opts,owner:crypto.randomUUID()})
  ]);
  assert.equal(first.rowCount+other.rowCount,1,'One PG lease winner');
  const lease1=(first.rowCount===1?first:other).rows[0];
  const expected1=queryClaim(null,head,lease1);
  await assert.rejects(attestor.verifyReadback(expected1),
   e=>e?.code==='PROTECTED_RDF_CARDINALITY_INVALID');
  await project(head.rootCid,head.rev,expected1.leaseEpoch);
  const digest=await attestor.verifyReadback(expected1);
  assert.equal(digest.length,32);
  assert.equal((await ops.ack({accountId,did,claimed:lease1,proof:head})).rowCount,0,
   'Projection login cannot ACK before independent attestor receipt');
  await attestor.attest(expected1);
  assert.equal((await ops.ack({accountId,did,claimed:lease1,
    proof:{...head,commitCid:'bafyre'+'f'.repeat(53)}})).rowCount,0,
   'Attestation cannot authorize a wrong signed commit');
  const ack=await ops.ack({accountId,did,claimed:lease1,proof:head});
  assert.equal(ack.rowCount,1,'Only matching independent proof may ACK');
  assert.equal((await p.worker.query(
   'SELECT state FROM paper_atproto_repo_proof.rdf_projection_jobs '+
   'WHERE account_id=$1',[accountId])).rows[0].state,'applied');
  assert.equal((await admin.query(
   'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.rdf_attestations')).rows[0].n,
   1,'One bounded receipt for one account');

  // Real crash/replay: the same signed head cannot ACK on its old receipt
  // after the lease epoch advances. A fresh trusted Jena CAS/readback is needed.
  await admin.query("UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
   "state='pending',applied_at=NULL,lease_owner=NULL,lease_until=NULL,"+
   "next_attempt_at=clock_timestamp() WHERE account_id=$1",[accountId]);
  const renewed=await ops.claim({...opts,owner:crypto.randomUUID()});
  assert.equal(renewed.rowCount,1);
  const lease2=renewed.rows[0];
  assert(BigInt(lease2.lease_epoch)>BigInt(lease1.lease_epoch));
  assert.equal((await ops.ack({accountId,did,claimed:lease2,proof:head})).rowCount,0,
   'Old receipt cannot authorize a new epoch');
  await assert.rejects(attestor.attest(queryClaim(null,head,lease2)),
   e=>e?.code==='PROTECTED_RDF_READBACK_MISMATCH');
  await project(head.rootCid,head.rev,String(lease2.lease_epoch));
  await attestor.attest(queryClaim(null,head,lease2));
  assert.equal((await admin.query(
   'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.rdf_attestations')).rows[0].n,
   1,'Receipt must replace prior epoch, never grow per lease');

  // The actual recovery state machine must be correctly composed: a
  // restricted SQL adapter without an independent attestor is invalid.
  const permitted=async ({accountId:owner,did:claimedDid})=>{
    const granted=await p.worker.query(
      'SELECT c.revision FROM paper_atproto_authority.consents AS c '+
      'JOIN paper_atproto_authority.identities AS i '+
      'ON i.owner_webid=c.owner_webid WHERE c.owner_webid=$1 '+
      "AND c.app_uri=$2 AND c.grant_uri=$3 AND c.state='active' "+
      "AND c.revision=1 AND i.did=$4 AND i.state='active' "+
      'AND i.managed=true',[owner,appUri,grantUri,claimedDid]
    );
    return owner===accountId&&claimedDid===did&&granted.rowCount===1;
  };
  const recoveryOptions={
    pool:p.worker,fixtureOnly:true,leaseSeconds:90,maxAttempts:8,
    restrictedOperations:ops,independentAttestor:attestor,
    verifyNativeEvidence:()=>store.verify({
      accountId,did,publicKeyPem:key.publicKey.export({format:'pem',type:'spki'}).toString()
    }),
    authorize:permitted,readRdf:readBinding,
    applyRdfFenced:async({rootCid,rev,fence})=>project(rootCid,rev,fence)
  };
  assert.throws(()=>createRdfProjectionRecovery({
    ...recoveryOptions,independentAttestor:null
  }),e=>e?.code==='PROJECTION_CONFIGURATION_INVALID');
  const recovery=createRdfProjectionRecovery(recoveryOptions);
  assert.equal(ops.requiresIndependentAttestation,true);
  assert.equal((await p.worker.query(
    'SELECT state FROM paper_atproto_repo_proof.rdf_projection_jobs '+
    'WHERE account_id=$1',[accountId])).rows[0].state,'leased');
  await assert.rejects(recovery.readiness({accountId,did}),
    e=>e?.code==='PROJECTION_NOT_READY');
  // A crashed worker left a valid attestor receipt but never ACKed. Its
  // released lease cannot be inherited by a new epoch. Recovery itself
  // must write new Jena fence, independently attest it and ACK.
  assert.equal((await ops.finishFailure({accountId,did,claimed:lease2,
    state:'pending',delay:0,code:'PROJECTION_RETRYABLE_ERROR'})).rowCount,1);
  const recovered=await recovery.reconcile({accountId,did});
  assert.equal(recovered.ready,true);
  assert(BigInt(recovered.fence)>BigInt(lease2.lease_epoch));
  assert.equal((await recovery.readiness({accountId,did})).ready,true);
  assert.equal((await admin.query(
    'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.rdf_attestations')).rows[0].n,
    1,'Recovery supersedes one receipt, not an unbounded collection');

  // If another privileged Jena process tampers with the protected binding
  // after PG ACK, even a compromised worker callback claiming correct RDF
  // cannot fool the separate read-only attestor at readiness.
  const trustedSnapshot=await readBinding();
  const misleadingWorker=createRdfProjectionRecovery({
    ...recoveryOptions,readRdf:async()=>({...trustedSnapshot})
  });
  await rewriteProtectedRoot('forgedroot');
  try{
    await assert.rejects(misleadingWorker.readiness({accountId,did}),
      e=>e?.code==='PROTECTED_RDF_READBACK_MISMATCH');
  }finally{
    await rewriteProtectedRoot(head.rootCid);
  }
  assert.equal((await recovery.readiness({accountId,did})).ready,true);
  const spoofedAttestor=createRdfProjectionRecovery({
    ...recoveryOptions,independentAttestor:{
      attest:attestor.attest,verifyReadback:async()=>true
    }
  });
  await assert.rejects(spoofedAttestor.readiness({accountId,did}),
    e=>e?.code==='PROJECTION_INDEPENDENT_READBACK_INVALID');

  // Fresh pending lease for canonical revocation *after* a valid receipt.
  await admin.query("UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
   "state='pending',applied_at=NULL,lease_owner=NULL,lease_until=NULL,"+
   "next_attempt_at=clock_timestamp() WHERE account_id=$1",[accountId]);
  const last=await ops.claim({...opts,owner:crypto.randomUUID()});
  assert.equal(last.rowCount,1);
  const revocationLease=last.rows[0];
  assert(BigInt(revocationLease.lease_epoch)>BigInt(recovered.fence));
  await project(head.rootCid,head.rev,String(revocationLease.lease_epoch));
  await attestor.attest(queryClaim(null,head,revocationLease));

  // Canonical revocation races after attestation: SQL ACK remains fenced by
  // the active SAI grant even if the signed record and Jena are intact.
  const revoked=await p.revoker.query(
   'SELECT * FROM paper_atproto_authority.block_consent($1,$2,$3,1::bigint)',
   [accountId,appUri,grantUri]);
  assert.equal(revoked.rowCount,1);
  assert.equal((await ops.ack({accountId,did,claimed:revocationLease,proof:head})).rowCount,0,
   'Revocation between Jena readback and PG ACK is authoritative');
  await assert.rejects(attestor.attest(queryClaim(null,head,revocationLease)),
   e=>e?.code==='PROTECTED_RDF_SQL_ATTESTATION_REJECTED');
  assert.equal((await ops.claim({...opts,owner:crypto.randomUUID()})).rowCount,0,
   'Revoked grant cannot lease again');
  assert.equal((await attestor.verifyReadback(queryClaim(null,head,revocationLease))).length,32,
   'RDF remains durably readback-verifiable independently of revoked authority');

  console.log('INDEPENDENT_PG18_JENA_ATTESTATION '+JSON.stringify({
    phase:'prepare',realSignedGenesis:true,oneLeaseWinner:true,
    independentRdfCredential:true,exactRoleGrantAdmission:true,
    injectedReceiptGrantRefusals:6,
    legacyAckRevoked:true,ackWithoutReceiptDenied:true,
    signedHeadMismatchDenied:true,attestedAckSucceeded:true,
    replayRequiresNewRdfFence:true,receiptRowsBounded:true,
    revocationAfterAttestationDenied:true,productionStorageReleased:false,
    automaticRecoveryAttestation:true,readinessTamperRefused:true,
    noMissingAttestorFallback:true
  }));
 }finally{await endPools(p);}
}
async function verify(){
 const meta=await loadMeta();
 const p=await pools(meta);
 try{
  const admitted=await assertRestrictedRdfAttestorLogin(p.attestor);
  assert.equal(admitted.independent,true);
  await createAttestedPgProjectionOperations({
   pool:p.worker,appUri,grantUri,consentRevision:'1',fixtureOnly:true
  });
  const attestor=await createIndependentProtectedRdfAttestor({
   pool:p.attestor,readProtectedRdf:reader(),appUri,grantUri,
   consentRevision:'1',fixtureOnly:true
  });
  const head=(await p.worker.query(
   'SELECT r.head_cid,r.root_cid,r.rev,r.generation,j.lease_epoch,'+
   'j.lease_owner,j.state FROM paper_atproto_repo_proof.repos r JOIN '+
   'paper_atproto_repo_proof.rdf_projection_jobs j '+
   'ON r.account_id=j.account_id AND r.did=j.did '+
   'WHERE r.account_id=$1 AND r.did=$2',[accountId,did])).rows[0];
  assert(head,'Signed head must survive Jena restart');
  assert.equal(head.state,'leased','Revocation denied ACK before restart');
  const payload={
   accountId,did,commitCid:head.head_cid,
   rootCid:head.root_cid,rev:head.rev,generation:Number(head.generation),
   leaseOwner:head.lease_owner,leaseEpoch:String(head.lease_epoch)
  };
  assert.equal((await attestor.verifyReadback(payload)).length,32,
   'Independent read-only Jena credential sees persisted fenced projection');
  const state=(await p.attestor.query(
   'SELECT state FROM paper_atproto_authority.consents '+
   'WHERE owner_webid=$1 AND app_uri=$2',[accountId,appUri])).rows[0];
  assert.equal(state.state,'blocked','Revocation persists across container restart');
  await assert.rejects(attestor.attest(payload),
   e=>e?.code==='PROTECTED_RDF_SQL_ATTESTATION_REJECTED');
  console.log('INDEPENDENT_PG18_JENA_ATTESTATION '+JSON.stringify({
   phase:'verify',jenaRestartReadback:true,canonicalRevocationPersisted:true,
   postRestartAttestationDenied:true,productionStorageReleased:false
  }));
 }finally{await endPools(p);}
}
async function cleanup(){
 let meta=null;
 try{meta=await loadMeta();}catch{/* no roles provisioned */}
 for(const schema of ['paper_atproto_repo_proof','paper_atproto_authority']){
  await admin.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE');
 }
 if(meta){
  for(const name of Object.values(meta.names)){
   await admin.query('DROP ROLE IF EXISTS '+id(name));
  }
 }
 for(const role of ['paper_atproto_rdf_attestor',
  'paper_atproto_projection_worker','paper_atproto_repo_writer',
  'paper_atproto_authority_revoker','paper_atproto_authority_reader',
  'paper_atproto_authority_importer']){
  await admin.query('DROP ROLE IF EXISTS '+id(role));
 }
 await fs.rm(META,{force:true});
 console.log('DISPOSABLE_PG18_ATTESTATION_CLEANUP '+JSON.stringify({cleaned:true}));
}
try{
 if(phase==='prepare')await prepare();
 else if(phase==='verify')await verify();
 else await cleanup();
}finally{await admin.end();}
