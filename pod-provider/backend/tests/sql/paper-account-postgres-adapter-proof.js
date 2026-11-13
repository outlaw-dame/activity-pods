'use strict';
// Run ONLY against disposable PostgreSQL after schema v1. The integration
// uses official @atproto/repo, a real v3 signed CAR and independent mock-XRPC
// PDS/PLC responses; no real PLC, real user or production pod is contacted.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const { createAccountPostgresLifecycleCandidate } =
  require('../../candidates/account-postgres-lifecycle');
const { createNewSignupPostgresAuthority } =
  require('../../candidates/new-signup-postgres-authority');

const connection = {
  host:'127.0.0.1',port:15432,database:'paper_account_disposable',
  user:'postgres',password:'disposable-ci-only',
  max:2,connectionTimeoutMillis:3000,idleTimeoutMillis:2000
};
const pa=new Pool(connection),pb=new Pool(connection);
const fixtureKey=crypto.randomBytes(32);
const h=value=>crypto.createHmac('sha256',fixtureKey).update(value).digest();
const newId=()=>crypto.randomUUID();
const base=(name,key,client='https://client.example')=>({
  operationId:newId(),leaseToken:newId(),providerId:'provider-candidate',
  operationKind:'new_signup',
  appClientId:client,
  idempotencyDigest:h('idempotency:'+key),
  requestDigest:h('request:'+key),
  usernameKey:name,verifiedEmailHmac:null
});
async function reject(promise,code) {
  await assert.rejects(promise,e=>e.type===code||e.code===code);
}
async function main() {
  const { Secp256k1Keypair } = await import('@atproto/crypto');
  const { generateSignedGenesis,verifySignedGenesisEvidence } =
    await import('../../candidates/atproto-repo-genesis.mjs');
  const { verifyPdsReadiness } =
    await import('../../candidates/atproto-pds-readiness.mjs');
  const did='did:plc:abcdefghijklmnopqrstuvwx';
  const handle='alice.pds.example';
  const pds='https://pds.example',plc='https://plc.example';
  const key=await Secp256k1Keypair.create({exportable:false});
  const genesis=await generateSignedGenesis({
    did,signer:{keyDid:key.did(),sign:bytes=>key.sign(bytes)}
  });
  const document={
    id:did,alsoKnownAs:['at://'+handle],
    verificationMethod:[{
      id:did+'#atproto',controller:did,type:'Multikey',
      publicKeyMultibase:key.did().replace('did:key:','')
    }],
    service:[{id:did+'#atproto_pds',type:'AtprotoPersonalDataServer',serviceEndpoint:pds}]
  };
  const routes={
    [plc+'/'+encodeURIComponent(did)]:new Response(JSON.stringify(document)),
    [pds+'/xrpc/com.atproto.sync.getLatestCommit?did='+encodeURIComponent(did)]:
      new Response(JSON.stringify({cid:genesis.rootCid,rev:genesis.rev})),
    [pds+'/xrpc/com.atproto.sync.getRepo?did='+encodeURIComponent(did)]:
      new Response(genesis.car)
  };
  const mockFetch=async url=>{
    const response=routes[url];
    assert(response, 'unexpected external fixture URL');
    return response.clone();
  };
  const authoritativeCall=async (action,params)=>{
    switch(action){
      case 'auth.account.findByUsername':
        return params.username.startsWith('legacy')
          ? {'@id':'https://pods.example/auth/legacy-account'} : null;
      case 'auth.account.findByWebId':
        return {'@id':'https://pods.example/auth/account-1',disabled:false};
      case 'identitybindings.getByCanonicalAccountId':
        return {
          webId:params.canonicalAccountId,
          activityPubActorId:params.canonicalAccountId,
          atprotoDid:did,atprotoSource:'local',atprotoManaged:true
        };
      case 'auth.awaitBootstrapComplete':
        return {webId:params.webId,complete:true};
      default: throw new Error('Unapproved authority lookup');
    }
  };
  const factory=pool=>createNewSignupPostgresAuthority({
    pool,call:authoritativeCall,
    resolveTrustedKeyDid:async claimed=>{
      assert.equal(claimed,did);
      return key.did();
    },
    verifyGenesis:verifySignedGenesisEvidence,
    verifyPds:opts=>verifyPdsReadiness({
      ...opts,plcDirectoryUrl:plc,fetchImpl:mockFetch
    })
  });
  const a=factory(pa),b=factory(pb);
  const excluded = base('legacyuser','legacy-key');
  await reject(a.reserve(excluded),'ACCOUNT_LEDGER_EXISTING_ACCOUNT');
  await reject(a.reserve({...excluded,operationKind:'legacy_migration'}),
    'ACCOUNT_LEDGER_NEW_SIGNUP_ONLY');
  const missingFresh=createAccountPostgresLifecycleCandidate({pool:pa});
  await reject(missingFresh.reserve(base('newuserwithoutpreflight','key')),
    'ACCOUNT_LEDGER_NEW_ACCOUNT_CHECK_REQUIRED');
  const failingFresh=createAccountPostgresLifecycleCandidate({
    pool:pa,assertFreshAccount:async()=>{throw new Error('Solid datastore down');}
  });
  await reject(failingFresh.reserve(base('accountwhenlegacydown','key')),
    'ACCOUNT_LEDGER_EXISTING_ACCOUNT_CHECK_UNAVAILABLE');
  const input=base('accountcandidatealice','candidate-key-1');
  assert.equal((await a.reserve(input)).state,'reserved');
  await reject(a.reserve(input),'ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
  await reject(a.reserve({...input,requestDigest:h('changed')}),'ACCOUNT_LEDGER_IDEMPOTENCY_MISMATCH');
  await reject(a.markAccountCreated({
    ...input,webId:'https://admin:password@pods.example/alice'
  }),'ACCOUNT_LEDGER_INVALID_WEBID');
  assert.equal((await a.markAccountCreated({
    ...input,webId:'https://pods.example/alice'
  })).state,'account_created');
  await reject(a.markIdentitiesReady({
    ...input,did,repoRootCid:genesis.rootCid,repoRev:genesis.rev,
    handle,expectedPdsUrl:pds
  }),'ACCOUNT_LEDGER_GENESIS_NOT_STAGED');
  const staged=await a.stageSignedGenesis({...input,genesis});
  assert.equal(staged.staged,true);
  assert.equal(staged.replay,false);
  assert.equal((await b.stageSignedGenesis({...input,genesis})).replay,true);
  const different=await generateSignedGenesis({
    did,signer:{keyDid:key.did(),sign:bytes=>key.sign(bytes)}
  });
  if (different.rootCid!==genesis.rootCid) {
    await reject(a.stageSignedGenesis({...input,genesis:different}),
      'ACCOUNT_LEDGER_GENESIS_CONFLICT');
  }
  const missingVerifier=createAccountPostgresLifecycleCandidate({pool:pa});
  await reject(missingVerifier.stageSignedGenesis({...input,genesis}),
    'ACCOUNT_LEDGER_GENESIS_VERIFIER_REQUIRED');
  await reject(missingVerifier.markIdentitiesReady({
    ...input,did,repoRootCid:genesis.rootCid,repoRev:genesis.rev,
    handle,expectedPdsUrl:pds
  }), 'ACCOUNT_LEDGER_LIVE_PDS_VERIFIER_REQUIRED');
  await reject(a.markIdentitiesReady({
    ...input,did,repoRootCid:genesis.rootCid,repoRev:genesis.rev,
    handle,expectedPdsUrl:'https://attacker.example'
  }), 'ACCOUNT_LEDGER_PDS_NOT_VERIFIED');
  assert.equal((await a.markIdentitiesReady({
    ...input,did,repoRootCid:genesis.rootCid,repoRev:genesis.rev,
    handle,expectedPdsUrl:pds
  })).state,'identities_ready');
  await reject(missingVerifier.complete(input),'ACCOUNT_LEDGER_SOLID_VERIFIER_REQUIRED');
  const wrongSolid=createAccountPostgresLifecycleCandidate({
    pool:pa,
    verifySolid:async()=>({webId:'https://pods.example/wrong-user',complete:true})
  });
  await reject(wrongSolid.complete(input),'ACCOUNT_LEDGER_SOLID_NOT_VERIFIED');
  assert.equal((await a.complete(input)).state,'completed');
  const stored=await pa.query(
    'SELECT car_sha256,car_bytes FROM paper_account_candidate.signed_genesis WHERE operation_id=$1',
    [input.operationId]
  );
  assert.equal(stored.rowCount,1);
  assert(stored.rows[0].car_bytes.equals(genesis.car));
  assert(stored.rows[0].car_sha256.equals(
    crypto.createHash('sha256').update(genesis.car).digest()
  ));
  assert.equal((await b.reserve(input)).replay,true);
  await reject(a.requireReconciliation(input),'ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');

  const one=base('accountcandidatecontest','contest-1','https://client-1.example');
  const two=base('accountcandidatecontest','contest-2','https://client-2.example');
  const results=await Promise.allSettled([a.reserve(one),b.reserve(two)]);
  assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
  assert.equal(results.filter(x=>x.status==='rejected').length,1);
  assert.equal(results.find(x=>x.status==='rejected').reason.type,'ACCOUNT_LEDGER_IDENTITY_RESERVED');
  const winner=results[0].status==='fulfilled'?one:two;
  await reject(a.markAccountCreated({...winner,leaseToken:newId(),
    webId:'https://pods.example/contest'}),'ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
  await pa.query(
    "UPDATE paper_account_candidate.operations SET lease_expires_at=clock_timestamp()-interval '1 minute' WHERE operation_id=$1",
    [winner.operationId]
  );
  await reject(a.markAccountCreated({...winner,webId:'https://pods.example/contest'}),
    'ACCOUNT_LEDGER_RECONCILIATION_REQUIRED');
  console.log('account_pg_signed_genesis_and_pds_proof_passed');
  console.log('account_pg_dual_pool_concurrency_and_leases_passed');
}
main().then(async()=>{await Promise.all([pa.end(),pb.end()])}).catch(async err=>{
  console.error('account_pg_live_adapter_proof_failed',err.type||err.code||err.name);
  await Promise.allSettled([pa.end(),pb.end()]);
  process.exitCode=1;
});
