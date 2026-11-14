/**
 * NONACTIVATED end-to-end PDS HTTP mutation acceptance.
 * Actual PostgreSQL 18 signed repo, upstream @atproto/repo MST, canonical
 * consent locks, durable outbox and bounded CAR read-back. OAuth/DPoP and
 * protected Jena projection are injected fixture callbacks; they are NOT
 * claimed to be production auth/SAI integration.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import {test} from 'node:test';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {Pool} from 'pg';
import {createSignedRepoProofStore} from './store.mjs';
import {createReferenceMstWriter} from './reference-mst-writer.mjs';
import {createReferenceMstCarExporter} from './reference-mst-car-export.mjs';
import {createReadOnlySyncXrpc} from './sync-xrpc-candidate.mjs';
import {createCanonicalRecordWriteConsentFence} from './pg-record-write-consent-fence.mjs';
import {createAuthenticatedRecordWriteXrpc} from './pds-write-xrpc-candidate.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
const UPSTREAM=process.env.ATPROTO_REFERENCE_REPO_ENTRY||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_PDS_WRITE_TEST_DISPOSABLE!=='confirmed'||
   process.env.NODE_ENV!=='test'||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)||
   !UPSTREAM.startsWith('/')){
  throw Error('PDS write acceptance requires PG18 disposable target and upstream MST');
}
const reference=await import(pathToFileURL(UPSTREAM).href);
const pool=new Pool({connectionString:DSN,max:6,
  connectionTimeoutMillis:3000,idleTimeoutMillis:3000,allowExitOnIdle:true});
const accountId='https://paper.example.org/users/write-xrpc';
const did='did:plc:'+'v'.repeat(24);
const handle='write-xrpc.paper.example.org';
const pds='https://pds.paper.example.org';
const app='https://writer.paper.example.org/app';
const grant=accountId+'/data/grants/writer';
const rkey='3jzm3xwpf2222';
const collection='app.bsky.feed.post';
const route=method=>'http://127.0.0.1:'+server.address().port+
  '/xrpc/com.atproto.repo.'+method;
const record=text=>({$type:collection,text,
  createdAt:'2026-11-14T00:00:00.000Z'});
const authHeader='Bearer disposable_integration_token_1234567890';
let server;

async function post(method,body,authorization=authHeader){
  const h={'content-type':'application/json'};
  if(authorization!==null)h.authorization=authorization;
  const response=await fetch(route(method),{
    method:'POST',headers:h,body:JSON.stringify(body),
    signal:AbortSignal.timeout(9000)
  });
  return {status:response.status,body:await response.json()};
}
async function latest(){
  const url='http://127.0.0.1:'+server.address().port+
    '/xrpc/com.atproto.sync.getLatestCommit?did='+encodeURIComponent(did);
  const response=await fetch(url,{signal:AbortSignal.timeout(6000)});
  return {status:response.status,body:await response.json()};
}
async function listen(s){
  await new Promise((ok,no)=>{s.once('error',no);s.listen(0,'127.0.0.1',ok);});
}
async function close(s){
  if(s)await new Promise((ok,no)=>s.close(e=>e?no(e):ok()));
}
const currentConsent=async()=>{
  const r=await pool.query(
    'SELECT i.did,i.state AS identity_state,c.state AS consent_state,'+
    'c.grant_uri,c.revision::text AS revision FROM '+
    'paper_atproto_authority.identities i JOIN '+
    'paper_atproto_authority.consents c ON c.owner_webid=i.owner_webid '+
    'WHERE i.owner_webid=$1 AND c.app_uri=$2',[accountId,app]
  );
  return r.rows[0]||null;
};
async function revoke(){
  return pool.query('SELECT * FROM paper_atproto_authority.block_consent($1,$2,$3,1::bigint)',
    [accountId,app,grant]);
}
async function readState(){
  const rows=await pool.query(
    'SELECT head_cid,rev,generation FROM paper_atproto_repo_proof.repos '+
    'WHERE account_id=$1',[accountId]
  );
  return rows.rows[0];
}
test('OAuth-gated hosted write XRPC creates signed records with canonical PG revocation serialization',async t=>{
  const oldEnv=process.env.NODE_ENV;
  let cleanupFailed=null;
  try{
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables "+
      "WHERE schemaname IN ('paper_atproto_repo_proof','paper_atproto_authority')"
    )).rows[0].n,0,'signed repo and PG consent schemas must be disposable and empty');
    await pool.query(await fs.readFile(fileURLToPath(new URL('./schema.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(fileURLToPath(
      new URL('./single-record-mutation.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(fileURLToPath(
      new URL('../../sql/paper-atproto-canonical-authority-v1.sql',import.meta.url)),'utf8'));
    const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{
      namedCurve:'secp256k1'
    });
    const keys={
      publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
      signer:async bytes=>crypto.sign('sha256',bytes,{
        key:privateKey,dsaEncoding:'ieee-p1363'
      })
    };
    const genesis=createSignedRepoProofStore({pool,fixtureOnly:true});
    let current=await genesis.bootstrap({accountId,did,...keys});
    assert.equal(current.verified,true);
    await pool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='applied',"+
      'lease_epoch=1,applied_at=clock_timestamp() '+
      'WHERE account_id=$1 AND did=$2',[accountId,did]
    );
    const digest=crypto.createHash('sha256').update('owned-disposable-fixture').digest();
    await pool.query(
      'INSERT INTO paper_atproto_authority.identities '+
      '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
      "VALUES ($1,$2,'active',true,1,$3)",[accountId,did,digest]
    );
    await pool.query(
      'INSERT INTO paper_atproto_authority.consents '+
      '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256) '+
      "VALUES ($1,$2,$3,'active',1,$4)",[accountId,app,grant,digest]
    );
    let hosted={webId:accountId,activityPubActorId:accountId,
      did,handle,pdsUrl:pds,atprotoManaged:true,atprotoSource:'local',
      status:'active'};
    let oauthChecks=0;
    const authorizeOwner=async({authorization,did:chosen,webId})=>{
      oauthChecks++;
      const pg=await currentConsent();
      if(authorization!==authHeader||chosen!==did||webId!==accountId||
         pg?.did!==did||pg.identity_state!=='active'||
         pg.consent_state!=='active'||pg.grant_uri!==grant) return null;
      // This fixture represents a verdict from ActivityPods' real
      // OAuth/OIDC+DPoP verifier; token parsing is NOT part of this test.
      return {verified:true,ownerDid:did,ownerWebId:accountId,
        permission:'atproto:record-write',dpopVerified:true,
        issuerVerified:true,audienceVerified:true,
        appUri:app,grantUri:grant,consentRevision:pg.revision};
    };
    let lockCalls=0;
    let onLock=null;
    const makeWriter=({appUri,grantUri,consentRevision})=>{
      const fence=createCanonicalRecordWriteConsentFence({
        appUri,grantUri,consentRevision
      });
      return createReferenceMstWriter({
        pool,reference,fixtureOnly:true,
        authorize:async ({accountId:owner,did:subject})=>{
          const pg=await currentConsent();
          return owner===accountId&&subject===did&&
            pg?.consent_state==='active'&&pg?.revision===consentRevision;
        },
        lockCanonicalConsent:async(client,scope)=>{
          lockCalls++;
          const result=await fence(client,scope);
          if(onLock)await onLock();
          return result;
        }
      });
    };
    const writer=makeWriter({appUri:app,grantUri:grant,consentRevision:'1'});
    const projectExact=async({accountId:owner,did:subject,commitCid,
      rootCid,rev,generation})=>{
      assert.equal(owner,accountId);
      assert.equal(subject,did);
      const updated=await pool.query(
        'UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET '+
        "state='applied',lease_epoch=lease_epoch+1,applied_at=clock_timestamp() "+
        "WHERE account_id=$1 AND did=$2 AND state='pending' AND "+
        'head_cid=$3 AND root_cid=$4 AND rev=$5 AND generation=$6 '+
        'RETURNING generation',
        [owner,subject,commitCid,rootCid,rev,generation]
      );
      if(updated.rowCount!==1)return {ready:false};
      return {ready:true,accountId:owner,did:subject,commitCid,rev};
    };
    const hostedLookup=async({did:chosen})=>chosen===did?{...hosted}:null;
    const xrpc=createAuthenticatedRecordWriteXrpc({
      pdsOrigin:pds,fixtureOnly:true,resolveHostedAccount:hostedLookup,
      authorizeOwner,resolveSigner:async()=>keys,
      createFencedWriter:async auth=>makeWriter(auth),
      finalizeProjection:projectExact
    });
    const exporter=createReferenceMstCarExporter({
      pool,reference,fixtureOnly:true,
      verifySignedHead:args=>writer.verify(args),
      authorize:async()=>true
    });
    const readXrpc=createReadOnlySyncXrpc({
      resolveHostedAccount:hostedLookup,
      repositoryAuthority:{verifyReady:async()=>{
        const s=await writer.verify({accountId,did,
          publicKeyPem:keys.publicKeyPem});
        return {...s,pdsOrigin:pds};
      }},
      projectionAuthority:{readiness:async()=>{
        const p=await pool.query(
          'SELECT state,head_cid,root_cid,rev,lease_epoch '+
          'FROM paper_atproto_repo_proof.rdf_projection_jobs '+
          'WHERE account_id=$1',[accountId]
        );
        const h=await writer.verify({accountId,did,publicKeyPem:keys.publicKeyPem});
        return {ready:p.rows[0].state==='applied',accountId,did,
          headCid:p.rows[0].head_cid,rootCid:p.rows[0].root_cid,
          rev:p.rows[0].rev,outboxStatus:h.outboxStatus,
          fence:String(p.rows[0].lease_epoch)};
      }},
      signedRepoStore:writer,
      repositoryExporter:exporter,
      resolvePublicKey:async()=>keys.publicKeyPem,
      pdsOrigin:pds,fixtureOnly:true
    });
    server=http.createServer((req,res)=>
      req.method==='POST'?xrpc.handle(req,res):readXrpc.handle(req,res));
    await listen(server);
    const body=(swapCommit,rec)=>({
      repo:did,collection,rkey,record:rec,swapCommit
    });
    await t.test('missing, spoofed or unverified OAuth cannot call signer',async()=>{
      const prior=await readState();
      const missing=await post('createRecord',body(current.commitCid,record('one')),null);
      assert.equal(missing.status,401);
      const spoof=await post('createRecord',body(current.commitCid,record('one')),'Bearer forged-token-abcdef1234');
      assert.equal(spoof.status,401);
      const actor=await post('createRecord',{...body(current.commitCid,record('one')),
        repo:'did:plc:'+'z'.repeat(24)});
      assert.equal(actor.status,404);
      assert.deepEqual(await readState(),prior);
    });
    await t.test('valid OAuth creates real signed commit + indexed outbox and CAR',async()=>{
      const out=await post('createRecord',body(current.commitCid,record('first')));
      assert.equal(out.status,200,JSON.stringify(out.body));
      assert.equal(out.body.uri,'at://'+did+'/'+collection+'/'+rkey);
      assert.equal(out.body.commit.cid.length,59);
      assert(out.body.cid.startsWith('bafy'));
      current=await writer.verify({accountId,did,
        publicKeyPem:keys.publicKeyPem,path:collection+'/'+rkey});
      assert.equal(out.body.commit.cid,current.commitCid);
      assert.equal(out.body.cid,current.recordCid);
      assert.equal(current.generation,2);
      const event=await pool.query(
        'SELECT status,rev FROM paper_atproto_repo_proof.native_event_outbox '+
        'WHERE did=$1 AND commit_cid=$2',[did,current.commitCid]
      );
      assert.equal(event.rowCount,1);
      assert.equal(event.rows[0].status,'pending');
      assert.equal((await latest()).body.cid,current.commitCid);
      assert(lockCalls>=1);
    });
    await t.test('stale swapCommit has no second signed mutation',async()=>{
      const before=await readState();
      const old=await post('createRecord',body(
        (await pool.query('SELECT previous_commit_cid FROM '+
          'paper_atproto_repo_proof.record_mutations WHERE did=$1 '+
          'AND generation=2',[did])).rows[0].previous_commit_cid,
        record('duplicate')));
      assert.equal(old.status,400);
      assert.equal(old.body.error,'InvalidSwap');
      const exists=await post('createRecord',body(current.commitCid,record('dup')));
      assert.equal(exists.body.error,'RecordAlreadyExists');
      assert.deepEqual(await readState(),before);
    });
    await t.test('putRecord updates and deleteRecord maintains signed history',async()=>{
      const put=await post('putRecord',body(current.commitCid,record('edited')));
      assert.equal(put.status,200,JSON.stringify(put.body));
      assert.notEqual(put.body.cid,current.recordCid);
      current=await writer.verify({accountId,did,path:collection+'/'+rkey,
        publicKeyPem:keys.publicKeyPem});
      assert.equal(current.generation,3);
      const removal=await post('deleteRecord',{
        repo:did,collection,rkey,swapCommit:current.commitCid
      });
      assert.equal(removal.status,200,JSON.stringify(removal.body));
      assert(removal.body.commit.cid!==current.commitCid);
      current=await writer.verify({accountId,did,path:collection+'/'+rkey,
        publicKeyPem:keys.publicKeyPem});
      assert.equal(current.recordCid,null);
      assert.equal(current.generation,4);
      const revs=(await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.record_mutations '+
        'WHERE did=$1',[did])).rows[0].n;
      assert.equal(revs,3);
    });
    await t.test('revoked canonical PG consent stops HTTP writes without new blocks',async()=>{
      const before=await readState();
      assert.equal((await revoke()).rowCount,1);
      const out=await post('createRecord',{
        repo:did,collection,rkey,swapCommit:current.commitCid,
        record:record('blocked')
      });
      assert.equal(out.status,401);
      assert.deepEqual(await readState(),before);
    });
    await t.test('production flag cannot activate an already-constructed endpoint',async()=>{
      const prior=process.env.NODE_ENV;
      try{
        process.env.NODE_ENV='production';
        const out=await post('createRecord',{
          repo:did,collection,rkey,swapCommit:current.commitCid,
          record:record('not in production')
        });
        assert.equal(out.status,503);
      }finally{process.env.NODE_ENV=prior;}
    });
    assert(oauthChecks>=8);
    const idle=(await pool.query(
      "SELECT count(*)::int AS n FROM pg_stat_activity "+
      "WHERE datname=current_database() AND state='idle in transaction'"
    )).rows[0].n;
    assert.equal(idle,0);
    console.log('PDS_XRPC_PG18_PROOF '+JSON.stringify({
      signedGenerations:current.generation,oauthBound:true,
      canonicalPgFenceLocked:lockCalls>=3,outboxVerified:true,
      lostSwapRejected:true,revocationDenied:true,productionDenied:true,
      idleTransactions:idle
    }));
  }finally{
    process.env.NODE_ENV=oldEnv;
    await close(server);
    try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');}
    catch(e){cleanupFailed=e;}
    try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_authority CASCADE');}
    catch(e){cleanupFailed=e;}
    for(const role of ['paper_atproto_authority_reader',
      'paper_atproto_authority_importer','paper_atproto_authority_revoker']){
      try{await pool.query('DROP ROLE IF EXISTS '+role);}catch(e){cleanupFailed=e;}
    }
    await pool.end();
    if(cleanupFailed)throw cleanupFailed;
  }
});
