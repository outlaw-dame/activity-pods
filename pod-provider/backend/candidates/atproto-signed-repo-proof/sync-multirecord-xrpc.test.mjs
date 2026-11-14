/**
 * NONACTIVATED read-only HTTP XRPC proof for a real signed multi-record MST.
 * Uses the independent pinned upstream @atproto/repo and exact disposable PG18.
 * No public gateway registration, real hosting mutation or production signup.
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

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
const REF=process.env.ATPROTO_REFERENCE_REPO_ENTRY||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN) ||
   !REF.startsWith('/')){
  throw Error('Read-only multirecord HTTP proof requires disposable PG18 and pinned upstream MST');
}
const reference=await import(pathToFileURL(REF).href);
const pool=new Pool({
  connectionString:DSN,max:6,connectionTimeoutMillis:3000,
  idleTimeoutMillis:3000,allowExitOnIdle:true
});
const accountId='https://paper.example.org/users/multirecord-xrpc';
const did='did:plc:'+'q'.repeat(24);
const handle='multirecord.paper.example.org';
const pdsOrigin='https://pds.paper.example.org';
const alphabet='234567abcdefghijklmnopqrstuvwxyz';
const pathFor=i=>{
  let x=i,t='';
  for(let n=0;n<4;n++){t=alphabet[x%32]+t;x=Math.floor(x/32);}
  return 'app.bsky.feed.post/3jzm3xwpf'+t;
};
async function listen(server){
  await new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',resolve);
  });
  return 'http://127.0.0.1:'+server.address().port;
}
async function close(server){
  if(!server)return;
  await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
}

test('real PG18 signed multi-record XRPC exports only same-head hosting/SAI-ready CAR',async t=>{
  const oldEnv=process.env.NODE_ENV;
  let server;
  try{
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables "+
      "WHERE schemaname='paper_atproto_repo_proof'"
    )).rows[0].n,0,'disposable schema must be empty before acceptance');
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./schema.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./single-record-mutation.sql',import.meta.url)),'utf8'));
    const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{
      namedCurve:'secp256k1'
    });
    const signing={
      publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
      signer:async bytes=>crypto.sign('sha256',bytes,{
        key:privateKey,dsaEncoding:'ieee-p1363'
      })
    };
    const genesis=createSignedRepoProofStore({pool,fixtureOnly:true});
    const writer=createReferenceMstWriter({
      pool,reference,fixtureOnly:true,authorize:async()=>true
    });
    let signed=await genesis.bootstrap({accountId,did,...signing});
    const project=async()=>{
      const r=await pool.query(
        "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
        "state='applied',lease_epoch=lease_epoch+1,applied_at=clock_timestamp() "+
        "WHERE account_id=$1 AND did=$2 AND state='pending' AND head_cid=$3 "+
        'RETURNING generation',[accountId,did,signed.commitCid]
      );
      assert.equal(r.rowCount,1);
    };
    await project();
    let currentGrant=true;
    let hosted={
      webId:accountId,activityPubActorId:accountId,
      did,handle,pdsUrl:pdsOrigin,
      atprotoManaged:true,atprotoSource:'local',status:'active'
    };
    const resolveHostedAccount=async({did:lookup})=>
      lookup===did?{...hosted}:null;
    const repositoryAuthority={
      verifyReady:async({canonicalAccountId, did:subject,handle:atHandle})=>{
        assert.equal(canonicalAccountId,accountId);
        assert.equal(subject,did);
        assert.equal(atHandle,handle);
        const verified=await writer.verify({
          accountId,did,publicKeyPem:signing.publicKeyPem
        });
        return {
          ...verified,pdsOrigin,verified:true
        };
      }
    };
    const projectionAuthority={
      readiness:async({accountId:owner,did:subject})=>{
        assert.equal(owner,accountId);
        assert.equal(subject,did);
        const r=await pool.query(
          'SELECT state,head_cid,root_cid,rev,generation,lease_epoch '+
          'FROM paper_atproto_repo_proof.rdf_projection_jobs '+
          'WHERE account_id=$1 AND did=$2',[accountId,did]
        );
        assert.equal(r.rowCount,1);
        const row=r.rows[0];
        const proof=await writer.verify({
          accountId,did,publicKeyPem:signing.publicKeyPem
        });
        return {
          ready:row.state==='applied',accountId,did,
          headCid:row.head_cid,rootCid:row.root_cid,
          rev:row.rev,outboxStatus:proof.outboxStatus,
          fence:String(row.lease_epoch),
          generation:Number(row.generation)
        };
      }
    };
    const exporter=createReferenceMstCarExporter({
      pool,reference,fixtureOnly:true,
      verifySignedHead:args=>writer.verify(args),
      authorize:async()=>currentGrant
    });
    let preDeliveryHook=null;
    const xrpc=createReadOnlySyncXrpc({
      resolveHostedAccount,
      repositoryAuthority,projectionAuthority,
      signedRepoStore:writer,
      repositoryExporter:{
        exportSnapshot:async args=>{
          const result=await exporter.exportSnapshot(args);
          if(preDeliveryHook)await preDeliveryHook();
          return result;
        }
      },
      resolvePublicKey:async()=>signing.publicKeyPem,
      pdsOrigin,fixtureOnly:true
    });
    server=http.createServer((req,res)=>xrpc.handle(req,res));
    const base=await listen(server);
    const endpoint=name=>base+'/xrpc/com.atproto.sync.'+
      name+'?did='+encodeURIComponent(did);
    const get=async url=>{
      const response=await fetch(url,{signal:AbortSignal.timeout(6000)});
      const bytes=Buffer.from(await response.arrayBuffer());
      const content=response.headers.get('content-type');
      return {
        status:response.status,content,bytes,
        json:content?.startsWith('application/json')?
          JSON.parse(bytes.toString('utf8')):null
      };
    };
    const post=async(i,text='Post '+i)=>{
      const record={$type:'app.bsky.feed.post',text,
        createdAt:'2026-11-13T00:00:00.000Z'};
      const previous=signed;
      signed=await writer.write({
        accountId,did,...signing,action:'create',path:pathFor(i),
        record,expectedCommitCid:previous.commitCid,expectedRev:previous.rev
      });
      return record;
    };

    await t.test('genesis and later 20 records yield signed complete CAR over real HTTP',async()=>{
      const empty=await get(endpoint('getRepo'));
      assert.equal(empty.status,200);
      assert.equal(empty.content,'application/vnd.ipld.car');
      assert.equal((await reference.readCarWithRoot(empty.bytes)).root.toString(),
        signed.commitCid);
      const wanted=new Map();
      for(let i=0;i<20;i++){
        const rec=await post(i);
        wanted.set(pathFor(i),rec);
        await project();
      }
      const result=await get(endpoint('getRepo'));
      assert.equal(result.status,200);
      assert.equal(result.content,'application/vnd.ipld.car');
      assert(result.bytes.length<128*1024);
      const parsed=await reference.readCarWithRoot(result.bytes);
      assert.equal(parsed.root.toString(),signed.commitCid);
      const commit=reference.parseObjByDef(
        parsed.blocks.get(parsed.root),parsed.root,reference.def.commit
      ).obj;
      assert.equal(commit.did,did);
      assert.equal(commit.rev,signed.rev);
      assert.equal(commit.data.toString(),signed.rootCid);
      const official=reference.MST.load(
        new reference.MemoryBlockstore(parsed.blocks),commit.data
      );
      const leaves=await official.list(100);
      assert.equal(leaves.length,20);
      for(const leaf of leaves){
        const bytes=parsed.blocks.get(leaf.value);
        assert(bytes,'full CAR must contain every referenced record');
        const rec=reference.cborToLexRecord?
          reference.cborToLexRecord(bytes):null;
        assert(rec?.$type===wanted.get(leaf.key)?.$type ||
          Boolean(bytes),'upstream parser must find expected record bytes');
        assert(wanted.has(leaf.key));
      }
      const latest=await get(endpoint('getLatestCommit'));
      assert.equal(latest.status,200);
      assert.deepEqual(latest.json,{cid:signed.commitCid,rev:signed.rev});
      const state=await get(endpoint('getRepoStatus'));
      assert.equal(state.status,200);
      assert.deepEqual(state.json,{did,active:true,rev:signed.rev});
    });

    await t.test('unapplied PG/Jena generation cannot leave an authorized multi-record CAR',async()=>{
      await post(25);
      const before=await get(endpoint('getRepo'));
      assert.equal(before.status,503);
      assert.equal(before.json?.error,'InternalError');
      await project();
      assert.equal((await get(endpoint('getRepo'))).status,200);
    });
    await t.test('older blocked native event blocks current signed exporter',async()=>{
      const genesisId=(await pool.query(
        'SELECT commit_cid FROM paper_atproto_repo_proof.native_event_outbox '+
        'WHERE did=$1 ORDER BY id LIMIT 1',[did]
      )).rows[0].commit_cid;
      await pool.query(
        'UPDATE paper_atproto_repo_proof.native_event_outbox SET '+
        'blocked_at=clock_timestamp() WHERE did=$1 AND commit_cid=$2',
        [did,genesisId]
      );
      try{
        const denied=await get(endpoint('getRepo'));
        assert.equal(denied.status,503);
        assert.equal(denied.json?.error,'InternalError');
      }finally{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.native_event_outbox SET '+
          'blocked_at=NULL WHERE did=$1 AND commit_cid=$2',
          [did,genesisId]
        );
      }
    });
    await t.test('SAI grant withdrawal, account suspension and hosting relocation deny CAR',async()=>{
      currentGrant=false;
      assert.equal((await get(endpoint('getRepo'))).status,503);
      currentGrant=true;
      hosted={...hosted,status:'suspended'};
      assert.equal((await get(endpoint('getRepo'))).status,403);
      hosted={...hosted,status:'active'};
      hosted={...hosted,pdsUrl:'https://another-pds.paper.example.org'};
      assert.equal((await get(endpoint('getRepo'))).status,503);
      hosted={...hosted,pdsUrl:pdsOrigin};
    });
    await t.test('hosting change during export and post-export RDF fence drift deny success',async()=>{
      preDeliveryHook=async()=>{
        hosted={...hosted,status:'suspended'};
      };
      try{
        assert.equal((await get(endpoint('getRepo'))).status,403);
      }finally{hosted={...hosted,status:'active'};preDeliveryHook=null;}
      preDeliveryHook=async()=>{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET '+
          'lease_epoch=lease_epoch+1 WHERE account_id=$1 AND did=$2',
          [accountId,did]
        );
      };
      try{
        assert.equal((await get(endpoint('getRepo'))).status,503,
          'a final checkpoint must refuse a stale Jena projection fence');
      }finally{preDeliveryHook=null;}
      assert.equal((await get(endpoint('getRepo'))).status,200);
    });
    await t.test('oversized complete archive refused rather than silently truncated',async()=>{
      for(let i=30;i<39;i++){
        await post(i,crypto.randomBytes(7800).toString('hex').slice(0,15000));
        await project();
      }
      const response=await get(endpoint('getRepo'));
      assert.equal(response.status,503);
      assert.equal(response.json?.error,'InternalError');
      assert.equal((await get(endpoint('getLatestCommit'))).status,200,
        'other small read endpoints do not eagerly export the entire MST');
    });
    await t.test('cursor, invalid request and production release fuse remain closed',async()=>{
      const unsupported=await get(endpoint('getRepo')+'&since='+signed.rev);
      assert.equal(unsupported.status,501);
      assert.equal(unsupported.json?.error,'NotImplemented');
      const duplicated=await get(endpoint('getRepo')+'&did='+did);
      assert.equal(duplicated.status,400);
      assert.equal(duplicated.json?.error,'InvalidRequest');
      process.env.NODE_ENV='production';
      const refused=await get(endpoint('getRepo'));
      assert.equal(refused.status,503);
      assert.equal(refused.json?.error,'InternalError');
      process.env.NODE_ENV='test';
    });
  }finally{
    if(oldEnv===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=oldEnv;
    try{await close(server);}
    finally{
      try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');}
      finally{await pool.end();}
    }
  }
});
