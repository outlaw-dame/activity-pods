/**
 * Runs AFTER pinned @atproto/repo is installed by the existing independent
 * reference CI step. These proofs operate on the EXACT disposable PG18 DSN.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath,pathToFileURL } from 'node:url';
import { CID } from 'multiformats/cid';
import { Pool } from 'pg';
import { createSignedRepoProofStore } from './store.mjs';
import { createReferenceMstWriter } from './reference-mst-writer.mjs';
import { cid, checkRecord } from './signed-single-record.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
const REF=process.env.ATPROTO_REFERENCE_REPO_ENTRY||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN) ||
   !REF.startsWith('/')) {
  throw Error('Multi-record reference proof needs exact disposable PG18 and pinned upstream library');
}
const reference=await import(pathToFileURL(REF).href);
const pool=new Pool({
  connectionString:DSN,max:6,connectionTimeoutMillis:5000,
  idleTimeoutMillis:3000,allowExitOnIdle:true
});
const accountId='https://paper.example.org/users/multi-mst';
const did='did:plc:'+'m'.repeat(24);
const pathFor=i=>'app.bsky.feed.post/3jzm3xwpf'+i.toString(36).padStart(4,'2')+'a';
const post=(i,text)=>({
  $type:'app.bsky.feed.post',text,
  createdAt:'2026-11-13T00:00:00.000Z',langs:['en'],
  facets:[],sequence:i
});
const assertError=(promise,code)=>assert.rejects(promise,e=>{
  assert.equal(e?.code,code,
    'unexpected error: expected '+code+', received '+String(e?.code)+
    ', message: '+String(e?.message));
  return true;
});
async function projectExactHead(head) {
  const applied=await pool.query(
    'UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET '+
    "state='applied',lease_epoch=lease_epoch+1,applied_at=clock_timestamp() "+
    'WHERE account_id=$1 AND did=$2 AND head_cid=$3 '+
    "AND state='pending' RETURNING generation,lease_epoch",
    [accountId,did,head.commitCid]
  );
  assert.equal(applied.rowCount,1);
  assert.equal(Number(applied.rows[0].generation),head.generation??1);
}
async function countBlocks(){
  const row=await pool.query(
    'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.blocks WHERE did=$1',[did]
  );
  return row.rows[0].n;
}

test('reference MST immutable multi-record PG18 signing and durability gates',async t=>{
  const oldEnv=process.env.NODE_ENV;
  try {
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    )).rows[0].n,0,'isolated empty schema required');
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./schema.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./single-record-mutation.sql',import.meta.url)),'utf8'));
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
    let authorized=true,authorizations=0;
    const writer=createReferenceMstWriter({
      pool,reference,fixtureOnly:true,
      authorize:async scope=>{
        assert.equal(scope.accountId,accountId);
        assert.equal(scope.did,did);
        assert.equal(scope.scope,'atproto:record-write');
        authorizations++;
        return authorized;
      }
    });
    let current=await genesis.bootstrap({accountId,did,...keys});
    const genesisHead=current.commitCid;
    await projectExactHead(current);
    let official=await reference.MST.create(new reference.MemoryBlockstore());
    assert.equal((await official.getPointer()).toString(),current.rootCid);
    const expected=new Map();

    async function mutate({action,index,record=null,expectedHead=current}) {
      const path=pathFor(index);
      const next=await writer.write({
        accountId,did,action,path,record,...keys,
        expectedCommitCid:expectedHead.commitCid,
        expectedRev:expectedHead.rev
      });
      const link=record===null?null:await cid(checkRecord(record,path));
      if(action==='create')official=await official.add(path,link);
      else if(action==='update')official=await official.update(path,link);
      else official=await official.delete(path);
      if(record===null)expected.delete(path);
      else expected.set(path,link.toString());
      assert.equal(next.rootCid,(await official.getPointer()).toString(),
        'PG signed commit must match exact upstream MST root for all changes');
      assert.equal(next.generation,(current.generation||1)+1);
      assert(next.rev>current.rev,'revision strictly grows');
      assert.equal(next.previousCommitCid,current.commitCid);
      assert.equal(next.previousRootCid,current.rootCid);
      assert.equal(next.previousRev,current.rev);
      current=next;
      return next;
    }

    await t.test('no eager account-wide record read: 36 separate immutable record insertions',async()=>{
      for(let i=0;i<36;i++){
        const rec=post(i,'Independent canonical post '+i);
        await mutate({action:'create',index:i,record:rec});
        await projectExactHead(current);
      }
      assert.equal(expected.size,36);
      assert.equal(current.generation,37);
      const root=await writer.verify({
        accountId,did,publicKeyPem:keys.publicKeyPem
      });
      assert.equal(root.rootCid,current.rootCid);
      for(const i of [0,7,18,26,35]){
        const checked=await writer.verify({
          accountId,did,path:pathFor(i),publicKeyPem:keys.publicKeyPem
        });
        assert.equal(checked.recordCid,expected.get(pathFor(i)));
      }
      const actual=await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.record_mutations WHERE did=$1',
        [did]
      );
      assert.equal(actual.rows[0].n,36);
      assert(authorizations>=72);
    });
    await t.test('update nonfirst and delete distant leaves without changing other CIDs',async()=>{
      const oldRecords=new Map(expected);
      await mutate({action:'update',index:27,record:post(27,'Edit 27')});
      await projectExactHead(current);
      for(const i of [2,17,30,7,0,35]){
        await mutate({action:'delete',index:i});
        await projectExactHead(current);
      }
      for(const i of [1,6,16,18,26,34]){
        const checked=await writer.verify({
          accountId,did,path:pathFor(i),publicKeyPem:keys.publicKeyPem
        });
        assert.equal(checked.recordCid,oldRecords.get(pathFor(i)));
      }
      const before=await countBlocks();
      await mutate({action:'update',index:11,record:post(11,'Small edit')});
      const delta=await countBlocks()-before;
      assert(delta>=2 && delta<=18,
        'one update should write only a small MST branch and commit');
      const state=await pool.query(
        'SELECT state,generation,lease_epoch FROM paper_atproto_repo_proof.rdf_projection_jobs '+
        'WHERE account_id=$1',[accountId]
      );
      assert.equal(state.rows[0].state,'pending');
      assert.equal(Number(state.rows[0].generation),current.generation);
      assert(Number(state.rows[0].lease_epoch)>1);
      // The current repository cannot be changed twice while its exact
      // signed head is not yet protected by a Jena projection ACK.
      await assertError(writer.write({
        accountId,did,...keys,action:'create',path:pathFor(90),
        record:post(90,'Not yet'),expectedCommitCid:current.commitCid,
        expectedRev:current.rev
      }),'REFERENCE_MST_PROJECTION_NOT_APPLIED');
      await projectExactHead(current);
    });
    await t.test('wrong path and rejected grant fail without extra CID blocks',async()=>{
      const count=await countBlocks();
      await assertError(writer.write({
        accountId,did,...keys,action:'create',path:pathFor(11),
        record:post(11,'Duplicate'),expectedCommitCid:current.commitCid,
        expectedRev:current.rev
      }),'REFERENCE_MST_PATH_EXISTS');
      await assertError(writer.write({
        accountId,did,...keys,action:'delete',path:pathFor(91),
        expectedCommitCid:current.commitCid,expectedRev:current.rev
      }),'REFERENCE_MST_PATH_NOT_FOUND');
      await assertError(writer.write({
        accountId,did,...keys,action:'update',path:pathFor(11),
        record:post(11,'Small edit'),expectedCommitCid:current.commitCid,
        expectedRev:current.rev
      }),'REFERENCE_MST_NOOP_UPDATE');
      authorized=false;
      await assertError(writer.write({
        accountId,did,...keys,action:'update',path:pathFor(11),
        record:post(11,'Unauthorized'),expectedCommitCid:current.commitCid,
        expectedRev:current.rev
      }),'REFERENCE_MST_NOT_AUTHORIZED');
      authorized=true;
      assert.equal(await countBlocks(),count);
    });
    await t.test('eight racing writers yield exactly one signed head generation',async()=>{
      const prior=current;
      const batch=await Promise.allSettled(Array.from({length:8},(_,i)=>writer.write({
        accountId,did,...keys,action:'update',path:pathFor(11),
        record:post(11,'Race contender '+i),
        expectedCommitCid:prior.commitCid,expectedRev:prior.rev
      })));
      assert.equal(batch.filter(x=>x.status==='fulfilled').length,1);
      assert.equal(batch.filter(x=>x.status==='rejected' &&
        x.reason?.code==='REFERENCE_MST_STALE_HEAD').length,7);
      current=batch.find(x=>x.status==='fulfilled').value;
      assert.equal(current.generation,prior.generation+1);
      const rows=await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.record_mutations '+
        'WHERE did=$1 AND generation=$2',[did,current.generation]
      );
      assert.equal(rows.rows[0].n,1);
      await projectExactHead(current);
    });
    await t.test('transaction failure after native event does not advance head or leave blocks',async()=>{
      const before=await countBlocks();
      const prior=current;
      await assertError(writer.write({
        accountId,did,...keys,action:'create',path:pathFor(91),
        record:post(91,'Rollback fixture'),expectedCommitCid:prior.commitCid,
        expectedRev:prior.rev,testFailAfterOutbox:true
      }),'REFERENCE_MST_TEST_INJECTED_FAILURE');
      assert.equal(await countBlocks(),before);
      assert.equal((await writer.verify({
        accountId,did,publicKeyPem:keys.publicKeyPem
      })).commitCid,prior.commitCid);
      assert.equal((await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox WHERE did=$1',
        [did]
      )).rows[0].n,prior.generation);
    });
    await t.test('corrupt historical CID and unrelated blocked outbox deny verification',async()=>{
      const history=await pool.query(
        'SELECT previous_commit_cid FROM paper_atproto_repo_proof.record_mutations '+
        'WHERE did=$1 AND generation=$2',[did,current.generation]
      );
      const previousCid=history.rows[0].previous_commit_cid;
      const original=(await pool.query(
        'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
        [did,previousCid]
      )).rows[0].block;
      await pool.query(
        'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
        [did,previousCid,Buffer.from('corrupt')]
      );
      try{
        await assertError(writer.verify({
          accountId,did,publicKeyPem:keys.publicKeyPem
        }),'REFERENCE_MST_DURABLE_BLOCK_INVALID');
      }finally{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
          [did,previousCid,original]
        );
      }
      await pool.query(
        "UPDATE paper_atproto_repo_proof.native_event_outbox SET "+
        "blocked_at=clock_timestamp(),last_error_code='NATIVE_RETRY_EXHAUSTED' "+
        'WHERE did=$1 AND commit_cid=$2',[did,genesisHead]
      );
      await assertError(writer.verify({
        accountId,did,publicKeyPem:keys.publicKeyPem
      }),'REFERENCE_MST_OUTBOX_BLOCKED');
      await pool.query(
        'UPDATE paper_atproto_repo_proof.native_event_outbox '+
        'SET blocked_at=NULL,last_error_code=NULL WHERE did=$1 AND commit_cid=$2',
        [did,genesisHead]
      );
    });
    await t.test('fixture-only/production release fence cannot be toggled open',async()=>{
      const unavailable=createReferenceMstWriter({
        pool,reference,authorize:async()=>true
      });
      await assertError(unavailable.verify({}),'REFERENCE_MST_NOT_RELEASED');
      process.env.NODE_ENV='production';
      await assertError(writer.verify({
        accountId,did,publicKeyPem:keys.publicKeyPem
      }),'REFERENCE_MST_NOT_RELEASED');
      process.env.NODE_ENV='test';
    });
  }finally{
    if(oldEnv===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=oldEnv;
    try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');}
    finally{await pool.end();}
  }
});
