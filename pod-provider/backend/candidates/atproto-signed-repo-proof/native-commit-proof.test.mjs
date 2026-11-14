import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath,pathToFileURL } from 'node:url';
import * as cbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { Pool } from 'pg';
import { createSignedRepoProofStore } from './store.mjs';
import { createReferenceMstWriter } from './reference-mst-writer.mjs';
import { createNativeCommitProof } from './native-commit-proof.mjs';
import { createNativeOutboxDispatcher } from './native-outbox-dispatch.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
const REF=process.env.ATPROTO_REFERENCE_REPO_ENTRY||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN) ||
   !REF.startsWith('/'))throw Error('Inductive native-event proof requires pinned upstream MST and disposable PG18');
const reference=await import(pathToFileURL(REF).href);
const pool=new Pool({
  connectionString:DSN,max:6,connectionTimeoutMillis:4000,
  idleTimeoutMillis:3000,allowExitOnIdle:true
});
const accountId='https://paper.example.org/users/native-event';
const did='did:plc:'+'n'.repeat(24);
const ALPHABET='234567abcdefghijklmnopqrstuvwxyz';
function pathFor(i){
  let n=i,suffix='';
  for(let j=0;j<4;j++){suffix=ALPHABET[n%32]+suffix;n=Math.floor(n/32);}
  return 'app.bsky.feed.post/3jzm3xwpf'+suffix;
}
function post(i,text){
  return {$type:'app.bsky.feed.post',text,
    createdAt:'2026-11-13T00:00:00.000Z'};
}
const refuse=(promise,code)=>assert.rejects(promise,error=>{
  assert.equal(error?.code,code,
    'Expected '+code+' but received '+error?.code+': '+error?.message);
  return true;
});

test('historical signed native #commit is invertible from bounded proof CAR after later commits',async t=>{
  const initialEnv=process.env.NODE_ENV;
  try{
    const empty=await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    );
    assert.equal(empty.rows[0].n,0);
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./schema.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./single-record-mutation.sql',import.meta.url)),'utf8'));
    const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{namedCurve:'secp256k1'});
    const credentials={
      publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
      signer:async bytes=>crypto.sign('sha256',bytes,{
        key:privateKey,dsaEncoding:'ieee-p1363'
      })
    };
    const genesis=createSignedRepoProofStore({pool,fixtureOnly:true});
    const writer=createReferenceMstWriter({
      pool,reference,fixtureOnly:true,authorize:async()=>true
    });
    let approved=true;
    const native=createNativeCommitProof({
      pool,reference,fixtureOnly:true,
      authorize:async({accountId:owner,did:subject,scope})=>{
        assert.equal(owner,accountId);
        assert.equal(subject,did);
        assert.equal(scope,'atproto:native-event');
        return approved;
      }
    });
    let head=await genesis.bootstrap({accountId,did,...credentials});
    const genesisHead=head;
    const journal=[{head,action:null,path:null,prev:null,newCid:null}];
    async function project(){
      const response=await pool.query(
        "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='applied',"+
        "lease_epoch=lease_epoch+1,applied_at=clock_timestamp() "+
        "WHERE account_id=$1 AND did=$2 AND state='pending' AND head_cid=$3 "+
        'RETURNING generation',[accountId,did,head.commitCid]
      );
      assert.equal(response.rowCount,1);
    }
    await project();
    async function mutate(action,index,text){
      const former=head,path=pathFor(index);
      const record=action==='delete'?null:post(index,text);
      head=await writer.write({
        accountId,did,expectedCommitCid:former.commitCid,
        expectedRev:former.rev,action,path,record,...credentials
      });
      journal.push({
        head,action,path,
        prev:former,previousRev:former.rev,previousRootCid:former.rootCid,
        oldCid:head.previousRootCid ? null : undefined
      });
      await project();
      return head;
    }
    await t.test('construct several real signed commits and keep genesis event pending',async()=>{
      for(let i=0;i<18;i++)await mutate('create',i,'Original '+i);
      await mutate('update',10,'Updated 10');
      await mutate('delete',4);
      assert.equal(head.generation,21);
      const all=await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox '+
        'WHERE did=$1 AND status=$2',[did,'pending']
      );
      assert.equal(all.rows[0].n,21);
    });
    async function eventFor(h){
      return native.materialize({
        accountId,did,commitCid:h.commitCid,rev:h.rev,
        publicKeyPem:credentials.publicKeyPem
      });
    }
    async function assertEnvelope(h,result){
      assert.equal(result.verified,true);
      assert.equal(result.did,did);
      assert.equal(result.commitCid,h.commitCid);
      assert.equal(result.rev,h.rev);
      assert.equal(result.idempotencyKey,'at.commit.v1:'+did+':'+h.commitCid);
      const out=await pool.query(
        'SELECT id FROM paper_atproto_repo_proof.native_event_outbox '+
        'WHERE did=$1 AND commit_cid=$2',[did,h.commitCid]
      );
      assert.equal(result.seq,Number(out.rows[0].id));
      const prefix=Buffer.from(cbor.encode({op:1,t:'#commit'}));
      assert(Buffer.from(result.eventBytes).subarray(0,prefix.length).equals(prefix));
      const decoded=cbor.decode(Buffer.from(result.eventBytes).subarray(prefix.length));
      assert.equal(decoded.repo,did);
      assert.equal(decoded.seq,result.seq);
      assert.equal(decoded.rev,h.rev);
      assert.equal(decoded.commit.toString(),h.commitCid);
      assert.equal(decoded.rebase,false);
      assert.equal(decoded.tooBig,false);
      assert.equal(decoded.blobs.length,0);
      assert(Buffer.from(decoded.blocks).equals(Buffer.from(result.carBytes)));
      const car=await reference.readCarWithRoot(result.carBytes);
      assert.equal(car.root.toString(),h.commitCid);
      assert.equal(car.blocks.size,result.blockCount);
      const obj=reference.parseObjByDef(
        car.blocks.get(car.root),car.root,reference.def.commit
      ).obj;
      assert.equal(obj.did,did);
      assert.equal(obj.rev,h.rev);
      return {decoded,car,obj};
    }
    await t.test('oldest genesis event remains valid after 20 later signed writes',async()=>{
      const g=await eventFor(genesisHead);
      const {decoded,car,obj}=await assertEnvelope(genesisHead,g);
      assert.equal(decoded.since,null);
      assert.equal(decoded.ops.length,0);
      assert.equal(decoded.prevData,undefined);
      assert.equal(car.blocks.size,2);
      assert.equal(car.blocks.get(obj.data)!==undefined,true);
      assert.equal((await eventFor(genesisHead)).idempotencyKey,g.idempotencyKey);
    });
    await t.test('historical create event uses root covering proof and inverse delete',async()=>{
      const created=journal[11]; // a middle history event, not current head
      const e=await eventFor(created.head);
      const {decoded,car,obj}=await assertEnvelope(created.head,e);
      assert.equal(decoded.since,created.previousRev);
      assert.equal(decoded.prevData.toString(),created.previousRootCid);
      assert.equal(decoded.ops.length,1);
      const op=decoded.ops[0];
      assert.equal(op.action,'create');
      assert.equal(op.path,created.path);
      assert.equal(op.prev,undefined);
      assert(CID.asCID(op.cid));
      assert(e.blockCount<20,'inductive CAR must be far smaller than full 18-record repo');
      const memory=new reference.MemoryBlockstore(car.blocks);
      const tree=reference.MST.load(memory,obj.data);
      const leaf=await tree.get(op.path);
      assert.equal(leaf.toString(),op.cid.toString());
      const reverted=await tree.delete(op.path);
      assert.equal((await reverted.getPointer()).toString(),
        created.previousRootCid);
    });
    await t.test('historical update and delete events invert to exact preceding tree roots',async()=>{
      for(const entry of journal.slice(-2)){
        const event=await eventFor(entry.head);
        const {decoded,car,obj}=await assertEnvelope(entry.head,event);
        assert.equal(decoded.ops.length,1);
        const op=decoded.ops[0];
        assert.equal(op.action,entry.action);
        assert.equal(op.prev!==undefined,true);
        const storage=new reference.MemoryBlockstore(car.blocks);
        const tree=reference.MST.load(storage,obj.data);
        let inverse;
        if(op.action==='update'){
          assert(op.cid!==null);
          inverse=await tree.update(op.path,op.prev);
        }else{
          assert.equal(op.cid,null);
          inverse=await tree.add(op.path,op.prev);
        }
        assert.equal((await inverse.getPointer()).toString(),
          entry.previousRootCid);
      }
    });
    await t.test('corrupt immutable historical root and mismatched audit both block event',async()=>{
      const h=journal[8].head;
      const audit=await pool.query(
        'SELECT previous_root_cid FROM paper_atproto_repo_proof.record_mutations '+
        'WHERE did=$1 AND commit_cid=$2',[did,h.commitCid]
      );
      const oldRoot=audit.rows[0].previous_root_cid;
      const bytes=(await pool.query(
        'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
        [did,oldRoot]
      )).rows[0].block;
      await pool.query(
        'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
        [did,oldRoot,Buffer.from('corrupt')]
      );
      try {
        await refuse(eventFor(h),'NATIVE_COMMIT_BLOCK_INVALID');
      }finally{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
          [did,oldRoot,bytes]
        );
      }
      // Tamper a persisted UPDATE instead of a CREATE: the SQL audit
      // correctly forbids a create action from having a previous CID.
      // A plausible but incorrect prior record CID must fail at signed
      // old/new MST reconciliation, not just the SQL CHECK constraint.
      const auditedUpdate=journal[journal.length-2].head;
      const previousCid=(await pool.query(
        'SELECT previous_record_cid FROM paper_atproto_repo_proof.record_mutations '+
        'WHERE did=$1 AND commit_cid=$2',[did,auditedUpdate.commitCid]
      )).rows[0].previous_record_cid;
      await pool.query(
        'UPDATE paper_atproto_repo_proof.record_mutations '+
        'SET previous_record_cid=$3 WHERE did=$1 AND commit_cid=$2',
        [did,auditedUpdate.commitCid,'bafyre'+'b'.repeat(53)]
      );
      try{
        await refuse(eventFor(auditedUpdate),'NATIVE_COMMIT_AUDIT_MISMATCH');
      }finally{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.record_mutations '+
          'SET previous_record_cid=$3 WHERE did=$1 AND commit_cid=$2',
          [did,auditedUpdate.commitCid,previousCid]
        );
      }
    });
    await t.test('oversized event, blocked older queue and revoked authorization refuse',async()=>{
      await refuse(native.materialize({
        accountId,did,commitCid:head.commitCid,rev:head.rev,
        publicKeyPem:credentials.publicKeyPem,maxBytes:256
      }),'NATIVE_COMMIT_TOO_LARGE');
      approved=false;
      await refuse(eventFor(genesisHead),'NATIVE_COMMIT_NOT_AUTHORIZED');
      approved=true;
      await pool.query(
        'UPDATE paper_atproto_repo_proof.native_event_outbox SET '+
        'blocked_at=clock_timestamp() WHERE did=$1 AND commit_cid=$2',
        [did,genesisHead.commitCid]
      );
      try{
        await refuse(eventFor(head),'NATIVE_COMMIT_OUTBOX_BLOCKED');
      }finally{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.native_event_outbox SET '+
          'blocked_at=NULL WHERE did=$1 AND commit_cid=$2',
          [did,genesisHead.commitCid]
        );
      }
    });
    await t.test('eight parallel PG outbox workers deliver historical verified frames in order',async()=>{
      // Integrate the real durable PG lease/ack dispatcher with the actual
      // signed historic CAR materializer. Only the broker transport is a
      // deterministic disposable adapter; NO live Redpanda/relay is enabled.
      const published=[];
      const verifyEvent=async({did:subject,commitCid,rev,signal})=>{
        assert.equal(signal.aborted,false);
        assert.equal(subject,did);
        return native.materialize({
          accountId,did:subject,commitCid,rev,
          publicKeyPem:credentials.publicKeyPem
        });
      };
      const publish=async({idempotencyKey,commitCid,eventBytes,signal})=>{
        assert.equal(signal.aborted,false);
        const expected='at.commit.v1:'+did+':'+commitCid;
        assert.equal(idempotencyKey,expected);
        assert(eventBytes.byteLength>48);
        published.push({idempotencyKey,commitCid});
        return {acked:true,idempotencyKey};
      };
      const dispatcher=()=>createNativeOutboxDispatcher({
        pool,fixtureOnly:true,verifyEvent,publish,maxAttempts:3,leaseSeconds:20
      });
      await Promise.all(Array.from({length:8},()=>dispatcher().deliverOnce()));
      for(let attempt=0;attempt<24;attempt++){
        if((await pool.query(
          'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox '+
          "WHERE did=$1 AND status='pending'",[did]
        )).rows[0].n===0)break;
        await dispatcher().deliverOnce();
      }
      const rows=await pool.query(
        'SELECT commit_cid,status,blocked_at FROM paper_atproto_repo_proof.native_event_outbox '+
        'WHERE did=$1 ORDER BY id',[did]
      );
      assert.equal(rows.rowCount,journal.length);
      assert(rows.rows.every(x=>x.status==='delivered'&&x.blocked_at===null));
      assert.equal(published.length,journal.length);
      assert.deepEqual(published.map(x=>x.commitCid),
        journal.map(x=>x.head.commitCid),
        'per-DID native outbox must deliver signed historical frames in exact order');
      assert.equal(new Set(published.map(x=>x.idempotencyKey)).size,published.length);
    });

    await t.test('production release boundary cannot be bypassed by an existing object',async()=>{
      const closed=createNativeCommitProof({
        pool,reference,authorize:async()=>true
      });
      await refuse(closed.materialize({}),'NATIVE_COMMIT_NOT_RELEASED');
      process.env.NODE_ENV='production';
      await refuse(eventFor(genesisHead),'NATIVE_COMMIT_NOT_RELEASED');
      process.env.NODE_ENV='test';
    });
  }finally{
    if(initialEnv===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=initialEnv;
    try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');}
    finally{await pool.end();}
  }
});
