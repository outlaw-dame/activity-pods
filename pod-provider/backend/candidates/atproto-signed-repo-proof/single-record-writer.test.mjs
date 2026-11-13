import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Pool } from 'pg';
import * as cbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { createSignedRepoProofStore } from './store.mjs';
import { makeTid } from './genesis.mjs';
import { createSignedSingleRecordWriter } from './single-record-writer.mjs';
import { verifySignedSingleRecordSnapshot } from './signed-single-record.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)){
  throw Error('Signed record mutation proof only supports disposable local PG18');
}
const pool=new Pool({connectionString:DSN,max:4,connectionTimeoutMillis:3000,
  idleTimeoutMillis:3000,allowExitOnIdle:true});
const did=n=>'did:plc:'+n.padEnd(24,'a').slice(0,24);
const account=n=>'https://paper.example.org/users/'+n;
const path='app.bsky.feed.post/3jzm3xwpf342a';
const record=text=>({
  $type:'app.bsky.feed.post',text,
  createdAt:'2026-11-13T00:00:00.000Z'
});
function fixture(){
  const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{namedCurve:'secp256k1'});
  return {
    publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
    signer:async bytes=>crypto.sign('sha256',bytes,{key:privateKey,dsaEncoding:'ieee-p1363'})
  };
}
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);

test('PG18 signed v3 single-record commit CAS + atomic blocks/outbox/fence',async t=>{
  let priorEnv=process.env.NODE_ENV;
  try{
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    )).rows[0].n,0);
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./schema.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./single-record-mutation.sql',import.meta.url)),'utf8'));
    const genesis=createSignedRepoProofStore({pool,fixtureOnly:true});
    let consent=true,authorizations=0;
    const writer=createSignedSingleRecordWriter({
      pool,fixtureOnly:true,
      authorize:async({accountId,did,expectedCommitCid,scope})=>{
        assert(accountId.startsWith('https://paper.example.org/'));
        assert.match(did,/^did:plc:/u);
        assert.match(expectedCommitCid,/^bafyre/u);
        assert.equal(scope,'atproto:record-write');
        authorizations++;
        return consent;
      }
    });
    const signed=fixture(),acc=account('alice'),subject=did('alice');
    const first=await genesis.bootstrap({
      accountId:acc,did:subject,...signed
    });
    const original=await writer.verify({
      accountId:acc,did:subject,publicKeyPem:signed.publicKeyPem
    });
    assert.equal(original.commitCid,first.commitCid);
    assert.equal(original.path,null);
    assert.equal(original.recordCid,null);
    assert.equal(original.generation,1);

    await t.test('mutation cannot run in production or without fixture gate',async()=>{
      const closed=createSignedSingleRecordWriter({pool,authorize:async()=>true});
      await rejects(closed.write({}),'SINGLE_RECORD_WRITER_NOT_RELEASED');
      process.env.NODE_ENV='production';
      await rejects(writer.verify({
        accountId:acc,did:subject,publicKeyPem:signed.publicKeyPem
      }),'SINGLE_RECORD_WRITER_NOT_RELEASED');
      process.env.NODE_ENV='test';
    });

    await t.test('signed create: actual canonical one-leaf MST and outbox committed atomically',async()=>{
      const next=await writer.write({
        accountId:acc,did:subject,expectedCommitCid:first.commitCid,
        expectedRev:first.rev,action:'create',path,record:record('Hello!'),
        ...signed
      });
      assert.equal(next.verified,true);
      assert.equal(next.path,path);
      assert.equal(next.generation,2);
      assert.equal(next.outboxStatus,'pending');
      const verified=await verifySignedSingleRecordSnapshot({
        did:subject,publicKeyPem:signed.publicKeyPem,carBytes:next.carBytes
      });
      assert.equal(verified.commitCid,next.commitCid);
      assert.equal(verified.recordCid,next.recordCid);
      const mst=await pool.query(
        'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
        [subject,next.rootCid]
      );
      const node=cbor.decode(mst.rows[0].block);
      assert.equal(node.l,null);
      assert.equal(node.e.length,1);
      assert.equal(Buffer.from(node.e[0].k).toString(),path);
      assert.equal(node.e[0].t,null);
      assert.equal(node.e[0].v.toString(),next.recordCid);
      assert.equal(node.e[0].p,0);
      const ledger=await pool.query(
        'SELECT action,previous_commit_cid,commit_cid,previous_record_cid,'+
        'record_cid,generation FROM paper_atproto_repo_proof.record_mutations WHERE did=$1',
        [subject]
      );
      assert.equal(ledger.rowCount,1);
      assert.deepEqual([
        ledger.rows[0].action,ledger.rows[0].previous_commit_cid,
        ledger.rows[0].commit_cid,ledger.rows[0].previous_record_cid,
        ledger.rows[0].record_cid,Number(ledger.rows[0].generation)
      ],['create',first.commitCid,next.commitCid,null,next.recordCid,2]);
      const job=await pool.query(
        'SELECT state,generation,lease_epoch,applied_at,head_cid FROM '+
        'paper_atproto_repo_proof.rdf_projection_jobs WHERE account_id=$1',
        [acc]
      );
      assert.equal(job.rows[0].state,'pending');
      assert.equal(Number(job.rows[0].generation),2);
      assert.equal(job.rows[0].applied_at,null);
      assert.equal(job.rows[0].head_cid,next.commitCid);
      assert.equal(Number(job.rows[0].lease_epoch),0);
      assert(authorizations>=2);
    });
    let current=await writer.verify({
      accountId:acc,did:subject,publicKeyPem:signed.publicKeyPem
    });
    await t.test('unprojected revision, stale heads and invalid revisions reject mutation',async()=>{
      const input={
        accountId:acc,did:subject,expectedCommitCid:current.commitCid,
        expectedRev:current.rev,action:'update',path,record:record('Updated'),
        ...signed
      };
      await rejects(writer.write(input),'SINGLE_RECORD_PROJECTION_NOT_APPLIED');
      await rejects(writer.write({...input,expectedCommitCid:first.commitCid}),
        'SINGLE_RECORD_STALE_HEAD');
      await rejects(writer.write({...input,rev:current.rev}),
        'SINGLE_RECORD_REVISION_NOT_INCREASING');
      consent=false;
      await rejects(writer.write(input),'SINGLE_RECORD_WRITE_NOT_AUTHORIZED');
      consent=true;
      assert.equal((await writer.verify({accountId:acc,did:subject,
        publicKeyPem:signed.publicKeyPem})).commitCid,current.commitCid);
    });
    async function project(verified){
      // SQL fixture simulates a completed protected Jena fence. This is NOT
      // an actual SAI grant or atomic Fuseki projection; those have their
      // separate real-Jena acceptance job.
      const ack=await pool.query(
        "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
        "state='applied',lease_epoch=lease_epoch+1,applied_at=clock_timestamp() "+
        "WHERE account_id=$1 AND did=$2 AND state='pending' AND head_cid=$3 "+
        "RETURNING generation,lease_epoch",
        [acc,subject,verified.commitCid]
      );
      assert.equal(ack.rowCount,1);
      return ack.rows[0];
    }
    await project(current);
    await t.test('signed update preserves one canonical record and old immutable blocks',async()=>{
      const old=current;
      current=await writer.write({
        accountId:acc,did:subject,expectedCommitCid:old.commitCid,
        expectedRev:old.rev,action:'update',path,record:record('Updated'),
        ...signed
      });
      assert.equal(current.generation,3);
      assert.notEqual(current.rootCid,old.rootCid);
      assert.notEqual(current.recordCid,old.recordCid);
      assert.equal(current.path,path);
      const oldBlock=await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.blocks '+
        'WHERE did=$1 AND cid IN ($2,$3,$4)',[
          subject,old.commitCid,old.rootCid,old.recordCid
        ]);
      assert.equal(oldBlock.rows[0].n,3,'previous signed head is immutable');
      const audit=await pool.query(
        'SELECT action,previous_record_cid,record_cid FROM '+
        'paper_atproto_repo_proof.record_mutations WHERE did=$1 AND generation=3',
        [subject]
      );
      assert.equal(audit.rows[0].action,'update');
      assert.equal(audit.rows[0].previous_record_cid,old.recordCid);
      assert.equal(audit.rows[0].record_cid,current.recordCid);
    });
    await project(current);
    await t.test('signed delete returns exactly the canonical empty MST root',async()=>{
      const old=current;
      current=await writer.write({
        accountId:acc,did:subject,expectedCommitCid:old.commitCid,
        expectedRev:old.rev,action:'delete',path,record:null,
        ...signed
      });
      assert.equal(current.generation,4);
      assert.equal(current.rootCid,first.rootCid);
      assert.equal(current.recordCid,null);
      assert.equal(current.path,null);
      const events=await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox WHERE did=$1',
        [subject]
      );
      assert.equal(events.rows[0].n,4,'genesis + create + update + delete persisted');
    });
    await t.test('tampered record bytes or wrong public key cannot verify',async()=>{
      const other=fixture();
      await assert.rejects(writer.verify({
        accountId:acc,did:subject,publicKeyPem:other.publicKeyPem
      }));
      const old=await pool.query(
        'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
        [subject,current.rootCid]
      );
      await pool.query(
        'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
        [subject,current.rootCid,Buffer.from('corrupt')]
      );
      try{await assert.rejects(writer.verify({
        accountId:acc,did:subject,publicKeyPem:signed.publicKeyPem
      }));}finally{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
          [subject,current.rootCid,old.rows[0].block]
        );
      }
      assert.equal((await writer.verify({
        accountId:acc,did:subject,publicKeyPem:signed.publicKeyPem
      })).commitCid,current.commitCid);
    });
    await t.test('eight replicas writing same expected head yield one signed commit',async()=>{
      const bob=account('bob'),bobDid=did('bob');
      const own=fixture();
      const original=await genesis.bootstrap({accountId:bob,did:bobDid,...own});
      const batch=await Promise.allSettled(Array.from({length:8},()=>writer.write({
        accountId:bob,did:bobDid,expectedCommitCid:original.commitCid,
        expectedRev:original.rev,action:'create',path,record:record('Race'),
        ...own
      })));
      assert.equal(batch.filter(x=>x.status==='fulfilled').length,1);
      assert.equal(batch.filter(x=>x.status==='rejected' &&
        x.reason?.code==='SINGLE_RECORD_STALE_HEAD').length,7);
      const ok=batch.find(x=>x.status==='fulfilled').value;
      assert.equal(ok.generation,2);
      const events=await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox WHERE did=$1',
        [bobDid]
      );
      assert.equal(events.rows[0].n,2);
    });
    await t.test('injected transaction failure leaves no record block/outbox/head drift',async()=>{
      const charlie=account('charlie'),charlieDid=did('charlie');
      const own=fixture();
      const original=await genesis.bootstrap({
        accountId:charlie,did:charlieDid,...own
      });
      await rejects(writer.write({
        accountId:charlie,did:charlieDid,
        expectedCommitCid:original.commitCid,expectedRev:original.rev,
        action:'create',path,record:record('Rollback'),...own,
        testFailAfterOutbox:true
      }),'SINGLE_RECORD_TEST_INJECTED_FAILURE');
      const recovered=await writer.verify({
        accountId:charlie,did:charlieDid,publicKeyPem:own.publicKeyPem
      });
      assert.equal(recovered.commitCid,original.commitCid);
      assert.equal(recovered.generation,1);
      assert.equal((await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox WHERE did=$1',
        [charlieDid]
      )).rows[0].n,1);
    });
    await t.test('lost COMMIT reply forces reconciliation and never reports rollback',async()=>{
      const dave=account('dave'),daveDid=did('dave'),own=fixture();
      const original=await genesis.bootstrap({accountId:dave,did:daveDid,...own});
      let discarded=false;
      const lostPool={
        query:(...args)=>pool.query(...args),
        async connect(){
          const c=await pool.connect();
          return {
            async query(...args){
              if(args[0]==='COMMIT'){
                await c.query(...args);
                throw Error('lost reply after real COMMIT');
              }
              return c.query(...args);
            },
            release(discard){
              discarded=discard===true;c.release(discard);
            }
          };
        }
      };
      const uncertain=createSignedSingleRecordWriter({
        pool:lostPool,fixtureOnly:true,authorize:async()=>true
      });
      await rejects(uncertain.write({
        accountId:dave,did:daveDid,
        expectedCommitCid:original.commitCid,expectedRev:original.rev,
        action:'create',path,record:record('Committed'),...own
      }),'SINGLE_RECORD_COMMIT_OUTCOME_UNKNOWN');
      assert.equal(discarded,true);
      const recovery=await writer.verify({
        accountId:dave,did:daveDid,publicKeyPem:own.publicKeyPem
      });
      assert.equal(recovery.generation,2);
      assert.equal(recovery.outboxStatus,'pending');
      await rejects(writer.write({
        accountId:dave,did:daveDid,
        expectedCommitCid:original.commitCid,expectedRev:original.rev,
        action:'create',path,record:record('Duplicate'),...own
      }),'SINGLE_RECORD_STALE_HEAD');
    });
  }finally{
    if(priorEnv===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=priorEnv;
    try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');}
    finally{await pool.end();}
  }
});
