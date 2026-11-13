import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Pool } from 'pg';
import * as cbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { createSignedRepoProofStore } from './store.mjs';
import { createSignedSingleRecordWriter } from './single-record-writer.mjs';
import {
  carFromSingleRecordBlocks,verifySignedSingleRecordSnapshot
} from './signed-single-record.mjs';
import { createNativeOutboxDispatcher } from './native-outbox-dispatch.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)) {
  throw Error('Native event outbox acceptance is disposable PG18 only');
}
const pool=new Pool({
  connectionString:DSN,max:4,connectionTimeoutMillis:3000,
  idleTimeoutMillis:3000,allowExitOnIdle:true
});
const did=name=>'did:plc:'+name.padEnd(24,'a').slice(0,24);
const account=name=>'https://paper.example.org/users/'+name;
function keypair(){
  const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{
    namedCurve:'secp256k1'
  });
  return {
    publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
    signer:async bytes=>crypto.sign('sha256',bytes,{
      key:privateKey,dsaEncoding:'ieee-p1363'
    })
  };
}
async function getBlock(subject,blockCid) {
  const r=await pool.query(
    'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
    [subject,blockCid]
  );
  if(r.rowCount!==1) {
    const e=Error('Missing signed event block');
    e.code='NATIVE_EVENT_INTEGRITY_INVALID';
    throw e;
  }
  return r.rows[0].block;
}
const rejectCode=(promise,code)=>assert.rejects(promise,e=>e?.code===code);

test('native signed-event outbox claims are fenced, ordered and at least once',async t=>{
  const oldEnv=process.env.NODE_ENV;
  try{
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    )).rows[0].n,0);
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./schema.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./single-record-mutation.sql',import.meta.url)),'utf8'));
    const genesis=createSignedRepoProofStore({pool,fixtureOnly:true});
    const records=createSignedSingleRecordWriter({
      pool,fixtureOnly:true,authorize:async()=>true
    });
    const keys=new Map();
    async function newAccount(name) {
      const details=keypair();
      keys.set(did(name),details.publicKeyPem);
      const first=await genesis.bootstrap({
        accountId:account(name),did:did(name),...details
      });
      return {accountId:account(name),did:did(name),details,first};
    }
    const alice=await newAccount('alice');
    // A disposable SQL fixture simulates the exact genesis Jena ACK so a
    // second signed record commit can test historical ordered events.
    await pool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
      "state='applied',lease_epoch=1,applied_at=clock_timestamp() "+
      'WHERE account_id=$1 AND did=$2 AND head_cid=$3',
      [alice.accountId,alice.did,alice.first.commitCid]
    );
    const added=await records.write({
      accountId:alice.accountId,did:alice.did,
      expectedCommitCid:alice.first.commitCid,
      expectedRev:alice.first.rev,action:'create',
      path:'app.bsky.feed.post/3jzm3xwpf342a',
      record:{$type:'app.bsky.feed.post',text:'Hello',
        createdAt:'2026-11-13T00:00:00.000Z'},
      ...alice.details
    });
    assert.notEqual(added.commitCid,alice.first.commitCid);

    const published=[];
    const errorModes=new Map();
    const verifyEvent=async ({did:subject,commitCid,rev,signal})=>{
      assert.equal(signal.aborted,false);
      // Reference from immutable blocks, NOT necessarily the newest head:
      // events are emitted in commit order even after the repository moves.
      const commitBytes=await getBlock(subject,commitCid);
      const commit=cbor.decode(commitBytes);
      assert.equal(commit.did,subject);
      const rootCid=commit.data.toString();
      const rootBytes=await getBlock(subject,rootCid);
      const root=cbor.decode(rootBytes);
      const recordCid=root.e.length===1?root.e[0].v.toString():null;
      const recordBytes=recordCid?await getBlock(subject,recordCid):null;
      const car=await carFromSingleRecordBlocks({
        commitCid,rootCid,commitBytes,rootBytes,recordCid,recordBytes
      });
      const proof=await verifySignedSingleRecordSnapshot({
        did:subject,publicKeyPem:keys.get(subject),carBytes:car
      });
      assert.equal(proof.rev,rev);
      return {
        verified:true,did:subject,commitCid,rev,
        // This is an INTERNAL fixture payload, NOT a claimed ATProto
        // subscription event or a publicly federated firehose frame.
        eventBytes:Buffer.from(JSON.stringify({
          did:subject,commitCid,rev,recordCid:proof.recordCid
        }))
      };
    };
    const publish=async ({did:subject,commitCid,idempotencyKey,eventBytes,signal})=>{
      assert.equal(signal.aborted,false);
      assert.ok(eventBytes.length>0 && eventBytes.length<1024);
      published.push({subject,commitCid,idempotencyKey});
      const mode=errorModes.get(subject);
      if(mode?.failures>0){
        mode.failures--;
        const e=Error('simulated Redpanda durable ACK unavailable');
        e.code='NATIVE_BROKER_TIMEOUT';
        throw e;
      }
      return {acked:true,idempotencyKey};
    };
    const dispatcher=()=>createNativeOutboxDispatcher({
      pool,verifyEvent,publish,fixtureOnly:true,maxAttempts:2,
      leaseSeconds:10
    });
    const workers=Array.from({length:8},dispatcher);

    await t.test('only first pending revision of one DID is claimable across eight workers',async()=>{
      const batch=await Promise.all(workers.map(w=>w.deliverOnce()));
      assert.equal(batch.filter(x=>x.delivered).length,1);
      assert.equal(batch.filter(x=>x.claimed===false).length,7);
      assert.equal(published.length,1);
      assert.equal(published[0].commitCid,alice.first.commitCid);
      assert.equal((await dispatcher().inspect({
        did:alice.did,commitCid:alice.first.commitCid
      })).status,'delivered');
      const next=await dispatcher().deliverOnce();
      assert.equal(next.delivered,true);
      assert.equal(published[1].commitCid,added.commitCid);
      assert.notEqual(published[0].idempotencyKey,published[1].idempotencyKey);
      assert.equal((await dispatcher().deliverOnce()).claimed,false);
    });
    await t.test('crash after broker ACK before PG ACK replays exactly the same key',async()=>{
      const bob=await newAccount('bob');
      const crash=dispatcher();
      await rejectCode(crash.deliverOnce({testCrashAfterPublish:true}),
        'NATIVE_OUTBOX_TEST_CRASH');
      const before=await crash.inspect({
        did:bob.did,commitCid:bob.first.commitCid
      });
      assert.equal(before.status,'pending');
      assert.equal(before.attempts,1);
      assert.equal((await crash.deliverOnce()).claimed,false,
        'active lease prevents duplicate delivery by another worker');
      // Simulated SIGKILL recovery: the lease expires on the DB clock.
      await pool.query(
        "UPDATE paper_atproto_repo_proof.native_event_outbox SET "+
        "lease_until=clock_timestamp()-interval '1 second' "+
        'WHERE did=$1 AND commit_cid=$2',
        [bob.did,bob.first.commitCid]
      );
      const retry=await dispatcher().deliverOnce();
      assert.equal(retry.delivered,true);
      const bobEvents=published.filter(e=>e.subject===bob.did);
      assert.equal(bobEvents.length,2,'at-least-once publish can repeat after ACK loss');
      assert.equal(bobEvents[0].idempotencyKey,bobEvents[1].idempotencyKey,
        'downstream deduplication must use stable DID+commit key');
      assert.equal((await dispatcher().inspect({
        did:bob.did,commitCid:bob.first.commitCid
      })).status,'delivered');
    });
    await t.test('bounded transient retry and terminal poison prevent busy loops',async()=>{
      const charlie=await newAccount('charlie');
      errorModes.set(charlie.did,{failures:1});
      const first=await dispatcher().deliverOnce();
      assert.equal(first.delivered,false);
      assert.equal(first.blocked,false);
      assert.equal(first.retryScheduled,true);
      assert.equal((await dispatcher().deliverOnce()).claimed,false,
        'future retry schedule must not be polled immediately');
      await pool.query(
        'UPDATE paper_atproto_repo_proof.native_event_outbox '+
        'SET next_attempt_at=clock_timestamp()-interval \'1 second\' '+
        'WHERE did=$1 AND commit_cid=$2',[charlie.did,charlie.first.commitCid]
      );
      assert.equal((await dispatcher().deliverOnce()).delivered,true);

      const dave=await newAccount('dave');
      errorModes.set(dave.did,{failures:3});
      assert.equal((await dispatcher().deliverOnce()).retryScheduled,true);
      await pool.query(
        'UPDATE paper_atproto_repo_proof.native_event_outbox '+
        'SET next_attempt_at=clock_timestamp()-interval \'1 second\' '+
        'WHERE did=$1 AND commit_cid=$2',[dave.did,dave.first.commitCid]
      );
      const second=await dispatcher().deliverOnce();
      assert.equal(second.blocked,true);
      assert.equal(second.retryScheduled,false);
      assert.equal((await dispatcher().deliverOnce()).claimed,false);
      const blocked=await dispatcher().inspect({
        did:dave.did,commitCid:dave.first.commitCid
      });
      assert.equal(blocked.blocked,true);
      assert.equal(blocked.attempts,2);
      await rejectCode(genesis.verify({
        accountId:dave.accountId,did:dave.did,
        publicKeyPem:dave.details.publicKeyPem
      }),'ATPROTO_REPO_OUTBOX_BLOCKED');
    });
    await t.test('tampered historical commit is blocked, never sent to transport',async()=>{
      const eve=await newAccount('eve');
      const old=(await pool.query(
        'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
        [eve.did,eve.first.commitCid]
      )).rows[0].block;
      const before=published.length;
      await pool.query(
        'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
        [eve.did,eve.first.commitCid,Buffer.from('corrupt')]
      );
      try{
        const result=await dispatcher().deliverOnce();
        assert.equal(result.blocked,true);
        assert.equal(published.length,before);
      }finally{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
          [eve.did,eve.first.commitCid,old]
        );
      }
    });
    await t.test('production cannot activate a constructed dispatcher',async()=>{
      const live=dispatcher();
      process.env.NODE_ENV='production';
      await rejectCode(live.deliverOnce(),'NATIVE_OUTBOX_DISPATCH_NOT_RELEASED');
      process.env.NODE_ENV='test';
      const closed=createNativeOutboxDispatcher({pool,verifyEvent,publish});
      await rejectCode(closed.deliverOnce(),'NATIVE_OUTBOX_DISPATCH_NOT_RELEASED');
    });
  }finally{
    if(oldEnv===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=oldEnv;
    try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');}
    finally{await pool.end();}
  }
});
