/**
 * Disposable, REAL Redpanda v26.2.x broker integration.
 * No fake Kafka ACK: actual KafkaJS producer metadata and consumer records.
 * Requires pinned reference MST and pinned test-only KafkaJS dependency.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import {test} from 'node:test';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {Pool} from 'pg';
import * as cbor from '@ipld/dag-cbor';
import {createSignedRepoProofStore} from './store.mjs';
import {createReferenceMstWriter} from './reference-mst-writer.mjs';
import {createNativeCommitProof} from './native-commit-proof.mjs';
import {createNativeOutboxDispatcher} from './native-outbox-dispatch.mjs';
import {
  createNativeRedpandaPublisher,MIN_BROKER_TOPIC_MESSAGE_BYTES
} from './native-redpanda-publisher.mjs';
import {createNativeBrokerReceiptStore} from './native-redpanda-receipts.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
const REFERENCE=process.env.ATPROTO_REFERENCE_REPO_ENTRY||'';
const KAFKA=process.env.ATPROTO_KAFKAJS_ENTRY||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
   process.env.ATPROTO_REDPANDA_TEST_DISPOSABLE!=='confirmed' ||
   process.env.ATPROTO_REDPANDA_BROKERS!=='127.0.0.1:19092' ||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN) ||
   !REFERENCE.startsWith('/')||!KAFKA.startsWith('/')){
  throw Error('Native broker integration requires explicit disposable PG18, local Redpanda and pinned libraries');
}
const reference=await import(pathToFileURL(REFERENCE).href);
const kafkajs=(await import(pathToFileURL(KAFKA).href)).default;
const {Kafka,ConfigResourceTypes,CompressionTypes,logLevel}=kafkajs;
const pool=new Pool({
  connectionString:DSN,max:8,connectionTimeoutMillis:5000,
  idleTimeoutMillis:3000,allowExitOnIdle:true
});
const kafka=new Kafka({
  clientId:'paper-native-redpanda-proof',
  brokers:['127.0.0.1:19092'],
  connectionTimeout:8000,requestTimeout:8000,
  retry:{initialRetryTime:200,retries:1},
  logLevel:logLevel.ERROR
});
const topic='paper.atproto.native.commit.disposable';
const stressTopic=topic+'.payload';
function keys(){
  const pair=crypto.generateKeyPairSync('ec',{namedCurve:'secp256k1'});
  return {
    publicKeyPem:pair.publicKey.export({format:'pem',type:'spki'}).toString(),
    signer:async bytes=>crypto.sign('sha256',bytes,{
      key:pair.privateKey,dsaEncoding:'ieee-p1363'
    })
  };
}
async function projectionApplied(accountId,did,head){
  const result=await pool.query(
    "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
    "state='applied',lease_epoch=lease_epoch+1,applied_at=clock_timestamp() "+
    "WHERE account_id=$1 AND did=$2 AND head_cid=$3 AND state='pending' "+
    'RETURNING generation',[accountId,did,head.commitCid]
  );
  assert.equal(result.rowCount,1);
}
const rejectCode=(promise,code)=>assert.rejects(promise,e=>{
  assert.equal(e?.code,code,
    'expected '+code+', received '+e?.code+': '+e?.message);
  return true;
});
async function readBroker(group,expected,receipt){
  const consumer=kafka.consumer({
    groupId:group,allowAutoTopicCreation:false,
    maxBytes:4_000_000,maxBytesPerPartition:3_000_000,
    sessionTimeout:12000,heartbeatInterval:3000,
    retry:{retries:1}
  });
  const events=[];
  await consumer.connect();
  try{
    await consumer.subscribe({topic,fromBeginning:true});
    await consumer.run({
      autoCommit:false,
      eachMessage:async ({topic:receivedTopic,partition,message})=>{
        const record={
          receivedTopic,partition,offset:message.offset,
          key:message.key,value:message.value,headers:message.headers
        };
        const result=await receipt.observe(record);
        events.push({record,result});
      }
    });
    const until=Date.now()+16000;
    while(events.length<expected && Date.now()<until){
      await new Promise(resolve=>setTimeout(resolve,75));
    }
    assert.equal(events.length,expected,
      'broker consumer must read every physically persisted event within bounded test deadline');
    return events;
  }finally{
    await consumer.disconnect();
  }
}

test('Redpanda broker ACK, historical CBOR, PG18 worker crash and durable replay dedupe',async t=>{
  const originalEnv=process.env.NODE_ENV;
  const admin=kafka.admin({retry:{retries:1}});
  let producer=null,recoveryProducer=null;
  try{
    await admin.connect();
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    )).rows[0].n,0,'disposable integration must start with an empty proof schema');
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./schema.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./single-record-mutation.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./native-redpanda-receipts.sql',import.meta.url)),'utf8'));

    await admin.createTopics({waitForLeaders:true,topics:[
      {topic,numPartitions:3,replicationFactor:1,configEntries:[
        {name:'max.message.bytes',value:'2400000'},
        {name:'retention.ms',value:'3600000'},
        {name:'cleanup.policy',value:'delete'}
      ]},
      {topic:stressTopic,numPartitions:1,replicationFactor:1,configEntries:[
        {name:'max.message.bytes',value:'2400000'},
        {name:'retention.ms',value:'3600000'}
      ]}
    ]});
    const described=await admin.describeConfigs({
      includeSynonyms:false,
      resources:[{type:ConfigResourceTypes.TOPIC,name:topic,
        configNames:['max.message.bytes','retention.ms']}]
    });
    assert.equal(described.resources.length,1);
    assert.equal(described.resources[0].errorCode,0);
    const configs=new Map(described.resources[0].configEntries.map(x=>[
      x.configName,x.configValue
    ]));
    assert(Number(configs.get('max.message.bytes'))>=MIN_BROKER_TOPIC_MESSAGE_BYTES);
    assert.equal(configs.get('retention.ms'),'3600000');
    const topology=await admin.fetchTopicMetadata({topics:[topic]});
    assert.equal(topology.topics[0].partitions.length,3);
    assert(topology.topics[0].partitions.every(p=>p.replicas.length===1),
      'one broker is a dev fixture, not a production HA claim');

    producer=kafka.producer({
      allowAutoTopicCreation:false,maxInFlightRequests:5,
      retry:{retries:0},idempotent:false
    });
    await producer.connect();

    await t.test('actual broker accepts uncompressed >1 MiB payload on explicitly configured topic',async()=>{
      // Send a synthetic transport-only stress payload into a SEPARATE
      // non-public topic. Never masquerade random bytes as a signed event.
      const response=await producer.send({
        topic:stressTopic,acks:-1,timeout:7000,
        compression:CompressionTypes.None,
        messages:[{
          key:'stress',
          value:crypto.randomBytes(1_450_000)
        }]
      });
      assert.equal(response[0]?.topicName,stressTopic);
      assert(Number.isSafeInteger(response[0]?.partition));
      assert(/^(0|[1-9][0-9]*)$/u.test(response[0]?.baseOffset||''));
    });

    const alice={
      accountId:'https://paper.example.org/users/live-redpanda-alice',
      did:'did:plc:'+'a'.repeat(24),keys:keys()
    };
    const bob={
      accountId:'https://paper.example.org/users/live-redpanda-bob',
      did:'did:plc:'+'b'.repeat(24),keys:keys()
    };
    const accounts=new Map([[alice.did,alice],[bob.did,bob]]);
    const genesis=createSignedRepoProofStore({pool,fixtureOnly:true});
    const writer=createReferenceMstWriter({
      pool,reference,fixtureOnly:true,authorize:async()=>true
    });
    const native=createNativeCommitProof({
      pool,reference,fixtureOnly:true,authorize:async()=>true
    });
    const receipts=createNativeBrokerReceiptStore({
      pool,topic,fixtureOnly:true
    });
    alice.head=await genesis.bootstrap({
      accountId:alice.accountId,did:alice.did,...alice.keys
    });
    const genesisHead=alice.head;
    const aliceHeads=[genesisHead];
    await projectionApplied(alice.accountId,alice.did,alice.head);
    const path='app.bsky.feed.post/3jzm3xwpf342a';
    for(const action of ['create','update']){
      alice.head=await writer.write({
        accountId:alice.accountId,did:alice.did,...alice.keys,
        expectedCommitCid:alice.head.commitCid,
        expectedRev:alice.head.rev,
        action,path,
        record:{$type:'app.bsky.feed.post',
          text:action==='create'?'Initial native post':'Edited native post',
          createdAt:'2026-11-13T00:00:00.000Z'}
      });
      aliceHeads.push(alice.head);
      await projectionApplied(alice.accountId,alice.did,alice.head);
    }
    bob.head=await genesis.bootstrap({
      accountId:bob.accountId,did:bob.did,...bob.keys
    });
    await projectionApplied(bob.accountId,bob.did,bob.head);
    const eventFor=async ({did,commitCid,rev,signal})=>{
      assert.equal(signal?.aborted,false);
      const owner=accounts.get(did);
      assert(owner,'broker dispatcher must not materialize a foreign DID');
      return native.materialize({
        accountId:owner.accountId,did,commitCid,rev,
        publicKeyPem:owner.keys.publicKeyPem
      });
    };
    const publisher=createNativeRedpandaPublisher({
      producer,topic,fixtureOnly:true,timeoutMs:6000,
      compression:CompressionTypes.GZIP
    });
    const original=await eventFor({
      did:alice.did,commitCid:genesisHead.commitCid,rev:genesisHead.rev
    });
    const eventId='at.commit.v1:'+alice.did+':'+genesisHead.commitCid;
    const validPublishArgs={
      did:alice.did,commitCid:genesisHead.commitCid,
      rev:genesisHead.rev,idempotencyKey:eventId,
      eventBytes:original.eventBytes,signal:new AbortController().signal
    };

    await t.test('malformed signed envelope and falsified ACK cannot move the PG delivery state',async()=>{
      const fake=createNativeRedpandaPublisher({
        producer:{send:async()=>[]},topic,fixtureOnly:true
      });
      await rejectCode(fake(validPublishArgs),'NATIVE_BROKER_ACK_INVALID');
      await rejectCode(publisher({...validPublishArgs,did:bob.did}),
        'NATIVE_REDPANDA_FRAME_INVALID');
      const abort=new AbortController();
      abort.abort();
      await rejectCode(publisher({...validPublishArgs,signal:abort.signal}),
        'NATIVE_BROKER_LEASE_ABORTED');
      const state=await pool.query(
        "SELECT status,attempt_count FROM paper_atproto_repo_proof.native_event_outbox "+
        'WHERE did=$1 AND commit_cid=$2',[alice.did,genesisHead.commitCid]
      );
      assert.equal(state.rows[0].status,'pending');
      assert.equal(state.rows[0].attempt_count,0);
    });

    await t.test('real ACK before PG ACK loss yields durable replay, then eight-worker recovery',async()=>{
      const dispatch=publish=>createNativeOutboxDispatcher({
        pool,fixtureOnly:true,verifyEvent:eventFor,publish,
        maxAttempts:4,leaseSeconds:20
      });
      await rejectCode(dispatch(publisher).deliverOnce({
        testCrashAfterPublish:true
      }),'NATIVE_OUTBOX_TEST_CRASH');
      const inDoubt=await pool.query(
        'SELECT status,attempt_count,lease_epoch FROM '+
        'paper_atproto_repo_proof.native_event_outbox '+
        'WHERE did=$1 AND commit_cid=$2',
        [alice.did,genesisHead.commitCid]
      );
      assert.equal(inDoubt.rows[0].status,'pending');
      assert.equal(inDoubt.rows[0].attempt_count,1);
      // PG lease expires after a worker crash; no side effect may be
      // implicitly acknowledged. A NEW producer session replays the
      // exact frame and native event ID.
      await producer.disconnect();producer=null;
      recoveryProducer=kafka.producer({
        allowAutoTopicCreation:false,maxInFlightRequests:5,
        retry:{retries:0},idempotent:false
      });
      await recoveryProducer.connect();
      const resumed=createNativeRedpandaPublisher({
        producer:recoveryProducer,topic,fixtureOnly:true,timeoutMs:6000,
        compression:CompressionTypes.GZIP
      });
      await pool.query(
        "UPDATE paper_atproto_repo_proof.native_event_outbox SET "+
        "lease_until=clock_timestamp()-interval '1 second' "+
        'WHERE did=$1 AND commit_cid=$2 AND status=$3',
        [alice.did,genesisHead.commitCid,'pending']
      );
      const workers=Array.from({length:8},()=>dispatch(resumed));
      for(let round=0;round<8;round++){
        await Promise.all(workers.map(x=>x.deliverOnce()));
        const remaining=(await pool.query(
          "SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox "+
          "WHERE status='pending'"
        )).rows[0].n;
        if(remaining===0)break;
      }
      const rows=await pool.query(
        'SELECT did,commit_cid,status,attempt_count,blocked_at '+
        'FROM paper_atproto_repo_proof.native_event_outbox ORDER BY id'
      );
      assert.equal(rows.rowCount,4);
      assert(rows.rows.every(x=>x.status==='delivered'&&x.blocked_at===null));
      assert.equal(rows.rows[0].attempt_count,2);
      assert(rows.rows.slice(1).every(x=>x.attempt_count===1));
    });

    let observed=null;
    await t.test('broker consumption preserves DID order; durable receipt CAS suppresses ACK-retry duplicate',async()=>{
      observed=await readBroker(
        'paper-native-replay-a',5,receipts
      );
      assert.equal(observed.length,5,'4 signed commits plus one replay');
      const messages=observed.map(x=>({
        did:Buffer.from(x.record.key).toString('utf8'),
        seq:x.result.seq,commitCid:Buffer.from(
          x.record.headers['commit-cid']).toString('utf8'),
        partition:x.record.partition,offset:x.record.offset,
        firstSeen:x.result.firstSeen,
        eventId:x.result.idempotencyKey
      }));
      const seenAlice=messages.filter(x=>x.did===alice.did);
      assert.deepEqual(seenAlice.map(x=>x.commitCid),[
        aliceHeads[0].commitCid,aliceHeads[0].commitCid,
        aliceHeads[1].commitCid,aliceHeads[2].commitCid
      ]);
      assert(new Set(seenAlice.map(x=>x.partition)).size===1,
        'all events for one DID must have a stable broker partition');
      assert(messages.filter(x=>x.did===bob.did).length===1);
      assert.equal(messages.filter(x=>x.firstSeen).length,4);
      assert.equal(messages.filter(x=>!x.firstSeen).length,1);
      assert.equal(new Set(messages.filter(x=>x.firstSeen).map(x=>x.eventId)).size,4);
      const receiptsInPg=await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_broker_receipts'
      );
      assert.equal(receiptsInPg.rows[0].n,4);
    });

    await t.test('consumer restart replays every Kafka offset without applying one more effect',async()=>{
      const replay=await readBroker('paper-native-replay-b',5,receipts);
      assert.equal(replay.filter(x=>x.result.firstSeen).length,0);
      assert.equal((await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_broker_receipts'
      )).rows[0].n,4);
    });

    await t.test('same event identity but changed CBOR payload is rejected as durable replay conflict',async()=>{
      const first=observed.find(x=>x.result.firstSeen);
      assert(first);
      const raw=Buffer.from(first.record.value);
      const header=Buffer.from(cbor.encode({op:1,t:'#commit'}));
      assert(raw.subarray(0,header.length).equals(header));
      const payload=cbor.decode(raw.subarray(header.length));
      payload.time='2026-11-12T00:00:00.000Z';
      const changed=Buffer.concat([header,Buffer.from(cbor.encode(payload))]);
      await rejectCode(receipts.observe({
        ...first.record,value:changed
      }),'NATIVE_BROKER_REPLAY_CONFLICT');
    });

    await t.test('existing producer and receipt instances remain disabled in production',async()=>{
      const closed=createNativeRedpandaPublisher({
        producer:recoveryProducer,topic
      });
      await rejectCode(closed(validPublishArgs),'NATIVE_REDPANDA_NOT_RELEASED');
      process.env.NODE_ENV='production';
      await rejectCode(receipts.observe(observed[0].record),
        'NATIVE_BROKER_RECEIPT_NOT_RELEASED');
      const active=createNativeRedpandaPublisher({
        producer:recoveryProducer,topic,fixtureOnly:true
      });
      await rejectCode(active(validPublishArgs),'NATIVE_REDPANDA_NOT_RELEASED');
      process.env.NODE_ENV='test';
    });
  }finally{
    if(originalEnv===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=originalEnv;
    if(producer)await producer.disconnect();
    if(recoveryProducer)await recoveryProducer.disconnect();
    try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');}
    finally{
      await pool.end();
      await admin.disconnect();
    }
  }
});
