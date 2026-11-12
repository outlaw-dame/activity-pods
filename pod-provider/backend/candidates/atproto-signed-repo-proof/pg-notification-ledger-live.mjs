'use strict';

// Disposable real PostgreSQL 18 proof and bounded throughput measurement.
// It cannot connect to a production database or modify an existing schema.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { Pool } from 'pg';
import ledgerModule from '../../utils/canonical-notification-pg-ledger.js';
const { createCanonicalNotificationLedger } = ledgerModule;

const dsn = process.env.ATPROTO_REPO_PROOF_DSN || '';
if (process.env.NODE_ENV !== 'test' ||
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    !/^postgres(?:ql)?:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(dsn)) {
  throw Error('Notification ledger proof must use disposable local PostgreSQL 18');
}
const pool = new Pool({
  connectionString: dsn, max: 4, connectionTimeoutMillis: 3000,
  idleTimeoutMillis: 3000, query_timeout: 6500, allowExitOnIdle: true
});
const schema = 'paper_notification_ledger';
const root = new URL('../../sql/paper-canonical-notification-ledger-v1.sql', import.meta.url);
const ledger = createCanonicalNotificationLedger({ pool });
const epochMs = () => Number(process.hrtime.bigint())/1e6;
const pct = (values,p) => values.length
  ? Number(values[Math.min(values.length-1,Math.ceil(values.length*p)-1)].toFixed(3)) : 0;
const makeRequest = (i, count=4) => ({
  intentId: 'canonical-notify-load-' + i,
  kind: 'FollowAdd', protocol: 'activitypub',
  recipients: Array.from({length:count},(_,n)=>({
    recipient: 'https://paper.example.test/people/' + (i*count+n),
    actorUri: 'https://remote.example.test/alice',
    activity: {
      id: 'https://paper.example.test/_bridge/event/' + i + '/' + n + '#event',
      actor: 'https://remote.example.test/alice',
      type: 'Follow',
      object: 'https://paper.example.test/people/' + (i*count+n)
    }
  }))
});
function isCode(error, code) { return error?.code === code; }
async function one(name,fn) {
  await fn();
  console.log(JSON.stringify({test:name,status:'passed'}));
}

async function prove() {
  const existing = await pool.query("SELECT to_regnamespace('paper_notification_ledger') AS name");
  assert.equal(existing.rows[0].name,null,'Fixture must not overwrite existing schema');
  await pool.query(await fs.readFile(root,'utf8'));
  try {
    await ledger.verifySchema();
    await one('manifest replay and collision fail closed',async()=>{
      const request=makeRequest(0,2);
      const first=await ledger.enqueue(request);
      assert.equal(first.duplicate,false);
      const second=await ledger.enqueue(request);
      assert.equal(second.duplicate,true);
      await assert.rejects(ledger.enqueue({...request,recipients:makeRequest(100,1).recipients}),
        e=>isCode(e,'PG_NOTIFY_INTENT_CONFLICT'));
      await assert.rejects(ledger.enqueue({...request,recipients:[]}),
        e=>isCode(e,'PG_NOTIFY_INTENT_CONFLICT'));
      const count=await pool.query('SELECT count(*)::int AS n FROM '+schema+'.deliveries');
      assert.equal(count.rows[0].n,2);
    });
    await one('concurrent manifests insert only one durable recipient copy',async()=>{
      const item=makeRequest(1,4);
      const results=await Promise.all(Array.from({length:8},()=>ledger.enqueue(item)));
      assert.equal(results.filter(v=>v.duplicate===false).length,1);
      assert.equal(results.filter(v=>v.duplicate===true).length,7);
      const k=crypto.createHash('sha256').update(item.intentId).digest();
      const count=await pool.query(
        'SELECT count(*)::int AS n FROM '+schema+'.deliveries WHERE intent_key=$1',[k]);
      assert.equal(count.rows[0].n,4);
    });
    await one('two workers cannot concurrently claim the same recipient',async()=>{
      const [a,b]=await Promise.all([
        ledger.claim({limit:2,workerToken:crypto.randomUUID()}),
        ledger.claim({limit:2,workerToken:crypto.randomUUID()})
      ]);
      const ids=[...a,...b].map(x=>x.intent_key+'/'+x.recipient_key);
      assert.equal(new Set(ids).size,ids.length);
      for(const item of [...a,...b]){
        assert.equal((await ledger.finish({
          intentKey:item.intent_key,recipientKey:item.recipient_key,
          workerToken:item.workerToken
        })).delivered,true);
      }
    });
    await one('expired crash lease can be recovered but stale finisher denied',async()=>{
      const req=makeRequest(9,1);await ledger.enqueue(req);
      const key=crypto.createHash('sha256').update(req.intentId).digest();
      const tokenA=crypto.randomUUID();
      const first=(await ledger.claim({limit:16,workerToken:tokenA}))
        .find(item=>item.intent_key===key.toString('hex'));
      assert(first);
      await pool.query(
        'UPDATE '+schema+".deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE intent_key=$1",
        [key]);
      const tokenB=crypto.randomUUID();
      const recovered=(await ledger.claim({limit:16,workerToken:tokenB}))
        .find(item=>item.intent_key===key.toString('hex'));
      assert(recovered);
      await assert.rejects(ledger.finish({
        intentKey:first.intent_key,recipientKey:first.recipient_key,workerToken:tokenA
      }),e=>isCode(e,'PG_NOTIFY_STALE_LEASE'));
      await ledger.finish({
        intentKey:recovered.intent_key,recipientKey:recovered.recipient_key,
        workerToken:tokenB
      });
    });
    await one('poison event stops retrying after eight attempts and is quarantined',async()=>{
      const req=makeRequest(10,1);await ledger.enqueue(req);
      const target=crypto.createHash('sha256').update(req.intentId).digest('hex');
      for(let attempt=1;attempt<=8;attempt++){
        const t=crypto.randomUUID();
        const work=(await ledger.claim({limit:16,workerToken:t}))
          .find(j=>j.intent_key===target);
        assert(work,'Poison item should be claimable on attempt '+attempt);
        const result=await ledger.fail({
          intentKey:work.intent_key,recipientKey:work.recipient_key,
          workerToken:t,reasonCode:'HANDLER_PERMANENT_FAILURE'
        });
        assert.equal(result.attempts,attempt);
        assert.equal(result.dead,attempt===8);
        await pool.query(
          'UPDATE '+schema+".deliveries SET next_attempt_at=clock_timestamp()-interval '1 second' "+
          'WHERE intent_key=$1',[Buffer.from(target,'hex')]);
      }
      const dlq=await pool.query(
        'SELECT attempts,reason_code FROM '+schema+'.quarantine WHERE intent_key=$1',
        [Buffer.from(target,'hex')]);
      assert.equal(dlq.rowCount,1);
      assert.equal(dlq.rows[0].attempts,8);
      assert.equal(dlq.rows[0].reason_code,'HANDLER_PERMANENT_FAILURE');
      const remain=await pool.query(
        'SELECT state FROM '+schema+'.deliveries WHERE intent_key=$1',
        [Buffer.from(target,'hex')]);
      assert.equal(remain.rows[0].state,'dead');
    });

    // Controlled PG18 loopback workload. This is NOT a production-capacity
    // benchmark: report environment and tail latency, never label it prod.
    const n=256, recipientsPerIntent=4;
    const timings=[];
    const rssBefore=process.memoryUsage().rss;
    const heapBefore=process.memoryUsage().heapUsed;
    let next=20, failures=0;
    const started=epochMs();
    await Promise.all(Array.from({length:8},async()=>{
      while(next<20+n){
        const index=next++;
        const begin=epochMs();
        try{await ledger.enqueue(makeRequest(index,recipientsPerIntent));}
        catch{failures++;}
        timings.push(epochMs()-begin);
      }
    }));
    assert.equal(failures,0);
    const elapsed=epochMs()-started;
    timings.sort((a,b)=>a-b);
    const counts=await pool.query(
      'SELECT state,count(*)::int AS count FROM '+schema+'.deliveries GROUP BY state');
    const bytes=await pool.query(
      "SELECT pg_total_relation_size('paper_notification_ledger.deliveries')::bigint AS bytes");
    const backlog=await pool.query(
      'SELECT count(*)::int AS n FROM '+schema+".deliveries WHERE state='pending'");
    const report={
      success:true,scope:'disposable-postgresql18-loopback-notification-ledger',
      inputIntents:n,recipientRecords:n*recipientsPerIntent,
      concurrency:8,pgPoolMax:4,
      wallTimeMs:Number(elapsed.toFixed(2)),
      throughputIntentsPerSecond:Number((n*1000/elapsed).toFixed(2)),
      latencyMs:{p50:pct(timings,0.5),p95:pct(timings,0.95),p99:pct(timings,0.99)},
      processRssDeltaBytes:process.memoryUsage().rss-rssBefore,
      processHeapDeltaBytes:process.memoryUsage().heapUsed-heapBefore,
      pendingBacklog:backlog.rows[0].n,
      totalDeliveryTableBytes:Number(bytes.rows[0].bytes),
      stateCounts:Object.fromEntries(counts.rows.map(r=>[r.state,r.count])),
      retryAmplificationOfLoad:0,
      caveat:'Local single-host CI workload only; no deployed p95/p99, RSS growth slope, sidecar Kafka load, or real monthly cloud-cost proof'
    };
    console.log(JSON.stringify(report));
    const artifact=process.env.RUNNER_TEMP;
    if(artifact)await fs.writeFile(artifact+'/paper-notification-pg-capacity.json',JSON.stringify(report,null,2));
  } finally {
    await pool.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE');
    await pool.end();
  }
}

prove().catch(error=>{
  console.error('PG notification ledger proof failed:',error?.code||error?.name||'UNKNOWN');
  process.exitCode=1;
});
