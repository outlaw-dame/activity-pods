'use strict';

/**
 * Disposable PostgreSQL 18 sustained-queue and backpressure measurement.
 * Measures real enqueue/claim/complete/retry SQL over multiple bursts.
 * No live provider, external traffic, object storage, or production DB.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { Pool } from 'pg';

const require=createRequire(import.meta.url);
const { createCanonicalNotificationLedger } =
  require('../../utils/canonical-notification-pg-ledger.js');
const dsn=process.env.ATPROTO_REPO_PROOF_DSN||'';
if(process.env.NODE_ENV!=='test' ||
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
    !/^postgres(?:ql)?:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(dsn)){
  throw Error('Notification workload requires disposable PostgreSQL 18');
}
const pool=new Pool({
  connectionString:dsn,max:4,connectionTimeoutMillis:3000,
  idleTimeoutMillis:3000,query_timeout:6500,allowExitOnIdle:true
});
const ledger=createCanonicalNotificationLedger({pool});
const SCHEMA='paper_notification_ledger';
const WAVES=8;
const INTENTS_PER_WAVE=128;
const RECIPIENTS_PER_INTENT=2;
const TOTAL=WAVES*INTENTS_PER_WAVE*RECIPIENTS_PER_INTENT;
const timings={enqueue:[],delivery:[]};
const rss=[];
const backlog=[];
let attemptedDeliveries=0, failedOnce=0, successfulDeliveries=0, emptyPolls=0;
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const now=()=>Number(process.hrtime.bigint())/1e6;
const sample=(items,percentile)=>{
  if(!items.length)return 0;
  const index=Math.min(items.length-1,Math.max(0,Math.ceil(items.length*percentile)-1));
  return Number(items[index].toFixed(3));
};
function make(index){
  const actorUri='https://remote.example.test/batched';
  const recipients=Array.from({length:RECIPIENTS_PER_INTENT},(_,n)=>{
    const id=index*RECIPIENTS_PER_INTENT+n;
    return {
      recipient:'https://paper.example.test/people/'+id,
      actorUri,
      activity:{
        id:'https://paper.example.test/_notify/'+id+'#event',
        type:'Follow',actor:actorUri,
        object:'https://paper.example.test/people/'+id
      }
    };
  });
  return {
    intentId:'measured-pg-intent-'+index,
    kind:'FollowAdd',protocol:'activitypub',recipients
  };
}
async function stateCounts(){
  const r=await pool.query(
    'SELECT state,count(*)::int AS n FROM '+SCHEMA+
    '.deliveries GROUP BY state');
  return Object.fromEntries(r.rows.map(x=>[x.state,x.n]));
}
async function processClaimed(item){
  attemptedDeliveries++;
  const begun=now();
  // Deterministic 1/8 of recipient hashes receive one transient failure.
  // All retries are real durable rows, with production-style full-jitter
  // backoff; do not force next_attempt_at or bypass the scheduler.
  const forceOnce=Number.parseInt(item.recipient_key.slice(-2),16)%8===0 &&
    Number(item.attempts)===0;
  if(forceOnce){
    await ledger.fail({
      intentKey:item.intent_key,recipientKey:item.recipient_key,
      workerToken:item.workerToken,reasonCode:'SYNTHETIC_TRANSIENT'
    });
    failedOnce++;
  }else{
    await ledger.finish({
      intentKey:item.intent_key,recipientKey:item.recipient_key,
      workerToken:item.workerToken
    });
    successfulDeliveries++;
  }
  timings.delivery.push(now()-begun);
}
async function drainBatch(target){
  let claimed=0;
  while(claimed<target){
    const jobs=await ledger.claim({
      limit:Math.min(8,target-claimed),workerToken:crypto.randomUUID()
    });
    if(!jobs.length)break;
    claimed+=jobs.length;
    await Promise.all(jobs.map(processClaimed));
  }
  return claimed;
}
async function drainRemaining(){
  const deadline=now()+30000;
  while(now()<deadline){
    const remaining=await pool.query(
      'SELECT count(*)::int AS n FROM '+SCHEMA+
      ".deliveries WHERE state IN ('pending','leased')");
    if(remaining.rows[0].n===0)return;
    const claimed=await drainBatch(32);
    if(claimed===0){
      emptyPolls++;
      await sleep(25);
    }
  }
  throw Error('Notification backlog failed to drain under bounded test deadline');
}
let applied=false;
async function main(){
  const existing=await pool.query("SELECT to_regnamespace('paper_notification_ledger') AS schema");
  assert.equal(existing.rows[0].schema,null);
  await pool.query(await readFile(
    new URL('../../sql/paper-canonical-notification-ledger-v1.sql',import.meta.url),'utf8'));
  applied=true;
  try{
    await ledger.verifySchema();
    // Capture exact WAL LSN progression for this short isolated test.
    // It includes server housekeeping, so it is a measured upper-bound
    // context, not a pure per-notification WAL byte count.
    const walStart = await pool.query('SELECT pg_current_wal_lsn()::text AS lsn');
    const start=now();
    for(let wave=0;wave<WAVES;wave++){
      let next=wave*INTENTS_PER_WAVE;
      const max=next+INTENTS_PER_WAVE;
      // Eight bounded producers share a four-connection pool. Intent
      // payloads are generated on demand and never held in a global list.
      await Promise.all(Array.from({length:8},async()=>{
        while(next<max){
          const index=next++;
          const begun=now();
          const result=await ledger.enqueue(make(index));
          assert.equal(result.accepted,true);
          timings.enqueue.push(now()-begun);
        }
      }));
      // Consumer's capacity is intentionally half the incoming recipient
      // count in each wave, so backlog growth is visible and controlled.
      await drainBatch(128);
      const counts=await stateCounts();
      backlog.push({
        wave:wave+1,pending:counts.pending||0,
        leased:counts.leased||0,delivered:counts.delivered||0
      });
      if(typeof global.gc==='function')global.gc();
      const memory=process.memoryUsage();
      rss.push({
        wave:wave+1,rssBytes:memory.rss,heapUsedBytes:memory.heapUsed
      });
    }
    const peakBacklog=Math.max(...backlog.map(x=>x.pending+x.leased));
    const drainStart=now();
    await drainRemaining();
    const drainMs=now()-drainStart;
    const final=await stateCounts();
    const walFinish=await pool.query(
      'SELECT pg_wal_lsn_diff(pg_current_wal_lsn(),$1::pg_lsn)::text AS bytes',
      [walStart.rows[0].lsn]
    );
    const observedWalBytes=Number(walFinish.rows[0].bytes);
    assert(Number.isFinite(observedWalBytes) && observedWalBytes >= 0);
    assert.equal(final.delivered,TOTAL);
    assert.equal(final.pending||0,0);
    assert.equal(final.leased||0,0);
    assert.equal(final.dead||0,0);
    assert.equal(successfulDeliveries,TOTAL);
    assert.equal(attemptedDeliveries,TOTAL+failedOnce);
    assert(failedOnce>0,'Retry injection must actually exercise backoff');
    const relations=await pool.query(
      "SELECT pg_total_relation_size('paper_notification_ledger.intents')::bigint AS intents, " +
      "pg_total_relation_size('paper_notification_ledger.deliveries')::bigint AS deliveries, " +
      "pg_total_relation_size('paper_notification_ledger.quarantine')::bigint AS quarantine");
    const bytes=Object.fromEntries(
      Object.entries(relations.rows[0]).map(([k,v])=>[k,Number(v)]));
    const totalDbBytes=Object.values(bytes).reduce((a,b)=>a+b,0);
    timings.enqueue.sort((a,b)=>a-b);
    timings.delivery.sort((a,b)=>a-b);
    const wallTimeMs=now()-start;
    const report={
      success:true,
      scope:'disposable-postgresql18-bounded-multiphase-notification-workload',
      ciRunOnly:true,
      inputIntents:WAVES*INTENTS_PER_WAVE,
      uniqueRecipientNotifications:TOTAL,
      waves:WAVES,concurrentProducers:8,pgPoolMax:4,
      wallTimeMs:Number(wallTimeMs.toFixed(2)),
      enqueueLatencyMs:{
        p50:sample(timings.enqueue,0.5),
        p95:sample(timings.enqueue,0.95),
        p99:sample(timings.enqueue,0.99)
      },
      deliveryPersistenceLatencyMs:{
        p50:sample(timings.delivery,0.5),
        p95:sample(timings.delivery,0.95),
        p99:sample(timings.delivery,0.99)
      },
      backlogPerWave:backlog,
      peakBacklog,
      finalBacklog:(final.pending||0)+(final.leased||0),
      drainMs:Number(drainMs.toFixed(2)),
      uniqueDelivered:successfulDeliveries,
      simulatedTransientFailures:failedOnce,
      actualDeliveryAttempts:attemptedDeliveries,
      retryAmplification:Number((attemptedDeliveries/TOTAL).toFixed(4)),
      idlePollsWhileWaitingForBackoff:emptyPolls,
      postGcMemorySamples:rss,
      measuredPostGcRssDeltaBytes:rss.at(-1).rssBytes-rss[0].rssBytes,
      measuredPostGcHeapDeltaBytes:rss.at(-1).heapUsedBytes-rss[0].heapUsedBytes,
      relationBytes:bytes,totalRelationBytes:totalDbBytes,
      observedWalLsnBytes:observedWalBytes,
      observedWalBytesPerRecipient:Number((observedWalBytes/TOTAL).toFixed(2)),
      illustrativeBytesPerRecipient:Number((totalDbBytes/TOTAL).toFixed(2)),
      illustrativeDecimalGbAtMillionRecipients:Number(
        (totalDbBytes/TOTAL*1e6/1e9).toFixed(4)),
      costScope:'Measured primary relation/index size plus observed WAL-LSN growth, not retained WAL size; excludes replicas, backups, CPU, egress, vacuum, provider prices',
      limits:'Single GitHub Actions runner and PG18 container; no deployed end-to-end webhooks, push/WebSocket latency, memory-leak proof or production costs'
    };
    console.log(JSON.stringify(report));
    if(process.env.RUNNER_TEMP){
      await writeFile(process.env.RUNNER_TEMP+'/paper-notification-pg-steady-capacity.json',
        JSON.stringify(report,null,2),{flag:'wx'});
    }
  }finally{
    if(applied)await pool.query('DROP SCHEMA IF EXISTS '+SCHEMA+' CASCADE');
    await pool.end();
  }
}
main().catch(error=>{
  console.error('Notification PG sustained benchmark failed:',error?.code||error?.name||'UNKNOWN');
  process.exitCode=1;
});
