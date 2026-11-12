'use strict';

// Disposable, controlled multi-window notification-queue capacity measurement.
// This is not a production benchmark: CI loopback PG18, fixed pool and schema,
// explicit memory samples, full-indexed table size, and WAL byte estimates.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import {Pool} from 'pg';
import ledgerModule from '../../utils/canonical-notification-pg-ledger.js';
const {createCanonicalNotificationLedger}=ledgerModule;

const dsn=process.env.ATPROTO_REPO_PROOF_DSN||'';
if (process.env.NODE_ENV!=='test' ||
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
    !/^postgres(?:ql)?:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(dsn)) {
  throw Error('Sustained queue measurement requires disposable local PostgreSQL 18');
}
const schema='paper_notification_ledger';
const pool=new Pool({
  connectionString:dsn,max:4,connectionTimeoutMillis:3000,
  idleTimeoutMillis:3000,query_timeout:8000,allowExitOnIdle:true
});
const ledger=createCanonicalNotificationLedger({pool});
const now=()=>Number(process.hrtime.bigint())/1e6;
const pct=(arr,p)=>arr.length===0?0:
  Number(arr[Math.min(arr.length-1,Math.ceil(p*arr.length)-1)].toFixed(3));
const sampleMemory=()=>{
  if(global.gc)global.gc();
  const mem=process.memoryUsage();
  return {rssBytes:mem.rss,heapUsedBytes:mem.heapUsed,externalBytes:mem.external};
};
function request(i) {
  const actor='https://remote.example.test/users/verified';
  return {
    intentId:'stable-benchmark-intent-'+i,
    kind:'FollowAdd',protocol:'activitypub',
    recipients:Array.from({length:4},(_,k)=>{
      const recipient='https://paper.example.test/people/'+(i*4+k);
      return {
        recipient,actorUri:actor,
        activity:{
          id:'https://paper.example.test/_bridge/notification/'+i+'/'+k+'#event',
          type:'Follow',actor,object:recipient,to:[recipient]
        }
      };
    })
  };
}
async function backlog() {
  const rows=await pool.query(
    'SELECT state,count(*)::int AS count FROM '+schema+'.deliveries GROUP BY state');
  return Object.fromEntries(rows.rows.map(r=>[r.state,r.count]));
}
async function sizes(){
  const r=await pool.query(
    "SELECT pg_total_relation_size('paper_notification_ledger.deliveries')::bigint AS total, "+
    "pg_indexes_size('paper_notification_ledger.deliveries')::bigint AS indexes, "+
    "pg_total_relation_size('paper_notification_ledger.intents')::bigint AS intents, "+
    "pg_total_relation_size('paper_notification_ledger.quarantine')::bigint AS quarantine");
  return Object.fromEntries(Object.entries(r.rows[0]).map(([key,val])=>[key,Number(val)]));
}
const safeError=e=>e?.code||e?.name||'UNKNOWN';
async function main(){
  let created=false;
  await pool.query('SELECT 1');
  try{
    const check=await pool.query("SELECT to_regnamespace('paper_notification_ledger') AS schema");
    assert.equal(check.rows[0].schema,null,'Refuse to touch an existing ledger schema');
    await pool.query(await fs.readFile(
      new URL('../../sql/paper-canonical-notification-ledger-v1.sql',import.meta.url),'utf8'));
    created=true;
    await ledger.verifySchema();
    const rounds=12,perRound=512,concurrency=8;
    const before=sampleMemory();
    const beforeWal=(await pool.query('SELECT pg_current_wal_lsn() AS lsn')).rows[0].lsn;
    const phases=[];
    const allTimes=[];
    const start=now();
    for(let round=0;round<rounds;round++){
      const timings=[];
      let cursor=round*perRound,failed=0;
      const begin=now();
      await Promise.all(Array.from({length:concurrency},async()=>{
        while(cursor<(round+1)*perRound){
          const i=cursor++;
          const t=now();
          try{await ledger.enqueue(request(i+10000));}
          catch{failed++;}
          timings.push(now()-t);
        }
      }));
      assert.equal(failed,0);
      timings.sort((a,b)=>a-b);
      allTimes.push(...timings);
      const snapshot=await backlog();
      const size=await sizes();
      const memory=sampleMemory();
      phases.push({
        round:round+1,committedIntents:(round+1)*perRound,
        pendingRecipients:snapshot.pending||0,
        wallMs:Number((now()-begin).toFixed(2)),
        p50Ms:pct(timings,0.50),p95Ms:pct(timings,0.95),p99Ms:pct(timings,0.99),
        ...memory,tableBytes:size.total,indexBytes:size.indexes
      });
      assert.equal(snapshot.pending,(round+1)*perRound*4);
    }
    const ingestionMs=now()-start;
    allTimes.sort((a,b)=>a-b);
    const afterIngest=sampleMemory();
    const size=await sizes();
    const afterWal=(await pool.query('SELECT pg_current_wal_lsn() AS lsn')).rows[0].lsn;
    const wal=await pool.query('SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn) AS bytes',
      [afterWal,beforeWal]);
    const walBytes=Number(wal.rows[0].bytes);

    // Bounded, asynchronous worker-flow proof: deliberately fail 16 claims,
    // then claim/finish their replay. No production HTTP/push calls are made.
    const failureToken=crypto.randomUUID();
    const first=await ledger.claim({limit:16,workerToken:failureToken});
    assert.equal(first.length,16);
    await Promise.all(first.map(item=>ledger.fail({
      intentKey:item.intent_key,recipientKey:item.recipient_key,
      workerToken:failureToken,reasonCode:'BENCHMARK_TRANSIENT_FAILURE'
    })));
    const oneBackoff=(await pool.query(
      'SELECT count(*)::int AS n FROM '+schema+
      ".deliveries WHERE state='pending' AND attempts=1")).rows[0].n;
    assert.equal(oneBackoff,16);
    // Advance only fixture rows' scheduling clocks; the production retry
    // policy remains capped exponential full-jitter.
    await pool.query('UPDATE '+schema+
      ".deliveries SET next_attempt_at=clock_timestamp()-interval '1 minute' "+
      "WHERE state='pending' AND attempts=1");
    const secondToken=crypto.randomUUID();
    const replay=await ledger.claim({limit:16,workerToken:secondToken});
    assert.equal(replay.length,16);
    assert(replay.every(r=>Number(r.attempts)===1));
    await Promise.all(replay.map(item=>ledger.finish({
      intentKey:item.intent_key,recipientKey:item.recipient_key,
      workerToken:secondToken
    })));
    const afterDrain=await backlog();
    const finalMemory=sampleMemory();
    const records=rounds*perRound*4;
    const totalPgBytes=size.total+size.intents+size.quarantine;
    const bytesPerRecord=totalPgBytes/records;
    const report={
      success:true,scope:'disposable-pg18-repeated-queue-load',
      rounds,perRound,acceptedIntents:rounds*perRound,recipientRecords:records,
      poolMaxConnections:4,concurrentIngestWriters:concurrency,
      totalIngestMs:Number(ingestionMs.toFixed(2)),
      intentsPerSecond:Number((rounds*perRound*1000/ingestionMs).toFixed(2)),
      latencyMs:{
        p50:pct(allTimes,0.50),p95:pct(allTimes,0.95),p99:pct(allTimes,0.99),
        worstRoundP99:Math.max(...phases.map(p=>p.p99Ms))
      },
      memory:{
        before,afterIngest,final:finalMemory,
        rssGrowthBytes:afterIngest.rssBytes-before.rssBytes,
        heapGrowthBytes:afterIngest.heapUsedBytes-before.heapUsedBytes,
        rssFirstToLastRoundBytes:phases[phases.length-1].rssBytes-phases[0].rssBytes,
        sampledAfterExplicitGc:Boolean(global.gc)
      },
      queue:{
        maximumPendingRecords:records,
        afterSimulatedDelivery:afterDrain,
        transientFailureRecords:16,
        transientFailureDispatchAttempts:32,
        retryAmplificationForFailedSubset:2,
        separateQuarantineProofRequired:true
      },
      storage:{
        ...size,walBytes,bytesPerRecipientApprox:Number(bytesPerRecord.toFixed(2)),
        estimatedGiBForMillionRecipientRecords:Number(
          (bytesPerRecord*1000000/1024**3).toFixed(3)),
        estimatedWalGiBForMillionRecipientRecords:Number(
          (walBytes*1000000/records/1024**3).toFixed(3))
      },
      windows:phases,
      caveat:'Controlled loopback PG18 on a shared GitHub Actions runner. Single process over 12 windows; not production sustained RSS, real federation/push delivery, peak autoscaling or cloud-provider pricing.'
    };
    console.log(JSON.stringify(report));
    if(process.env.RUNNER_TEMP)await fs.writeFile(
      process.env.RUNNER_TEMP+'/paper-notification-pg-repeated-load.json',
      JSON.stringify(report,null,2));
  }finally{
    if(created)await pool.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE');
    await pool.end();
  }
}
main().catch(e=>{
  console.error('Repeated PG notification queue benchmark failed:',safeError(e));
  process.exitCode=1;
});
