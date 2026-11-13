/**
 * NONACTIVATED: multi-replica-safe PostgreSQL at-least-once native outbox.
 *
 * Claims are short atomic SQL statements. Network publication occurs outside
 * PostgreSQL locks and uses a stable DID+commit idempotency key. The callback
 * must materialize an independently verified ATProto event and wait for a
 * durable broker ACK; it is NOT wired to a public firehose or XRPC service.
 */
import crypto from 'node:crypto';

const TABLE='paper_atproto_repo_proof.native_event_outbox';
const MAX_EVENT_BYTES=2*1024*1024;
const CID=/^bafyre[a-z2-7]{53}$/u;
const DID=/^did:plc:[a-z2-7]{24}$/u;
const TID=/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;

function fail(code) {
  const e=new Error('Native repository event dispatch unavailable');
  e.code=code;
  throw e;
}
function enabled(fixtureOnly) {
  if (fixtureOnly!==true || process.env.NODE_ENV==='production' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed') {
    fail('NATIVE_OUTBOX_DISPATCH_NOT_RELEASED');
  }
}
function errorCode(error) {
  const code=error?.code;
  return typeof code==='string' && /^NATIVE_[A-Z0-9_]{1,52}$/u.test(code) ?
    code : 'NATIVE_EVENT_DELIVERY_FAILED';
}
function backoffMs(attempt) {
  // Full jitter exponential backoff, bounded between 1 second and 5 min.
  // Exactly one attempt per explicit deliverOnce invocation: no busy loop.
  const ceiling=Math.min(300000,1000*2**Math.min(9,Math.max(0,attempt-1)));
  return crypto.randomInt(1000,Math.max(1001,ceiling+1));
}

/**
 * verifyEvent(event) -> {verified:true,did,commitCid,rev,eventBytes:Buffer}
 * publish(event)     -> {acked:true,idempotencyKey}
 * Both are trusted provider-side functions. No public caller-provided CAR,
 * record, topic, signing reference, broker credentials or user token.
 */
export function createNativeOutboxDispatcher({
  pool,verifyEvent,publish,fixtureOnly=false,leaseSeconds=30,maxAttempts=8
}={}) {
  const unavailable=async()=>fail('NATIVE_OUTBOX_DISPATCH_NOT_RELEASED');
  if(fixtureOnly!==true || process.env.NODE_ENV==='production' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'){
    return Object.freeze({deliverOnce:unavailable,inspect:unavailable});
  }
  if(!pool || typeof pool.query!=='function' ||
     typeof verifyEvent!=='function'||typeof publish!=='function' ||
     !Number.isSafeInteger(leaseSeconds)||leaseSeconds<5||leaseSeconds>300 ||
     !Number.isSafeInteger(maxAttempts)||maxAttempts<1||maxAttempts>20) {
    fail('NATIVE_OUTBOX_CONFIGURATION_INVALID');
  }
  async function claimOne() {
    const owner=crypto.randomUUID();
    const r=await pool.query(
      'WITH candidate AS (SELECT e.id FROM '+TABLE+' e '+
      "WHERE e.status='pending' AND e.blocked_at IS NULL "+
      'AND e.next_attempt_at<=clock_timestamp() '+
      'AND (e.lease_until IS NULL OR e.lease_until<=clock_timestamp()) '+
      'AND e.lease_epoch<9223372036854775807 '+
      'AND NOT EXISTS (SELECT 1 FROM '+TABLE+' older '+
      "WHERE older.did=e.did AND older.id<e.id AND older.status='pending') "+
      'ORDER BY e.id LIMIT 1 FOR UPDATE OF e SKIP LOCKED) '+
      'UPDATE '+TABLE+' o SET lease_owner=$1::uuid,'+
      "lease_until=clock_timestamp()+($2::int*interval '1 second'),"+
      'lease_epoch=o.lease_epoch+1,attempt_count=o.attempt_count+1 '+
      'FROM candidate WHERE o.id=candidate.id AND o.status=$3 '+
      'RETURNING o.id,o.did,o.commit_cid,o.rev,o.kind,'+
      'o.lease_epoch,o.lease_owner,o.attempt_count',
      [owner,leaseSeconds,'pending']
    );
    return r.rowCount===1 ? r.rows[0] : null;
  }
  function validateLease(row) {
    if (!Number.isSafeInteger(Number(row.id)) ||
        !DID.test(row.did||'') || !CID.test(row.commit_cid||'') ||
        !TID.test(row.rev||'') || row.kind!=='at.commit.v1' ||
        !Number.isSafeInteger(Number(row.attempt_count)) ||
        !Number.isSafeInteger(Number(row.lease_epoch)) ||
        Number(row.lease_epoch)<1 ||
        typeof row.lease_owner!=='string') {
      fail('NATIVE_OUTBOX_CORRUPT_CLAIM');
    }
  }
  async function acknowledge(row) {
    const r=await pool.query(
      'UPDATE '+TABLE+" SET status='delivered',delivered_at=clock_timestamp(),"+
      'lease_owner=NULL,lease_until=NULL,last_error_code=NULL '+
      'WHERE id=$1 AND did=$2 AND commit_cid=$3 AND '+
      'lease_epoch=$4::bigint AND lease_owner=$5::uuid '+
      "AND status='pending' AND blocked_at IS NULL "+
      'AND lease_until>clock_timestamp() RETURNING id',
      [row.id,row.did,row.commit_cid,String(row.lease_epoch),row.lease_owner]
    );
    if(r.rowCount!==1) fail('NATIVE_OUTBOX_LEASE_STALE');
  }
  async function failDelivery(row,code,terminal) {
    const blocked=terminal||Number(row.attempt_count)>=maxAttempts;
    const retryMs=blocked?0:backoffMs(Number(row.attempt_count));
    const r=await pool.query(
      'UPDATE '+TABLE+' SET lease_owner=NULL,lease_until=NULL,'+
      'last_error_code=$6,'+
      'next_attempt_at=CASE WHEN $7::bool THEN next_attempt_at '+
      "ELSE clock_timestamp()+($8::bigint*interval '1 millisecond') END,"+
      'blocked_at=CASE WHEN $7::bool THEN clock_timestamp() ELSE NULL END '+
      'WHERE id=$1 AND did=$2 AND commit_cid=$3 AND '+
      'lease_epoch=$4::bigint AND lease_owner=$5::uuid '+
      "AND status='pending' AND lease_until>clock_timestamp() "+
      'RETURNING id',
      [row.id,row.did,row.commit_cid,String(row.lease_epoch),
        row.lease_owner,code,blocked,retryMs]
    );
    if(r.rowCount!==1) fail('NATIVE_OUTBOX_LEASE_STALE');
    return {claimed:true,delivered:false,blocked,retryScheduled:!blocked};
  }
  async function inspect({did,commitCid}) {
    enabled(fixtureOnly);
    if(!DID.test(did||'')||!CID.test(commitCid||'')) {
      fail('NATIVE_OUTBOX_INPUT_INVALID');
    }
    const r=await pool.query(
      'SELECT status,attempt_count,lease_epoch,blocked_at,next_attempt_at '+
      'FROM '+TABLE+' WHERE did=$1 AND commit_cid=$2',
      [did,commitCid]
    );
    if(r.rowCount!==1) return null;
    const row=r.rows[0];
    return Object.freeze({
      status:row.status,
      attempts:Number(row.attempt_count),
      leaseEpoch:String(row.lease_epoch),
      blocked:row.blocked_at!==null,
      nextAttemptAt:row.next_attempt_at?.toISOString()??null
    });
  }
  async function deliverOnce({testCrashAfterPublish=false}={}) {
    enabled(fixtureOnly);
    const claim=await claimOne();
    if(!claim)return Object.freeze({claimed:false});
    validateLease(claim);
    const idempotencyKey='at.commit.v1:'+claim.did+':'+claim.commit_cid;
    let event;
    try {
      event=await verifyEvent(Object.freeze({
        did:claim.did,commitCid:claim.commit_cid,
        rev:claim.rev,kind:claim.kind
      }));
      if(event?.verified!==true || event.did!==claim.did ||
         event.commitCid!==claim.commit_cid || event.rev!==claim.rev ||
         !(event.eventBytes instanceof Uint8Array) ||
         event.eventBytes.length<1 || event.eventBytes.length>MAX_EVENT_BYTES) {
        fail('NATIVE_EVENT_INTEGRITY_INVALID');
      }
    }catch(error){
      return Object.freeze(await failDelivery(claim,
        errorCode(error),true));
    }
    try {
      const ack=await publish(Object.freeze({
        did:claim.did,commitCid:claim.commit_cid,rev:claim.rev,
        kind:claim.kind,idempotencyKey,
        eventBytes:Buffer.from(event.eventBytes)
      }));
      if(ack?.acked!==true || ack.idempotencyKey!==idempotencyKey) {
        fail('NATIVE_EVENT_ACK_INVALID');
      }
      if(testCrashAfterPublish) {
        // The publisher DID durably ACK, but our process lost the ability to
        // update PG. The original lease must expire before another attempt.
        fail('NATIVE_OUTBOX_TEST_CRASH');
      }
      await acknowledge(claim);
      return Object.freeze({claimed:true,delivered:true,idempotencyKey});
    }catch(error){
      if(error?.code==='NATIVE_OUTBOX_TEST_CRASH' ||
         error?.code==='NATIVE_OUTBOX_LEASE_STALE') throw error;
      return Object.freeze(await failDelivery(claim,errorCode(error),false));
    }
  }
  return Object.freeze({deliverOnce,inspect});
}
