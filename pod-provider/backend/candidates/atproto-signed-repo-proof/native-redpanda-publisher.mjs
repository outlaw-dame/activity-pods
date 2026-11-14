/**
 * NONACTIVATED bridge from a verified native #commit frame to Redpanda's
 * Kafka API. Publisher is provider-injected, topic fixed at construction,
 * and PG monotone lease/ACK remains the sole outbox delivery authority.
 *
 * A successful Kafka response does not make an outbox event exactly-once:
 * after an uncertain PG ACK, retry can append the SAME event under the
 * same stable ID. Consumers MUST deduplicate by event ID.
 */
import { Buffer } from 'node:buffer';
import * as cbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';

export const MAX_NATIVE_EVENT_BYTES=2*1024*1024;
export const MIN_BROKER_TOPIC_MESSAGE_BYTES=2_400_000;
const DID=/^did:plc:[a-z2-7]{24}$/u;
const CID_RE=/^bafyre[a-z2-7]{53}$/u;
const TID=/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const TOPIC=/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,200}$/u;
const HEADER=Buffer.from(cbor.encode({op:1,t:'#commit'}));

function deny(code) {
  const error=new Error('Native event broker publication unavailable');
  error.code=code;
  throw error;
}
function enabled(fixtureOnly) {
  if(fixtureOnly!==true||process.env.NODE_ENV==='production' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
     process.env.ATPROTO_REDPANDA_TEST_DISPOSABLE!=='confirmed'){
    deny('NATIVE_REDPANDA_NOT_RELEASED');
  }
}
/** Accept only one independently materialized, internally consistent event. */
export function checkNativeFrame({did,commitCid,rev,idempotencyKey,eventBytes}) {
  if(!DID.test(did||'')||!CID_RE.test(commitCid||'') ||
     !TID.test(rev||'') ||
     idempotencyKey!=='at.commit.v1:'+did+':'+commitCid ||
     !(eventBytes instanceof Uint8Array) ||
     eventBytes.length<HEADER.length+10 ||
     eventBytes.length>MAX_NATIVE_EVENT_BYTES ||
     !Buffer.from(eventBytes).subarray(0,HEADER.length).equals(HEADER)) {
    deny('NATIVE_REDPANDA_FRAME_INVALID');
  }
  let body;
  try{body=cbor.decode(Buffer.from(eventBytes).subarray(HEADER.length));}
  catch{deny('NATIVE_REDPANDA_FRAME_INVALID');}
  if(!body||body.repo!==did||body.rev!==rev ||
     !CID.asCID(body.commit)||body.commit.toString()!==commitCid ||
     !Number.isSafeInteger(body.seq)||body.seq<1||
     !(body.blocks instanceof Uint8Array)||body.blocks.length<30 ||
     body.blocks.length>2_000_000 ||
     !Array.isArray(body.ops)||body.ops.length>200 ||
     !Array.isArray(body.blobs) ||
     body.rebase!==false||body.tooBig!==false ||
     typeof body.time!=='string'||!Number.isFinite(Date.parse(body.time))) {
    deny('NATIVE_REDPANDA_FRAME_INVALID');
  }
  return Object.freeze({seq:body.seq,frameBytes:Buffer.from(eventBytes)});
}
/**
 * The producer is already connected through a reviewed Kafka client.
 * On each send require all in-sync-replica ACKs; never accept an empty
 * offset, error code or aborted PG lease.
 */
export function createNativeRedpandaPublisher({
  producer,topic,fixtureOnly=false,
  timeoutMs=6000,compression=0
}={}) {
  const unavailable=async()=>deny('NATIVE_REDPANDA_NOT_RELEASED');
  if(fixtureOnly!==true||process.env.NODE_ENV==='production'||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
     process.env.ATPROTO_REDPANDA_TEST_DISPOSABLE!=='confirmed'){
    return unavailable;
  }
  if(typeof producer?.send!=='function'||!TOPIC.test(topic||'') ||
     !Number.isSafeInteger(timeoutMs)||timeoutMs<1000||timeoutMs>20000 ||
     !Number.isSafeInteger(compression)||compression<0||compression>3){
    deny('NATIVE_REDPANDA_CONFIGURATION_INVALID');
  }
  return async function publish({
    did,commitCid,rev,idempotencyKey,eventBytes,signal
  }) {
    enabled(fixtureOnly);
    if(signal?.aborted)deny('NATIVE_BROKER_LEASE_ABORTED');
    const parsed=checkNativeFrame({did,commitCid,rev,idempotencyKey,eventBytes});
    const metadata=await producer.send({
      topic,acks:-1,timeout:timeoutMs,compression,
      messages:[{
        key:did,
        value:parsed.frameBytes,
        headers:{
          'event-id':idempotencyKey,
          'atproto-seq':String(parsed.seq),
          'commit-cid':commitCid,
          'revision':rev
        }
      }]
    });
    // An ACK after the PG lease times out cannot advance PostgreSQL;
    // recovery may append a duplicate under the same stable event ID.
    if(signal?.aborted)deny('NATIVE_BROKER_LEASE_ABORTED');
    if(!Array.isArray(metadata)||metadata.length!==1||
       metadata[0]?.topicName!==topic ||
       !Number.isSafeInteger(metadata[0]?.partition) ||
       metadata[0].partition<0 ||
       (metadata[0].errorCode!==undefined &&
        metadata[0].errorCode!==0) ||
       !/^(0|[1-9][0-9]*)$/u.test(String(metadata[0].baseOffset||''))){
      deny('NATIVE_BROKER_ACK_INVALID');
    }
    return Object.freeze({
      acked:true,idempotencyKey,topic,
      partition:metadata[0].partition,
      offset:String(metadata[0].baseOffset)
    });
  };
}
