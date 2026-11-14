/**
 * NONACTIVATED durable consumer-effect deduplication proof.
 *
 * A KafkaJS producer with acks=-1 + a PostgreSQL outbox still has an
 * unavoidable ACK-to-PG-update uncertainty window. A retry can append the
 * same verified frame at another Kafka offset. Accept duplicates only when
 * the exact DID, signed commit, seq, revision, topic, partition and SHA-256
 * payload agree with the first committed receipt. Never execute an effect
 * twice merely because Kafka redelivered an offset.
 */
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';
import {checkNativeFrame} from './native-redpanda-publisher.mjs';

const TABLE='paper_atproto_repo_proof.native_broker_receipts';
const OUTBOX='paper_atproto_repo_proof.native_event_outbox';
const TOPIC=/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,200}$/u;
function fail(code){
  const e=new Error('Durable broker consumer receipt invalid');
  e.code=code;
  throw e;
}
function gated(fixtureOnly){
  if(fixtureOnly!==true||process.env.NODE_ENV==='production' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
     process.env.ATPROTO_REDPANDA_TEST_DISPOSABLE!=='confirmed'){
    fail('NATIVE_BROKER_RECEIPT_NOT_RELEASED');
  }
}
export function createNativeBrokerReceiptStore({
  pool,topic,fixtureOnly=false
}={}) {
  if(fixtureOnly!==true||process.env.NODE_ENV==='production'||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
     process.env.ATPROTO_REDPANDA_TEST_DISPOSABLE!=='confirmed'){
    return Object.freeze({observe:async()=>fail('NATIVE_BROKER_RECEIPT_NOT_RELEASED')});
  }
  if(typeof pool?.query!=='function'||!TOPIC.test(topic||'')){
    fail('NATIVE_BROKER_RECEIPT_CONFIGURATION_INVALID');
  }
  async function observe({
    receivedTopic,partition,offset,key,value,headers
  }){
    gated(fixtureOnly);
    if(receivedTopic!==topic||
       !Number.isSafeInteger(partition)||partition<0||
       typeof offset!=='string'||offset.length>19 ||
       !/^(0|[1-9][0-9]*)$/u.test(offset) ||
       BigInt(offset)>9223372036854775807n ||
       !(key instanceof Uint8Array)||key.length<1||key.length>128 ||
       !headers||typeof headers!=='object' ||
       !(value instanceof Uint8Array)){
      fail('NATIVE_BROKER_RECEIPT_INPUT_INVALID');
    }
    function readHeader(name,maxBytes=256) {
      const raw=headers[name];
      if(!(raw instanceof Uint8Array)&&typeof raw!=='string'){
        fail('NATIVE_BROKER_RECEIPT_INPUT_INVALID');
      }
      const bytes=Buffer.from(raw);
      if(bytes.length<1||bytes.length>maxBytes){
        fail('NATIVE_BROKER_RECEIPT_INPUT_INVALID');
      }
      return bytes.toString('utf8');
    }
    const did=Buffer.from(key).toString('utf8');
    const eventId=readHeader('event-id',220);
    const commitCid=readHeader('commit-cid',90);
    const rev=readHeader('revision',20);
    const declaredSeq=readHeader('atproto-seq',19);
    const parsed=checkNativeFrame({
      did,commitCid,rev,idempotencyKey:eventId,eventBytes:value
    });
    if(declaredSeq!==String(parsed.seq)){
      fail('NATIVE_BROKER_RECEIPT_HEADER_MISMATCH');
    }
    const digest=crypto.createHash('sha256').update(parsed.frameBytes).digest();
    // SELECT guards this exact outbox identity and signed revision; the
    // INSERT and ON CONFLICT are in a single PG statement. No read-modify-
    // write race, no process-local unbounded event set, no bulk scans.
    const inserted=await pool.query(
      'INSERT INTO '+TABLE+
      '(did,commit_cid,event_seq,rev,payload_sha256,topic,partition_id,first_offset) '+
      'SELECT e.did,e.commit_cid,e.id,e.rev,$5,$6,$7::int,$8::bigint '+
      'FROM '+OUTBOX+' e WHERE e.did=$1 AND e.commit_cid=$2 '+
      'AND e.id=$3::bigint AND e.rev=$4 AND e.blocked_at IS NULL '+
      'ON CONFLICT(did,commit_cid) DO NOTHING RETURNING event_seq',
      [did,commitCid,String(parsed.seq),rev,digest,topic,partition,offset]
    );
    const current=await pool.query(
      'SELECT r.did,r.commit_cid,r.event_seq,r.rev,r.payload_sha256,'+
      'r.topic,r.partition_id,r.first_offset,e.blocked_at '+
      'FROM '+TABLE+' r JOIN '+OUTBOX+
      ' e ON e.did=r.did AND e.commit_cid=r.commit_cid '+
      'WHERE r.did=$1 AND r.commit_cid=$2',[did,commitCid]
    );
    if(current.rowCount!==1 ||
       current.rows[0].blocked_at!==null ||
       String(current.rows[0].event_seq)!==String(parsed.seq)||
       current.rows[0].rev!==rev ||
       current.rows[0].topic!==topic ||
       Number(current.rows[0].partition_id)!==partition ||
       !Buffer.from(current.rows[0].payload_sha256).equals(digest)){
      fail('NATIVE_BROKER_REPLAY_CONFLICT');
    }
    return Object.freeze({
      firstSeen:inserted.rowCount===1,
      idempotencyKey:eventId,seq:parsed.seq,
      firstOffset:String(current.rows[0].first_offset),partition
    });
  }
  return Object.freeze({observe});
}
