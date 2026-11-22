/**
 * NONACTIVATED signed-reference-MST witness positive COMMIT reconciler.
 *
 * The trusted independent reconciler, NOT the signing worker or browser,
 * can settle a durable external witness intent after read-only proof of
 * its exact primary PostgreSQL signed commit, immutable mutation UUID,
 * historical CAR/CID/MST record and native event outbox. Aborts are NEVER
 * inferred from a missing DB row or network error; they require separate
 * WAL/failover proof beyond this candidate.
 */
import crypto from 'node:crypto';
import {Buffer} from 'node:buffer';
import {CID} from 'multiformats/cid';
import {cid,decodeCanonical,checkRecord,checkRecordPath}
 from './signed-single-record.mjs';
import {checkedCommit} from './reference-mst-writer.mjs';

const CID_RE=/^bafyre[a-z2-7]{53}$/u;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const GRANT_HASH_LENGTH=32;
const TABLE='paper_atproto_repo_proof';
const MAX_READS=192;
const MAX_BYTES=2*1024*1024;
function fail(code){
 const e=new Error('Independent signed-write recovery admission denied');
 e.code=code;
 throw e;
}
function validCid(s){return typeof s==='string'&&CID_RE.test(s);}
function validHttps(s){
 if(typeof s!=='string'||s.length<8||s.length>2048)return false;
 try{
  const u=new URL(s);
  return u.protocol==='https:'&&!u.username&&!u.password&&
   !u.hash&&!u.search&&u.href===s;
 }catch{return false;}
}
function enabled(){
 return process.env.NODE_ENV==='test'&&
  process.env.PAPER_OAUTH_WITNESS_DISPOSABLE==='confirmed'&&
  process.env.PAPER_OAUTH_WITNESS_SIGNED_REPO_DISPOSABLE==='confirmed'&&
  process.env.PAPER_OAUTH_PG_EPOCH_DISPOSABLE==='confirmed'&&
  process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE==='confirmed'&&
  process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE==='confirmed';
}
/**
 * readWitnessIntent/settleCommitted are authenticated connections to the
 * separate witness PG18 database; neither call is request-derived.
 * resolveSigningKey MUST independently attest the historic DID PLC
 * signing key for this commit, never take a PEM from the public XRPC body.
 */
export function createIndependentWitnessCommitReconciler({
 primaryPool,reference,readWitnessIntent,settleCommitted,
 resolveSigningKey,fixtureOnly=false
}={}){
 if(!enabled()||fixtureOnly!==true)return Object.freeze({
  reconcileCommitted:async()=>fail('WITNESS_RECONCILER_NOT_RELEASED')
 });
 if(typeof primaryPool?.connect!=='function'||
    typeof reference?.MST?.load!=='function'||
    typeof reference?.ReadableBlockstore!=='function'||
    typeof readWitnessIntent!=='function'||
    typeof settleCommitted!=='function'||
    typeof resolveSigningKey!=='function')
  fail('WITNESS_RECONCILER_CONFIGURATION_INVALID');

 async function reconcileCommitted(operationId){
  if(!enabled())fail('WITNESS_RECONCILER_NOT_RELEASED');
  if(typeof operationId!=='string'||!UUID.test(operationId))
   fail('WITNESS_RECONCILER_OPERATION_INVALID');
  let witness;
  try{witness=await readWitnessIntent(operationId);}
  catch{fail('WITNESS_RECONCILER_WITNESS_UNAVAILABLE');}
  if(!witness||witness.state!=='pending')return false;
  const owner=witness.owner_webid;
  const proposed=witness.proposed_head_cid;
  const expected=witness.expected_head_cid;
  if(!validHttps(owner)||!validHttps(witness.client_id)||
     !validCid(proposed)||!validCid(expected)||proposed===expected||
     !Buffer.isBuffer(witness.grant_sha256)||
     witness.grant_sha256.length!==GRANT_HASH_LENGTH||
     !/^[1-9][0-9]{0,18}$/u.test(String(witness.revision||'')))
   fail('WITNESS_RECONCILER_INTENT_INVALID');

  let client,open=false,discard=false,proof;
  try {
   client=await primaryPool.connect();
   await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
   open=true;
   await client.query("SET LOCAL statement_timeout='6500ms'");
   await client.query("SET LOCAL idle_in_transaction_session_timeout='3000ms'");
   // Reconciliation needs a separate read-only PRIMARY PostgreSQL LOGIN:
   // no superuser, no escalation memberships and no mutation rights on
   // repository tables. A restored/standby replica cannot attest the
   // primary COMMIT outcome.
   const primary=await client.query(
    'SELECT pg_is_in_recovery() AS standby,r.rolsuper,r.rolcreatedb,'+
    'r.rolcreaterole,r.rolreplication,r.rolbypassrls,'+
    '(SELECT count(*)::int FROM pg_catalog.pg_auth_members m '+
    'WHERE m.member=r.oid) AS memberships,'+
    'pg_catalog.has_table_privilege(current_user,'+
    "'paper_atproto_repo_proof.repos',"+
    "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS write_repos,"+
    'pg_catalog.has_table_privilege(current_user,'+
    "'paper_atproto_repo_proof.record_mutations',"+
    "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS write_mutations,"+
    'pg_catalog.has_table_privilege(current_user,'+
    "'paper_atproto_repo_proof.native_event_outbox',"+
    "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS write_outbox,"+
    'pg_catalog.has_table_privilege(current_user,'+
    "'paper_atproto_repo_proof.blocks',"+
    "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS write_blocks "+
    'FROM pg_catalog.pg_roles r WHERE r.rolname=current_user'
   );
   const role=primary.rows?.[0];
   if(primary.rowCount!==1||role.standby!==false||
      role.rolsuper!==false||role.rolcreatedb!==false||
      role.rolcreaterole!==false||role.rolreplication!==false||
      role.rolbypassrls!==false||role.memberships!==0||
      role.write_repos!==false||role.write_mutations!==false||
      role.write_outbox!==false||role.write_blocks!==false)
    fail('WITNESS_RECONCILER_PRIMARY_ROLE_UNSAFE');
   const q=await client.query(
    'SELECT r.account_id,r.did,r.generation AS repo_generation,'+
    'm.commit_cid,m.previous_commit_cid,m.previous_root_cid,'+
    'm.previous_rev,m.rev,m.action,m.path,m.previous_record_cid,'+
    'm.record_cid,'+
    'm.generation,m.witness_operation_id::text AS operation_id,'+
    'o.rev AS outbox_rev,o.kind AS outbox_kind,'+
    'o.status AS outbox_status,o.blocked_at,'+
    'EXISTS(SELECT 1 FROM '+TABLE+'.native_event_outbox b '+
    "WHERE b.did=r.did AND b.status='pending' "+
    'AND b.blocked_at IS NOT NULL) AS blocked_history '+
    'FROM '+TABLE+'.repos r '+
    'JOIN '+TABLE+'.record_mutations m ON m.did=r.did '+
    'JOIN '+TABLE+'.native_event_outbox o ON '+
    'o.did=m.did AND o.commit_cid=m.commit_cid '+
    'WHERE r.account_id=$1 AND m.witness_operation_id=$2::uuid '+
    'AND m.commit_cid=$3',
    [owner,operationId,proposed]);
   if(q.rowCount!==1){
    await client.query('COMMIT');open=false;
    return false; // NEVER infer abort from missing/rolled-back rows
   }
   const row=q.rows[0];
   if(row.operation_id!==operationId ||
      row.commit_cid!==proposed ||
      row.previous_commit_cid!==expected ||
      row.account_id!==owner||
      !/^did:plc:[a-z2-7]{24}$/u.test(row.did||'')||
      !Number.isSafeInteger(Number(row.generation))||
      !Number.isSafeInteger(Number(row.repo_generation))||
      Number(row.generation)<=1||
      Number(row.generation)>Number(row.repo_generation)||
      row.rev!==row.outbox_rev ||
      !(row.rev>row.previous_rev)||
      row.outbox_kind!=='at.commit.v1'||
      !['pending','delivered'].includes(row.outbox_status)||
      row.blocked_at!==null||row.blocked_history!==false||
      !validCid(row.previous_root_cid)||
      !validCid(row.previous_commit_cid)||
      !['create','update','delete'].includes(row.action)){
    fail('WITNESS_RECONCILER_PRIMARY_MISMATCH');
   }
   checkRecordPath(row.path);
   let reads=0,bytesRead=0;
   class SnapshotReader extends reference.ReadableBlockstore{
    async getBytes(link){
     const key=link?.toString?.();
     if(!validCid(key))fail('WITNESS_RECONCILER_CID_INVALID');
     if(++reads>MAX_READS)fail('WITNESS_RECONCILER_READ_LIMIT');
     const r=await client.query(
      'SELECT block FROM '+TABLE+'.blocks WHERE did=$1 AND cid=$2',
      [row.did,key]);
     if(r.rowCount!==1)return null;
     const bytes=Buffer.from(r.rows[0].block);
     bytesRead+=bytes.length;
     if(bytes.length<1||bytes.length>131072||
        bytesRead>MAX_BYTES||
        !(await cid(bytes)).equals(CID.parse(key)))
       fail('WITNESS_RECONCILER_BLOCK_INVALID');
     return bytes;
    }
    async has(link){return (await this.getBytes(link))!==null;}
    async getBlocks(links){
     if(!Array.isArray(links)||links.length>MAX_READS)
       fail('WITNESS_RECONCILER_READ_LIMIT');
     const blocks=new reference.BlockMap(),missing=[];
     for(const link of links){
      const bytes=await this.getBytes(link);
      if(bytes===null)missing.push(link);else blocks.set(link,bytes);
     }
     return {blocks,missing};
    }
   }
   const blocks=new SnapshotReader();
   const commitBytes=await blocks.getBytes(CID.parse(proposed));
   const previousBytes=await blocks.getBytes(CID.parse(expected));
   if(!commitBytes||!previousBytes)
    fail('WITNESS_RECONCILER_COMMIT_MISSING');
   const decoded=decodeCanonical(commitBytes);
   const root=CID.asCID(decoded?.data)?.toString();
   if(!validCid(root))fail('WITNESS_RECONCILER_ROOT_INVALID');
   // Independently verify the historic BEFORE and AFTER MST states:
   // a forged mutation audit saying 'create', 'update' or 'delete' may
   // not hide a no-op or modify a different path, even with a valid
   // signed commit and a matching witness operation ID.
   const before=reference.MST.load(blocks,CID.parse(row.previous_root_cid));
   const beforeLink=await before.get(row.path);
   const beforeCid=beforeLink?.toString()??null;
   if((row.action==='create' &&
      (beforeCid!==null||row.previous_record_cid!==null))||
      (row.action!=='create'&&
       (!validCid(beforeCid)||beforeCid!==row.previous_record_cid)))
     fail('WITNESS_RECONCILER_PREVIOUS_RECORD_MISMATCH');
   const mst=reference.MST.load(blocks,CID.parse(root));
   const recordLink=await mst.get(row.path);
   const recordCid=recordLink?.toString()??null;
   if((row.action==='delete'&&
      (recordCid!==null||row.record_cid!==null))||
      (row.action!=='delete'&&
       (!validCid(recordCid)||recordCid!==row.record_cid)))
     fail('WITNESS_RECONCILER_RECORD_MISMATCH');
   if(recordCid!==null){
    const recordBytes=await blocks.getBytes(CID.parse(recordCid));
    if(!recordBytes)fail('WITNESS_RECONCILER_RECORD_MISSING');
    checkRecord(decodeCanonical(recordBytes),row.path);
   }
   proof=Object.freeze({
    owner,clientId:witness.client_id,
    operationId,revision:String(witness.revision),
    did:row.did,commitCid:proposed,rev:row.rev,
    rootCid:root,commitBytes:Buffer.from(commitBytes)
   });
   await client.query('COMMIT');open=false;
  }catch(e){
   if(open)try{await client.query('ROLLBACK')}catch{discard=true}
   if(e?.code?.startsWith('WITNESS_RECONCILER_'))throw e;
   fail('WITNESS_RECONCILER_PRIMARY_UNAVAILABLE');
  }finally{if(client)client.release(discard)}
  let pem,key;
  try{
   pem=await resolveSigningKey(Object.freeze({
    owner:proof.owner,did:proof.did,commitCid:proof.commitCid,
    rev:proof.rev
   }));
   key=crypto.createPublicKey(pem);
   if(key.asymmetricKeyType!=='ec'||
      key.asymmetricKeyDetails?.namedCurve!=='secp256k1')
    fail('WITNESS_RECONCILER_SIGNER_INVALID');
   checkedCommit(proof.commitBytes,{
    did:proof.did,headCid:proof.commitCid,rev:proof.rev,
    rootCid:proof.rootCid,publicKey:key
   });
  }catch{fail('WITNESS_RECONCILER_SIGNATURE_INVALID')}
  // Only the reconciler owns this callback/SQL LOGIN. Crucially the
  // signing worker may NEVER call it to guess its own COMMIT outcome.
  try{
   return (await settleCommitted(Object.freeze({
    operationId:proof.operationId,
    owner:proof.owner,clientId:proof.clientId,
    revision:proof.revision,commitCid:proof.commitCid
   })))===true;
  }catch{fail('WITNESS_RECONCILER_SETTLEMENT_UNAVAILABLE')}
 }
 return Object.freeze({reconcileCommitted});
}
