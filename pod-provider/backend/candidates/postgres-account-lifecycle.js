'use strict';
// Experimental and never autoloaded; does not own authentication or WebID.
// Only a disposable fixture can construct an enabled candidate.
const crypto=require('node:crypto');
const SCHEMA='paper_account_candidate';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const USERNAME=/^[a-z0-9][a-z0-9_-]{1,63}$/;
const ALLOWED={reserved:['provisioning'],provisioning:['ready','suspended','deleting'],ready:['suspended','deleting'],suspended:['ready','deleting'],deleting:['deleted'],deleted:[]};
function fail(code){const e=new Error(code);e.code=code;throw e;}
function uuid(v){if(typeof v!=='string'||!UUID.test(v))fail('ACCOUNT_INVALID_UUID');}
function scope(v){if(typeof v!=='string'||v.trim()!==v||v.length<8||v.length>255)fail('ACCOUNT_INVALID_SCOPE');}
async function tx(pool,fn){
  const c=await pool.connect();let open=false,broken=false;
  try{
    await c.query('BEGIN');open=true;
    await c.query("SET LOCAL lock_timeout='2000ms'");
    await c.query("SET LOCAL statement_timeout='8000ms'");
    await c.query("SET LOCAL idle_in_transaction_session_timeout='4000ms'");
    const result=await fn(c);await c.query('COMMIT');open=false;return result;
  }catch(e){
    if(open){try{await c.query('ROLLBACK');}catch(_){broken=true;}}
    throw e;
  }finally{c.release(broken);}
}
function createCandidate({pool,fixtureOnly=false}={}){
  if(!pool||typeof pool.connect!=='function')fail('ACCOUNT_POOL_REQUIRED');
  const gate=()=>{if(fixtureOnly!==true)fail('ACCOUNT_CANDIDATE_NOT_RELEASED');};
  async function reserve({providerId,accountId,username}){
    gate();scope(providerId);uuid(accountId);
    if(typeof username!=='string'||!USERNAME.test(username))fail('ACCOUNT_INVALID_USERNAME');
    return tx(pool,async c=>{
      const old=await c.query('SELECT provider_id,username_key,state,generation FROM '+SCHEMA+'.accounts WHERE account_id=$1 FOR UPDATE',[accountId]);
      if(old.rowCount){
        if(old.rows[0].provider_id!==providerId||old.rows[0].username_key!==username)fail('ACCOUNT_ID_COLLISION');
        return {accountId,generation:Number(old.rows[0].generation),state:old.rows[0].state,replay:true};
      }
      const created=await c.query('INSERT INTO '+SCHEMA+'.accounts (account_id,provider_id,username_key) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING generation',[accountId,providerId,username]);
      if(created.rowCount!==1)fail('ACCOUNT_USERNAME_CONFLICT');
      return {accountId,generation:1,state:'reserved',replay:false};
    });
  }
  async function change({providerId,accountId,operationId,expectedGeneration,kind,webId,activityPubActorId,atprotoDid,atprotoHandle,atprotoPdsUrl,repoInitialized,nextState}){
    gate();scope(providerId);uuid(accountId);uuid(operationId);
    if(!Number.isSafeInteger(expectedGeneration)||expectedGeneration<1)fail('ACCOUNT_INVALID_GENERATION');
    if(!['bind_unified_identity','transition_state'].includes(kind))fail('ACCOUNT_INVALID_OPERATION');
    if(kind==='bind_unified_identity'){
      if(typeof webId!=='string'||webId.length>2048||!/^https:\/\/[^\s]+$/.test(webId))fail('ACCOUNT_INVALID_WEBID');
      const parsed=new URL(webId);
      if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.hash)fail('ACCOUNT_INVALID_WEBID');
      if(activityPubActorId!==webId)fail('ACCOUNT_UNIFIED_ACTOR_MISMATCH');
      if(typeof atprotoDid!=='string'||!/^did:plc:[a-z2-7]{24}$/.test(atprotoDid))fail('ACCOUNT_UNIFIED_DID_REQUIRED');
      if(typeof atprotoHandle!=='string'||atprotoHandle.length<3||atprotoHandle.length>253||!atprotoHandle.includes('.'))fail('ACCOUNT_UNIFIED_HANDLE_REQUIRED');
      if(typeof atprotoPdsUrl!=='string'||!/^https:\/\/[^\s]+$/.test(atprotoPdsUrl))fail('ACCOUNT_UNIFIED_PDS_REQUIRED');
      const pds=new URL(atprotoPdsUrl);
      if(pds.protocol!=='https:'||pds.username||pds.password||pds.hash)fail('ACCOUNT_UNIFIED_PDS_REQUIRED');
      if(repoInitialized!==true||nextState!==undefined)fail('ACCOUNT_UNIFIED_REPOSITORY_INCOMPLETE');
    }else if(typeof nextState!=='string'||!Object.hasOwn(ALLOWED,nextState)||
      [webId,activityPubActorId,atprotoDid,atprotoHandle,atprotoPdsUrl,repoInitialized].some(v=>v!==undefined))fail('ACCOUNT_INVALID_OPERATION');
    const digest=crypto.createHash('sha256').update(JSON.stringify([kind,providerId,accountId,webId??null,activityPubActorId??null,atprotoDid??null,atprotoHandle??null,atprotoPdsUrl??null,repoInitialized??null,nextState??null])).digest('hex');
    return tx(pool,async c=>{
      const a=await c.query('SELECT state,webid,atproto_did,generation FROM '+SCHEMA+'.accounts WHERE provider_id=$1 AND account_id=$2 FOR UPDATE',[providerId,accountId]);
      if(a.rowCount!==1)fail('ACCOUNT_NOT_FOUND');
      const replay=await c.query('SELECT payload_digest,next_generation FROM '+SCHEMA+'.transitions WHERE account_id=$1 AND operation_id=$2',[accountId,operationId]);
      if(replay.rowCount){
        if(replay.rows[0].payload_digest!==digest)fail('ACCOUNT_OPERATION_CONFLICT');
        return {accountId,generation:Number(replay.rows[0].next_generation),replay:true};
      }
      const current=a.rows[0],target=kind==='bind_unified_identity'?'provisioning':nextState;
      if(Number(current.generation)!==expectedGeneration)fail('ACCOUNT_STALE_GENERATION');
      if(!ALLOWED[current.state].includes(target))fail('ACCOUNT_INVALID_TRANSITION');
      if(kind==='bind_unified_identity'&&(current.webid!==null||current.atproto_did!==null))fail('ACCOUNT_ALREADY_BOUND');
      if(kind==='transition_state'&&(current.webid===null||current.atproto_did===null))fail('ACCOUNT_UNIFIED_IDENTITY_REQUIRED');
      const updated=await c.query('UPDATE '+SCHEMA+'.accounts SET webid=COALESCE($3,webid),activitypub_actor_uri=COALESCE($4,activitypub_actor_uri),atproto_did=COALESCE($5,atproto_did),atproto_handle=COALESCE($6,atproto_handle),atproto_pds_url=COALESCE($7,atproto_pds_url),atproto_repo_initialized=CASE WHEN $5::text IS NOT NULL THEN true ELSE atproto_repo_initialized END,state=$8,generation=generation+1,changed_at=clock_timestamp() WHERE provider_id=$1 AND account_id=$2 AND generation=$9 RETURNING generation',[providerId,accountId,kind==='bind_unified_identity'?webId:null,kind==='bind_unified_identity'?activityPubActorId:null,kind==='bind_unified_identity'?atprotoDid:null,kind==='bind_unified_identity'?atprotoHandle:null,kind==='bind_unified_identity'?atprotoPdsUrl:null,target,expectedGeneration]);
      if(updated.rowCount!==1)fail('ACCOUNT_STALE_GENERATION');
      const generation=Number(updated.rows[0].generation);
      if(!Number.isSafeInteger(generation))fail('ACCOUNT_GENERATION_OVERFLOW');
      await c.query('INSERT INTO '+SCHEMA+'.transitions (account_id,operation_id,previous_generation,next_generation,kind,payload_digest) VALUES ($1,$2,$3,$4,$5,$6)',[accountId,operationId,expectedGeneration,generation,kind,digest]);
      return {accountId,generation,replay:false};
    });
  }
  async function read({providerId,accountId}){
    gate();scope(providerId);uuid(accountId);
    const r=await pool.query('SELECT account_id,provider_id,username_key,webid,activitypub_actor_uri,atproto_did,atproto_handle,atproto_pds_url,atproto_repo_initialized,state,generation FROM '+SCHEMA+'.accounts WHERE provider_id=$1 AND account_id=$2',[providerId,accountId]);
    return r.rowCount?{...r.rows[0],generation:Number(r.rows[0].generation)}:null;
  }
  return Object.freeze({reserve,change,read});
}
module.exports={createCandidate};
