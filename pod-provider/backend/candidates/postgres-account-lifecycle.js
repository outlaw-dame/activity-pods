'use strict';
// Experimental and never autoloaded; does not own authentication or WebID.
// Only a disposable fixture can construct an enabled candidate.
const crypto=require('node:crypto');
const { verifyNewSignupSolidAuthority } = require('./solid-new-signup-proof');
const SCHEMA='paper_account_candidate';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const USERNAME=/^[a-z0-9][a-z0-9_-]{1,63}$/;
const ALLOWED={reserved:['provisioning'],provisioning:['ready','suspended','deleting'],ready:['suspended','deleting'],suspended:['ready','deleting'],deleting:['deleted'],deleted:[]};
function fail(code){const e=new Error(code);e.code=code;throw e;}
function uuid(v){if(typeof v!=='string'||!UUID.test(v))fail('ACCOUNT_INVALID_UUID');}
function scope(v){if(typeof v!=='string'||v.trim()!==v||v.length<8||v.length>255)fail('ACCOUNT_INVALID_SCOPE');}
async function tx(pool,fn){
  const c=await pool.connect();let open=false,broken=false,commitAttempted=false;
  try{
    await c.query('BEGIN');open=true;
    await c.query("SET LOCAL lock_timeout='2000ms'");
    await c.query("SET LOCAL statement_timeout='8000ms'");
    await c.query("SET LOCAL idle_in_transaction_session_timeout='4000ms'");
    const result=await fn(c);commitAttempted=true;await c.query('COMMIT');open=false;return result;
  }catch(e){
    // Once COMMIT is sent a lost reply does not tell us whether it was
    // durable. Discard the connection and prohibit blind retry.
    if(commitAttempted){broken=true;fail('ACCOUNT_COMMIT_OUTCOME_UNKNOWN');}
    if(open){try{await c.query('ROLLBACK');}catch(_){broken=true;}}
    throw e;
  }finally{c.release(broken);}
}
function createCandidate({pool,fixtureOnly=false,verifyNewSignupEvidence=null}={}){
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
      const current=a.rows[0],target=kind==='bind_unified_identity'?'provisioning':nextState;
      if(target==='ready'){
        // A newly reserved account is NOT ready merely because its
        // PostgreSQL identity columns contain WebID, DID and a Boolean
        // repoInitialized. Only a future, reviewed provider-owned completion
        // CAS may transition a signup-journal account to ready after
        // verifying signed CAR, SAI revocation epoch and RDF projection.
        // The journal's UNIQUE(provider_id,account_id) gives an indexed,
        // bounded row lock, not a full account scan.
        const newSignup=await c.query(
          'SELECT operation_id FROM '+SCHEMA+'.signup_operations '+
          'WHERE provider_id=$1 AND account_id=$2 FOR UPDATE',
          [providerId,accountId]
        );
        if(newSignup.rowCount!==0)fail('ACCOUNT_SIGNUP_COMPLETION_SEAL_REQUIRED');
      }
      const replay=await c.query('SELECT payload_digest,next_generation FROM '+SCHEMA+'.transitions WHERE account_id=$1 AND operation_id=$2',[accountId,operationId]);
      if(replay.rowCount){
        if(replay.rows[0].payload_digest!==digest)fail('ACCOUNT_OPERATION_CONFLICT');
        return {accountId,generation:Number(replay.rows[0].next_generation),replay:true};
      }
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

  const signupTable=SCHEMA+'.signup_operations';
  const isHmac=v=>Buffer.isBuffer(v)&&v.length===32;
  const assertSignupScope=({providerId,appClientId,hmacKeyVersion,idempotencyHmac})=>{
    scope(providerId);
    if(typeof appClientId!=='string'||appClientId.length<1||appClientId.length>2048 ||
       !Number.isSafeInteger(hmacKeyVersion)||hmacKeyVersion<1||hmacKeyVersion>255||
       !isHmac(idempotencyHmac))fail('ACCOUNT_SIGNUP_INVALID_SCOPE');
  };
  const signupResult=(row,replay)=>({
    operationId:row.operation_id,accountId:row.account_id,
    state:row.state,generation:Number(row.generation),replay
  });
  /**
   * Reserve one NEW signup in the same PostgreSQL account authority.
   * HMAC digests are produced by a trusted provider using a versioned,
   * domain-separated secret: never accept raw public idempotency keys here.
   * A replay cannot authorize another PLC/PDS attempt, even before phase 1.
   */
  async function reserveSignup(input){
    gate();
    assertSignupScope(input);
    const {providerId,appClientId,hmacKeyVersion,idempotencyHmac,requestHmac,
      accountId,operationId,username}=input;
    uuid(accountId);uuid(operationId);
    if(!isHmac(requestHmac)||typeof username!=='string'||!USERNAME.test(username)){
      fail('ACCOUNT_SIGNUP_INVALID_REQUEST');
    }
    return tx(pool,async c=>{
      const prior=await c.query(
        'SELECT o.operation_id,o.account_id,o.request_hmac,o.state,o.generation,a.username_key '+
        'FROM '+signupTable+' o JOIN '+SCHEMA+'.accounts a ON a.account_id=o.account_id '+
        'WHERE o.provider_id=$1 AND o.app_client_id=$2 AND o.hmac_key_version=$3 '+
        'AND o.idempotency_hmac=$4 FOR UPDATE OF o',
        [providerId,appClientId,hmacKeyVersion,idempotencyHmac]
      );
      if(prior.rowCount){
        const row=prior.rows[0];
        if(row.username_key!==username||
           !Buffer.isBuffer(row.request_hmac)||
           !crypto.timingSafeEqual(row.request_hmac,requestHmac)){
          fail('ACCOUNT_SIGNUP_IDEMPOTENCY_CONFLICT');
        }
        return signupResult(row,true);
      }
      // One transaction reserves the canonical account and its operation.
      // No second account registry or orphaned operation is introduced.
      const account=await c.query(
        'INSERT INTO '+SCHEMA+'.accounts(account_id,provider_id,username_key) '+
        'VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING account_id',
        [accountId,providerId,username]
      );
      if(account.rowCount!==1)fail('ACCOUNT_USERNAME_CONFLICT');
      const op=await c.query(
        'INSERT INTO '+signupTable+
        '(operation_id,provider_id,account_id,app_client_id,hmac_key_version,'+
        'idempotency_hmac,request_hmac) VALUES($1,$2,$3,$4,$5,$6,$7) '+
        'ON CONFLICT DO NOTHING RETURNING operation_id,account_id,state,generation',
        [operationId,providerId,accountId,appClientId,hmacKeyVersion,
          idempotencyHmac,requestHmac]
      );
      // A conflicting idempotency tuple or operation UUID must roll back
      // the account insert as well.
      if(op.rowCount!==1)fail('ACCOUNT_SIGNUP_OPERATION_CONFLICT');
      return signupResult(op.rows[0],false);
    });
  }
  /**
   * Commit BEFORE invoking the first remote account/WebID/PLC/PDS RPC.
   * On timeout, crash or a lost COMMIT response, reconciliation is required;
   * no process may automatically run the remote call again on a replay.
   */
  async function markSignupMayHaveSideEffects(input){
    gate();assertSignupScope(input);
    uuid(input.operationId);uuid(input.accountId);
    return tx(pool,async c=>{
      const r=await c.query(
        'UPDATE '+signupTable+
        " SET state='reconciliation_required',may_have_side_effects=true,"+
        'generation=generation+1,changed_at=clock_timestamp() '+
        'WHERE operation_id=$1 AND provider_id=$2 AND account_id=$3 '+
        'AND app_client_id=$4 AND hmac_key_version=$5 AND idempotency_hmac=$6 '+
        "AND state='reserved' AND generation=1 "+
        'RETURNING operation_id,account_id,state,generation',
        [input.operationId,input.providerId,input.accountId,input.appClientId,
          input.hmacKeyVersion,input.idempotencyHmac]
      );
      if(r.rowCount===1)return signupResult(r.rows[0],false);
      // A repeated fence is observable but NEVER permission to execute
      // a second remote identity-creation RPC.
      const prior=await c.query(
        'SELECT operation_id,account_id,state,generation FROM '+signupTable+
        ' WHERE operation_id=$1 AND provider_id=$2 AND account_id=$3 '+
        'AND app_client_id=$4 AND hmac_key_version=$5 AND idempotency_hmac=$6 '+
        'FOR UPDATE',
        [input.operationId,input.providerId,input.accountId,input.appClientId,
          input.hmacKeyVersion,input.idempotencyHmac]
      );
      if(prior.rowCount===1 && prior.rows[0].state==='reconciliation_required'){
        return signupResult(prior.rows[0],true);
      }
      fail('ACCOUNT_SIGNUP_RECONCILIATION_REQUIRED');
    });
  }
  async function readSignup({providerId,appClientId,hmacKeyVersion,idempotencyHmac}){
    gate();
    assertSignupScope({providerId,appClientId,hmacKeyVersion,idempotencyHmac});
    const r=await pool.query(
      'SELECT operation_id,account_id,state,generation FROM '+signupTable+
      ' WHERE provider_id=$1 AND app_client_id=$2 AND hmac_key_version=$3 '+
      'AND idempotency_hmac=$4',
      [providerId,appClientId,hmacKeyVersion,idempotencyHmac]
    );
    return r.rowCount?signupResult(r.rows[0],true):null;
  }
  // Read-only readiness probe. This does NOT mark a signup complete, renew
  // its lease or grant the caller permission to repeat remote identity RPCs.
  // The trusted caller must seal a fresh verified proof in a separate,
  // reviewed generation-fenced completion transaction.
  async function verifySignupSolidReadiness({providerId,appClientId,
    hmacKeyVersion,idempotencyHmac,call}){
    gate();
    if(typeof call!=='function')fail('ACCOUNT_SIGNUP_TRUSTED_SOLID_CALL_REQUIRED');
    const operation=await readSignup({providerId,appClientId,
      hmacKeyVersion,idempotencyHmac});
    if(!operation||operation.state!=='reconciliation_required'){
      fail('ACCOUNT_SIGNUP_RECONCILIATION_REQUIRED');
    }
    const before=await read({providerId,accountId:operation.accountId});
    if(!before||before.webid!==before.activitypub_actor_uri||
       !/^did:plc:[a-z2-7]{24}$/.test(before.atproto_did||'')||
       before.atproto_repo_initialized!==true||
       !['provisioning','ready'].includes(before.state)){
      fail('ACCOUNT_SIGNUP_IDENTITY_NOT_READY');
    }
    const proof=await verifyNewSignupSolidAuthority({call,webId:before.webid,
      did:before.atproto_did,operationId:operation.operationId});
    // A concurrent lifecycle transition must never elevate a stale read-only
    // proof. No SQL lock or connection is held across Solid/RDF calls.
    const after=await read({providerId,accountId:operation.accountId});
    if(!after||after.generation!==before.generation||
       after.state!==before.state||after.webid!==before.webid||
       after.atproto_did!==before.atproto_did){
      fail('ACCOUNT_SIGNUP_CONCURRENT_IDENTITY_CHANGE');
    }
    return Object.freeze({...proof,operationId:operation.operationId,
      accountId:operation.accountId,generation:after.generation});
  }
  /**
   * Persist ONLY a verified evidence digest in this existing signup journal.
   *
   * The verifier is injected by the trusted provider when constructing the
   * candidate, NOT received from a caller as an untrusted "ready" flag.
   * External Solid/DID/SAI checks run before any PG locks; an exact
   * generation CAS prevents sealing a concurrently changed account/journal.
   *
   * The sealed operation is NOT a ready account or permission to skip
   * future consent/revocation checks. It cannot be converted to ready via
   * the generic change() action, which retains its new-signup guard.
   */
  async function sealSignupEvidence(input) {
    gate();
    if (process.env.NODE_ENV === 'production' ||
        process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed' ||
        process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') {
      fail('ACCOUNT_SIGNUP_EVIDENCE_NOT_RELEASED');
    }
    assertSignupScope(input);
    if (typeof verifyNewSignupEvidence !== 'function') {
      fail('ACCOUNT_SIGNUP_EVIDENCE_PROVIDER_REQUIRED');
    }
    const prior = await readSignup(input);
    if (!prior) fail('ACCOUNT_SIGNUP_RECONCILIATION_REQUIRED');
    if (prior.state === 'evidence_sealed') {
      // This is a historical journal read, NOT renewed SAI permission and
      // NOT permission to trigger any remote identity creation or login.
      return Object.freeze({ ...prior, replay:true, releaseAuthorized:false });
    }
    if (prior.state !== 'reconciliation_required' ||
        !Number.isSafeInteger(prior.generation) || prior.generation < 2) {
      fail('ACCOUNT_SIGNUP_RECONCILIATION_REQUIRED');
    }
    let proof;
    try {
      proof = await verifyNewSignupEvidence(Object.freeze({
        providerId:input.providerId,appClientId:input.appClientId,
        hmacKeyVersion:input.hmacKeyVersion,
        idempotencyHmac:Buffer.from(input.idempotencyHmac)
      }));
    }catch(error){
      // Do not leak remote DID, SAI, OIDC or signing-service details to
      // eventual internal log consumers at the account boundary.
      if (error?.code === 'ACCOUNT_SIGNUP_EVIDENCE_NOT_RELEASED') throw error;
      fail('ACCOUNT_SIGNUP_EVIDENCE_UNAVAILABLE');
    }
    const cid=/^bafyre[a-z2-7]{53}$/;
    const tid=/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/;
    const fence=/^[1-9][0-9]{0,18}$/;
    if (!proof || proof.status !== 'evidence_only' ||
        proof.productionReady !== false ||
        proof.accountId !== prior.accountId ||
        proof.signupGeneration !== prior.generation ||
        typeof proof.webId !== 'string' || proof.webId.length > 2048 ||
        typeof proof.did !== 'string' ||
        !/^did:plc:[a-z2-7]{24}$/.test(proof.did) ||
        typeof proof.pdsOrigin !== 'string' || proof.pdsOrigin.length > 2048 ||
        !cid.test(proof.commitCid||'') ||
        !cid.test(proof.rootCid||'') ||
        !tid.test(proof.rev||'') ||
        typeof proof.projectionFence !== 'string' ||
        !fence.test(proof.projectionFence) ||
        BigInt(proof.projectionFence) > 9223372036854775807n ||
        !Number.isSafeInteger(proof.accountGeneration) ||
        proof.accountGeneration < 1 ||
        !['pending','delivered'].includes(proof.outboxStatus)) {
      fail('ACCOUNT_SIGNUP_EVIDENCE_INVALID');
    }
    const digest=crypto.createHash('sha256').update(
      JSON.stringify([
        'paper.signup.evidence.seal.v1',input.providerId,prior.operationId,
        prior.accountId,prior.generation,
        proof.accountGeneration,proof.webId,proof.did,proof.pdsOrigin,
        proof.commitCid,proof.rootCid,proof.rev,proof.projectionFence,
        proof.outboxStatus
      ])
    ).digest();
    return tx(pool,async c=>{
      // Lock in the same canonical order as change(): account first,
      // then the unique journal row. Never use a cross-Pod scan.
      const account=await c.query(
        'SELECT generation,state,webid,activitypub_actor_uri,atproto_did,'+
        'atproto_pds_url FROM '+SCHEMA+'.accounts '+
        'WHERE provider_id=$1 AND account_id=$2 FOR UPDATE',
        [input.providerId,prior.accountId]
      );
      if(account.rowCount!==1 ||
         Number(account.rows[0].generation)!==proof.accountGeneration ||
         account.rows[0].state!=='provisioning' ||
         account.rows[0].webid!==proof.webId ||
         account.rows[0].activitypub_actor_uri!==proof.webId ||
         account.rows[0].atproto_did!==proof.did ||
         account.rows[0].atproto_pds_url!==proof.pdsOrigin){
        fail('ACCOUNT_SIGNUP_EVIDENCE_ACCOUNT_CHANGED');
      }
      const operation=await c.query(
        'SELECT operation_id,account_id,state,generation,may_have_side_effects '+
        'FROM '+signupTable+
        ' WHERE provider_id=$1 AND app_client_id=$2 '+
        'AND hmac_key_version=$3 AND idempotency_hmac=$4 AND account_id=$5 '+
        'AND operation_id=$6 FOR UPDATE',
        [input.providerId,input.appClientId,input.hmacKeyVersion,
          input.idempotencyHmac,prior.accountId,prior.operationId]
      );
      if(operation.rowCount!==1 ||
         operation.rows[0].state!=='reconciliation_required' ||
         operation.rows[0].may_have_side_effects!==true ||
         Number(operation.rows[0].generation)!==proof.signupGeneration){
        fail('ACCOUNT_SIGNUP_EVIDENCE_OPERATION_CHANGED');
      }
      const sealed=await c.query(
        'UPDATE '+signupTable+
        " SET state='evidence_sealed',generation=generation+1,"+
        'evidence_digest=$3,evidence_commit_cid=$4,evidence_root_cid=$5,'+
        'evidence_rev=$6,evidence_fence=$7::bigint,'+
        'evidence_account_generation=$8,evidence_sealed_at=clock_timestamp(),'+
        'changed_at=clock_timestamp() '+
        "WHERE operation_id=$1 AND account_id=$2 AND state='reconciliation_required' "+
        'AND generation=$9 RETURNING operation_id,account_id,state,generation',
        [prior.operationId,prior.accountId,digest,proof.commitCid,
          proof.rootCid,proof.rev,proof.projectionFence,
          proof.accountGeneration,proof.signupGeneration]
      );
      if(sealed.rowCount!==1)fail('ACCOUNT_SIGNUP_EVIDENCE_OPERATION_CHANGED');
      return Object.freeze({
        ...signupResult(sealed.rows[0],false),
        releaseAuthorized:false
      });
    });
  }

  return Object.freeze({reserve,change,read,reserveSignup,
    markSignupMayHaveSideEffects,readSignup,verifySignupSolidReadiness,sealSignupEvidence});
}
module.exports={createCandidate};
