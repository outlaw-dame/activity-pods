'use strict';

/**
 * NON-ACTIVATED new signup completion candidate.
 *
 * No HTTP action, no signer, no generic account-state transition and no
 * automatic retry of PLC/PDS side effects. A trusted provider callback checks
 * Solid/SAI, DID/handle, real signed repository CAR and hosted PDS endpoints
 * outside the SQL transaction; PostgreSQL then locks every canonical state
 * that can invalidate that proof and promotes account+journal atomically.
 *
 * This is a disposable transaction acceptance seam, NOT an assertion that the
 * production provider actually supports the full hosted PDS lifecycle.
 */
const crypto = require('node:crypto');
const ACCOUNT = 'paper_account_candidate.accounts';
const SIGNUP = 'paper_account_candidate.signup_operations';
const REPOS = 'paper_atproto_repo_proof.repos';
const PROJECTION = 'paper_atproto_repo_proof.rdf_projection_jobs';
const OUTBOX = 'paper_atproto_repo_proof.native_event_outbox';
const IDENTITY = 'paper_atproto_authority.identities';
const CONSENT = 'paper_atproto_authority.consents';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DID = /^did:plc:[a-z2-7]{24}$/u;
const CID = /^bafyre[a-z2-7]{53}$/u;
const REV = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const UINT = /^[1-9][0-9]{0,18}$/u;
const MAX = 9223372036854775807n;

function deny(code) {
  const e = new Error('Provider-managed new account completion is unavailable');
  e.code = code;
  throw e;
}
function canonicalUrl(value, originOnly = false) {
  if (typeof value !== 'string' || value.length < 8 || value.length > 2048) {
    deny('SIGNUP_COMPLETION_SCOPE_INVALID');
  }
  try {
    const u = new URL(value);
    if (u.protocol !== 'https:' || !u.hostname ||
        u.username || u.password || u.search || u.hash ||
        (originOnly ? u.origin !== value : u.href !== value)) {
      deny('SIGNUP_COMPLETION_SCOPE_INVALID');
    }
  } catch { deny('SIGNUP_COMPLETION_SCOPE_INVALID'); }
  return value;
}
function epoch(value) {
  if (typeof value !== 'string' || !UINT.test(value) ||
      BigInt(value) > MAX) deny('SIGNUP_COMPLETION_SCOPE_INVALID');
  return value;
}
function checkScope(s) {
  if (!s || typeof s !== 'object' || Array.isArray(s) ||
      typeof s.providerId !== 'string' || s.providerId.length < 8 ||
      s.providerId.length > 255 ||
      typeof s.appClientId !== 'string' || s.appClientId.length < 1 ||
      s.appClientId.length > 2048 ||
      !Number.isSafeInteger(s.hmacKeyVersion) ||
      s.hmacKeyVersion < 1 || s.hmacKeyVersion > 255 ||
      !Buffer.isBuffer(s.idempotencyHmac) || s.idempotencyHmac.length !== 32) {
    deny('SIGNUP_COMPLETION_SCOPE_INVALID');
  }
}
function allowed() {
  // Both constructor-time AND call-time checks. A fixture instance can never
  // be re-used merely by changing runtime flags or switching to production.
  return process.env.NODE_ENV === 'test' &&
    process.env.PAPER_ACCOUNTS_DISPOSABLE === 'confirmed' &&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE === 'confirmed' &&
    process.env.PAPER_ACCOUNT_COMPLETION_DISPOSABLE === 'confirmed';
}
const number = value => {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) deny('SIGNUP_COMPLETION_GENERATION_INVALID');
  return n;
};
function compareDigest(a, b) {
  return Buffer.isBuffer(a) && a.length === 32 && Buffer.isBuffer(b) &&
    b.length === 32 && crypto.timingSafeEqual(a, b);
}
function sealedEvidenceDigest(p, sealedGeneration, outboxStatus) {
  return crypto.createHash('sha256').update(JSON.stringify([
    'paper.signup.evidence.seal.v1',
    p.providerId,p.operationId,p.accountId,sealedGeneration,
    p.accountGeneration,p.webId,p.did,p.pdsOrigin,p.commitCid,p.rootCid,
    p.rev,p.projectionFence,outboxStatus
  ])).digest();
}
function completionDigest(p) {
  return crypto.createHash('sha256').update(JSON.stringify([
    'paper.signup.atomic.completion.v1', p.providerId,p.operationId,p.accountId,
    p.accountGeneration,p.webId,p.did,p.handle,p.pdsOrigin,p.commitCid,p.rootCid,
    p.rev,p.projectionFence,p.appUri,p.grantUri,p.consentRevision,
    'signed-repo-solid-pds-current'
  ])).digest();
}
function validateProof(p, before) {
  if (!p || typeof p !== 'object' || Array.isArray(p) ||
      p.status !== 'disposable_provider_verified' || p.productionReady !== false ||
      p.signedRepoVerified !== true || p.solidVerified !== true ||
      p.hostedPdsVerified !== true || p.ownerConsentVerified !== true ||
      p.operationId !== before.operationId || p.accountId !== before.accountId ||
      p.providerId !== before.providerId ||
      !UUID.test(p.operationId || '') || !UUID.test(p.accountId || '') ||
      number(p.accountGeneration) < 1 ||
      !Number.isSafeInteger(p.accountGeneration) ||
      !DID.test(p.did || '') || !CID.test(p.commitCid || '') ||
      !CID.test(p.rootCid || '') || !REV.test(p.rev || '') ||
      typeof p.handle !== 'string' || p.handle.length > 253 ||
      !/^[a-z0-9.-]+$/u.test(p.handle) || !p.handle.includes('.') ||
      !['pending','delivered'].includes(p.outboxStatus)) {
    deny('SIGNUP_COMPLETION_PROOF_INVALID');
  }
  for (const key of ['webId','appUri','grantUri']) canonicalUrl(p[key]);
  canonicalUrl(p.pdsOrigin, true);
  epoch(p.projectionFence);
  epoch(p.consentRevision);
  if (p.webId !== before.webid || p.did !== before.atproto_did ||
      p.handle !== before.atproto_handle ||
      p.pdsOrigin !== before.atproto_pds_url ||
      p.accountGeneration !== number(before.account_generation)) {
    deny('SIGNUP_COMPLETION_PROOF_MISMATCH');
  }
}

function createDisposableSignupCompletion({ pool, verifyCurrent, fixtureOnly = false } = {}) {
  if (!pool?.connect || !pool?.query || typeof verifyCurrent !== 'function') {
    deny('SIGNUP_COMPLETION_CONFIGURATION_INVALID');
  }
  async function complete(scope) {
    if (fixtureOnly !== true || !allowed()) deny('SIGNUP_COMPLETION_NOT_RELEASED');
    checkScope(scope);
    const params=[scope.providerId,scope.appClientId,scope.hmacKeyVersion,
      scope.idempotencyHmac];
    const initial=await pool.query(
      'SELECT s.operation_id,s.account_id,s.state,s.generation,'+
      's.evidence_account_generation,a.webid,a.atproto_did,a.atproto_handle,'+
      'a.atproto_pds_url,a.generation AS account_generation '+
      'FROM '+SIGNUP+' s JOIN '+ACCOUNT+' a ON a.account_id=s.account_id '+
      'WHERE s.provider_id=$1 AND s.app_client_id=$2 AND '+
      's.hmac_key_version=$3 AND s.idempotency_hmac=$4 LIMIT 2',params
    );
    if(initial.rowCount!==1) deny('SIGNUP_COMPLETION_NOT_FOUND');
    const before={...initial.rows[0],providerId:scope.providerId,
      operationId:initial.rows[0].operation_id,
      accountId:initial.rows[0].account_id};
    if (before.state==='ready') {
      return Object.freeze({state:'ready',replay:true,accountId:before.accountId,
        releaseAuthorized:false,canAuthenticate:false});
    }
    if (before.state!=='evidence_sealed' || number(before.generation)<3) {
      deny('SIGNUP_COMPLETION_NOT_SEALED');
    }
    // No SQL lock or pool connection is held over cross-store, PDS, DNS,
    // Solid-OIDC or external signing-key verification. The provider callback
    // is injected, never received as an untrusted request field.
    let p;
    try {
      p=await verifyCurrent(Object.freeze({
        providerId:scope.providerId,appClientId:scope.appClientId,
        hmacKeyVersion:scope.hmacKeyVersion,
        idempotencyHmac:Buffer.from(scope.idempotencyHmac),
        operationId:before.operationId,accountId:before.accountId
      }));
    } catch { deny('SIGNUP_COMPLETION_PROVIDER_UNAVAILABLE'); }
    validateProof(p,before);

    const c=await pool.connect();let open=false,commitAttempted=false,broken=false;
    try {
      await c.query('BEGIN');open=true;
      await c.query("SET LOCAL lock_timeout='2000ms'");
      await c.query("SET LOCAL statement_timeout='8000ms'");
      await c.query("SET LOCAL idle_in_transaction_session_timeout='4000ms'");
      // Uniform lock order for all completion callers. Other writers must
      // take account first, then journal. Never scan across tenants.
      const a=await c.query('SELECT account_id,provider_id,webid,'+
        'activitypub_actor_uri,atproto_did,atproto_handle,atproto_pds_url,'+
        'atproto_repo_initialized,state,generation FROM '+ACCOUNT+
        ' WHERE provider_id=$1 AND account_id=$2 FOR UPDATE',
        [scope.providerId,before.accountId]);
      if(a.rowCount!==1)deny('SIGNUP_COMPLETION_ACCOUNT_CHANGED');
      const row=a.rows[0];
      if (row.state === 'ready') {
        // Another cell may have committed while this caller was verifying
        // external evidence. Re-read the exact journal under the account
        // lock before returning an idempotent, non-authorizing replay.
        const completed=await c.query(
          'SELECT operation_id,account_id,state FROM '+SIGNUP+
          ' WHERE provider_id=$1 AND app_client_id=$2 AND '+
          'hmac_key_version=$3 AND idempotency_hmac=$4 AND account_id=$5 '+
          'AND operation_id=$6 FOR UPDATE',
          [...params,before.accountId,before.operationId]
        );
        if(completed.rowCount!==1 || completed.rows[0].state!=='ready') {
          deny('SIGNUP_COMPLETION_JOURNAL_CHANGED');
        }
        await c.query('ROLLBACK');open=false;
        return Object.freeze({state:'ready',replay:true,accountId:before.accountId,
          releaseAuthorized:false,canAuthenticate:false});
      }
      if(row.state!=='provisioning' || number(row.generation)!==p.accountGeneration ||
          row.webid!==p.webId || row.activitypub_actor_uri!==p.webId ||
          row.atproto_did!==p.did || row.atproto_handle!==p.handle ||
          row.atproto_pds_url!==p.pdsOrigin ||
          row.atproto_repo_initialized!==true) {
        deny('SIGNUP_COMPLETION_ACCOUNT_CHANGED');
      }
      const op=await c.query(
        'SELECT operation_id,account_id,state,generation,may_have_side_effects,'+
        'evidence_digest,evidence_commit_cid,evidence_root_cid,evidence_rev,'+
        'evidence_fence::text AS evidence_fence,evidence_account_generation '+
        'FROM '+SIGNUP+' WHERE provider_id=$1 AND app_client_id=$2 '+
        'AND hmac_key_version=$3 AND idempotency_hmac=$4 AND account_id=$5 '+
        'AND operation_id=$6 FOR UPDATE',
        [...params,before.accountId,before.operationId]
      );
      if(op.rowCount!==1)deny('SIGNUP_COMPLETION_JOURNAL_CHANGED');
      const sealed=op.rows[0];
      if(sealed.state==='ready') {
        await c.query('ROLLBACK');open=false;
        return Object.freeze({state:'ready',replay:true,accountId:before.accountId,
          releaseAuthorized:false,canAuthenticate:false});
      }
      if(sealed.state!=='evidence_sealed' || sealed.may_have_side_effects!==true ||
          number(sealed.generation)!==number(before.generation) ||
          number(sealed.evidence_account_generation)!==p.accountGeneration ||
          sealed.evidence_commit_cid!==p.commitCid ||
          sealed.evidence_root_cid!==p.rootCid ||
          sealed.evidence_rev!==p.rev ||
          String(sealed.evidence_fence)!==p.projectionFence ||
          !['pending','delivered'].some(status=>compareDigest(
            sealed.evidence_digest,sealedEvidenceDigest(p,
              number(sealed.generation)-1,status)))) {
        deny('SIGNUP_COMPLETION_SEALED_EVIDENCE_DRIFT');
      }
      const repo=await c.query(
        'SELECT account_id,did,head_cid,root_cid,rev,generation FROM '+REPOS+
        ' WHERE account_id=$1 AND did=$2 FOR SHARE',[p.webId,p.did]
      );
      if(repo.rowCount!==1 || repo.rows[0].head_cid!==p.commitCid ||
          repo.rows[0].root_cid!==p.rootCid || repo.rows[0].rev!==p.rev ||
          number(repo.rows[0].generation)<1) deny('SIGNUP_COMPLETION_REPO_CHANGED');
      const projection=await c.query(
        'SELECT account_id,did,head_cid,root_cid,rev,generation,state,'+
        'lease_epoch::text AS lease_epoch,applied_at FROM '+PROJECTION+
        ' WHERE account_id=$1 AND did=$2 FOR SHARE',[p.webId,p.did]
      );
      if(projection.rowCount!==1 || projection.rows[0].state!=='applied' ||
          !projection.rows[0].applied_at ||
          projection.rows[0].head_cid!==p.commitCid ||
          projection.rows[0].root_cid!==p.rootCid ||
          projection.rows[0].rev!==p.rev ||
          String(projection.rows[0].lease_epoch)!==p.projectionFence ||
          Number(projection.rows[0].generation)!==Number(repo.rows[0].generation)) {
        deny('SIGNUP_COMPLETION_PROJECTION_CHANGED');
      }
      // Read and lock canonical consent in the very same SQL transaction.
      // The block_consent SECURITY DEFINER UPDATE takes an incompatible row
      // lock; the observed active revision cannot be revoked before COMMIT.
      const auth=await c.query(
        'SELECT i.did,i.state AS identity_state,i.managed,'+
        'c.state AS consent_state,c.grant_uri,c.revision::text AS consent_revision '+
        'FROM '+CONSENT+' c JOIN '+IDENTITY+' i ON i.owner_webid=c.owner_webid '+
        'WHERE c.owner_webid=$1 AND c.app_uri=$2 FOR SHARE OF c,i',
        [p.webId,p.appUri]
      );
      if(auth.rowCount!==1 || auth.rows[0].did!==p.did ||
          auth.rows[0].identity_state!=='active' || auth.rows[0].managed!==true ||
          auth.rows[0].consent_state!=='active' ||
          auth.rows[0].grant_uri!==p.grantUri ||
          auth.rows[0].consent_revision!==p.consentRevision) {
        deny('SIGNUP_COMPLETION_CONSENT_REVOKED');
      }
      const event=await c.query(
        'SELECT status,blocked_at,rev FROM '+OUTBOX+
        ' WHERE did=$1 AND commit_cid=$2 FOR SHARE',[p.did,p.commitCid]
      );
      if(event.rowCount!==1 || event.rows[0].blocked_at!==null ||
          !['pending','delivered'].includes(event.rows[0].status) ||
          event.rows[0].rev!==p.rev) {
        deny('SIGNUP_COMPLETION_EVENT_UNAVAILABLE');
      }
      const blocked=await c.query(
        'SELECT 1 FROM '+OUTBOX+
        " WHERE did=$1 AND status='pending' AND blocked_at IS NOT NULL LIMIT 1",
        [p.did]
      );
      if(blocked.rowCount!==0)deny('SIGNUP_COMPLETION_EVENT_HISTORY_BLOCKED');

      const updated=await c.query(
        'UPDATE '+ACCOUNT+" SET state='ready',generation=generation+1,"+
        'changed_at=clock_timestamp() '+
        "WHERE account_id=$1 AND provider_id=$2 AND state='provisioning' "+
        'AND generation=$3 RETURNING generation',
        [p.accountId,p.providerId,p.accountGeneration]
      );
      if(updated.rowCount!==1 || number(updated.rows[0].generation)!==
          p.accountGeneration+1)deny('SIGNUP_COMPLETION_GENERATION_STALE');
      const digest=completionDigest(p);
      const opUpdated=await c.query(
        'UPDATE '+SIGNUP+" SET state='ready',generation=generation+1,"+
        'completion_at=clock_timestamp(),completion_account_generation=$3,'+
        'completion_app_uri=$4,completion_grant_uri=$5,'+
        'completion_consent_revision=$6::bigint,completion_proof_digest=$7,'+
        'changed_at=clock_timestamp() '+
        "WHERE operation_id=$1 AND account_id=$2 AND state='evidence_sealed' "+
        'AND generation=$8 RETURNING generation',
        [p.operationId,p.accountId,p.accountGeneration+1,p.appUri,
          p.grantUri,p.consentRevision,digest,number(sealed.generation)]
      );
      if(opUpdated.rowCount!==1)deny('SIGNUP_COMPLETION_GENERATION_STALE');
      commitAttempted=true;await c.query('COMMIT');open=false;
      // The candidate never emits a login token, grant or production release.
      return Object.freeze({state:'ready',replay:false,accountId:p.accountId,
        generation:p.accountGeneration+1,releaseAuthorized:false,
        canAuthenticate:false});
    }catch(error){
      if(commitAttempted){
        broken=true;
        deny('SIGNUP_COMPLETION_COMMIT_OUTCOME_UNKNOWN');
      }
      if(open){try{await c.query('ROLLBACK');open=false;}
        catch{broken=true;}}
      throw error;
    }finally{c.release(broken);}
  }
  return Object.freeze({complete});
}
module.exports={createDisposableSignupCompletion};
