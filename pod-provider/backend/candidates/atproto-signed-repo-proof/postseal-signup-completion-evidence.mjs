/**
 * NONACTIVATED ActivityPods-only new-signup verifier AFTER journal sealing.
 *
 * Do not weaken createNewSignupCrossAuthority's pre-seal reconciliation guard.
 * This bridge performs read-only current Solid/SAI/PG/repo/hosted PDS checks,
 * then feeds the v4 same-transaction PostgreSQL completion candidate.
 *
 * This does not mint identities, grant an OAuth token, or activate signup.
 */
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {verifyNewSignupSolidAuthority}=
  require('../solid-new-signup-proof.js');

const DID=/^did:plc:[a-z2-7]{24}$/u;
const CID=/^bafyre[a-z2-7]{53}$/u;
const REV=/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const EPOCH=/^[1-9][0-9]{0,18}$/u;
function deny(code){
  const e=new Error('New account completion evidence unavailable');
  e.code=code;throw e;
}
function canonical(value){
  if(typeof value!=='string'||value.length>2048)return false;
  try{const u=new URL(value);
    return u.protocol==='https:'&&u.hostname&&u.href===value&&
      !u.username&&!u.password&&!u.search&&!u.hash;
  }catch{return false;}
}
const snapshot=a=>JSON.stringify([a.account_id,a.provider_id,a.webid,
  a.activitypub_actor_uri,a.atproto_did,a.atproto_handle,a.atproto_pds_url,
  a.atproto_repo_initialized,a.state,a.generation]);

export function createPostSealSignupCompletionEvidence({
  accountAuthority,repositoryAuthority,projectionAuthority,
  hostedPdsAttestation,solidCall,pool,approvedProviderId,
  approvedAppClientId,approvedAppUri,fixtureOnly=false
}={}){
  const allowed=()=>fixtureOnly===true&&process.env.NODE_ENV==='test'&&
    process.env.PAPER_ACCOUNTS_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_PDS_ATTESTATION_DISPOSABLE==='confirmed'&&
    process.env.PAPER_ACCOUNT_COMPLETION_DISPOSABLE==='confirmed';
  const unavailable=async()=>deny('SIGNUP_POSTSEAL_PROOF_NOT_RELEASED');
  if(!allowed())return Object.freeze({verify:unavailable});
  if(typeof accountAuthority?.readSignup!=='function'||
     typeof accountAuthority?.read!=='function'||
     typeof repositoryAuthority?.verifyReady!=='function'||
     typeof projectionAuthority?.readiness!=='function'||
     typeof hostedPdsAttestation?.verify!=='function'||
     typeof solidCall!=='function'||typeof pool?.query!=='function'||
     !canonical(approvedAppUri)||
     typeof approvedProviderId!=='string'||approvedProviderId.length<8||
     typeof approvedAppClientId!=='string'||approvedAppClientId.length<8) {
    deny('SIGNUP_POSTSEAL_CONFIGURATION_INVALID');
  }
  async function verify(scope){
    if(!allowed())deny('SIGNUP_POSTSEAL_PROOF_NOT_RELEASED');
    if(scope?.providerId!==approvedProviderId||
       scope?.appClientId!==approvedAppClientId||
       !Buffer.isBuffer(scope?.idempotencyHmac)||
       scope.idempotencyHmac.length!==32) {
      deny('SIGNUP_POSTSEAL_SCOPE_INVALID');
    }
    const op=await accountAuthority.readSignup(scope);
    if(!op||op.state!=='evidence_sealed'||op.generation<3||
       op.operationId!==scope.operationId||
       op.accountId!==scope.accountId) {
      deny('SIGNUP_POSTSEAL_OPERATION_INCOMPLETE');
    }
    const a=await accountAuthority.read({
      providerId:scope.providerId,accountId:op.accountId
    });
    if(!a||a.provider_id!==approvedProviderId||
       a.state!=='provisioning'||a.webid!==a.activitypub_actor_uri||
       !canonical(a.webid)||!DID.test(a.atproto_did||'')||
       a.atproto_repo_initialized!==true||
       typeof a.atproto_handle!=='string'||
       typeof a.atproto_pds_url!=='string') {
      deny('SIGNUP_POSTSEAL_ACCOUNT_CHANGED');
    }
    const solid=await verifyNewSignupSolidAuthority({
      call:solidCall,webId:a.webid,
      did:a.atproto_did,operationId:op.operationId
    });
    if(solid.complete!==true||solid.webId!==a.webid||
       solid.did!==a.atproto_did)deny('SIGNUP_POSTSEAL_SOLID_INCOMPLETE');
    const binding=await solidCall('identitybindings.getByCanonicalAccountId',{
      canonicalAccountId:a.webid
    });
    if(!binding||binding.canonicalAccountId!==a.webid||
       binding.webId!==a.webid||
       binding.activityPubActorId!==a.webid||
       binding.atprotoDid!==a.atproto_did||
       binding.atprotoHandle!==a.atproto_handle||
       binding.atprotoPdsUrl!==a.atproto_pds_url||
       binding.atprotoSource!=='local'||binding.atprotoManaged!==true) {
      deny('SIGNUP_POSTSEAL_BINDING_CHANGED');
    }
    const repo=await repositoryAuthority.verifyReady({
      canonicalAccountId:a.webid,did:a.atproto_did,handle:a.atproto_handle
    });
    const projection=await projectionAuthority.readiness({
      accountId:a.webid,did:a.atproto_did
    });
    if(repo?.verified!==true||repo.accountId!==a.webid||
       repo.did!==a.atproto_did||
       repo.pdsOrigin!==a.atproto_pds_url||
       !CID.test(repo.commitCid||'')||!CID.test(repo.rootCid||'')||
       !REV.test(repo.rev||'')||
       projection?.ready!==true||projection.headCid!==repo.commitCid||
       projection.rootCid!==repo.rootCid||projection.rev!==repo.rev||
       projection.accountId!==a.webid||projection.did!==a.atproto_did||
       projection.outboxStatus!==repo.outboxStatus||
       typeof projection.fence!=='string'||!EPOCH.test(projection.fence)) {
      deny('SIGNUP_POSTSEAL_SIGNED_HEAD_CHANGED');
    }
    const hosted=await hostedPdsAttestation.verify({
      webId:a.webid,did:a.atproto_did,handle:a.atproto_handle,
      pdsOrigin:a.atproto_pds_url,commitCid:repo.commitCid,
      rootCid:repo.rootCid,rev:repo.rev,
      projectionFence:projection.fence
    });
    if(hosted?.hostedPdsVerified!==true||
       hosted.status!=='hosted_genesis_evidence_only'||
       hosted.productionReady!==false||
       hosted.commitCid!==repo.commitCid||
       hosted.did!==a.atproto_did) {
      deny('SIGNUP_POSTSEAL_HOSTED_PDS_UNVERIFIED');
    }
    // Canonical consent is an indexed lookup; the v4 completion transaction
    // later locks this same identity and consent row and requires exact
    // revision, so a concurrent revocation cannot become a ready account.
    const consent=await pool.query(
      'SELECT i.did,i.managed,i.state AS identity_state,'+
      'c.state AS consent_state,c.grant_uri,c.revision::text AS revision '+
      'FROM paper_atproto_authority.consents c JOIN '+
      'paper_atproto_authority.identities i ON i.owner_webid=c.owner_webid '+
      'WHERE c.owner_webid=$1 AND c.app_uri=$2',
      [a.webid,approvedAppUri]
    );
    if(consent.rowCount!==1||consent.rows[0].did!==a.atproto_did||
       consent.rows[0].managed!==true||
       consent.rows[0].identity_state!=='active'||
       consent.rows[0].consent_state!=='active'||
       !canonical(consent.rows[0].grant_uri)||
       !EPOCH.test(consent.rows[0].revision)) {
      deny('SIGNUP_POSTSEAL_CONSENT_REVOKED');
    }
    const [afterOp,afterAccount]=await Promise.all([
      accountAuthority.readSignup(scope),
      accountAuthority.read({providerId:scope.providerId,accountId:op.accountId})
    ]);
    if(!afterOp||afterOp.state!==op.state||
       afterOp.generation!==op.generation||
       afterOp.operationId!==op.operationId||
       afterOp.accountId!==op.accountId||
       snapshot(afterAccount)!==snapshot(a)) {
      deny('SIGNUP_POSTSEAL_CONCURRENT_CHANGE');
    }
    // The output is only a disposable proof object. In production, the
    // dedicated provider writer must construct it, never an HTTP caller.
    return Object.freeze({
      status:'disposable_provider_verified',productionReady:false,
      signedRepoVerified:true,solidVerified:true,
      hostedPdsVerified:true,ownerConsentVerified:true,
      providerId:scope.providerId,operationId:op.operationId,
      accountId:op.accountId,accountGeneration:Number(a.generation),
      webId:a.webid,did:a.atproto_did,handle:a.atproto_handle,
      pdsOrigin:a.atproto_pds_url,commitCid:repo.commitCid,
      rootCid:repo.rootCid,rev:repo.rev,
      projectionFence:projection.fence,
      outboxStatus:repo.outboxStatus,
      appUri:approvedAppUri,grantUri:consent.rows[0].grant_uri,
      consentRevision:consent.rows[0].revision
    });
  }
  return Object.freeze({verify});
}
