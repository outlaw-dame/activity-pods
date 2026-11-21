import solidAuthority from '../solid-new-signup-proof.js';
import lifecycle from '../postgres-account-lifecycle.js';
import {createBootstrapHosting} from './provider-bootstrap-hosting.mjs';
import {createNewSignupCrossAuthority} from './new-signup-cross-authority.mjs';
import {createHostedSignupPdsAttestation} from './hosted-signup-pds-attestation.mjs';

export async function sealProviderBootstrap({reader,sealer,scope,broker,requestPds}) {
  const {did,operationId,reservationId}=scope;
  const {rows}=await sealer.query({text:
    'SELECT provider_id,app_client_id,hmac_key_version,idempotency_hmac FROM paper_account_candidate.signup_operations WHERE operation_id=$1',
    values:[operationId],query_timeout:2500});
  if(rows.length!==1) throw Error('Unknown provider enrollment');
  const op=rows[0];
  const journal={providerId:op.provider_id,appClientId:op.app_client_id,hmacKeyVersion:op.hmac_key_version,idempotencyHmac:op.idempotency_hmac};
  const hosting=createBootstrapHosting(reader);
  const accountAuthority=lifecycle.createCandidate({pool:sealer,fixtureOnly:true});
  const signed=await hosting.snapshot(did);
  const owner=await broker.call('auth.account.findByWebId',{webId:signed.webId},{meta:{},timeout:3000,retries:0});
  if(owner?.signupReservationId!==reservationId || owner.webId!==signed.webId ||
      !/^claimtest-[a-z0-9]{8,24}$/u.test(owner.username) || owner.webId!==op.provider_id+'/'+owner.username) {
    throw Error('Native account and reservation mismatch');
  }
  const cross=createNewSignupCrossAuthority({accountAuthority,...hosting,fixtureOnly:true,
    solidCall:(action,params)=>broker.call(action,params,{meta:{webId:owner.webId,dataset:owner.username},timeout:40000,retries:0})});
  const hosted=createHostedSignupPdsAttestation({...hosting,requestPds,fixtureOnly:true});
  const writer=lifecycle.createCandidate({pool:sealer,fixtureOnly:true,async verifyNewSignupEvidence(input){
    const proof=await cross.verify(input);
    const current=await accountAuthority.read({providerId:input.providerId,accountId:proof.accountId});
    if(owner.webId!==proof.webId || proof.did!==did) {
      throw Error('Native account and reservation mismatch');
    }
    await hosted.verify({...proof,handle:current.atproto_handle});
    return proof;
  }});
  return writer.sealSignupEvidence(journal);
}

// Called by the disposable provider worker after sealing. A replay observes
// the same signed head and the same owner without issuing an app credential.
export async function activateProviderOwner({reader,activator,scope,broker,requestPds}) {
  const {did,reservationId,operationId}=scope;
  const hosting=createBootstrapHosting(reader);
  const signed=await hosting.snapshot(did);
  const owner=await broker.call('auth.account.findByWebId',{webId:signed.webId},{meta:{},timeout:3000,retries:0});
  if(owner?.signupReservationId!==reservationId || !/^claimtest-[a-z0-9]{8,24}$/u.test(owner.username) ||
    owner.webId!==signed.webId || signed.webId!=='https://paper.example.org/'+owner.username) {
    throw Error('Native account and reservation mismatch');
  }
  const call=(action,params)=>broker.call(action,params,{meta:{dataset:owner.username,webId:owner.webId},timeout:40000,retries:0});
  await solidAuthority.verifyNewSignupSolidAuthority({call,webId:owner.webId,did,operationId});
  const hosted=createHostedSignupPdsAttestation({...hosting,requestPds,fixtureOnly:true});
  await hosted.verify({...signed,projectionFence:signed.fence});
  const result=await activator.query({text:
    'SELECT paper_account_reservation_proof.activate_provider_owner($1,$2,$3,$4,$5,$6,$7,$8) AS ready',
    values:[reservationId,operationId,signed.webId,did,signed.commitCid,signed.rootCid,signed.rev,signed.fence],query_timeout:4000});
  if(result.rows[0]?.ready!==true) throw Error('Provider owner activation refused');
  return {ownerReady:true,releaseAuthorized:false};
}
