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
