'use strict';

/**
 * Actual unified-account HTTP action -> trusted disposable coordinator.
 * A public user can supply an app ID and credentials, NEVER a reservation
 * fence, signed claim, approval Boolean or coordinator network destination.
 *
 * New account activation is still blocked in production. This acceptance
 * integration intentionally cannot return HTTP 201 until the existing
 * Solid/SAI/signed-CAR + hosted PDS post-seal verifier has been joined to
 * the same PostgreSQL completion compare-and-swap transaction.
 */
const crypto = require('node:crypto');
const {MoleculerError} = require('moleculer').Errors;
const {parseSecret,reserveCoordinatedDataset,assertDisposable}
  = require('./atproto-account-coordinator-client');

function deny(type,code=503){
  throw new MoleculerError('New account requires trusted coordinator reconciliation',
    code,type,{retryable:false});
}
const ALLOWED_PARAMS = new Set([
  'username','email','password','profile','solid','activitypub','atproto'
]);
const RESERVED_INPUT = Object.freeze([
  'datasetAdminTicket','accountCoordinatorTicket','accountCoordinatorProof',
  'accountProvisioning','reservationId','fenceToken','dailyLimit',
  'requestFingerprint','issuer','signedTicket'
]);
function rejectUntrustedInput(params,normalized){
  if (!params || typeof params!=='object' ||
      RESERVED_INPUT.some(key=>Object.prototype.hasOwnProperty.call(params,key)) ||
      Object.keys(normalized).some(key=>!ALLOWED_PARAMS.has(key))) {
    deny('ACCOUNT_COORDINATOR_INPUT_DENIED',400);
  }
}
function fingerprint({api,appClientId,redirectUri,accountParams,protocols,env}){
  const secret=parseSecret(env.APODS_ACCOUNT_REQUEST_FINGERPRINT_KEY);
  const ordered=api.stableStringify({
    appClientId,redirectUri,account:accountParams,requestedProtocols:protocols
  });
  // Passwords must NEVER enter a fast, unkeyed SHA-256 stored request
  // fingerprint; the server-only key thwarts offline dictionary attacks.
  return crypto.createHmac('sha256',secret)
    .update('activitypods:durable-signup-fingerprint:v1\0','utf8')
    .update(ordered,'utf8').digest('hex');
}
async function coordinatedDisposableSignup({
  ctx,api,env=process.env,
  reserveImpl=reserveCoordinatedDataset
}={}){
  assertDisposable(env);
  const accountParams=api.normalizeAccountCreateParams(ctx.params || {});
  rejectUntrustedInput(ctx.params,accountParams);
  const headers=ctx.meta?.$headers || {};
  const appClientId=ctx.params?.appClientId;
  const redirectUri=ctx.params?.redirectUri;
  const idempotencyKey=headers['idempotency-key'] ||
    headers['Idempotency-Key'] || ctx.params?.idempotencyKey;
  const protocols=api.requestedProtocolsFromAccountParams(accountParams);
  const requestFingerprint=fingerprint({
    api,appClientId,redirectUri,accountParams,protocols,env
  });
  // Broker.call is deliberately used rather than ctx.call; user-supplied
  // ctx.meta (HTTP headers, user identity, account routing) must not be
  // inherited by service-to-service calls, especially the signed claim.
  const grant=await ctx.broker.call(
    'provider-capabilities.authorizeDurableAccountProvisioning',{
      appClientId,
      authorization:headers.authorization||headers.Authorization||'',
      origin:headers.origin||headers.Origin||'',
      redirectUri,
      idempotencyKey,
      requestFingerprint,
      username:accountParams.username,
      email:accountParams.email,
      requestedProtocols:protocols,
      verification:ctx.params?.verification
    },{timeout:5000,meta:{}});
  if(grant?.allowed!==true || grant?.approvedApp!==true ||
     grant?.verifiedUser!==true || grant?.appClientId!==appClientId ||
     grant?.username!==accountParams.username ||
     grant?.requestFingerprint!==requestFingerprint ||
     grant?.idempotencyKey!==idempotencyKey)deny('ACCOUNT_COORDINATOR_AUTHORITY_MISMATCH');

  // After this RPC is submitted, a lost acknowledgment could mean a
  // PostgreSQL reservation and signing fence have already committed.
  // Fail closed: NEVER repeat it with a new key or mint a second identity.
  let ticket;
  try{
    const receipt=await reserveImpl({
      grant,username:accountParams.username,appClientId,env
    });
    ticket=receipt.ticket;
  }catch(error){
    if(error?.code==='ACCOUNT_COORDINATOR_CONFLICT') {
      deny('ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED',409);
    }
    deny('ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED');
  }

  try{
    // Ticket is an explicit operation parameter, never Moleculer ctx.meta.
    // Grant is non-secret policy evidence and is separately checked by the
    // unified-account service as in the existing internal integration.
    await ctx.broker.call('unified-account.create',{
      ...accountParams,datasetAdminTicket:ticket
    },{
      meta:{accountProvisioning:grant},timeout:120000
    });
  }catch(error){
    // The actual signup RPC may have created a WebID and a DID before its
    // transport failed. The PostgreSQL fence is intentionally retained.
    deny('ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED');
  }
  // The current unified facade returns metadata, NOT the attested signed
  // CAR/hosted-PDS/Solid/SAI completion evidence and atomic PG seal.
  // No 201, replay token, or completed reservation may be fabricated.
  deny('ACCOUNT_COMPLETION_ATTESTATION_PENDING');
}
module.exports={coordinatedDisposableSignup,rejectUntrustedInput,fingerprint};
