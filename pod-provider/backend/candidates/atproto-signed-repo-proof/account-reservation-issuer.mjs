/**
 * NONACTIVATED restricted ActivityPods pre-account claim issuer.
 * The signed dataset claim is derived from a *started* PostgreSQL
 * reservation and its server-clock expiry, never from a caller-selected
 * owner, issuer, audience, timestamp or nonce.
 *
 * This module has no Fuseki/admin privileges and no worker SQL mutation
 * credential. The caller must run it in a separate, least-privileged
 * issuer process; ordinary SemApps providers cannot import a signing key.
 */
import { ownerWebId } from '../../services/utils/disposable-provider-identity.js';
import crypto from 'node:crypto';
import {signDisposableDatasetClaim} from './dataset-admin-claim-service.mjs';

const ISSUER='https://paper.example.org/provider';
const DATASET=/^claimtest-[a-z0-9]{8,24}$/u;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function refuse(){
  const e=Error('Trusted pre-account claim issuer refused this reservation');
  e.code='ACCOUNT_CLAIM_ISSUER_DENIED';
  throw e;
}
export async function issueBoundDatasetClaim({
  authority, privateKey, fence, dataset, now=Date.now()
}={}){
  if(process.env.NODE_ENV!=='test' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
     process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed' ||
     process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE!=='confirmed' ||
     process.env.APODS_DATASET_CLAIM_ISSUER_DISPOSABLE!=='confirmed')refuse();
  if(typeof dataset!=='string'||!DATASET.test(dataset)||
     !fence||typeof fence!=='object'||!UUID.test(fence.reservationId)||
     typeof authority?.getDatasetClaimLease!=='function'||
     !(privateKey instanceof crypto.KeyObject)||
     privateKey.type!=='private'||privateKey.asymmetricKeyType!=='ed25519'||
     !Number.isSafeInteger(now))refuse();

  const expectedWebId=ownerWebId(dataset);
  const lease=await authority.getDatasetClaimLease(fence,dataset,expectedWebId);
  if(!(lease instanceof Date)||!Number.isSafeInteger(lease.getTime()))refuse();
  const expiresAtMs=lease.getTime();
  const issuedAtMs=expiresAtMs-120000;
  // No right to renew a lost lease or create a second identity. A claimed
  // reservation near expiry must reconcile rather than send an expiring
  // signed ticket into the dataset admin.
  if(now<issuedAtMs-30000||now>=expiresAtMs-1000||
     now-issuedAtMs>119000)refuse();
  const claim=Object.freeze({
    version:1,issuer:ISSUER,audience:'urn:activitypods:dataset-admin:v1',
    dataset,ownerWebid:expectedWebId,reservationId:fence.reservationId,
    // The PG reservation ID is a unique random v4 nonce; repeating a
    // request produces identical Ed25519 signatures and the admin's
    // immutable ticket digest, not a conflicting second claim.
    nonce:fence.reservationId,issuedAtMs,expiresAtMs
  });
  return signDisposableDatasetClaim(claim,privateKey,now);
}
