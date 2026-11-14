/**
 * Disposable ordinary ActivityPods process. The issuer signs a claim in the
 * separate test harness; this child has NO Jena administrator credential,
 * PostgreSQL connection string, claim-signing key or sidecar secret.
 * Calls exactly the same CJS client required by the real Moleculer service.
 */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const ALLOWED = new Set([
  'NODE_ENV','ATPROTO_REPO_PROOF_DISPOSABLE',
  'ATPROTO_FUSEKI_ISOLATION_DISPOSABLE','FUSEKI_ISOLATION_URL',
  'APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE',
  'DATASET_ADMIN_ORDINARY_TICKET','DATASET_ADMIN_ORDINARY_MODE'
]);
if(Object.keys(process.env).some(key=>!ALLOWED.has(key))||
   process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed'||
   process.env.FUSEKI_ISOLATION_URL!=='http://127.0.0.1:3041'||
   process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE!=='confirmed'||
   !['valid','mismatch','missing'].includes(process.env.DATASET_ADMIN_ORDINARY_MODE)){
  throw Error('Disposable ordinary-provider test process rejects inherited privilege');
}

const require=createRequire(import.meta.url);
const {createDelegatedDisposableDataset}=
  require('../../services/utils/atproto-dataset-admin-delegation.js');
const ticket=JSON.parse(Buffer.from(
  process.env.DATASET_ADMIN_ORDINARY_TICKET||'','base64').toString('utf8'));
const mode=process.env.DATASET_ADMIN_ORDINARY_MODE;
const dataset=mode==='mismatch'?'claimtest-999999999999':ticket.claim.dataset;
try{
  const result=await createDelegatedDisposableDataset({
    dataset,ticket:mode==='missing'?undefined:ticket
  });
  assert.equal(mode,'valid','Mismatched or missing ticket must not succeed');
  assert.equal(result.created,true);
  assert.equal(result.idempotent,true);
  assert.equal(result.strategy,'isolated_claim_admin_disposable');
  console.log('ORDINARY_PROVIDER_DATASET_DELEGATION '+JSON.stringify({
    mode,restrictedOrdinaryProcess:true,
    adminSecretAvailable:false,signatureIssuerAvailable:false,
    postgresAdministratorAvailable:false,
    signedClaimAccepted:true,productionStorageReleased:false
  }));
}catch(error){
  if(mode==='valid')throw error;
  assert.equal(error.code,'DATASET_ADMIN_DELEGATION_CLAIM_INVALID');
  console.log('ORDINARY_PROVIDER_DATASET_DELEGATION '+JSON.stringify({
    mode,restrictedOrdinaryProcess:true,invalidClaimDenied:true,
    productionStorageReleased:false
  }));
}
