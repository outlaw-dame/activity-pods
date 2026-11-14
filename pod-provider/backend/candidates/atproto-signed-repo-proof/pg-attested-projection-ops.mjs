/**
 * NONACTIVATED PG18 projection operations under independent-attestation ACK.
 * No fallback to legacy ack_verified_projection, even if Jena is unavailable.
 * No network calls are made while a SQL transaction is held open.
 */
import {assertRestrictedProjectionWorkerLogin} from './pg-projection-worker-role.mjs';
const ENABLED=()=>process.env.NODE_ENV==='test'&&
  process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
  process.env.ATPROTO_PROJECTION_ROLE_TEST_DISPOSABLE==='confirmed'&&
  process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE==='confirmed';
const EPOCH=/^[1-9][0-9]{0,18}$/u;
function deny(){
  const e=new Error('Independent attestation SQL projection not released');
  e.code='PROJECTION_ATTESTED_ACK_NOT_RELEASED';throw e;
}
function canonical(value){
  if(typeof value!=='string'||value.length>2048)return false;
  try{const url=new URL(value);return url.protocol==='https:'&&
    url.href===value&&!url.search&&!url.hash&&!url.username&&!url.password;}
  catch{return false;}
}
export async function createAttestedPgProjectionOperations({
  pool,appUri,grantUri,consentRevision,fixtureOnly=false
}={}){
  if(fixtureOnly!==true||!ENABLED()||!canonical(appUri)||
     !canonical(grantUri)||typeof pool?.query!=='function'||
     typeof consentRevision!=='string'||!EPOCH.test(consentRevision)||
     BigInt(consentRevision)>9223372036854775807n)deny();
  await assertRestrictedProjectionWorkerLogin(pool,{attestedOnly:true});
  const checked=()=>{if(!ENABLED())deny();};
  return Object.freeze({
    async claim({accountId,did,owner,leaseSeconds,maxAttempts}){
      checked();
      return pool.query('SELECT * FROM paper_atproto_repo_proof.claim_verified_projection('+
        '$1,$2,$3::uuid,$4::integer,$5::integer,$6,$7,$8::bigint)',[
        accountId,did,owner,leaseSeconds,maxAttempts,appUri,grantUri,consentRevision
      ]);
    },
    async ack({accountId,did,claimed,proof}){
      checked();
      return pool.query('SELECT * FROM paper_atproto_repo_proof.ack_attested_projection('+
        '$1,$2,$3::uuid,$4::bigint,$5,$6,$7,$8::bigint,$9,$10,$11::bigint)',[
        accountId,did,claimed.lease_owner,String(claimed.lease_epoch),
        proof.commitCid,proof.rootCid,proof.rev,String(claimed.generation),
        appUri,grantUri,consentRevision
      ]);
    },
    async finishFailure({accountId,did,claimed,state,delay,code}){
      checked();
      if(!['pending','blocked'].includes(state)||!Number.isFinite(delay)||
         delay<0||delay>300||!/^[A-Z][A-Z0-9_]{2,79}$/u.test(code||''))deny();
      return pool.query('SELECT * FROM paper_atproto_repo_proof.release_failed_projection('+
        '$1,$2,$3::uuid,$4::bigint,$5,$6::double precision,$7)',[
        accountId,did,claimed.lease_owner,String(claimed.lease_epoch),
        state,delay,code
      ]);
    },
    async blockExhausted({accountId,did,maxAttempts}){
      checked();
      return pool.query('SELECT paper_atproto_repo_proof.block_exhausted_projection('+
        '$1,$2,$3::integer)',[accountId,did,maxAttempts]);
    }
  });
}
