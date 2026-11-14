/**
 * NONACTIVATED PostgreSQL-only adapter for the existing cross-store
 * recovery state machine. No generic SQL UPDATE and no pool-per-Pod.
 * The independently verified protected Jena readback is still REQUIRED
 * before ack(); SQL functions cannot attest remote RDF contents.
 */
import {assertRestrictedProjectionWorkerLogin}
  from './pg-projection-worker-role.mjs';
const EPOCH=/^[1-9][0-9]{0,18}$/u;
function deny(){
  const e=new Error('Restricted projection worker not released');
  e.code='PROJECTION_PG_ROLE_NOT_RELEASED';throw e;
}
function canonical(s){
  if(typeof s!=='string'||s.length>2048)return false;
  try{const u=new URL(s);
    return u.protocol==='https:'&&u.href===s&&!!u.hostname&&
      !u.username&&!u.password&&!u.search&&!u.hash;
  }catch{return false;}
}
function enabled(){
  return process.env.NODE_ENV==='test'&&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_PROJECTION_ROLE_TEST_DISPOSABLE==='confirmed';
}
export async function createRestrictedPgProjectionOperations({
  pool,appUri,grantUri,consentRevision,fixtureOnly=false
}={}){
  if(fixtureOnly!==true||!enabled())deny();
  if(typeof pool?.query!=='function'||!canonical(appUri)||
     !canonical(grantUri)||typeof consentRevision!=='string'||
     !EPOCH.test(consentRevision)||BigInt(consentRevision)>9223372036854775807n){
    deny();
  }
  await assertRestrictedProjectionWorkerLogin(pool);
  const current=()=>{if(!enabled())deny();};
  const q=(sql,args)=>pool.query(sql,args);
  return Object.freeze({
    async claim({accountId,did,owner,leaseSeconds,maxAttempts}){
      current();
      return q(
        'SELECT * FROM paper_atproto_repo_proof.claim_verified_projection('+
        '$1,$2,$3::uuid,$4::integer,$5::integer,$6,$7,$8::bigint)',
        [accountId,did,owner,leaseSeconds,maxAttempts,
          appUri,grantUri,consentRevision]
      );
    },
    async ack({accountId,did,claimed,proof}){
      current();
      return q(
        'SELECT * FROM paper_atproto_repo_proof.ack_verified_projection('+
        '$1,$2,$3::uuid,$4::bigint,$5,$6,$7,$8::bigint,$9,$10,$11::bigint)',
        [accountId,did,claimed.lease_owner,String(claimed.lease_epoch),
          proof.commitCid,proof.rootCid,proof.rev,claimed.generation,
          appUri,grantUri,consentRevision]
      );
    },
    async finishFailure({accountId,did,claimed,state,delay,code}){
      current();
      return q(
        'SELECT * FROM paper_atproto_repo_proof.release_failed_projection('+
        '$1,$2,$3::uuid,$4::bigint,$5,$6::double precision,$7)',
        [accountId,did,claimed.lease_owner,String(claimed.lease_epoch),
          state,delay,code]
      );
    },
    async blockExhausted({accountId,did,maxAttempts}){
      current();
      return q(
        'SELECT paper_atproto_repo_proof.block_exhausted_projection('+
        '$1,$2,$3::integer) AS count',
        [accountId,did,maxAttempts]
      );
    }
  });
}
