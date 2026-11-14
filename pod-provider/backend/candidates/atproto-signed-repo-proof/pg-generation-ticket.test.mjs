import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Pool } from 'pg';
import { createSignedRepoProofStore } from './store.mjs';
import { createSignedSingleRecordWriter } from './single-record-writer.mjs';
import { createPodOperationTicketAuthority } from './pod-operation-ticket.mjs';
import { createPgLeaseTicketIssuer } from './pg-lease-ticket.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)){
  throw Error('Signed generation ticket acceptance requires exact disposable PG18');
}
const pool=new Pool({
  connectionString:DSN,max:4,connectionTimeoutMillis:3000,
  idleTimeoutMillis:3000,allowExitOnIdle:true
});
const accountId='https://paper.example.org/users/ticket-record';
const did='did:plc:'+'t'.repeat(24);
const appUri='https://paper.example.org/apps/writer';
const grantUri=accountId+'/data/access-grants/approved';
const rejected=(promise,code)=>assert.rejects(promise,error=>error?.code===code);

test('provider projection ticket binds signed generation-2 parent and live PG/SAI lease',async t=>{
  const originalEnv=process.env.NODE_ENV;
  try{
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    )).rows[0].n,0);
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./schema.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./single-record-mutation.sql',import.meta.url)),'utf8'));
    const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{
      namedCurve:'secp256k1'
    });
    const keys={
      publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
      signer:async bytes=>crypto.sign('sha256',bytes,{
        key:privateKey,dsaEncoding:'ieee-p1363'
      })
    };
    const genesis=createSignedRepoProofStore({pool,fixtureOnly:true});
    const writer=createSignedSingleRecordWriter({
      pool,fixtureOnly:true,authorize:async()=>true
    });
    const first=await genesis.bootstrap({accountId,did,...keys});
    const ack=await pool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
      "state='applied',lease_epoch=1,applied_at=clock_timestamp() "+
      "WHERE account_id=$1 AND did=$2 AND head_cid=$3 RETURNING generation",
      [accountId,did,first.commitCid]
    );
    assert.equal(ack.rowCount,1);
    const successor=await writer.write({
      accountId,did,...keys,
      expectedCommitCid:first.commitCid,expectedRev:first.rev,
      action:'create',path:'app.bsky.feed.post/3jzm3xwpf342a',
      record:{$type:'app.bsky.feed.post',text:'Ticket generation 2',
        createdAt:'2026-11-13T00:00:00.000Z'}
    });
    assert.equal(successor.generation,2);
    assert.equal(successor.previousRootCid,first.rootCid);
    assert.equal(successor.previousCommitCid,first.commitCid);
    const owner=crypto.randomUUID();
    const lease=await pool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
      "state='leased',lease_owner=$2::uuid,lease_epoch=2,"+
      "lease_until=clock_timestamp()+interval '60 seconds',"+
      "attempt_count=1 WHERE account_id=$1 AND did=$3 AND "+
      "state='pending' AND generation=2 RETURNING head_cid,root_cid,rev,generation",
      [accountId,owner,did]
    );
    assert.equal(lease.rowCount,1);
    const claim={accountId,did,leaseOwner:owner,leaseEpoch:'2'};
    const authority=createPodOperationTicketAuthority({
      secret:crypto.randomBytes(32)
    });
    const currentProof=()=>writer.verify({
      accountId,did,publicKeyPem:keys.publicKeyPem
    });
    let allowed=true;
    let checked=0;
    const verifyCurrentSaiConsent=async input=>{
      checked++;
      assert.equal(input.accountId,accountId);
      assert.equal(input.grantUri,grantUri);
      assert.equal(input.appUri,appUri);
      assert.equal(input.consentRevision,'3');
      return allowed;
    };
    const makeIssuer=(verifySignedHead=currentProof,check=verifyCurrentSaiConsent)=>
      createPgLeaseTicketIssuer({
        pool,tickets:authority,fixtureOnly:true,
        verifySignedHead,verifyCurrentSaiConsent:check
      });
    const args={claim,appUri,grantUri,consentRevision:'3'};

    await t.test('current signed v3 successor and PG mutation audit produce exact scope',async()=>{
      const issued=await makeIssuer().issueForLease(args);
      assert.equal(issued.headCid,successor.commitCid);
      assert.equal(issued.scope.generation,2);
      assert.equal(issued.scope.previousRootCid,first.rootCid);
      assert.equal(issued.scope.previousRev,first.rev);
      const accepted=authority.verify(issued.ticket,issued.scope);
      assert.equal(accepted.generation,2);
      assert.equal(accepted.previousRootCid,first.rootCid);
      assert.equal(accepted.rev,successor.rev);
      for(const badScope of [
        {...issued.scope,generation:1,previousRootCid:null,previousRev:null},
        {...issued.scope,previousRootCid:successor.rootCid},
        {...issued.scope,previousRev:successor.rev},
        {...issued.scope,rootCid:first.rootCid},
        {...issued.scope,projectionFence:'3'}
      ]){
        assert.throws(()=>authority.verify(issued.ticket,badScope),
          e=>e.code==='POD_PROJECTION_PROVIDER_UNAUTHORIZED');
      }
      assert(checked>=1);
    });

    await t.test('legacy genesis-only and false predecessor proofs cannot mint a mutation ticket',async()=>{
      const intact=await currentProof();
      const {generation,previousRootCid,previousRev,previousCommitCid,...old}=intact;
      await rejected(makeIssuer(async()=>old).issueForLease(args),
        'PG_TICKET_SIGNED_HEAD_CHANGED');
      await rejected(makeIssuer(async()=>({
        ...intact,previousRootCid:successor.rootCid
      })).issueForLease(args),'PG_TICKET_SIGNED_HEAD_CHANGED');
      await rejected(makeIssuer(async()=>({
        ...intact,previousCommitCid:successor.commitCid
      })).issueForLease(args),'PG_TICKET_SIGNED_HEAD_CHANGED');
    });

    await t.test('revoked current SAI grant cannot mint a later generation ticket',async()=>{
      allowed=false;
      await rejected(makeIssuer().issueForLease(args),'PG_TICKET_SAI_NOT_CURRENT');
      allowed=true;
    });

    await t.test('a changed repository projection while checking SAI refuses ticket despite lease owner/epoch',async()=>{
      const altered='3333333333333';
      const badIssuer=makeIssuer(currentProof,async()=>{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET rev=$2 '+
          'WHERE account_id=$1 AND did=$3 AND state=$4',
          [accountId,altered,did,'leased']
        );
        return true;
      });
      try{
        await rejected(badIssuer.issueForLease(args),
          'PG_TICKET_SIGNED_HEAD_CHANGED');
      }finally{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET rev=$2 '+
          'WHERE account_id=$1 AND did=$3',
          [accountId,successor.rev,did]
        );
      }
      const recovered=await makeIssuer().issueForLease(args);
      assert.equal(recovered.scope.rev,successor.rev);
    });

    await t.test('stale lease and production mode are both fail closed',async()=>{
      await rejected(makeIssuer().issueForLease({
        ...args,claim:{...claim,leaseEpoch:'1'}
      }),'PG_TICKET_LEASE_STALE');
      process.env.NODE_ENV='production';
      await rejected(makeIssuer().issueForLease(args),'PG_TICKET_NOT_RELEASED');
      process.env.NODE_ENV='test';
    });
  }finally{
    if(originalEnv===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=originalEnv;
    try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');}
    finally{await pool.end();}
  }
});
