'use strict';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPgLeaseTicketIssuer } from './pg-lease-ticket.mjs';

const originalPg = process.env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED;
const originalMarker = process.env.ATPROTO_REPO_PROOF_DISPOSABLE;
const originalNodeEnv = process.env.NODE_ENV;
const owner='https://paper.example.test/alice';
const app='https://app.example.test/paper';
const grant=owner+'/data/grants/1';
const did='did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
const cid='bafyre'+'a'.repeat(53);
const rev='2222222222222';
const leaseOwner='5bd4a10a-e905-40ad-8ae3-b3ae344fb9fe';
const claim={accountId:owner,did,leaseOwner,leaseEpoch:'1'};
const row={
  account_id:owner,did,head_cid:cid,root_cid:cid,rev,
  generation:1,state:'leased',lease_owner:leaseOwner,
  lease_epoch:'1',lease_live:true
};
function dependencies(canonical) {
  return {
    pool:{query:async()=>({rowCount:1,rows:[row]})},
    tickets:{issue:()=> 'disposable-ticket'},
    verifySignedHead:async()=>({
      verified:true,accountId:owner,did,commitCid:cid,rootCid:cid,
      rev,outboxStatus:'pending'
    }),
    verifyCurrentSaiConsent:async()=>true,
    ...(canonical===undefined?{}:{verifyCanonicalPgConsent:canonical}),
    fixtureOnly:true
  };
}
test('signed repository tickets fail closed without canonical PostgreSQL permission source',async()=>{
  try{
    process.env.NODE_ENV='test';
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE='confirmed';
    process.env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED='true';
    assert.throws(()=>createPgLeaseTicketIssuer(dependencies()),
      e=>e.code==='PG_TICKET_CANONICAL_AUTHORITY_REQUIRED');
    const denied=createPgLeaseTicketIssuer(dependencies(async()=>false));
    await assert.rejects(
      denied.issueForLease({claim,appUri:app,grantUri:grant,consentRevision:'1'}),
      e=>e.code==='PG_TICKET_CANONICAL_PERMISSION_DENIED'
    );
    const verified=[];
    const allowed=createPgLeaseTicketIssuer(dependencies(async scope=>{
      verified.push(scope);
      return scope.accountId===owner && scope.did===did &&
        scope.appUri===app && scope.grantUri===grant && scope.consentRevision==='1';
    }));
    const ticket=await allowed.issueForLease({
      claim,appUri:app,grantUri:grant,consentRevision:'1'
    });
    assert.equal(ticket.ticket,'disposable-ticket');
    assert.equal(verified.length,1);
    assert.deepEqual(verified[0],{
      accountId:owner,did,appUri:app,grantUri:grant,consentRevision:'1'
    });
  }finally{
    if(originalPg===undefined)delete process.env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED;
    else process.env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED=originalPg;
    if(originalMarker===undefined)delete process.env.ATPROTO_REPO_PROOF_DISPOSABLE;
    else process.env.ATPROTO_REPO_PROOF_DISPOSABLE=originalMarker;
    if(originalNodeEnv===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=originalNodeEnv;
  }
});
