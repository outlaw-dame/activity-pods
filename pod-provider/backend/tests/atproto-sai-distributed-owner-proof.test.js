'use strict';
const crypto=require('node:crypto');
const {
  createSaiDistributedOwnerProof,PROOF_KEY,MAX_IN_FLIGHT
}=require('../services/utils/atproto-sai-distributed-owner-proof');

const owner='https://paper.example.test/users/alice';
const app='https://paper.example.test/clients/paper';
const secret=crypto.randomBytes(32).toString('base64url');
function context(requestID='client-request-1') {
  return {requestID,meta:{webId:owner}};
}
function redisAt(clock){
  const entries=new Map();
  let unavailable=false;
  return {
    entries,
    setUnavailable(value){unavailable=value},
    async set(key,value,ttlMode,ttl,onlyAbsent){
      if(unavailable)throw Error('unreachable redis');
      expect(ttlMode).toBe('PX');expect(onlyAbsent).toBe('NX');
      if(entries.has(key)&&entries.get(key).until>clock.now)return null;
      entries.set(key,{value,until:clock.now+ttl});return 'OK';
    },
    async get(key){
      if(unavailable)throw Error('unreachable redis');
      const saved=entries.get(key);if(!saved||saved.until<=clock.now)return null;
      return saved.value;
    },
    async del(key){
      if(unavailable)throw Error('unreachable redis');
      return entries.delete(key)?1:0;
    }
  };
}

test('independent replica verifies signed owner proof but does not trust metadata alone',async()=>{
  const clock={now:0},redis=redisAt(clock);
  const issuer=createSaiDistributedOwnerProof({
    redis,secret,clock:()=>clock.now
  });
  const remote=createSaiDistributedOwnerProof({
    redis,secret,clock:()=>clock.now
  });
  const parent=context();const release=await issuer.issue(parent,{owner,app});
  expect(issuer.inFlight()).toBe(1);expect(remote.inFlight()).toBe(0);
  const nested={requestID:parent.requestID,meta:{webId:'system',[PROOF_KEY]:parent.meta[PROOF_KEY]}};
  expect(await remote.verify(nested,{owner,app})).toBe(true);
  expect(await remote.verify({...nested,requestID:'not-the-parent'}, {owner,app})).toBe(false);
  expect(await remote.verify(nested,{owner:'https://paper.example.test/users/bob',app})).toBe(false);
  expect(await remote.verify(nested,{owner,app:'https://paper.example.test/other'})).toBe(false);
  expect(await remote.verify({requestID:parent.requestID,meta:{webId:'system'}},{owner,app})).toBe(false);
  await release();
  expect(issuer.inFlight()).toBe(0);
  expect(parent.meta[PROOF_KEY]).toBeUndefined();
  expect(await remote.verify(nested,{owner,app})).toBe(false);
  await release();expect(issuer.inFlight()).toBe(0);
});

test('proof is denied after Redis TTL and cannot be forged by alternate signer',async()=>{
  const clock={now:1000},redis=redisAt(clock);
  const issuer=createSaiDistributedOwnerProof({redis,secret,ttlMs:5000,clock:()=>clock.now});
  const verifier=createSaiDistributedOwnerProof({redis,secret,clock:()=>clock.now});
  const alternate=createSaiDistributedOwnerProof({
    redis,secret:crypto.randomBytes(32).toString('base64url'),clock:()=>clock.now
  });
  const parent=context('request-ttl'),release=await issuer.issue(parent,{owner,app});
  const remote={requestID:parent.requestID,meta:{[PROOF_KEY]:parent.meta[PROOF_KEY]}};
  expect(await verifier.verify(remote,{owner,app})).toBe(true);
  expect(await alternate.verify(remote,{owner,app})).toBe(false);
  clock.now=6000;
  expect(await verifier.verify(remote,{owner,app})).toBe(false);
  await release();
});

test('untrusted apps cannot mint owner proof and a failed Redis write frees its reservation',async()=>{
  const clock={now:1000},redis=redisAt(clock);
  const issuer=createSaiDistributedOwnerProof({redis,secret,maxInFlight:1,clock:()=>clock.now});
  await expect(issuer.issue({requestID:'abc',meta:{webId:'https://attacker.example.test'}},{owner,app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_ISSUER_NOT_OWNER'});
  await expect(issuer.issue({requestID:'abc',meta:{webId:owner,impersonatedUser:owner}},{owner,app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_ISSUER_NOT_OWNER'});
  redis.setUnavailable(true);
  await expect(issuer.issue(context('failed'),{owner,app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_STORE_UNAVAILABLE'});
  expect(issuer.inFlight()).toBe(0);
  redis.setUnavailable(false);
  const parent=context('good');
  const release=await issuer.issue(parent,{owner,app});
  await expect(issuer.issue(context('overload'),{owner,app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_BUSY'});
  expect(issuer.inFlight()).toBe(1);
  await release();
});

test('Redis outage fails closed in remote verification without leaking context',async()=>{
  const clock={now:0},redis=redisAt(clock);
  const issuer=createSaiDistributedOwnerProof({redis,secret,clock:()=>clock.now});
  const parent=context('fail-closed');
  const release=await issuer.issue(parent,{owner,app});
  const remote={requestID:parent.requestID,meta:{[PROOF_KEY]:parent.meta[PROOF_KEY]}};
  redis.setUnavailable(true);
  await expect(issuer.verify(remote,{owner,app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_STORE_UNAVAILABLE'});
  redis.setUnavailable(false);
  await release();
});

test('inherited metadata with a malformed token never queries Redis',async()=>{
  const clock={now:0},redis=redisAt(clock);
  const verifier=createSaiDistributedOwnerProof({redis,secret});
  for(const token of ['','evil','a'.repeat(100),null,{},'@'.repeat(43)]){
    const ctx={requestID:'abc',meta:{[PROOF_KEY]:token}};
    expect(await verifier.verify(ctx,{owner,app})).toBe(false);
  }
  expect(redis.entries.size).toBe(0);
});

test('rejects weak secrets, malformed scopes and unsafe configuration',async()=>{
  const clock={now:0},redis=redisAt(clock);
  expect(()=>createSaiDistributedOwnerProof({redis,secret:'short'})).toThrow();
  expect(()=>createSaiDistributedOwnerProof({redis,secret,maxInFlight:MAX_IN_FLIGHT+1})).toThrow();
  expect(()=>createSaiDistributedOwnerProof({redis,secret,ttlMs:121000})).toThrow();
  const issuer=createSaiDistributedOwnerProof({redis,secret});
  await expect(issuer.issue(context(),{owner:'http://paper.example.test/alice',app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_SCOPE_INVALID'});
  await expect(issuer.issue(context(),{owner,app:app+'?access_token=private'}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_SCOPE_INVALID'});
});
