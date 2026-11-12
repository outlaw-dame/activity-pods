'use strict';
jest.mock('ioredis',()=>jest.fn());
const Redis=require('ioredis');
const crypto=require('node:crypto');
const {
  issueDistributedOwnerProof,verifyDistributedOwnerProof,
  closeDistributedSaiOwnerProof,getDistributedSaiOwnerProof,assertFixture
}=require('../services/utils/atproto-sai-distributed-owner-runtime');
const {
  authorizeOwnerSaiActionForBroker,hasAuthorizedOwnerParentForBroker
}=require('../services/utils/atproto-sai-owner-context');

const owner='https://paper.example.test/alice';
const app='https://paper.example.test/client';
const markerKeys=[
  'NODE_ENV','APODS_ATPROTO_TEST_STORAGE_DISPOSABLE',
  'APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED',
  'APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED',
  'APODS_SAI_DISTRIBUTED_OWNER_REDIS_URL',
  'APODS_SAI_DISTRIBUTED_OWNER_HMAC_KEY'
];
const original=Object.fromEntries(markerKeys.map(k=>[k,process.env[k]]));
let liveStore;
beforeEach(async()=>{
  await closeDistributedSaiOwnerProof();
  Redis.mockReset();
  liveStore=new Map();
  Redis.mockImplementation(()=>({
    connect:jest.fn(async()=>undefined),
    disconnect:jest.fn(),
    async set(key,value,mode,ttl,nx){
      expect(mode).toBe('PX');expect(nx).toBe('NX');
      expect(ttl).toBeLessThanOrEqual(120000);
      if(liveStore.has(key))return null;
      liveStore.set(key,value);return 'OK';
    },
    async get(key){return liveStore.get(key)||null},
    async del(key){return liveStore.delete(key)?1:0}
  }));
  process.env.NODE_ENV='test';
  process.env.APODS_ATPROTO_TEST_STORAGE_DISPOSABLE='confirmed';
  process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED='true';
  process.env.APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED='true';
  process.env.APODS_SAI_DISTRIBUTED_OWNER_REDIS_URL='redis://127.0.0.1:6379/15';
  process.env.APODS_SAI_DISTRIBUTED_OWNER_HMAC_KEY=
    crypto.randomBytes(32).toString('base64url');
});
afterEach(async()=>{await closeDistributedSaiOwnerProof()});
afterAll(()=>{
  for(const key of markerKeys){
    if(original[key]===undefined)delete process.env[key];
    else process.env[key]=original[key];
  }
});
function parent(requestID='test-request'){
  return {requestID,meta:{webId:owner}};
}
test('test-only runtime uses one shared connection even under simultaneous first requests',async()=>{
  const proof=await Promise.all(Array.from({length:20},
    ()=>getDistributedSaiOwnerProof()));
  expect(new Set(proof).size).toBe(1);
  expect(Redis).toHaveBeenCalledTimes(1);
  expect(proof[0]).toHaveProperty('issue');
});
test('nested broker contexts prove exact owner and request through Redis',async()=>{
  const ctx=parent(),release=await authorizeOwnerSaiActionForBroker(ctx,{owner,app});
  const nested={requestID:ctx.requestID,meta:{
    webId:'system',apodsNativeSaiOwnerProof:ctx.meta.apodsNativeSaiOwnerProof
  }};
  expect(await hasAuthorizedOwnerParentForBroker(nested,{owner,app})).toBe(true);
  expect(await hasAuthorizedOwnerParentForBroker({
    ...nested,requestID:'another-request'
  },{owner,app})).toBe(false);
  expect(await hasAuthorizedOwnerParentForBroker(nested,{
    owner,app:'https://paper.example.test/other'
  })).toBe(false);
  await release();
  expect(await hasAuthorizedOwnerParentForBroker(nested,{owner,app})).toBe(false);
});
test('production and untrusted Redis hosts fail before creating a connection',async()=>{
  process.env.NODE_ENV='production';
  expect(()=>assertFixture()).toThrow(/unavailable/);
  await expect(issueDistributedOwnerProof(parent(),{owner,app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_NOT_RELEASED'});
  process.env.NODE_ENV='test';
  process.env.APODS_SAI_DISTRIBUTED_OWNER_REDIS_URL='redis://prod.db.example/15';
  await expect(issueDistributedOwnerProof(parent(),{owner,app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_CONFIG_INVALID'});
  expect(Redis).not.toHaveBeenCalled();
});
test('owner context cannot issue proof to app impersonation',async()=>{
  const ctx=parent();ctx.meta.impersonatedUser=owner;
  await expect(authorizeOwnerSaiActionForBroker(ctx,{owner,app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_ISSUER_NOT_OWNER'});
});
test('disabled runtime calls existing local bounded proof, no Redis connection',async()=>{
  delete process.env.APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED;
  const ctx=parent('local-request');
  const release=await authorizeOwnerSaiActionForBroker(ctx,{owner,app});
  const nested={requestID:ctx.requestID,meta:{
    webId:'system',apodsNativeSaiOwnerProof:ctx.meta.apodsNativeSaiOwnerProof
  }};
  expect(await hasAuthorizedOwnerParentForBroker(nested,{owner,app})).toBe(true);
  await release();
  expect(await hasAuthorizedOwnerParentForBroker(nested,{owner,app})).toBe(false);
  expect(Redis).not.toHaveBeenCalled();
});
test('redis availability loss aborts nested proof, never falls back to local',async()=>{
  const ctx=parent('redis-outage');
  const release=await issueDistributedOwnerProof(ctx,{owner,app});
  const store=Redis.mock.results[0].value;
  store.get=jest.fn(async()=>{throw new Error('network partition')});
  const nested={requestID:ctx.requestID,meta:{
    webId:'system',apodsNativeSaiOwnerProof:ctx.meta.apodsNativeSaiOwnerProof
  }};
  await expect(verifyDistributedOwnerProof(nested,{owner,app}))
    .rejects.toMatchObject({code:'SAI_DISTRIBUTED_STORE_UNAVAILABLE'});
  await release();
});
