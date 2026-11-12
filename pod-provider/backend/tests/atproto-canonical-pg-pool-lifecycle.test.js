'use strict';

jest.mock('pg', () => ({
  Pool: jest.fn()
}));
const { Pool } = require('pg');
const {
  getProviderAtprotoPgAuthority,
  closeProviderAtprotoPgAuthority
} = require('../utils/atproto-canonical-pg-authority');

const keys = [
  'APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED',
  'APODS_ATPROTO_TEST_STORAGE_DISPOSABLE',
  'APODS_ATPROTO_AUTHORITY_PG_URL',
  'NODE_ENV'
];
const saved = Object.fromEntries(keys.map(k=>[k,process.env[k]]));
beforeEach(async()=>{
  await closeProviderAtprotoPgAuthority();
  Pool.mockReset();
  process.env.NODE_ENV='test';
  process.env.APODS_ATPROTO_TEST_STORAGE_DISPOSABLE='confirmed';
  process.env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED='true';
  process.env.APODS_ATPROTO_AUTHORITY_PG_URL='postgres://not-a-real-db/proof';
});
afterAll(async()=>{
  await closeProviderAtprotoPgAuthority();
  for(const key of keys) {
    if(saved[key]===undefined) delete process.env[key];
    else process.env[key]=saved[key];
  }
});
test('many simultaneous grants initialize exactly one bounded PostgreSQL pool',async()=>{
  let release;
  const gate = new Promise(resolve=>{release=resolve;});
  const pool={query:jest.fn(()=>gate),end:jest.fn(async()=>undefined)};
  Pool.mockImplementation(()=>pool);
  const all=Array.from({length:32},()=>getProviderAtprotoPgAuthority());
  expect(Pool).toHaveBeenCalledTimes(1);
  release({rows:[],rowCount:0});
  const values=await Promise.all(all);
  expect(new Set(values).size).toBe(1);
  expect(pool.query).toHaveBeenCalledTimes(1);
  await closeProviderAtprotoPgAuthority();
  expect(pool.end).toHaveBeenCalledTimes(1);
});
test('failed initialization cleans sockets and permits safe retry',async()=>{
  const bad={query:jest.fn(async()=>{throw new Error('test transport loss')}),
    end:jest.fn(async()=>undefined)};
  const good={query:jest.fn(async()=>({rows:[],rowCount:0})),
    end:jest.fn(async()=>undefined)};
  Pool.mockImplementationOnce(()=>bad).mockImplementationOnce(()=>good);
  await expect(getProviderAtprotoPgAuthority())
    .rejects.toMatchObject({code:'ATPROTO_PG_AUTHORITY_UNAVAILABLE'});
  expect(bad.end).toHaveBeenCalledTimes(1);
  const instance=await getProviderAtprotoPgAuthority();
  expect(instance.getIdentity).toEqual(expect.any(Function));
  await closeProviderAtprotoPgAuthority();
  expect(good.end).toHaveBeenCalledTimes(1);
});
test('production mode cannot create a runtime authority client',async()=>{
  process.env.NODE_ENV='production';
  await expect(getProviderAtprotoPgAuthority())
    .rejects.toMatchObject({code:'ATPROTO_PG_AUTHORITY_NOT_RELEASED'});
  expect(Pool).not.toHaveBeenCalled();
});
