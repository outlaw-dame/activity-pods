'use strict';

jest.mock('pg', () => ({
  Pool: jest.fn()
}));
const { Pool } = require('pg');
const {
  getProviderAtprotoPgAuthority,
  closeProviderAtprotoPgAuthority
} = require('../utils/atproto-canonical-pg-authority');

const restrictedRole = {
  rolsuper:false,rolcreatedb:false,rolcreaterole:false,
  rolreplication:false,rolbypassrls:false,rolcanlogin:true,
  schema_create:false,identity_read:true,consent_read:true,
  identity_insert:false,consent_insert:false,consent_update:false,
  consent_delete:false,consent_truncate:false,revoke_execute:true
};

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
  process.env.APODS_ATPROTO_AUTHORITY_PG_URL='postgres://role:secret@127.0.0.1:5548/atproto_signed_repo_proof_test';
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
  release({rows:[restrictedRole],rowCount:1});
  const values=await Promise.all(all);
  expect(new Set(values).size).toBe(1);
  expect(pool.query).toHaveBeenCalledTimes(1);
  await closeProviderAtprotoPgAuthority();
  expect(pool.end).toHaveBeenCalledTimes(1);
});
test('failed initialization cleans sockets and permits safe retry',async()=>{
  const bad={query:jest.fn(async()=>{throw new Error('test transport loss')}),
    end:jest.fn(async()=>undefined)};
  const good={query:jest.fn(async()=>({rows:[restrictedRole],rowCount:1})),
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

test('role validation rejects privileged importer or schema-owner credentials',async()=>{
  const {assertRestrictedPgAuthorityLogin}=require('../utils/atproto-canonical-pg-authority');
  for(const violation of [
    {rolsuper:true},{identity_insert:true},{consent_update:true},
    {schema_create:true},{revoke_execute:false},{identity_read:false}
  ]){
    await expect(assertRestrictedPgAuthorityLogin({
      query:async()=>({rowCount:1,rows:[{...restrictedRole,...violation}]})
    })).rejects.toMatchObject({code:'ATPROTO_PG_AUTHORITY_PRIVILEGES_UNSAFE'});
  }
  await expect(assertRestrictedPgAuthorityLogin({
    query:async()=>({rowCount:1,rows:[restrictedRole]})
  })).resolves.toBe(true);
});
test('disposable authority cannot connect to an arbitrary host',async()=>{
  process.env.APODS_ATPROTO_AUTHORITY_PG_URL='postgres://role:secret@remote.example.test/production';
  await expect(getProviderAtprotoPgAuthority())
    .rejects.toMatchObject({code:'ATPROTO_PG_AUTHORITY_DSN_UNTRUSTED'});
  expect(Pool).not.toHaveBeenCalled();
});
