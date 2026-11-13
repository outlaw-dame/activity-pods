import assert from 'node:assert/strict';
import { createProviderHandleResolver } from '../candidates/provider-handle-resolver.mjs';

const did='did:plc:abcdefghijklmnopqrstuvwx';
const otherDid='did:plc:bbbbbbbbbbbbbbbbbbbbbbbb';
let calls=0;
const resolver=createProviderHandleResolver({
  providerDomain:'pds.example',allowFixture:true,
  lookupTxt:async (name,{signal})=>{
    calls+=1;
    assert.equal(signal.aborted,false);
    assert.equal(name,'_atproto.alice.pds.example');
    return [['did=did:plc:abcdefghijklmnop','qrstuvwx'],['v=spf1 -all']];
  }
});
assert.equal(await resolver('alice.pds.example'),did);
assert.equal(calls,1);
await assert.rejects(resolver('alice.attacker.example'),e=>
  e.code==='HANDLE_PROOF_OUTSIDE_PROVIDER_DOMAIN');
await assert.rejects(resolver('pds.example.attacker.test'),e=>
  e.code==='HANDLE_PROOF_OUTSIDE_PROVIDER_DOMAIN');
assert.equal(calls,1,'unsafe names must not reach DNS');
const make=(response)=>createProviderHandleResolver({
  providerDomain:'pds.example',allowFixture:true,lookupTxt:async()=>response
});
await assert.rejects(make([['did='+did],['did='+otherDid]])('alice.pds.example'),
  e=>e.code==='HANDLE_PROOF_AMBIGUOUS');
await assert.rejects(make([['did='+did],['did='+did]])('alice.pds.example'),
  e=>e.code==='HANDLE_PROOF_AMBIGUOUS');
await assert.rejects(make([['did=did:plc:malformed']])('alice.pds.example'),
  e=>e.code==='HANDLE_PROOF_INVALID_TXT');
await assert.rejects(make([['random=record']])('alice.pds.example'),
  e=>e.code==='HANDLE_PROOF_NOT_FOUND');
await assert.rejects(make([[1]])('alice.pds.example'),
  e=>e.code==='HANDLE_PROOF_INVALID_TXT');
await assert.rejects(make(Array.from({length:33},()=>['not-did']))('alice.pds.example'),
  e=>e.code==='HANDLE_PROOF_INVALID_TXT');
await assert.rejects(
  createProviderHandleResolver({
    providerDomain:'pds.example',allowFixture:true,
    lookupTxt:async()=>{throw new Error('DNS unavailable');}
  })('alice.pds.example'),
  e=>e.code==='HANDLE_PROOF_LOOKUP_UNAVAILABLE'
);
const aborted=new AbortController();
aborted.abort();
await assert.rejects(resolver('alice.pds.example',{signal:aborted.signal}),
  e=>e.code==='HANDLE_PROOF_LOOKUP_UNAVAILABLE');
assert.equal(calls,1);
const timeout=createProviderHandleResolver({
  providerDomain:'pds.example',allowFixture:true,timeoutMs:100,
  lookupTxt:async()=>new Promise(()=>{})
});
const keepAlive=setTimeout(()=>{},200);
try {
  await assert.rejects(timeout('alice.pds.example'),e=>
    e.code==='HANDLE_PROOF_LOOKUP_UNAVAILABLE');
} finally {
  clearTimeout(keepAlive);
}
assert.throws(()=>createProviderHandleResolver({
  providerDomain:'evil.internal',allowFixture:false
}),e=>e.code==='HANDLE_PROOF_INVALID_PROVIDER_DOMAIN');
console.log('atproto_provider_scoped_dns_handle_authority_and_bounded_failure_passed');
