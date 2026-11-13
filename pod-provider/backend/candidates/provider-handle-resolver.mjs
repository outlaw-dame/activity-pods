/**
 * Nonactivated new-signup AT Protocol handle authority for a provider-
 * controlled domain. Resolves the standard _atproto.<handle> DNS TXT entry.
 * No arbitrary-domain egress, unbounded cache, PDS trust, or HTTPS SSRF.
 *
 * AT Protocol permits the HTTPS well-known method too; this first rollout
 * supports newly provisioned handles on the provider's own DNS domain.
 * Custom / legacy handles are deliberately out of scope.
 */
import { resolveTxt as systemResolveTxt } from 'node:dns/promises';

const HANDLE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,61}$/;
const DID = /^did:plc:[a-z2-7]{24}$/;
function fail(code) {
  const error=new Error(code);
  error.code=code;
  throw error;
}
function validDomain(name,allowFixture) {
  if(typeof name!=='string'||!HANDLE.test(name)||
      (!allowFixture && /(?:^|\.)(?:test|example|invalid|localhost|local|internal)$/.test(name))) {
    fail('HANDLE_PROOF_INVALID_PROVIDER_DOMAIN');
  }
}
export function createProviderHandleResolver({
  providerDomain, lookupTxt=systemResolveTxt, timeoutMs=2500,
  allowFixture=false
}={}) {
  const fixture=allowFixture===true&&process.env.NODE_ENV!=='production';
  validDomain(providerDomain,fixture);
  if(typeof lookupTxt!=='function'||!Number.isInteger(timeoutMs)||
      timeoutMs<100||timeoutMs>5000) {
    fail('HANDLE_PROOF_INVALID_CONFIGURATION');
  }
  return async function resolveProviderHandle(handle,{signal}={}) {
    if(typeof handle!=='string'||!HANDLE.test(handle) ||
        !(handle===providerDomain||handle.endsWith('.'+providerDomain))) {
      fail('HANDLE_PROOF_OUTSIDE_PROVIDER_DOMAIN');
    }
    if(signal?.aborted) fail('HANDLE_PROOF_LOOKUP_UNAVAILABLE');
    const name='_atproto.'+handle;
    if(name.length>253) fail('HANDLE_PROOF_DNS_NAME_TOO_LONG');
    const controller=new AbortController();
    const onAbort=()=>controller.abort();
    if(signal) signal.addEventListener('abort',onAbort,{once:true});
    const timer=setTimeout(()=>controller.abort(),timeoutMs);
    timer.unref?.();
    let records;
    try {
      records=await Promise.race([
        Promise.resolve().then(()=>lookupTxt(name,{signal:controller.signal})),
        new Promise((_,reject)=>{
          controller.signal.addEventListener('abort',()=>{
            reject(Object.assign(new Error('DNS timeout'),{
              code:'HANDLE_PROOF_LOOKUP_UNAVAILABLE'
            }));
          },{once:true});
        })
      ]);
    } catch (_) {
      fail('HANDLE_PROOF_LOOKUP_UNAVAILABLE');
    } finally {
      clearTimeout(timer);
      if(signal) signal.removeEventListener('abort',onAbort);
      controller.abort();
    }
    // A hostile / buggy resolver result should not create unbounded memory,
    // or turn an ambiguous TXT set into a valid signed-up account.
    if(!Array.isArray(records)||records.length>32) fail('HANDLE_PROOF_INVALID_TXT');
    let result=null;
    let count=0;
    for(const fragments of records) {
      if(!Array.isArray(fragments)||fragments.length>20) fail('HANDLE_PROOF_INVALID_TXT');
      let size=0;
      for(const value of fragments) {
        if(typeof value!=='string'||value.length>1024) fail('HANDLE_PROOF_INVALID_TXT');
        size+=value.length;
        if(size>1024) fail('HANDLE_PROOF_INVALID_TXT');
      }
      const txt=fragments.join('');
      if(!txt.startsWith('did=')) continue;
      const did=txt.slice(4);
      if(!DID.test(did)) fail('HANDLE_PROOF_INVALID_TXT');
      count+=1;
      if(count>1 || result && result!==did) fail('HANDLE_PROOF_AMBIGUOUS');
      result=did;
    }
    if(result===null) fail('HANDLE_PROOF_NOT_FOUND');
    return result;
  };
}
