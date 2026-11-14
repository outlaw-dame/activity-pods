'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const policy = require('../utils/atproto-managed-repo-proof-policy');

const webId = 'https://paper.example.org/users/alice';
const did = 'did:plc:abcdefghijklmnopqrstuvwx';
const pds = 'https://pds.paper.example.org';
const handle = 'alice.paper.example.org';
const rootCid = 'bafyre' + 'b'.repeat(53);
const commitCid = 'bafyre' + 'a'.repeat(53);
const rev = '3jzfcijpj2z2a';
const proof = { verified: true, accountId: webId, did, pdsOrigin: pds,
  rootCid, commitCid, rev, outboxStatus: 'pending' };
const capability = 'candidate_' + 'x'.repeat(48);

class MoleculerError extends Error {
  constructor(message, code, type) { super(message); this.code = code; this.type = type; }
}
function service() {
  const code = fs.readFileSync(path.resolve(__dirname,
    '../services/core/atproto-provisioning.js'), 'utf8');
  const m = { exports: {} };
  const factory = vm.runInNewContext('(function(require,module){\n' + code + '\n})',
    { process, URL, Buffer, console, setTimeout, clearTimeout });
  factory(name => {
    if (name === 'crypto') return crypto;
    if (name === 'moleculer') return { Errors: { MoleculerError } };
    if (name === '../../utils/atproto-managed-repo-proof-policy') return policy;
    throw Error('Unexpected dependency: ' + name);
  }, m);
  return { ...m.exports.methods, actions: m.exports.actions,
    settings: { repoBootstrapRootCid: 'bafyreigenesisplaceholder', repoBootstrapRev: '0' },
    _resolveLocalPdsUrl: () => pds, _signingCallMeta: () => ({}) };
}
async function env(values, fn) {
  const original = Object.fromEntries(Object.keys(values).map(k => [k, process.env[k]]));
  try {
    for (const [k,v] of Object.entries(values)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    return await fn();
  } finally {
    for (const [k,v] of Object.entries(original)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}
const enabled = { NODE_ENV:'test', ATPROTO_REPO_PROOF_DISPOSABLE:'confirmed',
  APODS_ATPROTO_REQUIRE_VERIFIED_REPO:'true',
  APODS_ATPROTO_MANAGED_REPO_CAPABILITY:capability };
function binding() {
  return { webId, activityPubActorId:webId, atprotoDid:did,
    atprotoHandle:handle, atprotoSource:'local', atprotoManaged:true,
    atprotoPdsUrl:pds, repoInitialized:true, repoRootCid:rootCid, repoRev:rev,
    atSigningKeyRef:'commit-ref', atRotationKeyRef:'rotation-ref' };
}
test('structured proof is scoped and strips unknown fields', () => {
  const clean = policy.requireVerifiedManagedRepoProof({
    canonicalAccountId:webId, did, expectedPdsOrigin:pds,
    proof:{ ...proof, extraneous:'not-persisted' }
  });
  assert.equal(clean.extraneous, undefined);
  assert.equal(Object.isFrozen(clean), true);
  for(const bad of [
    null, { ...proof, verified:false }, { ...proof, did:'did:plc:'+'z'.repeat(24) },
    { ...proof, pdsOrigin:'https://elsewhere.example.org' },
    { ...proof, commitCid:'placeholder' }, { ...proof, rev:'0' },
    { ...proof, outboxStatus:'blocked' }
  ]) assert.throws(() => policy.requireVerifiedManagedRepoProof({
    canonicalAccountId:webId, did, expectedPdsOrigin:pds, proof:bad
  }), e => e.code === 'ATPROTO_REPO_PROOF_INVALID');
});
test('production never permits disposable repository bridge', async () => {
  await env({...enabled, NODE_ENV:'production'}, async () => {
    let calls=0; const ctx={call:async()=>{calls++;}};
    await assert.rejects(service().initializeRepoState(ctx,
      {canonicalAccountId:webId,did,handle}), e=>e.type==='ATPROTO_REPO_PROOF_UNAVAILABLE');
    assert.equal(calls,0);
    // A caller invoking the Moleculer service directly must not create a
    // key or PLC genesis while the public signup release fuse is closed.
    await assert.rejects(service().actions.provisionForAccount.handler({
      params: { canonicalAccountId:webId, webId: webId, didMethod:'plc' },
      call: async () => { calls++; throw Error('identity mutation attempted'); }
    }), e => e.type === 'ATPROTO_PDS_REPOSITORY_NOT_READY' && e.code === 503);
    assert.equal(calls,0);
  });
});
test('missing provider capability refuses before binding write', async () => {
  await env({...enabled, APODS_ATPROTO_MANAGED_REPO_CAPABILITY:undefined}, async () => {
    let calls=0; const ctx={call:async()=>{calls++;}};
    await assert.rejects(service().initializeRepoState(ctx,
      {canonicalAccountId:webId,did,handle}), e=>e.type==='ATPROTO_REPO_PROOF_UNAVAILABLE');
    assert.equal(calls,0);
  });
});
test('bound signed repository is verified, sanitized and rechecked after write', async () => {
  await env(enabled, async () => {
    let persisted, checks=0;
    const ctx={call:async (action,params,options)=>{
      if(action==='atproto-managed-repository.bootstrapAndVerify') {
        assert.equal(options.meta.providerRepoCapability,capability);
        return {...proof,extra:'not-persisted'};
      }
      if(action==='identitybindings.upsertRepoBootstrap'){persisted=params;return {};}
      if(action==='atproto-managed-repository.verifyReady'){checks++;return proof;}
      if(action==='signing.getAtprotoPublicKey') return {};
      throw Error('Unexpected '+action);
    }};
    const methods=service();
    const state=await methods.initializeRepoState(ctx,{canonicalAccountId:webId,did,handle});
    assert.equal(state.rootCid,rootCid);
    assert.equal(persisted.canonicalAccountId, webId);
    assert.equal(persisted.did, did);
    assert.equal(persisted.handle, handle);
    assert.equal(persisted.repoInitialized, true);
    assert.equal(persisted.rootCid, rootCid);
    assert.equal(persisted.rev, rev);
    assert.equal(Object.keys(persisted).length, 6, 'no unverified fields persisted');
    await methods.verifyProvisionedState(ctx,{canonicalAccountId:webId,binding:binding(),didMethod:'plc'});
    assert.equal(checks,1);
    await assert.rejects(methods.verifyProvisionedState(ctx,{
      canonicalAccountId:webId,binding:{...binding(),repoRootCid:commitCid},didMethod:'plc'
    }),e=>e.type==='ATPROTO_REPO_BINDING_MISMATCH');
  });
});
test('untrusted signed repository response does not write a ready binding', async () => {
  await env(enabled, async () => {
    for (const bogus of [null, { ...proof, verified:false },
      { ...proof, pdsOrigin:'https://other.example.org' },
      { ...proof, rootCid:'bafyreigenesisplaceholder' }]) {
      let writes = 0;
      const request={call:async action => {
        if(action==='atproto-managed-repository.bootstrapAndVerify') return bogus;
        if(action==='identitybindings.upsertRepoBootstrap') writes++;
        throw Error('unexpected action');
      }};
      await assert.rejects(service().initializeRepoState(request,
        {canonicalAccountId:webId,did,handle}),
        e => e.type==='ATPROTO_REPO_PROOF_INVALID');
      assert.equal(writes,0,'untrusted proof must not become signed repo state');
    }
  });
});
test('ordinary development bootstrap remains explicitly fixture-only', async () => {
  await env({NODE_ENV:'test',APODS_ATPROTO_REQUIRE_VERIFIED_REPO:undefined},async()=>{
    const state=await service().initializeRepoState({
      call:async(action)=>assert.equal(action,'identitybindings.upsertRepoBootstrap')
    },{canonicalAccountId:webId,did,handle});
    assert.equal(state.fixtureOnly,true);
  });
});
