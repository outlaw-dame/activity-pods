'use strict';
// Dependency-free fail-closed gateway acceptance. Runs before system libvips.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { requireVerifiedManagedRepoProof } = require('../utils/atproto-repo-proof-policy');

const webId = 'https://paper.example/users/alice';
const did = 'did:plc:abcdefghijklmnopqrstuvwx';
const cid = 'bafyre' + 'a'.repeat(53);
const otherCid = 'bafyre' + 'b'.repeat(53);
const rev = '3jzfcijpj2z2a';
const validProof = Object.freeze({
  accountId: webId, did, commitCid: cid, rootCid: otherCid,
  rev, outboxStatus: 'pending', verified: true
});

function loadServiceWithoutDependencies() {
  const source = fs.readFileSync(path.resolve(__dirname, '../services/core/atproto-provisioning.js'), 'utf8');
  const moduleMock = { exports: {} };
  class MoleculerError extends Error {
    constructor(message, status, type) {
      super(message);
      this.code = status;
      this.type = type;
    }
  }
  const factory = vm.runInNewContext('(function(require,module){\n' + source + '\n})', {
    process, URL, Buffer, console, setTimeout, clearTimeout
  });
  factory(id => {
    if (id === 'crypto') return crypto;
    if (id === 'moleculer') return { Errors: { MoleculerError } };
    if (id === '../../utils/atproto-repo-proof-policy') {
      return require('../utils/atproto-repo-proof-policy');
    }
    throw new Error('Unexpected dependency: ' + id);
  }, moduleMock);
  return moduleMock.exports;
}

function runtime() {
  const service = loadServiceWithoutDependencies();
  return {
    ...service.methods,
    settings: { repoBootstrapRootCid: 'bafyreigenesisplaceholder', repoBootstrapRev: '0' },
    logger: { warn() {} }
  };
}

async function production(fn) {
  const prev = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prev;
  }
}

test('proof policy rejects fake, missing and account-mismatched evidence', () => {
  const checked = requireVerifiedManagedRepoProof({
    canonicalAccountId: webId, did, proof: validProof
  });
  assert.equal(checked.rootCid, otherCid);
  assert.equal(checked.rev, rev);
  assert.equal(checked.carBytes, undefined);
  for (const proof of [
    null,
    {},
    { ...validProof, verified: false },
    { ...validProof, accountId: 'https://paper.example/users/eve' },
    { ...validProof, did: 'did:plc:' + 'z'.repeat(24) },
    { ...validProof, rootCid: 'bafyreigenesisplaceholder' },
    { ...validProof, commitCid: 'not-a-cid' },
    { ...validProof, rev: '0' },
    { ...validProof, outboxStatus: 'skipped' }
  ]) {
    assert.throws(() => requireVerifiedManagedRepoProof({
      canonicalAccountId: webId, did, proof
    }), error => error.code === 'ATPROTO_REPO_PROOF_INVALID');
  }
  assert.throws(() => requireVerifiedManagedRepoProof({
    canonicalAccountId: webId, did: 'did:web:paper.example', proof: validProof
  }));
});

test('production refuses signup repo metadata when signed repo authority is absent', async () => {
  await production(async () => {
    const caller = runtime();
    let writes = 0;
    const ctx = { call: async action => {
      if (action === 'identitybindings.upsertRepoBootstrap') writes += 1;
      throw new Error('Service is not registered: ' + action);
    }};
    await assert.rejects(
      caller.initializeRepoState(ctx, { canonicalAccountId: webId, did, handle: 'alice.paper.example' }),
      error => error.type === 'ATPROTO_REPO_PROOF_UNAVAILABLE' && error.code === 503
    );
    assert.equal(writes, 0, 'must never write a fake initialized binding');
  });
});

test('production persists only sanitized independently verified native root/rev', async () => {
  await production(async () => {
    const caller = runtime();
    let binding;
    const ctx = { call: async (action, params) => {
      if (action === 'atproto-managed-repository.bootstrapAndVerify') return {
        ...validProof, privateKeyPem: 'MUST NOT PERSIST', carBytes: 'MUST NOT PERSIST'
      };
      if (action === 'identitybindings.upsertRepoBootstrap') {
        binding = params;
        return { ok: true };
      }
      throw new Error('Unexpected service: ' + action);
    }};
    const result = await caller.initializeRepoState(ctx, {
      canonicalAccountId: webId, did, handle: 'alice.paper.example'
    });
    assert.equal(result.rootCid, otherCid);
    assert.equal(result.rev, rev);
    assert.equal(binding.rootCid, otherCid);
    assert.equal(binding.rev, rev);
    assert.equal(binding.repoInitialized, true);
    assert.equal(binding.privateKeyPem, undefined);
    assert.equal(binding.carBytes, undefined);
    assert.equal(binding.rootCid.includes('placeholder'), false);
  });
});

test('production refuses incorrect signer/repo evidence and mismatched identitybinding head', async () => {
  await production(async () => {
    const caller = runtime();
    let writes = 0;
    const invalidCtx = { call: async action => {
      if (action === 'atproto-managed-repository.bootstrapAndVerify') return {
        ...validProof, rootCid: 'bafyreigenesisplaceholder'
      };
      if (action === 'identitybindings.upsertRepoBootstrap') writes++;
      throw new Error('Unexpected action');
    }};
    await assert.rejects(
      caller.initializeRepoState(invalidCtx, { canonicalAccountId: webId, did, handle: 'alice.paper.example' }),
      error => error.type === 'ATPROTO_REPO_PROOF_INVALID'
    );
    assert.equal(writes, 0);

    const binding = {
      webId, atprotoDid: did, atprotoHandle: 'alice.paper.example',
      atSigningKeyRef: 'private-commit-key-ref',
      atRotationKeyRef: 'private-rotation-key-ref',
      repoInitialized: true,
      repoRootCid: cid, // intentionally different from real root
      repoRev: rev,
      atprotoSource: 'local',
      atprotoManaged: true,
      atprotoPdsUrl: 'https://paper.example'
    };
    const ctx = { call: async action => {
      if (action === 'atproto-managed-repository.verifyReady') return validProof;
      throw new Error('Unexpected public-key lookup: ' + action);
    }};
    await assert.rejects(
      caller.verifyProvisionedState(ctx, { canonicalAccountId: webId, binding, didMethod: 'plc' }),
      error => error.type === 'ATPROTO_REPO_BINDING_MISMATCH'
    );
  });
});

test('nonproduction metadata bootstrap is classified as fixture-only, never proof', async () => {
  const prev = process.env.NODE_ENV;
  const prevRequire = process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO;
  try {
    process.env.NODE_ENV = 'test';
    delete process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO;
    const caller = runtime();
    const ctx = { call: async action => {
      assert.equal(action, 'identitybindings.upsertRepoBootstrap');
      return { ok: true };
    }};
    const result = await caller.initializeRepoState(ctx, {
      canonicalAccountId: webId, did, handle: 'alice.paper.example'
    });
    assert.equal(result.fixtureOnly, true);
    assert.equal(result.rootCid, 'bafyreigenesisplaceholder');
  } finally {
    if (prev === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prev;
    if (prevRequire === undefined) delete process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO;
    else process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO = prevRequire;
  }
});

test('production verifies exact signed repo head and both key references on happy path', async () => {
  await production(async () => {
    const caller = runtime();
    caller._signingCallMeta = () => ({});
    caller._resolveLocalPdsUrl = () => 'https://paper.example';
    const actions = [];
    const ctx = { call: async (action, params) => {
      actions.push(action);
      if (action === 'atproto-managed-repository.verifyReady') return validProof;
      if (action === 'signing.getAtprotoPublicKey') {
        assert(['commit', 'rotation'].includes(params.purpose));
        return { publicKeyMultibase: 'test-only-key' };
      }
      throw new Error('Unexpected service: ' + action);
    }};
    const binding = {
      webId, atprotoDid: did, atprotoHandle: 'alice.paper.example',
      atSigningKeyRef: 'commit-key-ref', atRotationKeyRef: 'rotation-key-ref',
      repoInitialized: true, repoRootCid: otherCid, repoRev: rev,
      atprotoSource: 'local', atprotoManaged: true, atprotoPdsUrl: 'https://paper.example'
    };
    await caller.verifyProvisionedState(ctx, { canonicalAccountId: webId, binding, didMethod: 'plc' });
    assert.deepEqual(actions, [
      'atproto-managed-repository.verifyReady',
      'signing.getAtprotoPublicKey',
      'signing.getAtprotoPublicKey'
    ]);
  });
});

test('nonproduction explicit real-repo flag still refuses metadata-only fixture', async () => {
  const previous = process.env.NODE_ENV;
  const previousFlag = process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO;
  try {
    process.env.NODE_ENV = 'test';
    process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO = 'true';
    const caller = runtime();
    let writes = 0;
    const ctx = { call: async action => {
      if (action === 'identitybindings.upsertRepoBootstrap') writes += 1;
      throw new Error('Missing signed native repo verifier');
    }};
    await assert.rejects(
      caller.initializeRepoState(ctx, { canonicalAccountId: webId, did, handle: 'alice.paper.example' }),
      error => error.type === 'ATPROTO_REPO_PROOF_UNAVAILABLE'
    );
    assert.equal(writes, 0);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
    if (previousFlag === undefined) delete process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO;
    else process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO = previousFlag;
  }
});
