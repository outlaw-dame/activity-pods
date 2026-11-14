import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { base58btc } from 'multiformats/bases/base58';
import { Pool } from 'pg';
import {
  createProviderManagedRepoAuthority, publicKeyPemFromMultibase
} from './provider-authority.mjs';
import { createSignedRepoProofStore } from './store.mjs';
import { makeProviderManagedRepositoryService } from './provider-moleculer.mjs';

const DSN = process.env.ATPROTO_REPO_PROOF_DSN || '';
if (process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/.test(DSN)) {
  throw new Error('Refusing to run the bridge proof outside disposable loopback PG18');
}
const pool = new Pool({
  connectionString: DSN, max: 4, connectionTimeoutMillis: 3000,
  idleTimeoutMillis: 3000, allowExitOnIdle: true
});

function createKeys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const uncompressed = publicKey.export({ format: 'der', type: 'spki' }).subarray(-65);
  const compressed = crypto.ECDH.convertKey(uncompressed, 'secp256k1', undefined, undefined, 'compressed');
  const publicKeyMultibase = base58btc.encode(Buffer.concat([Buffer.from([0xe7, 0x01]), compressed]));
  return { privateKey, publicKeyPem, publicKeyMultibase };
}

const did = 'did:plc:' + 'd'.repeat(24);
const account = 'https://paper.example.org/users/alice';
const handle = 'alice.paper.example.org';
const pds = 'https://pds.paper.example.org';
const head = {
  canonicalAccountId: account, webId: account, activityPubActorId: account,
  atprotoDid: did, atprotoHandle: handle, atprotoSource: 'local',
  atprotoManaged: true, atprotoPdsUrl: pds, atSigningKeyRef: 'key://commit',
  atRotationKeyRef: 'key://rotation', status: 'active',
  repoInitialized: false, repoRootCid: null, repoRev: null
};

function harness({ store, keys = createKeys() } = {}) {
  let binding = { ...head };
  let didDocumentKey = keys.publicKeyMultibase;
  let resolvedDid = did;
  let signCount = 0;
  let signEnabled = true;
  const doc = () => ({
    id: did, alsoKnownAs: ['at://' + handle],
    verificationMethod: [{
      id: did + '#atproto', controller: did, type: 'Multikey',
      publicKeyMultibase: didDocumentKey
    }],
    service: [{
      id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: pds
    }]
  });
  const authority = createProviderManagedRepoAuthority({
    store,
    resolveBinding: async () => ({ ...binding }),
    resolveCommitKey: async () => ({
      did, keyId: did + '#atproto', publicKeyMultibase: keys.publicKeyMultibase
    }),
    resolveDelegatedIdentity: async () => ({
      resolvedHandleDid: resolvedDid, didDocument: doc()
    }),
    signCommit: async (_accountId, _did, _rev, encoded) => {
      signCount += 1;
      if (!signEnabled) throw new Error('Provider signer unavailable');
      const signature = crypto.sign('sha256', Buffer.from(encoded, 'base64'), {
        key: keys.privateKey, dsaEncoding: 'ieee-p1363'
      }).toString('base64url');
      return { did, keyId: did + '#atproto', signatureBase64Url: signature };
    }
  });
  return {
    authority, input: { canonicalAccountId: account, did, handle },
    binding: () => ({ ...binding }),
    setBinding: value => { binding = { ...binding, ...value }; },
    setPlcKey: value => { didDocumentKey = value; },
    setHandleDid: value => { resolvedDid = value; },
    disableSigning: () => { signEnabled = false; },
    signatures: () => signCount
  };
}

test('provider-authorized bridge: actual PG18 signed repo, identity drift and durable recovery', async t => {
  try {
    const tables = await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    );
    assert.equal(tables.rows[0].n, 0, 'disposable schema must start empty');
    await pool.query(await fs.readFile(fileURLToPath(new URL('./schema.sql', import.meta.url)), 'utf8'));
    const store = createSignedRepoProofStore({ pool, fixtureOnly: true });
    const h = harness({ store });

    await t.test('compressed secp256k1 multibase produces exact verification public key', async () => {
      const k = createKeys();
      assert.equal(
        crypto.createPublicKey(publicKeyPemFromMultibase(k.publicKeyMultibase))
          .export({ format: 'der', type: 'spki' }).toString('hex'),
        crypto.createPublicKey(k.publicKeyPem).export({ format: 'der', type: 'spki' }).toString('hex')
      );
      await assert.rejects(async () => publicKeyPemFromMultibase('z3'), /public key|multibase/i);
      await assert.rejects(async () => publicKeyPemFromMultibase('did:plc:fake'), /multibase/i);
    });

    await t.test('spoofed account, DID, handle, AP identity and unverified PLC fail before any signature', async () => {
      const untrusted = [
        { canonicalAccountId: 'https://attacker.example.org/users/alice', did, handle },
        { canonicalAccountId: account, did: 'did:plc:' + 'e'.repeat(24), handle },
        { canonicalAccountId: account, did, handle: 'attacker.example.org' }
      ];
      for (const input of untrusted) await assert.rejects(h.authority.bootstrapAndVerify(input));
      h.setBinding({ activityPubActorId: 'https://attacker.example.org/ap/alice' });
      await assert.rejects(h.authority.bootstrapAndVerify(h.input), e => e.code === 'MANAGED_REPO_BINDING_INVALID');
      h.setBinding({ activityPubActorId: account });
      h.setHandleDid('did:plc:' + 'e'.repeat(24));
      await assert.rejects(h.authority.bootstrapAndVerify(h.input), e => e.code === 'MANAGED_REPO_HANDLE_DID_MISMATCH');
      h.setHandleDid(did);
      h.setPlcKey(createKeys().publicKeyMultibase);
      await assert.rejects(h.authority.bootstrapAndVerify(h.input), e => e.code === 'MANAGED_REPO_PLC_KEY_MISMATCH');
      assert.equal(h.signatures(), 0);
      const rows = await pool.query('SELECT count(*)::int AS n FROM paper_atproto_repo_proof.repos');
      assert.equal(rows.rows[0].n, 0);
    });

    await t.test('genuine commit stored once; RDF projection required and idempotent', async () => {
      const trusted = harness({ store });
      const result = await trusted.authority.bootstrapAndVerify(trusted.input);
      assert.equal(result.verified, true);
      assert.equal(result.did, did);
      assert.equal(result.outboxStatus, 'pending');
      assert(!('carBytes' in result) && !('publicKeyPem' in result) && !('privateKey' in result));
      await assert.rejects(
        trusted.authority.verifyReady(trusted.input),
        e => e.code === 'MANAGED_REPO_RDF_DRIFT'
      );
      const crash = await trusted.authority.inspectRecovery(trusted.input);
      assert.equal(crash.recoveryRequired, true);
      const count = trusted.signatures();
      const replay = await trusted.authority.bootstrapAndVerify(trusted.input);
      assert.equal(replay.commitCid, result.commitCid);
      assert.equal(trusted.signatures(), count, 'replay must not sign duplicate genesis commit');
      trusted.setBinding({ repoInitialized: true, repoRootCid: result.rootCid, repoRev: result.rev });
      const ready = await trusted.authority.verifyReady(trusted.input);
      assert.equal(ready.commitCid, result.commitCid);
      assert.equal((await trusted.authority.inspectRecovery(trusted.input)).bindingMatch, true);
      trusted.setBinding({ repoRev: '2222222222222' });
      await assert.rejects(
        trusted.authority.verifyReady(trusted.input),
        e => e.code === 'MANAGED_REPO_RDF_DRIFT'
      );
      const outbox = await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.native_event_outbox WHERE did=$1', [did]
      );
      assert.equal(outbox.rows[0].n, 1);
      const blocks = await pool.query(
        'SELECT count(*)::int AS n FROM paper_atproto_repo_proof.blocks WHERE did=$1', [did]
      );
      assert.equal(blocks.rows[0].n, 2);
    });

    await t.test('key rotation and changed identity are rejected against existing signed head', async () => {
      const other = harness({ store });
      await assert.rejects(
        other.authority.bootstrapAndVerify(other.input),
        /signature/i,
        'new key must not verify existing immutable signed commit'
      );
      other.setBinding({ atSigningKeyRef: 'key://unexpected' });
      // This still has a valid record shape, but the old signature fails.
      await assert.rejects(other.authority.verifyReady(other.input));
    });

    await t.test('authorized Moleculer adapter signs only bound genesis and isolates capability metadata', async () => {
      const id = 'did:plc:' + 'f'.repeat(24);
      const webId = 'https://paper.example.org/users/bob';
      const userHandle = 'bob.paper.example.org';
      const keys = createKeys();
      let binding = {
        ...head, canonicalAccountId: webId, webId, activityPubActorId: webId,
        atprotoDid: id, atprotoHandle: userHandle
      };
      let signed = 0;
      const capability = 'capability_'.padEnd(64, 'x');
      const bearer = 'signer_'.padEnd(64, 'y');
      const observed = [];
      const service = makeProviderManagedRepositoryService({
        pool, providerCapability: capability, signingBearerToken: bearer
      });
      const broker = {
        async call(name, params, options) {
          observed.push({ name, options });
          assert.equal(options?.meta?.providerRepoCapability, undefined,
            'broker-internal capability must never reach downstream provider calls');
          if (name.startsWith('signing.')) {
            assert.equal(options?.meta?.$headers?.authorization, 'Bearer ' + bearer);
          } else {
            assert.equal(options, undefined, 'only the signer gets its own bearer credential');
          }
          if (name === 'identitybindings.getByCanonicalAccountId') {
            assert.equal(params.canonicalAccountId, webId);
            return { ...binding };
          }
          if (name === 'signing.getAtprotoPublicKey') {
            assert.equal(params.canonicalAccountId, webId);
            assert.equal(params.purpose, 'commit');
            return { did: id, keyId: id + '#atproto', publicKeyMultibase: keys.publicKeyMultibase };
          }
          if (name === 'atproto-verification.verifyDelegatedIdentity') {
            assert.equal(params.subjectDid, id);
            assert.equal(params.did, id);
            assert.equal(params.handle, userHandle);
            assert.equal(params.pdsUrl, pds);
            return {
              resolvedHandleDid: id,
              didDocument: {
                id,
                alsoKnownAs: ['at://' + userHandle],
                verificationMethod: [{
                  id: id + '#atproto', controller: id,
                  type: 'Multikey', publicKeyMultibase: keys.publicKeyMultibase
                }],
                service: [{
                  id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: pds
                }]
              }
            };
          }
          if (name === 'signing.signAtprotoCommit') {
            signed += 1;
            assert.equal(params.did, id);
            assert.equal(params.canonicalAccountId, webId);
            const bytes = Buffer.from(params.unsignedCommitBytesBase64, 'base64');
            const signatureBase64Url = crypto.sign('sha256', bytes, {
              key: keys.privateKey, dsaEncoding: 'ieee-p1363'
            }).toString('base64url');
            return { did: id, keyId: id + '#atproto', signatureBase64Url };
          }
          throw new Error('Unexpected broker action: ' + name);
        }
      };
      const ctx = {
        broker, caller: 'atproto-provisioning',
        meta: { providerRepoCapability: capability },
        params: { canonicalAccountId: webId, did: id, handle: userHandle }
      };
      const result = await service.actions.bootstrapAndVerify.handler(ctx);
      assert.equal(result.verified, true);
      assert.equal(result.did, id);
      assert.equal(result.outboxStatus, 'pending');
      assert.equal(signed, 1);
      assert(!Object.hasOwn(result, 'carBytes'));
      const replay = await service.actions.bootstrapAndVerify.handler(ctx);
      assert.equal(replay.commitCid, result.commitCid);
      assert.equal(signed, 1, 'repeat bootstrap must not request second signature');
      await assert.rejects(
        service.actions.verifyReady.handler(ctx),
        e => e.code === 'MANAGED_REPO_RDF_DRIFT'
      );
      const recovery = await service.actions.inspectRecovery.handler(ctx);
      assert.equal(recovery.recoveryRequired, true);
      binding = {
        ...binding, repoInitialized: true,
        repoRootCid: result.rootCid, repoRev: result.rev
      };
      const verified = await service.actions.verifyReady.handler(ctx);
      assert.equal(verified.commitCid, result.commitCid);
      assert.equal((await service.actions.inspectRecovery.handler(ctx)).bindingMatch, true);
      // Cross the REAL ActivityPods provisioning method -> protected
      // Moleculer action -> PG18 signed repository readback boundary.
      // This does not register a production service or open a public API.
      const oldEnv = {
        NODE_ENV: process.env.NODE_ENV,
        APODS_ATPROTO_REQUIRE_VERIFIED_REPO:
          process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO,
        APODS_ATPROTO_MANAGED_REPO_CAPABILITY:
          process.env.APODS_ATPROTO_MANAGED_REPO_CAPABILITY
      };
      try {
        process.env.NODE_ENV = 'test';
        process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO = 'true';
        process.env.APODS_ATPROTO_MANAGED_REPO_CAPABILITY = capability;
        const source = await fs.readFile(
          new URL('../../services/core/atproto-provisioning.js', import.meta.url), 'utf8');
        const moduleMock = { exports: {} };
        class LocalError extends Error {
          constructor(message, status, type) {
            super(message); this.code = status; this.type = type;
          }
        }
        const requireLocal = createRequire(import.meta.url);
        const loader = vm.runInNewContext(
          '(function(require,module){\\n' + source + '\\n})',
          { process, URL, Buffer, console, setTimeout, clearTimeout }
        );
        loader(name => {
          if (name === 'crypto') return crypto;
          if (name === 'moleculer') return { Errors: { MoleculerError: LocalError } };
          if (name === '../../utils/atproto-managed-repo-proof-policy') {
            return requireLocal('../../utils/atproto-managed-repo-proof-policy.js');
          }
          throw Error('Unexpected production service dependency: ' + name);
        }, moduleMock);
        const methods = {
          ...moduleMock.exports.methods,
          _resolveLocalPdsUrl: () => pds,
          _signingCallMeta: () => ({}),
          settings: { repoBootstrapRootCid: 'bafyreigenesisplaceholder', repoBootstrapRev: '0' }
        };
        let repoCalls = 0;
        const request = { call: async (action, params, options) => {
          if (action.startsWith('atproto-managed-repository.')) {
            assert.equal(options?.meta?.providerRepoCapability, capability);
            repoCalls += 1;
            const method = action.split('.')[1];
            assert(method === 'bootstrapAndVerify' || method === 'verifyReady');
            return service.actions[method].handler({
              broker, caller: 'atproto-provisioning', params,
              meta: { providerRepoCapability: options.meta.providerRepoCapability }
            });
          }
          if (action === 'identitybindings.upsertRepoBootstrap') {
            assert.equal(params.canonicalAccountId, webId);
            assert.equal(params.did, id);
            assert.equal(params.handle, userHandle);
            binding = { ...binding, repoInitialized: true,
              repoRootCid: params.rootCid, repoRev: params.rev };
            return { ok: true };
          }
          if (action === 'signing.getAtprotoPublicKey') {
            assert.equal(params.canonicalAccountId, webId);
            return { publicKeyMultibase: keys.publicKeyMultibase };
          }
          throw Error('Unexpected provisioning call: ' + action);
        } };
        binding = { ...binding, repoInitialized: false, repoRootCid: null, repoRev: null };
        const initialized = await methods.initializeRepoState(request, {
          canonicalAccountId: webId, did: id, handle: userHandle
        });
        assert.equal(initialized.rootCid, result.rootCid);
        assert.equal(initialized.rev, result.rev);
        await methods.verifyProvisionedState(request, {
          canonicalAccountId: webId, binding: { ...binding }, didMethod: 'plc'
        });
        assert.equal(repoCalls, 2);
        assert.equal(signed, 1, 'readiness replay must not mint a second commit');
      } finally {
        for (const [name, value] of Object.entries(oldEnv)) {
          if (value === undefined) delete process.env[name];
          else process.env[name] = value;
        }
      }

      assert(observed.some(x => x.name === 'signing.signAtprotoCommit'));
      assert(observed.some(x => x.name === 'atproto-verification.verifyDelegatedIdentity'));
    });

    await t.test('Moleculer schema is NOT enabled and rejects API / missing capability', async () => {
      const service = makeProviderManagedRepositoryService({
        pool, providerCapability: 'c'.repeat(64), signingBearerToken: 's'.repeat(64)
      });
      const request = { params: h.input, caller: 'api', meta: { providerRepoCapability: 'c'.repeat(64) } };
      await assert.rejects(
        service.actions.bootstrapAndVerify.handler(request),
        e => e.code === 'MANAGED_REPO_NOT_RELEASED'
      );
      const providerCall = { ...request, caller: 'atproto-provisioning' };
      await assert.rejects(
        service.actions.verifyReady.handler({ ...providerCall, meta: {} }),
        e => e.code === 'MANAGED_REPO_NOT_RELEASED'
      );
      const before = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        await assert.rejects(
          service.actions.verifyReady.handler(providerCall),
          e => e.code === 'MANAGED_REPO_NOT_RELEASED'
        );
      } finally {
        if (before === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = before;
      }
    });
  } finally {
    try {
      await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');
    } finally {
      await pool.end();
    }
  }
});
