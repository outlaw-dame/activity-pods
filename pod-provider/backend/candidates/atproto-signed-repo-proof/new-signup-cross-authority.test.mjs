import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Pool } from 'pg';
import { base58btc } from 'multiformats/bases/base58';

import { createSignedRepoProofStore } from './store.mjs';
import { createProviderManagedRepoAuthority } from './provider-authority.mjs';
import { createRdfProjectionRecovery } from './projection-recovery.mjs';
import { createNewSignupCrossAuthority } from './new-signup-cross-authority.mjs';

const require = createRequire(import.meta.url);
const { createCandidate } = require('../postgres-account-lifecycle.js');
const dsn = process.env.ATPROTO_REPO_PROOF_DSN || '';
if (process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed' ||
    !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(dsn)) {
  throw Error('Cross-authority proof requires isolated disposable PostgreSQL 18');
}

const pool = new Pool({
  connectionString: dsn, max: 4, connectionTimeoutMillis: 3000,
  idleTimeoutMillis: 3000, allowExitOnIdle: true
});
const providerId = 'https://provider.paper.example.org';
const appClientId = 'https://app.paper.example.org/app';
const webId = 'https://paper.example.org/newsignup';
const did = 'did:plc:' + 'a'.repeat(24);
const handle = 'newsignup.paper.example.org';
const pds = 'https://pds.paper.example.org';
const uuid = () => crypto.randomUUID();
const secret = crypto.randomBytes(32);
const hmac = (purpose, message) => crypto.createHmac('sha256', secret)
  .update(purpose + '\0' + message).digest();
const signup = {
  providerId, appClientId, hmacKeyVersion: 1,
  idempotencyHmac: hmac('paper.signup.idempotency.v1', 'key-a'),
  requestHmac: hmac('paper.signup.request.v1', 'request-a'),
  accountId: uuid(), operationId: uuid(), username: 'newsignup'
};

function keys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1'
  });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const point = publicKey.export({ type: 'spki', format: 'der' }).subarray(-65);
  const compressed = crypto.ECDH.convertKey(point, 'secp256k1', undefined, undefined, 'compressed');
  const publicKeyMultibase = base58btc.encode(Buffer.concat([
    Buffer.from([0xe7,0x01]), compressed
  ]));
  return {
    privateKey, publicKeyPem, publicKeyMultibase,
    signer: async bytes => crypto.sign('sha256', bytes, {
      key: privateKey, dsaEncoding: 'ieee-p1363'
    })
  };
}

const rejectCode = (promise, code) =>
  assert.rejects(promise, error => error?.code === code);

test('PR #138 new signup is correlated to real signed CAR and applied, grant-fenced RDF', async t => {
  let oldEnv = process.env.NODE_ENV;
  try {
    const preAccount = await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_account_candidate'"
    );
    const preRepo = await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    );
    assert.equal(preAccount.rows[0].n, 0);
    assert.equal(preRepo.rows[0].n, 0);
    const accountSchema = new URL('../../sql/paper-account-postgres-candidate-v1.sql', import.meta.url);
    const ledgerSchema = new URL('../../sql/paper-account-postgres-candidate-v2-signup-ledger.sql', import.meta.url);
    await pool.query(await fs.readFile(fileURLToPath(accountSchema), 'utf8'));
    await pool.query(await fs.readFile(fileURLToPath(ledgerSchema), 'utf8'));
    await pool.query(await fs.readFile(fileURLToPath(new URL('./schema.sql', import.meta.url)), 'utf8'));

    const account = createCandidate({ pool, fixtureOnly: true });
    const signing = keys();
    const store = createSignedRepoProofStore({ pool, fixtureOnly: true });
    let r = await account.reserveSignup(signup);
    assert.equal(r.replay, false);
    assert.equal(r.state, 'reserved');
    r = await account.markSignupMayHaveSideEffects(signup);
    assert.equal(r.state, 'reconciliation_required');
    assert.equal(r.generation, 2);
    const bound = await account.change({
      providerId, accountId: signup.accountId, operationId: uuid(),
      expectedGeneration: 1, kind: 'bind_unified_identity',
      webId, activityPubActorId: webId, atprotoDid: did,
      atprotoHandle: handle, atprotoPdsUrl: pds, repoInitialized: true
    });
    assert.equal(bound.generation, 2);

    let binding = {
      canonicalAccountId: webId, webId, activityPubActorId: webId,
      atprotoDid: did, atprotoHandle: handle, atprotoPdsUrl: pds,
      atprotoSource: 'local', atprotoManaged: true,
      atSigningKeyRef: 'key://commit', atRotationKeyRef: 'key://rotation',
      status: 'active', repoInitialized: false,
      repoRootCid: null, repoRev: null, repoProjectionFence: null
    };
    let consentAllowed = true;
    let bootstrapComplete = true;
    const solidCall = async (action, params) => {
      if (action === 'auth.account.findByWebId') {
        assert.equal(params.webId, webId);
        return { '@id': webId, disabled: false };
      }
      if (action === 'identitybindings.getByCanonicalAccountId') {
        assert.equal(params.canonicalAccountId, webId);
        return { ...binding };
      }
      if (action === 'auth.awaitBootstrapComplete') {
        assert.equal(params.webId, webId);
        return { webId, complete: bootstrapComplete };
      }
      throw Error('Unexpected Solid action');
    };
    const repoAuthority = createProviderManagedRepoAuthority({
      store,
      resolveBinding: async () => ({ ...binding }),
      resolveCommitKey: async () => ({
        did, keyId: did + '#atproto',
        publicKeyMultibase: signing.publicKeyMultibase
      }),
      resolveDelegatedIdentity: async () => ({
        resolvedHandleDid: did,
        didDocument: {
          id: did, alsoKnownAs: ['at://' + handle],
          verificationMethod: [{
            id: did + '#atproto', controller: did, type: 'Multikey',
            publicKeyMultibase: signing.publicKeyMultibase
          }],
          service: [{
            id: '#atproto_pds', type: 'AtprotoPersonalDataServer',
            serviceEndpoint: pds
          }]
        }
      }),
      signCommit: async (_account, _did, _rev, encoded) => ({
        did, keyId: did + '#atproto',
        signatureBase64Url: (await signing.signer(Buffer.from(encoded, 'base64')))
          .toString('base64url')
      })
    });
    const projection = createRdfProjectionRecovery({
      pool, fixtureOnly: true,
      verifyNativeEvidence: async () => store.verify({
        accountId: webId, did, publicKeyPem: signing.publicKeyPem
      }),
      authorize: async () => consentAllowed,
      readRdf: async () => ({ ...binding }),
      applyRdfFenced: async () => { throw Error('Read-only acceptance must not write RDF'); }
    });
    const gate = createNewSignupCrossAuthority({
      accountAuthority: account, repositoryAuthority: repoAuthority,
      projectionAuthority: projection, solidCall, fixtureOnly: true
    });
    const scope = {
      providerId, appClientId, hmacKeyVersion: signup.hmacKeyVersion,
      idempotencyHmac: signup.idempotencyHmac
    };

    await t.test('signed repository must exist before reporting completion evidence', async () => {
      await rejectCode(gate.verify(scope), 'ATPROTO_REPO_NOT_FOUND');
    });
    const signed = await store.bootstrap({
      accountId: webId, did, publicKeyPem: signing.publicKeyPem,
      signer: signing.signer
    });
    assert.equal(signed.verified, true);
    assert.equal(signed.outboxStatus, 'pending');
    binding = {
      ...binding, repoInitialized: true,
      repoRootCid: signed.rootCid, repoRev: signed.rev,
      repoProjectionFence: '1'
    };

    await t.test('matching RDF fields alone cannot bypass unapplied recovery intent', async () => {
      await rejectCode(gate.verify(scope), 'PROJECTION_NOT_READY');
    });
    const ack = await pool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET " +
      "state='applied',lease_epoch=1,applied_at=clock_timestamp() " +
      'WHERE account_id=$1 AND did=$2 RETURNING state',
      [webId, did]
    );
    assert.equal(ack.rowCount, 1);

    await t.test('one new account has complete read-only verified signed evidence', async () => {
      const result = await gate.verify(scope);
      assert.equal(result.evidence, 'signed_repo_solid_projection_v1');
      assert.equal(result.accountId, signup.accountId);
      assert.equal(result.webId, webId);
      assert.equal(result.did, did);
      assert.equal(result.rootCid, signed.rootCid);
      assert.equal(result.commitCid, signed.commitCid);
      assert.equal(result.rev, signed.rev);
      assert.equal(result.projectionFence, '1');
      assert.equal(result.outboxStatus, 'pending');
      assert.equal(result.signupGeneration, 2);
      assert.equal(result.accountGeneration, 2);
      assert.equal(result.status, 'evidence_only');
      assert.equal(result.productionReady, false);
      assert.equal((await account.readSignup(scope)).state,
        'reconciliation_required', 'verification must never complete the signup');
    });
    await t.test('wrong application idempotency scope cannot read another signup', async () => {
      await rejectCode(gate.verify({ ...scope, appClientId: 'https://other.example.org/app' }),
        'UNIFIED_SIGNUP_OPERATION_NOT_FENCED');
    });
    await t.test('protected RDF handle/PDS drift fails before signed repo approval', async () => {
      binding = { ...binding, atprotoPdsUrl: 'https://wrong-pds.example.org' };
      await rejectCode(gate.verify(scope), 'UNIFIED_SIGNUP_ACCOUNT_RDF_PROJECTION_MISMATCH');
      binding = { ...binding, atprotoPdsUrl: pds };
      binding = { ...binding, atprotoHandle: 'wrong.paper.example.org' };
      await rejectCode(gate.verify(scope), 'UNIFIED_SIGNUP_ACCOUNT_RDF_PROJECTION_MISMATCH');
      binding = { ...binding, atprotoHandle: handle };
    });
    await t.test('SAI revocation and incomplete Solid bootstrap deny readiness', async () => {
      consentAllowed = false;
      await rejectCode(gate.verify(scope), 'PROJECTION_AUTH_REVOKED');
      consentAllowed = true;
      bootstrapComplete = false;
      await rejectCode(gate.verify(scope), 'SOLID_SIGNUP_PROOF_BOOTSTRAP_INCOMPLETE');
      bootstrapComplete = true;
    });
    await t.test('repository corruption cannot be substituted with RDF repoInitialized', async () => {
      const old = (await pool.query(
        'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
        [did, signed.rootCid]
      )).rows[0].block;
      try {
        await pool.query(
          'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
          [did, signed.rootCid, Buffer.from('corrupt CID')]
        );
        await assert.rejects(gate.verify(scope));
      } finally {
        await pool.query(
          'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
          [did, signed.rootCid, old]
        );
      }
      assert.equal((await gate.verify(scope)).rootCid, signed.rootCid);
    });
    await t.test('late account generation transition invalidates read-only proof', async () => {
      const changed = await account.change({
        providerId, accountId: signup.accountId, operationId: uuid(),
        expectedGeneration: 2, kind: 'transition_state', nextState: 'suspended'
      });
      assert.equal(changed.generation, 3);
      await rejectCode(gate.verify(scope), 'UNIFIED_SIGNUP_ACCOUNT_IDENTITY_INCOMPLETE');
    });
    await t.test('new account evidence cannot be enabled via a production env toggle', async () => {
      process.env.NODE_ENV = 'production';
      await rejectCode(gate.verify(scope), 'UNIFIED_SIGNUP_CROSS_AUTHORITY_NOT_RELEASED');
      process.env.NODE_ENV = 'test';
      const closed = createNewSignupCrossAuthority({
        accountAuthority: account, repositoryAuthority: repoAuthority,
        projectionAuthority: projection, solidCall
      });
      await rejectCode(closed.verify(scope), 'UNIFIED_SIGNUP_CROSS_AUTHORITY_NOT_RELEASED');
    });
  } finally {
    if (oldEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = oldEnv;
    try {
      await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');
      await pool.query('DROP SCHEMA IF EXISTS paper_account_candidate CASCADE');
    } finally {
      await pool.end();
    }
  }
});
