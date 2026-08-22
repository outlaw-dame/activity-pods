'use strict';

const crypto = require('crypto');
const signingService = require('../services/signing.service');
const {
  buildExpectedPlcGenesis,
  encodeCanonicalCbor
} = require('../utils/atproto-signing-policy');
const {
  MAX_AUTHORIZATION_HEADER_BYTES,
  MAX_BEARER_TOKEN_BYTES,
  MIN_SIGNING_TOKEN_BYTES,
  configuredSigningToken,
  isDateWithinSkew,
  parseBearerToken,
  timingSafeSecretEqual
} = require('../utils/signing-security');

function captureError(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error('expected function to throw');
}

function expectMoleculerError(fn, { code, type, message }) {
  const error = captureError(fn);
  expect(error.code).toBe(code);
  expect(error.type).toBe(type);
  expect(error.message).toMatch(message);
}

function service(overrides = {}) {
  return {
    settings: signingService.settings,
    ...signingService.methods,
    _auth: jest.fn(),
    ...overrides
  };
}

function activeManagedBinding(canonicalAccountId, fields = {}) {
  return {
    canonicalAccountId,
    webId: canonicalAccountId,
    status: 'active',
    atprotoSource: 'local',
    atprotoManaged: true,
    atprotoDid: 'did:plc:alice',
    atprotoHandle: 'alice.test',
    atprotoPdsUrl: 'https://pds.example',
    repoInitialized: true,
    repoRootCid: 'bafyprev',
    repoRev: '2',
    ...fields
  };
}

function pendingPlcBinding(canonicalAccountId, fields = {}) {
  return {
    canonicalAccountId,
    webId: canonicalAccountId,
    status: 'pending-plc',
    atprotoSource: 'local',
    atprotoManaged: true,
    atprotoDid: null,
    atprotoHandle: 'alice.test',
    atprotoPdsUrl: 'https://pds.example',
    atSigningKeyRef: 'commit-key',
    atRotationKeyRef: 'rotation-key',
    ...fields
  };
}

function generateSecp256k1PemPair() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

function generateRsaPrivateKey() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  }).privateKey;
}

function validCommit(binding, fields = {}) {
  const commit = {
    did: binding.atprotoDid,
    version: 3,
    data: 'bafynewroot',
    rev: String(Number.parseInt(binding.repoRev, 10) + 1),
    prev: binding.repoRootCid,
    ...fields
  };
  return {
    rev: commit.rev,
    bytesBase64: Buffer.from(JSON.stringify(commit), 'utf8').toString('base64')
  };
}

describe('internal signing authentication', () => {
  test('requires a dedicated ACTIVITYPODS_TOKEN and never falls back to sidecar secrets', () => {
    const validToken = 'a'.repeat(MIN_SIGNING_TOKEN_BYTES);
    expect(configuredSigningToken({})).toBeNull();
    expect(configuredSigningToken({ SIDECAR_TOKEN: 'a'.repeat(64) })).toBeNull();
    expect(configuredSigningToken({ SIGNING_API_TOKEN: 'a'.repeat(64) })).toBeNull();
    expect(configuredSigningToken({ ACTIVITYPODS_TOKEN: validToken })).toBe(validToken);
  });

  test('keeps configured token bounds compatible with Authorization parsing', () => {
    const maxToken = 'a'.repeat(MAX_BEARER_TOKEN_BYTES);
    expect(Buffer.byteLength(`Bearer ${maxToken}`, 'utf8')).toBe(MAX_AUTHORIZATION_HEADER_BYTES);
    expect(configuredSigningToken({ ACTIVITYPODS_TOKEN: maxToken })).toBe(maxToken);
    expect(parseBearerToken(`Bearer ${maxToken}`)).toBe(maxToken);
    expect(configuredSigningToken({ ACTIVITYPODS_TOKEN: 'a'.repeat(MAX_BEARER_TOKEN_BYTES + 1) })).toBeNull();
  });

  test('strictly parses bearer credentials and compares them timing-safely', () => {
    expect(parseBearerToken('Bearer abc.DEF_123-~+/==')).toBe('abc.DEF_123-~+/==');
    expect(parseBearerToken('bearer abc123')).toBe('abc123');
    expect(parseBearerToken('Basic abc123')).toBeNull();
    expect(parseBearerToken('Bearer  abc123')).toBeNull();
    expect(parseBearerToken('Bearer abc123 extra')).toBeNull();
    expect(timingSafeSecretEqual('same-secret', 'same-secret')).toBe(true);
    expect(timingSafeSecretEqual('same-secret', 'different-secret')).toBe(false);
  });

  test('fails closed when signing authentication is unconfigured or wrong', () => {
    expectMoleculerError(
      () => signingService.methods._auth.call(
        { settings: { auth: { bearerToken: null } } },
        { meta: { $headers: { authorization: 'Bearer supplied' } } }
      ),
      { code: 503, type: 'SIGNING_AUTH_NOT_CONFIGURED', message: /not configured/iu }
    );

    const expected = 'e'.repeat(32);
    expectMoleculerError(
      () => signingService.methods._auth.call(
        { settings: { auth: { bearerToken: expected } } },
        { meta: { $headers: { authorization: `Bearer ${'w'.repeat(32)}` } } }
      ),
      { code: 403, type: 'AUTH_FAILED', message: /invalid bearer token/iu }
    );
  });
});

describe('ActivityPub HTTP signing profiles', () => {
  const actorUri = 'https://pods.example/alice';
  const keyId = `${actorUri}#main-key`;
  let privateKey;

  beforeAll(() => {
    privateKey = generateRsaPrivateKey();
  });

  test('GET profile cannot sign mutating methods', async () => {
    const result = await signingService.methods._signOne.call(
      service(),
      actorUri,
      keyId,
      privateKey,
      {
        requestId: 'delete-oracle',
        method: 'DELETE',
        profile: 'ap_get_v1',
        target: { host: 'remote.example', path: '/objects/123' }
      }
    );
    expect(result).toMatchObject({
      requestId: 'delete-oracle',
      ok: false,
      error: { code: 'PROFILE_NOT_ALLOWED', retryable: false }
    });
  });

  test('POST profile cannot be reused for GET', async () => {
    const result = await signingService.methods._signOne.call(
      service(),
      actorUri,
      keyId,
      privateKey,
      {
        requestId: 'profile-confusion',
        method: 'GET',
        profile: 'ap_post_v1',
        target: { host: 'remote.example', path: '/inbox' },
        body: { bytes: '{}', encoding: 'utf8' }
      }
    );
    expect(result).toMatchObject({ ok: false, error: { code: 'PROFILE_NOT_ALLOWED' } });
  });

  test('rejects body encoding reinterpretation and stale dates', async () => {
    const badEncoding = await signingService.methods._signOne.call(
      service(),
      actorUri,
      keyId,
      privateKey,
      {
        requestId: 'encoding-confusion',
        method: 'POST',
        profile: 'ap_post_v1',
        target: { host: 'remote.example', path: '/inbox' },
        body: { bytes: 'e30=', encoding: 'base64' }
      }
    );
    expect(badEncoding).toMatchObject({ ok: false, error: { code: 'INVALID_INPUT' } });

    const stale = await signingService.methods._signOne.call(
      service(),
      actorUri,
      keyId,
      privateKey,
      {
        requestId: 'stale',
        method: 'GET',
        profile: 'ap_get_v1',
        target: { host: 'remote.example', path: '/actor' },
        headers: { date: 'Mon, 17 Aug 2026 20:00:00 GMT' }
      }
    );
    expect(stale).toMatchObject({ ok: false, error: { code: 'INVALID_INPUT' } });
  });

  test('computes Digest over the exact UTF-8 body and signs POST', async () => {
    const body = JSON.stringify({ type: 'Create', content: 'héllo' });
    const result = await signingService.methods._signOne.call(
      service(),
      actorUri,
      keyId,
      privateKey,
      {
        requestId: 'post',
        method: 'POST',
        profile: 'ap_post_v1',
        target: { host: 'remote.example', path: '/inbox' },
        body: { bytes: body, encoding: 'utf8' },
        digest: { mode: 'server_compute' }
      }
    );
    const expected = crypto.createHash('sha256').update(Buffer.from(body, 'utf8')).digest('base64');
    expect(result.ok).toBe(true);
    expect(result.outHeaders.Digest).toBe(`SHA-256=${expected}`);
    expect(result.outHeaders.Signature).toContain(`keyId="${keyId}"`);
  });
});

describe('HTTP date replay protection', () => {
  const now = Date.parse('Mon, 17 Aug 2026 20:00:00 GMT');
  test('accepts only canonical IMF-fixdate within skew', () => {
    expect(isDateWithinSkew('Mon, 17 Aug 2026 20:00:00 GMT', 300, now)).toBe(true);
    expect(isDateWithinSkew('Mon, 17 Aug 2026 19:55:00 GMT', 300, now)).toBe(true);
    expect(isDateWithinSkew('Mon, 17 Aug 2026 20:05:01 GMT', 300, now)).toBe(false);
    expect(isDateWithinSkew('2026-08-17T20:00:00Z', 300, now)).toBe(false);
  });
});

describe('ATProto provisioning and signing authority', () => {
  const canonicalAccountId = 'https://pods.example/alice';

  test('rejects mismatched/non-local account identifiers before key mutation', async () => {
    const mismatchCtx = {
      params: { canonicalAccountId, webId: 'https://pods.example/bob' },
      meta: {},
      call: jest.fn()
    };
    await expect(
      signingService.actions.provisionAtprotoIdentity.handler.call(service(), mismatchCtx)
    ).rejects.toMatchObject({ code: 403, type: 'ACCOUNT_BINDING_MISMATCH' });
    expect(mismatchCtx.call).not.toHaveBeenCalled();

    const remoteCtx = {
      params: { canonicalAccountId: 'https://remote.example/alice' },
      meta: {},
      call: jest.fn().mockResolvedValueOnce(null)
    };
    await expect(
      signingService.actions.provisionAtprotoIdentity.handler.call(service(), remoteCtx)
    ).rejects.toMatchObject({ code: 403, type: 'ACCOUNT_NOT_LOCAL' });
    expect(remoteCtx.call).toHaveBeenCalledTimes(1);
  });

  test('refuses to overwrite any existing identity binding before generating keys', async () => {
    const existing = activeManagedBinding(canonicalAccountId, {
      atprotoSource: 'external',
      atprotoManaged: false,
      status: 'disabled'
    });
    const ctx = {
      params: { canonicalAccountId },
      meta: {},
      call: jest.fn()
        .mockResolvedValueOnce({ webId: canonicalAccountId, username: 'alice-dataset' })
        .mockResolvedValueOnce(existing)
    };
    await expect(
      signingService.actions.provisionAtprotoIdentity.handler.call(service(), ctx)
    ).rejects.toMatchObject({ code: 409, type: 'IDENTITY_BINDING_EXISTS' });
    expect(ctx.call).toHaveBeenCalledTimes(2);
    expect(ctx.call.mock.calls.some(([name]) => name === 'keys.generateSecp256k1Key')).toBe(false);
    expect(ctx.call.mock.calls.some(([name]) => name === 'identitybindings.upsert')).toBe(false);
  });

  test('creates keys only in the authoritative local account dataset when no binding exists', async () => {
    const ctx = {
      params: { canonicalAccountId, did: 'did:plc:alice', handle: 'alice.test' },
      meta: { requestId: 'provision' },
      call: jest.fn()
        .mockResolvedValueOnce({ webId: canonicalAccountId, username: 'alice-dataset' })
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({ keyRef: 'commit-key' })
        .mockResolvedValueOnce({ keyRef: 'rotation-key' })
        .mockResolvedValueOnce({ canonicalAccountId, webId: canonicalAccountId })
    };
    await signingService.actions.provisionAtprotoIdentity.handler.call(service(), ctx);
    expect(ctx.call).toHaveBeenNthCalledWith(
      3,
      'keys.generateSecp256k1Key',
      { webId: canonicalAccountId },
      { meta: { requestId: 'provision', dataset: 'alice-dataset', webId: canonicalAccountId } }
    );
    expect(ctx.call).toHaveBeenNthCalledWith(
      4,
      'keys.generateSecp256k1Key',
      { webId: canonicalAccountId },
      { meta: { requestId: 'provision', dataset: 'alice-dataset', webId: canonicalAccountId } }
    );
  });

  test('signs only the exact next repository commit bound to DID, rev and prev', async () => {
    const binding = activeManagedBinding(canonicalAccountId, { atSigningKeyRef: 'commit-key' });
    const { privateKey } = generateSecp256k1PemPair();
    const commit = validCommit(binding);
    const ctx = {
      params: {
        canonicalAccountId,
        did: binding.atprotoDid,
        unsignedCommitBytesBase64: commit.bytesBase64,
        rev: commit.rev
      },
      meta: { requestId: 'commit' },
      call: jest.fn()
        .mockResolvedValueOnce(binding)
        .mockResolvedValueOnce({ webId: canonicalAccountId, username: 'alice-dataset' })
        .mockResolvedValueOnce({ privateKeyPem: privateKey })
    };
    const result = await signingService.actions.signAtprotoCommit.handler.call(service(), ctx);
    expect(result.did).toBe(binding.atprotoDid);
    expect(result.signatureBase64Url).toEqual(expect.any(String));
    expect(ctx.call).toHaveBeenNthCalledWith(3, 'keys.getAtprotoKeyPair', { keyRef: 'commit-key' }, {
      meta: { requestId: 'commit', dataset: 'alice-dataset', webId: canonicalAccountId }
    });
  });

  test.each([
    ['wrong DID', { did: 'did:plc:attacker' }, '3'],
    ['wrong revision', {}, '99'],
    ['wrong prev', { prev: 'bafyattacker' }, '3']
  ])('rejects commit transition with %s before private-key lookup', async (_label, commitFields, suppliedRev) => {
    const binding = activeManagedBinding(canonicalAccountId, { atSigningKeyRef: 'commit-key' });
    const commit = validCommit(binding, commitFields);
    const ctx = {
      params: {
        canonicalAccountId,
        did: binding.atprotoDid,
        unsignedCommitBytesBase64: commit.bytesBase64,
        rev: suppliedRev
      },
      meta: {},
      call: jest.fn().mockResolvedValueOnce(binding)
    };
    await expect(
      signingService.actions.signAtprotoCommit.handler.call(service(), ctx)
    ).rejects.toMatchObject({ code: 400, type: 'INVALID_INPUT' });
    expect(ctx.call).toHaveBeenCalledTimes(1);
  });

  test('rejects external, unmanaged, inactive and malformed commit inputs before key reads', async () => {
    for (const binding of [
      activeManagedBinding(canonicalAccountId, { status: 'disabled', atSigningKeyRef: 'commit-key' }),
      activeManagedBinding(canonicalAccountId, { atprotoSource: 'external', atSigningKeyRef: 'commit-key' }),
      activeManagedBinding(canonicalAccountId, { atprotoManaged: false, atSigningKeyRef: 'commit-key' })
    ]) {
      const ctx = {
        params: { canonicalAccountId, did: 'did:plc:alice', unsignedCommitBytesBase64: 'YQ==', rev: '3' },
        meta: {},
        call: jest.fn().mockResolvedValueOnce(binding)
      };
      await expect(
        signingService.actions.signAtprotoCommit.handler.call(service(), ctx)
      ).rejects.toMatchObject({ code: 403 });
      expect(ctx.call).toHaveBeenCalledTimes(1);
    }

    const binding = activeManagedBinding(canonicalAccountId, { atSigningKeyRef: 'commit-key' });
    const malformed = {
      params: {
        canonicalAccountId,
        did: binding.atprotoDid,
        unsignedCommitBytesBase64: 'not base64!!!',
        rev: '3'
      },
      meta: {},
      call: jest.fn().mockResolvedValueOnce(binding)
    };
    await expect(
      signingService.actions.signAtprotoCommit.handler.call(service(), malformed)
    ).rejects.toMatchObject({ code: 400, type: 'INVALID_INPUT' });
    expect(malformed.call).toHaveBeenCalledTimes(1);
  });

  test('permits public-key reads for narrowly formed pending PLC genesis but not commit signing', async () => {
    const binding = pendingPlcBinding(canonicalAccountId);
    const ctx = {
      params: { canonicalAccountId, purpose: 'commit' },
      meta: { requestId: 'public' },
      call: jest.fn()
        .mockResolvedValueOnce(binding)
        .mockResolvedValueOnce({ webId: canonicalAccountId, username: 'alice-dataset' })
        .mockResolvedValueOnce({ publicKeyMultibase: 'z12345' })
    };
    const result = await signingService.actions.getAtprotoPublicKey.handler.call(service(), ctx);
    expect(result).toMatchObject({ keyId: '#atproto', publicKeyMultibase: 'z12345' });

    const commitCtx = {
      params: { canonicalAccountId, did: 'did:plc:pending', unsignedCommitBytesBase64: 'YQ==', rev: '1' },
      meta: {},
      call: jest.fn().mockResolvedValueOnce(binding)
    };
    await expect(
      signingService.actions.signAtprotoCommit.handler.call(service(), commitCtx)
    ).rejects.toMatchObject({ code: 403, type: 'IDENTITY_BINDING_INACTIVE' });
    expect(commitCtx.call).toHaveBeenCalledTimes(1);
  });

  test('PLC rotation key signs only the exact authorized pending genesis CBOR', async () => {
    const binding = pendingPlcBinding(canonicalAccountId);
    const { privateKey } = generateSecp256k1PemPair();
    const rotationMultibase = 'z12345';
    const verificationMultibase = 'z6789A';
    const operation = buildExpectedPlcGenesis({
      binding,
      rotationKeyMultibase: rotationMultibase,
      verificationKeyMultibase: verificationMultibase
    });
    const operationBytesBase64 = encodeCanonicalCbor(operation).toString('base64');
    const ctx = {
      params: { canonicalAccountId, did: 'did:plc:pending', operationBytesBase64 },
      meta: { requestId: 'plc' },
      call: jest.fn()
        .mockResolvedValueOnce(binding)
        .mockResolvedValueOnce({ webId: canonicalAccountId, username: 'alice-dataset' })
        .mockResolvedValueOnce({ privateKeyPem: privateKey, publicKeyMultibase: rotationMultibase })
        .mockResolvedValueOnce({ publicKeyMultibase: verificationMultibase })
    };
    const result = await signingService.actions.signAtprotoPlcOp.handler.call(service(), ctx);
    expect(result.signatureBase64Url).toEqual(expect.any(String));
    expect(ctx.call.mock.calls.filter(([name]) => name === 'keys.getAtprotoKeyPair')).toHaveLength(2);
  });

  test('rejects attacker-selected PLC genesis contents and generic active-DID rotation', async () => {
    const binding = pendingPlcBinding(canonicalAccountId);
    const { privateKey } = generateSecp256k1PemPair();
    const malicious = encodeCanonicalCbor({
      ...buildExpectedPlcGenesis({
        binding,
        rotationKeyMultibase: 'z12345',
        verificationKeyMultibase: 'z6789A'
      }),
      rotationKeys: ['did:key:zAttacker']
    }).toString('base64');
    const ctx = {
      params: { canonicalAccountId, did: 'did:plc:pending', operationBytesBase64: malicious },
      meta: {},
      call: jest.fn()
        .mockResolvedValueOnce(binding)
        .mockResolvedValueOnce({ webId: canonicalAccountId, username: 'alice-dataset' })
        .mockResolvedValueOnce({ privateKeyPem: privateKey, publicKeyMultibase: 'z12345' })
        .mockResolvedValueOnce({ publicKeyMultibase: 'z6789A' })
    };
    await expect(
      signingService.actions.signAtprotoPlcOp.handler.call(service(), ctx)
    ).rejects.toMatchObject({ code: 403, type: 'PLC_TRANSITION_NOT_AUTHORIZED' });

    const active = activeManagedBinding(canonicalAccountId, { atRotationKeyRef: 'rotation-key' });
    const activeCtx = {
      params: { canonicalAccountId, did: active.atprotoDid, operationBytesBase64: 'YQ==' },
      meta: {},
      call: jest.fn().mockResolvedValueOnce(active)
    };
    await expect(
      signingService.actions.signAtprotoPlcOp.handler.call(service(), activeCtx)
    ).rejects.toMatchObject({ code: 403, type: 'IDENTITY_BINDING_INACTIVE' });
    expect(activeCtx.call).toHaveBeenCalledTimes(1);
  });
});