'use strict';

const crypto = require('crypto');
const fs = require('fs');
const Module = require('module');
const path = require('path');

const { KEYS_MARKER, MARKER, PRISTINE_HASHES, sha256, patchHttpSignatures, patchKeys } = require('../scripts/patch-semapps-crypto-hs2019-verification');

const semappsFile = require.resolve('@semapps/crypto/signature/http-signatures');
const keysFile = require.resolve('@semapps/crypto/keys/keys');

function loadPatchedService(source) {
  const compiled = new Module(semappsFile, module);
  compiled.filename = semappsFile;
  compiled.paths = Module._nodeModulePaths(path.dirname(semappsFile));
  compiled._compile(source, semappsFile);
  return compiled.exports;
}

function signedRequest(algorithm = 'hs2019', keyType = 'rsa') {
  const { privateKey, publicKey } = keyType === 'rsa'
    ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    : crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const date = new Date().toUTCString();
  const signingString = `(request-target): get /actor\nhost: remote.example\ndate: ${date}`;
  const signature = crypto.sign('sha256', Buffer.from(signingString), privateKey).toString('base64');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    params: {
      url: 'https://remote.example/actor',
      method: 'GET',
      headers: {
        host: 'remote.example',
        date,
        signature: `keyId="https://sender.example/users/alice#main-key",algorithm="${algorithm}",headers="(request-target) host date",signature="${signature}"`
      }
    }
  };
}

function restorePristineHttpSignatures(source) {
  return source.replace(
    /\nfunction normalizeHs2019RsaSignatureAlgorithm[\s\S]*?\/\/ activitypods-hs2019-rsa-(?:sha256|key-binding)-verification-v[123]\n\n/,
    ''
  ).replace("const { createSign, createHash, createPublicKey } = require('crypto');", "const { createSign, createHash } = require('crypto');")
    .replace("const { arrayOf } = require('../utils/utils');\n\n\nconst HttpSignatureService", "const { arrayOf } = require('../utils/utils');\n\nconst HttpSignatureService")
    .replace("const { arrayOf } = require('../utils/utils');\nconst HttpSignatureService", "const { arrayOf } = require('../utils/utils');\n\nconst HttpSignatureService")
    .replace('headers: normalizeHs2019RsaSignatureAlgorithm(headers)', 'headers').replace(
    /      const keyDocumentUri =[\s\S]*?      return verifiedKey \|\| \{ isValid: false \};/,
    `      const [actorUri] = keyId.split('#');

      // TODO: Check if keys are outdated

      const publicKeys = await ctx.call('keys.getRemotePublicKeys', { webId: actorUri, keyType: KEY_TYPES.RSA });

      if (!publicKeys) return { isValid: false };

      // Check, if one of the keys is able to verify the signature.
      const { isValid: keyValid, publicKey: publicKeyPem } = publicKeys
        .flatMap(key => key.publicKeyPem || [])
        .map(pubKeyPem => {
          try {
            return { isValid: verifySignature(parsedSignature, pubKeyPem), publicKey: pubKeyPem };
          } catch (e) {
            return { isValid: false };
          }
        })
        .find(({ isValid }) => isValid) || { isValid: false, publicKey: null };

      return { isValid: keyValid, actorUri, publicKeyPem };`
    );
}

describe('SemApps hs2019 HTTP signature verification patch', () => {
  const original = restorePristineHttpSignatures(fs.readFileSync(semappsFile, 'utf8'));

  test('restores the byte-exact pristine source from every supported patched output', () => {
    expect(sha256(original)).toBe(PRISTINE_HASHES.httpSignatures);
    expect(restorePristineHttpSignatures(patchHttpSignatures(original).source)).toBe(original);
  });

  test('is wired into postinstall and copied before production dependency installation', () => {
    const packageJson = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../package.json'), 'utf8'));
    expect(packageJson.scripts.postinstall).toContain('node scripts/patch-semapps-crypto-hs2019-verification.js');

    const dockerfile = fs.readFileSync(path.resolve(__dirname, '../../docker/backend.dockerfile'), 'utf8');
    const copyIndex = dockerfile.indexOf(
      'ADD backend/scripts/patch-semapps-crypto-hs2019-verification.js /app/backend/scripts/patch-semapps-crypto-hs2019-verification.js'
    );
    expect(copyIndex).toBeGreaterThan(-1);
    expect(dockerfile.indexOf('RUN yarn install && yarn cache clean')).toBeGreaterThan(copyIndex);
  });

  test('accepts a valid hs2019-declared RSA-SHA256 signature through cryptographic verification', async () => {
    const service = loadPatchedService(patchHttpSignatures(original).source);
    const request = signedRequest();
    const result = await service.actions.verifyHttpSignature({
      params: request.params,
      call: jest.fn().mockResolvedValue([{
        id: 'https://sender.example/users/alice#main-key',
        controller: 'https://sender.example/users/alice',
        publicKeyPem: request.publicKeyPem
      }])
    });

    expect(result).toMatchObject({ isValid: true, actorUri: 'https://sender.example/users/alice' });
    expect(result.publicKeyPem).toBe(request.publicKeyPem);
  });

  test('rejects a tampered hs2019 signature', async () => {
    const service = loadPatchedService(patchHttpSignatures(original).source);
    const request = signedRequest();
    request.params.headers.host = 'attacker.example';

    await expect(service.actions.verifyHttpSignature({
      params: request.params,
      call: jest.fn().mockResolvedValue([{
        id: 'https://sender.example/users/alice#main-key',
        controller: 'https://sender.example/users/alice',
        publicKeyPem: request.publicKeyPem
      }])
    })).resolves.toMatchObject({ isValid: false });
  });

  test('rejects a valid EC signature that declares hs2019 instead of treating it as RSA', async () => {
    const service = loadPatchedService(patchHttpSignatures(original).source);
    const request = signedRequest('hs2019', 'ec');

    await expect(service.actions.verifyHttpSignature({
      params: request.params,
      call: jest.fn().mockResolvedValue([{
        id: 'https://sender.example/users/alice#main-key',
        controller: 'https://sender.example/users/alice',
        publicKeyPem: request.publicKeyPem
      }])
    })).resolves.toEqual({ isValid: false });
  });

  test('does not reinterpret unknown algorithms or ambiguous duplicate declarations', async () => {
    const service = loadPatchedService(patchHttpSignatures(original).source);
    const unknown = signedRequest('not-supported');
    let unknownError;
    try {
      await service.actions.verifyHttpSignature({ params: unknown.params, call: jest.fn() });
    } catch (error) {
      unknownError = error;
    }
    expect(unknownError).toMatchObject({ message: 'not-supported is not supported' });

    const duplicate = signedRequest();
    duplicate.params.headers.signature += ',algorithm="rsa-sha256"';
    let duplicateError;
    try {
      await service.actions.verifyHttpSignature({ params: duplicate.params, call: jest.fn() });
    } catch (error) {
      duplicateError = error;
    }
    expect(duplicateError).toMatchObject({ message: 'Multiple HTTP Signature algorithm parameters are not supported' });
  });

  test('is idempotent only when the complete patched source hash matches', () => {
    const once = patchHttpSignatures(original);
    expect(once.changed).toBe(true);
    expect(once.source).toContain(MARKER);
    expect(patchHttpSignatures(once.source)).toEqual({ source: once.source, changed: false });
    expect(() => patchHttpSignatures(`// ${MARKER}`)).toThrow('patched HTTP signature source hash mismatch');
  });

  test('binds slash-style key IDs to the exact same-origin controller', async () => {
    const service = loadPatchedService(patchHttpSignatures(original).source);
    const request = signedRequest();
    request.params.headers.signature = request.params.headers.signature.replace(
      'https://sender.example/users/alice#main-key',
      'https://sender.example/users/alice/main-key'
    );
    const call = jest.fn().mockResolvedValue([{
      id: 'https://sender.example/users/alice/main-key',
      owner: 'https://sender.example/users/alice',
      publicKeyPem: request.publicKeyPem
    }]);

    await expect(service.actions.verifyHttpSignature({ params: request.params, call })).resolves.toMatchObject({
      isValid: true,
      actorUri: 'https://sender.example/users/alice'
    });
    expect(call).toHaveBeenCalledWith('keys.getRemotePublicKeys', {
      webId: 'https://sender.example/users/alice/main-key',
      keyType: expect.any(String)
    });
  });

  test('rejects key-ID substitution and cross-origin controller claims', async () => {
    const service = loadPatchedService(patchHttpSignatures(original).source);
    const request = signedRequest();
    const baseKey = { publicKeyPem: request.publicKeyPem };

    await expect(service.actions.verifyHttpSignature({
      params: request.params,
      call: jest.fn().mockResolvedValue([{
        ...baseKey,
        id: 'https://sender.example/users/alice#other-key',
        controller: 'https://sender.example/users/alice'
      }])
    })).resolves.toEqual({ isValid: false });

    await expect(service.actions.verifyHttpSignature({
      params: request.params,
      call: jest.fn().mockResolvedValue([{
        ...baseKey,
        id: 'https://sender.example/users/alice#main-key',
        controller: 'https://victim.example/users/alice'
      }])
    })).resolves.toEqual({ isValid: false });
  });

  test('uses ActivityPub negotiation and accepts an exact direct key document', () => {
    const source = fs.readFileSync(keysFile, 'utf8')
      .replace(/const REMOTE_KEY_ACCEPT[^\n]*activitypods-activitypub-remote-key-fetch-v1\n\n/, '')
      .replaceAll('headers: { Accept: REMOTE_KEY_ACCEPT }', "headers: { Accept: 'application/json' }")
      .replace(/\n        const directKeyDocument =[\s\S]*?keyObjects = \[actor\];/, '');
    const result = patchKeys(source);
    expect(result.changed).toBe(true);
    expect(result.source).toContain(KEYS_MARKER);
    expect(result.source.match(/headers: \{ Accept: REMOTE_KEY_ACCEPT \}/g)).toHaveLength(2);
    expect(result.source).toContain('if (keyObjects.length === 0 && directKeyDocument) keyObjects = [actor];');
    expect(patchKeys(result.source)).toEqual({ source: result.source, changed: false });
  });

  test('fails closed on any complete-file drift before or after patching', () => {
    expect(() => patchHttpSignatures(`${original}\n`)).toThrow('pristine HTTP signature source hash mismatch');
    expect(() => patchKeys('no keys service')).toThrow('pristine keys source hash mismatch');

    const patchedHttp = patchHttpSignatures(original).source;
    expect(() => patchHttpSignatures(patchedHttp.replace('TODO: Check', 'TODO:  Check')))
      .toThrow('patched HTTP signature source hash mismatch');

    const pristineKeys = fs.readFileSync(keysFile, 'utf8')
      .replace(/const REMOTE_KEY_ACCEPT[^\n]*activitypods-activitypub-remote-key-fetch-v1\n\n/, '')
      .replaceAll('headers: { Accept: REMOTE_KEY_ACCEPT }', "headers: { Accept: 'application/json' }")
      .replace(/\n        const directKeyDocument =[\s\S]*?keyObjects = \[actor\];/, '');
    const patchedKeys = patchKeys(pristineKeys).source;
    expect(() => patchKeys(patchedKeys.replace('const KeysService', 'const  KeysService')))
      .toThrow('patched keys source hash mismatch');
  });
});
