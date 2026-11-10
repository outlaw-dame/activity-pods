'use strict';

const fs = require('fs');
const path = require('path');
const { createHash } = require('crypto');

const EXPECTED_VERSION = '1.1.4';
const LEGACY_MARKER = 'activitypods-hs2019-rsa-sha256-verification-v1';
const PREVIOUS_MARKER = 'activitypods-hs2019-rsa-key-binding-verification-v3';
const MARKER = 'activitypods-hs2019-rsa-key-binding-verification-v4';
const KEYS_MARKER = 'activitypods-activitypub-remote-key-fetch-v1';
const PRISTINE_HASHES = Object.freeze({
  httpSignatures: '8ddcc0cbdaf11fb5f0c9f599e6da98e7215773e64bc9720940008c1aa6284ece',
  keys: '43a29bc040ad63b9d9f6734fb6e369e63889b136fe350238b878cfa4e6fa925e'
});
const PATCHED_HASHES = Object.freeze({
  httpSignatures: 'a266e375c25a8e0099e3aa84d4f8c268e0f358ecdb9cbdf0aa24ca2712556a25',
  keys: '8545664eb35396b4c3da1eebe107c0934c564eaf57e3fb134e745464442b19af'
});

function sha256(source) {
  return createHash('sha256').update(source).digest('hex');
}

function requireHash(source, expected, label) {
  const actual = sha256(source);
  if (expected && actual !== expected) {
    throw new Error(`Pinned SemApps ${label} hash mismatch: expected ${expected}, found ${actual}`);
  }
}

const HELPER = `
function normalizeHs2019RsaSignatureAlgorithm(headers) {
  const signature = headers.signature;
  if (typeof signature !== 'string') return headers;

  const algorithmParameters = signature.match(/(?:^|,)\\s*algorithm\\s*=\\s*(?:"[^"]*"|[^,\\s]+)/gi) || [];
  if (algorithmParameters.length > 1) throw new Error('Multiple HTTP Signature algorithm parameters are not supported');
  if (algorithmParameters.length !== 1 || !/algorithm\\s*=\\s*"?hs2019"?$/i.test(algorithmParameters[0])) return headers;

  return {
    ...headers,
    signature: signature.replace(algorithmParameters[0], algorithmParameters[0].replace(/hs2019/i, 'rsa-sha256'))
  };
} // ${MARKER}
`;

function replaceOnce(source, search, replacement, label) {
  const first = source.indexOf(search);
  if (first < 0 || source.indexOf(search, first + search.length) >= 0) {
    throw new Error(`Expected exactly one pinned SemApps ${label}`);
  }
  return source.replace(search, replacement);
}

function patchHttpSignatures(source) {
  if (source.includes(MARKER)) {
    requireHash(source, PATCHED_HASHES.httpSignatures, 'patched HTTP signature source');
    return { source, changed: false };
  }

  requireHash(source, PRISTINE_HASHES.httpSignatures, 'pristine HTTP signature source');
  let patched = source;
  patched = replaceOnce(
    patched,
    "const { createSign, createHash } = require('crypto');",
    "const { createSign, createHash, createPublicKey } = require('crypto');",
    'crypto import'
  );
  patched = replaceOnce(
    patched,
    "const HttpSignatureService = {",
    `${HELPER}\nconst HttpSignatureService = {`,
    'HTTP signature service declaration'
  );
  patched = replaceOnce(
    patched,
    `        headers\n      });\n\n      const { keyId } = parsedSignature.params;`,
    `        headers: normalizeHs2019RsaSignatureAlgorithm(headers)\n      });\n\n      const { keyId } = parsedSignature.params;`,
    'HTTP signature parser headers'
  );

  patched = replaceOnce(
    patched,
    `      const [actorUri] = keyId.split('#');\n\n      // TODO: Check if keys are outdated\n\n      const publicKeys = await ctx.call('keys.getRemotePublicKeys', { webId: actorUri, keyType: KEY_TYPES.RSA });\n\n      if (!publicKeys) return { isValid: false };\n\n      // Check, if one of the keys is able to verify the signature.\n      const { isValid: keyValid, publicKey: publicKeyPem } = publicKeys\n        .flatMap(key => key.publicKeyPem || [])\n        .map(pubKeyPem => {\n          try {\n            return { isValid: verifySignature(parsedSignature, pubKeyPem), publicKey: pubKeyPem };\n          } catch (e) {\n            return { isValid: false };\n          }\n        })\n        .find(({ isValid }) => isValid) || { isValid: false, publicKey: null };\n\n      return { isValid: keyValid, actorUri, publicKeyPem };`,
    `      const keyDocumentUri = keyId.includes('#') ? keyId.split('#')[0] : keyId;\n\n      // TODO: Check if keys are outdated\n\n      let publicKeys = await ctx.call('keys.getRemotePublicKeys', { webId: keyDocumentUri, keyType: KEY_TYPES.RSA });\n      if ((!publicKeys || publicKeys.length === 0) && !keyId.includes('#')) {\n        const fallbackParentUri = keyId.replace(/\\/[^/]+$/, '');\n        if (fallbackParentUri !== keyId) {\n          publicKeys = await ctx.call('keys.getRemotePublicKeys', { webId: fallbackParentUri, keyType: KEY_TYPES.RSA });\n        }\n      }\n      if (!publicKeys) return { isValid: false };\n\n      // Bind verification to the exact requested key and its same-origin controller.\n      const verifiedKey = publicKeys\n        .filter(key => (key.id || key['@id']) === keyId && typeof key.publicKeyPem === 'string')\n        .map(key => {\n          const actorUri = key.controller || key.owner;\n          if (typeof actorUri !== 'string') return { isValid: false };\n          try {\n            if (new URL(actorUri).origin !== new URL(keyId).origin) return { isValid: false };\n            if (keyId.includes('#') && actorUri !== keyDocumentUri) return { isValid: false };\n            const parsedPublicKey = createPublicKey(key.publicKeyPem);\n            if (parsedPublicKey.asymmetricKeyType !== 'rsa') return { isValid: false };\n            return {\n              isValid: verifySignature(parsedSignature, key.publicKeyPem),\n              actorUri,\n              publicKeyPem: key.publicKeyPem\n            };\n          } catch (e) {\n            return { isValid: false };\n          }\n        })\n        .find(({ isValid }) => isValid);\n\n      return verifiedKey || { isValid: false };`,
    'HTTP signature exact key binding'
  );
  requireHash(patched, PATCHED_HASHES.httpSignatures, 'patched HTTP signature source');
  return { source: patched, changed: true };
}

function patchKeys(source) {
  if (source.includes(KEYS_MARKER)) {
    requireHash(source, PATCHED_HASHES.keys, 'patched keys source');
    return { source, changed: false };
  }

  requireHash(source, PRISTINE_HASHES.keys, 'pristine keys source');
  let patched = replaceOnce(
    source,
    "const { generateKeyPair } = require('crypto');",
    "const { generateKeyPair, createPublicKey } = require('crypto');",
    'keys crypto import'
  );
  patched = replaceOnce(
    patched,
    "const KeysService = {",
    `const REMOTE_KEY_ACCEPT = 'application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams"'; // ${KEYS_MARKER}

function hasRsaPublicKeyMaterial(key) {
  if (typeof key?.publicKeyPem !== 'string') return false;
  try {
    return createPublicKey(key.publicKeyPem).asymmetricKeyType === 'rsa';
  } catch {
    return false;
  }
}

const KeysService = {`,
    'keys service declaration'
  );
  const occurrences = patched.split("headers: { Accept: 'application/json' }").length - 1;
  if (occurrences !== 2) throw new Error(`Expected exactly two pinned SemApps remote key Accept headers, found ${occurrences}`);
  patched = patched.replaceAll("headers: { Accept: 'application/json' }", 'headers: { Accept: REMOTE_KEY_ACCEPT }');
  patched = replaceOnce(
    patched,
    `        let keyObjects = arrayOf(actor?.publicKey).concat(arrayOf(actor?.assertionMethod));`,
    `        let keyObjects = arrayOf(actor?.publicKey).concat(arrayOf(actor?.assertionMethod));\n        const directKeyDocument = (actor?.id || actor?.['@id']) === webId &&\n          typeof actor?.publicKeyPem === 'string' &&\n          typeof (actor?.controller || actor?.owner) === 'string';\n        if (keyObjects.length === 0 && directKeyDocument) keyObjects = [actor];`,
    'direct remote key document handling'
  );
  patched = replaceOnce(
    patched,
    `              return types.length === 0 || types.includes(KEY_TYPES.RSA);`,
    `              return types.length === 0 || types.includes(KEY_TYPES.RSA) || hasRsaPublicKeyMaterial(key);`,
    'generic ActivityPub Key RSA material validation'
  );
  requireHash(patched, PATCHED_HASHES.keys, 'patched keys source');
  return { source: patched, changed: true };
}

function applyPatch(root = path.dirname(require.resolve('@semapps/crypto/package.json'))) {
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  if (version !== EXPECTED_VERSION) throw new Error(`Expected @semapps/crypto@${EXPECTED_VERSION}, found ${version}`);

  for (const [relative, patch] of [
    ['signature/http-signatures.js', patchHttpSignatures],
    ['keys/keys.js', patchKeys]
  ]) {
    const file = path.join(root, relative);
    const result = patch(fs.readFileSync(file, 'utf8'));
    if (result.changed) fs.writeFileSync(file, result.source);
  }
  process.stdout.write('[ActivityPods] SemApps hs2019 RSA signature verification compatibility applied\n');
}

if (require.main === module) applyPatch();
module.exports = { EXPECTED_VERSION, LEGACY_MARKER, PREVIOUS_MARKER, MARKER, KEYS_MARKER, PRISTINE_HASHES, PATCHED_HASHES, sha256, patchHttpSignatures, patchKeys, applyPatch };
