'use strict';

const { MoleculerError } = require('moleculer').Errors;

const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const NULL_BYTE = 0xf6;

function fail(message, type = 'INVALID_INPUT', code = 400, data) {
  throw new MoleculerError(message, code, type, data);
}

function decodeCanonicalBase64(value, fieldName) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2 * 1024 * 1024) {
    fail(`${fieldName} must be a bounded canonical base64 string`);
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    fail(`${fieldName} is not canonical base64`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0 || bytes.toString('base64') !== value) {
    fail(`${fieldName} is not canonical base64`);
  }
  return bytes;
}

function normalizeOriginUrl(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
    if (parsed.pathname !== '/' || parsed.search || parsed.hash) return null;
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

function assertAuthorizedMockRepoCommit({ bytes, binding, suppliedDid, suppliedRev }) {
  if (
    !binding?.repoInitialized ||
    !binding?.repoRootCid ||
    binding.repoRev === null ||
    binding.repoRev === undefined ||
    !binding.atprotoDid
  ) {
    fail('Repository state is not initialized for signing', 'REPO_STATE_UNAVAILABLE', 409);
  }

  let commit;
  try {
    commit = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('Current repository signer only accepts the bounded JSON commit skeleton');
  }
  if (!commit || typeof commit !== 'object' || Array.isArray(commit)) {
    fail('Commit must decode to an object');
  }

  const keys = Object.keys(commit);
  const expectedKeys = ['did', 'version', 'data', 'rev', 'prev'];
  if (keys.length !== expectedKeys.length || expectedKeys.some(key => !Object.hasOwn(commit, key))) {
    fail('Commit contains an unsupported field set');
  }

  const currentRev = Number.parseInt(String(binding.repoRev), 10);
  if (!Number.isSafeInteger(currentRev) || currentRev < 0) {
    fail('Current mock repository revision is not a non-negative integer', 'REPO_STATE_UNAVAILABLE', 409);
  }
  const expectedRev = String(currentRev + 1);

  if (suppliedDid !== binding.atprotoDid || commit.did !== binding.atprotoDid) {
    fail('Commit DID does not match the authoritative binding');
  }
  if (suppliedRev !== expectedRev || commit.rev !== expectedRev) {
    fail('Commit revision does not advance the authoritative repository revision by exactly one');
  }
  if (commit.prev !== binding.repoRootCid) {
    fail('Commit prev does not match the authoritative repository root');
  }
  if (commit.version !== 3 || typeof commit.data !== 'string' || commit.data.length === 0 || commit.data.length > 512) {
    fail('Commit version/data are invalid');
  }

  const canonical = Buffer.from(JSON.stringify({
    did: commit.did,
    version: 3,
    data: commit.data,
    rev: commit.rev,
    prev: commit.prev
  }), 'utf8');
  if (!canonical.equals(bytes)) {
    fail('Commit bytes are not in the canonical current-builder representation');
  }
}

function encodeTypeAndLength(major, len) {
  const head = major << 5;
  if (len < 24) return Buffer.from([head | len]);
  if (len < 256) return Buffer.from([head | 24, len]);
  if (len < 65536) {
    const out = Buffer.alloc(3);
    out[0] = head | 25;
    out.writeUInt16BE(len, 1);
    return out;
  }
  if (len < 4294967296) {
    const out = Buffer.alloc(5);
    out[0] = head | 26;
    out.writeUInt32BE(len, 1);
    return out;
  }
  fail('CBOR length out of range', 'CBOR_ENCODE_OVERFLOW', 500);
}

function encodeText(value) {
  if (typeof value !== 'string') fail('CBOR expected string', 'CBOR_ENCODE_TYPE', 500);
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([encodeTypeAndLength(MAJOR_TEXT, bytes.length), bytes]);
}

function encodeAny(value) {
  if (value === null) return Buffer.from([NULL_BYTE]);
  if (typeof value === 'string') return encodeText(value);
  if (Array.isArray(value)) {
    return Buffer.concat([
      encodeTypeAndLength(MAJOR_ARRAY, value.length),
      ...value.map(encodeAny)
    ]);
  }
  if (typeof value === 'object') return encodeMap(value);
  fail(`CBOR unsupported type ${typeof value}`, 'CBOR_ENCODE_UNSUPPORTED', 500);
}

function encodeMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('CBOR expected object', 'CBOR_ENCODE_TYPE', 500);
  }
  const entries = Object.entries(value).map(([key, item]) => ({
    keyBytes: Buffer.from(key, 'utf8'),
    item
  }));
  entries.sort((left, right) => {
    if (left.keyBytes.length !== right.keyBytes.length) return left.keyBytes.length - right.keyBytes.length;
    return Buffer.compare(left.keyBytes, right.keyBytes);
  });

  const parts = [encodeTypeAndLength(MAJOR_MAP, entries.length)];
  for (const { keyBytes, item } of entries) {
    parts.push(encodeTypeAndLength(MAJOR_TEXT, keyBytes.length), keyBytes, encodeAny(item));
  }
  return Buffer.concat(parts);
}

function buildExpectedPlcGenesis({ binding, rotationKeyMultibase, verificationKeyMultibase }) {
  if (
    binding?.status !== 'pending-plc' ||
    binding.atprotoDid ||
    binding.atprotoSource !== 'local' ||
    binding.atprotoManaged !== true ||
    !binding.atprotoHandle ||
    !binding.atprotoPdsUrl
  ) {
    fail('Binding is not an authorized pending PLC genesis state', 'PLC_TRANSITION_NOT_AUTHORIZED', 409);
  }

  const pdsEndpoint = normalizeOriginUrl(binding.atprotoPdsUrl);
  if (!pdsEndpoint) {
    fail('Pending PLC PDS endpoint is not an origin-only HTTP(S) URL', 'PLC_TRANSITION_NOT_AUTHORIZED', 409);
  }
  if (!/^z[1-9A-HJ-NP-Za-km-z]+$/.test(rotationKeyMultibase) ||
      !/^z[1-9A-HJ-NP-Za-km-z]+$/.test(verificationKeyMultibase)) {
    fail('Pending PLC public keys are not valid base58btc multibase values', 'KEY_UNAVAILABLE', 500);
  }

  return {
    type: 'plc_operation',
    rotationKeys: [`did:key:${rotationKeyMultibase}`],
    verificationMethods: { atproto: `did:key:${verificationKeyMultibase}` },
    alsoKnownAs: [`at://${binding.atprotoHandle}`],
    services: {
      atproto_pds: {
        type: 'AtprotoPersonalDataServer',
        endpoint: pdsEndpoint
      }
    },
    prev: null
  };
}

function assertAuthorizedPlcGenesis({ bytes, binding, rotationKeyMultibase, verificationKeyMultibase }) {
  const expected = encodeMap(buildExpectedPlcGenesis({
    binding,
    rotationKeyMultibase,
    verificationKeyMultibase
  }));
  if (!expected.equals(bytes)) {
    fail(
      'PLC operation does not exactly match the authorized pending genesis transition',
      'PLC_TRANSITION_NOT_AUTHORIZED',
      403
    );
  }
}

module.exports = {
  assertAuthorizedMockRepoCommit,
  assertAuthorizedPlcGenesis,
  buildExpectedPlcGenesis,
  decodeCanonicalBase64,
  encodeCanonicalCbor: encodeAny,
  normalizeOriginUrl
};