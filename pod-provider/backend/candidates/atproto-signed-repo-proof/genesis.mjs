/**
 * Scoped ATProto v3 EMPTY repository proof. No production service imports it.
 *
 * Uses widely reviewed IPLD codecs, CAR and CID implementations; does not
 * construct a fake CID, unsigned commit, or in-memory substitute for storage.
 *
 * Security boundary: the signer and current DID-document public key must be
 * supplied by a trusted ActivityPods authority. This module never sees a
 * private key and deliberately does NOT implement arbitrary record writes.
 */
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import * as dagCbor from '@ipld/dag-cbor';
import { CarReader, CarWriter } from '@ipld/car';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';

const DID_RE = /^did:plc:[a-z2-7]{24}$/;
const TID_RE = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/;
const SORTABLE_BASE32 = '234567abcdefghijklmnopqrstuvwxyz';
const MAX_GENESIS_CAR_BYTES = 128 * 1024;

function reject(message) {
  const error = new Error(message);
  error.code = 'INVALID_ATPROTO_REPO_PROOF';
  throw error;
}

export function assertManagedDid(did) {
  if (typeof did !== 'string' || !DID_RE.test(did)) reject('Invalid managed did:plc');
  return did;
}

export function assertTid(rev) {
  if (typeof rev !== 'string' || !TID_RE.test(rev)) reject('Invalid ATProto TID revision');
  return rev;
}

/** Generate an ATProto sortable TID from microseconds and a random 10-bit clock ID. */
export function makeTid(microseconds = BigInt(Date.now()) * 1000n, clockId = crypto.randomInt(0, 1024)) {
  if (typeof microseconds !== 'bigint' ||
      microseconds < 0n || microseconds >= (1n << 53n) ||
      !Number.isSafeInteger(clockId) || clockId < 0 || clockId > 1023) {
    reject('TID timestamp or clock ID out of range');
  }
  let value = (microseconds << 10n) | BigInt(clockId);
  let encoded = '';
  for (let i = 0; i < 13; i += 1) {
    encoded = SORTABLE_BASE32[Number(value & 31n)] + encoded;
    value >>= 5n;
  }
  return assertTid(encoded);
}

function publicKey(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' || publicKeyPem.length > 8192) {
    reject('Missing or excessive commit-verification key');
  }
  let key;
  try {
    key = crypto.createPublicKey(publicKeyPem);
  } catch {
    reject('Invalid commit-verification public key');
  }
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'secp256k1') {
    reject('ATProto commit key must be secp256k1');
  }
  return key;
}

async function cidFor(bytes) {
  return CID.create(1, dagCbor.code, await sha256.digest(bytes));
}

async function writeEmptyRepoCar(commitCid, commitBytes, mstCid, mstBytes) {
  const { writer, out } = CarWriter.create([commitCid]);
  const chunks = [];
  let length = 0;
  const collect = (async () => {
    for await (const part of out) {
      length += part.length;
      if (length > MAX_GENESIS_CAR_BYTES) reject('Genesis CAR exceeds size limit');
      chunks.push(Buffer.from(part));
    }
  })();
  try {
    await writer.put({ cid: commitCid, bytes: commitBytes });
    await writer.put({ cid: mstCid, bytes: mstBytes });
  } finally {
    await writer.close();
  }
  await collect;
  return Buffer.concat(chunks, length);
}

/**
 * Create and locally verify a genuine signed v3 empty repository with
 * a non-null MST root (empty node {l:null,e:[]}) and prev:null.
 *
 * signer(unsignedCommitCbor) returns a 64-byte P1363 ECDSA signature or
 * its base64url encoding. A mock/absent signer is always rejected.
 */
export async function buildSignedEmptyRepo({ did, rev, signer, publicKeyPem }) {
  assertManagedDid(did);
  assertTid(rev);
  const key = publicKey(publicKeyPem);
  if (typeof signer !== 'function') reject('Trusted commit signer is mandatory');

  const mstBytes = dagCbor.encode({ l: null, e: [] });
  const mstCid = await cidFor(mstBytes);
  const unsignedCommit = { did, version: 3, data: mstCid, rev, prev: null };
  const unsignedBytes = dagCbor.encode(unsignedCommit);
  const answer = await signer(Buffer.from(unsignedBytes));
  let signature;
  if (typeof answer === 'string' && /^[A-Za-z0-9_-]{86}$/.test(answer)) {
    signature = Buffer.from(answer, 'base64url');
  } else if (Buffer.isBuffer(answer) || answer instanceof Uint8Array) {
    signature = Buffer.from(answer);
  } else {
    reject('Commit signer returned an invalid signature representation');
  }
  if (signature.length !== 64 ||
      !crypto.verify('sha256', Buffer.from(unsignedBytes), { key, dsaEncoding: 'ieee-p1363' }, signature)) {
    reject('Commit signature does not verify against the account key');
  }

  const commitBytes = dagCbor.encode({ ...unsignedCommit, sig: new Uint8Array(signature) });
  const commitCid = await cidFor(commitBytes);
  const carBytes = await writeEmptyRepoCar(commitCid, commitBytes, mstCid, mstBytes);
  const verified = await verifySignedEmptyRepo({ did, carBytes, publicKeyPem });
  if (verified.commitCid !== commitCid.toString() || verified.rootCid !== mstCid.toString()) {
    reject('Generated CAR does not round-trip to the intended repository head');
  }

  return Object.freeze({
    did, rev, commitCid: commitCid.toString(), rootCid: mstCid.toString(),
    commitBytes: Buffer.from(commitBytes), rootBytes: Buffer.from(mstBytes),
    carBytes
  });
}

/**
 * Content-addressed, signed read-back of a CAR; never trusts a boolean,
 * arbitrary caller CID, or identitybinding "repoInitialized" metadata.
 */
export async function verifySignedEmptyRepo({ did, carBytes, publicKeyPem }) {
  assertManagedDid(did);
  const key = publicKey(publicKeyPem);
  if (!(carBytes instanceof Uint8Array) ||
      carBytes.byteLength < 64 || carBytes.byteLength > MAX_GENESIS_CAR_BYTES) {
    reject('Invalid genesis CAR size');
  }

  let reader;
  try {
    reader = await CarReader.fromBytes(carBytes);
  } catch {
    reject('Invalid CAR format');
  }
  const roots = await reader.getRoots();
  if (roots.length !== 1) reject('Expected one CAR root');
  const commitLink = roots[0];
  const commitBlock = await reader.get(commitLink);
  if (!commitBlock) reject('CAR has no signed commit block');
  if (!(await cidFor(commitBlock.bytes)).equals(commitLink)) reject('Commit CID digest mismatch');

  let commit;
  try {
    commit = dagCbor.decode(commitBlock.bytes);
  } catch {
    reject('Signed commit is not canonical DAG-CBOR');
  }
  if (commit?.did !== did || commit?.version !== 3 || commit?.prev !== null ||
      !CID.asCID(commit?.data) || !TID_RE.test(commit?.rev || '') ||
      !(commit?.sig instanceof Uint8Array) || commit.sig.length !== 64) {
    reject('Invalid signed repository v3 commit shape');
  }
  if (!Buffer.from(dagCbor.encode(commit)).equals(Buffer.from(commitBlock.bytes))) {
    reject('Non-canonical signed commit CBOR bytes');
  }
  const { sig, ...unsigned } = commit;
  if (!crypto.verify('sha256', Buffer.from(dagCbor.encode(unsigned)),
    { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig))) {
    reject('Repository commit signature verification failed');
  }

  const mstBlock = await reader.get(commit.data);
  if (!mstBlock) reject('CAR is missing its MST root');
  if (!(await cidFor(mstBlock.bytes)).equals(commit.data)) reject('MST root CID digest mismatch');
  let mst;
  try {
    mst = dagCbor.decode(mstBlock.bytes);
  } catch {
    reject('MST root is not DAG-CBOR');
  }
  if (!mst || mst.l !== null || !Array.isArray(mst.e) || mst.e.length !== 0 ||
      Object.keys(mst).sort().join(',') !== 'e,l' ||
      !Buffer.from(dagCbor.encode(mst)).equals(Buffer.from(mstBlock.bytes))) {
    reject('MST is not a valid canonical empty node');
  }

  let count = 0;
  for await (const block of reader.blocks()) {
    count += 1;
    if (count > 2) reject('Genesis CAR contains unexpected blocks');
    if (!(await cidFor(block.bytes)).equals(block.cid)) reject('CAR block CID digest mismatch');
  }
  if (count !== 2) reject('Genesis CAR must contain signed commit and MST root');
  return Object.freeze({
    did, rev: commit.rev,
    commitCid: commitLink.toString(), rootCid: commit.data.toString(),
    valid: true
  });
}

export async function carFromBlocks({ commitCid, rootCid, commitBytes, rootBytes }) {
  if (typeof commitCid !== 'string' || typeof rootCid !== 'string' ||
      !(commitBytes instanceof Uint8Array) || !(rootBytes instanceof Uint8Array)) {
    reject('Missing durable repo blocks');
  }
  const commitLink = CID.parse(commitCid);
  const mstLink = CID.parse(rootCid);
  if (!(await cidFor(commitBytes)).equals(commitLink) ||
      !(await cidFor(rootBytes)).equals(mstLink)) {
    reject('Durable block CID mismatch');
  }
  return writeEmptyRepoCar(commitLink, commitBytes, mstLink, rootBytes);
}
