/**
 * Nonactivated AT Protocol v3 single-record repository snapshot.
 *
 * This is a deliberately bounded MST subset: zero or ONE leaf only.
 * The on-wire node encoding is the canonical ATProto one-leaf MST, validated
 * independently by the reference @atproto/repo in the CI suite. Never
 * interpret it as a general-purpose multi-record MST or enable XRPC writes.
 */
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import * as cbor from '@ipld/dag-cbor';
import { CarReader, CarWriter } from '@ipld/car';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { assertManagedDid, assertTid, normalizeK256LowS } from './genesis.mjs';

const MAX_CAR = 128 * 1024;
const MAX_RECORD = 16 * 1024;
const PATH = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}\/[A-Za-z0-9_~.:-][A-Za-z0-9_~.:-]{0,510}$/u;
const MAX_PATH = 1024;
const K256 = 'secp256k1';

function deny(code) {
  const e = new Error('Signed single-record repository evidence invalid');
  e.code = code;
  throw e;
}
export function checkRecordPath(path) {
  if (typeof path !== 'string' || path.length > MAX_PATH ||
      !PATH.test(path) || path.includes('..') || path.split('/').length !== 2 ||
      !/^[a-zA-Z][a-zA-Z0-9.-]*[a-zA-Z0-9]$/u.test(path.split('/')[0])) {
    deny('SINGLE_RECORD_PATH_INVALID');
  }
  return path;
}
export async function cid(bytes) {
  return CID.create(1, cbor.code, await sha256.digest(bytes));
}
function keyFor(pem) {
  try {
    if (typeof pem !== 'string' || pem.length > 4096) deny('SINGLE_RECORD_KEY_INVALID');
    const key = crypto.createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ec' ||
        key.asymmetricKeyDetails?.namedCurve !== K256) {
      deny('SINGLE_RECORD_KEY_INVALID');
    }
    return key;
  } catch { deny('SINGLE_RECORD_KEY_INVALID'); }
}
export function decodeCanonical(bytes) {
  let decoded;
  try { decoded = cbor.decode(bytes); }
  catch { deny('SINGLE_RECORD_CBOR_INVALID'); }
  if (!Buffer.from(cbor.encode(decoded)).equals(Buffer.from(bytes))) {
    deny('SINGLE_RECORD_NONCANONICAL_CBOR');
  }
  return decoded;
}
export function checkRecord(record, path) {
  if (!record || typeof record !== 'object' || Array.isArray(record) ||
      record.$type !== path.split('/')[0]) {
    deny('SINGLE_RECORD_LEXICON_MISMATCH');
  }
  let bytes;
  try { bytes = Buffer.from(cbor.encode(record)); }
  catch { deny('SINGLE_RECORD_CBOR_INVALID'); }
  if (!bytes.length || bytes.length > MAX_RECORD) deny('SINGLE_RECORD_SIZE_INVALID');
  const roundtrip = decodeCanonical(bytes);
  if (roundtrip.$type !== record.$type) deny('SINGLE_RECORD_LEXICON_MISMATCH');
  return bytes;
}
export function signatureFrom(answer) {
  let bytes;
  if (typeof answer === 'string' && /^[A-Za-z0-9_-]{86}$/u.test(answer)) {
    bytes = Buffer.from(answer, 'base64url');
    if (bytes.toString('base64url') !== answer) deny('SINGLE_RECORD_SIGNER_INVALID');
  } else if (answer instanceof Uint8Array) bytes = Buffer.from(answer);
  else deny('SINGLE_RECORD_SIGNER_INVALID');
  try { return normalizeK256LowS(bytes); }
  catch { deny('SINGLE_RECORD_SIGNER_INVALID'); }
}
async function carFor(blocks) {
  const { writer, out } = CarWriter.create([blocks[0].cid]);
  const parts = [];
  let size = 0;
  const collect = (async () => {
    for await (const chunk of out) {
      size += chunk.byteLength;
      if (size > MAX_CAR) deny('SINGLE_RECORD_CAR_TOO_LARGE');
      parts.push(Buffer.from(chunk));
    }
  })();
  try {
    for (const block of blocks) await writer.put(block);
  } finally {
    await writer.close();
  }
  await collect;
  return Buffer.concat(parts, size);
}
/**
 * Build a canonical signed v3 snapshot for an empty or single-record MST.
 * The v3 prev field MUST exist, and is null (ATProto reference behavior);
 * revision progression is checked against the PostgreSQL preceding head.
 */
export async function buildSignedSingleRecordSnapshot({
  did, rev, path = null, record = null, signer, publicKeyPem
}) {
  assertManagedDid(did);
  assertTid(rev);
  const verifyingKey = keyFor(publicKeyPem);
  if (typeof signer !== 'function') deny('SINGLE_RECORD_SIGNER_REQUIRED');
  if (path !== null) checkRecordPath(path);
  if ((path === null) !== (record === null)) deny('SINGLE_RECORD_STATE_INVALID');
  let recordBlock = null;
  let mst;
  if (record !== null) {
    const recordBytes = checkRecord(record, path);
    const recordCid = await cid(recordBytes);
    recordBlock = { cid: recordCid, bytes: recordBytes };
    // Exact canonical single-leaf encoding: no left/right subtree, no
    // prefix from a preceding leaf, and an explicit null subtree link.
    mst = { l: null, e: [{
      p: 0, k: new Uint8Array(Buffer.from(path, 'ascii')),
      v: recordCid, t: null
    }] };
  } else {
    mst = { l: null, e: [] };
  }
  const mstBytes = Buffer.from(cbor.encode(mst));
  const rootCid = await cid(mstBytes);
  const unsigned = { did, version: 3, data: rootCid, rev, prev: null };
  const unsignedBytes = Buffer.from(cbor.encode(unsigned));
  const signature = signatureFrom(await signer(unsignedBytes));
  if (!crypto.verify('sha256', unsignedBytes,
    { key: verifyingKey, dsaEncoding: 'ieee-p1363' }, signature)) {
    deny('SINGLE_RECORD_SIGNATURE_MISMATCH');
  }
  const commitBytes = Buffer.from(cbor.encode({
    ...unsigned, sig: new Uint8Array(signature)
  }));
  const commitCid = await cid(commitBytes);
  const blocks = [
    { cid: commitCid, bytes: commitBytes },
    { cid: rootCid, bytes: mstBytes },
    ...(recordBlock ? [recordBlock] : [])
  ];
  const carBytes = await carFor(blocks);
  const verified = await verifySignedSingleRecordSnapshot({
    did, publicKeyPem, carBytes
  });
  if (verified.commitCid !== commitCid.toString() ||
      verified.rootCid !== rootCid.toString()) {
    deny('SINGLE_RECORD_SELF_VERIFY_FAILED');
  }
  return Object.freeze({
    did, rev, commitCid: commitCid.toString(), rootCid: rootCid.toString(),
    recordCid: recordBlock?.cid.toString() ?? null, path,
    blocks: Object.freeze(blocks.map(b => Object.freeze({
      cid: b.cid.toString(), bytes: Buffer.from(b.bytes)
    }))),
    carBytes
  });
}

/** Checks complete CID-addressed CAR blocks, signature, canonical tree & record. */
export async function verifySignedSingleRecordSnapshot({
  did, publicKeyPem, carBytes
}) {
  assertManagedDid(did);
  const key = keyFor(publicKeyPem);
  if (!(carBytes instanceof Uint8Array) || carBytes.length < 64 ||
      carBytes.length > MAX_CAR) deny('SINGLE_RECORD_CAR_INVALID');
  let reader;
  try { reader = await CarReader.fromBytes(carBytes); }
  catch { deny('SINGLE_RECORD_CAR_INVALID'); }
  const roots = await reader.getRoots();
  if (roots.length !== 1) deny('SINGLE_RECORD_CAR_ROOT_INVALID');
  const blocks = new Map();
  for await (const block of reader.blocks()) {
    if (blocks.size >= 3 || blocks.has(block.cid.toString()) ||
        !(await cid(block.bytes)).equals(block.cid)) {
      deny('SINGLE_RECORD_CAR_BLOCK_INVALID');
    }
    blocks.set(block.cid.toString(), Buffer.from(block.bytes));
  }
  const commitCid = roots[0].toString();
  const commitBytes = blocks.get(commitCid);
  if (!commitBytes) deny('SINGLE_RECORD_COMMIT_MISSING');
  const commit = decodeCanonical(commitBytes);
  if (!commit || commit.did !== did || commit.version !== 3 ||
      commit.prev !== null || !CID.asCID(commit.data) ||
      typeof commit.rev !== 'string' ||
      !(commit.sig instanceof Uint8Array) || commit.sig.length !== 64 ||
      Object.keys(commit).sort().join(',') !== 'data,did,prev,rev,sig,version') {
    deny('SINGLE_RECORD_COMMIT_INVALID');
  }
  assertTid(commit.rev);
  let lowS;
  try { lowS = normalizeK256LowS(commit.sig); }
  catch { deny('SINGLE_RECORD_SIGNATURE_INVALID'); }
  if (!Buffer.from(lowS).equals(Buffer.from(commit.sig))) {
    deny('SINGLE_RECORD_SIGNATURE_NONCANONICAL');
  }
  const { sig, ...unsigned } = commit;
  if (!crypto.verify('sha256', Buffer.from(cbor.encode(unsigned)),
    { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig))) {
    deny('SINGLE_RECORD_SIGNATURE_INVALID');
  }
  const rootCid = commit.data.toString();
  const mstBytes = blocks.get(rootCid);
  if (!mstBytes) deny('SINGLE_RECORD_ROOT_MISSING');
  const tree = decodeCanonical(mstBytes);
  if (!tree || tree.l !== null || !Array.isArray(tree.e) ||
      tree.e.length > 1 || Object.keys(tree).sort().join(',') !== 'e,l') {
    deny('SINGLE_RECORD_MST_INVALID');
  }
  let path = null, recordCid = null;
  if (tree.e.length) {
    const leaf = tree.e[0];
    if (!leaf || leaf.p !== 0 || leaf.t !== null ||
        !CID.asCID(leaf.v) || !(leaf.k instanceof Uint8Array) ||
        Object.keys(leaf).sort().join(',') !== 'k,p,t,v') {
      deny('SINGLE_RECORD_MST_INVALID');
    }
    path = Buffer.from(leaf.k).toString('ascii');
    checkRecordPath(path);
    if (!Buffer.from(path, 'ascii').equals(Buffer.from(leaf.k))) {
      deny('SINGLE_RECORD_MST_INVALID');
    }
    recordCid = leaf.v.toString();
    const recordBytes = blocks.get(recordCid);
    if (!recordBytes || recordBytes.length > MAX_RECORD) {
      deny('SINGLE_RECORD_RECORD_MISSING');
    }
    checkRecord(decodeCanonical(recordBytes), path);
  }
  if (blocks.size !== (path === null ? 2 : 3)) {
    deny('SINGLE_RECORD_CAR_BLOCK_INVALID');
  }
  return Object.freeze({
    verified: true, did, rev: commit.rev, commitCid, rootCid,
    path, recordCid, carBytes: Buffer.from(carBytes)
  });
}

export async function carFromSingleRecordBlocks({
  commitCid, rootCid, commitBytes, rootBytes, recordCid = null, recordBytes = null
}) {
  const refs = [
    { cid: commitCid, bytes: commitBytes },
    { cid: rootCid, bytes: rootBytes },
    ...(recordCid && recordBytes ? [{ cid: recordCid, bytes: recordBytes }] : [])
  ];
  const blocks = [];
  for (const ref of refs) {
    if (typeof ref.cid !== 'string' || !(ref.bytes instanceof Uint8Array)) {
      deny('SINGLE_RECORD_DURABLE_BLOCK_INVALID');
    }
    let link;
    try { link = CID.parse(ref.cid); }
    catch { deny('SINGLE_RECORD_DURABLE_BLOCK_INVALID'); }
    if (!(await cid(ref.bytes)).equals(link)) {
      deny('SINGLE_RECORD_DURABLE_BLOCK_INVALID');
    }
    blocks.push({ cid: link, bytes: Buffer.from(ref.bytes) });
  }
  return carFor(blocks);
}
