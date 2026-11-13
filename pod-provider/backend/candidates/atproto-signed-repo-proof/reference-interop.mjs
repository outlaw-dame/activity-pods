/**
 * Independent cross-implementation check using Bluesky's reference
 * @atproto/repo, not our CAR/MST parser. Executed only in disposable CI.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import * as dagCbor from '@ipld/dag-cbor';
import { buildSignedEmptyRepo, makeTid } from './genesis.mjs';
import { buildSignedSingleRecordSnapshot, verifySignedSingleRecordSnapshot } from './signed-single-record.mjs';
import { CID } from 'multiformats/cid';

const refPath = process.env.ATPROTO_REFERENCE_REPO_ENTRY;
if (!refPath || !refPath.startsWith('/')) {
  throw new Error('Pin an absolute @atproto/repo dist entry for the independent reference proof');
}
const ref = await import(pathToFileURL(refPath).href);
for (const symbol of ['MST', 'MemoryBlockstore', 'readCarWithRoot', 'parseObjByDef', 'def']) {
  if (!ref[symbol]) throw new Error('Reference @atproto/repo missing API: ' + symbol);
}

const keys = crypto.generateKeyPairSync('ec', {
  namedCurve: 'secp256k1',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const did = 'did:plc:abcdefghijklmnopqrstuvwx';
const signed = await buildSignedEmptyRepo({
  did, rev: makeTid(), publicKeyPem: keys.publicKey,
  signer: async bytes => crypto.sign('sha256', bytes, {
    key: keys.privateKey, dsaEncoding: 'ieee-p1363'
  })
});

// Independent MST encoder and block CID implementation.
const referenceTree = await ref.MST.create(new ref.MemoryBlockstore());
const referenceEmptyRoot = await referenceTree.getPointer();
assert.equal(referenceEmptyRoot.toString(), signed.rootCid,
  'our empty MST root CID must match official @atproto/repo deterministically');

// Independent CAR parser and strict v3 commit schema.
const { root, blocks } = await ref.readCarWithRoot(signed.carBytes);
assert.equal(root.toString(), signed.commitCid);
const commitBytes = blocks.get(root);
assert(commitBytes, 'Reference CAR parser must return signed commit bytes');
const parsed = ref.parseObjByDef(commitBytes, root, ref.def.commit).obj;
assert.equal(parsed.did, did);
assert.equal(parsed.version, 3);
assert.equal(parsed.prev, null);
assert.equal(parsed.data.toString(), signed.rootCid);
assert.equal(parsed.rev, signed.rev);
assert.equal(parsed.sig.length, 64);
assert(blocks.get(parsed.data), 'Reference CAR reader must find the MST block');
const { sig, ...unsigned } = parsed;
assert(crypto.verify('sha256', Buffer.from(dagCbor.encode(unsigned)),
  { key: keys.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig)),
  'Officially parsed commit must verify with the registered public key');

process.stdout.write('Reference @atproto/repo independently accepted genesis CAR, v3 commit and empty MST CID.\n');


// Distinct nonempty record interoperability: construct the exact same MST
// through the maintained @atproto/repo reference, not our one-leaf codec.
const recordPath = 'app.bsky.feed.post/3jzm3xwpf342a';
const record = {
  $type: 'app.bsky.feed.post',
  text: 'Interoperability check',
  createdAt: '2026-11-13T00:00:00.000Z'
};
const one = await buildSignedSingleRecordSnapshot({
  did, rev: makeTid(), path: recordPath, record,
  publicKeyPem: keys.publicKey,
  signer: async bytes => crypto.sign('sha256', bytes, {
    key: keys.privateKey, dsaEncoding: 'ieee-p1363'
  })
});
const officialTree = await ref.MST.create(new ref.MemoryBlockstore());
const officialWithRecord = await officialTree.add(recordPath, CID.parse(one.recordCid));
const officialSingleRoot = await officialWithRecord.getPointer();
assert.equal(officialSingleRoot.toString(), one.rootCid,
  'single-leaf MST encoding must have the reference implementation CID');
const officialRecord = await officialWithRecord.get(recordPath);
assert.equal(officialRecord?.toString(), one.recordCid);
const officialCar = await ref.readCarWithRoot(one.carBytes);
assert.equal(officialCar.root.toString(), one.commitCid);
const officialCommit = ref.parseObjByDef(
  officialCar.blocks.get(officialCar.root), officialCar.root, ref.def.commit
).obj;
assert.equal(officialCommit.prev, null);
assert.equal(officialCommit.data.toString(), one.rootCid);
assert.equal(officialCommit.rev, one.rev);
assert.equal(officialCar.blocks.get(officialCommit.data).length > 0, true);
const checkedRecord = await verifySignedSingleRecordSnapshot({
  did, carBytes: one.carBytes, publicKeyPem: keys.publicKey
});
assert.equal(checkedRecord.recordCid, one.recordCid);
assert.equal(checkedRecord.path, recordPath);
const backToEmpty = await officialWithRecord.delete(recordPath);
assert.equal((await backToEmpty.getPointer()).toString(), signed.rootCid,
  'reference delete must restore the exact empty-MST root');
process.stdout.write(
  'Reference @atproto/repo accepted canonical one-leaf signed CAR, record and deletion.\\n'
);
