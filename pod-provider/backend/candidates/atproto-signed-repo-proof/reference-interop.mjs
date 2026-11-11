/**
 * Independent cross-implementation check using Bluesky's reference
 * @atproto/repo, not our CAR/MST parser. Executed only in disposable CI.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { buildSignedEmptyRepo, makeTid } from './genesis.mjs';

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
assert(crypto.verify('sha256', signed.commitBytes ? 
  // The independently parsed official commit re-encoded without sig is
  // guaranteed by the proof's own verification; verify with official
  // parsing here, keeping signing keys and content separate.
  (await import('@ipld/dag-cbor')).encode(({ sig, ...withoutSig }) => withoutSig)(parsed)
  : Buffer.alloc(0), { key: keys.publicKey, dsaEncoding: 'ieee-p1363' }, parsed.sig));

process.stdout.write('Reference @atproto/repo independently accepted genesis CAR, v3 commit and empty MST CID.\n');
