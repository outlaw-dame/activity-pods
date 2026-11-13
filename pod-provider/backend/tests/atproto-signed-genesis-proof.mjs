import assert from 'node:assert/strict';
import { Secp256k1Keypair } from '@atproto/crypto';
import { readCarWithRoot } from '@atproto/repo';
import { generateSignedGenesis, delegatedActivityPodsSigner } from '../candidates/atproto-repo-genesis.mjs';

const did = 'did:plc:abcdefghijklmnopqrstuvwx';
const webId = 'https://pods.example/alice';
const key = await Secp256k1Keypair.create({ exportable: false });
const fixtureCall = async (action, payload) => {
  assert.equal(payload.canonicalAccountId, webId);
  if (action === 'signing.getAtprotoPublicKey') {
    assert.equal(payload.purpose, 'commit');
    return { did, publicKeyMultibase: key.did().replace('did:key:', '') };
  }
  if (action === 'signing.signAtprotoCommit') {
    assert.equal(payload.did, did);
    assert(typeof payload.rev === 'string');
    const signedBytes = await key.sign(Buffer.from(payload.unsignedCommitBytesBase64, 'base64'));
    return {
      did,
      algorithm: 'k256',
      signatureBase64Url: Buffer.from(signedBytes).toString('base64url')
    };
  }
  throw new Error('Unexpected service call');
};
const signer = await delegatedActivityPodsSigner({
  call: fixtureCall,
  canonicalAccountId: webId, did
});
const genesis = await generateSignedGenesis({did,signer});
assert(genesis.rootCid.startsWith('bafy'));
assert.equal(genesis.did,did);
assert(genesis.rev.length>=12);
assert(genesis.car.byteLength < 256*1024);
const parsed=await readCarWithRoot(genesis.car);
assert.equal(parsed.root.toString(),genesis.rootCid);
assert.equal(parsed.blocks.size,genesis.blockCount);
console.log('atproto_signed_repo_genesis_car_and_signature_passed');

await assert.rejects(
  generateSignedGenesis({ did:'did:web:evil.example', signer }),
  err=>err.code==='REPO_GENESIS_INVALID_DID'
);
await assert.rejects(
  generateSignedGenesis({
    did, signer: {
      keyDid: signer.keyDid,
      sign: async () => new Uint8Array(64)
    }
  }),
  err=>err.code==='REPO_GENESIS_SIGNATURE_NOT_VERIFIED'
);
await assert.rejects(
  generateSignedGenesis({
    did, signer: {
      keyDid: signer.keyDid,
      sign: async () => new Uint8Array(1)
    }
  }),
  err=>err.code==='REPO_GENESIS_INVALID_SIGNATURE'
);
await assert.rejects(
  delegatedActivityPodsSigner({
    did, canonicalAccountId:webId,
    call: async name => {
      if (name==='signing.getAtprotoPublicKey')
        return { publicKeyMultibase:'not-a-real-key' };
      throw new Error('Unexpected');
    }
  }),
  err=>err.code==='REPO_GENESIS_INVALID_SIGNER'
);
await assert.rejects(
  delegatedActivityPodsSigner({
    did,canonicalAccountId:webId,
    call:async name=>{
      if(name==='signing.getAtprotoPublicKey')
        return {publicKeyMultibase:key.did().replace('did:key:','')};
      return {did:'did:plc:wrongwrongwrongwrongwrongwr',algorithm:'k256',signatureBase64Url:'a'.repeat(88)};
    }
  }).then(s=>generateSignedGenesis({did,signer:s})),
  err=>err.code==='REPO_GENESIS_SIGNER_UNAVAILABLE'
);
console.log('atproto_signed_repo_rejection_cases_passed');
