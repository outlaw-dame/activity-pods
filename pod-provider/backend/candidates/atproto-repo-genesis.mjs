/**
 * NON-ACTIVATED signed repository genesis with the official @atproto/repo
 * implementation. No second private signing key: signing is delegated to the
 * existing ActivityPods canonical-account signing service.
 *
 * A signed CAR proves an AT Protocol v3 repository exists, but until the
 * server also exposes sync.getRepo/getLatestCommit, authenticated writes,
 * blob support and subscription sequencing it is NOT a deployable PDS.
 */
import { Repo, MemoryBlockstore, readCarWithRoot, blocksToCarFile, verifyCommitSig } from '@atproto/repo';
import { decode as decodeCbor } from '@atproto/lex-cbor';

const DID_PATTERN = /^did:plc:[a-z2-7]{24}$/;
const KEY_PATTERN = /^did:key:z[1-9A-HJ-NP-Za-km-z]{30,160}$/;
const MAX_GENESIS_CAR_BYTES = 256 * 1024;
const MAX_GENESIS_BLOCKS = 8;
const TID_PATTERN = /^[234567abcdefghij][234567abcdefghij]{12}$/;

function assert(condition, code) {
  if (!condition) {
    const error = new Error(code);
    error.code = code;
    throw error;
  }
}

/**
 * The signer interface uses only the public key DID plus a remote callback:
 * { keyDid: "did:key:...", sign: async (Uint8Array) => Uint8Array }
 * Never pass a private key or account password across this boundary.
 */
export async function generateSignedGenesis({ did, signer, revOverride } = {}) {
  assert(typeof did === 'string' && DID_PATTERN.test(did), 'REPO_GENESIS_INVALID_DID');
  assert(signer && KEY_PATTERN.test(signer.keyDid) && typeof signer.sign === 'function',
    'REPO_GENESIS_INVALID_SIGNER');
  assert(revOverride === undefined || (typeof revOverride === 'string' && TID_PATTERN.test(revOverride)),
    'REPO_GENESIS_INVALID_REV');
  let signingCalls = 0;
  const delegatedSigner = {
    jwtAlg: 'ES256K',
    did: () => signer.keyDid,
    async sign(bytes) {
      assert(bytes instanceof Uint8Array && bytes.byteLength <= 4096,
        'REPO_GENESIS_INVALID_SIGNING_BYTES');
      signingCalls += 1;
      assert(signingCalls === 1, 'REPO_GENESIS_MULTIPLE_SIGNATURES');
      const sig = await signer.sign(new Uint8Array(bytes));
      assert(sig instanceof Uint8Array && sig.byteLength === 64,
        'REPO_GENESIS_INVALID_SIGNATURE');
      return sig;
    }
  };
  const commit = await Repo.formatInitCommit(
    new MemoryBlockstore(), did, delegatedSigner, [], revOverride
  );
  assert(signingCalls === 1 && commit.newBlocks.size <= MAX_GENESIS_BLOCKS,
    'REPO_GENESIS_SIZE_LIMIT');
  const signedBytes = commit.newBlocks.get(commit.cid);
  assert(signedBytes instanceof Uint8Array, 'REPO_GENESIS_MISSING_COMMIT');
  const decoded = decodeCbor(signedBytes);
  assert(decoded && decoded.did === did && decoded.version === 3 &&
      decoded.prev === null && decoded.rev === commit.rev &&
      decoded.sig instanceof Uint8Array && decoded.sig.byteLength === 64,
    'REPO_GENESIS_INVALID_COMMIT');
  let signatureVerified = false;
  try {
    signatureVerified = await verifyCommitSig(decoded, signer.keyDid);
  } catch (_) {
    // Official cryptographic verifiers may throw for invalid r/s scalars
    // rather than return false; both outcomes must fail closed.
    signatureVerified = false;
  }
  assert(signatureVerified === true, 'REPO_GENESIS_SIGNATURE_NOT_VERIFIED');
  const car = await blocksToCarFile(commit.cid, commit.newBlocks);
  assert(car.byteLength > 0 && car.byteLength <= MAX_GENESIS_CAR_BYTES,
    'REPO_GENESIS_SIZE_LIMIT');
  // Parses the official CAR format and rehashes EVERY contained block. It
  // catches a mismatched CID, a missing root or malformed block encoding.
  const parsed = await readCarWithRoot(car);
  assert(parsed.root.equals(commit.cid) &&
      parsed.blocks.size === commit.newBlocks.size &&
      parsed.blocks.get(commit.cid)?.byteLength === signedBytes.byteLength,
    'REPO_GENESIS_CAR_INTEGRITY_FAILED');
  return Object.freeze({
    did, keyDid: signer.keyDid,
    rootCid: commit.cid.toString(),
    rev: commit.rev,
    car: Buffer.from(car),
    blockCount: commit.newBlocks.size
  });
}

/** Build a delegate against ActivityPods' existing signing service.
 * The caller MUST have already checked authorized provider+WebID+PLC state.
 * The service authenticates callers and resolves the canonical binding.
 */
export async function delegatedActivityPodsSigner({ call, canonicalAccountId, did, meta } = {}) {
  assert(typeof call === 'function' && typeof canonicalAccountId === 'string' &&
    DID_PATTERN.test(did), 'REPO_GENESIS_INVALID_AUTHORITY');
  const publicKey = await call('signing.getAtprotoPublicKey', {
    canonicalAccountId, purpose: 'commit'
  }, meta);
  assert(publicKey && typeof publicKey.publicKeyMultibase === 'string',
    'REPO_GENESIS_SIGNER_UNAVAILABLE');
  const keyDid = `did:key:${publicKey.publicKeyMultibase}`;
  assert(KEY_PATTERN.test(keyDid), 'REPO_GENESIS_INVALID_SIGNER');
  return {
    keyDid,
    async sign(bytes) {
      const unsignedCommit = decodeCbor(bytes);
      assert(unsignedCommit && unsignedCommit.did === did &&
        unsignedCommit.version === 3 &&
        unsignedCommit.prev === null &&
        typeof unsignedCommit.rev === 'string',
      'REPO_GENESIS_UNEXPECTED_SIGN_INPUT');
      const signed = await call('signing.signAtprotoCommit', {
        canonicalAccountId,
        did,
        rev: unsignedCommit.rev,
        unsignedCommitBytesBase64: Buffer.from(bytes).toString('base64')
      }, meta);
      assert(signed && signed.did === did &&
        signed.algorithm === 'k256' &&
        typeof signed.signatureBase64Url === 'string',
      'REPO_GENESIS_SIGNER_UNAVAILABLE');
      const signature = Buffer.from(signed.signatureBase64Url, 'base64url');
      assert(signature.byteLength === 64, 'REPO_GENESIS_INVALID_SIGNATURE');
      return new Uint8Array(signature);
    }
  };
}


/**
 * Independently validate an externally stored genesis CAR. Caller must
 * obtain trustedKeyDid from the resolved and checked PLC DID document,
 * never from a request payload. This proves signing *and* content hashing.
 * It does not prove any PDS XRPC endpoint serves the repository.
 */
export async function verifySignedGenesisEvidence({
  did, rootCid, rev, car, trustedKeyDid
} = {}) {
  assert(DID_PATTERN.test(did || '') && KEY_PATTERN.test(trustedKeyDid || ''),
    'REPO_GENESIS_INVALID_AUTHORITY');
  assert(typeof rootCid === 'string' && rootCid.startsWith('bafy') &&
      typeof rev === 'string' && rev.length >= 12,
  'REPO_GENESIS_INVALID_CLAIM');
  assert((car instanceof Uint8Array || Buffer.isBuffer(car)) &&
      car.byteLength > 0 && car.byteLength <= MAX_GENESIS_CAR_BYTES,
  'REPO_GENESIS_SIZE_LIMIT');
  let parsed, commit;
  try {
    parsed = await readCarWithRoot(car);
    assert(parsed.root.toString() === rootCid &&
        parsed.blocks.size >= 2 && parsed.blocks.size <= MAX_GENESIS_BLOCKS,
      'REPO_GENESIS_CAR_INTEGRITY_FAILED');
    const bytes = parsed.blocks.get(parsed.root);
    assert(bytes instanceof Uint8Array, 'REPO_GENESIS_MISSING_COMMIT');
    commit = decodeCbor(bytes);
  } catch (error) {
    assert(false, error?.code || 'REPO_GENESIS_CAR_INTEGRITY_FAILED');
  }
  assert(commit && commit.did === did && commit.version === 3 &&
      commit.rev === rev && commit.prev === null &&
      commit.sig instanceof Uint8Array && commit.sig.byteLength === 64,
  'REPO_GENESIS_INVALID_COMMIT');
  let verified = false;
  try { verified = await verifyCommitSig(commit, trustedKeyDid); }
  catch (_) { verified = false; }
  assert(verified === true, 'REPO_GENESIS_SIGNATURE_NOT_VERIFIED');
  return Object.freeze({
    did, rootCid, rev, keyDid: trustedKeyDid,
    car: Buffer.from(car)
  });
}
