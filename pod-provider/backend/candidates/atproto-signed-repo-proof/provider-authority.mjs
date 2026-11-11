/**
 * NOT ACTIVATED. Provider-owned, signed genesis authority adapter for PR #139.
 * The caller supplies an account claim, never a DID, signing key or network
 * document to be trusted. Every claim is checked against current protected RDF
 * binding and independently resolved PLC + handle state before signing.
 *
 * The injected functions MUST be trusted provider-side implementations. There
 * is deliberately no HTTP route, token fallback, or production enable switch.
 */
import crypto from 'node:crypto';
import { base58btc } from 'multiformats/bases/base58';
import { assertManagedDid } from './genesis.mjs';

const SPKI_UNCOMPRESSED_SECP256K1 = Buffer.from('3056301006072a8648ce3d020106052b8104000a034200', 'hex');
const MAX_ACCOUNT_LENGTH = 2048;
const HANDLE_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function refusal(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function canonicalAccount(accountId) {
  if (typeof accountId !== 'string' || accountId.length > MAX_ACCOUNT_LENGTH) {
    refusal('MANAGED_REPO_ACCOUNT_INVALID', 'Invalid managed repository account');
  }
  let parsed;
  try {
    parsed = new URL(accountId);
  } catch {
    refusal('MANAGED_REPO_ACCOUNT_INVALID', 'Invalid managed repository account URL');
  }
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.href !== accountId ||
      parsed.search || parsed.hash || parsed.username || parsed.password) {
    refusal('MANAGED_REPO_ACCOUNT_INVALID', 'Account must be a canonical HTTPS WebID');
  }
  return accountId;
}

function checkedHandle(handle) {
  if (typeof handle !== 'string' || handle.length > 244 || !HANDLE_RE.test(handle)) {
    refusal('MANAGED_REPO_HANDLE_INVALID', 'Invalid normalized ATProto handle');
  }
  return handle;
}

function checkedPds(endpoint) {
  let url;
  try {
    url = new URL(endpoint);
  } catch {
    refusal('MANAGED_REPO_PDS_INVALID', 'Missing trusted PDS origin');
  }
  if (url.protocol !== 'https:' || !url.hostname || url.origin !== endpoint ||
      url.username || url.password || url.port === '0') {
    refusal('MANAGED_REPO_PDS_INVALID', 'Managed PDS endpoint must be HTTPS origin');
  }
  return endpoint;
}

function requireDependency(name, fn) {
  if (typeof fn !== 'function') refusal('MANAGED_REPO_CONFIGURATION_INVALID', 'Missing provider dependency: ' + name);
  return fn;
}

/**
 * Resolve a PEM key from the provider-returned public multibase representation.
 * No private key ever enters this authority adapter or PostgreSQL.
 */
export function publicKeyPemFromMultibase(value) {
  if (typeof value !== 'string' || value.length > 128 || !value.startsWith('z')) {
    refusal('MANAGED_REPO_PUBLIC_KEY_INVALID', 'Expected secp256k1 public multibase');
  }
  let raw;
  try {
    raw = Buffer.from(base58btc.decode(value));
  } catch {
    refusal('MANAGED_REPO_PUBLIC_KEY_INVALID', 'Invalid base58btc public key');
  }
  if (raw.length !== 35 || raw[0] !== 0xe7 || raw[1] !== 0x01 ||
      (raw[2] !== 0x02 && raw[2] !== 0x03)) {
    refusal('MANAGED_REPO_PUBLIC_KEY_INVALID', 'Wrong signing public key multicodec');
  }
  try {
    const fullPoint = crypto.ECDH.convertKey(raw.subarray(2), 'secp256k1', undefined, undefined, 'uncompressed');
    const der = Buffer.concat([SPKI_UNCOMPRESSED_SECP256K1, fullPoint]);
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'secp256k1') {
      refusal('MANAGED_REPO_PUBLIC_KEY_INVALID', 'Wrong signing curve');
    }
    return key.export({ format: 'pem', type: 'spki' }).toString();
  } catch {
    refusal('MANAGED_REPO_PUBLIC_KEY_INVALID', 'Invalid secp256k1 public point');
  }
}

function validateBinding(binding, accountId, did, handle) {
  if (!binding || binding.canonicalAccountId !== accountId || binding.webId !== accountId ||
      binding.activityPubActorId !== accountId ||
      binding.atprotoDid !== did || binding.atprotoHandle !== handle ||
      binding.atprotoSource !== 'local' || binding.atprotoManaged !== true ||
      !binding.atSigningKeyRef || !binding.atRotationKeyRef ||
      binding.atSigningKeyRef === binding.atRotationKeyRef ||
      binding.status !== 'active') {
    refusal('MANAGED_REPO_BINDING_INVALID', 'Managed account identity binding is absent or inconsistent');
  }
  checkedPds(binding.atprotoPdsUrl);
  return binding;
}

function assertDidDocument(document, did, handle, pds, multibase) {
  if (!document || document.id !== did ||
      !Array.isArray(document.alsoKnownAs) ||
      !document.alsoKnownAs.includes('at://' + handle)) {
    refusal('MANAGED_REPO_PLC_MISMATCH', 'PLC document does not claim the managed account handle');
  }
  const methods = Array.isArray(document.verificationMethod) ? document.verificationMethod : [];
  const key = methods.find(item => item?.id === did + '#atproto' && item.controller === did &&
    item.type === 'Multikey');
  if (!key || key.publicKeyMultibase !== multibase) {
    refusal('MANAGED_REPO_PLC_KEY_MISMATCH', 'PLC signing key differs from provider-held key');
  }
  const services = Array.isArray(document.service) ? document.service : [];
  const service = services.find(item => (item?.id === '#atproto_pds' || item?.id === did + '#atproto_pds') &&
    item.type === 'AtprotoPersonalDataServer');
  if (!service || service.serviceEndpoint !== pds) {
    refusal('MANAGED_REPO_PLC_PDS_MISMATCH', 'PLC PDS endpoint differs from provider account binding');
  }
}

const bindingSnapshot = binding => JSON.stringify([
  binding.canonicalAccountId, binding.webId, binding.activityPubActorId,
  binding.atprotoDid, binding.atprotoHandle, binding.atprotoPdsUrl,
  binding.atSigningKeyRef, binding.atRotationKeyRef,
  binding.atprotoManaged, binding.atprotoSource, binding.status,
  binding.repoInitialized, binding.repoRootCid, binding.repoRev
]);

function sanitize(proof) {
  // CAR, byte buffers, key references, network DID documents and any private
  // provider data must never be returned by Moleculer readiness actions.
  return Object.freeze({
    verified: true, accountId: proof.accountId, did: proof.did,
    commitCid: proof.commitCid, rootCid: proof.rootCid,
    rev: proof.rev, outboxStatus: proof.outboxStatus
  });
}

/**
 * The source of truth for signed repository head and outbox is PostgreSQL,
 * while Jena identitybindings remain the WebID/AP/PLC association authority.
 * This adapter cannot publish native events or mutate any RDF binding.
 *
 * resolveBinding(accountId) -> current protected binding
 * resolveCommitKey(accountId) -> {did,keyId,publicKeyMultibase}
 * resolveDidDocument(did) -> independently resolved DID document
 * resolveHandleDid(handle) -> independently resolved handle DID
 * signCommit(accountId,did,rev,bytes) -> {did,keyId,signatureBase64Url}
 */
export function createProviderManagedRepoAuthority({
  store, resolveBinding, resolveCommitKey, resolveDidDocument,
  resolveHandleDid, signCommit
} = {}) {
  if (!store || typeof store.verify !== 'function' || typeof store.bootstrap !== 'function') {
    refusal('MANAGED_REPO_CONFIGURATION_INVALID', 'A durable signed-repository store is required');
  }
  [resolveBinding, resolveCommitKey, resolveDidDocument, resolveHandleDid, signCommit].forEach((fn, index) =>
    requireDependency(['resolveBinding', 'resolveCommitKey', 'resolveDidDocument', 'resolveHandleDid', 'signCommit'][index], fn));

  async function resolveIdentity({ canonicalAccountId, did, handle }) {
    const accountId = canonicalAccount(canonicalAccountId);
    assertManagedDid(did);
    checkedHandle(handle);
    const binding = validateBinding(await resolveBinding(accountId), accountId, did, handle);
    const resolvedHandleDid = await resolveHandleDid(handle);
    if (resolvedHandleDid !== did) {
      refusal('MANAGED_REPO_HANDLE_DID_MISMATCH', 'Handle resolution does not match bound DID');
    }
    const signerKey = await resolveCommitKey(accountId);
    if (!signerKey || signerKey.did !== did || signerKey.keyId !== did + '#atproto') {
      refusal('MANAGED_REPO_PUBLIC_KEY_INVALID', 'Provider signing authority differs from account identity');
    }
    const publicKeyPem = publicKeyPemFromMultibase(signerKey.publicKeyMultibase);
    const doc = await resolveDidDocument(did);
    assertDidDocument(doc, did, handle, binding.atprotoPdsUrl, signerKey.publicKeyMultibase);
    return { accountId, did, handle, binding, publicKeyPem };
  }

  async function confirmStableIdentity(before) {
    const current = await resolveIdentity({
      canonicalAccountId: before.accountId, did: before.did, handle: before.handle
    });
    if (bindingSnapshot(current.binding) !== bindingSnapshot(before.binding) ||
        current.publicKeyPem !== before.publicKeyPem) {
      refusal('MANAGED_REPO_IDENTITY_CHANGED', 'Managed identity changed during signed repository operation');
    }
    return current;
  }

  async function verifiedRepo(identity) {
    const proof = await store.verify({
      accountId: identity.accountId, did: identity.did,
      publicKeyPem: identity.publicKeyPem
    });
    await confirmStableIdentity(identity);
    return proof;
  }

  async function bootstrapAndVerify(input) {
    const identity = await resolveIdentity(input);
    let proof;
    try {
      // Avoid generating a signature on an idempotent replay; never treat a
      // corruption/signature error as an absent repo or silently overwrite it.
      proof = await verifiedRepo(identity);
    } catch (error) {
      if (error?.code !== 'ATPROTO_REPO_NOT_FOUND') throw error;
      proof = await store.bootstrap({
        accountId: identity.accountId, did: identity.did,
        publicKeyPem: identity.publicKeyPem,
        signer: async unsignedBytes => {
          // The trusted store constructs this exact unsigned commit. Public
          // callers cannot submit raw bytes, an actor or a key reference.
          const unsignedCommitBytesBase64 = Buffer.from(unsignedBytes).toString('base64');
          const rev = (await import('@ipld/dag-cbor')).decode(unsignedBytes).rev;
          const answer = await signCommit(identity.accountId, identity.did, rev, unsignedCommitBytesBase64);
          if (answer?.did !== identity.did || answer?.keyId !== identity.did + '#atproto' ||
              typeof answer.signatureBase64Url !== 'string') {
            refusal('MANAGED_REPO_SIGNER_MISMATCH', 'Provider signature response does not match bound signing identity');
          }
          return answer.signatureBase64Url;
        }
      });
      await confirmStableIdentity(identity);
    }
    return sanitize(proof);
  }

  async function verifyReady(input) {
    const identity = await resolveIdentity(input);
    const proof = await verifiedRepo(identity);
    // RDF binding is not authoritative for the repository head: require its
    // projection to match verified PostgreSQL data, never vice versa.
    if (identity.binding.repoInitialized !== true ||
        identity.binding.repoRootCid !== proof.rootCid ||
        identity.binding.repoRev !== proof.rev) {
      refusal('MANAGED_REPO_RDF_DRIFT', 'RDF repository readiness projection differs from durable signed head');
    }
    return sanitize(proof);
  }

  async function inspectRecovery(input) {
    // Read-only crash diagnostic: no blind RDF repairs or external signing.
    const identity = await resolveIdentity(input);
    const proof = await verifiedRepo(identity);
    const bindingMatch = identity.binding.repoInitialized === true &&
      identity.binding.repoRootCid === proof.rootCid &&
      identity.binding.repoRev === proof.rev;
    return Object.freeze({
      accountId: identity.accountId, did: identity.did, headCid: proof.commitCid,
      bindingMatch, recoveryRequired: !bindingMatch,
      outboxStatus: proof.outboxStatus
    });
  }

  return Object.freeze({ bootstrapAndVerify, verifyReady, inspectRecovery });
}
