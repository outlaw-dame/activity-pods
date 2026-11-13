/**
 * Non-activated public sync XRPC read prototype for a verified signed v3
 * EMPTY repository. Only the three explicitly implemented methods are
 * supported; it is not loaded by any ActivityPods HTTP gateway.
 *
 * The account/DID lookup is provider-owned and indexed. A public caller
 * supplies only the DID query parameter, NEVER a WebID, private signer,
 * PDS location, database connection or arbitrary repo head.
 */
const DID = /^did:plc:[a-z2-7]{24}$/u;
const CID = /^bafyre[a-z2-7]{53}$/u;
const TID = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const MAX_CAR = 128 * 1024;
const PREFIX = '/xrpc/';
const METHODS = new Set([
  'com.atproto.sync.getRepo',
  'com.atproto.sync.getLatestCommit',
  'com.atproto.sync.getRepoStatus'
]);
const UNAVAILABLE = new Set(['suspended','takendown','deactivated','deleted']);

function failure(code, status = 503) {
  const e = new Error('PDS repository query unavailable');
  e.code = code;
  e.status = status;
  throw e;
}
function canonicalOrigin(raw) {
  let u;
  try { u = new URL(raw); } catch { failure('PDS_CANDIDATE_CONFIGURATION_INVALID'); }
  if (u.protocol !== 'https:' || raw !== u.origin ||
      u.username || u.password || u.pathname !== '/' ||
      u.search || u.hash) failure('PDS_CANDIDATE_CONFIGURATION_INVALID');
  return raw;
}
function identitySnapshot(a) {
  return JSON.stringify([
    a.webId, a.activityPubActorId, a.did, a.handle, a.pdsUrl,
    a.atprotoManaged, a.atprotoSource, a.status
  ]);
}
function validateAccount(account, did, pdsOrigin) {
  if (!account) failure('RepoNotFound', 404);
  let webId;
  try { webId = new URL(account.webId); }
  catch { failure('PDS_CANDIDATE_IDENTITY_MISMATCH'); }
  if (webId.protocol !== 'https:' || !webId.hostname ||
      webId.href !== account.webId || webId.username || webId.password ||
      webId.hash || webId.search ||
      account.did !== did || typeof account.webId !== 'string' ||
      account.webId !== account.activityPubActorId ||
      account.atprotoSource !== 'local' || account.atprotoManaged !== true ||
      account.pdsUrl !== pdsOrigin || typeof account.handle !== 'string') {
    failure('PDS_CANDIDATE_IDENTITY_MISMATCH');
  }
  if (!['active',...UNAVAILABLE].includes(account.status)) {
    failure('PDS_CANDIDATE_STATE_UNKNOWN');
  }
  return account;
}
function ensureActive(account) {
  if (account.status === 'active') return;
  const mapping = {
    suspended: 'RepoSuspended', takendown: 'RepoTakendown',
    deactivated: 'RepoDeactivated', deleted: 'RepoNotFound'
  };
  failure(mapping[account.status] || 'RepoNotFound',
    account.status === 'deleted' ? 404 : 403);
}
function checkSignedRepo(repo, proof, projected, account, did) {
  if (repo?.verified !== true || repo.accountId !== account.webId ||
      repo.did !== did || repo.pdsOrigin !== account.pdsUrl ||
      !CID.test(repo.commitCid || '') ||
      !CID.test(repo.rootCid || '') || !TID.test(repo.rev || '') ||
      !['pending', 'delivered'].includes(repo.outboxStatus) ||
      proof?.verified !== true || proof.accountId !== account.webId ||
      proof.did !== did || proof.commitCid !== repo.commitCid ||
      proof.rootCid !== repo.rootCid || proof.rev !== repo.rev ||
      proof.outboxStatus !== repo.outboxStatus ||
      projected?.ready !== true || projected.accountId !== account.webId ||
      projected.did !== did || projected.headCid !== repo.commitCid ||
      projected.rootCid !== repo.rootCid || projected.rev !== repo.rev ||
      projected.outboxStatus !== repo.outboxStatus ||
      typeof projected.fence !== 'string' ||
      !/^[1-9][0-9]{0,18}$/u.test(projected.fence)) {
    failure('PDS_CANDIDATE_SIGNED_HEAD_NOT_READY');
  }
}
function disabled() { failure('PDS_CANDIDATE_NOT_RELEASED'); }

export function createReadOnlySyncXrpc({
  resolveHostedAccount, repositoryAuthority, projectionAuthority,
  signedRepoStore, resolvePublicKey, pdsOrigin, fixtureOnly = false
} = {}) {
  if (fixtureOnly !== true || process.env.NODE_ENV === 'production' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') {
    return Object.freeze({ handle: async () => disabled() });
  }
  const ownerPds = canonicalOrigin(pdsOrigin);
  if (typeof resolveHostedAccount !== 'function' ||
      typeof repositoryAuthority?.verifyReady !== 'function' ||
      typeof projectionAuthority?.readiness !== 'function' ||
      typeof signedRepoStore?.verify !== 'function' ||
      typeof resolvePublicKey !== 'function') {
    failure('PDS_CANDIDATE_CONFIGURATION_INVALID');
  }

  async function read(method, did) {
    const before = validateAccount(await resolveHostedAccount({ did }), did, ownerPds);
    if (method === 'com.atproto.sync.getRepoStatus' && before.status !== 'active') {
      return { kind: 'json', value: { did, active: false, status: before.status } };
    }
    ensureActive(before);
    const input = { canonicalAccountId: before.webId, did, handle: before.handle };
    const repo = await repositoryAuthority.verifyReady(input);
    const projection = await projectionAuthority.readiness({ accountId: before.webId, did });
    const publicKeyPem = await resolvePublicKey({ accountId: before.webId, did });
    if (typeof publicKeyPem !== 'string' || publicKeyPem.length > 4096) {
      failure('PDS_CANDIDATE_SIGNING_KEY_UNAVAILABLE');
    }
    const proof = await signedRepoStore.verify({
      accountId: before.webId, did, publicKeyPem
    });
    checkSignedRepo(repo, proof, projection, before, did);
    // Fresh state check after all external DID, RDF, key and SQL I/O.
    // Still NOT a production atomic revocation fence.
    const after = validateAccount(await resolveHostedAccount({ did }), did, ownerPds);
    ensureActive(after);
    if (identitySnapshot(after) !== identitySnapshot(before)) {
      failure('PDS_CANDIDATE_HOSTING_CHANGED');
    }

    if (method === 'com.atproto.sync.getLatestCommit') {
      return { kind: 'json', value: { cid: repo.commitCid, rev: repo.rev } };
    }
    if (method === 'com.atproto.sync.getRepoStatus') {
      return { kind: 'json', value: { did, active: true, rev: repo.rev } };
    }
    const car = Buffer.from(proof.carBytes || []);
    // The current proof contains exactly one signed commit and an empty MST.
    // Real record repositories require a separately reviewed streaming path.
    if (!car.length || car.length > MAX_CAR) {
      failure('PDS_CANDIDATE_CAR_TOO_LARGE');
    }
    return { kind: 'car', value: car };
  }

  async function handle(req, res) {
    try {
      if (process.env.NODE_ENV === 'production' ||
          process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') disabled();
      if (req.method !== 'GET' || typeof req.url !== 'string' ||
          req.url.length > 4096) failure('InvalidRequest', 400);
      let url;
      try { url = new URL(req.url, 'http://localhost'); }
      catch { failure('InvalidRequest', 400); }
      if (!url.pathname.startsWith(PREFIX) ||
          !METHODS.has(url.pathname.slice(PREFIX.length))) {
        failure('MethodNotImplemented', 404);
      }
      const method = url.pathname.slice(PREFIX.length);
      const params = [...url.searchParams.keys()];
      if (params.some(key => key !== 'did' &&
          !(method === 'com.atproto.sync.getRepo' && key === 'since')) ||
          url.searchParams.getAll('did').length !== 1 ||
          url.searchParams.getAll('since').length > 1) {
        failure('InvalidRequest', 400);
      }
      const did = url.searchParams.get('did');
      if (!DID.test(did || '')) failure('InvalidRequest', 400);
      const since = url.searchParams.get('since');
      if (since !== null) {
        if (!TID.test(since)) failure('InvalidRequest', 400);
        // Returning a full CAR for a delta cursor would mislead relays.
        // Diff construction requires a real history-aware MST store.
        failure('NotImplemented', 501);
      }
      const result = await read(method, did);
      res.writeHead(200, {
        'content-type': result.kind === 'car' ?
          'application/vnd.ipld.car' : 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'access-control-allow-origin': '*',
        'x-content-type-options': 'nosniff'
      });
      return res.end(result.kind === 'car' ?
        result.value : JSON.stringify(result.value));
    } catch (error) {
      const code = typeof error?.code === 'string' &&
        ['InvalidRequest','NotImplemented','RepoNotFound','RepoSuspended',
          'RepoTakendown','RepoDeactivated','MethodNotImplemented'].includes(error.code)
        ? error.code : 'InternalError';
      const status = code === 'InternalError' ? 503 :
        Number.isInteger(error?.status) ? error.status : 500;
      if (!res.headersSent) {
        res.writeHead(status, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
          'access-control-allow-origin': '*',
          'x-content-type-options': 'nosniff'
        });
      }
      return res.end(JSON.stringify({ error: code }));
    }
  }

  return Object.freeze({ handle });
}
