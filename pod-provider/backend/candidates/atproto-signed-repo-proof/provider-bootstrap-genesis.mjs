// Local provider bootstrap. The caller supplies an internal coordinator scope.
// The app and the browser cannot select a repository or obtain its CAR here.
import { carFromBlocks, verifySignedEmptyRepo, assertManagedDid } from './genesis.mjs';
import { publicKeyPemFromMultibase } from './provider-authority.mjs';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const provider = 'https://paper.example.org';
function refused() { throw new Error('Provider genesis readback refused'); }

async function plcKey(did, handle) {
  const response = await fetch('http://127.0.0.1:2582/' + did, {
    signal: AbortSignal.timeout(3500), redirect: 'error', headers: { accept: 'application/did+ld+json, application/did+json, application/json' }
  });
  try {
    if (!response.ok || !/^application\/(?:did\+(?:ld\+)?json|json)(?:;|$)/iu.test(response.headers.get('content-type') || '')) refused();
    const parts = [];
    let size = 0;
    for await (const part of response.body) {
      size += part.byteLength;
      if (size > 16384) refused();
      parts.push(part);
    }
    const document = JSON.parse(Buffer.concat(parts).toString('utf8'));
    if (document.id !== did || !Array.isArray(document.alsoKnownAs) ||
        !document.alsoKnownAs.includes('at://' + handle)) refused();
    const keys = document.verificationMethod.filter(key => key.id === did + '#atproto');
    const endpoints = document.service.filter(service =>
      service.id === '#atproto_pds' || service.id === did + '#atproto_pds');
    if (keys.length !== 1 || keys[0].type !== 'Multikey' || keys[0].controller !== did ||
        endpoints.length !== 1 || endpoints[0].type !== 'AtprotoPersonalDataServer' ||
        endpoints[0].serviceEndpoint !== provider) refused();
    return publicKeyPemFromMultibase(keys[0].publicKeyMultibase);
  } finally { await response.body?.cancel().catch(() => {}); }
}

export async function verifyProviderGenesis(pool, { reservationId, operationId, did }) {
  if (process.env.NODE_ENV !== 'test' || process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' || !uuid.test(reservationId) ||
      !uuid.test(operationId)) refused();
  assertManagedDid(did);
  const read = async () => {
    const { rows } = await pool.query({
      text: 'SELECT * FROM paper_account_reservation_proof.read_provider_genesis($1,$2,$3)',
      values: [reservationId, operationId, did], query_timeout: 3000
    });
    if (rows.length !== 1 || rows[0].pds_origin !== provider) refused();
    return rows[0];
  };
  const row = await read();
  const key = await plcKey(did, row.handle);
  const carBytes = await carFromBlocks({ commitCid: row.head_cid, rootCid: row.root_cid,
    commitBytes: row.commit_block, rootBytes: row.root_block });
  const proof = await verifySignedEmptyRepo({ did, carBytes, publicKeyPem: key });
  if (!proof.valid || proof.rev !== row.rev || proof.commitCid !== row.head_cid ||
      proof.rootCid !== row.root_cid) refused();
  const current = await read();
  if (['webid','handle','head_cid','root_cid','rev'].some(field => current[field] !== row[field]) ||
      !current.commit_block.equals(row.commit_block) || !current.root_block.equals(row.root_block)) refused();
  return Object.freeze({ ...proof, webId: row.webid });
}
