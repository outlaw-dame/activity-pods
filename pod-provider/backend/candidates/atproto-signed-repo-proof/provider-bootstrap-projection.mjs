// Only an operator-owned, disposable provider worker can project a genesis.
// The account and signed head come from the consumed reservation.
import { verifyProviderGenesis } from './provider-bootstrap-genesis.mjs';
import { buildFencedRepoProjectionSparql } from './fuseki-fence.mjs';
import { makeDisposableProtectedFusekiReader, verifyProtectedBindingTerms } from './protected-rdf-attestor.mjs';

const origin = 'http://127.0.0.1:3041';
function gate() {
  if (process.env.ATPROTO_PROJECTION_ROLE_TEST_DISPOSABLE !== 'confirmed' ||
      process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE !== 'confirmed') throw Error('Disposable projection disabled');
}
async function update(query) {
  const response = await fetch(origin + '/protected-proof/update', {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(4000),
    headers: { authorization: 'Basic ' + Buffer.from('fixture-projector:fixture-projector-only').toString('base64'),
      'content-type': 'application/sparql-update' }, body: query
  });
  await response.body?.cancel();
  if (![200,204].includes(response.status)) throw Error('Protected projection update unavailable');
}

export async function projectProviderGenesis({ reader, projector, scope }) {
  gate();
  const proof = await verifyProviderGenesis(reader,scope);
  const { webId, did, commitCid, rootCid, rev } = proof;
  if (!/^https:\/\/paper\.example\.org\/claimtest-[a-z0-9]{8,24}$/u.test(webId)) throw Error('Invalid bootstrap owner');
  const result = await projector.query({
    text:'SELECT * FROM paper_account_reservation_proof.claim_provider_genesis($1,$2,$3,$4)',
    values:[scope.reservationId, scope.operationId, did, commitCid], query_timeout:3000
  });
  if (result.rowCount !== 1) throw Error('Provider genesis lease unavailable');
  const { lease_owner: leaseOwner, lease_epoch: leaseEpoch } = result.rows[0];
  const resourceUri = 'urn:paper:bootstrap:' + did;
  // Initialize only a missing subject. Existing identity claims remain under
  // the typed readback and monotone Jena fence.
  await update('PREFIX apods: <http://activitypods.org/ns/core#> INSERT { <'+resourceUri+'> '+
    'a apods:AtprotoIdentityBinding; apods:canonicalAccountId '+JSON.stringify(webId)+'; '+
    'apods:webId <'+webId+'>; apods:activityPubActorId <'+webId+'>; apods:atprotoDid '+JSON.stringify(did)+'; '+
    'apods:atprotoManaged true; apods:atprotoSource "local"; apods:status "active" } '+
    'WHERE { FILTER NOT EXISTS { <'+resourceUri+'> ?p ?o } }');
  await update(buildFencedRepoProjectionSparql({resourceUri, accountId:webId,did,rootCid,rev,fence:leaseEpoch}));
  return {leaseOwner, leaseEpoch};
}

export async function attestProviderGenesis({reader,attestor,scope,leaseOwner,leaseEpoch}) {
  gate();
  const proof = await verifyProviderGenesis(reader,scope);
  const read = makeDisposableProtectedFusekiReader({origin,password:'fixture-attestor-only',bootstrapDid:proof.did});
  const digest = verifyProtectedBindingTerms(await read(),{...proof,accountId:proof.webId,leaseEpoch});
  const result = await attestor.query({
    text:'SELECT paper_account_reservation_proof.ack_provider_genesis($1,$2,$3,$4,$5,$6,$7) AS applied',
    values:[scope.reservationId,scope.operationId,proof.did,proof.commitCid,leaseOwner,leaseEpoch,digest], query_timeout:3000
  });
  if(result.rows[0]?.applied !== true) throw Error('Independent genesis acknowledgment refused');
  return {applied:true};
}
