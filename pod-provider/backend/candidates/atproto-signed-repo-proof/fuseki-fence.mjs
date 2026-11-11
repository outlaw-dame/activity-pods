/**
 * Candidate-only atomic Jena/Fuseki RDF projection fence query.
 * Must be executed against the exact protected binding's canonical dataset.
 * Never expose SPARQL update, dataset, graph or resource selection to clients.
 *
 * Fuseki/TDB2 executes a single DELETE/INSERT WHERE transaction with a
 * monotone integer fence and immutable identity constraints. A 2xx HTTP
 * response CAN mean the guarded WHERE matched zero rows, so trusted callers
 * MUST independently read the resulting RDF and verify all projected terms.
 */
const P = 'http://activitypods.org/ns/core#';
const DID = /^did:plc:[a-z2-7]{24}$/;
const CID = /^bafyre[a-z2-7]{53}$/;
const TID = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/;
const FENCE = /^[1-9][0-9]{0,18}$/;
const MAX = 9223372036854775807n;
function refused(message) {
  const e = new Error(message); e.code = 'RDF_FENCE_INPUT_INVALID'; throw e;
}
function iri(value) {
  if (typeof value !== 'string' || value.length > 2048 ||
      /[<>"{}\s\\]/u.test(value)) refused('Invalid trusted RDF IRI');
  try {
    const url = new URL(value);
    if (!['https:', 'urn:'].includes(url.protocol)) refused('Unsupported protected RDF IRI scheme');
    return '<' + value + '>';
  } catch {
    refused('Invalid protected RDF IRI');
  }
}
function literal(value) {
  if (typeof value !== 'string' || value.length > 2048) refused('Invalid protected RDF literal');
  return JSON.stringify(value);
}
function accountCheck(accountId) {
  const quoted = iri(accountId);
  if (!quoted.startsWith('<https://')) refused('Canonical account must be HTTPS');
  const url = new URL(accountId);
  if (url.href !== accountId || url.username || url.password || url.hash || url.search) {
    refused('Canonical WebID does not normalize');
  }
}
/**
 * These values are provided only by current provider-held RDF identity,
 * PG-backed cryptographically verified repository and PG lease.
 */
export function buildFencedRepoProjectionSparql({
  resourceUri, graphUri = null, accountId, did, rootCid, rev, fence
} = {}) {
  accountCheck(accountId);
  if (!DID.test(did || '') || !CID.test(rootCid || '') || !TID.test(rev || '') ||
      typeof fence !== 'string' || !FENCE.test(fence) || BigInt(fence) > MAX) {
    refused('Invalid signed repository projection or lease epoch');
  }
  const subject = iri(resourceUri);
  const graph = graphUri === null ? inner => inner :
    inner => 'GRAPH ' + iri(graphUri) + ' { ' + inner + ' }';
  const clean = (key, name) => subject + ' apods:' + key + ' ?' + name + ' . ';
  const oldNames = [
    ['repoInitialized', 'oldInitialized'],
    ['repoRootCid', 'oldRoot'],
    ['repoRev', 'oldRev'],
    ['repoProjectionFence', 'oldFence']
  ];
  const deletePatterns = oldNames.map(([key, name]) => clean(key, name)).join(' ');
  const insert = subject + ' apods:repoInitialized true ; ' +
    'apods:repoRootCid ' + literal(rootCid) + ' ; ' +
    'apods:repoRev ' + literal(rev) + ' ; ' +
    'apods:repoProjectionFence "' + fence + '"^^xsd:integer . ';
  const identity = subject + ' a apods:AtprotoIdentityBinding ; ' +
    'apods:canonicalAccountId ?canonical ; apods:webId ?webId ; ' +
    'apods:activityPubActorId ?actor ; apods:atprotoDid ?did ; ' +
    'apods:atprotoManaged ?managed ; apods:atprotoSource ?source ; ' +
    'apods:status ?status . ';
  const guards = 'FILTER(STR(?canonical) = ' + literal(accountId) +
    ' && STR(?webId) = ' + literal(accountId) +
    ' && STR(?actor) = ' + literal(accountId) +
    ' && STR(?did) = ' + literal(did) +
    ' && LCASE(STR(?managed)) = "true" && STR(?source) = "local" && STR(?status) = "active") ';
  const old = oldNames.map(([key, name]) =>
    'OPTIONAL { ' + clean(key, name) + ' }').join(' ');
  // Reject *any* malformed, equal or higher fence, not merely the first value.
  // Also refuse replacing an existing different CID or rev. Only a genesis
  // replay with the same immutable PG head may advance the fence.
  const immutable = 'FILTER NOT EXISTS { ' + subject + ' apods:repoRootCid ?differentRoot . ' +
    'FILTER(STR(?differentRoot) != ' + literal(rootCid) + ') } ' +
    'FILTER NOT EXISTS { ' + subject + ' apods:repoRev ?differentRev . ' +
    'FILTER(STR(?differentRev) != ' + literal(rev) + ') } ';
  const noHigher = 'FILTER NOT EXISTS { ' + subject + ' apods:repoProjectionFence ?priorFence . ' +
    'FILTER(!REGEX(STR(?priorFence), "^[0-9]+$") || ' +
    'xsd:integer(STR(?priorFence)) >= ' + fence + ') } ';
  const prefix = 'PREFIX apods: <' + P + '> PREFIX xsd: <http://www.w3.org/2001/XMLSchema#> ';
  return prefix + 'DELETE { ' + graph(deletePatterns) + ' } ' +
    'INSERT { ' + graph(insert) + ' } WHERE { ' +
    graph(identity + guards + old + immutable + noHigher) + ' }';
}
