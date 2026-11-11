/**
 * Non-activated direct canonical account location lookup for the protected
 * managed-repository path. SemApps auth.account.findByWebId currently calls
 * TripleStoreAdapter.find (unbounded CONSTRUCT + JSON-LD framing). This
 * SELECT uses one account type/predicate and LIMIT 2 to reject WebID collision.
 * The canonical dataset name must still be resolved against the provider's
 * installed account schema and the actual Solid storage location.
 */
const SEMAPPS = 'http://semapps.org/ns/core#';
const USERNAME = /^[a-z0-9][a-z0-9_-]{0,62}$/u;

function reject() {
  const err = new Error('Untrusted or ambiguous canonical Pod account location');
  err.code = 'POD_PROJECTION_OWNER_UNKNOWN';
  throw err;
}
function webId(value) {
  if (typeof value !== 'string' || value.length > 2048 ||
      /[\u0000-\u0020\u007f\\<>"{}]/u.test(value)) reject();
  let url;
  try { url = new URL(value); } catch { reject(); }
  if (url.protocol !== 'https:' || url.href !== value ||
      url.username || url.password || url.search || url.hash) reject();
  return value;
}
export function buildCanonicalPodAccountLookup(accountId) {
  const canonical = webId(accountId);
  // Existing SemApps TripleStoreAdapter({type:'AuthAccount', dataset:'settings'})
  // uses default http://semapps.org/ns/core# ontology and stores the WebID as
  // a literal. Do not CONSTRUCT all properties or enumerate accounts.
  return 'PREFIX semapps: <' + SEMAPPS + '> ' +
    'SELECT ?account ?username WHERE { ' +
    '?account a semapps:AuthAccount ; ' +
    'semapps:webId ' + JSON.stringify(canonical) + ' ; ' +
    'semapps:username ?username . ' +
    '} LIMIT 2';
}
export function parseCanonicalPodAccount(rows, accountId) {
  webId(accountId);
  if (!Array.isArray(rows) || rows.length !== 1) reject();
  const row = rows[0];
  const user = row?.username?.value;
  const accountUri = row?.account?.value;
  if (typeof user !== 'string' || !USERNAME.test(user) ||
      typeof accountUri !== 'string' ||
      !/^urn:AuthAccount:[0-9A-Za-z-]+$/u.test(accountUri)) {
    reject();
  }
  return Object.freeze({ username: user, webId: accountId, accountUri });
}
