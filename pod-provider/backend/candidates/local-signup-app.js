'use strict';

const { createHash } = require('node:crypto');

// The HTTPS test app serves these exact bytes to SemApps. Computing the
// consent revision over all three representations also binds the callback.
function createLocalSignupApp(port = 3443) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid local app port');
  const origin = new URL('https://app-e2e.test:' + port).origin;
  const appUri = origin + '/app';
  const returnUri = origin + '/callback';
  const groupUri = origin + '/access-need';
  const context = { id: '@id', type: '@type', interop: 'http://www.w3.org/ns/solid/interop#',
    apods: 'http://activitypods.org/ns/core#', oidc: 'http://www.w3.org/ns/solid/oidc#' };
  const appDocument = JSON.stringify({ '@context': context, '@id': appUri, '@type': 'interop:Application',
    'interop:hasAccessNeedGroup': groupUri, 'interop:hasAuthorizationCallbackEndpoint': returnUri });
  const required = ['apods:CreateGroup', 'apods:ReadGroups', 'apods:ManageMembers'];
  const needDocument = JSON.stringify({ '@context': context, id: groupUri, type: 'interop:AccessNeedGroup',
    'interop:accessNecessity': 'interop:AccessRequired', 'apods:hasSpecialRights': required });
  const oidcDocument = JSON.stringify({ '@context': ['https://www.w3.org/ns/solid/oidc-context.jsonld'],
    client_id: appUri, client_name: 'Paper disposable G1 application', redirect_uris: [returnUri],
    response_types: ['code'], grant_types: ['authorization_code'], token_endpoint_auth_method: 'none',
    scope: 'openid profile webid' });
  const revision = createHash('sha256').update(JSON.stringify([appDocument, needDocument, oidcDocument])).digest('hex');
  async function verifyDocument(uri, expected, headers = {}) {
    const response = await fetch(uri, { headers: { accept: 'application/ld+json', ...headers },
      redirect: 'error', signal: AbortSignal.timeout(5000) });
    const bytes = Buffer.from(expected);
    let offset = 0;
    try {
      if (response.status !== 200 || !/^application\/ld\+json(?:;|$)/iu.test(response.headers.get('content-type') || '')) {
        throw new Error('Local application document unavailable');
      }
      for await (const chunk of response.body) {
        const end = offset + chunk.length;
        if (end > bytes.length || !bytes.subarray(offset, end).equals(chunk)) throw new Error('Local application document changed');
        offset = end;
      }
      if (offset !== bytes.length) throw new Error('Incomplete local application document');
    } finally { await response.body?.cancel().catch(() => {}); }
  }
  async function loadRequirements(uri) {
    if (uri !== appUri) throw new Error('Unrecognized local signup application');
    await Promise.all([verifyDocument(appUri, appDocument), verifyDocument(groupUri, needDocument),
      verifyDocument(appUri, oidcDocument, { JsonLdContext: 'https://www.w3.org/ns/solid/oidc-context.jsonld' })]);
    return { required: [...required], optional: [], revision };
  }
  return Object.freeze({ origin, appUri, returnUri, groupUri, requiredRights: Object.freeze(required), appDocument, needDocument, oidcDocument, loadRequirements });
}
module.exports = { createLocalSignupApp };
