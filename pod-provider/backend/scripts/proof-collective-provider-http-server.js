'use strict';

/**
 * Disposable HTTPS front door and remote SAI application documents.
 * Never a production route: this process only runs in GitHub Actions.
 * The backend remains the real Pod-provider instance behind this proxy.
 */
const https = require('node:https');
const http = require('node:http');
const fs = require('node:fs');

const port = Number(process.env.G1_E2E_HTTPS_PORT || 3443);
const origin = 'https://app-e2e.test:' + port;
const appUri = origin + '/app';
const accessNeedUri = origin + '/access-need';
const context = {
  id: '@id',
  type: '@type',
  interop: 'http://www.w3.org/ns/solid/interop#',
  apods: 'http://activitypods.org/ns/core#',
  oidc: 'http://www.w3.org/ns/solid/oidc#'
};
function resource(res, obj) {
  res.writeHead(200, {
    'content-type': 'application/ld+json; charset=utf-8',
    'cache-control': 'no-store',
    'access-control-allow-origin': '*',
    'x-content-type-options': 'nosniff'
  });
  res.end(JSON.stringify({ '@context': context, ...obj }));
}
const app = {
  '@id': appUri, '@type': 'interop:Application',
  'interop:hasAccessNeedGroup': accessNeedUri,
  'interop:hasAuthorizationCallbackEndpoint': origin + '/callback'
};
const need = {
  id: accessNeedUri,
  type: 'interop:AccessNeedGroup',
  'interop:accessNecessity': 'interop:AccessRequired',
  'apods:hasSpecialRights': ['apods:CreateGroup', 'apods:ReadGroups']
};
const proxy = https.createServer({
  cert: fs.readFileSync(process.env.G1_E2E_CERT),
  key: fs.readFileSync(process.env.G1_E2E_KEY)
}, (req, res) => {
  const host = String(req.headers.host || '').split(':')[0];
  const pathname = new URL(req.url, 'https://fixture.invalid').pathname;
  if (host === 'app-e2e.test') {
    if (pathname === '/app') {
      // SemApps requests the SAI Application Linked Data representation.
      // RedisAdapter.find('Client') explicitly requests the official OIDC
      // context via JsonLdContext. Serve two compatible representations of
      // the same canonical HTTPS identity without colliding JSON-LD terms.
      if (req.headers.jsonldcontext ===
          'https://www.w3.org/ns/solid/oidc-context.jsonld') {
        res.writeHead(200, {
          'content-type': 'application/ld+json; charset=utf-8',
          'cache-control': 'no-store',
          'vary': 'JsonLdContext'
        });
        return res.end(JSON.stringify({
          '@context': ['https://www.w3.org/ns/solid/oidc-context.jsonld'],
          client_id: appUri,
          client_name: 'Paper disposable G1 application',
          redirect_uris: [origin + '/callback'],
          response_types: ['code'],
          grant_types: ['authorization_code'],
          token_endpoint_auth_method: 'none',
          scope: 'openid profile webid'
        }));
      }
      return resource(res, app);
    }
    if (pathname === '/access-need') return resource(res, need);
    if (pathname === '/callback') {
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      return res.end('Disposable OAuth callback; no session material logged.');
    }
    res.writeHead(404);
    return res.end();
  }
  if (host !== 'paper-e2e.test') {
    res.writeHead(421);
    return res.end();
  }
  const upstream = http.request({
    host: '127.0.0.1', port: 3000,
    method: req.method, path: req.url,
    headers: { ...req.headers, 'x-forwarded-proto': 'https',
      'x-forwarded-host': req.headers.host, 'x-forwarded-port': String(port) }
  }, backend => {
    res.writeHead(backend.statusCode, backend.headers);
    backend.pipe(res);
  });
  upstream.on('error', err => {
    if (!res.headersSent) res.writeHead(502);
    res.end('Backend not ready');
  });
  req.pipe(upstream);
});
proxy.listen(port, '0.0.0.0', () => {
  console.log('Disposable G1 HTTPS test gateway listening on port ' + port);
});
const close = () => proxy.close(() => process.exit(0));
process.on('SIGINT', close);
process.on('SIGTERM', close);
