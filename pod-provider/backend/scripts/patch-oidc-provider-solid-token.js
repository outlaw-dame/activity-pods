'use strict';

const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..', 'node_modules', 'oidc-provider');
const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
if (version !== '8.5.1') {
  throw Error(
    'Solid-OIDC token patch was reviewed for oidc-provider 8.5.1; ' +
    'review the issuer before upgrading to ' + version
  );
}

const plans = [
  {
    path: 'lib/models/id_token.js',
    old: "case 'idtoken':\n          alg = client.idTokenSignedResponseAlg;\n          signOptions = {\n            audience: client.clientId,",
    replacement: "case 'idtoken':\n          alg = client.idTokenSignedResponseAlg;\n          signOptions = {\n            audience: this.scope?.split(' ').includes('webid') ? [client.clientId, 'solid'] : client.clientId,"
  },
  {
    path: 'lib/actions/grants/authorization_code.js',
    old: "    token.set('sid', code.sid);\n\n    idToken = await token.issue({ use: 'idtoken' });",
    replacement: [
      "    token.set('sid', code.sid);",
      "    if (code.scopes.has('webid')) {",
      "      if (!dPoP || !at.jkt || at.jkt !== dPoP.thumbprint) {",
      "        throw new InvalidGrant('Solid-OIDC webid requires a DPoP-bound ID token');",
      "      }",
      "      token.set('cnf', { jkt: at.jkt });",
      "    }",
      "",
      "    idToken = await token.issue({ use: 'idtoken' });"
    ].join('\n')
  },
  {
    path: 'lib/actions/grants/refresh_token.js',
    old: "    token.set('sid', refreshToken.sid);\n\n    idToken = await token.issue({ use: 'idtoken' });",
    replacement: [
      "    token.set('sid', refreshToken.sid);",
      "    if (scope.has('webid')) {",
      "      if (!dPoP || !at.jkt || at.jkt !== dPoP.thumbprint) {",
      "        throw new InvalidGrant('Solid-OIDC webid refresh requires DPoP');",
      "      }",
      "      token.set('cnf', { jkt: at.jkt });",
      "    }",
      "",
      "    idToken = await token.issue({ use: 'idtoken' });"
    ].join('\n')
  }
];

const pending = plans.map(plan => {
  const filename = path.join(root, plan.path);
  const source = fs.readFileSync(filename, 'utf8');
  if (source.includes(plan.replacement)) return null;
  const found = source.split(plan.old).length - 1;
  if (found !== 1) {
    throw Error('Cannot safely patch ' + plan.path + ': expected one exact upstream anchor');
  }
  return { filename, source: source.replace(plan.old, plan.replacement) };
}).filter(Boolean);

for (const { filename, source } of pending) {
  const temp = filename + '.paper-patch-' + process.pid;
  fs.writeFileSync(temp, source, { mode: 0o644 });
  fs.renameSync(temp, filename);
}
console.log('Verified Solid-OIDC audience and DPoP binding for oidc-provider ' + version);
