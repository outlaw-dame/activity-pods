'use strict';
const assert = require('node:assert/strict');
const { createLocalSignupApp } = require('../candidates/local-signup-app');

async function main() {
  const app = createLocalSignupApp();
  await assert.rejects(app.loadRequirements(app.appUri + '/other'));
  const result = await app.loadRequirements(app.appUri);
  const manifest = JSON.parse(app.needDocument);
  assert.deepEqual(result.required, manifest['apods:hasSpecialRights']);
  assert.deepEqual(result.optional, []);
  assert.match(result.revision, /^[a-f0-9]{64}$/u);
  assert.equal(JSON.parse(app.appDocument)['interop:hasAccessNeedGroup'], manifest.id);
  assert.deepEqual(JSON.parse(app.oidcDocument).redirect_uris, [app.returnUri]);
}
main().catch(() => { console.error('Local signup application acceptance failed'); process.exitCode = 1; });
