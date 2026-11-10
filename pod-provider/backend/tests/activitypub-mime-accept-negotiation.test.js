'use strict';

const fs = require('fs');
const path = require('path');

describe('ActivityPub Accept header profile negotiation contract', () => {
  test('patch script exists and can be required/executed idempotently', () => {
    const patchScriptPath = path.resolve(__dirname, '../scripts/patch-semapps-middlewares-activitypub-accept.js');
    expect(fs.existsSync(patchScriptPath)).toBe(true);
  });

  test('patch script defines supported ActivityStreams profile mime types and non-GET fallback', () => {
    const patchScript = fs.readFileSync(path.resolve(__dirname, '../scripts/patch-semapps-middlewares-activitypub-accept.js'), 'utf8');
    expect(patchScript).toContain('application/ld+json; profile="https://www.w3.org/ns/activitystreams"');
    expect(patchScript).toContain('application/activity+json; profile="https://www.w3.org/ns/activitystreams"');
    expect(patchScript).toContain('APODS_ACTIVITYPUB_ACCEPT_PROFILE_NORMALIZATION_V1');
    expect(patchScript).toContain('req.method !== \'GET\' && req.method !== \'HEAD\'');
  });
});
