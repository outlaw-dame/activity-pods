'use strict';

const fs = require('fs');
const path = require('path');
const EXPECTED_VERSION = '1.1.4';
const LEGACY_ACTOR_MARKER = 'activitypods-signed-remote-actor-fetch-v1';
const ACTOR_MARKER = 'activitypods-signed-remote-actor-fetch-v2';
const OUTBOX_MARKER = 'activitypods-remote-fetch-actor-authority-v1';
const OUTBOX_CONTENT_TYPE_MARKER = 'activitypods-remote-post-activitypub-content-type-v1';

function replaceOnce(source, search, replacement, label) {
  const first = source.indexOf(search);
  if (first < 0 || source.indexOf(search, first + search.length) >= 0) throw new Error(`Expected exactly one pinned SemApps ${label}`);
  return source.replace(search, replacement);
}

function patchActor(source) {
  if (source.includes(ACTOR_MARKER)) {
    const valid = source.includes("const headers = { Accept: 'application/activity+json, application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"' }") &&
      source.includes("ctx.call('signature.generateSignatureHeaders'") &&
      source.includes("new URL(webId).origin !== new URL(actorUri).origin") &&
      source.includes('url: actorUri, method: \'GET\', actorUri: webId') &&
      source.includes('const response = await fetch(actorUri, { headers });');
    if (!valid) throw new Error('Remote actor fetch marker exists without the complete hardened contract');
    return { source, changed: false };
  }
  if (source.includes(LEGACY_ACTOR_MARKER)) {
    let upgraded = replaceOnce(source, LEGACY_ACTOR_MARKER, ACTOR_MARKER, 'legacy remote actor marker');
    upgraded = replaceOnce(
      upgraded,
      "        if (webId && webId !== 'system' && webId !== 'anon') {",
      "        if (webId && webId !== 'system' && webId !== 'anon' && new URL(webId).origin !== new URL(actorUri).origin) {",
      'legacy remote actor signing scope'
    );
    return { source: upgraded, changed: true };
  }
  return { changed: true, source: replaceOnce(source,
    "        const response = await fetch(actorUri, { headers: { Accept: 'application/json' } });",
    `        const headers = { Accept: 'application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams"' }; // ${ACTOR_MARKER}\n        if (webId && webId !== 'system' && webId !== 'anon' && new URL(webId).origin !== new URL(actorUri).origin) {\n          Object.assign(headers, await ctx.call('signature.generateSignatureHeaders', {\n            url: actorUri, method: 'GET', actorUri: webId\n          }));\n        }\n        const response = await fetch(actorUri, { headers });`, 'remote actor fetch') };
}

function patchOutbox(source) {
  let patched = source;
  let changed = false;
  if (source.includes(OUTBOX_MARKER)) {
    if (!source.includes(`webId: activity.actor // ${OUTBOX_MARKER}`)) {
      throw new Error('Remote actor authority marker exists without sender authority');
    }
  } else {
    patched = replaceOnce(
      patched,
      "          webId: 'system'\n        });\n\n        if (!recipientInbox)",
      `          webId: activity.actor // ${OUTBOX_MARKER}\n        });\n\n        if (!recipientInbox)`,
      'remote recipient actor authority'
    );
    changed = true;
  }

  if (patched.includes(OUTBOX_CONTENT_TYPE_MARKER)) {
    if (!patched.includes(`'Content-Type': 'application/activity+json', // ${OUTBOX_CONTENT_TYPE_MARKER}`)) {
      throw new Error('Remote ActivityPub content-type marker exists without the hardened media type');
    }
  } else {
    patched = replaceOnce(
      patched,
      "            'Content-Type': 'application/json',",
      `            'Content-Type': 'application/activity+json', // ${OUTBOX_CONTENT_TYPE_MARKER}`,
      'remote ActivityPub content type'
    );
    changed = true;
  }
  return { source: patched, changed };
}

function applyPatch(root = path.dirname(require.resolve('@semapps/activitypub/package.json'))) {
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  if (version !== EXPECTED_VERSION) throw new Error(`Expected @semapps/activitypub@${EXPECTED_VERSION}, found ${version}`);
  for (const [relative, patch] of [['services/activitypub/subservices/actor.js', patchActor], ['services/activitypub/subservices/outbox.js', patchOutbox]]) {
    const file = path.join(root, relative);
    const result = patch(fs.readFileSync(file, 'utf8'));
    if (result.changed) fs.writeFileSync(file, result.source);
  }
  process.stdout.write('[ActivityPods] SemApps remote actor fetch hardened\n');
}

if (require.main === module) applyPatch();
module.exports = {
  ACTOR_MARKER,
  LEGACY_ACTOR_MARKER,
  OUTBOX_CONTENT_TYPE_MARKER,
  OUTBOX_MARKER,
  patchActor,
  patchOutbox,
  applyPatch
};
