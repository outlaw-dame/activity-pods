'use strict';

const fs = require('fs');
const path = require('path');

const {
  ACTOR_MARKER,
  LEGACY_ACTOR_MARKER,
  OUTBOX_CONTENT_TYPE_MARKER,
  OUTBOX_MARKER,
  patchActor,
  patchOutbox
} = require('../scripts/patch-semapps-activitypub-remote-actor-fetch');

const ORIGINAL_ACTOR_FETCH = "        const response = await fetch(actorUri, { headers: { Accept: 'application/json' } });";
const ORIGINAL_REMOTE_AUTHORITY = "          webId: 'system'\n        });\n\n        if (!recipientInbox)";
const ORIGINAL_CONTENT_TYPE = "            'Content-Type': 'application/json',";
const ORIGINAL_OUTBOX = `${ORIGINAL_REMOTE_AUTHORITY}\n${ORIGINAL_CONTENT_TYPE}`;

describe('SemApps remote actor fetch hardening patch', () => {
  test('is wired into postinstall and available before production dependency installation', () => {
    const packageJson = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../package.json'), 'utf8'));
    expect(packageJson.scripts.postinstall).toContain('node scripts/patch-semapps-activitypub-remote-actor-fetch.js');

    const dockerfile = fs.readFileSync(path.resolve(__dirname, '../../docker/backend.dockerfile'), 'utf8');
    const copyIndex = dockerfile.indexOf(
      'ADD backend/scripts/patch-semapps-activitypub-remote-actor-fetch.js /app/backend/scripts/patch-semapps-activitypub-remote-actor-fetch.js'
    );
    expect(copyIndex).toBeGreaterThan(-1);
    expect(dockerfile.indexOf('RUN yarn install && yarn cache clean')).toBeGreaterThan(copyIndex);
  });

  test('requests ActivityPub representations and signs remote GETs as the sending actor', () => {
    const result = patchActor(`before\n${ORIGINAL_ACTOR_FETCH}\nafter`);
    expect(result.changed).toBe(true);
    expect(result.source).toContain("Accept: 'application/activity+json, application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"'");
    expect(result.source).toContain("ctx.call('signature.generateSignatureHeaders'");
    expect(result.source).toContain("new URL(webId).origin !== new URL(actorUri).origin");
    expect(result.source).toContain("url: actorUri, method: 'GET', actorUri: webId");
    expect(result.source).toContain('const response = await fetch(actorUri, { headers });');
    expect(result.source).not.toContain(ORIGINAL_ACTOR_FETCH);
  });

  test('uses sender authority and an ActivityPub media type for native remote delivery', () => {
    const result = patchOutbox(`before\n${ORIGINAL_OUTBOX}\nafter`);
    expect(result.changed).toBe(true);
    expect(result.source).toContain(`webId: activity.actor // ${OUTBOX_MARKER}`);
    expect(result.source).toContain(
      `'Content-Type': 'application/activity+json', // ${OUTBOX_CONTENT_TYPE_MARKER}`
    );
    expect(result.source).not.toContain(ORIGINAL_REMOTE_AUTHORITY);
    expect(result.source).not.toContain(ORIGINAL_CONTENT_TYPE);
  });

  test('is idempotent only while both hardened contracts remain complete', () => {
    const actor = patchActor(ORIGINAL_ACTOR_FETCH).source;
    const outbox = patchOutbox(ORIGINAL_OUTBOX).source;
    expect(patchActor(actor)).toEqual({ source: actor, changed: false });
    expect(patchOutbox(outbox)).toEqual({ source: outbox, changed: false });
    expect(() => patchActor(`// ${ACTOR_MARKER}`)).toThrow('complete hardened contract');
    expect(() => patchOutbox(`// ${OUTBOX_MARKER}\n// ${OUTBOX_CONTENT_TYPE_MARKER}`)).toThrow('sender authority');
  });

  test('upgrades the prior cross-origin-unaware patch without weakening signing', () => {
    const current = patchActor(ORIGINAL_ACTOR_FETCH).source;
    const legacy = current
      .replace(ACTOR_MARKER, LEGACY_ACTOR_MARKER)
      .replace(
        "webId !== 'anon' && new URL(webId).origin !== new URL(actorUri).origin",
        "webId !== 'anon'"
      );
    const upgraded = patchActor(legacy);
    expect(upgraded.changed).toBe(true);
    expect(upgraded.source).toContain(ACTOR_MARKER);
    expect(upgraded.source).not.toContain(LEGACY_ACTOR_MARKER);
    expect(upgraded.source).toContain("new URL(webId).origin !== new URL(actorUri).origin");
    expect(patchActor(upgraded.source)).toEqual({ source: upgraded.source, changed: false });
  });

  test('fails closed when either pinned SemApps source contract drifts', () => {
    expect(() => patchActor('no remote fetch')).toThrow('Expected exactly one pinned SemApps remote actor fetch');
    expect(() => patchActor(`${ORIGINAL_ACTOR_FETCH}\n${ORIGINAL_ACTOR_FETCH}`)).toThrow(
      'Expected exactly one pinned SemApps remote actor fetch'
    );
    expect(() => patchOutbox(`no remote authority\n${ORIGINAL_CONTENT_TYPE}`)).toThrow(
      'Expected exactly one pinned SemApps remote recipient actor authority'
    );
    expect(() => patchOutbox(`${ORIGINAL_REMOTE_AUTHORITY}\n${ORIGINAL_REMOTE_AUTHORITY}\n${ORIGINAL_CONTENT_TYPE}`)).toThrow(
      'Expected exactly one pinned SemApps remote recipient actor authority'
    );
    expect(() => patchOutbox(`${ORIGINAL_REMOTE_AUTHORITY}\nno content type`)).toThrow(
      'Expected exactly one pinned SemApps remote ActivityPub content type'
    );
    expect(() => patchOutbox(`${ORIGINAL_OUTBOX}\n${ORIGINAL_CONTENT_TYPE}`)).toThrow(
      'Expected exactly one pinned SemApps remote ActivityPub content type'
    );
  });
});
