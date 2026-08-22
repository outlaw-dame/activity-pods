'use strict';

const crypto = require('crypto');
const { Errors: E } = require('moleculer-web');
const { MIME_TYPES } = require('@semapps/mime-types');
const { sanitizeSparqlQuery } = require('@semapps/triplestore');
const { activityPubRsaKeyId } = require('../../utils/activitypub-rsa-key-id');
const FORBIDDEN_ACTOR_FIELDS = new Set([
  'accessToken',
  'privateKey',
  'privateKeyPem',
  'refreshToken',
  'secretKey'
]);
const ACTIVITYSTREAMS_ACTOR_TYPES = new Set(['Application', 'Group', 'Organization', 'Person', 'Service']);

function resourceId(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && !Array.isArray(value)) return value.id || value['@id'] || null;
  return null;
}

function asArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function activityStreamsActorType(actor) {
  const normalized = asArray(actor?.type ?? actor?.['@type'])
    .map(value => resourceId(value))
    .filter(Boolean)
    .map(value => value.replace(/^https:\/\/www\.w3\.org\/ns\/activitystreams#/u, '').replace(/^as:/u, ''))
    .filter(value => ACTIVITYSTREAMS_ACTOR_TYPES.has(value));
  const unique = [...new Set(normalized)];
  return unique.length === 1 ? unique[0] : null;
}

function sameOriginResource(actorUri, value) {
  const id = resourceId(value);
  if (!id) return null;
  try {
    return new URL(id).origin === new URL(actorUri).origin ? id : null;
  } catch {
    return null;
  }
}

function bindingValue(row, name) {
  const value = row?.[name]?.value;
  return typeof value === 'string' ? value : null;
}

function withSecurityContext(context) {
  const values = context === undefined ? [] : Array.isArray(context) ? context : [context];
  return values.includes('https://w3id.org/security/v1')
    ? values
    : [...values, 'https://w3id.org/security/v1'];
}

function embeddedPublicKey(keyDocument) {
  return {
    id: keyDocument.id,
    type: keyDocument.type,
    owner: keyDocument.owner,
    controller: keyDocument.controller,
    publicKeyPem: keyDocument.publicKeyPem
  };
}

module.exports = {
  name: 'activitypub-public-keys',

  dependencies: ['api', 'auth.account', 'activitypub.actor', 'triplestore'],

  async started() {
    await this.broker.call('api.addRoute', {
      route: {
        name: 'activitypub-public-actor-document',
        path: '/:username([^/.][^/]+)',
        authentication: false,
        authorization: false,
        aliases: {
          'GET /': 'activitypub-public-keys.getActor'
        }
      },
      toBottom: false
    });
    await this.broker.call('api.addRoute', {
      route: {
        name: 'activitypub-public-key-document',
        path: '/:username([^/.][^/]+)/keys/main',
        authentication: false,
        authorization: false,
        aliases: {
          'GET /': 'activitypub-public-keys.get'
        }
      },
      toBottom: false
    });
  },

  actions: {
    getActor: {
      params: {
        username: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const account = await ctx.call('auth.account.findByUsername', { username: ctx.params.username });
        if (!account || typeof account.webId !== 'string' || !account.username) throw new E.NotFoundError();

        const actor = await ctx.call(
          'activitypub.actor.get',
          { actorUri: account.webId, webId: 'anon' },
          { meta: { dataset: account.username, webId: 'anon' } }
        );
        if (!actor || resourceId(actor) !== account.webId) throw new E.NotFoundError();
        if (Object.keys(actor).some(key => FORBIDDEN_ACTOR_FIELDS.has(key))) throw new E.NotFoundError();
        const actorType = activityStreamsActorType(actor);
        const inbox = sameOriginResource(account.webId, actor.inbox);
        if (!actorType || !inbox) throw new E.NotFoundError();

        const keyDocument = await ctx.call('activitypub-public-keys.get', { username: account.username });
        if (
          keyDocument?.id !== activityPubRsaKeyId(account.webId) ||
          keyDocument.type !== 'CryptographicKey' ||
          keyDocument.owner !== account.webId ||
          keyDocument.controller !== account.webId ||
          typeof keyDocument.publicKeyPem !== 'string'
        ) {
          throw new E.NotFoundError();
        }
        let parsedKey;
        try {
          parsedKey = crypto.createPublicKey(keyDocument.publicKeyPem);
        } catch {
          throw new E.NotFoundError();
        }
        if (parsedKey.asymmetricKeyType !== 'rsa') throw new E.NotFoundError();

        ctx.meta.$responseType = 'application/activity+json';
        ctx.meta.$responseHeaders = { 'Cache-Control': 'no-store' };
        const publicActor = { ...actor };
        delete publicActor['@id'];
        delete publicActor['@type'];
        return {
          ...publicActor,
          '@context': withSecurityContext(actor['@context']),
          id: account.webId,
          type: actorType,
          // Some consumers (including Pixelfed) require the compact
          // ActivityStreams property when first materializing a remote actor.
          // The account binding is authoritative here and avoids trusting an
          // ambiguous expanded/aliased value from the stored actor document.
          preferredUsername: account.username,
          inbox,
          publicKey: embeddedPublicKey(keyDocument)
        };
      }
    },
    get: {
      params: {
        username: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const account = await ctx.call('auth.account.findByUsername', { username: ctx.params.username });
        if (!account || typeof account.webId !== 'string' || !account.username) throw new E.NotFoundError();

        const actor = await ctx.call(
          'activitypub.actor.get',
          { actorUri: account.webId, webId: 'system' },
          { meta: { dataset: account.username, webId: 'system' } }
        );
        const expectedKeyId = activityPubRsaKeyId(account.webId);
        const matches = asArray(actor?.publicKey).filter(key => resourceId(key) === expectedKeyId);
        if (matches.length !== 1) throw new E.NotFoundError();

        const keyIri = sanitizeSparqlQuery`<${expectedKeyId}>`;
        const rows = await ctx.call('triplestore.query', {
          query: `
            PREFIX sec: <https://w3id.org/security#>
            SELECT DISTINCT ?owner ?controller ?publicKeyPem
            WHERE {
              ${keyIri} sec:owner ?owner ;
                        sec:controller ?controller ;
                        sec:publicKeyPem ?publicKeyPem .
            }
            LIMIT 2
          `,
          accept: MIME_TYPES.SPARQL_JSON,
          dataset: account.username,
          webId: 'system'
        });
        if (!Array.isArray(rows) || rows.length !== 1) throw new E.NotFoundError();
        const owner = bindingValue(rows[0], 'owner');
        const controller = bindingValue(rows[0], 'controller');
        const publicKeyPem = bindingValue(rows[0], 'publicKeyPem');
        if (!publicKeyPem || owner !== account.webId || controller !== account.webId) throw new E.NotFoundError();

        let parsedKey;
        try {
          parsedKey = crypto.createPublicKey(publicKeyPem);
        } catch {
          throw new E.NotFoundError();
        }
        if (parsedKey.asymmetricKeyType !== 'rsa') throw new E.NotFoundError();
        ctx.meta.$responseType = 'application/activity+json';
        ctx.meta.$responseHeaders = { 'Cache-Control': 'no-store' };
        return {
          '@context': [
            'https://www.w3.org/ns/activitystreams',
            'https://w3id.org/security/v1'
          ],
          id: expectedKeyId,
          type: 'CryptographicKey',
          owner: account.webId,
          controller: account.webId,
          publicKeyPem
        };
      }
    }
  }
};

module.exports.embeddedPublicKey = embeddedPublicKey;
module.exports.activityStreamsActorType = activityStreamsActorType;
module.exports.sameOriginResource = sameOriginResource;
module.exports.withSecurityContext = withSecurityContext;
