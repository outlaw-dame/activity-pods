'use strict';

const crypto = require('crypto');
const { Errors: E } = require('moleculer-web');
const { MIME_TYPES } = require('@semapps/mime-types');
const { sanitizeSparqlQuery } = require('@semapps/triplestore');
const { activityPubRsaKeyId, activityPubRsaSigningKeyId } = require('../../utils/activitypub-rsa-key-id');
const FORBIDDEN_ACTOR_FIELDS = new Set([
  'accessToken',
  'privateKey',
  'privateKeyPem',
  'refreshToken',
  'secretKey'
]);
const ACTIVITYSTREAMS_ACTOR_TYPES = new Set(['Application', 'Group', 'Organization', 'Person', 'Service']);
const RDF_MEDIA_TYPES = new Set([
  'text/turtle',
  'application/n-triples',
  'application/trig',
  'application/n-quads',
  'application/sparql-results+json'
]);

function acceptsActivityPubRepresentation(value) {
  if (typeof value !== 'string' || value.trim().length === 0) return false;
  let bestApQuality = -1;
  let bestRdfQuality = -1;

  for (const rawRange of value.split(',')) {
    const [rawMediaType, ...rawParameters] = rawRange.split(';');
    const mediaType = rawMediaType.trim().toLowerCase();
    if (!mediaType) continue;

    let quality = 1;
    let validQuality = true;
    for (const rawParameter of rawParameters) {
      const separator = rawParameter.indexOf('=');
      if (separator < 0) continue;
      const name = rawParameter.slice(0, separator).trim().toLowerCase();
      if (name !== 'q') continue;
      const rawQuality = rawParameter.slice(separator + 1).trim();
      if (!/^(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/u.test(rawQuality)) {
        validQuality = false;
        break;
      }
      quality = Number(rawQuality);
    }
    if (!validQuality || quality <= 0) continue;

    if (RDF_MEDIA_TYPES.has(mediaType)) {
      if (quality > bestRdfQuality) bestRdfQuality = quality;
    } else if (
      mediaType === 'application/activity+json' ||
      (mediaType === 'application/ld+json' && rawParameters.some(parameter =>
        /^\s*profile\s*=\s*"?https:\/\/www\.w3\.org\/ns\/activitystreams"?\s*$/iu.test(parameter)
      ))
    ) {
      if (quality > bestApQuality) bestApQuality = quality;
    }
  }

  return bestApQuality > bestRdfQuality;
}

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

function publicActivityPubContext() {
  // The stored Solid actor can carry provider-local contexts. Publishing
  // those here makes remote JSON-LD processors dereference private vocabulary
  // authorities before they can materialize an otherwise standard actor.
  // This endpoint emits only ActivityStreams fields plus the RSA verification
  // method, so its public processing context is intentionally closed.
  return ['https://www.w3.org/ns/activitystreams', 'https://w3id.org/security/v1'];
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
        onBeforeCall(ctx, _route, req) {
          ctx.meta.activityPubActorRequest = acceptsActivityPubRepresentation(req.headers?.accept);
          ctx.meta.activityPubActorAccept = typeof req.headers?.accept === 'string' ? req.headers.accept : null;
        },
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
        onBeforeCall(ctx, _route, req) {
          ctx.meta.activityPubKeyRequest = acceptsActivityPubRepresentation(req.headers?.accept);
          ctx.meta.activityPubKeyAccept = typeof req.headers?.accept === 'string' ? req.headers.accept : null;
        },
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
        // This front-inserted route exists only to provide the deliberately
        // reduced ActivityPub actor document. Preserve the established LDP
        // WebID route for Solid/OIDC and other RDF representations.
        if (ctx.meta.activityPubActorRequest === false) {
          const accept = ctx.meta.activityPubActorAccept || MIME_TYPES.JSON;
          return ctx.call('ldp.api.get', { username: ctx.params.username, slugParts: [] }, {
            meta: {
              ...ctx.meta,
              headers: { ...(ctx.meta.headers || {}), accept },
              originalHeaders: { ...(ctx.meta.originalHeaders || {}), accept }
            }
          });
        }
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
        const standardCollections = Object.fromEntries(
          ['outbox', 'followers', 'following']
            .map(field => [field, sameOriginResource(account.webId, actor[field])])
            .filter(([, value]) => value !== null)
        );

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
        const displayName =
          typeof actor.name === 'string' && actor.name.trim().length > 0
            ? actor.name
            : account.username;
        return {
          '@context': publicActivityPubContext(),
          id: account.webId,
          type: actorType,
          // Some consumers (including Pixelfed) require the compact
          // ActivityStreams property when first materializing a remote actor.
          // The account binding is authoritative here and avoids trusting an
          // ambiguous expanded/aliased value from the stored actor document.
          preferredUsername: account.username,
          // ActivityStreams permits name to be omitted, but Castopod 1.9
          // persists it into a non-null display_name column when first
          // materializing a remote actor. Use only the authenticated local
          // account name as the deterministic compatibility fallback.
          name: displayName,
          inbox,
          ...standardCollections,
          // Publish a fragment verification method for broad ActivityPub
          // interoperability. The persisted slash-style key remains the sole
          // private-material authority; this deterministic alias carries only
          // the already-validated public key and exact actor controller.
          publicKey: embeddedPublicKey({
            ...keyDocument,
            id: activityPubRsaSigningKeyId(account.webId)
          })
        };
      }
    },
    get: {
      params: {
        username: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        // As with the actor root, do not shadow the established LDP/RDF
        // representation of this resource for Solid clients.
        if (ctx.meta.activityPubKeyRequest === false) {
          const accept = ctx.meta.activityPubKeyAccept || MIME_TYPES.JSON;
          return ctx.call('ldp.api.get', { username: ctx.params.username, slugParts: ['keys', 'main'] }, {
            meta: {
              ...ctx.meta,
              headers: { ...(ctx.meta.headers || {}), accept },
              originalHeaders: { ...(ctx.meta.originalHeaders || {}), accept }
            }
          });
        }
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
        const publicKey = embeddedPublicKey({
          id: expectedKeyId,
          type: 'CryptographicKey',
          owner,
          controller,
          publicKeyPem
        });
        return {
          '@context': [
            'https://www.w3.org/ns/activitystreams',
            'https://w3id.org/security/v1'
          ],
          ...publicKey,
          // Castopod 1.9 dereferences keyId correctly, but reads the PEM from
          // an embedded publicKey. Repeat only the already-validated exact
          // verification method; never substitute another owner or key.
          publicKey
        };
      }
    }
  }
};

module.exports.acceptsActivityPubRepresentation = acceptsActivityPubRepresentation;

module.exports.embeddedPublicKey = embeddedPublicKey;
module.exports.activityStreamsActorType = activityStreamsActorType;
module.exports.sameOriginResource = sameOriginResource;
module.exports.publicActivityPubContext = publicActivityPubContext;
