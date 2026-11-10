const { WebfingerService } = require('@semapps/webfinger');
const CONFIG = require('../../config/config');

const LOCAL_USERNAME_PATTERN = /^[\w._-]+$/u;

function webfingerDocument(resource, actorUri) {
  return {
    subject: resource,
    aliases: [actorUri],
    links: [{ rel: 'self', type: 'application/activity+json', href: actorUri }]
  };
}

function localActivityPubResource(resource, baseUrl) {
  if (typeof resource !== 'string' || typeof baseUrl !== 'string') return null;

  let resourceUrl;
  let base;
  try {
    resourceUrl = new URL(resource);
    base = new URL(baseUrl);
  } catch {
    return null;
  }

  if (resourceUrl.origin !== base.origin || resourceUrl.search || resourceUrl.hash) return null;

  const basePath = base.pathname.replace(/\/+$/u, '');
  const baseHref = `${base.origin}${basePath}/`;
  const pathPrefix = new URL(baseHref).pathname;
  if (!resourceUrl.pathname.startsWith(pathPrefix)) return null;

  const relativePath = resourceUrl.pathname.slice(pathPrefix.length);
  const segments = relativePath.split('/');
  const isActor = segments.length === 1;
  const isKey = segments.length === 3 && segments[1] === 'keys' && segments[2] === 'main';
  if (!isActor && !isKey) return null;

  const username = segments[0];
  if (!LOCAL_USERNAME_PATTERN.test(username)) return null;

  const actorUri = new URL(username, baseHref).href;
  const keyUri = `${actorUri.replace(/\/$/u, '')}/keys/main`;
  const canonicalResource = isKey ? keyUri : actorUri;
  if (resourceUrl.href !== canonicalResource) return null;

  return { username, actorUri };
}

module.exports = {
  mixins: [WebfingerService],
  settings: {
    baseUrl: CONFIG.BASE_URL
  },
  actions: {
    async get(ctx) {
      const { resource } = ctx.params;
      const suffix = `@${this.settings.domainName}`;
      const username = typeof resource === 'string' && resource.startsWith('acct:') && resource.endsWith(suffix)
        ? resource.slice('acct:'.length, -suffix.length)
        : null;

      if (username && LOCAL_USERNAME_PATTERN.test(username)) {
        // Local acct identifiers are canonical and deterministic. Avoid a
        // settings-dataset lookup on this public discovery path: the actor
        // endpoint remains authoritative and returns 404 when no actor exists.
        const webId = new URL(username, `${this.settings.baseUrl.replace(/\/$/u, '')}/`).href;
        return webfingerDocument(resource, webId);
      }

      const localResource = localActivityPubResource(resource, this.settings.baseUrl);
      if (localResource) {
        let account;
        try {
          // Friendica probes HTTP keyId/actor resources through WebFinger before
          // dereferencing them. Resolve only an exact authoritative local
          // username -> WebID binding; arbitrary same-origin resources remain
          // outside this public discovery directory.
          account = await this.broker.call('auth.account.findByUsername', { username: localResource.username });
        } catch (e) {
          this.logger?.debug?.(`Local WebFinger authority lookup failed closed: ${e.message}`);
        }

        if (
          account &&
          account.username === localResource.username &&
          account.webId === localResource.actorUri
        ) {
          return webfingerDocument(resource, localResource.actorUri);
        }
      }

      ctx.meta.$statusCode = 404;
    }
  },
  // FEP-3B86 §3 — append Activity Intent link templates to every WebFinger
  // response without forking the upstream @semapps/webfinger action.
  hooks: {
    after: {
      async get(ctx, res) {
        if (!res || !Array.isArray(res.links)) return res;
        try {
          // This is public, deterministic provider metadata. Keep the remote
          // request principal and deadline out of the local service call, and
          // bound the optional enrichment so WebFinger cannot be held open.
          const intentLinks = await this.broker.call('fep-3b86-activity-intents.getLinks', {}, { timeout: 1000 });
          if (Array.isArray(intentLinks) && intentLinks.length > 0) {
            res.links.push(...intentLinks);
          }
        } catch (e) {
          // Activity Intents are advisory; WebFinger remains available if the
          // companion intent service is unavailable.
          this.logger.debug(`FEP-3B86 intent links unavailable: ${e.message}`);
        }
        return res;
      }
    }
  }
};
