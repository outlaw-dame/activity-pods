const { WebfingerService } = require('@semapps/webfinger');
const CONFIG = require('../../config/config');

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

      if (username && /^[\w._-]+$/u.test(username)) {
        // Local actor identifiers are canonical and deterministic. Avoid a
        // settings-dataset lookup on this public discovery path: the actor
        // endpoint remains authoritative and returns 404 when no actor exists.
        const webId = new URL(username, `${this.settings.baseUrl.replace(/\/$/u, '')}/`).href;
        return {
          subject: resource,
          aliases: [webId],
          links: [{ rel: 'self', type: 'application/activity+json', href: webId }]
        };
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
