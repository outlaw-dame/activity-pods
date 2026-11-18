const { WebIdService } = require('@semapps/webid');
const { FULL_ACTOR_TYPES } = require('@semapps/activitypub');
const CONFIG = require('../../config/config');

module.exports = {
  mixins: [WebIdService],
  settings: {
    path: '/',
    baseUrl: CONFIG.BASE_URL,
    acceptedTypes: Object.values(FULL_ACTOR_TYPES),
    podProvider: true,
    podsContainer: true, // Will register the container but not create LDP containers on a dataset
    newResourcesPermissions: {
      anon: {
        read: true
      }
    }
  },
  hooks: {
    before: {
      async createWebId(ctx) {
        const { nick } = ctx.params;
        if (process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE === 'confirmed') {
          if (process.env.NODE_ENV !== 'test' || ctx.caller !== 'auth' || ctx.meta.isSignup !== true) {
            throw new Error('Delegated WebID creation requires provider signup');
          }
          await ctx.call('solid-storage.createPendingSignupRoot', { username: nick });
        } else {
          await ctx.call('solid-storage.create', { username: nick });
        }
        ctx.params['solid:oidcIssuer'] = CONFIG.BASE_URL.replace(/\/$/, ''); // Remove trailing slash if it exists
      }
    }
  }
};
