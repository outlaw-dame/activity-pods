const { StorageService } = require('@semapps/solid');
const CONFIG = require('../../config/config');
const urlJoin = require('url-join');

module.exports = {
  mixins: [StorageService],
  dependencies: ['dataset-provisioning'],
  settings: {
    baseUrl: CONFIG.BASE_URL,
    secureDataset: process.env.SEMAPPS_SECURE_DATASET !== 'false'
  },
  actions: {
    async create(ctx) {
      const { username } = ctx.params;
      if (!username) throw new Error('Cannot create Solid storage without a username');

      const shouldUseSecureDataset = this.settings.secureDataset !== false;

      if (shouldUseSecureDataset) {
        await ctx.call('dataset-provisioning.ensureSecureDataset', { dataset: username });
      } else {
        await ctx.call('triplestore.dataset.create', {
          dataset: username,
          secure: false
        });
      }

      return this.createStorageRoot(ctx, username);
    },

    // The auth service already consumed the signed claim and initialized the
    // dataset before inserting this private account. Never reissue the ticket.
    createPendingSignupRoot: {
      visibility: 'protected',
      params: { $$strict: true, username: { type: 'string', pattern: /^claimtest-[a-z0-9]{8,24}$/u } },
      async handler(ctx) {
        if (process.env.NODE_ENV !== 'test' ||
            process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE !== 'confirmed' ||
            process.env.APODS_ACCOUNT_COORDINATOR_DISPOSABLE !== 'confirmed' ||
            process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE !== 'confirmed' ||
            ctx.caller !== 'webid' || this.settings.secureDataset === false) {
          throw new Error('Pending storage creation unavailable');
        }
        const { username } = ctx.params;
        const account = await ctx.broker.call('auth.account.findByUsername', { username },
          { meta: {}, timeout: 5000, retries: 0 });
        if (!account || account.username !== username || account.webId || account.deletedAt ||
            typeof account.signupReservationId !== 'string' ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(account.signupReservationId)) {
          throw new Error('Pending storage owner mismatch');
        }
        return this.createStorageRoot(ctx, username);
      }
    }
  },
  methods: {
    async createStorageRoot(ctx, username) {
      ctx.meta.dataset = username;

      const storageRootUri = urlJoin(this.settings.baseUrl, username, this.settings.pathName);
      await ctx.call('ldp.container.create', { containerUri: storageRootUri, webId: 'system' });

      return storageRootUri;
    }
  }
};
