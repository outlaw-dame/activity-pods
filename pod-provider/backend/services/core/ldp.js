const { LdpService, DocumentTaggerMixin } = require('@semapps/ldp');
const CONFIG = require('../../config/config');
const { assertNotManagedLdpMutation } = require('../utils/atproto-ldp-write-barrier');

module.exports = {
  // Don't specify name/dependencies - the mixin provides them
  mixins: [LdpService, DocumentTaggerMixin],
  // SemApps creates the ldp.resource and ldp.container services internally.
  // These hooks run on their *actual* actions, including direct Moleculer
  // calls that bypass our ControlledContainerMixin service.
  hooksResource: {
    before: {
      create(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL); },
      put(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL); },
      patch(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL); },
      delete(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL); },
      upload(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL); }
    }
  },
  hooksContainer: {
    before: {
      post(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL); },
      create(ctx) {
        assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL, { allowEmptyBootstrap: 'create' });
      },
      createAndAttach(ctx) {
        assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL, { allowEmptyBootstrap: 'create' });
      },
      delete(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL, { protectAncestors: true }); },
      clear(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL, { protectAncestors: true }); },
      patch(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL); },
      attach(ctx) {
        assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL, { allowEmptyBootstrap: 'attach' });
      },
      detach(ctx) { assertNotManagedLdpMutation(ctx, CONFIG.BASE_URL); }
    }
  },
  settings: {
    baseUrl: CONFIG.BASE_URL,
    podProvider: true,
    resourcesWithContainerPath: false,
    defaultContainerOptions: {
      permissions: {},
      newResourcesPermissions: {}
    }
  }
};
