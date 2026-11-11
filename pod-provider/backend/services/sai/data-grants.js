const { beforeSaiMutation } = require('../utils/atproto-sai-native-fence');
const { ControlledContainerMixin } = require('@semapps/ldp');

module.exports = {
  name: 'data-grants',
  mixins: [ControlledContainerMixin],
  settings: {
    acceptedTypes: ['interop:DataGrant'],
    newResourcesPermissions: {
      anon: {
        read: true
      }
    },
    excludeFromMirror: true,
    activateTombstones: false,
    typeIndex: 'private'
  },
  dependencies: ['ldp', 'ldp.registry'],
  actions: {
    put() {
      throw new Error(`The resources of type interop:DataGrant are immutable`);
    },
    patch() {
      throw new Error(`The resources of type interop:DataGrant are immutable`);
    },
    // Get the DataGrant linked with an AccessNeed
    async getByAccessNeed(ctx) {
      const { accessNeedUri, podOwner } = ctx.params;

      const filteredContainer = await this.actions.list(
        {
          filters: {
            'http://www.w3.org/ns/solid/interop#satisfiesAccessNeed': accessNeedUri,
            'http://www.w3.org/ns/solid/interop#dataOwner': podOwner
          },
          webId: podOwner
        },
        { parentCtx: ctx }
      );

      return filteredContainer['ldp:contains']?.[0];
    },
    async getByDataAuthorization(ctx) {
      const { dataAuthorizationUri, podOwner } = ctx.params;

      const dataAuthorization = await ctx.call('data-authorizations.get', {
        resourceUri: dataAuthorizationUri,
        webId: podOwner
      });

      return await this.actions.getByAccessNeed(
        { accessNeedUri: dataAuthorization['interop:satisfiesAccessNeed'], podOwner },
        { parentCtx: ctx }
      );
    }
  },
  hooks: {
    before: {
      async post(ctx) {
        await beforeSaiMutation(ctx, 'data-grants', ctx.params.resource);
      },
      async delete(ctx) {
        if (process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED !== 'true') return;
        const resource = await this.actions.get(
          { resourceUri: ctx.params.resourceUri, webId: 'system' },
          { parentCtx: ctx }
        );
        await beforeSaiMutation(ctx, 'data-grants', resource);
      }
    }
  }
};
