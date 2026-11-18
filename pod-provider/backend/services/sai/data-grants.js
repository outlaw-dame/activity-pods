const { findScopedRecord } = require('../utils/sai-scoped-lookup');
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
      return findScopedRecord(this, ctx, 'dataOwner', 'satisfiesAccessNeed', ctx.params.accessNeedUri);
    },
    async getByDataAuthorization(ctx) {
      const { dataAuthorizationUri, podOwner, appUri } = ctx.params;

      const dataAuthorization = await ctx.call('data-authorizations.get', {
        resourceUri: dataAuthorizationUri,
        webId: podOwner
      });

      if (dataAuthorization['interop:dataOwner'] !== podOwner || dataAuthorization['interop:grantee'] !== appUri) {
        throw new Error('Mismatched SAI data authorization');
      }
      return await this.actions.getByAccessNeed(
        { accessNeedUri: dataAuthorization['interop:satisfiesAccessNeed'], podOwner, appUri },
        { parentCtx: ctx }
      );
    }
  },
  hooks: {
    before: {
      async post(ctx) {
        await beforeSaiMutation(ctx, 'data-grants', ctx.params.resource, 'post');
      },
      async delete(ctx) {
        if (process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED !== 'true') return;
        const resource = await this.actions.get(
          { resourceUri: ctx.params.resourceUri, webId: 'system' },
          { parentCtx: ctx }
        );
        await beforeSaiMutation(ctx, 'data-grants', resource, 'delete');
      }
    }
  }
};
