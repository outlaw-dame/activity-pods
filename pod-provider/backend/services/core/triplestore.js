const { TripleStoreService, DatasetService } = require('@semapps/triplestore');
const CONFIG = require('../../config/config');
const { assertNativeProtectedStorageReleased } = require('../utils/atproto-production-release-gate');

// Verify the release boundary before the generic RDF update service exists.
assertNativeProtectedStorageReleased();

const { localPodData } = require('../../candidates/local-pod-data');
const podData = localPodData();

module.exports = {
  // Don't specify name/dependencies - the mixin provides them
  mixins: [TripleStoreService],
  settings: {
    url: CONFIG.SPARQL_ENDPOINT,
    user: CONFIG.JENA_USER,
    password: CONFIG.JENA_PASSWORD,
    fusekiBase: CONFIG.FUSEKI_BASE,
    ...(podData && { ...podData.settings, dataset:false })
  },
  ...(podData && {
    created() {
      this.subservices.dataset = this.broker.createService({
        mixins:[DatasetService],
        settings:podData.settings,
        actions:{
          async exist(ctx) { return podData.exists(ctx.params.dataset); },
          async waitForCreation(ctx) {
            // The separate administrator verified the signed dataset before acknowledging.
            if (!await podData.exists(ctx.params.dataset)) throw new Error('Signed Pod dataset missing');
          }
        },
        started:podData.assertIsolated
      });
    }
  })
};
