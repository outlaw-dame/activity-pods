const { TripleStoreService } = require('@semapps/triplestore');
const CONFIG = require('../../config/config');
const { assertNativeProtectedStorageReleased } = require('../utils/atproto-production-release-gate');

// Verify the release boundary before the generic RDF update service exists.
assertNativeProtectedStorageReleased();

module.exports = {
  // Don't specify name/dependencies - the mixin provides them
  mixins: [TripleStoreService],
  settings: {
    url: CONFIG.SPARQL_ENDPOINT,
    user: CONFIG.JENA_USER,
    password: CONFIG.JENA_PASSWORD,
    fusekiBase: CONFIG.FUSEKI_BASE
  }
};
