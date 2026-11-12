'use strict';

// A single shared ioredis client per node is closed on graceful Moleculer
// shutdown. This service has no public actions, and imports no Redis client
// unless the test-only distributed SAI feature is actually exercised.
const { closeDistributedSaiOwnerProof } =
  require('./utils/atproto-sai-distributed-owner-runtime');
module.exports = {
  name: 'internal-sai-owner-proof-lifecycle',
  async stopped() {
    await closeDistributedSaiOwnerProof();
  }
};
