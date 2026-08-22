const { SignatureService } = require('@semapps/crypto');
const { generateAuthorityBoundSignatureHeaders } = require('../../utils/native-activitypub-signing');

module.exports = {
  mixins: [SignatureService],
  actions: {
    // SemApps 1.1.4 signs native deliveries with keyId=<actor URI>, even
    // though the published RSA verification method has its own URI. Strict
    // implementations such as Akkoma reject that mismatch. Route native
    // signing through the same hardened ActivityPods authority chain as the
    // external sidecar so both modes use the exact actor-attached key ID.
    generateSignatureHeaders: {
      async handler(ctx) {
        return generateAuthorityBoundSignatureHeaders(ctx);
      }
    }
  }
};
