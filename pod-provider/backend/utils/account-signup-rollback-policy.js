'use strict';

/**
 * Releasing a WebID, private signing keys or an account name after a possibly
 * submitted did:plc genesis creates a permanent identity split. Neither an
 * RPC error nor a timeout implies the PLC directory rejected the operation.
 */
function mustPreserveFailedSignup(env = process.env) {
  return env.NODE_ENV === 'production' ||
    env.APODS_ATPROTO_ENABLE_PLC_SUBMISSION === 'true';
}
module.exports = Object.freeze({ mustPreserveFailedSignup });
