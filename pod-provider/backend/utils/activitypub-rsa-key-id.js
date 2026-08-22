'use strict';

function activityPubRsaKeyId(actorUri) {
  const parsed = new URL(actorUri);
  if (
    !['http:', 'https:'].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error('RSA key owner must be a credential-free HTTP(S) actor URI without query or fragment');
  }
  parsed.pathname = `${parsed.pathname.replace(/\/$/u, '')}/keys/main`;
  return parsed.toString();
}

module.exports = { activityPubRsaKeyId };
