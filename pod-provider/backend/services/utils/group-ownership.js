'use strict';

/**
 * Legacy ActivityPods group-account ownership guard.
 *
 * The account's `owns` collection is not evidence that its subject controls
 * arbitrary group actors. Only a provider-provisioned local group account with
 * an exact owner binding may be attached to an owner's account.
 *
 * This is intentionally scoped to legacy `groups.claim`. Future collective
 * multi-owner governance must have its own provider-authoritative grants; it
 * must not silently broaden this legacy account-linking API.
 */
function isClaimableGroup({ groupWebId, groupAccount, ownerWebId, trustedProviderCall = false }) {
  if (typeof groupWebId !== 'string' || groupWebId.length === 0 || groupWebId !== groupWebId.trim()) {
    return false;
  }
  if (!groupAccount || typeof groupAccount !== 'object' || Array.isArray(groupAccount)) {
    return false;
  }
  if (groupAccount.webId !== groupWebId || groupAccount.group !== true || groupAccount.disabled === true) {
    return false;
  }
  if (trustedProviderCall === true) return true;

  return (
    typeof ownerWebId === 'string' &&
    ownerWebId !== '' &&
    typeof groupAccount.owner === 'string' &&
    groupAccount.owner === ownerWebId
  );
}

function isSafeGroupSlug(value) {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value);
}

module.exports = { isClaimableGroup, isSafeGroupSlug };
