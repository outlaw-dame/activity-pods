/**
 * Owner-selected native SAI authorization policy.
 *
 * Required rights may be presented as preselected and locked; optional rights
 * must require an affirmative user action. Reuse this for fresh installs and
 * app upgrades so a changed app manifest never widens existing grants.
 */
export function needIdentifier(need) {
  if (typeof need === 'string') return need.trim() || null;
  if (need && typeof need === 'object' &&
      !Array.isArray(need) && typeof need.id === 'string') {
    return need.id.trim() || null;
  }
  return null;
}

export function uniqueNeedIdentifiers(needs) {
  if (!Array.isArray(needs)) return [];
  return [...new Set(needs.map(needIdentifier).filter(Boolean))];
}

export function initialConsentSelection(requiredAccessNeeds) {
  return uniqueNeedIdentifiers(requiredAccessNeeds);
}

export function hasMissingRequirements(required, optional) {
  return uniqueNeedIdentifiers(required).length > 0 ||
    uniqueNeedIdentifiers(optional).length > 0;
}

export function acceptedUpgradeNeeds(existingGrants, requiredMissing, selectedMissing, optionalMissing) {
  const required = uniqueNeedIdentifiers(requiredMissing);
  const selected = uniqueNeedIdentifiers(selectedMissing);
  const allowed = new Set([
    ...required,
    ...uniqueNeedIdentifiers(optionalMissing)
  ]);
  const selectedSet = new Set(selected);
  if (required.some(id => !selectedSet.has(id)) ||
      selected.some(id => !allowed.has(id))) {
    throw new Error('SAI_CONSENT_SELECTION_INVALID');
  }
  const alreadyGranted = uniqueNeedIdentifiers(existingGrants);
  const additions = selected.filter(id => !alreadyGranted.includes(id));
  return {
    grants: [...new Set([...alreadyGranted, ...selected])],
    additions,
    changed: additions.length > 0
  };
}


/**
 * An app manifest refresh must be acknowledged even when no new rights were
 * selected. Otherwise the remote and locally cached dc:modified values
 * diverge, causing the authorizer to redirect back to /authorize indefinitely.
 * Persisting the *same* grants is not consent to new optional rights.
 *
 * Reject malformed selections before performing a network mutation.
 */
export async function persistApprovedUpgrade({
  appUri, existingGrants, requiredMissing, selectedMissing, optionalMissing, upgradeApp
}) {
  const approved = acceptedUpgradeNeeds(
    existingGrants, requiredMissing, selectedMissing, optionalMissing
  );
  if (typeof appUri !== 'string' || !appUri ||
      typeof upgradeApp !== 'function') {
    throw new Error('SAI_UPGRADE_INVALID');
  }
  await upgradeApp({ appUri, grantedAccessNeeds: approved.grants });
  return approved;
}
