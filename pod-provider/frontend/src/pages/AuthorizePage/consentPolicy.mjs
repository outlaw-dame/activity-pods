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
