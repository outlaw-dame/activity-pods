'use strict';

/**
 * ActivityPods represents these rights in two exact, legitimate forms:
 * application request JSON may use compact CURIEs, while persisted JSON-LD
 * reads return fully expanded RDF IRIs. Never compare by suffix or substring.
 */
const NS = 'http://activitypods.org/ns/core#';
const CANONICAL = Object.freeze({
  CreateGroup: Object.freeze(['apods:CreateGroup', NS + 'CreateGroup']),
  ReadGroups: Object.freeze(['apods:ReadGroups', NS + 'ReadGroups'])
});
const EXACT = new Set(Object.values(CANONICAL).flat());

function isGroupRight(value) {
  return typeof value === 'string' && EXACT.has(value);
}

function hasGroupRight(rights, right) {
  const forms = CANONICAL[right];
  if (!forms || !Array.isArray(rights)) return false;
  return rights.some(value => forms.includes(value));
}

function onlyGroupRights(rights) {
  return Array.isArray(rights) && rights.length > 0 && rights.every(isGroupRight);
}

module.exports = Object.freeze({ NS, isGroupRight, hasGroupRight, onlyGroupRights });
