'use strict';

const fs = require('fs');
const path = require('path');

const EXPECTED_PACKAGE = '@semapps/ldp';
const EXPECTED_VERSION = '1.1.4';
const PATCH_MARKER = 'ACTIVITYPODS_LDP_SAME_DOCUMENT_FRAGMENTS';
const ORIGINAL_FILTER = '`FILTER((isBLANK(?o${i}))) .`,';
const PATCHED_FILTER =
  '`FILTER((isBLANK(?o${i}) || (isIRI(?o${i}) && STRSTARTS(STR(?o${i}), CONCAT(STR(?s1), "#"))))) .`, // ACTIVITYPODS_LDP_SAME_DOCUMENT_FRAGMENTS';

function countOccurrences(source, needle) {
  return source.split(needle).length - 1;
}

function patchSource(source) {
  if (source.includes(PATCH_MARKER)) {
    if (!source.includes(PATCHED_FILTER)) {
      throw new Error('[ActivityPods] SemApps LDP fragment patch marker exists without the expected filter');
    }
    return { source, changed: false };
  }
  const count = countOccurrences(source, ORIGINAL_FILTER);
  if (count !== 1) {
    throw new Error(`[ActivityPods] Expected one pinned SemApps blank-node filter, found ${count}`);
  }
  return { source: source.replace(ORIGINAL_FILTER, PATCHED_FILTER), changed: true };
}

function findPackageRoot() {
  let current = path.dirname(require.resolve(EXPECTED_PACKAGE));
  while (current !== path.dirname(current)) {
    const packageJsonPath = path.join(current, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      if (packageJson.name === EXPECTED_PACKAGE) return current;
    }
    current = path.dirname(current);
  }
  throw new Error(`[ActivityPods] Could not locate ${EXPECTED_PACKAGE}`);
}

function applyPatch() {
  const packageRoot = findPackageRoot();
  const packageJson = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
  if (packageJson.version !== EXPECTED_VERSION) {
    throw new Error(
      `[ActivityPods] Refusing to patch ${EXPECTED_PACKAGE}@${packageJson.version}; expected ${EXPECTED_VERSION}`
    );
  }
  const target = path.join(packageRoot, 'utils.js');
  const result = patchSource(fs.readFileSync(target, 'utf8'));
  if (result.changed) fs.writeFileSync(target, result.source, 'utf8');
  process.stdout.write(
    `[ActivityPods] SemApps LDP same-document fragment traversal ${result.changed ? 'patched' : 'verified'}\n`
  );
  return { target, changed: result.changed };
}

if (require.main === module) applyPatch();

module.exports = {
  EXPECTED_PACKAGE,
  EXPECTED_VERSION,
  PATCH_MARKER,
  ORIGINAL_FILTER,
  PATCHED_FILTER,
  patchSource,
  applyPatch
};
