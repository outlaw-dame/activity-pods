'use strict';

// SemApps LDP 1.1.4 single-resource readiness must not loop forever.
// The upstream loop continues while attempts > 30, even if the resource is absent.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PACKAGE = '@semapps/ldp';
const VERSION = '1.1.4';
const MARKER = 'APODS_SINGLE_RESOURCE_BOUNDED_WAIT_V1';
const BEFORE = 'while (!resource || attempts > 30);';
const AFTER = 'while (!resource && attempts <= 30);';

function patchSingleResource(source) {
  if (source.includes(MARKER)) {
    if (!source.includes(AFTER) || source.includes(BEFORE) ||
        source.split(MARKER).length !== 2) {
      throw new Error('Pinned single-resource readiness repair drifted');
    }
    new vm.Script(source);
    return { source, changed: false };
  }
  if (source.split(BEFORE).length !== 2 ||
      !source.includes('waitForResourceCreation') ||
      !source.includes('Resource still had not been created after 30s')) {
    throw new Error('Pinned single-resource readiness implementation changed; refusing patch');
  }
  const result = source.replace(BEFORE, AFTER + ' // ' + MARKER);
  new vm.Script(result);
  return { source: result, changed: true };
}

function applyPatch() {
  let root = path.dirname(require.resolve(PACKAGE));
  while (root !== path.dirname(root)) {
    const manifest = path.join(root, 'package.json');
    if (fs.existsSync(manifest)) {
      const pkg = JSON.parse(fs.readFileSync(manifest, 'utf8'));
      if (pkg.name === PACKAGE) {
        if (pkg.version !== VERSION) throw new Error('Unexpected SemApps LDP version');
        const file = path.join(root, 'mixins', 'single-resource-container.js');
        const original = fs.readFileSync(file, 'utf8');
        const result = patchSingleResource(original);
        if (result.changed) fs.writeFileSync(file, result.source, 'utf8');
        process.stdout.write(`[Solid bootstrap] ${result.changed ? 'patched' : 'verified'} bounded single-resource readiness\n`);
        return result;
      }
    }
    root = path.dirname(root);
  }
  throw new Error('Cannot locate pinned SemApps LDP');
}

if (require.main === module) applyPatch();
module.exports = { MARKER, BEFORE, AFTER, patchSingleResource, applyPatch };
