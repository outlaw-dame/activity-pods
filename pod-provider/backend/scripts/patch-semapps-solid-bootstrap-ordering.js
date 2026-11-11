'use strict';

// Narrow, fail-closed compatibility repair for pinned SemApps Solid 1.1.4.
// No alternate account bootstrap, event emission, storage writer or synthetic resource.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PACKAGE = '@semapps/solid';
const VERSION = '1.1.4';
const MARKER = 'APODS_SOLID_BOOTSTRAP_DEPENDENCY_BARRIER_V1';
const WAIT_OLD = 'while (!indexUri || attempts > 30);';
const WAIT_NEW = 'while (!indexUri && attempts <= 30);';
const CREATE_OLD = 'await this.actions.createPrivateIndex({ webId }, { parentCtx: ctx });';
const CREATE_NEW = `// ${MARKER}: preferences creation is a separate auth.registered handler.\n        // Do not dereference it before its actual persisted resource exists.\n        await ctx.call('solid-preferences-file.waitForResourceCreation', { webId });\n        ${CREATE_OLD}`;

function occurrences(source, needle) {
  return source.split(needle).length - 1;
}

function patchTypeIndexes(source) {
  if (source.includes(MARKER)) {
    if (occurrences(source, MARKER) !== 1 ||
        occurrences(source, CREATE_NEW) !== 1 ||
        occurrences(source, WAIT_NEW) !== 1 ||
        occurrences(source, WAIT_OLD) !== 0) {
      throw new Error('Existing SemApps Solid bootstrap repair drifted');
    }
    new vm.Script(source);
    return { source, changed: false };
  }
  if (occurrences(source, CREATE_OLD) !== 1 ||
      occurrences(source, WAIT_OLD) !== 1 ||
      !source.includes("'auth.registered'") ||
      !source.includes('createPublicIndex') ||
      !source.includes('createPrivateIndex') ||
      !source.includes('waitForIndexCreation')) {
    throw new Error('Pinned SemApps Solid type-indexes implementation changed; refusing patch');
  }
  const patched = source.replace(CREATE_OLD, CREATE_NEW).replace(WAIT_OLD, WAIT_NEW);
  new vm.Script(patched);
  return { source: patched, changed: true };
}

function packageRoot() {
  let current = path.dirname(require.resolve(PACKAGE));
  while (current !== path.dirname(current)) {
    const filename = path.join(current, 'package.json');
    if (fs.existsSync(filename)) {
      const data = JSON.parse(fs.readFileSync(filename, 'utf8'));
      if (data.name === PACKAGE) {
        if (data.version !== VERSION) throw new Error(`Expected ${PACKAGE}@${VERSION}, got ${data.version}`);
        return current;
      }
    }
    current = path.dirname(current);
  }
  throw new Error('Cannot locate pinned SemApps Solid package');
}

function applyPatch() {
  const root = packageRoot();
  const file = path.join(root, 'services', 'type-index', 'type-indexes.js');
  if (!fs.existsSync(file)) throw new Error('Pinned SemApps Solid type-indexes path missing');
  const original = fs.readFileSync(file, 'utf8');
  const result = patchTypeIndexes(original);
  if (result.changed) fs.writeFileSync(file, result.source, 'utf8');
  process.stdout.write(`[Solid bootstrap] ${result.changed ? 'patched' : 'verified'} pinned type-index dependency barrier\n`);
  return result;
}

if (require.main === module) applyPatch();
module.exports = { VERSION, MARKER, WAIT_OLD, WAIT_NEW, CREATE_OLD, CREATE_NEW, patchTypeIndexes, applyPatch };
