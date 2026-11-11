'use strict';

const fs = require('fs');
const path = require('path');

const EXPECTED_PACKAGE = '@semapps/ldp';
const EXPECTED_VERSION = '1.1.4';
const ACTION_NAME = 'ldp.registry.register';
const PATCH_MARKER = 'ADSP-P2_LOCAL_LDP_REGISTRY_BOOTSTRAP';
const LOCAL_READY_TIMEOUT_MS = 30000;
const LOCAL_READY_POLL_MS = 25;
const ONTOLOGY_PENDING_PATTERN = /(?:Could not expand (?:all types|predicate)|No registered ontology found for resourceType)/u;

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

  throw new Error(`[ADSP-P2] Could not locate ${EXPECTED_PACKAGE} package root`);
}

function walkJavaScriptFiles(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkJavaScriptFiles(entryPath));
    } else if (/\.(?:c?js|mjs)$/u.test(entry.name)) {
      files.push(entryPath);
    }
  }
  return files;
}

function isControlledContainerCandidate(source) {
  return (
    source.includes(ACTION_NAME) &&
    source.includes('controlledActions') &&
    source.includes('waitForContainerCreation') &&
    source.includes('dependencies') &&
    source.includes('ldp')
  );
}

function locateControlledContainerSource(packageRoot) {
  const candidates = walkJavaScriptFiles(packageRoot).filter(file => {
    const source = fs.readFileSync(file, 'utf8');
    return source.includes(PATCH_MARKER) || isControlledContainerCandidate(source);
  });

  if (candidates.length !== 1) {
    throw new Error(
      `[ADSP-P2] Expected exactly one ${EXPECTED_PACKAGE} ControlledContainer artifact, found ${candidates.length}: ${candidates.join(', ')}`
    );
  }

  return candidates[0];
}

function countOccurrences(source, needle) {
  let count = 0;
  let offset = 0;
  while (true) {
    const index = source.indexOf(needle, offset);
    if (index === -1) return count;
    count += 1;
    offset = index + needle.length;
  }
}

function findMatchingCallParen(source, openParen) {
  let depth = 1;
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let index = openParen + 1; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];

    if (lineComment) {
      if (char === '\n') lineComment = false;
      continue;
    }
    if (blockComment) {
      if (char === '*' && next === '/') {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === '\\') {
        escaped = true;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }

    if (char === '/' && next === '/') {
      lineComment = true;
      index += 1;
      continue;
    }
    if (char === '/' && next === '*') {
      blockComment = true;
      index += 1;
      continue;
    }
    if (char === '\'' || char === '"' || char === '`') {
      quote = char;
      continue;
    }
    if (char === '(') depth += 1;
    if (char === ')') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }

  throw new Error('[ADSP-P2] Could not find the end of the pinned ldp.registry.register call');
}

function patchControlledContainerSource(source) {
  if (source.includes(PATCH_MARKER)) return { source, changed: false };
  if (!isControlledContainerCandidate(source)) {
    throw new Error('[ADSP-P2] SemApps ControlledContainer artifact no longer matches the expected v1.1.4 contract');
  }
  if (countOccurrences(source, ACTION_NAME) !== 1) {
    throw new Error(`[ADSP-P2] Expected exactly one ${ACTION_NAME} occurrence in ControlledContainer artifact`);
  }

  const actionIndex = source.indexOf(ACTION_NAME);
  const callIndex = source.lastIndexOf('this.broker.call(', actionIndex);
  if (callIndex === -1) {
    throw new Error(`[ADSP-P2] ${ACTION_NAME} is no longer invoked through this.broker.call`);
  }

  const statementIndex = source.lastIndexOf('const registration', callIndex);
  if (statementIndex === -1 || statementIndex > callIndex) {
    throw new Error(`[ADSP-P2] Could not locate the pinned registration assignment before ${ACTION_NAME}`);
  }

  const openParen = source.indexOf('(', callIndex);
  const closeParen = findMatchingCallParen(source, openParen);
  const callSource = source.slice(callIndex, closeParen + 1);
  if (!callSource.includes(ACTION_NAME)) {
    throw new Error(`[ADSP-P2] Located broker.call does not contain ${ACTION_NAME}`);
  }

  const paramsStart = callSource.indexOf(',', callSource.indexOf(ACTION_NAME));
  if (paramsStart === -1) {
    throw new Error(`[ADSP-P2] Could not locate ${ACTION_NAME} params in the pinned call`);
  }
  const paramsSource = callSource.slice(paramsStart + 1, -1).trim();
  if (!paramsSource.startsWith('{') || !paramsSource.endsWith('}')) {
    throw new Error(`[ADSP-P2] ${ACTION_NAME} params no longer match the expected object-literal contract`);
  }

  const semicolonIndex = source.indexOf(';', closeParen);
  if (semicolonIndex === -1 || semicolonIndex - closeParen > 8) {
    throw new Error(`[ADSP-P2] Could not locate the end of the pinned ${ACTION_NAME} assignment`);
  }

  const replacement = `let registration; // ${PATCH_MARKER}\n    let adspP2LastBootstrapError;\n    const adspP2LocalBootstrapDeadline = Date.now() + ${LOCAL_READY_TIMEOUT_MS};\n    do {\n      try {\n        const adspP2LocalRegistry = this.broker.getLocalService('ldp.registry');\n        if (!adspP2LocalRegistry || !adspP2LocalRegistry.actions || typeof adspP2LocalRegistry.actions.register !== 'function') {\n          throw new Error('[ADSP-P2] Local ldp.registry service is not ready');\n        }\n        registration = await adspP2LocalRegistry.actions.register(${paramsSource});\n        if (!registration || typeof registration !== 'object') {\n          throw new Error('[ADSP-P2] Local ldp.registry.register returned no registration object');\n        }\n      } catch (error) {\n        adspP2LastBootstrapError = error;\n        const adspP2Message = String(error && error.message ? error.message : error);\n        const adspP2BootstrapPending =\n          adspP2Message.includes('[ADSP-P2] Local ldp.registry service is not ready') ||\n          ${ONTOLOGY_PENDING_PATTERN.toString()}.test(adspP2Message);\n        if (!adspP2BootstrapPending || Date.now() >= adspP2LocalBootstrapDeadline) throw error;\n        await new Promise(resolve => setTimeout(resolve, ${LOCAL_READY_POLL_MS}));\n      }\n    } while (!registration);\n    if (!registration) throw adspP2LastBootstrapError || new Error('[ADSP-P2] Local LDP bootstrap did not produce a registration');`;

  return {
    source: `${source.slice(0, statementIndex)}${replacement}${source.slice(semicolonIndex + 1)}`,
    changed: true
  };
}

function applyPatch() {
  const packageRoot = findPackageRoot();
  const packageJson = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
  if (packageJson.version !== EXPECTED_VERSION) {
    throw new Error(
      `[ADSP-P2] Refusing to patch ${EXPECTED_PACKAGE}@${packageJson.version}; expected exactly ${EXPECTED_VERSION}`
    );
  }

  const controlledContainerFile = locateControlledContainerSource(packageRoot);
  const originalSource = fs.readFileSync(controlledContainerFile, 'utf8');
  const result = patchControlledContainerSource(originalSource);

  if (result.changed) {
    fs.writeFileSync(controlledContainerFile, result.source, 'utf8');
    process.stdout.write(
      `[ADSP-P2] Patched ${path.relative(packageRoot, controlledContainerFile)} so controlled-container bootstrap waits for local semantic readiness\n`
    );
  } else {
    process.stdout.write(`[ADSP-P2] ${path.relative(packageRoot, controlledContainerFile)} already patched\n`);
  }

  return { packageRoot, controlledContainerFile, changed: result.changed };
}

if (require.main === module) applyPatch();

module.exports = {
  EXPECTED_PACKAGE,
  EXPECTED_VERSION,
  ACTION_NAME,
  PATCH_MARKER,
  LOCAL_READY_TIMEOUT_MS,
  LOCAL_READY_POLL_MS,
  ONTOLOGY_PENDING_PATTERN,
  findPackageRoot,
  locateControlledContainerSource,
  findMatchingCallParen,
  patchControlledContainerSource,
  applyPatch
};
