#!/usr/bin/env node
'use strict';

/**
 * Prevent serialized account state and runtime secrets from re-entering the
 * Git index. Check the INDEX rather than the working tree: legitimate local
 * .env and Redis persistence files must not cause a false CI failure.
 */
const path = require('node:path');
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '../../..');
const BACKEND = 'pod-provider/backend/';
const TEST_FIXTURE = new Map([
  ['SEMAPPS_SPARQL_ENDPOINT', 'http://localhost:3040/'],
  ['SEMAPPS_QUEUE_SERVICE_URL', 'redis://localhost:6379/11'],
  ['SEMAPPS_REDIS_TRANSPORTER_URL', 'redis://localhost:6379/12'],
  ['SEMAPPS_REDIS_OIDC_PROVIDER_URL', 'redis://localhost:6379/13']
]);
const EMPTY_IN_TEMPLATE = new Set([
  'SEMAPPS_JENA_PASSWORD',
  'SEMAPPS_COOKIE_SECRET',
  'SEMAPPS_SMTP_PASS',
  'SEMAPPS_BACKUP_SERVER_PASSWORD',
  'SIDECAR_TOKEN',
  'ACTIVITYPODS_TOKEN',
  'SIGNING_API_TOKEN'
]);

function forbiddenTrackedPath(relativePath) {
  if (typeof relativePath !== 'string' ||
      !relativePath.startsWith(BACKEND)) return false;
  const remainder = relativePath.slice(BACKEND.length);
  const file = path.posix.basename(remainder);
  if (file === '.env' || (file.startsWith('.env.') &&
      file !== '.env.example' && file !== '.env.test')) return true;
  if (/\.(?:rdb|aof)$/iu.test(file)) return true;
  if (remainder.split('/').includes('appendonlydir')) return true;
  return false;
}

function readAssignments(source) {
  const assignments = new Map();
  for (const line of source.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = /^([A-Za-z_][A-Za-z_0-9]*)=(.*)$/u.exec(trimmed);
    if (!match) throw new Error('Invalid environment template assignment');
    if (assignments.has(match[1])) throw new Error('Duplicate environment setting');
    assignments.set(match[1], match[2].trim());
  }
  return assignments;
}

function validateSafeTemplates({ example, testFixture }) {
  const template = readAssignments(example);
  const fixture = readAssignments(testFixture);
  for (const key of EMPTY_IN_TEMPLATE) {
    if (!template.has(key) || template.get(key) !== '') {
      throw new Error('Secret-bearing environment template must have empty value: ' + key);
    }
  }
  for (const [key, value] of template) {
    if (/(?:^|_)(?:TOKEN|PASSWORD|PASS|SECRET|PRIVATE|KEY|CREDENTIAL)(?:_|$)/iu.test(key) &&
        value !== '') {
      throw new Error('Secret-looking example environment value is populated: ' + key);
    }
  }
  for (const [key, value] of fixture) {
    if (!TEST_FIXTURE.has(key) || TEST_FIXTURE.get(key) !== value) {
      throw new Error('Unexpected tracked test environment value: ' + key);
    }
  }
  if (fixture.size !== TEST_FIXTURE.size) {
    throw new Error('Tracked test environment fixture has changed');
  }
}

function auditTrackedArtifacts() {
  const filenames = execFileSync('git', ['ls-files', '-z', '--cached'], {
    cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024
  }).split('\0').filter(Boolean);
  const violations = filenames.filter(forbiddenTrackedPath);
  if (violations.length > 0) {
    // Paths alone, never contents of env files, credentials or Redis dumps.
    throw new Error('Forbidden runtime artifacts tracked in Git: ' +
      violations.join(', '));
  }
  validateSafeTemplates({
    example: fs.readFileSync(path.join(REPO_ROOT, BACKEND, '.env.example'), 'utf8'),
    testFixture: fs.readFileSync(path.join(REPO_ROOT, BACKEND, '.env.test'), 'utf8')
  });
  return filenames.length;
}

if (require.main === module) {
  try {
    const checked = auditTrackedArtifacts();
    process.stdout.write('Runtime artifact index guard passed (' + checked +
      ' tracked paths inspected).\n');
  } catch (error) {
    process.stderr.write('Runtime artifact index guard FAILED: ' +
      (error instanceof Error ? error.message : 'unknown') + '\n');
    process.exitCode = 1;
  }
}

module.exports = { forbiddenTrackedPath, readAssignments,
  validateSafeTemplates, auditTrackedArtifacts };
