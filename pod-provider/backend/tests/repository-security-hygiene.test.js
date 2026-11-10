'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '../../..');
const BACKEND_PREFIX = 'pod-provider/backend/';
const ALLOWED_TRACKED_ENV_FILES = new Set([
  'pod-provider/backend/.env.example',
  'pod-provider/backend/.env.test'
]);
const REQUIRED_BLANK_EXAMPLE_SECRETS = [
  'SEMAPPS_JENA_PASSWORD',
  'SEMAPPS_COOKIE_SECRET',
  'SEMAPPS_SMTP_USER',
  'SEMAPPS_SMTP_PASS',
  'SEMAPPS_BACKUP_SERVER_PASSWORD',
  'SIDECAR_TOKEN',
  'ACTIVITYPODS_TOKEN'
];

function trackedFiles() {
  return execFileSync('git', ['ls-files', '-z'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024
  })
    .split('\0')
    .filter(Boolean);
}

function parseEnvAssignments(text) {
  const assignments = new Map();
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 1) continue;
    assignments.set(line.slice(0, separator).trim(), line.slice(separator + 1).trim());
  }
  return assignments;
}

describe('repository security hygiene', () => {
  test('does not track backend runtime environment files or Redis snapshots', () => {
    const backendFiles = trackedFiles().filter(file => file.startsWith(BACKEND_PREFIX));
    const unexpectedEnvFiles = backendFiles.filter(file => {
      const basename = path.posix.basename(file);
      return basename.startsWith('.env') && !ALLOWED_TRACKED_ENV_FILES.has(file);
    });
    const trackedRedisSnapshots = backendFiles.filter(file => file.toLowerCase().endsWith('.rdb'));

    expect(unexpectedEnvFiles).toEqual([]);
    expect(trackedRedisSnapshots).toEqual([]);
  });

  test('keeps secret-bearing placeholders blank in the committed environment example', () => {
    const examplePath = path.join(REPO_ROOT, 'pod-provider/backend/.env.example');
    const assignments = parseEnvAssignments(fs.readFileSync(examplePath, 'utf8'));

    for (const variable of REQUIRED_BLANK_EXAMPLE_SECRETS) {
      expect(assignments.has(variable)).toBe(true);
      expect(assignments.get(variable)).toBe('');
    }
  });

  test('keeps ignore rules that prevent the same runtime artifacts from being recommitted', () => {
    const ignorePath = path.join(REPO_ROOT, 'pod-provider/backend/.gitignore');
    const ignoreLines = new Set(
      fs.readFileSync(ignorePath, 'utf8').split(/\r?\n/u).map(line => line.trim()).filter(Boolean)
    );

    expect(ignoreLines.has('.env')).toBe(true);
    expect(ignoreLines.has('!.env.example')).toBe(true);
    expect(ignoreLines.has('!.env.test')).toBe(true);
    expect(ignoreLines.has('*.rdb')).toBe(true);
  });
});
