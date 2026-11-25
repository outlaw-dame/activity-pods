'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  forbiddenTrackedPath, readAssignments, validateSafeTemplates, auditTrackedArtifacts
} = require('../scripts/proof-no-tracked-runtime-artifacts.cjs');

test('reject runtime env files, RDB/AOF snapshots and persistence directories', () => {
  for (const filename of [
    'pod-provider/backend/.env',
    'pod-provider/backend/.env.production',
    'pod-provider/backend/.env.local',
    'pod-provider/backend/dump.rdb',
    'pod-provider/backend/session.rdb',
    'pod-provider/backend/appendonly.aof',
    'pod-provider/backend/appendonlydir/appendonly.aof.1.base.rdb'
  ]) assert.equal(forbiddenTrackedPath(filename), true, filename);
  for (const filename of [
    'pod-provider/backend/.env.example',
    'pod-provider/backend/.env.test',
    'pod-provider/backend/config/config.js',
    'pod-provider/backend/tests/fixture.json',
    'other-repository/redis.rdb'
  ]) assert.equal(forbiddenTrackedPath(filename), false, filename);
});

test('reject populated sensitive templates, unexpected test keys and duplicates', () => {
  const keys = [
    'SEMAPPS_JENA_PASSWORD', 'SEMAPPS_COOKIE_SECRET', 'SEMAPPS_SMTP_PASS',
    'SEMAPPS_BACKUP_SERVER_PASSWORD', 'SIDECAR_TOKEN',
    'ACTIVITYPODS_TOKEN', 'SIGNING_API_TOKEN'
  ];
  const example = keys.map(key => key + '=').join('\n');
  const fixture = [
    'SEMAPPS_SPARQL_ENDPOINT=http://localhost:3040/',
    'SEMAPPS_QUEUE_SERVICE_URL=redis://localhost:6379/11',
    'SEMAPPS_REDIS_TRANSPORTER_URL=redis://localhost:6379/12',
    'SEMAPPS_REDIS_OIDC_PROVIDER_URL=redis://localhost:6379/13'
  ].join('\n');
  assert.doesNotThrow(() => validateSafeTemplates({
    example, testFixture: fixture
  }));
  assert.throws(() => validateSafeTemplates({
    example: example.replace('SEMAPPS_COOKIE_SECRET=', 'SEMAPPS_COOKIE_SECRET=leaked'),
    testFixture: fixture
  }), /SEMAPPS_COOKIE_SECRET/u);
  assert.throws(() => validateSafeTemplates({
    example, testFixture: fixture + '\nSIGNING_API_TOKEN=leaked'
  }), /Unexpected tracked test environment value/u);
  assert.throws(() => validateSafeTemplates({
    example: example + '\nNEW_SERVICE_TOKEN=leaked', testFixture: fixture
  }), /NEW_SERVICE_TOKEN/u);
  assert.throws(() => validateSafeTemplates({
    example, testFixture: fixture.replace('localhost:6379/12', 'external.example.org:6379/12')
  }), /Unexpected tracked test environment value/u);
  assert.throws(() => readAssignments('A=one\nA=two'), /Duplicate/u);
  assert.throws(() => readAssignments('this is not an assignment'), /Invalid/u);
});

test('current Git index and tracked test fixtures pass hardened source guard', () => {
  const count = auditTrackedArtifacts();
  assert.ok(count > 0);
});

test('local example separates Redis service databases and binds them to loopback', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const example = readAssignments(fs.readFileSync(
    path.join(__dirname, '../.env.example'), 'utf8'
  ));
  const names = [
    'SEMAPPS_REDIS_CACHE_URL',
    'SEMAPPS_QUEUE_SERVICE_URL',
    'SEMAPPS_REDIS_TRANSPORTER_URL',
    'SEMAPPS_REDIS_OIDC_PROVIDER_URL'
  ];
  const databases = new Set();
  for (const key of names) {
    const address = new URL(example.get(key));
    assert.equal(address.protocol, 'redis:');
    assert.equal(address.hostname, 'localhost');
    assert.equal(address.port, '6379');
    assert.match(address.pathname, /^\/[0-9]+$/u);
    assert.equal(address.username, '');
    assert.equal(address.password, '');
    assert.equal(address.search, '');
    assert.equal(address.hash, '');
    assert.equal(databases.has(address.pathname), false,
      'Two local Redis services must not share a database');
    databases.add(address.pathname);
  }
  assert.equal(databases.size, names.length);
  assert.equal(example.get('SEMAPPS_FUSEKI_BASE'), '../data/fuseki');
});
