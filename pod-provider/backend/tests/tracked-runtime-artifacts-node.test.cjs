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
    'SEMAPPS_SPARQL_ENDPOINT=http://localhost:3030',
    'SEMAPPS_QUEUE_SERVICE_URL=redis://localhost:6379',
    'SEMAPPS_REDIS_TRANSPORTER_URL=redis://localhost:6379',
    'SEMAPPS_REDIS_OIDC_PROVIDER_URL=redis://localhost:6379'
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
  }), /Unexpected tracked test environment key/u);
  assert.throws(() => readAssignments('A=one\nA=two'), /Duplicate/u);
  assert.throws(() => readAssignments('this is not an assignment'), /Invalid/u);
});

test('current Git index and tracked test fixtures pass hardened source guard', () => {
  const count = auditTrackedArtifacts();
  assert.ok(count > 0);
});
