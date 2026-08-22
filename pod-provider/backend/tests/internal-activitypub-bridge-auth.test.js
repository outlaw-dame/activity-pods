'use strict';

const ENV_KEYS = ['ACTIVITYPODS_TOKEN', 'INTERNAL_API_TOKEN', 'SIDECAR_TOKEN'];

function snapshotEnv() {
  return Object.fromEntries(ENV_KEYS.map(key => [key, process.env[key]]));
}

function restoreEnv(snapshot) {
  for (const key of ENV_KEYS) {
    if (snapshot[key] === undefined) delete process.env[key];
    else process.env[key] = snapshot[key];
  }
}

function loadBridgeWithEnv(values = {}) {
  for (const key of ENV_KEYS) delete process.env[key];
  for (const [key, value] of Object.entries(values)) process.env[key] = value;
  jest.resetModules();
  return require('../services/internal-activitypub-bridge-api.service');
}

describe('internal ActivityPub bridge credential direction', () => {
  let originalEnv;

  beforeEach(() => {
    originalEnv = snapshotEnv();
  });

  afterEach(() => {
    restoreEnv(originalEnv);
    jest.resetModules();
  });

  test('fails closed when the sidecar-to-ActivityPods credential is absent', () => {
    const bridge = loadBridgeWithEnv();
    expect(bridge.settings.auth.bearerToken).toBe('');
  });

  test('does not accept SIDECAR_TOKEN as reverse-direction bridge authority', () => {
    const bridge = loadBridgeWithEnv({ SIDECAR_TOKEN: 'activitypods-to-sidecar-only' });
    expect(bridge.settings.auth.bearerToken).toBe('');
  });

  test('does not retain the legacy INTERNAL_API_TOKEN fallback', () => {
    const bridge = loadBridgeWithEnv({ INTERNAL_API_TOKEN: 'legacy-shared-token' });
    expect(bridge.settings.auth.bearerToken).toBe('');
  });

  test('uses ACTIVITYPODS_TOKEN for sidecar-to-ActivityPods bridge calls', () => {
    const bridge = loadBridgeWithEnv({
      ACTIVITYPODS_TOKEN: 'dedicated-sidecar-to-activitypods-token',
      SIDECAR_TOKEN: 'opposite-direction-token'
    });
    expect(bridge.settings.auth.bearerToken).toBe('dedicated-sidecar-to-activitypods-token');
  });
});
