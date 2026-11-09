'use strict';

const gate = require('../services/utils/collective-release-gate');
const reservations = require('../services/collective-reservations.service');
const api = require('../services/collective-reservations-api.service');
const leases = require('../services/collective-provisioning-leases.service');

describe('incomplete SAI bridge cannot be enabled with environment variables', () => {
  test('a code-reviewed release fuse stays closed', () => {
    expect(gate).toEqual({ CONSENT_BRIDGE_RELEASED: false });
    expect(Object.isFrozen(gate)).toBe(true);
    expect(reservations.settings.enabled).toBe(false);
    expect(api.settings.enabled).toBe(false);
    expect(leases.settings.enabled).toBe(false);
  });

  test('provider startup never registers an unauthorized Group route', async () => {
    const calls = [];
    await api.started.call({
      settings: api.settings,
      broker: { call: async (...args) => calls.push(args) }
    });
    expect(calls).toEqual([]);
  });
});
