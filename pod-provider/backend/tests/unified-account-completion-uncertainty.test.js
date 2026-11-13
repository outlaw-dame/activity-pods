'use strict';
const { ServiceBroker } = require('moleculer');
const api = require('../services/unified-account-api.service');
const provider = require('../services/provider-capabilities.service');

describe('unified account completion is fail-closed after side effects', () => {
  it('never returns HTTP 201 or releases an idempotency reservation when completion storage fails', async () => {
    const failProvisioning = jest.fn(async () => ({ ok: true }));
    const begin = jest.fn(async () => ({ canonicalAccountId: 'https://pods.example/alice' }));
    const broker = new ServiceBroker({ logger: false });
    broker.createService({ name: 'api', actions: { addRoute: () => true } });
    broker.createService({
      name: 'provider-capabilities',
      actions: {
        reserveAccountProvisioning: () => ({
          capabilityId: 'provider.account.provisioning',
          idempotency: { key: 'opaque-key', state: 'reserved', replay: false }
        }),
        completeAccountProvisioning: () => { throw new Error('PostgreSQL connection lost'); },
        failAccountProvisioning: failProvisioning
      }
    });
    broker.createService({ name: 'unified-account', actions: { create: begin } });
    broker.createService(api);
    await broker.start();
    try {
      await expect(broker.call('unified-account-api.create', {
        appClientId: 'https://client.example',
        username: 'alice', password: 'very-long-password',
        profile: { displayName: 'Alice' }
      }, {
        meta: { $headers: { 'idempotency-key': 'opaque-key' } }
      })).rejects.toMatchObject({ code: 503, type: 'ACCOUNT_COMPLETION_UNCERTAIN' });
      expect(begin).toHaveBeenCalledTimes(1);
      expect(failProvisioning).not.toHaveBeenCalled();
    } finally {
      await broker.stop();
    }
  });

  it.each([
    {
      caseName: 'timed-out or rejected identity RPC',
      create: () => { throw new Error('Transport closed after PLC submission'); },
      complete: () => ({ ok: true, stored: true }),
      expectedType: 'ACCOUNT_PROVISIONING_UNCERTAIN'
    },
    {
      caseName: 'successfully returned account with a lost completion record',
      create: () => ({ canonicalAccountId: 'https://pods.example/alice' }),
      complete: () => ({ ok: true, stored: false }),
      expectedType: 'ACCOUNT_COMPLETION_UNCERTAIN'
    }
  ])('keeps reservation blocked for $caseName', async ({ create, complete, expectedType }) => {
    const failure = jest.fn();
    const commit = jest.fn(complete);
    const broker = new ServiceBroker({ logger: false });
    broker.createService({ name: 'api', actions: { addRoute: () => true } });
    broker.createService({
      name: 'provider-capabilities',
      actions: {
        reserveAccountProvisioning: () => ({
          allowed: true, capabilityId: 'provider.account.provisioning',
          idempotencyKey: 'durable-key',
          idempotency: { key: 'durable-key', state: 'reserved', replay: false }
        }),
        completeAccountProvisioning: commit,
        failAccountProvisioning: failure
      }
    });
    broker.createService({ name: 'unified-account', actions: { create } });
    broker.createService(api);
    await broker.start();
    try {
      await expect(broker.call('unified-account-api.create', {
        appClientId: 'https://client.example',
        username: 'alice', email: 'alice@example.test',
        password: 'example-password'
      }, { meta: { $headers: { 'idempotency-key': 'durable-key' } } }))
        .rejects.toMatchObject({
          code: 503, type: expectedType, data: { retryable: false }
        });
      expect(failure).not.toHaveBeenCalled();
      if (expectedType === 'ACCOUNT_PROVISIONING_UNCERTAIN') {
        expect(commit).not.toHaveBeenCalled();
      } else {
        expect(commit).toHaveBeenCalledTimes(1);
      }
    } finally {
      await broker.stop();
    }
  });

  it('rejects old WebID/DID import before reserving a capability or calling the signup RPC', async () => {
    const reserve = jest.fn();
    const create = jest.fn();
    const broker = new ServiceBroker({ logger: false });
    broker.createService({ name: 'api', actions: { addRoute: () => true } });
    broker.createService({
      name: 'provider-capabilities',
      actions: {
        reserveAccountProvisioning: reserve,
        failAccountProvisioning: jest.fn()
      }
    });
    broker.createService({ name: 'unified-account', actions: { create } });
    broker.createService(api);
    await broker.start();
    try {
      for (const injected of [
        { webId: 'https://existing.example/alice' },
        { atproto: { existingDid: 'did:plc:abcdefghijklmnopqrstuvwx' } },
        { protocols: { atproto: { force: true } } },
        { migration: true }
      ]) {
        await expect(broker.call('unified-account-api.create', {
          appClientId: 'https://client.example',
          username: 'new-account', password: 'example-password',
          ...injected
        })).rejects.toMatchObject({
          code: 400, type: 'UNIFIED_ACCOUNT_NEW_ONLY'
        });
      }
      expect(reserve).not.toHaveBeenCalled();
      expect(create).not.toHaveBeenCalled();
    } finally {
      await broker.stop();
    }
  });

  it('denies the process-local idempotency backend for production reservations', () => {
    const old = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      const result = provider.methods.reserveAccountProvisioning.call({
        deny: (reasonCode, message, retryable, statusCode) => ({
          reasonCode, message, retryable, statusCode
        })
      }, {});
      expect(result).toMatchObject({
        reasonCode: 'durable_account_provisioning_not_ready',
        statusCode: 503
      });
    } finally {
      if (old === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = old;
    }
  });
});
