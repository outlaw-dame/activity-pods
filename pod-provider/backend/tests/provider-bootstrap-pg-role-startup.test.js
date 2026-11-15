'use strict';

const service = require('../services/provider-capabilities.service');

describe('provider bootstrap PostgreSQL least-privilege startup gate', () => {
  test('refuses service startup and closes the pool when the reader role is unsafe', async () => {
    const pool = { end: jest.fn(async () => undefined) };
    const reader = { assertReaderRole: jest.fn(async () => {
      throw new Error('postgresql://superuser:secret@private-db/real');
    }) };
    const runtime = {
      pgBootstrapReadiness: reader,
      pgBootstrapPool: pool,
      pgBootstrapAppClientId: 'https://app.example.org/app'
    };
    await expect(service.started.call(runtime)).rejects.toMatchObject({
      code: 503,
      type: 'BOOTSTRAP_PG_READER_NOT_AUTHORIZED',
      data: { retryable: false }
    });
    expect(reader.assertReaderRole).toHaveBeenCalledTimes(1);
    expect(pool.end).toHaveBeenCalledTimes(1);
    expect(runtime.pgBootstrapReadiness).toBeNull();
    expect(runtime.pgBootstrapPool).toBeNull();
    expect(runtime.pgBootstrapAppClientId).toBeNull();
  });

  test('accepts the specifically verified reader and leaves its pool owned by the service', async () => {
    const pool = { end: jest.fn() };
    const reader = { assertReaderRole: jest.fn(async () => true) };
    const runtime = {
      pgBootstrapReadiness: reader,
      pgBootstrapPool: pool,
      pgBootstrapAppClientId: 'https://app.example.org/app'
    };
    await expect(service.started.call(runtime)).resolves.toBeUndefined();
    expect(reader.assertReaderRole).toHaveBeenCalledTimes(1);
    expect(pool.end).not.toHaveBeenCalled();
    expect(runtime.pgBootstrapReadiness).toBe(reader);
  });

  test('provider with no configured PostgreSQL reader has no startup SQL or privilege bypass', async () => {
    await expect(service.started.call({
      pgBootstrapReadiness: null, pgBootstrapPool: null,
      pgBootstrapAppClientId: null
    })).resolves.toBeUndefined();
  });
});
