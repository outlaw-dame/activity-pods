'use strict';
const auth = require('../services/core/auth');

describe('irreversible PLC signup rollback safety', () => {
  const originalEnv = { node: process.env.NODE_ENV, plc: process.env.APODS_ATPROTO_ENABLE_PLC_SUBMISSION };
  afterEach(() => {
    if (originalEnv.node === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalEnv.node;
    if (originalEnv.plc === undefined) delete process.env.APODS_ATPROTO_ENABLE_PLC_SUBMISSION;
    else process.env.APODS_ATPROTO_ENABLE_PLC_SUBMISSION = originalEnv.plc;
  });
  const context = async () => {
    const ctx = { call: jest.fn() };
    const service = {
      _mustPreserveFailedSignup: auth.methods._mustPreserveFailedSignup,
      logger: { warn: jest.fn() }
    };
    await expect(auth.methods._cleanupPartialAtprotoArtifacts.call(service, ctx,
      'https://pods.example/alice')).rejects.toMatchObject({
      type: 'ACCOUNT_IDENTITY_RECONCILIATION_REQUIRED'
    });
    expect(ctx.call).not.toHaveBeenCalled();
  };
  test('production does not delete identity binding or signing keys after failed signup', async () => {
    process.env.NODE_ENV = 'production';
    delete process.env.APODS_ATPROTO_ENABLE_PLC_SUBMISSION;
    await context();
  });
  test('staging with real PLC submissions also preserves recovery materials', async () => {
    process.env.NODE_ENV = 'test';
    process.env.APODS_ATPROTO_ENABLE_PLC_SUBMISSION = 'true';
    await context();
  });
  test('isolated mock fixture cleanup retains its original behavior', async () => {
    process.env.NODE_ENV = 'test';
    process.env.APODS_ATPROTO_ENABLE_PLC_SUBMISSION = 'false';
    const ctx = { call: jest.fn(async () => true) };
    const service = {
      _mustPreserveFailedSignup: auth.methods._mustPreserveFailedSignup,
      logger: { warn: jest.fn() }
    };
    await auth.methods._cleanupPartialAtprotoArtifacts.call(service, ctx,
      'http://localhost:3000/test-user');
    expect(ctx.call).toHaveBeenCalledTimes(2);
    expect(ctx.call.mock.calls.map(x => x[0])).toEqual([
      'identitybindings.remove', 'keys.deleteAllKeysForWebId'
    ]);
  });
});
