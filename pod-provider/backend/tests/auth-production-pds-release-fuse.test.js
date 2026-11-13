'use strict';

// Test the actual signup action, not merely a regex over its source.
// Keep external SemApps objects isolated: the release refusal must happen
// before any trusted service RPC or irreversible identity side effect.
jest.mock('@semapps/auth', () => ({ AuthLocalService: {} }));
jest.mock('../config/config', () => ({
  BASE_URL: 'https://pods.example/',
  FRONTEND_URL: 'https://app.example/',
  AUTH_ACCOUNTS_DATASET: 'settings',
  AUTH_RESERVED_USER_NAMES: [],
  FROM_NAME: 'Test Provider',
  FROM_EMAIL: 'no-reply@example.invalid'
}));
jest.mock('../config/transport', () => ({}));

const schema = require('../services/core/auth');

describe('production new-account signed-PDS release fuse', () => {
  const saved = {
    nodeEnv: process.env.NODE_ENV,
    atprotoOptOut: process.env.APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP
  };
  afterAll(() => {
    if (saved.nodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = saved.nodeEnv;
    if (saved.atprotoOptOut === undefined) delete process.env.APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP;
    else process.env.APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP = saved.atprotoOptOut;
  });

  const params = {
    username: 'new-account',
    email: 'new-account@example.invalid',
    password: 'DisposableOnlyPassword123'
  };

  test.each(['true', 'false', undefined])(
    'refuses production signup before all account/PLC side effects with ATProto opt-out=%p',
    async flag => {
      process.env.NODE_ENV = 'production';
      if (flag === undefined) delete process.env.APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP;
      else process.env.APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP = flag;
      const call = jest.fn();
      const emit = jest.fn();
      const logger = { info: jest.fn(), error: jest.fn() };
      await expect(schema.actions.signup.call({ logger }, {
        params, meta: {}, call, emit
      })).rejects.toMatchObject({
        code: 503,
        type: 'ATPROTO_PDS_REPOSITORY_NOT_READY',
        data: { retryable: false }
      });
      expect(call).not.toHaveBeenCalled();
      expect(emit).not.toHaveBeenCalled();
    }
  );

  test('isolated test fixture still reaches username moderation', async () => {
    process.env.NODE_ENV = 'test';
    process.env.APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP = 'false';
    const call = jest.fn(async () => {
      throw new Error('TEST_REACHED_MODERATION_BOUNDARY');
    });
    const logger = { info: jest.fn(), error: jest.fn() };
    await expect(schema.actions.signup.call({ logger }, {
      params, meta: {}, call, emit: jest.fn()
    })).rejects.toThrow('TEST_REACHED_MODERATION_BOUNDARY');
    expect(call.mock.calls[0][0]).toBe('username-moderation.assertSafe');
  });
});
