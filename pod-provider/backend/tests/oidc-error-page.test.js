'use strict';

const makeConfig = require('../config/oidc');

test('native OIDC error page escapes client-supplied markup and limits output', async () => {
  const config = makeConfig({
    frontendUrl: 'https://app.example.test/',
    cookieSecret: 'test-only-cookie-secret'
  }, { alg: 'ES256' });
  const ctx = {};
  const log = jest.spyOn(console, 'error').mockImplementation(() => {});
  try {
    await config.renderError(ctx, {
      '<img src=x onerror=alert(1)>': '<script>alert(1)</script>',
      message: 'bad&"quoted" and \'single\'',
      large: 'A'.repeat(5000)
    }, { error: 'invalid_request', statusCode: 400,
      // An authorization header must never be emitted into logs.
      authorization: 'private-test-secret' });
    expect(ctx.type).toBe('html');
    expect(ctx.body).not.toContain('<img');
    expect(ctx.body).not.toContain('<script>');
    expect(ctx.body).toContain('&lt;img');
    expect(ctx.body).toContain('&lt;script&gt;');
    expect(ctx.body).toContain('&amp;');
    expect(ctx.body).toContain('&quot;');
    expect(ctx.body).toContain('&#39;');
    expect(ctx.body).not.toContain('A'.repeat(2049));
    expect(log).toHaveBeenCalledWith('OIDC error response', {
      errorCode: 'invalid_request', statusCode: 400
    });
    expect(JSON.stringify(log.mock.calls)).not.toContain('private-test-secret');
  } finally {
    log.mockRestore();
  }
});

test('unexpected OIDC error metadata fails to a non-sensitive log code', async () => {
  const config = makeConfig({ frontendUrl: 'https://app.example.test/',
    cookieSecret: 'test-only-secret' }, { alg: 'ES256' });
  const ctx = {};
  const log = jest.spyOn(console, 'error').mockImplementation(() => {});
  try {
    await config.renderError(ctx, { message: '<b>unsafe</b>' },
      { error: 'bad\nforged_header', statusCode: '400' });
    expect(ctx.body).toContain('&lt;b&gt;unsafe&lt;/b&gt;');
    expect(log).toHaveBeenCalledWith('OIDC error response', {
      errorCode: 'unspecified', statusCode: null
    });
  } finally {
    log.mockRestore();
  }
});
