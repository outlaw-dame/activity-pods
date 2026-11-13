'use strict';
const { mountedOidcCallback } = require('../config/oidc-mount-policy');

describe('mounted Solid-OIDC request routing', () => {
  test.each([
    ['/.oidc/auth/.well-known/openid-configuration','/.well-known/openid-configuration'],
    ['/.oidc/auth/token?code=x&state=123','/token?code=x&state=123'],
    ['/.oidc/auth','/'],
    ['/.oidc/auth/','/'],
    ['/.oidc/authorization?next=1','/.oidc/authorization?next=1'],
    ['/other/.oidc/auth/token','/other/.oidc/auth/token'],
    ['/.oidc/authentication/token','/.oidc/authentication/token']
  ])('routes %s as %s without broad rewriting', (input, expected) => {
    const handler = jest.fn((req) => req.url);
    const wrapped = mountedOidcCallback(handler, '/.oidc/auth');
    const req = { url: input };
    expect(wrapped(req, {}, () => undefined)).toBe(expected);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test.each(['', 'oidc/auth', '/', '/.oidc/auth/', '/..', '/oidc?x', '/oidc#h', '//oidc'])(
    'rejects unsafe or noncanonical prefix %s', prefix => {
      expect(() => mountedOidcCallback(() => {}, prefix)).toThrow(TypeError);
    }
  );

  test('forwards malformed requests to caller error handling without invoking auth', () => {
    const callback = jest.fn();
    const next = jest.fn();
    mountedOidcCallback(callback, '/.oidc/auth')({url: 12}, {}, next);
    expect(callback).not.toHaveBeenCalled();
    expect(next.mock.calls[0][0]).toBeInstanceOf(Error);
  });
});
