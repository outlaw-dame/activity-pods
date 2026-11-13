'use strict';

const { optimizeApiRouteOrder } = require('../utils/api-route-ordering');

const route = (name, catchAll = false) => ({ name, opts: { catchAll } });
const alias = (name, routeRef) => ({ name, route: routeRef });

describe('API gateway route precedence across distributed pod cells', () => {
  test('keeps catch-all routes last and preserves registration order within each class', () => {
    const gateway = {
      routes: [
        route('public-prefix'), route('catch-1', true), route('root-redirect'),
        route('catch-2', true), route('oidc'), route('api-public')
      ],
      aliases: []
    };

    optimizeApiRouteOrder(gateway);
    expect(gateway.routes.map(r => r.name)).toEqual([
      'public-prefix', 'root-redirect', 'oidc', 'api-public', 'catch-1', 'catch-2'
    ]);
    optimizeApiRouteOrder(gateway);
    expect(gateway.routes.map(r => r.name)).toEqual([
      'public-prefix', 'root-redirect', 'oidc', 'api-public', 'catch-1', 'catch-2'
    ]);
  });

  test('keeps root redirect and other concrete aliases ahead of catch-all aliases', () => {
    const root = route('root');
    const oidc = route('oidc');
    const wildcard1 = route('wildcard-1', true);
    const wildcard2 = route('wildcard-2', true);
    const gateway = {
      routes: [wildcard1, root, wildcard2, oidc],
      aliases: [
        alias('fallback-a', wildcard1), alias('GET /', root),
        alias('fallback-b', wildcard2), alias('GET /.well-known/openid-configuration', oidc)
      ]
    };

    optimizeApiRouteOrder(gateway);
    expect(gateway.routes.map(r => r.name)).toEqual([
      'root', 'oidc', 'wildcard-1', 'wildcard-2'
    ]);
    expect(gateway.aliases.map(a => a.name)).toEqual([
      'GET /', 'GET /.well-known/openid-configuration', 'fallback-a', 'fallback-b'
    ]);
  });
  test('root redirect never intercepts prefixed OIDC discovery or token routes', () => {
    const root = { ...route('root-redirect'), path: '/' };
    const discovery = { ...route('discovery'), path: '/.well-known/openid-configuration' };
    const oidc = { ...route('oidc-provider'), path: '/.oidc/auth' };
    const signup = { ...route('signup'), path: '/auth' };
    const fallback = { ...route('catchall', true), path: '/fallback' };
    const gateway = {
      routes: [root, discovery, oidc, fallback, signup],
      aliases: [
        alias('GET /', root),
        alias('GET /.well-known/openid-configuration', discovery),
        alias('GET /auth/signup', signup)
      ]
    };
    optimizeApiRouteOrder(gateway);
    expect(gateway.routes.map(x => x.name)).toEqual([
      'discovery', 'oidc-provider', 'signup', 'catchall', 'root-redirect'
    ]);
    const firstMatch = url => gateway.routes.find(x => url.startsWith(x.path));
    expect(firstMatch('/.oidc/auth/.well-known/openid-configuration')).toBe(oidc);
    expect(firstMatch('/.oidc/auth/token')).toBe(oidc);
    expect(firstMatch('/auth/signup')).toBe(signup);
    expect(firstMatch('/')).toBe(root);
    expect(gateway.aliases.map(a => a.name)).toEqual([
      'GET /', 'GET /.well-known/openid-configuration', 'GET /auth/signup'
    ]);
    optimizeApiRouteOrder(gateway);
    expect(gateway.routes[gateway.routes.length - 1]).toBe(root);
  });

});
