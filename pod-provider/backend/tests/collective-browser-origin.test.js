'use strict';

const { approvedBrowserOrigins, canonicalOrigin } = require(
  '../services/utils/collective-endpoint-policy'
);

describe('Group-only browser CORS policy', () => {
  test('same-origin default without wildcard or general cross-origin access', () => {
    expect(approvedBrowserOrigins('https://provider.example')).toEqual([
      'https://provider.example'
    ]);
    expect(approvedBrowserOrigins('https://provider.example/')).toEqual([
      'https://provider.example'
    ]);
  });

  test('only explicitly approved canonical origins may be added', () => {
    expect(approvedBrowserOrigins('https://provider.example',
      'https://paper.example,https://client.example,https://paper.example'
    )).toEqual([
      'https://provider.example', 'https://paper.example', 'https://client.example'
    ]);
  });

  test.each([
    'http://not-secure.example',
    'https://client.example/login',
    'https://user:password@client.example',
    'https://client.example?state=evil',
    'https://client.example#fragment',
    'https://client.example spaces',
    '*',
    'null'
  ])('denies invalid CORS origin %s', origin => {
    expect(canonicalOrigin(origin)).toBeNull();
    expect(() => approvedBrowserOrigins('https://provider.example', origin)).toThrow();
  });
  test('disallows invalid provider origins and unbounded origin allowlists', () => {
    expect(() => approvedBrowserOrigins('http://provider.example')).toThrow();
    expect(() => approvedBrowserOrigins('https://provider.example',
      Array.from({ length: 33 }, (_, i) => 'https://app' + i + '.example').join(',')
    )).toThrow('Too many');
  });
});
