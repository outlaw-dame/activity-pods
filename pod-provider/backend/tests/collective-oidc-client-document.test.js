'use strict';

jest.mock('node-fetch', () => jest.fn());
const fetch = require('node-fetch');
const RedisAdapter = require('../config/oidc-adapter');
const { safeUri, isAllowedAddress, clientFetchOptions } =
  require('../config/oidc-client-network-policy');

const URI = 'https://paper.example/app';
const CONTEXT = 'https://www.w3.org/ns/solid/oidc-context.jsonld';

function adapter() {
  return new RedisAdapter('Client', {
    get: jest.fn(async () => null)
  });
}
function makeResponse(value, contentType = 'application/ld+json') {
  return {
    status: 200,
    headers: { get: () => contentType },
    text: jest.fn(async () => JSON.stringify(value))
  };
}
function document(uri = URI) {
  return {
    '@context': [CONTEXT],
    client_id: uri,
    redirect_uris: ['https://paper.example/callback']
  };
}

describe('remote HTTPS Solid-OIDC Client ID document hardening', () => {
  beforeEach(() => jest.clearAllMocks());

  test('exact URI metadata can be resolved, but fetch cost and redirect behavior are bounded', async () => {
    fetch.mockResolvedValue(makeResponse(document()));
    const client = await adapter().find(URI);
    expect(client).toMatchObject({
      client_id: URI,
      redirect_uris: ['https://paper.example/callback'],
      token_endpoint_auth_method: 'none'
    });
    expect(fetch).toHaveBeenCalledWith(URI, expect.objectContaining({
      timeout: 6000, size: 65536, redirect: 'error'
    }));
    expect(fetch.mock.calls[0][1].headers.Accept).toBe('application/ld+json');
  });

  test('does not accept metadata from a different application identity', async () => {
    fetch.mockResolvedValue(makeResponse(document('https://attacker.example/app')));
    await expect(adapter().find(URI)).rejects.toThrow('must match the client ID');
  });

  test('rejects invalid MIME and malformed redirect metadata', async () => {
    fetch.mockResolvedValueOnce(makeResponse(document(), 'text/html'));
    await expect(adapter().find(URI)).rejects.toThrow('JSON-LD/JSON content type');
    fetch.mockResolvedValueOnce(makeResponse({ ...document(), redirect_uris: undefined }));
    await expect(adapter().find(URI)).rejects.toThrow('bounded nonempty list');
    fetch.mockResolvedValueOnce(makeResponse({
      ...document(), redirect_uris: new Array(33).fill('https://paper.example/callback')
    }));
    await expect(adapter().find(URI)).rejects.toThrow('bounded nonempty list');
  });

  test('non-200 errors never log untrusted response bodies', async () => {
    const text = jest.fn(async () => 'secret-controlled-response');
    fetch.mockResolvedValue({ status: 502, text });
    await expect(adapter().find(URI)).rejects.toThrow('HTTP 502');
    expect(text).not.toHaveBeenCalled();
  });

  test('public DNS addresses are permitted and private/metadata networks denied', () => {
    for (const address of ['127.0.0.1', '10.1.2.3', '169.254.169.254',
      '172.18.0.1', '192.168.1.1', '100.64.0.1', '198.51.100.8']) {
      expect(isAllowedAddress(address, 4, 'example.net')).toBe(false);
    }
    for (const address of ['::1', 'fe80::1', 'fc00::1', '2001:db8::1']) {
      expect(isAllowedAddress(address, 6, 'example.net')).toBe(false);
    }
    expect(isAllowedAddress('8.8.8.8', 4, 'example.net')).toBe(true);
    expect(isAllowedAddress('2606:4700:4700::1111', 6, 'example.net')).toBe(true);
  });

  test('rejects malformed and direct private URLs before any HTTP request', () => {
    for (const uri of [
      'http://127.0.0.1/admin', 'https://127.0.0.1/admin',
      'https://10.0.0.2/', 'https://169.254.169.254/latest/meta-data',
      'https://user:secret@example.net/app', 'https://example.net/app query'
    ]) {
      expect(() => safeUri(uri)).toThrow();
    }
    expect(clientFetchOptions(URI).agent).toBeDefined();
    expect(clientFetchOptions(URI).agent.maxTotalSockets).toBe(64);
  });

  test('oversized, slow or redirected fetch errors propagate fail closed', async () => {
    for (const reason of ['max-size', 'timeout', 'redirect']) {
      fetch.mockRejectedValueOnce(new Error(reason));
      await expect(adapter().find(URI)).rejects.toThrow(reason);
    }
  });
});
