'use strict';

jest.mock('node-fetch', () => jest.fn());
const fetch = require('node-fetch');
const RedisAdapter = require('../config/oidc-adapter');

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

  test('oversized, slow or redirected fetch errors propagate fail closed', async () => {
    for (const reason of ['max-size', 'timeout', 'redirect']) {
      fetch.mockRejectedValueOnce(new Error(reason));
      await expect(adapter().find(URI)).rejects.toThrow(reason);
    }
  });
});
