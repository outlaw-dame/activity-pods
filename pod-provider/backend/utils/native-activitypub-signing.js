'use strict';

const crypto = require('crypto');
const { MoleculerError } = require('moleculer').Errors;
const { configuredSigningToken } = require('./signing-security');

function signingRequestFromSemApps(params) {
  const method = String(params?.method || '').toUpperCase();
  if (method !== 'GET' && method !== 'POST') {
    throw new MoleculerError('Native ActivityPub signing only supports GET and POST', 400, 'INVALID_INPUT');
  }

  let target;
  try {
    target = new URL(params.url);
  } catch {
    throw new MoleculerError('Native ActivityPub signing target must be a valid URL', 400, 'INVALID_INPUT');
  }
  if (
    (target.protocol !== 'http:' && target.protocol !== 'https:') ||
    target.username ||
    target.password ||
    target.hash
  ) {
    throw new MoleculerError(
      'Native ActivityPub signing target must be a credential-free HTTP(S) URL without a fragment',
      400,
      'INVALID_INPUT'
    );
  }
  if (typeof params.actorUri !== 'string' || params.actorUri.length === 0) {
    throw new MoleculerError('Native ActivityPub signing requires an actor URI', 400, 'INVALID_INPUT');
  }
  if (method === 'POST' && typeof params.body !== 'string') {
    throw new MoleculerError('Native ActivityPub POST signing requires a string body', 400, 'INVALID_INPUT');
  }

  return {
    requestId: `native-ap-${crypto.randomUUID()}`,
    actorUri: params.actorUri,
    method,
    profile: method === 'POST' ? 'ap_post_v1' : 'ap_get_v1',
    target: {
      host: target.host,
      path: target.pathname || '/',
      query: target.search
    },
    ...(method === 'POST'
      ? {
          body: { bytes: params.body, encoding: 'utf8' },
          digest: { mode: 'server_compute' }
        }
      : {})
  };
}

async function generateAuthorityBoundSignatureHeaders(ctx) {
  const token = configuredSigningToken();
  if (!token) {
    throw new MoleculerError(
      'Native ActivityPub signing authentication is not configured',
      503,
      'SIGNING_AUTH_NOT_CONFIGURED'
    );
  }

  const request = signingRequestFromSemApps(ctx.params);
  const response = await ctx.call(
    'signing.signHttpRequestsBatch',
    { requests: [request] },
    {
      meta: {
        ...ctx.meta,
        $headers: {
          ...(ctx.meta?.$headers || {}),
          authorization: `Bearer ${token}`
        }
      }
    }
  );
  const result = response?.results?.[0];
  if (
    response?.results?.length !== 1 ||
    !result ||
    result.requestId !== request.requestId ||
    result.ok !== true ||
    typeof result.outHeaders?.Date !== 'string' ||
    typeof result.outHeaders?.Signature !== 'string'
  ) {
    throw new MoleculerError(
      'Native ActivityPub signing failed closed',
      result?.error?.retryable === true ? 503 : 500,
      result?.error?.code || 'NATIVE_SIGNING_FAILED'
    );
  }
  if (request.method === 'POST' && typeof result.outHeaders.Digest !== 'string') {
    throw new MoleculerError('Native ActivityPub signer omitted the required digest', 500, 'NATIVE_SIGNING_FAILED');
  }

  return result.outHeaders;
}

module.exports = { generateAuthorityBoundSignatureHeaders, signingRequestFromSemApps };
