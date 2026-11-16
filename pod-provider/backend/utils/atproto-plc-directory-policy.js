'use strict';

const DEFAULT_DIRECTORY = 'https://plc.directory';

function normalizeDirectory(value, env) {
  try {
    if (typeof value !== 'string' || value.trim() !== value || value.length > 2048) throw new Error();
    const url = new URL(value);
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
        (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback && env.NODE_ENV !== 'production'))) {
      throw new Error();
    }
    return url.origin;
  } catch {
    // Configuration errors must not disclose credentials from an invalid URL.
    throw new Error('Invalid PLC directory origin');
  }
}

function resolvePlcDirectory(env = process.env) {
  const values = [env.APODS_ATPROTO_PLC_DIRECTORY_URL, env.ATPROTO_PLC_DIRECTORY_URL]
    .filter(value => value !== undefined)
    .map(value => normalizeDirectory(value, env));
  if (values.length === 2 && values[0] !== values[1]) {
    throw new Error('PLC submission and verification directory origins disagree');
  }
  return values[0] || DEFAULT_DIRECTORY;
}

function allowMockAtprotoIdentity(env = process.env) {
  if (env.NODE_ENV === 'production' || env.APODS_ATPROTO_ENABLE_PLC_SUBMISSION === 'true') return false;
  const value = env.APODS_ATPROTO_ALLOW_MOCK_IDENTITY;
  if (value !== undefined && value !== 'true' && value !== 'false') {
    throw new Error('Invalid ATProto mock identity configuration');
  }
  return value === undefined || value === 'true';
}

module.exports = { resolvePlcDirectory, allowMockAtprotoIdentity };
