'use strict';

/**
 * OIDC Client ID documents are untrusted URLs. Enforce network authority at
 * DNS/socket selection, not only before fetch: URL hostname validation alone
 * would permit DNS rebinding into internal provider, Redis or Fuseki services.
 *
 * This does not replace an egress firewall. Deployments should also prohibit
 * backend access to link-local/metadata and administrative networks.
 */
const dns = require('node:dns');
const net = require('node:net');
const https = require('node:https');

const blocked = new net.BlockList();
for (const [prefix, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
  ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4]
]) blocked.addSubnet(prefix, bits, 'ipv4');
for (const [prefix, bits] of [
  ['::', 128], ['::1', 128], ['::ffff:0:0', 96],
  ['fc00::', 7], ['fec0::', 10], ['fe80::', 10], ['ff00::', 8],
  ['64:ff9b::', 96], ['2001::', 32], ['2001:10::', 28],
  ['2001:db8::', 32], ['2002::', 16]
]) blocked.addSubnet(prefix, bits, 'ipv6');

function allowedTestHost(hostname) {
  return process.env.NODE_ENV === 'test' &&
    hostname === process.env.G1_E2E_ALLOW_PRIVATE_CLIENT_HOST &&
    hostname === 'app-e2e.test';
}
function isAllowedAddress(address, family, hostname) {
  if (allowedTestHost(hostname)) return true;
  return !blocked.check(address, family === 6 ? 'ipv6' : 'ipv4');
}
function safeUri(raw) {
  if (typeof raw !== 'string' || raw.length > 2048 || /[\u0000-\u0020\u007f\\]/u.test(raw)) {
    throw new Error('Invalid Solid-OIDC Client ID URL');
  }
  let url;
  try { url = new URL(raw); } catch { throw new Error('Invalid Solid-OIDC Client ID URL'); }
  const localDev = ['development', 'test'].includes(process.env.NODE_ENV) &&
    url.protocol === 'http:' && url.hostname === 'localhost';
  if ((!localDev && url.protocol !== 'https:') ||
      url.href !== raw || url.username || url.password ||
      !url.hostname || url.port === '0') {
    throw new Error('Invalid Solid-OIDC Client ID URL');
  }
  // WHATWG URL.hostname includes brackets for IPv6 literals on Node 22;
  // net.isIP('[::1]') returns 0. Reject bracketed literals explicitly so
  // they can never bypass the DNS/socket address validation path.
  if (url.hostname.startsWith('[')) {
    throw new Error('Solid-OIDC Client ID resolves to a prohibited network');
  }
  const literal = net.isIP(url.hostname);
  if (literal && !isAllowedAddress(url.hostname, literal, url.hostname) && !localDev) {
    throw new Error('Solid-OIDC Client ID resolves to a prohibited network');
  }
  return { url, localDev };
}

function protectedLookup(hostname, options, callback) {
  dns.lookup(hostname, { all: true, verbatim: true }, (err, rows) => {
    if (err) return callback(err);
    const accepted = (rows || []).filter(row =>
      isAllowedAddress(row.address, row.family, hostname) &&
      (!options.family || options.family === row.family));
    if (!accepted.length) return callback(
      new Error('Solid-OIDC Client ID resolves to a prohibited network')
    );
    callback(null, accepted[0].address, accepted[0].family);
  });
}
const guardedAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 16,
  maxTotalSockets: 64,
  lookup: protectedLookup
});

function clientFetchOptions(raw) {
  const { localDev } = safeUri(raw);
  return {
    timeout: 6000,
    size: 65536,
    redirect: 'error',
    ...(localDev ? {} : { agent: guardedAgent })
  };
}
module.exports = {
  clientFetchOptions,
  safeUri,
  isAllowedAddress,
  protectedLookup
};
