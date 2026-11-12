const fetch = require('node-fetch');
const isEmpty = require('lodash/isEmpty.js');
const { clientFetchOptions } = require('./oidc-client-network-policy');
const {
  ATOMIC_GRANT_UPSERT, MAX_GRANT_TOKENS, MAX_GRANT_TTL_SECONDS,
  REVOKE_BATCH, MAX_REVOKE_BATCHES, revokeMarker, validTtl, cappedError
} = require('./oidc-grant-index-policy');

const grantable = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest'
]);

const consumable = new Set(['AuthorizationCode', 'RefreshToken', 'DeviceCode', 'BackchannelAuthenticationRequest']);

function grantKeyFor(id) {
  return `grant:${id}`;
}

function userCodeKeyFor(userCode) {
  return `userCode:${userCode}`;
}

function uidKeyFor(uid) {
  return `uid:${uid}`;
}

class RedisAdapter {
  constructor(name, client) {
    this.name = name;
    this.client = client;
  }

  async upsert(id, payload, expiresIn) {
    const key = this.key(id);
    const tracking = grantable.has(this.name) && Boolean(payload.grantId);
    const isHash = consumable.has(this.name);
    const serialized = JSON.stringify(payload);

    if (tracking) {
      if (!validTtl(expiresIn)) {
        throw cappedError('OIDC_GRANT_TTL_INVALID');
      }
      // Persist the token, its revocation pointer and its TTL in one
      // server-side transaction. Reject before writing if the grant was
      // revoked or its bounded index is full.
      const result = await this.client.eval(
        ATOMIC_GRANT_UPSERT, 5,
        key, grantKeyFor(payload.grantId), revokeMarker(payload.grantId),
        payload.userCode ? userCodeKeyFor(payload.userCode) : 'unused:code',
        payload.uid ? uidKeyFor(payload.uid) : 'unused:uid',
        isHash ? 'hash' : 'string', serialized, String(expiresIn),
        String(MAX_GRANT_TOKENS), key,
        payload.userCode ? 'yes' : '', id,
        payload.uid ? 'yes' : '', payload.grantId
      );
      if (result === -1) throw cappedError('OIDC_GRANT_TOKEN_LIMIT');
      if (result === -2) throw cappedError('OIDC_GRANT_ALREADY_REVOKED');
      if (result === -3) throw cappedError('OIDC_GRANT_TOKEN_ID_CONFLICT');
      if (result !== 1) throw cappedError('OIDC_GRANT_WRITE_UNKNOWN');
      return;
    }

    const store = isHash ? { payload: serialized } : serialized;
    const multi = this.client.multi();
    multi[isHash ? 'hmset' : 'set'](key, store);
    if (expiresIn) multi.expire(key, expiresIn);
    if (payload.userCode) {
      multi.set(userCodeKeyFor(payload.userCode), id);
      multi.expire(userCodeKeyFor(payload.userCode), expiresIn);
    }
    if (payload.uid) {
      multi.set(uidKeyFor(payload.uid), id);
      multi.expire(uidKeyFor(payload.uid), expiresIn);
    }
    const executed = await multi.exec();
    if (!executed || executed.some(([error]) => error)) {
      throw cappedError('OIDC_GRANT_WRITE_FAILED');
    }
  }

  async find(id) {
    const data = consumable.has(this.name)
      ? await this.client.hgetall(this.key(id))
      : await this.client.get(this.key(id));

    if (isEmpty(data)) {
      if (this.name === 'Client' && id.startsWith('http')) {
        if (!/^https:|^http:\/\/localhost(?::\d+)?(?:\/|$)/u.test(id)) {
          throw new Error(`SSL is required for client_id authentication unless working locally.`);
        }
        // Remote Client ID Documents are untrusted network input on the
        // authentication path. Bound their latency, response size and redirect
        // behavior so an external app cannot monopolize a Pod cell or redirect
        // the provider's request toward private services.
        const response = await fetch(id, {
          headers: {
            Accept: 'application/ld+json',
            JsonLdContext: 'https://www.w3.org/ns/solid/oidc-context.jsonld'
          },
          ...clientFetchOptions(id)
        });
        if (response.status !== 200) {
          throw new Error(`Unable to access Client ID Document at ${id}. HTTP ${response.status}`);
        }
        const contentType = response.headers.get('content-type') || '';
        if (!/^application\/(?:ld\+json|json)(?:\s*;|\s*$)/iu.test(contentType)) {
          throw new Error('Client ID Document must have a JSON-LD/JSON content type');
        }
        const data = await response.text();
        let json;
        try {
          json = JSON.parse(data);
          const contexts = Array.isArray(json['@context']) ? json['@context'] : [json['@context']];
          // We can only parse as simple JSON if the @context is correct
          if (!contexts.includes('https://www.w3.org/ns/solid/oidc-context.jsonld')) {
            throw new Error('Missing context https://www.w3.org/ns/solid/oidc-context.jsonld');
          }
        } catch (error) {
          // A malformed or unexpectedly contextualized document must never
          // fall through as a client with an implicit public auth method.
          // No RDF fallback parser is implemented on this adapter.
          throw new Error('Invalid Solid-OIDC Client ID Document JSON-LD');
        }

        if (json) {
          // Need to make sure the document is about the id
          if (json.client_id !== id) {
            throw new Error('The client registration `client_id` field must match the client ID');
          }
          // Reformat if necessary as the @container directive doesn't work
          if (json.redirect_uris && !Array.isArray(json.redirect_uris) &&
              json.redirect_uris['@none']) json.redirect_uris = json.redirect_uris['@none'];
          if (!Array.isArray(json.redirect_uris) || json.redirect_uris.length === 0 ||
              json.redirect_uris.length > 32 ||
              json.redirect_uris.some(uri => typeof uri !== 'string' || uri.length > 2048)) {
            throw new Error('Client ID Document redirect_uris must be a bounded nonempty list');
          }
          json = {
            client_id: json.client_id,
            redirect_uris: json.redirect_uris
          };
        }

        // `token_endpoint_auth_method: 'none'` prevents oidc-provider from requiring a client_secret
        // eslint-disable-next-line ts/naming-convention
        return { ...json, token_endpoint_auth_method: 'none' };
      } else {
        return undefined;
      }
    }

    const value = typeof data === 'string'
      ? JSON.parse(data)
      : { ...data, ...JSON.parse(data.payload) };
    // A cancelled revocation can leave an old key in Redis until the
    // next recovery attempt. The marker still denies that token.
    if (grantable.has(this.name) && value.grantId &&
        await this.client.exists(revokeMarker(value.grantId))) {
      return undefined;
    }
    return value;
  }

  async findByUid(uid) {
    const id = await this.client.get(uidKeyFor(uid));
    return this.find(id);
  }

  async findByUserCode(userCode) {
    const id = await this.client.get(userCodeKeyFor(userCode));
    return this.find(id);
  }

  async destroy(id) {
    const key = this.key(id);
    await this.client.del(key);
  }

  async revokeByGrantId(grantId) {
    const key = grantKeyFor(grantId);
    // Mark as revoked before deleting any token: concurrent upserts must
    // observe the marker and fail closed. Retain it for the maximum allowed
    // tracked-token lifetime so interrupted revocation is still denied.
    await this.client.set(
      revokeMarker(grantId), '1', 'EX', MAX_GRANT_TTL_SECONDS
    );
    for (let batch = 0; batch < MAX_REVOKE_BATCHES; batch++) {
      const tokens = await this.client.lrange(key, 0, REVOKE_BATCH - 1);
      if (!tokens.length) {
        await this.client.del(key);
        return;
      }
      // Delete this batch's token keys and remove their pointers in one
      // Redis transaction. A crash cannot discard a pointer before its token.
      const multi = this.client.multi();
      for (const token of tokens) multi.del(token);
      multi.ltrim(key, tokens.length, -1);
      const executed = await multi.exec();
      if (!executed || executed.some(([error]) => error)) {
        throw cappedError('OIDC_GRANT_REVOKE_FAILED');
      }
    }
    throw cappedError('OIDC_GRANT_LEGACY_INDEX_TOO_LARGE');
  }

  async consume(id) {
    await this.client.hset(this.key(id), 'consumed', Math.floor(Date.now() / 1000));
  }

  key(id) {
    return `${this.name}:${id}`;
  }
}

module.exports = RedisAdapter;
