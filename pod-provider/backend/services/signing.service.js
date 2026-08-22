// ActivityPods internal signing service.
'use strict';

require('dotenv-flow').config();

const crypto = require('crypto');
const { URL } = require('url');
const { MoleculerError } = require('moleculer').Errors;
const { MIME_TYPES } = require('@semapps/mime-types');
const {
  configuredSigningToken,
  isDateWithinSkew,
  parseBearerToken,
  timingSafeSecretEqual
} = require('../utils/signing-security');
const {
  assertAuthorizedMockRepoCommit,
  assertAuthorizedPlcGenesis,
  decodeCanonicalBase64
} = require('../utils/atproto-signing-policy');

const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const SECP256K1_MULTICODEC = Buffer.from([0xe7, 0x01]);
const BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const SAFE_HEADER_VALUE_RE = /^[\x20-\x7e]+$/;

function toHttpDate(d = new Date()) {
  return d.toUTCString();
}

function normalizeMethod(value) {
  return String(value || '').toUpperCase();
}

function assertHost(host) {
  if (!host || typeof host !== 'string') return false;
  if (!SAFE_HEADER_VALUE_RE.test(host)) return false;
  if (host.includes('://') || host.includes('/') || /\s/.test(host)) return false;
  return true;
}

function assertPath(path) {
  return typeof path === 'string' && path.startsWith('/') && !/[\r\n]/.test(path);
}

function assertQuery(query) {
  return typeof query === 'string' && !/[\r\n]/.test(query);
}

function assertContentType(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && SAFE_HEADER_VALUE_RE.test(value);
}

function assertKeyId(value) {
  if (!isSafeHttpUrl(value)) return false;
  return !/["\\\r\n]/.test(value);
}

function buildRequestTarget(method, path, query) {
  const q = query ? String(query) : '';
  const qp = q ? (q.startsWith('?') ? q : `?${q}`) : '';
  return `${method.toLowerCase()} ${path}${qp}`;
}

function sha256Base64(buf) {
  return crypto.createHash('sha256').update(buf).digest('base64');
}

function asArray(value) {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

function getResourceId(resource) {
  if (!resource || typeof resource !== 'object') return null;
  return resource.id || resource['@id'] || null;
}

function isSafeHttpUrl(value) {
  if (!value || typeof value !== 'string') return false;
  try {
    const parsed = new URL(value);
    return (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      !parsed.username &&
      !parsed.password &&
      !/[\r\n]/.test(value)
    );
  } catch {
    return false;
  }
}

function buildSigningString({ requestTarget, host, date, digest, contentType }, signedHeaders) {
  const lines = [];
  for (const h of signedHeaders) {
    const header = h.toLowerCase();
    if (header === '(request-target)') lines.push(`(request-target): ${requestTarget}`);
    else if (header === 'host') lines.push(`host: ${host}`);
    else if (header === 'date') lines.push(`date: ${date}`);
    else if (header === 'digest') lines.push(`digest: ${digest}`);
    else if (header === 'content-type') lines.push(`content-type: ${contentType}`);
    else throw new Error(`PROFILE_INVALID: unsupported signed header: ${h}`);
  }
  return lines.join('\n');
}

function signRsaSha256(privateKeyPem, signingString) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingString);
  signer.end();
  return signer.sign(privateKeyPem, 'base64');
}

function derToCompact(derBuf) {
  let offset = 2;
  if (derBuf[offset++] !== 0x02) throw new Error('DER: expected 0x02 for r');
  const rLen = derBuf[offset++];
  const rBytes = derBuf.slice(offset, offset + rLen);
  offset += rLen;
  if (derBuf[offset++] !== 0x02) throw new Error('DER: expected 0x02 for s');
  const sLen = derBuf[offset++];
  const sBytes = derBuf.slice(offset, offset + sLen);

  const to32 = bytes => {
    if (bytes.length === 32) return Buffer.from(bytes);
    if (bytes.length > 32) return bytes.slice(bytes.length - 32);
    const out = Buffer.alloc(32);
    bytes.copy(out, 32 - bytes.length);
    return out;
  };

  const r = to32(rBytes);
  const s = to32(sBytes);
  const sInt = BigInt(`0x${s.toString('hex')}`);
  let finalS = s;
  if (sInt > SECP256K1_N >> 1n) {
    finalS = Buffer.from((SECP256K1_N - sInt).toString(16).padStart(64, '0'), 'hex');
  }
  return Buffer.concat([r, finalS]);
}

function toBase58(buf) {
  if (buf.length === 0) return '';
  let num = BigInt(`0x${buf.toString('hex')}`);
  let result = '';
  while (num > 0n) {
    result = BASE58_CHARS[Number(num % 58n)] + result;
    num /= 58n;
  }
  for (let i = 0; i < buf.length && buf[i] === 0; i += 1) result = `1${result}`;
  return result;
}

function secp256k1PubkeyToMultibase(compressedKeyBytes) {
  return `z${toBase58(Buffer.concat([SECP256K1_MULTICODEC, compressedKeyBytes]))}`;
}

function getCompressedPublicKey(publicKeyPem) {
  const pubKey = crypto.createPublicKey(publicKeyPem);
  const der = pubKey.export({ type: 'spki', format: 'der' });
  const raw = der.slice(-65);
  if (raw.length !== 65 || raw[0] !== 0x04) throw new Error('Expected uncompressed EC point');
  const x = raw.slice(1, 33);
  const y = raw.slice(33, 65);
  return Buffer.concat([Buffer.from([(y[31] & 1) === 0 ? 0x02 : 0x03]), x]);
}

function keyPairToMultibase(keyPair) {
  if (typeof keyPair?.publicKeyMultibase === 'string' && keyPair.publicKeyMultibase.length > 0) {
    return keyPair.publicKeyMultibase;
  }
  const publicKeyPem = keyPair?.publicKeyPem || keyPair?.publicKey;
  if (!publicKeyPem) throw new Error('AT public key unavailable');
  return secp256k1PubkeyToMultibase(getCompressedPublicKey(publicKeyPem));
}

function signSecp256k1(privateKeyPem, dataBytes) {
  const signer = crypto.createSign('SHA256');
  signer.update(dataBytes);
  signer.end();
  return derToCompact(signer.sign(privateKeyPem)).toString('base64url');
}

module.exports = {
  name: 'signing',

  dependencies: ['api', 'keys', 'activitypub.actor', 'identitybindings', 'auth.account'],

  settings: {
    auth: {
      bearerToken: configuredSigningToken()
    },
    limits: {
      maxBatch: Number(process.env.SIGNING_MAX_BATCH || 500),
      maxBodyBytes: Number(process.env.SIGNING_MAX_BODY_BYTES || 512 * 1024),
      maxClockSkewSeconds: Number(process.env.SIGNING_MAX_SKEW_SECONDS || 300)
    },
    profiles: {
      ap_get_v1: {
        method: 'GET',
        algorithm: 'rsa-sha256',
        signedHeaders: ['(request-target)', 'host', 'date'],
        requireDigest: false,
        signContentType: false
      },
      ap_post_v1: {
        method: 'POST',
        algorithm: 'rsa-sha256',
        signedHeaders: ['(request-target)', 'host', 'date', 'digest'],
        requireDigest: true,
        signContentType: false
      },
      ap_post_v1_ct: {
        method: 'POST',
        algorithm: 'rsa-sha256',
        signedHeaders: ['(request-target)', 'host', 'date', 'digest', 'content-type'],
        requireDigest: true,
        signContentType: true
      }
    }
  },

  async started() {
    await this.broker.call('api.addRoute', {
      route: {
        name: 'signing-internal',
        path: '/api/internal',
        authorization: false,
        authentication: false,
        bodyParsers: { json: { strict: false, limit: this.settings.limits.maxBodyBytes } },
        onBeforeCall(ctx, route, req) {
          ctx.meta.$headers = req.headers;
        },
        aliases: {
          'POST /signatures/batch': 'signing.signHttpRequestsBatch',
          'POST /atproto/provision': 'signing.provisionAtprotoIdentity',
          'POST /atproto/commit-sign': 'signing.signAtprotoCommit',
          'POST /atproto/plc-sign': 'signing.signAtprotoPlcOp',
          'GET  /atproto/public-key': 'signing.getAtprotoPublicKey'
        }
      },
      toBottom: false
    });

    if (!this.settings.auth.bearerToken) {
      this.logger.warn('[Signing] ACTIVITYPODS_TOKEN is not configured; internal signing endpoints will fail closed');
    }
    this.logger.info('[Signing] Internal signing routes registered under /api/internal');
  },

  actions: {
    signHttpRequestsBatch: {
      params: {
        requests: { type: 'array', min: 1 },
        options: {
          type: 'object',
          optional: true,
          props: {
            maxPerBatch: { type: 'number', optional: true },
            failClosedIfActorUnknown: { type: 'boolean', optional: true, default: true }
          }
        }
      },
      async handler(ctx) {
        this._auth(ctx);
        const reqs = ctx.params.requests;
        if (reqs.length > this.settings.limits.maxBatch) {
          return {
            results: reqs.map(r => this._err(
              r,
              'INVALID_INPUT',
              `maxBatch=${this.settings.limits.maxBatch} exceeded`,
              false
            ))
          };
        }

        const byActor = new Map();
        for (const request of reqs) {
          const actorUri = request?.actorUri || '';
          if (!byActor.has(actorUri)) byActor.set(actorUri, []);
          byActor.get(actorUri).push(request);
        }

        const results = [];
        for (const [actorUri, items] of byActor) {
          const authority = await this._validateLocalActor(ctx, actorUri);
          if (!authority.ok) {
            for (const item of items) {
              results.push(this._err(item, authority.error, authority.message, authority.retryable === true));
            }
            continue;
          }

          const material = await this._resolveActivityPubSigningMaterial(
            ctx,
            actorUri,
            authority.account,
            authority.actor
          );
          if (!material.ok) {
            for (const item of items) {
              results.push(this._err(item, material.error, material.message, material.retryable === true));
            }
            continue;
          }

          for (const item of items) {
            results.push(await this._signOne(actorUri, material.keyId, material.privateKeyPem, item));
          }
        }
        return { results };
      }
    },

    provisionAtprotoIdentity: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 },
        webId: { type: 'string', optional: true },
        did: { type: 'string', optional: true },
        handle: { type: 'string', optional: true }
      },
      async handler(ctx) {
        this._auth(ctx);
        const canonicalAccountId = ctx.params.canonicalAccountId;
        const webId = ctx.params.webId || canonicalAccountId;
        if (webId !== canonicalAccountId) {
          throw new MoleculerError(
            'webId must match canonicalAccountId for internal ATProto provisioning',
            403,
            'ACCOUNT_BINDING_MISMATCH'
          );
        }
        if (!isSafeHttpUrl(webId)) {
          throw new MoleculerError(
            'canonicalAccountId must be an HTTP(S) WebID without credentials',
            400,
            'INVALID_INPUT'
          );
        }

        const accountAuthority = await this._resolveAtprotoAccountAuthority(ctx, canonicalAccountId);
        const existing = await this._getIdentityBinding(ctx, canonicalAccountId);
        if (existing) {
          throw new MoleculerError(
            'AT identity binding already exists; use the explicit repair/rotation workflow',
            409,
            'IDENTITY_BINDING_EXISTS',
            {
              canonicalAccountId,
              status: existing.status || null,
              source: existing.atprotoSource || null,
              managed: existing.atprotoManaged === true
            }
          );
        }

        const parsed = new URL(webId);
        const slug = parsed.pathname.split('/').filter(Boolean).pop() || 'account';
        const did = ctx.params.did || `did:plc:${slug}`;
        const handle = ctx.params.handle || `${slug}.test`;
        const keyMeta = { ...ctx.meta, dataset: accountAuthority.dataset, webId };

        const commitKey = await ctx.call('keys.generateSecp256k1Key', { webId }, { meta: keyMeta });
        const rotationKey = await ctx.call('keys.generateSecp256k1Key', { webId }, { meta: keyMeta });
        if (!commitKey?.keyRef || !rotationKey?.keyRef || commitKey.keyRef === rotationKey.keyRef) {
          throw new MoleculerError('AT key generation returned invalid key refs', 500, 'KEY_UNAVAILABLE');
        }

        const binding = await ctx.call('identitybindings.upsert', {
          canonicalAccountId,
          webId,
          atprotoDid: did,
          atprotoHandle: handle,
          atprotoSource: 'local',
          atprotoManaged: true,
          atSigningKeyRef: commitKey.keyRef,
          atRotationKeyRef: rotationKey.keyRef,
          status: 'active'
        });

        return {
          binding,
          commitKeyRef: commitKey.keyRef,
          rotationKeyRef: rotationKey.keyRef
        };
      }
    },

    signAtprotoCommit: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 },
        did: { type: 'string', min: 1 },
        unsignedCommitBytesBase64: { type: 'string', min: 1 },
        rev: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        this._auth(ctx);
        const { canonicalAccountId, did, unsignedCommitBytesBase64, rev } = ctx.params;
        const binding = await this._requireManagedBinding(ctx, canonicalAccountId, { statuses: ['active'] });
        if (!binding.atSigningKeyRef) {
          throw new MoleculerError('AT commit signing key is not provisioned', 422, 'KEY_UNAVAILABLE');
        }
        if (!binding.atprotoDid || did !== binding.atprotoDid) {
          throw new MoleculerError('Caller DID does not match the active binding', 400, 'INVALID_INPUT');
        }

        const commitBytes = decodeCanonicalBase64(unsignedCommitBytesBase64, 'unsignedCommitBytesBase64');
        assertAuthorizedMockRepoCommit({ bytes: commitBytes, binding, suppliedDid: did, suppliedRev: rev });

        const accountAuthority = await this._resolveAtprotoAccountAuthority(ctx, canonicalAccountId);
        const keyPair = await this._getAtprotoKeyPair(
          ctx,
          binding.atSigningKeyRef,
          accountAuthority,
          canonicalAccountId,
          'AT commit key lookup failed'
        );
        const privateKeyPem = keyPair?.privateKeyPem || keyPair?.privateKey;
        if (!privateKeyPem) {
          throw new MoleculerError('AT private key not available', 500, 'KEY_UNAVAILABLE');
        }

        let signatureBase64Url;
        try {
          signatureBase64Url = signSecp256k1(privateKeyPem, commitBytes);
        } catch (error) {
          throw new MoleculerError('Commit signing failed', 500, 'SIGNING_FAILED', {
            message: error?.message
          });
        }

        return {
          did: binding.atprotoDid,
          keyId: `${binding.atprotoDid}#atproto`,
          signatureBase64Url,
          algorithm: 'k256',
          signedAt: new Date().toISOString()
        };
      }
    },

    signAtprotoPlcOp: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 },
        did: { type: 'string', min: 1 },
        operationBytesBase64: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        this._auth(ctx);
        const { canonicalAccountId, did, operationBytesBase64 } = ctx.params;
        const binding = await this._requireManagedBinding(ctx, canonicalAccountId, {
          statuses: ['pending-plc']
        });
        if (binding.atprotoDid) {
          throw new MoleculerError(
            'Generic PLC rotation signing is not exposed; use an explicit state-bound rotation workflow',
            409,
            'PLC_TRANSITION_NOT_AUTHORIZED'
          );
        }
        if (did !== 'did:plc:pending') {
          throw new MoleculerError('PLC genesis requires the pending DID sentinel', 400, 'INVALID_INPUT');
        }
        if (!binding.atRotationKeyRef || !binding.atSigningKeyRef) {
          throw new MoleculerError('Pending PLC binding is missing key refs', 422, 'KEY_UNAVAILABLE');
        }

        const opBytes = decodeCanonicalBase64(operationBytesBase64, 'operationBytesBase64');
        const accountAuthority = await this._resolveAtprotoAccountAuthority(ctx, canonicalAccountId);
        const [rotationKeyPair, signingKeyPair] = await Promise.all([
          this._getAtprotoKeyPair(
            ctx,
            binding.atRotationKeyRef,
            accountAuthority,
            canonicalAccountId,
            'AT rotation key lookup failed'
          ),
          this._getAtprotoKeyPair(
            ctx,
            binding.atSigningKeyRef,
            accountAuthority,
            canonicalAccountId,
            'AT commit public key lookup failed'
          )
        ]);

        let rotationMultibase;
        let verificationMultibase;
        try {
          rotationMultibase = keyPairToMultibase(rotationKeyPair);
          verificationMultibase = keyPairToMultibase(signingKeyPair);
        } catch (error) {
          throw new MoleculerError('PLC public key conversion failed', 500, 'KEY_UNAVAILABLE', {
            message: error?.message
          });
        }

        assertAuthorizedPlcGenesis({
          bytes: opBytes,
          binding,
          rotationKeyMultibase: rotationMultibase,
          verificationKeyMultibase: verificationMultibase
        });

        const privateKeyPem = rotationKeyPair?.privateKeyPem || rotationKeyPair?.privateKey;
        if (!privateKeyPem) {
          throw new MoleculerError('AT rotation private key not available', 500, 'KEY_UNAVAILABLE');
        }

        let signatureBase64Url;
        try {
          signatureBase64Url = signSecp256k1(privateKeyPem, opBytes);
        } catch (error) {
          throw new MoleculerError('PLC op signing failed', 500, 'SIGNING_FAILED', {
            message: error?.message
          });
        }

        return {
          keyId: '#atproto-rotation-key',
          signatureBase64Url,
          algorithm: 'k256',
          signedAt: new Date().toISOString()
        };
      }
    },

    getAtprotoPublicKey: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 },
        purpose: { type: 'enum', values: ['commit', 'rotation'] }
      },
      async handler(ctx) {
        this._auth(ctx);
        const { canonicalAccountId, purpose } = ctx.params;
        const binding = await this._requireManagedBinding(ctx, canonicalAccountId, {
          statuses: ['active', 'pending-plc'],
          allowPendingPlcPublicKeyOnly: true
        });

        const keyRef = purpose === 'commit' ? binding.atSigningKeyRef : binding.atRotationKeyRef;
        if (!keyRef) {
          throw new MoleculerError(
            `${purpose === 'commit' ? 'atSigningKeyRef' : 'atRotationKeyRef'} not set`,
            422,
            'KEY_UNAVAILABLE'
          );
        }

        const accountAuthority = await this._resolveAtprotoAccountAuthority(ctx, canonicalAccountId);
        const keyPair = await this._getAtprotoKeyPair(
          ctx,
          keyRef,
          accountAuthority,
          canonicalAccountId,
          'AT public key lookup failed'
        );

        let publicKeyMultibase;
        try {
          publicKeyMultibase = keyPairToMultibase(keyPair);
        } catch (error) {
          throw new MoleculerError('Public key conversion failed', 500, 'KEY_UNAVAILABLE', {
            message: error?.message
          });
        }

        const resolvedDid = binding.atprotoDid || null;
        const keyFragment = purpose === 'commit' ? 'atproto' : 'atproto-rotation-key';
        return {
          ...(resolvedDid ? { did: resolvedDid } : {}),
          keyId: resolvedDid ? `${resolvedDid}#${keyFragment}` : `#${keyFragment}`,
          publicKeyMultibase,
          algorithm: 'k256'
        };
      }
    }
  },

  methods: {
    _auth(ctx) {
      const expectedToken = this.settings.auth.bearerToken;
      if (!expectedToken) {
        throw new MoleculerError(
          'Internal signing authentication is not configured',
          503,
          'SIGNING_AUTH_NOT_CONFIGURED'
        );
      }
      const authorization = ctx.meta?.$headers?.authorization || ctx.meta?.$headers?.Authorization;
      const token = parseBearerToken(authorization);
      if (!token) throw new MoleculerError('Missing or malformed bearer token', 401, 'AUTH_FAILED');
      if (!timingSafeSecretEqual(token, expectedToken)) {
        throw new MoleculerError('Invalid bearer token', 403, 'AUTH_FAILED');
      }
    },

    _err(request, code, message, retryable) {
      return {
        requestId: request?.requestId,
        ok: false,
        error: { code, message, retryable: retryable === true }
      };
    },

    async _getIdentityBinding(ctx, canonicalAccountId) {
      try {
        return await ctx.call('identitybindings.getByCanonicalAccountId', { canonicalAccountId });
      } catch (error) {
        throw new MoleculerError('IdentityBinding lookup failed', 500, 'KEY_UNAVAILABLE', {
          message: error?.message
        });
      }
    },

    async _resolveAtprotoAccountAuthority(ctx, canonicalAccountId) {
      let account;
      try {
        account = await ctx.call('auth.account.findByWebId', { webId: canonicalAccountId });
      } catch (error) {
        throw new MoleculerError(
          'Local account verification unavailable',
          503,
          'ACCOUNT_AUTHORITY_UNAVAILABLE',
          { canonicalAccountId, message: error?.message }
        );
      }
      const dataset = String(account?.username || '').trim();
      if (!account || account.webId !== canonicalAccountId || !dataset) {
        throw new MoleculerError(
          'canonicalAccountId is not bound to a local ActivityPods account',
          403,
          'ACCOUNT_NOT_LOCAL',
          { canonicalAccountId }
        );
      }
      return { account, dataset };
    },

    async _requireManagedBinding(ctx, canonicalAccountId, options = {}) {
      const binding = await this._getIdentityBinding(ctx, canonicalAccountId);
      if (!binding) {
        throw new MoleculerError('IdentityBinding not found', 404, 'ACTOR_NOT_FOUND', {
          canonicalAccountId
        });
      }
      if (binding.canonicalAccountId !== canonicalAccountId || binding.webId !== canonicalAccountId) {
        throw new MoleculerError('Identity binding account mismatch', 403, 'IDENTITY_BINDING_MISMATCH');
      }
      if (binding.atprotoSource !== 'local' || binding.atprotoManaged !== true) {
        throw new MoleculerError(
          'AT identity is not locally managed',
          403,
          'IDENTITY_BINDING_NOT_MANAGED'
        );
      }
      const statuses = Array.isArray(options.statuses) ? options.statuses : ['active'];
      if (!statuses.includes(binding.status)) {
        throw new MoleculerError('AT identity binding is inactive', 403, 'IDENTITY_BINDING_INACTIVE', {
          status: binding.status || null
        });
      }
      if (binding.status === 'pending-plc') {
        if (!options.allowPendingPlcPublicKeyOnly && statuses.length !== 1) {
          throw new MoleculerError(
            'Pending PLC state is not authorized for this action',
            403,
            'IDENTITY_BINDING_INACTIVE'
          );
        }
        if (
          binding.atprotoDid ||
          !binding.atprotoHandle ||
          !binding.atprotoPdsUrl ||
          !binding.atSigningKeyRef ||
          !binding.atRotationKeyRef
        ) {
          throw new MoleculerError(
            'Pending PLC binding is structurally incomplete',
            409,
            'IDENTITY_BINDING_INVALID'
          );
        }
      }
      return binding;
    },

    async _getAtprotoKeyPair(ctx, keyRef, accountAuthority, canonicalAccountId, failureMessage) {
      try {
        return await ctx.call(
          'keys.getAtprotoKeyPair',
          { keyRef },
          {
            meta: {
              ...ctx.meta,
              dataset: accountAuthority.dataset,
              webId: canonicalAccountId
            }
          }
        );
      } catch (error) {
        throw new MoleculerError(failureMessage, 500, 'KEY_UNAVAILABLE', {
          message: error?.message
        });
      }
    },

    async _validateLocalActor(ctx, actorUri) {
      if (!isSafeHttpUrl(actorUri)) {
        return {
          ok: false,
          error: 'INVALID_INPUT',
          message: 'actorUri must be an HTTP(S) URL without credentials',
          retryable: false
        };
      }

      let account;
      try {
        account = await ctx.call('auth.account.findByWebId', { webId: actorUri });
      } catch {
        return {
          ok: false,
          error: 'ACTOR_NOT_LOCAL',
          message: 'local account verification unavailable',
          retryable: true
        };
      }
      if (!account || account.webId !== actorUri || !account.username) {
        return {
          ok: false,
          error: 'ACTOR_NOT_LOCAL',
          message: 'actorUri is not bound to a local ActivityPods account',
          retryable: false
        };
      }

      let actor;
      try {
        actor = await ctx.call(
          'activitypub.actor.get',
          { actorUri, webId: 'system' },
          { meta: { ...ctx.meta, dataset: account.username, webId: actorUri } }
        );
      } catch {
        return {
          ok: false,
          error: 'ACTOR_NOT_LOCAL',
          message: 'local actor verification unavailable',
          retryable: true
        };
      }
      if (!actor || getResourceId(actor) !== actorUri) {
        return {
          ok: false,
          error: 'ACTOR_NOT_LOCAL',
          message: 'local account does not resolve to the requested ActivityPub actor',
          retryable: false
        };
      }

      return { ok: true, account, actor };
    },

    async _resolveActivityPubSigningMaterial(ctx, actorUri, account, actor) {
      const dataset = String(account?.username || '').trim();
      if (!dataset) {
        return {
          ok: false,
          error: 'KEY_UNAVAILABLE',
          message: 'local account dataset is unavailable',
          retryable: false
        };
      }

      const attachedPublicKeyIds = [
        ...new Set(
          asArray(actor?.publicKey)
            .map(key => (typeof key === 'string' ? key : getResourceId(key)))
            .filter(id => typeof id === 'string' && id.length > 0)
        )
      ];
      if (attachedPublicKeyIds.length === 0) {
        return {
          ok: false,
          error: 'KEY_UNAVAILABLE',
          message: 'no RSA signing key is attached to the actor',
          retryable: false
        };
      }

      let keyPairs;
      try {
        keyPairs = (
          await Promise.all(
            attachedPublicKeyIds.map(async publicKeyUri => {
              const privateKeyUri = await ctx.call(
                'keys.findPrivateKeyUri',
                { publicKeyUri },
                { meta: { ...ctx.meta, dataset, webId: actorUri } }
              );
              if (typeof privateKeyUri !== 'string' || privateKeyUri.length === 0) return null;
              return await ctx.call(
                'keys.container.get',
                { resourceUri: privateKeyUri, accept: MIME_TYPES.JSON, webId: actorUri },
                { meta: { ...ctx.meta, dataset, webId: actorUri } }
              );
            })
          )
        ).filter(Boolean);
      } catch {
        return {
          ok: false,
          error: 'KEY_UNAVAILABLE',
          message: 'RSA key lookup unavailable',
          retryable: true
        };
      }
      const attachedPublicKeyIdSet = new Set(attachedPublicKeyIds);

      const candidates = keyPairs.filter(key => {
        const keyId = key?.['rdfs:seeAlso'];
        return (
          key &&
          key.owner === actorUri &&
          key.controller === actorUri &&
          typeof key.privateKeyPem === 'string' &&
          key.privateKeyPem.length > 0 &&
          assertKeyId(keyId) &&
          attachedPublicKeyIdSet.has(keyId)
        );
      });

      if (candidates.length !== 1) {
        return {
          ok: false,
          error: 'KEY_UNAVAILABLE',
          message:
            candidates.length === 0
              ? 'no unambiguous actor-controlled RSA signing key is attached to the actor'
              : 'multiple actor-controlled RSA signing keys are attached to the actor',
          retryable: false
        };
      }

      return {
        ok: true,
        keyId: candidates[0]['rdfs:seeAlso'],
        privateKeyPem: candidates[0].privateKeyPem
      };
    },

    _parseBodyBytes(request) {
      const body = request?.body;
      if (!body || typeof body.bytes !== 'string') return null;
      if (body.encoding !== undefined && body.encoding !== 'utf8') return null;
      return Buffer.from(body.bytes, 'utf8');
    },

    _validateDateSkew(dateString) {
      return isDateWithinSkew(dateString, this.settings.limits.maxClockSkewSeconds);
    },

    async _signOne(actorUri, keyId, privateKeyPem, request) {
      try {
        const method = normalizeMethod(request?.method);
        const profileName = request?.profile;
        const profile = this.settings.profiles[profileName];
        if (!profile) {
          return this._err(request, 'PROFILE_NOT_ALLOWED', `unknown profile: ${profileName}`, false);
        }
        if (method !== profile.method) {
          return this._err(
            request,
            'PROFILE_NOT_ALLOWED',
            `profile ${profileName} only permits ${profile.method}`,
            false
          );
        }

        const host = request?.target?.host;
        const path = request?.target?.path;
        const query = request?.target?.query || '';
        if (!assertHost(host)) return this._err(request, 'INVALID_INPUT', 'target.host invalid', false);
        if (!assertPath(path)) return this._err(request, 'INVALID_INPUT', 'target.path invalid', false);
        if (!assertQuery(query)) return this._err(request, 'INVALID_INPUT', 'target.query invalid', false);

        let date = request?.headers?.date;
        if (!date) date = toHttpDate();
        if (!this._validateDateSkew(date)) {
          return this._err(request, 'INVALID_INPUT', 'date invalid or skew too large', false);
        }

        let digest = null;
        let bodySha256Base64 = null;
        if (profile.requireDigest) {
          const digestMode = request?.digest?.mode || 'server_compute';
          const bodyBuf = this._parseBodyBytes(request);
          if (!bodyBuf) {
            return this._err(request, 'INVALID_INPUT', 'utf8 body.bytes required for POST profile', false);
          }
          if (bodyBuf.length > this.settings.limits.maxBodyBytes) {
            return this._err(
              request,
              'BODY_TOO_LARGE',
              `body exceeds ${this.settings.limits.maxBodyBytes} bytes`,
              false
            );
          }
          const computedHash = sha256Base64(bodyBuf);
          const expectedDigest = `SHA-256=${computedHash}`;

          if (digestMode === 'server_compute') {
            digest = expectedDigest;
          } else if (digestMode === 'caller_provided_strict') {
            const providedDigest = request?.digest?.value;
            const providedBodyHash = request?.digest?.bodyHashSha256Base64;
            if (!providedDigest) {
              return this._err(request, 'INVALID_INPUT', 'digest.value required', false);
            }
            if (providedBodyHash && providedBodyHash !== computedHash) {
              return this._err(request, 'DIGEST_MISMATCH', 'provided body hash does not match body', false);
            }
            if (providedDigest !== expectedDigest) {
              return this._err(request, 'DIGEST_MISMATCH', 'provided digest does not match body', false);
            }
            digest = providedDigest;
          } else {
            return this._err(request, 'INVALID_INPUT', `unknown digest.mode: ${digestMode}`, false);
          }
          bodySha256Base64 = computedHash;
        } else if (request?.body !== undefined || request?.digest !== undefined) {
          return this._err(request, 'INVALID_INPUT', 'GET profile does not accept body or digest input', false);
        }

        const contentType = request?.headers?.contentType || 'application/activity+json';
        if (profile.signContentType && !assertContentType(contentType)) {
          return this._err(request, 'INVALID_INPUT', 'content-type invalid', false);
        }

        const requestTarget = buildRequestTarget(method, path, query);
        const signingString = buildSigningString(
          { requestTarget, host, date, digest, contentType },
          profile.signedHeaders
        );
        const signature = signRsaSha256(privateKeyPem, signingString);
        const signedHeadersList = profile.signedHeaders.join(' ');
        const signatureHeader = [
          `keyId="${keyId}"`,
          `algorithm="${profile.algorithm}"`,
          `headers="${signedHeadersList}"`,
          `signature="${signature}"`
        ].join(',');

        const outHeaders = { Date: date, Signature: signatureHeader };
        if (digest) outHeaders.Digest = digest;

        return {
          requestId: request?.requestId,
          ok: true,
          actorUri,
          profile: profileName,
          signedComponents: { method, path, host },
          outHeaders,
          meta: {
            keyId,
            algorithm: profile.algorithm,
            signedHeaders: signedHeadersList,
            bodySha256Base64
          }
        };
      } catch (error) {
        return this._err(request, 'INTERNAL_ERROR', error?.message || 'signing failed', true);
      }
    }
  }
};
