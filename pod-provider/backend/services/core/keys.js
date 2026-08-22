const crypto = require('crypto');
const { literal, namedNode, triple } = require('@rdfjs/data-model');
const { MIME_TYPES } = require('@semapps/mime-types');
const { KEY_TYPES } = require('@semapps/crypto/constants');
const { KeysService } = require('@semapps/crypto');
const { activityPubRsaKeyId } = require('../../utils/activitypub-rsa-key-id');

const ATPROTO_KEY_TYPE = 'urn:secp256k1-key';
const VERIFICATION_METHOD_TYPE = 'https://w3id.org/security#VerificationMethod';
const SECP256K1_MULTICODEC_PREFIX = Buffer.from([0xe7, 0x01]);
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const RDFS_SEE_ALSO = 'http://www.w3.org/2000/01/rdf-schema#seeAlso';
const SECURITY = 'https://w3id.org/security#';

function activityPubRsaVerificationMethodTriples(actorUri, publicKeyPem, keyTypes) {
  if (typeof publicKeyPem !== 'string' || publicKeyPem.length === 0) {
    throw new Error('RSA publicKeyPem is required');
  }
  const keyId = activityPubRsaKeyId(actorUri);
  return {
    keyId,
    triples: [
      ...asArray(keyTypes).map(type => triple(namedNode(keyId), namedNode(RDF_TYPE), namedNode(type))),
      triple(namedNode(keyId), namedNode(`${SECURITY}owner`), namedNode(actorUri)),
      triple(namedNode(keyId), namedNode(`${SECURITY}controller`), namedNode(actorUri)),
      triple(namedNode(keyId), namedNode(`${SECURITY}publicKeyPem`), literal(publicKeyPem))
    ]
  };
}

function asArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

module.exports = {
  mixins: [KeysService],
  settings: {
    podProvider: true
  },
  actions: {
    publishPublicKeyLocally: {
      params: {
        keyId: { type: 'string', optional: true },
        keyObject: { type: 'object', optional: true },
        webId: { type: 'string', optional: true }
      },
      async handler(ctx) {
        const webId = ctx.params.webId || ctx.meta.webId;
        const privateKeyUri = ctx.params.keyId || ctx.params.keyObject?.id || ctx.params.keyObject?.['@id'];
        if (!privateKeyUri) throw new Error('RSA key publication requires a private key resource URI');

        const keyObject =
          ctx.params.keyObject ||
          (await ctx.call('ldp.resource.get', { resourceUri: privateKeyUri, accept: MIME_TYPES.JSON }));
        const publicKeyObject = await this.actions.getPublicKeyObject({ keyObject }, { parentCtx: ctx });
        const keyTypes = asArray(publicKeyObject['@type'] || publicKeyObject.type);

        let publicKeyUri;
        if (keyTypes.includes(KEY_TYPES.RSA)) {
          if (publicKeyObject.owner !== webId || publicKeyObject.controller !== webId) {
            throw new Error('RSA verification method must be owned and controlled by its actor');
          }
          const verificationMethod = activityPubRsaVerificationMethodTriples(
            webId,
            publicKeyObject.publicKeyPem,
            keyTypes
          );
          publicKeyUri = verificationMethod.keyId;
          const actorIsRemote = await ctx.call('ldp.remote.isRemote', { resourceUri: webId });
          if (actorIsRemote) {
            throw new Error('RSA verification methods can only be published for a local actor');
          }
          // SemApps 1.1.4 treats a same-document fragment URI as a different
          // pod in ldp.remote.isRemote because it appends `/` after the hash.
          // Keep that global remote-resource guard intact: after proving the
          // fragment's credential-free owner is the local actor above, insert
          // only the already validated verification-method triples into the
          // actor's current dataset.
          await ctx.call('triplestore.update', {
            query: {
              type: 'update',
              updates: [
                {
                  updateType: 'insert',
                  insert: [{ type: 'bgp', triples: verificationMethod.triples }]
                }
              ]
            },
            webId
          });
        } else {
          publicKeyUri = await ctx.call('keys.public-container.post', {
            resource: publicKeyObject,
            contentType: MIME_TYPES.JSON,
            webId
          });
        }

        await ctx.call('ldp.resource.patch', {
          resourceUri: privateKeyUri,
          triplesToAdd: [triple(namedNode(privateKeyUri), namedNode(RDFS_SEE_ALSO), namedNode(publicKeyUri))],
          webId
        });
        return publicKeyUri;
      }
    },
    generateKey: {
      params: {
        keyType: { type: 'string' }
      },
      async handler(ctx) {
        const { keyType } = ctx.params;

        if (keyType === ATPROTO_KEY_TYPE) {
          return this.actions.generateSecp256k1KeyMaterial({}, { parentCtx: ctx });
        }

        if (keyType === KEY_TYPES.ED25519) {
          return this.actions.generateEd25519Key({}, { parentCtx: ctx });
        }

        if (keyType === KEY_TYPES.RSA) {
          return this.actions.generateRsaKey({}, { parentCtx: ctx });
        }

        throw new Error('Key type not supported.');
      }
    },

    generateSecp256k1KeyMaterial: {
      params: {},
      async handler() {
        return new Promise((resolve, reject) => {
          crypto.generateKeyPair(
            'ec',
            {
              namedCurve: 'secp256k1',
              publicKeyEncoding: { type: 'spki', format: 'pem' },
              privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
            },
            (err, publicKeyPem, privateKeyPem) => {
              if (err) return reject(err);
              resolve({
                '@type': [ATPROTO_KEY_TYPE, VERIFICATION_METHOD_TYPE],
                publicKeyPem,
                privateKeyPem
              });
            }
          );
        });
      }
    },

    generateSecp256k1Key: {
      params: {
        webId: { type: 'string' },
        attachToWebId: { type: 'boolean', optional: true, default: false },
        publishKey: { type: 'boolean', optional: true, default: false }
      },
      async handler(ctx) {
        const { webId, attachToWebId = false, publishKey = false } = ctx.params;

        const keyObject = await this.actions.createKeyForActor(
          {
            webId,
            keyType: ATPROTO_KEY_TYPE,
            attachToWebId,
            publishKey
          },
          { parentCtx: ctx }
        );

        return {
          keyRef: keyObject.id,
          publicKeyRef: keyObject['rdfs:seeAlso'] || null,
          privateKeyPem: keyObject.privateKeyPem,
          publicKeyPem: keyObject.publicKeyPem,
          publicKeyMultibase: this.secp256k1PublicPemToMultibase(keyObject.publicKeyPem)
        };
      }
    },

    getAtprotoKeyPair: {
      params: {
        keyRef: { type: 'string' }
      },
      async handler(ctx) {
        const { keyRef } = ctx.params;
        const keyObject = await ctx.call('keys.container.get', {
          resourceUri: keyRef,
          accept: MIME_TYPES.JSON,
          webId: 'system'
        });

        const keyTypes = asArray(keyObject['@type'] || keyObject.type);
        if (!keyTypes.includes(ATPROTO_KEY_TYPE)) {
          throw new Error('KEY_INVALID: keyRef must be a private secp256k1 key resource URI');
        }
        if (!keyObject.privateKeyPem) {
          throw new Error('KEY_UNAVAILABLE: privateKeyPem missing on key resource');
        }

        let publicKeyPem = keyObject.publicKeyPem;
        if (!publicKeyPem && keyObject['rdfs:seeAlso']) {
          const publicKeyObject = await ctx.call('ldp.resource.get', {
            resourceUri: keyObject['rdfs:seeAlso'],
            accept: MIME_TYPES.JSON,
            webId: 'system'
          });
          publicKeyPem = publicKeyObject.publicKeyPem;
        }
        if (!publicKeyPem) {
          throw new Error('KEY_UNAVAILABLE: publicKeyPem missing on key resource');
        }

        const publicKeyMultibase = this.secp256k1PublicPemToMultibase(publicKeyPem);

        return {
          keyRef,
          privateKeyPem: keyObject.privateKeyPem,
          publicKeyPem,
          publicKeyMultibase,
          // Temporary aliases for compatibility with existing callers.
          privateKey: keyObject.privateKeyPem,
          publicKey: publicKeyPem
        };
      }
    }
  },
  methods: {
    secp256k1PublicPemToMultibase(publicKeyPem) {
      const compressedPoint = this._secp256k1CompressSpkiPublicKey(publicKeyPem);
      return `z${this._toBase58(Buffer.concat([SECP256K1_MULTICODEC_PREFIX, compressedPoint]))}`;
    },

    _secp256k1CompressSpkiPublicKey(publicKeyPem) {
      const publicKey = crypto.createPublicKey(publicKeyPem);
      const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
      const point = spkiDer.slice(-65);

      if (point.length !== 65 || point[0] !== 0x04) {
        throw new Error('Invalid secp256k1 SPKI key encoding');
      }

      const x = point.slice(1, 33);
      const y = point.slice(33, 65);
      const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
      return Buffer.concat([Buffer.from([prefix]), x]);
    },

    _toBase58(buffer) {
      if (buffer.length === 0) return '';

      let value = BigInt(`0x${buffer.toString('hex')}`);
      let out = '';
      while (value > 0n) {
        out = BASE58_ALPHABET[Number(value % 58n)] + out;
        value /= 58n;
      }

      for (let i = 0; i < buffer.length && buffer[i] === 0; i += 1) {
        out = '1' + out;
      }

      return out;
    }
  }
};

module.exports.activityPubRsaKeyId = activityPubRsaKeyId;
module.exports.activityPubRsaVerificationMethodTriples = activityPubRsaVerificationMethodTriples;
