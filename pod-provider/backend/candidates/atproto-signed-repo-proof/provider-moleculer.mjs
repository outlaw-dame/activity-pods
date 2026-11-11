/**
 * NON-ACTIVATED Moleculer schema factory. This module lives under candidates,
 * not services. It is not registered by the production service loader.
 *
 * A future reviewed integration must instantiate this schema with a real PG
 * pool and TWO independent internal secrets, then add the call-site capability
 * on atproto-provisioning. Do not import it into the service tree prematurely.
 */
import crypto from 'node:crypto';
import { createSignedRepoProofStore } from './store.mjs';
import { createProviderManagedRepoAuthority } from './provider-authority.mjs';

function configurationError() {
  const err = new Error('Managed repository authority is disabled or missing trusted provider configuration');
  err.code = 'MANAGED_REPO_NOT_RELEASED';
  return err;
}

function secretEquals(value, expected) {
  if (typeof value !== 'string' || typeof expected !== 'string' || expected.length < 32) return false;
  const a = Buffer.from(value);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * Broker-internal adapter; no API routes, arbitrary signer endpoints, or
 * external actor inputs are introduced. No secret fallback is permitted.
 *
 * Both secrets are injected by the provider process; never exposed through
 * the service settings (which may be introspected).
 */
export function makeProviderManagedRepositoryService({ pool, providerCapability, signingBearerToken } = {}) {
  if (!pool || typeof pool.connect !== 'function' || typeof pool.query !== 'function' ||
      typeof providerCapability !== 'string' || providerCapability.length < 32 ||
      typeof signingBearerToken !== 'string' || signingBearerToken.length < 32 ||
      providerCapability === signingBearerToken) {
    throw configurationError();
  }
  const store = createSignedRepoProofStore({ pool, fixtureOnly: true });
  // A fresh top-level broker call deliberately does not inherit the caller's
  // providerRepoCapability through Moleculer's nested Context.meta merging.
  const callSigning = (ctx, action, params) => ctx.broker.call(action, params, {
    meta: { $headers: { authorization: 'Bearer ' + signingBearerToken } }
  });
  const authorized = ctx => {
    if (process.env.NODE_ENV === 'production' ||
        process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
        ctx?.caller !== 'atproto-provisioning' ||
        !secretEquals(ctx?.meta?.providerRepoCapability, providerCapability)) {
      throw configurationError();
    }
  };
  async function perform(ctx, action) {
    authorized(ctx);
    const input = {
      canonicalAccountId: ctx.params?.canonicalAccountId,
      did: ctx.params?.did, handle: ctx.params?.handle
    };
    // Existing provider verifier does DID doc, DNS/.well-known and PDS checks
    // in a single call. The authority has already matched the protected RDF
    // binding and never accepts a public caller's arbitrary PDS endpoint.
    const resolveDelegatedIdentity = ({ did, handle, pdsUrl }) =>
      ctx.broker.call('atproto-verification.verifyDelegatedIdentity', {
        pdsUrl, subjectDid: did, did, handle
      });
    const authority = createProviderManagedRepoAuthority({
      store,
      resolveBinding: accountId => ctx.broker.call('identitybindings.getByCanonicalAccountId', {
        canonicalAccountId: accountId
      }),
      resolveCommitKey: accountId => callSigning(ctx, 'signing.getAtprotoPublicKey', {
        canonicalAccountId: accountId, purpose: 'commit'
      }),
      resolveDelegatedIdentity,
      signCommit: (accountId, did, rev, unsignedCommitBytesBase64) =>
        callSigning(ctx, 'signing.signAtprotoCommit', {
          canonicalAccountId: accountId, did, rev, unsignedCommitBytesBase64
        })
    });
    return authority[action](input);
  }
  return Object.freeze({
    name: 'atproto-managed-repository',
    dependencies: [
      'identitybindings', 'signing', 'atproto-verification'
    ],
    actions: {
      bootstrapAndVerify: {
        params: {
          canonicalAccountId: 'string|min:1',
          did: 'string|min:1',
          handle: 'string|min:1'
        },
        handler(ctx) { return perform(ctx, 'bootstrapAndVerify'); }
      },
      verifyReady: {
        params: {
          canonicalAccountId: 'string|min:1',
          did: 'string|min:1',
          handle: 'string|min:1'
        },
        handler(ctx) { return perform(ctx, 'verifyReady'); }
      },
      inspectRecovery: {
        params: {
          canonicalAccountId: 'string|min:1',
          did: 'string|min:1',
          handle: 'string|min:1'
        },
        handler(ctx) { return perform(ctx, 'inspectRecovery'); }
      }
    }
  });
}
