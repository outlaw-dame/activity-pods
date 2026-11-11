// Keep the ESM adapter and CommonJS Moleculer services on the same
// revocation policy. Changing the fence in one place changes it in both.
import consentFence from './pod-consent-fence.cjs';
export const { safeIri, safeEpoch, consentSubject, consentGuard, readConsentQuery, bootstrapConsentQuery, beginRevocationQuery, parseConsentRows } = consentFence;
