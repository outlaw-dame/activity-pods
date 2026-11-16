# Dependency and lint maintenance — 2026-11-16

Base: `eb533a260940f0e0966fdb6a9e4d3e24aebaf804`.

Root ESLint 9 conflicted with TypeScript ESLint 7. The dependency declarations
now use compatible ESLint 8.57.1. The frontend uses the same ESLint generation
and TypeScript 4.9 supported by its existing react-scripts 5 toolchain. MUI
styles supports the installed React generation. Backend manifests and locks
are synchronized; the React workspace explicitly supplies React DOM, and the
test workspace explicitly declares its WebSocket import.

Lint repairs include missing actor context, missing UI imports, duplicate keys,
and an undefined activity in the grant matcher. The grant matcher now requires
the actual activity as its third argument and fails closed if it is absent.
No in-repository callers required migration. It is a matching helper, not a
credential signature verifier. Cleanup failures no longer replace primary
failures in four disposable proof tests. Intentional control-character security
filters retain their behavior with narrow lint exceptions.

Verification performed locally in a fresh checkout outside iCloud:

- Root, backend, frontend, and test `npm ci` succeeded; backend postinstall
  patches executed successfully.
- Full repository lint and the additional actor-context regression lint passed;
  the final commit is also checked by the new CI workflow.
- Frontend production build succeeded with existing dependency source-map,
  outdated Browserslist, and bundle-size warnings.
- 64 targeted authorization, actor-context, and hashtag tests passed.

ESLint 8 and the existing CRA ecosystem remain deprecated; this compatibility
repair is not a completed toolchain modernization or vulnerability audit.
Documentation and app-framework Yarn lockfiles and the root Bun lockfile were
synchronized with their manifests. The
domain-guard package still has no committed lockfile; its installation remains
manifest-based and is not claimed as reproducible.

Production release fuses remain CLOSED. Durable PostgreSQL canonical signup,
genuinely signed hosted PDS authority, and Solid-OIDC/SAI browser acceptance
remain separate production acceptance gates. These maintenance changes do not
establish production readiness.
