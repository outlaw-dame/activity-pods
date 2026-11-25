# Tracked ActivityPods runtime credentials and Redis snapshot — containment and rotation

**Status: security hygiene candidate; production signup remains CLOSED.**

The default branch previously tracked `pod-provider/backend/.env` and
`pod-provider/backend/dump.rdb`. The former had populated signing-related
tokens, a cookie secret and a Fuseki administrator password. The latter is a
binary Redis persistence image; its full contents are **not** examined or
reproduced here. Assume it may include authentication/session data until an
authorized private forensic review determines otherwise.

Deleting these files from the latest tree does **not** remove them from earlier
Git commits, clones, pull-request diffs, artifacts, caches, images or mirrors.
Do not publish their values in issues, CI, documentation or logs.

## Immediate operator actions

1. Record ownership of all affected deployments. Preserve necessary audit
   evidence securely, not in the public repository. Identify whether any
   historical value was actually accepted outside disposable local testing.
2. Rotate each formerly committed secret wherever used: Fuseki admin login,
   cookie/session signing secret, sidecar handoff token, ActivityPods internal
   API token, signing API token and SMTP/backup credentials if applicable.
   Reconfigure both sides of each authenticated bridge atomically and verify
   denial with the retired token. Do not log or include the values in tests.
3. Invalidate existing application sessions and token/refresh families that
   depended on compromised keys or Redis material. If keys, OAuth grants or
   account access data may be present in the Redis snapshot, perform a
   privacy/security incident assessment and enforce canonical revocations.
   Rotating a cookie secret alone does not revoke signed JWTs issued from an
   unaffected signing key.
4. Replace the released Redis state with clean, independently backed-up
   production volumes. Do not import the tracked `dump.rdb` or restore old
   grants into new production. Verify restored sessions cannot bypass the
   canonical PostgreSQL and independent witness revocation fence.
5. Rebuild containers from a reviewed source revision. Verify the build
   context and resulting image do not carry env files, Redis dumps, key
   directories, historical build-cache layers or copied host data.
6. Independently review any Git-history rewrite plan using `git-filter-repo`
   or equivalent. A normal deletion commit leaves historic objects accessible.
   Coordinate force-push, branch protection, fork/mirror cleanup, cached CI
   artifacts and secret scanning; rewriting history is disruptive and must
   not be performed unilaterally. **Rotation is mandatory even if history is
   later rewritten.**

## Regression controls

- `pod-provider/backend/.gitignore` rejects local env files (except a
  deliberately nonsecret test fixture and example), RDB/AOF state and AOF
  directories.
- `pod-provider/.dockerignore` excludes the corresponding backend secrets
  and serialized state from container build contexts.
- `backend/.env.example` contains no populated sensitive credential values.
  Use unique credentials through the deployment secret store; the example is
  not a functioning production configuration.
- CI runs `proof-no-tracked-runtime-artifacts.cjs` before installing
  dependencies. It audits tracked INDEX paths, permits local untracked files,
  checks the test-only fixture's strict key allowlist, and rejects populated
  credential fields in the example.
- The security cleanup does not disable any auth checks, change signer
  delegation, open signup, or qualify an independent immutable witness.

## Remaining release acceptance

The operator must record the credential rotation, confirm the old values
are rejected, perform restore rollback tests across PostgreSQL/Redis/Jena/PDS,
and complete independent signer/WORM custody plus owner-approved OAuth/SAI/PDS
lifecycle acceptance. Positive hosted signup and independent security signoff
are still required. **Never treat this cleanup as authorization to change
`release=CLOSED`.**
