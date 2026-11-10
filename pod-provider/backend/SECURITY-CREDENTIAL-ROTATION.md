# Internal signing credential rotation

The internal signing and federation bridge credentials are service credentials. Treat any credential that has ever been committed to repository history as compromised, even after the current working tree no longer contains it.

## Required production response

1. Generate new, independent high-entropy values for each deployed internal credential. Do not reuse a historical value and do not derive one credential from another.
2. Store credentials only in the deployment secret manager or equivalent protected runtime configuration. Do not commit generated values to Git.
3. Rotate both ends of each authenticated internal connection in a coordinated deployment so no component silently falls back to an older credential.
4. Verify the old credential is rejected after rollout. A successful request using an old credential is a failed rotation.
5. Review deployment logs and secret stores for copied historical values and replace them where found.
6. If repository-history removal is required by the project's incident policy, perform that as an explicit history-rewrite operation with coordinated clone/fork invalidation. Deleting a file in a normal commit does not remove old blobs from Git history.

## ActivityPods signing token

`ACTIVITYPODS_TOKEN` is required by the internal signing API. The service deliberately has no source-level default and does not fall back to `SIDECAR_TOKEN` or `SIGNING_API_TOKEN`.

Use a random token with at least 32 bytes of entropy encoded with characters safe for a Bearer credential. Generate it with the deployment secret manager or another cryptographically secure random generator; never use test fixtures or documentation examples as production credentials.

## Validation expectations

After rotation:

- requests without `ACTIVITYPODS_TOKEN` fail closed;
- malformed or incorrect bearer credentials are rejected;
- the previous credential is rejected;
- the sidecar and ActivityPods agree on the new credential;
- no generated credential appears in Git-tracked `.env*`, Redis snapshots, logs, test output, or documentation.
