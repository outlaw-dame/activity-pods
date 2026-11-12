# Private storage and ATProto release gate

This change is a **first-party Compose fresh-install baseline**, not a live migration or an enabled managed-ATProto repository service.

## Deployment boundaries

- Fuseki's administrative SPARQL listener, Redis, Mailcatcher, and optional administration dashboards publish only on 127.0.0.1 in the resolved Docker Compose configuration. Containers on the same Docker network can still reach them: **host loopback binding alone is not service-to-service authorization**. Restrict deployment networks and use dedicated Fuseki credentials/ACLs before granting an untrusted service network access.
- Fuseki's administrator password is a required deployment secret, not a checked-in default. The host port and password policy are exercised against rendered Compose JSON in `.github/workflows/atproto-private-storage-boundary.yml`.
- First-party ActivityPods Redis is pinned to `redis:8.2.11-alpine` with AOF every-second fsync and `noeviction`. This does not guarantee losslessness on a hard crash: independent backups, verified restores and remaining writer-side ACKED/queue admission are release gates. No automatic Redis 7 downgrade or in-place data conversion is performed by this PR.
- A persisted Redis 7 deployment must inventory outstanding Streams/PEL entries, ACLs and source writers; back up and restore-test the volume; rehearse the supported upgrade; and check memory/AOF headroom before switching its image tag.
- The source-controlled `assertNativeProtectedStorageReleased` deliberately refuses to activate the real ATProto native SAI or canonical PostgreSQL authority outside an expressly disposable test provider. The guard is **not** authorization for privileged SPARQL: until normal SemApps triplestore write credentials are separated from the canonical protected identity/consent graph, privileged direct writes remain a bypass.

## Production release acceptance (still closed)

1. Confirm Compose and production network/firewall policy, TLS and least-privilege Fuseki service credentials with an actual nonprivileged denied write against the protected dataset.
2. Prove all native LDP, SPARQL, SAI authorization/grant create/update/delete/revoke and fallback mutations respect the same atomic permission revision and ownership model across multiple provider nodes.
3. Verify a real Solid-OIDC login/grant, managed DID/PLC resolution, signed PostgreSQL repository readiness, and remote ATProto record federation; do not equate a fixture boolean with a signed repository.
4. Rehearse container loss, Redis and PostgreSQL restore, grant revocation races, and measured p95/p99, RSS, queue growth and cost.
5. Only a separate, explicit release PR may remove the hard-coded disabled gate, with exact-head protected workflows and production deployment evidence.

This PR makes no changes to the notification ledger, WebSocket gateway, ActivityPub webhook, or unrelated OAuth API surface from superseded stacked experiments.
