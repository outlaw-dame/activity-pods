# Paper Groups G2-P2 — Provider-Owned Membership Authority

**Status:** Storage template and internal service contract implemented, under the immutable release fuse. Not approved for live Group membership, public membership APIs or federation. No Group actor was issued.

## Scope and authority

Paper Groups are true provider-owned Groups, not a Pod ACL group, a personal account or a WebID replacement. Membership is distinct from following a Group and distinct from participating in a forum thread.

All G2-P2 writes operate on the same Fuseki `settings` dataset as G1 Group reservations and SemApps `AuthAccount`. The membership key is deterministic from canonical Group ID + member ActivityPub actor/WebID URI. A registered Group owner is immutable in this slice. Owner membership is initialized once; owner-only management currently supports roles `member`, `moderator`, `admin` and statuses `active`, `banned`, `left`. Delegated moderation, join requests, invitation approvals, co-owner transfers and ATProto membership proofs are **not** implemented; all must be explicitly reviewed instead of inferred from a role string.

### Authorization

The `collective-memberships` Moleculer service defines **no HTTP route** and is disabled by both `CONSENT_BRIDGE_RELEASED=false` and the default-off `PROVIDER_COLLECTIVES_MEMBERSHIPS_ENABLED` flag. Every action would require a short-lived HMAC capability bound to owner WebID, canonical Group ID, approved application URI, operation and normalized inputs.

The SAI capability `apods:ManageMembers` is now defined distinctly from `CreateGroup` and `ReadGroups`, including their canonical expanded RDF forms. Group-only SAI grants do **not** become personal Pod WebACL permissions. Every membership operation performs native live account, app-registration and `ManageMembers` rights checks before and after the authoritative settings query/update, and the SAME settings-dataset SPARQL operation requires the exact reserved app, stable provider SAI consent ledger, no pending SAI mutation and active unique SemApps account. This adds a bounded number of authority checks per membership **operation/page**, not per local or remote recipient.

**No credential issuer exists yet.** A future provider issuer must validate the user's real Solid-OIDC identity and SAI `ManageMembers` consent before signing the short-lived operation capability. `CreateGroup` and `ReadGroups` alone are never sufficient; a valid HMAC alone is insufficient without live SAI consent. The disabled release fuse stays closed, and this change does not expose an authentication endpoint. This code must not be enabled by changing the release fuse without that integration and real HTTP negative tests.

Every Fuseki conditional write and owner-scoped read simultaneously checks the persisted Group owner and unique, active SemApps account. Deletion, suspension, disabled and duplicate accounts fail closed without a stale cached grant. Authorization is not inferred from client-supplied identity or Pod group membership.

### Storage correctness and revisions

- `initializeQuery`: virgin membership epoch becomes 1 only for an existing G1 reservation with a unique, currently active owner account. Replay cannot reset an existing membership epoch.
- `mutateQuery`: one TDB2 `DELETE/INSERT WHERE` update compares expected epoch, validates persisted Group ownership and active account, changes one deterministic member subject and increments the epoch. Each invocation writes a fresh random receipt to prevent a losing concurrent request from claiming success based on another request's identical desired state.
- `readMutationQuery`: confirms committed epoch, member role/status and **exact receipt**, not merely a matching postcondition.
- `listQuery`: active-only members, owner-authorized, keyset cursor, `LIMIT pageSize+1`, no `OFFSET` or provider-wide account scan. Revisions are returned for each row to detect in-query ambiguity.
- `collective-membership-cursor.js` (merged in PR #118) separately rejects cross-page revision changes, overlapping/unsorted actor keys and missing terminal cursors. It does not authenticate source pages.
- All writes remain provider-authoritative and never create a per-Group Pod.

## Evidence and performance limitations

The dedicated G2 workflow starts disposable TDB2, verifies owner initialization, unique membership revision, concurrent expected-epoch conflict, outsider rejection, banned-member exclusion, keyset cursor and restart durability on real Fuseki. It also exercises owner deletion, suspension, disabled/duplicate account records and a deliberately blocked SAI consent ledger: each must deny reads and writes while leaving the revision unchanged. A separate backend test validates the real SAI right distinction and non-escalation to personal Pod ACLs.

**Keyset paging prevents OFFSET but is not, by itself, proof of an indexed low-cost sort.** Fuseki `FILTER(STR(?actor) > cursor) ORDER BY STR(?actor)` may still evaluate many Group membership records, especially for deep pages. Before enabling large Groups, benchmark 1k/10k/100k member datasets and Fuseki query plans; if sorting or repeated scans dominate, add a verified secondary index/materialized per-Group cursor projection or move membership pagination to an appropriately indexed authority store with transactional replay/reconciliation semantics. Never claim that this query scales sublinearly simply because it uses a cursor.

G1's release fuse, public Group API, actor issuance, Fedify remote delivery and local Pod inbox implementation remain untouched. This PR does **not** solve the senior engineer's local delivery call-amplification problem: APDM P10–P12 must eliminate that work before Groups content fan-out is activated.

## G2-P2 follow-on — native Solid-OIDC credential bridge (review branch)

The native provider API now contains a separately release-fenced owner-scoped
membership **read-only** bridge. It reuses the **existing authenticated Solid-OIDC gateway**
and re-verifies the signed access token and its exact app/user projection.
A single shared claim module constructs the same canonical request digest as
the membership authority; its 30-second, operation/group/owner/app/parameters-
bound HMAC never appears in the HTTP response. The authoritative membership
service still checks live `ManageMembers` SAI rights, registered application,
active owner and the transactionally stable consent ledger. This is not a new
login, passkey ceremony or an app-issued permission.

Both the G1 API gate and the additional
`PROVIDER_COLLECTIVES_MEMBERS_API_ENABLED` gate are required; the immutable
`CONSENT_BRIDGE_RELEASED=false` still blocks the entire route. Only the
existing owner-scoped list operation is bridged. **No HTTP membership mutation
route exists:** owner-driven active membership insertion cannot be exposed
until invitations, acceptance and user-consent authorization are implemented. There is no
moderator delegation, join approval, invitation, membership self-service,
public Group page, Group actor or delivery activation.

**Acceptance still pending:** real rendered consent UI and deployed provider
OIDC/SAI negative-path tests; private member-list IDOR and LDP bypass probes;
disposable Fuseki grant/revoke/race/kill-restart tests; join/moderation semantics;
deep-page 10k/100k query-plan measurements and local delivery cost proof.
Do not enable this bridge based on unit tests alone.

## Next activation gates

1. Integrate a real native Solid-OIDC/SAI ManageMembers consent issuer, owner/admin/moderator policies, delegated role limits, and authenticated HTTP/LDP abuse tests.
2. Add requested/invited membership, following-vs-membership boundaries, bans, join/leave semantics and ATProto-compatible identity mapping without treating unrelated ATProto DID records as verified AP actors.
3. Prove membership pagination query plans/cost under high cardinality, and multi-replica owner/account deletion vs membership-write races, including SIGKILL and retry.
4. Connect only completed authoritative membership snapshots to the **non-dispatchable** G2-P1 planner; never execute partial pages or leak private memberships.
5. Complete G2-P3 local Pod delivery cost reduction and G2-P4 single Fedify delivery authority, then end-to-end 1/10/100/1,000 local, remote and mixed load/fault measurements.

**Production activation remains blocked.**
