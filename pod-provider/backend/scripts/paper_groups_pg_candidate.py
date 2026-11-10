"""Isolated Paper Groups PostgreSQL *candidate* authority.

No runtime import, HTTP route, live Solid/SAI grant or federation executor.
Callers must use one provider-only PostgreSQL DB connection. Every operation
acquires locks in the order identity -> consent -> Group to guarantee that
revocation and member commits have one unambiguous serialization order.
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import urlsplit

NAMESPACE = "paper_groups_candidate"
GROUP_RE = re.compile(r"cg_[0-9a-f]{32}\Z")
VALID_ROLES = frozenset(("admin", "moderator", "member"))
VALID_STATUSES = frozenset(("active", "invited", "requested", "left", "banned"))
MAX_PAGE = 100


class AuthorityDenied(Exception):
    pass


class StaleRevision(Exception):
    pass


def require_https(value: str) -> str:
    if not isinstance(value, str) or not 8 <= len(value) <= 2048:
        raise ValueError("invalid HTTPS actor URI length")
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("invalid HTTPS actor URI characters")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.netloc or
            parsed.username is not None or parsed.password is not None or
            parsed.hostname is None):
        raise ValueError("invalid HTTPS actor URI")
    return value


def require_group(group_id: str) -> str:
    if not isinstance(group_id, str) or GROUP_RE.fullmatch(group_id) is None:
        raise ValueError("invalid Group identifier")
    return group_id


def configure_transaction(conn):
    # Bounded lock and query wait. No database I/O during an HTTP request
    # beyond the single short transaction; no remote dereferencing in locks.
    conn.execute("SET LOCAL lock_timeout = '2500ms'")
    conn.execute("SET LOCAL statement_timeout = '8000ms'")
    conn.execute("SET LOCAL idle_in_transaction_session_timeout = '5000ms'")


def _identity(conn, owner: str, lock: str = "SHARE",\n              require_active: bool = True):
    result = conn.execute(
        "SELECT enabled,lifecycle_revision FROM paper_groups_candidate.identities "
        "WHERE webid=%s FOR " + lock, (owner,)
    ).fetchone()
    if not result or not result[0]:
        raise AuthorityDenied("owner disabled or unknown")
    return result


def _consent(conn, owner: str, app: str, lock: str = "SHARE"):
    result = conn.execute(
        "SELECT granted,revision FROM paper_groups_candidate.consent "
        "WHERE owner_webid=%s AND app_uri=%s FOR " + lock,
        (owner, app)
    ).fetchone()
    if result is None or not result[0]:
        raise AuthorityDenied("consent revoked or missing")
    return result[1]


def provision_owner(conn, owner: str, app: str):
    """Fixture bootstrap only; NEVER wired to a live Solid-OIDC provider."""
    owner, app = require_https(owner), require_https(app)
    with conn.transaction():
        configure_transaction(conn)
        conn.execute(
            "INSERT INTO paper_groups_candidate.identities(webid) VALUES (%s)",
            (owner,)
        )
        conn.execute(
            "INSERT INTO paper_groups_candidate.consent(owner_webid,app_uri,granted) "
            "VALUES (%s,%s,true)", (owner,app)
        )


def revoke_consent(conn, owner: str, app: str, expected_revision: int):
    """Revocation owns the same consent row that all writes hold FOR SHARE.

    A committed revocation blocks any newer membership transaction, even
    when its request originally arrived before revocation.
    """
    owner, app = require_https(owner), require_https(app)
    with conn.transaction():
        configure_transaction(conn)
        # Revocation must be allowed even if the account was suspended first;
        # otherwise a later re-enable could resurrect an old grant.
        _identity(conn, owner, require_active=False)
        revision = _consent(conn, owner, app, "UPDATE")
        if revision != expected_revision:
            raise StaleRevision("consent revision changed")
        result = conn.execute(
            "UPDATE paper_groups_candidate.consent "
            "SET granted=false,revision=revision+1 "
            "WHERE owner_webid=%s AND app_uri=%s AND revision=%s "
            "RETURNING revision", (owner,app,revision)
        ).fetchone()
        if result is None:
            raise StaleRevision("consent revision changed")
        return result[0]


def disable_owner(conn, owner: str, expected_revision: int):
    owner = require_https(owner)
    with conn.transaction():
        configure_transaction(conn)
        result = _identity(conn,owner,"UPDATE")
        if result[1] != expected_revision:
            raise StaleRevision("owner lifecycle changed")
        return conn.execute(
            "UPDATE paper_groups_candidate.identities "
            "SET enabled=false,lifecycle_revision=lifecycle_revision+1 "
            "WHERE webid=%s RETURNING lifecycle_revision",(owner,)
        ).fetchone()[0]


def reserve_group(conn, group: str, owner: str, app: str):
    """An inert Group reservation, not actor activation or membership grant."""
    group = require_group(group)
    owner, app = require_https(owner),require_https(app)
    with conn.transaction():
        configure_transaction(conn)
        _identity(conn, owner)
        _consent(conn, owner, app)
        conn.execute(
            "INSERT INTO paper_groups_candidate.groups "
            "(group_id,owner_webid,app_uri,revision,state) "
            "VALUES (%s,%s,%s,1,'reserved')",(group,owner,app)
        )
        conn.execute(
            "INSERT INTO paper_groups_candidate.members "
            "(group_id,actor_uri,role,status,change_revision) "
            "VALUES (%s,%s,'owner','active',1)",(group,owner)
        )


def _locked_group(conn, group: str, owner: str, app: str):
    row = conn.execute(
        "SELECT revision,state,visibility FROM paper_groups_candidate.groups "
        "WHERE group_id=%s AND owner_webid=%s AND app_uri=%s FOR UPDATE",
        (group,owner,app)
    ).fetchone()
    if not row or row[1] == "suspended":
        raise AuthorityDenied("Group missing, mismatched or suspended")
    return row


def mutate_member(conn, *, group: str, owner: str, app: str,
                  member: str, role: str, status: str,
                  expected_revision: int, operation_id: str):
    """Atomic candidate only: actual admission and actor consent not wired.

    Exactly one mutation+revision+audit transition per Group transaction.
    The production handler must not expose this until invitations, admission
    policies, actor proof and Solid-OIDC/SAI migration are complete.
    """
    group=require_group(group)
    owner,app,member=map(require_https,(owner,app,member))
    if member == owner or role not in VALID_ROLES or status not in VALID_STATUSES:
        raise ValueError("owner role immutable or member state invalid")
    if type(expected_revision) is not int or expected_revision < 1:
        raise ValueError("invalid expected revision")
    operation_id = uuid.UUID(operation_id)
    with conn.transaction():
        configure_transaction(conn)
        _identity(conn,owner)
        consent_revision=_consent(conn,owner,app)
        current=_locked_group(conn,group,owner,app)
        replay=conn.execute(
            "SELECT revision,actor_uri,role,status FROM "
            "paper_groups_candidate.transitions "
            "WHERE group_id=%s AND operation_id=%s",
            (group,operation_id)
        ).fetchone()
        if replay is not None:
            if replay[1:] != (member,role,status):
                raise AuthorityDenied("operation ID reused for different mutation")
            return {"revision": replay[0], "replay": True}
        if current[0] != expected_revision:
            raise StaleRevision("membership revision changed")
        next_revision = expected_revision+1
        conn.execute(
            "INSERT INTO paper_groups_candidate.members "
            "(group_id,actor_uri,role,status,change_revision) "
            "VALUES (%s,%s,%s,%s,%s) "
            "ON CONFLICT (group_id,actor_uri) DO UPDATE "
            "SET role=EXCLUDED.role,status=EXCLUDED.status,"
            "change_revision=EXCLUDED.change_revision",
            (group,member,role,status,next_revision)
        )
        conn.execute(
            "UPDATE paper_groups_candidate.groups SET revision=%s "
            "WHERE group_id=%s AND revision=%s",
            (next_revision,group,expected_revision)
        )
        conn.execute(
            "INSERT INTO paper_groups_candidate.transitions "
            "(group_id,revision,actor_uri,status,role,operation_id,consent_revision) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (group,next_revision,member,status,role,operation_id,consent_revision)
        )
        return {"revision":next_revision,"replay":False}


def list_members(conn, *, group: str, owner: str, app: str,
                 after: str | None = None, limit: int = MAX_PAGE,
                 expected_revision: int | None = None):
    group=require_group(group)
    owner,app=map(require_https,(owner,app))
    if after is not None:
        after=require_https(after)
        if expected_revision is None:
            raise ValueError("paged roster requires expected revision")
    if expected_revision is not None and (type(expected_revision) is not int or
                                          expected_revision < 1):
        raise ValueError("invalid expected roster revision")
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise ValueError("invalid bounded page size")
    with conn.transaction():
        configure_transaction(conn)
        _identity(conn,owner)
        _consent(conn,owner,app)
        row=conn.execute(
            "SELECT revision FROM paper_groups_candidate.groups "
            "WHERE group_id=%s AND owner_webid=%s AND app_uri=%s "
            "AND state!='suspended' FOR SHARE",
            (group,owner,app)
        ).fetchone()
        if not row:
            raise AuthorityDenied("Group not available")
        if expected_revision is not None and row[0] != expected_revision:
            raise StaleRevision("roster changed between pages")
        # The membership visibility contract is not publicly wired. This
        # query is strictly for a trusted provider operation after checking
        # live consent. No OFFSET, global sort, or per-member database calls.
        members=conn.execute(
            'SELECT actor_uri,role FROM paper_groups_candidate.members '
            'WHERE group_id=%s AND status=\'active\' '
            'AND actor_uri COLLATE "C" > %s COLLATE "C" '
            'ORDER BY actor_uri COLLATE "C" LIMIT %s',
            (group,after or "",limit+1)
        ).fetchall()
        more=len(members)>limit
        rows=members[:limit]
        return {
            "revision":row[0],
            "members":[{"actorUri":u,"role":r} for u,r in rows],
            "hasMore":more,
            "nextCursor":rows[-1][0] if more else None
        }
