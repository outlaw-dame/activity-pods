#!/usr/bin/env python3
"""Real PostgreSQL 18 integration proof for isolated Group-state prototype.

All operations are against a disposable localhost database. No live Pod
credentials, no real federation, and absolutely no runtime feature flag.
"""
import concurrent.futures
import os
import threading
import unittest
import uuid
from pathlib import Path

import psycopg
from psycopg import errors

from paper_groups_pg_candidate import (
    AuthorityDenied, StaleRevision, provision_owner, reserve_group,
    revoke_consent, disable_owner, mutate_member, list_members
)

DSN = os.environ.get("G2_POSTGRES_DSN","")
if (os.environ.get("G2_BENCH_DISPOSABLE") != "confirmed" or
        "127.0.0.1" not in DSN and "localhost" not in DSN):
    raise RuntimeError("Refusing non-disposable non-local PostgreSQL connection")

OWNER="https://paper-test.example/users/owner#me"
APP="https://paper-test.example/app"
def gid(n):
    return "cg_"+format(n,"032x")
def actor(n):
    return "https://remote-federated.example/users/"+str(n).zfill(6)

def connection():
    return psycopg.connect(DSN, autocommit=True, connect_timeout=5)

def mutate(conn,g,i,**extras):
    return mutate_member(conn,group=g,owner=OWNER,app=APP,member=actor(i),
        role=extras.get("role","member"),status=extras.get("status","active"),
        expected_revision=extras["revision"],operation_id=extras.get("op",str(uuid.uuid4())))

class CandidateIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin=connection()
        rows=cls.admin.execute(
            "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public'"
        ).fetchone()[0]
        assert rows==0, "Disposable database is not empty"
        sql=(Path(__file__).resolve().parent.parent / "sql" /
             "paper-groups-postgres-candidate-v1.sql").read_text()
        cls.admin.execute(sql)
        provision_owner(cls.admin, OWNER, APP)

    @classmethod
    def tearDownClass(cls):
        cls.admin.close()

    def test_01_revision_idempotency_owner_group_separation(self):
        g=gid(1)
        reserve_group(self.admin,g,OWNER,APP)
        op=str(uuid.uuid4())
        res=mutate(self.admin,g,1,revision=1,op=op)
        self.assertEqual(res,{"revision":2,"replay":False})
        self.assertEqual(mutate(self.admin,g,1,revision=1,op=op),
                         {"revision":2,"replay":True})
        with self.assertRaises(AuthorityDenied):
            mutate(self.admin,g,2,revision=2,op=op)
        with self.assertRaises(StaleRevision):
            mutate(self.admin,g,2,revision=1)
        with self.assertRaises(AuthorityDenied):
            mutate(self.admin,gid(2),2,revision=1)
        with self.assertRaises(ValueError):
            mutate_member(self.admin,group=g,owner=OWNER,app=APP,member=OWNER,
                          role="owner",status="active",expected_revision=2,
                          operation_id=str(uuid.uuid4()))
        q=self.admin.execute(
            "SELECT count(*) FROM paper_groups_candidate.transitions WHERE group_id=%s",
            (g,)
        ).fetchone()[0]
        self.assertEqual(q,1)
        self.assertEqual(list_members(self.admin,group=g,owner=OWNER,app=APP)["revision"],2)

    def test_02_bounded_keyset_reads_with_1000_members(self):
        g=gid(2)
        reserve_group(self.admin,g,OWNER,APP)
        # Seed realistic large-roster shape only in disposable PostgreSQL.
        # This deliberately bypasses admission because we're benchmarking a
        # B-tree read, not claiming production invitation/consent semantics.
        with self.admin.transaction():
            with self.admin.cursor() as cursor:
                cursor.executemany(
                    "INSERT INTO paper_groups_candidate.members "
                    "(group_id,actor_uri,role,status,change_revision) "
                    "VALUES (%s,%s,'member','active',2)",
                    [(g,actor(i)) for i in range(1000)]
                )
            self.admin.execute(
                "UPDATE paper_groups_candidate.groups SET revision=2 WHERE group_id=%s",
                (g,)
            )
        after=None
        seen=[]
        for _ in range(12):
            page=list_members(self.admin,group=g,owner=OWNER,app=APP,
                              after=after,limit=100)
            seen.extend(x["actorUri"] for x in page["members"])
            self.assertLessEqual(len(page["members"]),100)
            self.assertEqual(page["revision"],2)
            if not page["hasMore"]:
                break
            after=page["nextCursor"]
        self.assertEqual(len(seen),1001)
        self.assertEqual(len(set(seen)),1001)
        self.assertEqual(seen,sorted(seen))
        self.assertIn(OWNER,seen)
        self.assertNotIn("ORDER BY actor_uri OFFSET",
                         list_members.__code__.co_consts)

    def test_03_independent_groups_update_concurrently(self):
        groups=[gid(100+i) for i in range(8)]
        for g in groups: reserve_group(self.admin,g,OWNER,APP)
        def run(pair):
            idx,g=pair
            with connection() as conn:
                for i in range(12):
                    result=mutate_member(
                        conn,group=g,owner=OWNER,app=APP,
                        member=actor(idx*100+i),role="member",status="requested",
                        expected_revision=i+1,operation_id=str(uuid.uuid4())
                    )
                    assert result["revision"]==i+2
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(run,enumerate(groups)))
        for g in groups:
            rev=self.admin.execute(
                "SELECT revision FROM paper_groups_candidate.groups WHERE group_id=%s",
                (g,)
            ).fetchone()[0]
            self.assertEqual(rev,13)

    def test_03b_roster_snapshot_group_lock_blocks_concurrent_writer(self):
        g=gid(199)
        reserve_group(self.admin,g,OWNER,APP)
        acquired=threading.Event()
        allow_release=threading.Event()
        completed=threading.Event()
        failures=[]
        def reader_hold():
            with connection() as conn:
                with conn.transaction():
                    conn.execute(
                        "SELECT revision FROM paper_groups_candidate.groups "
                        "WHERE group_id=%s FOR SHARE",(g,)
                    )
                    acquired.set()
                    if not allow_release.wait(timeout=5):
                        failures.append("reader release timeout")
        def competing_writer():
            try:
                with connection() as conn:
                    mutate(conn,g,30,revision=1)
                completed.set()
            except BaseException as e:
                failures.append(str(e))
                completed.set()
        a=threading.Thread(target=reader_hold,daemon=True)
        a.start()
        self.assertTrue(acquired.wait(timeout=3))
        b=threading.Thread(target=competing_writer,daemon=True)
        b.start()
        self.assertFalse(completed.wait(timeout=0.15),
                         "Writer bypassed Group snapshot revision lock")
        allow_release.set()
        a.join(timeout=5)
        b.join(timeout=5)
        self.assertFalse(a.is_alive() or b.is_alive())
        self.assertEqual(failures,[])
        self.assertTrue(completed.is_set())
        page=list_members(self.admin,group=g,owner=OWNER,app=APP)
        self.assertEqual(page["revision"],2)
        self.assertIn(actor(30),[x["actorUri"] for x in page["members"]])

    def test_04_revoke_fences_new_mutations_and_private_reads(self):
        g=gid(201)
        reserve_group(self.admin,g,OWNER,APP)
        self.assertEqual(mutate(self.admin,g,1,revision=1)["revision"],2)
        self.assertEqual(revoke_consent(self.admin,OWNER,APP,1),2)
        with self.assertRaises(AuthorityDenied):
            mutate(self.admin,g,2,revision=2)
        with self.assertRaises(AuthorityDenied):
            list_members(self.admin,group=g,owner=OWNER,app=APP)
        self.assertEqual(self.admin.execute(
            "SELECT revision FROM paper_groups_candidate.groups WHERE group_id=%s",
            (g,)
        ).fetchone()[0],2)

    def test_05_replay_preexisting_in_flight_writer_before_revoke(self):
        # Separate, freshly provisioned owner so the earlier revocation
        # does not affect this test. A writer that holds the consent SHARE
        # lock must finish before revocation's exclusive row lock can commit.
        owner2="https://paper-test.example/users/second-owner#me"
        app2="https://paper-test.example/second-app"
        g=gid(202)
        provision_owner(self.admin,owner2,app2)
        reserve_group(self.admin,g,owner2,app2)
        ready=threading.Event()
        release=threading.Event()
        results=[]
        def writer():
            with connection() as conn:
                with conn.transaction():
                    conn.execute(
                        "SELECT granted FROM paper_groups_candidate.consent "
                        "WHERE owner_webid=%s AND app_uri=%s FOR SHARE",
                        (owner2,app2)
                    )
                    ready.set()
                    release.wait(timeout=3)
                results.append("writer_done")
        t=threading.Thread(target=writer,daemon=True)
        t.start()
        self.assertTrue(ready.wait(timeout=3))
        def revoker():
            with connection() as conn:
                revoke_consent(conn,owner2,app2,1)
                results.append("revoked")
        r=threading.Thread(target=revoker,daemon=True)
        r.start()
        self.assertFalse("revoked" in results)
        release.set()
        t.join(timeout=5)
        r.join(timeout=5)
        self.assertFalse(t.is_alive() or r.is_alive())
        self.assertEqual(results,["writer_done","revoked"])
        with connection() as conn:
            with self.assertRaises(AuthorityDenied):
                mutate_member(conn,group=g,owner=owner2,app=app2,
                    member=actor(40),role="member",status="active",
                    expected_revision=1,operation_id=str(uuid.uuid4()))

    def test_06_disabled_account_denies_all_group_writes(self):
        owner3="https://paper-test.example/users/disabled#me"
        app3="https://paper-test.example/third-app"
        g=gid(203)
        provision_owner(self.admin,owner3,app3)
        reserve_group(self.admin,g,owner3,app3)
        self.assertEqual(disable_owner(self.admin,owner3,1),2)
        with self.assertRaises(AuthorityDenied):
            mutate_member(self.admin,group=g,owner=owner3,app=app3,
                member=actor(41),role="member",status="active",
                expected_revision=1,operation_id=str(uuid.uuid4()))

if __name__=="__main__":
    unittest.main(verbosity=2)
