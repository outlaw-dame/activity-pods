#!/usr/bin/env python3
"""Disposable PostgreSQL comparison for same Group CAS correctness workload.

This is a *candidate* relational design, not ActivityPods production backend.
The owner/consent/Group epoch checks execute under one SQL transaction, as
with the authoritative TDB2 settings write. No Solid HTTP or remote delivery.
"""

import concurrent.futures
import hashlib
import json
import os
import statistics
import time
import uuid
from urllib.parse import urlparse

import psycopg

if os.environ.get("G2_BENCH_DISPOSABLE") != "confirmed":
    raise SystemExit("G2_BENCH_DISPOSABLE=confirmed required")
dsn = os.environ.get("G2_POSTGRES_DSN", "")
parsed = urlparse(dsn)
if parsed.scheme not in ("postgres", "postgresql") or parsed.hostname not in (
    "127.0.0.1", "localhost"
):
    raise SystemExit("Refusing non-local PostgreSQL target")
count = int(os.environ.get("G2_WRITE_OPS_PER_WRITER", "24"))
if not 4 <= count <= 48:
    raise SystemExit("Only 4-48 writes per worker are supported")

owner = "https://paper-benchmark.example/users/owner"
app = "https://paper-benchmark.example/app"

def connect():
    return psycopg.connect(dsn, connect_timeout=10, autocommit=False)

def setup():
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public'")
            if cur.fetchone()[0] != 0:
                raise RuntimeError("Database must be disposable and empty")
            cur.execute("""
                CREATE TABLE owner_account (
                    webid text PRIMARY KEY, active boolean NOT NULL
                );
                CREATE TABLE consent_ledger (
                    owner text NOT NULL REFERENCES owner_account(webid),
                    app text NOT NULL, status text NOT NULL,
                    pending boolean NOT NULL, revision bigint NOT NULL,
                    PRIMARY KEY(owner,app)
                );
                CREATE TABLE grp (
                    id text PRIMARY KEY, owner text NOT NULL REFERENCES owner_account(webid),
                    app text NOT NULL, epoch bigint NOT NULL CHECK (epoch >= 1),
                    indexed_epoch bigint, delta_count integer NOT NULL DEFAULT 0,
                    CHECK (delta_count BETWEEN 0 AND 512)
                );
                CREATE TABLE member (
                    group_id text NOT NULL REFERENCES grp(id),
                    actor text NOT NULL, role text NOT NULL, status text NOT NULL,
                    receipt uuid NOT NULL,
                    PRIMARY KEY(group_id,actor)
                );
                CREATE TABLE changed_member (
                    group_id text NOT NULL REFERENCES grp(id),
                    actor text NOT NULL,
                    PRIMARY KEY(group_id,actor)
                );
            """)
            cur.execute("INSERT INTO owner_account VALUES (%s,true)", (owner,))
            cur.execute(
                "INSERT INTO consent_ledger VALUES (%s,%s,'stable',false,1)",
                (owner,app)
            )

def group_id(mode,writers,worker):
    key = json.dumps([mode,writers,worker], separators=(",",":"))
    return "cg_"+hashlib.sha256(key.encode()).hexdigest()[:32]

def prepare(groups,indexed):
    with connect() as conn:
        with conn.cursor() as cur:
            for group in groups:
                cur.execute(
                    "INSERT INTO grp(id,owner,app,epoch,indexed_epoch,delta_count) "
                    "VALUES (%s,%s,%s,1,%s,0)",
                    (group,owner,app,1 if indexed else None)
                )
                cur.execute(
                    "INSERT INTO member VALUES (%s,%s,'owner','active',%s)",
                    (group,owner,str(uuid.uuid4()))
                )

def percentile(samples,fraction):
    sorted_values=sorted(samples)
    return round(sorted_values[max(0,int((len(samples)*fraction+0.999999))-1)],2)

def worker(group,indexed):
    durations=[]
    with connect() as conn:
        for i in range(count):
            member_uri = "https://remote.example/users/"+group[-12:]+"-"+str(i)
            started=time.perf_counter()
            # A single transaction includes live account, consent, Group CAS,
            # membership write and optionally Group-local unique delta count.
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT g.epoch,g.delta_count
                        FROM grp g
                        JOIN owner_account a ON a.webid=g.owner AND a.active
                        JOIN consent_ledger c ON c.owner=g.owner AND c.app=g.app
                          AND c.status='stable' AND NOT c.pending
                        WHERE g.id=%s AND g.owner=%s AND g.app=%s
                        FOR UPDATE OF g
                    """, (group,owner,app))
                    row=cur.fetchone()
                    if row is None or row[0] != i+1:
                        raise RuntimeError("Unauthorized or stale Group CAS")
                    cur.execute("""
                        INSERT INTO member(group_id,actor,role,status,receipt)
                        VALUES (%s,%s,'member','active',%s)
                        ON CONFLICT (group_id,actor)
                        DO UPDATE SET role=EXCLUDED.role,
                                      status=EXCLUDED.status,
                                      receipt=EXCLUDED.receipt
                    """,(group,member_uri,str(uuid.uuid4())))
                    next_count = row[1]
                    if indexed:
                        cur.execute("""
                            INSERT INTO changed_member(group_id,actor)
                            VALUES (%s,%s) ON CONFLICT DO NOTHING
                            RETURNING actor
                        """,(group,member_uri))
                        next_count += int(cur.fetchone() is not None)
                    if next_count>512: raise RuntimeError("Delta overflow")
                    cur.execute(
                        "UPDATE grp SET epoch=epoch+1,delta_count=%s WHERE id=%s",
                        (next_count,group)
                    )
            durations.append((time.perf_counter()-started)*1000)
    return durations

def run_one(mode,writers):
    indexed = mode=="indexed"
    groups=[group_id(mode,writers,i) for i in range(writers)]
    prepare(groups,indexed)
    started=time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=writers) as executor:
        work=list(executor.map(lambda group: worker(group,indexed),groups))
    wall_ms=(time.perf_counter()-started)*1000
    samples=[x for group in work for x in group]
    with connect() as conn:
        with conn.cursor() as cur:
            for group in groups:
                cur.execute("SELECT epoch,delta_count FROM grp WHERE id=%s",(group,))
                assert cur.fetchone() == (count+1,count if indexed else 0)
                cur.execute("SELECT count(*) FROM member WHERE group_id=%s",(group,))
                assert cur.fetchone()[0]==count+1
                if indexed:
                    cur.execute(
                        "SELECT count(*) FROM changed_member WHERE group_id=%s",(group,))
                    assert cur.fetchone()[0]==count
    return {
        "proof":"g2-postgres-candidate-writer-contention",
        "ok":True,"mode":mode,"concurrentGroupWriters":writers,
        "mutations":writers*count,
        "wallMs":round(wall_ms,2),
        "mutationsPerSecond":round(writers*count*1000/wall_ms,2),
        "latencyP50Ms":percentile(samples,0.5),
        "latencyP95Ms":percentile(samples,0.95),
        "latencyP99Ms":percentile(samples,0.99),
        "maxMs":round(max(samples),2)
    }

def main():
    setup()
    results=[]
    for writers in (1,4,16):
        for mode in ("legacy","indexed"):
            result=run_one(mode,writers)
            print(json.dumps(result,sort_keys=True),flush=True)
            results.append(result)
    print(json.dumps({
        "proof":"g2-postgres-candidate-writer-contention-summary",
        "ok":True,"operationsPerWriter":count,
        "results":results,
        "limitations":"Synthetic candidate schema, no Solid/SAI service, no Pods, no federation"
    },sort_keys=True),flush=True)

if __name__=="__main__":
    main()
