"""
HoneyBot-IoT — apply the (idempotent) PostgreSQL schema at start-up.

`init.sql` only runs automatically when the Postgres volume is created. Re-applying
it from the API / intel engine upgrades an existing database in place (new tables,
indexes and views), so moving from v0.6 to v0.7 needs no manual migration.
A Postgres advisory lock stops two services applying it at the same moment.
"""

import os
import logging

from common.db import get_pool, _getconn

log = logging.getLogger("schema")

SCHEMA_FILE = os.environ.get(
    "SCHEMA_FILE", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "init.sql"))
_LOCK_ID = 7_070_707


def ensure_schema(path=SCHEMA_FILE):
    if not os.path.exists(path):
        log.warning("schema file %s not found – skipping auto-migration", path)
        return False
    with open(path, encoding="utf-8") as f:
        sql = f.read()
    pool = get_pool()
    conn = _getconn(pool)
    try:
        with conn.cursor() as cur:
            # transaction-scoped lock: released automatically on commit OR rollback
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_ID,))
            cur.execute(sql)
        conn.commit()
        log.info("schema up to date (%s)", os.path.basename(path))
        return True
    except Exception as e:
        conn.rollback()
        log.error("schema apply failed: %s", e)
        return False
    finally:
        pool.putconn(conn)
