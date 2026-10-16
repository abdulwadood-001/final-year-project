"""Shared pytest set-up: loaded before any test module imports project code."""
import os
import tempfile

# fail fast (one attempt, no 2-s sleeps) when no PostgreSQL is running, so the
# DB-backed tests are skipped in seconds instead of hanging for minutes
os.environ.setdefault("DB_CONNECT_RETRIES", "1")
# captured malware samples go to a throw-away directory during tests
os.environ.setdefault("CAPTURE_DIR", tempfile.mkdtemp(prefix="hb-captures-"))
