"""
HoneyBot-IoT — API smoke tests (need a running Postgres via DATABASE_URL).
Skipped automatically if the database is not reachable, so `pytest -q` still
passes on a machine without the stack up.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest

db_ok = True
try:
    from common.db import fetchall
    fetchall("SELECT 1")
except Exception:
    db_ok = False

pytestmark = pytest.mark.skipif(not db_ok, reason="no database (set DATABASE_URL and load init.sql)")


@pytest.fixture(scope="module")
def client():
    try:
        from fastapi.testclient import TestClient
        from api.api import app
        return TestClient(app)
    except TypeError as e:
        pytest.skip(f"starlette/httpx version mismatch in this env: {e}")


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_stats_shape(client):
    d = client.get("/api/stats").json()
    for key in ("sessions", "total_events", "unique_ips", "detections"):
        assert key in d
    assert set(["SSH", "Telnet", "HTTP", "MQTT", "RTSP"]).issubset(d["sessions"].keys())


@pytest.mark.parametrize("path", ["/api/attacks/recent", "/api/detections", "/api/sessions",
                                  "/api/map", "/api/mitre/summary", "/api/iocs", "/api/devices",
                                  "/api/credentials/top", "/api/alerts"])
def test_endpoints_return_json(client, path):
    r = client.get(path)
    assert r.status_code == 200


def test_search_requires_query(client):
    assert client.get("/api/search").status_code == 422
    assert client.get("/api/search?q=ab").status_code == 200
