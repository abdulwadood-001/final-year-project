"""
HoneyBot-IoT — tests for the final scope-closure features:
Slack alerts (M6), per-session PCAP recording (M3), GreyNoise reputation (M4).
Pure-unit; no PostgreSQL or network.
"""
import os
import struct
import tempfile

import pytest


# ── M6: Slack webhook ───────────────────────────────────────────────────────
def test_slack_disabled_without_url(monkeypatch):
    from alerts import notifier
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    status, _ = notifier.send_slack(
        {"ip": "1.2.3.4", "attack_type": "BRUTE_FORCE", "severity": "HIGH", "details": "x",
         "device": "smartlock", "protocol": "SSH", "mitre": ["T1110"], "timestamp": "now"}, "")
    assert status == "disabled"


def test_slack_payload_is_valid_block_kit(monkeypatch):
    # capture the request instead of sending it
    from alerts import notifier
    import urllib.request
    import json
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    captured = {}

    class _Resp:
        status = 200
        def read(self): return b"ok"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=0):
        captured["body"] = json.loads(req.data.decode())
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    status, err = notifier.send_slack(
        {"ip": "203.0.113.9", "attack_type": "MALWARE_DELIVERY", "severity": "CRITICAL",
         "details": "dropper", "device": "smartlock", "protocol": "SSH", "mitre": ["T1105"],
         "timestamp": "now"}, "Lahore, PK")
    assert status == "sent" and err is None
    body = captured["body"]
    assert body["attachments"][0]["blocks"][0]["type"] == "header"
    assert "MALWARE_DELIVERY" in json.dumps(body)


# ── M3: PCAP recording ──────────────────────────────────────────────────────
@pytest.fixture()
def pcap_mod(monkeypatch):
    monkeypatch.setenv("PCAP_ENABLED", "1")
    d = tempfile.mkdtemp(prefix="hb-pcap-test-")
    monkeypatch.setenv("PCAP_DIR", d)
    import importlib
    from common import pcap as pcap_mod
    importlib.reload(pcap_mod)
    return pcap_mod, d


def test_pcap_is_valid_libpcap_and_reassembles(pcap_mod):
    pcap, d = pcap_mod
    tap = pcap.PcapTap("33333333-3333-3333-3333-333333333333", "203.0.113.7", 55000, 2323)
    tap.inbound(b"root\r\n")
    tap.outbound(b"Password: ")
    tap.inbound(b"xc3511\r\n")
    path = tap.flush()
    assert path and os.path.isfile(path)
    with open(path, "rb") as f:
        magic = struct.unpack("!I", f.read(4))[0]
    assert magic == 0xA1B2C3D4                       # big-endian libpcap
    scapy = pytest.importorskip("scapy.all")
    pkts = scapy.rdpcap(path)
    assert len(pkts) >= 6                              # handshake + data + teardown
    cli = b"".join(bytes(p[scapy.TCP].payload) for p in pkts
                   if scapy.TCP in p and p[scapy.TCP].dport == 2323)
    assert b"xc3511" in cli                            # attacker input is in the capture
    # IP checksums must be valid (Wireshark-openable)
    bad = 0
    for p in pkts:
        if scapy.IP in p:
            stored = p[scapy.IP].chksum
            p[scapy.IP].chksum = None
            if scapy.IP(bytes(p[scapy.IP])).chksum != stored:
                bad += 1
    assert bad == 0


def test_pcap_disabled_writes_nothing(monkeypatch):
    monkeypatch.setenv("PCAP_ENABLED", "0")
    import importlib
    from common import pcap as pcap_mod
    importlib.reload(pcap_mod)
    tap = pcap_mod.PcapTap("x", "1.2.3.4", 1, 2)
    tap.inbound(b"data")
    assert tap.flush() is None


def test_recording_socket_taps_both_directions(pcap_mod):
    pcap, _ = pcap_mod

    class FakeSock:
        def __init__(self): self.sent = b""
        def recv(self, n): return b"inbound-bytes"
        def sendall(self, d): self.sent += d
        def close(self): pass

    tap = pcap.PcapTap("44444444-4444-4444-4444-444444444444", "1.2.3.4", 5, 502)
    rs = pcap.RecordingSocket(FakeSock(), tap)
    assert rs.recv(100) == b"inbound-bytes"
    rs.sendall(b"outbound-bytes")
    dirs = [fc for _ts, fc, _d in tap.frames]
    assert True in dirs and False in dirs             # both directions recorded


# ── M4: GreyNoise reputation ─────────────────────────────────────────────────
def test_reputation_disabled_without_key(monkeypatch):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    import importlib
    from intel import reputation
    importlib.reload(reputation)
    assert reputation.lookup("8.8.8.8") == {"reputation_source": "disabled"}


def test_reputation_never_queries_private_ips(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "dummy")
    import importlib, urllib.request
    from intel import reputation
    importlib.reload(reputation)

    def boom(*a, **k):
        raise AssertionError("must not contact GreyNoise for a private IP")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    out = reputation.lookup("192.168.1.50")
    assert out["reputation_source"] == "disabled" and out["reputation"] == "benign"


# ── M8-FE-4: predictive forecast (trend fallback, no TensorFlow needed) ──────
def test_forecast_trend_rises_with_escalation():
    from ml import forecast
    quiet = [{f: 0 for f in forecast.FEATS} for _ in range(forecast.WINDOW)]
    esc = [{f: 0 for f in forecast.FEATS} for _ in range(forecast.WINDOW)]
    for i, r in enumerate(esc):
        r["events"] = i * 2
        r["downloads"] = max(0, i - 18)
        r["det_weight"] = max(0, i - 16) * 6
        r["commands"] = i
    rq, _ = forecast._trend_forecast(quiet)
    re_, factors = forecast._trend_forecast(esc)
    assert re_ > rq and re_ > 40
    assert any("rise" in f or "download" in f for f in factors)


def test_forecast_from_series_without_model_uses_trend(monkeypatch):
    from ml import forecast
    monkeypatch.setattr(forecast, "_load", lambda: None)
    series = [{f: 1 for f in forecast.FEATS} for _ in range(forecast.WINDOW)]
    out = forecast.forecast_from_series("sensor", series)
    assert out["model"] == "trend" and 0 <= out["risk"] <= 100
    assert out["horizon_hours"] == 24 and isinstance(out["factors"], list)


# ── live network-flow IDS (ml/flow.py) ───────────────────────────────────────
def test_flow_reads_honeypot_pcap_and_builds_windows(pcap_mod):
    pcap, _ = pcap_mod
    from ml import flow
    tap = pcap.PcapTap("55555555-5555-5555-5555-555555555555", "203.0.113.9", 40000, 1502)
    tap.inbound(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x07")
    tap.outbound(b"\x00\x01\x00\x00\x00\x11\x01\x03\x0e" + b"\x00" * 14)
    path = tap.flush()
    pkts = list(flow.read_pcap(path))
    assert len(pkts) >= 6 and all(p["proto"] == "tcp" for p in pkts)
    syns = [p for p in pkts if p["flags"] & 0x02 and not p["flags"] & 0x10]
    assert len(syns) == 1 and syns[0]["dport"] == 1502
    wins = flow.windows_for(pkts)
    assert wins and len(wins[0][1]) == len(flow.FLOW_FEATURES)


def test_empty_connection_still_recorded(pcap_mod):
    pcap, _ = pcap_mod
    tap = pcap.PcapTap("66666666-6666-6666-6666-666666666666", "203.0.113.9", 40001, 2222)
    assert tap.flush() is not None              # scans/floods are mostly empty connections


def test_flow_model_flags_connection_flood():
    import os
    from ml import flow
    if not os.path.exists(flow.MODEL_PATH):
        import pytest
        pytest.skip("flow model not present")
    __import__("pytest").importorskip("xgboost")
    t, pkts = 1000.0, []
    for i in range(300):                         # 300 connections inside one second
        sp = 30000 + i
        for flags, frm in ((0x02, True), (0x12, False), (0x10, True), (0x11, True), (0x11, False)):
            pkts.append({"ts": t + i / 400, "length": 54, "proto": "tcp", "flags": flags,
                         "src": "203.0.113.9" if frm else "172.31.66.10",
                         "dst": "172.31.66.10" if frm else "203.0.113.9",
                         "sport": sp if frm else 1502, "dport": 1502 if frm else sp})
    wins = flow.windows_for(pkts)
    preds = flow.predict([w for _t, w in wins])
    assert any(p["label"] == "TCP_BURST" for p in preds)


# ── RTSP real video (RFC 6184 packetisation) ─────────────────────────────────
def test_rtsp_media_and_fua_packetisation():
    import rtsp_honeypot.rtsp_honeypot as r
    aus, sps, pps = r.load_media()
    assert len(aus) > 10 and sps and pps and sps[0] & 0x1F == 7
    big = bytes([0x65]) + b"\xab" * 4000          # IDR slice larger than the MTU
    pkts, nxt = r.rtp_packets(big, 100, 9000, 0x1234, True)
    assert len(pkts) > 1 and nxt == 100 + len(pkts)
    assert pkts[0][12] & 0x1F == 28 and pkts[0][13] & 0x80          # FU-A, start bit
    assert pkts[-1][13] & 0x40 and pkts[-1][1] & 0x80                # end bit + RTP marker
    monkey = (r.SPS, r.PPS)
    r.SPS, r.PPS = sps, pps
    try:
        sdp = r.build_sdp()
    finally:
        r.SPS, r.PPS = monkey
    assert "sprop-parameter-sets=Z" in sdp and "packetization-mode=1" in sdp
