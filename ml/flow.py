"""
HoneyBot-IoT — live network-flow IDS (Module 8, complementary to the session model).

The flow classifier (ml/iot_flow/, trained on the real IoT-IDS Lab dataset) works on
26 features computed over 1-second windows of packets. This module computes exactly
those features from the honeypot's OWN per-session PCAPs (common/pcap.py), so the
model runs on live attacker traffic, not just on the offline dataset:

    intel engine (every pass) ── score_pending() ──► read new PCAPs (pcap_files)
        → group packets per attacker IP into 1-s windows → 26 features per window
        → ml_api POST /flow (XGBoost) → FLOW_PORT_SCAN / FLOW_FLOOD detections

Parsing is dependency-free (libpcap, Ethernet/IPv4, TCP/UDP/ICMP) and read-only.
"""

import os
import json
import math
import struct
import logging
import urllib.request

log = logging.getLogger("ml.flow")

FLOW_FEATURES = ["n_pkts", "n_bytes", "len_mean", "len_std", "len_max", "n_small", "n_tcp", "n_udp",
                 "n_icmp", "n_other", "n_syn", "n_synack", "n_rst", "n_fin", "n_ackonly", "n_psh",
                 "rst_per_syn", "syn_without_synack", "u_syn_dport", "u_syn_sport", "u_syn_pairs",
                 "u_tuples", "u_udp_dport", "iat_mean", "iat_std", "iat_min"]
FLOW_CLASSES = ["BENIGN", "PORT_SCAN", "TCP_BURST", "UDP_BURST"]
MODEL_PATH = os.environ.get("FLOW_MODEL_PATH", os.path.join(os.path.dirname(__file__), "iot_flow",
                                                             "iot_flow_classifier.json"))
ML_API_URL = os.environ.get("ML_API_URL", "http://ml_api:5001")
WINDOW_S = 1.0
MIN_CONF = float(os.environ.get("FLOW_MIN_CONFIDENCE", 0.8))


# ── libpcap reader ───────────────────────────────────────────────────────────
def read_pcap(path):
    """Yield dicts (ts, src, dst, sport, dport, proto, length, flags) for each IPv4 packet."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[:4])[0]
        if magic == 0xA1B2C3D4:
            end = "<"
        elif magic == 0xD4C3B2A1:
            end = ">"
        else:
            return
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            sec, usec, incl, orig = struct.unpack(end + "IIII", rh)
            pkt = f.read(incl)
            if len(pkt) < incl:
                return
            off = 14 if linktype == 1 else 0
            if linktype == 1 and pkt[12:14] != b"\x08\x00":
                yield {"ts": sec + usec / 1e6, "proto": "other", "length": orig, "flags": 0,
                       "src": None, "dst": None, "sport": None, "dport": None}
                continue
            ip = pkt[off:]
            if len(ip) < 20 or ip[0] >> 4 != 4:
                continue
            ihl = (ip[0] & 0x0F) * 4
            pnum = ip[9]
            src, dst = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20]))
            l4 = ip[ihl:]
            rec = {"ts": sec + usec / 1e6, "length": orig, "src": src, "dst": dst,
                   "sport": None, "dport": None, "flags": 0}
            if pnum == 6 and len(l4) >= 14:
                rec.update(proto="tcp", sport=struct.unpack("!H", l4[0:2])[0],
                           dport=struct.unpack("!H", l4[2:4])[0], flags=l4[13])
            elif pnum == 17 and len(l4) >= 4:
                rec.update(proto="udp", sport=struct.unpack("!H", l4[0:2])[0],
                           dport=struct.unpack("!H", l4[2:4])[0])
            elif pnum == 1:
                rec.update(proto="icmp")
            else:
                rec.update(proto="other")
            yield rec


# ── window features (same definitions as the IoT-IDS Lab data dictionary) ───
def window_features(pkts):
    n = len(pkts)
    lens = [p["length"] for p in pkts]
    mean = sum(lens) / n
    std = math.sqrt(sum((x - mean) ** 2 for x in lens) / n)
    tcp = [p for p in pkts if p["proto"] == "tcp"]
    syn = [p for p in tcp if p["flags"] & 0x02 and not p["flags"] & 0x10]
    synack = [p for p in tcp if p["flags"] & 0x12 == 0x12]
    rst = [p for p in tcp if p["flags"] & 0x04]
    ts = sorted(p["ts"] for p in pkts)
    iats = [b - a for a, b in zip(ts, ts[1:])]
    iat_mean = sum(iats) / len(iats) if iats else 0.0
    iat_std = math.sqrt(sum((x - iat_mean) ** 2 for x in iats) / len(iats)) if iats else 0.0
    f = {
        "n_pkts": n, "n_bytes": float(sum(lens)), "len_mean": mean, "len_std": std,
        "len_max": float(max(lens)), "n_small": sum(1 for x in lens if x <= 66),
        "n_tcp": len(tcp), "n_udp": sum(1 for p in pkts if p["proto"] == "udp"),
        "n_icmp": sum(1 for p in pkts if p["proto"] == "icmp"),
        "n_other": sum(1 for p in pkts if p["proto"] == "other"),
        "n_syn": len(syn), "n_synack": len(synack), "n_rst": len(rst),
        "n_fin": sum(1 for p in tcp if p["flags"] & 0x01),
        "n_ackonly": sum(1 for p in tcp if p["flags"] == 0x10),
        "n_psh": sum(1 for p in tcp if p["flags"] & 0x08),
        "rst_per_syn": (len(rst) / len(syn)) if syn else 0.0,
        "syn_without_synack": max(0, len(syn) - len(synack)),
        "u_syn_dport": len({p["dport"] for p in syn}), "u_syn_sport": len({p["sport"] for p in syn}),
        "u_syn_pairs": len({(p["src"], p["dst"]) for p in syn}),
        "u_tuples": len({(p["proto"], p["src"], p["sport"], p["dst"], p["dport"]) for p in pkts
                         if p["proto"] in ("tcp", "udp")}),
        "u_udp_dport": len({p["dport"] for p in pkts if p["proto"] == "udp"}),
        "iat_mean": iat_mean, "iat_std": iat_std, "iat_min": min(iats) if iats else 0.0,
    }
    return [float(f[k]) for k in FLOW_FEATURES]


def windows_for(packets, size=WINDOW_S):
    """Group packets into non-overlapping windows; return [(t_start, [features])]."""
    if not packets:
        return []
    packets = sorted(packets, key=lambda p: p["ts"])
    t0, out, cur, start = packets[0]["ts"], [], [], None
    for p in packets:
        idx = int((p["ts"] - t0) // size)
        if start is None:
            start = idx
        if idx != start:
            out.append((t0 + start * size, window_features(cur)))
            cur, start = [], idx
        cur.append(p)
    if cur:
        out.append((t0 + start * size, window_features(cur)))
    return out


# ── model (served by ml_api) ─────────────────────────────────────────────────
_model = None


def predict(windows):
    """windows: list of 26-float vectors -> list of {label, confidence}. Runs inside ml_api."""
    global _model
    if _model is None:
        import xgboost as xgb
        if not os.path.exists(MODEL_PATH):
            return [{"label": "BENIGN", "confidence": 0.0, "model": "untrained"} for _ in windows]
        _model = xgb.XGBClassifier()
        _model.load_model(MODEL_PATH)
    import numpy as np
    if not windows:
        return []
    proba = _model.predict_proba(np.array(windows, dtype="float32"))
    return [{"label": FLOW_CLASSES[int(p.argmax())], "confidence": round(float(p.max()), 4)} for p in proba]


# ── live scoring, run by the intel engine ───────────────────────────────────
def _post(path, payload, timeout=20):
    req = urllib.request.Request(ML_API_URL.rstrip("/") + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def score_pending(limit=200):
    """Score PCAPs not yet flow-scored. Returns detection dicts for the engine to store."""
    from common.db import fetchall, execute
    rows = fetchall("""
        SELECT session_id::text, ip, device, storage_path FROM pcap_files
        WHERE NOT COALESCE(flow_scored, FALSE) ORDER BY captured_at LIMIT %s""", (limit,))
    if not rows:
        return []
    by_ip = {}
    for sid, ip, dev, path in rows:
        pk = []
        try:
            if path and os.path.isfile(path):
                pk = list(read_pcap(path))
        except Exception as e:
            log.debug("pcap %s unreadable: %s", path, e)
        by_ip.setdefault(ip, {"pkts": [], "dev": dev, "sids": []})
        by_ip[ip]["pkts"] += pk
        by_ip[ip]["sids"].append(sid)
    dets = []
    for ip, d in by_ip.items():
        wins = windows_for(d["pkts"])
        if not wins:
            continue
        try:
            preds = _post("/flow", {"windows": [w for _t, w in wins]}).get("predictions", [])
        except Exception as e:
            log.info("flow scoring skipped (ml_api unavailable: %s)", e)
            return []
        hits = {}
        for (t, _w), p in zip(wins, preds):
            execute("""INSERT INTO flow_detections (ip, device, window_start, label, confidence)
                       VALUES (%s,%s,to_timestamp(%s),%s,%s)""", (ip, d["dev"], t, p["label"], p["confidence"]))
            if p["label"] != "BENIGN" and p["confidence"] >= MIN_CONF:
                hits[p["label"]] = hits.get(p["label"], 0) + 1
        for label, n in hits.items():
            atype = "FLOW_PORT_SCAN" if label == "PORT_SCAN" else "FLOW_FLOOD"
            dets.append({"ip": ip, "attack_type": atype,
                         "severity": "MEDIUM" if atype == "FLOW_PORT_SCAN" else "HIGH",
                         "details": f"network-flow IDS: {n} window(s) classified {label}",
                         "protocol": "NET", "device": d["dev"], "session_id": None})
    for sid, *_ in rows:
        execute("UPDATE pcap_files SET flow_scored = TRUE WHERE session_id = %s", (sid,))
    return dets
