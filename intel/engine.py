"""
HoneyBot-IoT — Threat Intelligence Engine worker  (replaces attack_detector.py)

Every INTEL_INTERVAL seconds:
  1. YARA-scan newly captured malware samples              (intel/yara_scan.py)
  2. run all detection rules on the unified event store   (intel/rules.py)
  3. store new detections with MITRE ATT&CK technique IDs (intel/mitre.py)
     and push them on Redis `honeybot:detections` (dashboard WebSocket)
  4. correlate attackers, GeoIP, campaigns, IOCs          (intel/correlate.py)
  5. send alerts for new detections (threshold + dedupe)  (alerts/notifier.py)
  6. once a day: e-mail the daily threat summary report    (intel/report.py)
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.db import fetchdicts
from common.state import start_heartbeat, redis_client
from common.schema import ensure_schema
from intel import rules, correlate, mitre, yara_scan
from alerts import notifier

INTERVAL = int(os.environ.get("INTEL_INTERVAL", 30))
BUCKET_MIN = int(os.environ.get("DETECTION_BUCKET_MIN", 60))

logging.basicConfig(level=logging.INFO, format="%(asctime)s | intel | %(message)s")
log = logging.getLogger("intel")


def _bucket():
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%d") + f"-{(now.hour * 60 + now.minute) // BUCKET_MIN}"


def store(dets):
    """Insert detections; return the ones that are NEW (not deduped)."""
    new = []
    bucket = _bucket()
    seen = set()
    for d in dets:
        key = f"{d['ip']}|{d['attack_type']}|{d.get('protocol') or '-'}|{d.get('session_id') or '-'}|{bucket}"
        if d["attack_type"] in ("BRUTE_FORCE", "RECONNAISSANCE", "WEB_SCAN", "MULTI_PROTOCOL_ATTACK",
                                "CREDENTIAL_STUFFING", "BOTNET_C2", "PROTOCOL_EXPLOIT", "RTSP_ROUTE_ENUM",
                                "CREDENTIAL_COMPROMISE", "ICS_PROCESS_MONITORING"):
            key = f"{d['ip']}|{d['attack_type']}|{d.get('protocol') or '-'}|{d.get('device') or '-'}|{bucket}"
        if key in seen:
            continue
        seen.add(key)
        ids, names = mitre.techniques_for(d["attack_type"])
        rows = fetchdicts("""
            INSERT INTO detections (ip, attack_type, severity, protocol, device, details, mitre, mitre_names,
                                    session_id, dedupe_key)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (dedupe_key) DO UPDATE
               SET details = EXCLUDED.details,
                   severity = CASE WHEN array_position(ARRAY['LOW','MEDIUM','HIGH','CRITICAL'], EXCLUDED.severity)
                                  > array_position(ARRAY['LOW','MEDIUM','HIGH','CRITICAL'], detections.severity)
                                  THEN EXCLUDED.severity ELSE detections.severity END
            RETURNING id, timestamp, (xmax = 0) AS inserted, severity
        """, (d["ip"], d["attack_type"], d["severity"], d.get("protocol"), d.get("device"), d["details"],
              ids, names, d.get("session_id"), key))
        if rows and rows[0]["inserted"]:
            new.append({**d, "id": rows[0]["id"], "timestamp": rows[0]["timestamp"],
                        "mitre": ids, "mitre_names": names})
    return new


def publish(new):
    """Push new detections to the dashboard (FastAPI WebSocket relays this channel)."""
    r = redis_client()
    if not r:
        return
    for d in new:
        try:
            r.publish("honeybot:detections", json.dumps({
                "id": d["id"], "timestamp": d["timestamp"], "ip": d["ip"], "attack_type": d["attack_type"],
                "severity": d["severity"], "protocol": d.get("protocol"), "device": d.get("device"),
                "details": d["details"], "mitre": d["mitre"], "mitre_names": d["mitre_names"],
                "session_id": d.get("session_id")}, default=str))
        except Exception:
            pass


def run_once():
    t0 = time.time()
    scanned = 0
    try:
        scanned = yara_scan.scan_pending()
    except Exception as e:
        log.error("YARA scan failed: %s", e)
    dets = rules.run_rules()
    new = store(dets)
    publish(new)
    try:
        correlate.run()
    except Exception as e:
        log.error("correlation failed: %s", e)
    sent = 0
    if new:
        try:
            sent = notifier.notify(new)
        except Exception as e:
            log.error("notifier failed: %s", e)
    for d in new:
        log.info("DETECTION %-8s %-24s %-15s %s", d["severity"], d["attack_type"], d["ip"], d["details"][:90])
    try:
        from intel import report
        report.maybe_send_daily()
    except Exception as e:
        log.error("daily report failed: %s", e)
    log.info("pass: %d samples scanned, %d matches, %d new detections, %d alerts, %.2fs",
             scanned, len(dets), len(new), sent, time.time() - t0)
    return {"samples_scanned": scanned, "matches": len(dets), "new_detections": len(new), "alerts_sent": sent}


def main():
    ensure_schema()
    start_heartbeat("intel", interval=10)
    log.info("Threat intelligence engine started (every %ds)", INTERVAL)
    while True:
        try:
            run_once()
        except Exception as e:
            log.error("engine pass failed: %s", e)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
