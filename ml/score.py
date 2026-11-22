"""
HoneyBot-IoT — Module 8 session scoring, run by the intel engine each pass.

For every finished session that has not yet been classified, it builds the feature
vector, asks the ml_api microservice for a classification + anomaly + risk + threat
narrative, and stores the result in `ml_predictions` (indexed against the session,
scope M4 "Attack Classification Storage"). The dashboard then shows the AI class,
risk score and narrative per session and per device.

If ml_api is unreachable or no model is trained yet, scoring is skipped cleanly —
the honeypot and the rule engine keep working (the AI layer is additive).
"""

import os
import json
import logging
import urllib.request

from common.db import fetchdicts, fetchall, execute
from ml.features import build_dataset
from ml.model import FEATURES

log = logging.getLogger("ml.score")

ML_API_URL = os.environ.get("ML_API_URL", "http://ml_api:5001")
SCORE_LIMIT = int(os.environ.get("ML_SCORE_LIMIT", 200))
_warned = False


def _post(path, payload, timeout=20):
    req = urllib.request.Request(ML_API_URL.rstrip("/") + path,
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _ml_api_ready():
    try:
        with urllib.request.urlopen(ML_API_URL.rstrip("/") + "/health", timeout=5) as r:
            return json.loads(r.read()).get("model_loaded", False)
    except Exception:
        return False


def _detections_for(session_id, ip):
    rows = fetchall("""
        SELECT attack_type, severity, details FROM detections
        WHERE session_id = %s OR (session_id IS NULL AND ip = %s
              AND timestamp > NOW() - INTERVAL '2 hours')
        ORDER BY timestamp DESC LIMIT 8
    """, (session_id, ip))
    return [{"attack_type": a, "severity": s, "details": d} for a, s, d in rows]


def score_pending(limit=SCORE_LIMIT):
    """Classify + narrate finished, not-yet-scored sessions. Returns the number scored."""
    global _warned
    if not _ml_api_ready():
        if not _warned:
            log.info("ml_api not ready (no model or unreachable) — skipping AI scoring")
            _warned = True
        return 0
    _warned = False

    done = {r["session_id"] for r in fetchdicts(
        "SELECT session_id FROM ml_predictions ORDER BY predicted_at DESC LIMIT 20000")}
    rows = build_dataset(days=2, limit=limit * 4)
    pending = [r for r in rows if r["session_id"] not in done][:limit]
    if not pending:
        return 0

    scored = 0
    for r in pending:
        session = {k: r.get(k) for k in (FEATURES + ["ip", "device", "protocol"])}
        try:
            dets = _detections_for(r["session_id"], r.get("ip"))
            res = _post("/score_session", {"session": session, "detections": dets})
        except Exception as e:
            log.warning("scoring %s failed: %s", r["session_id"][:8], e)
            continue
        pred = res.get("prediction", {})
        execute("""
            INSERT INTO ml_predictions (session_id, ip, device, protocol, ml_class, confidence,
                                        anomaly, risk, probabilities, model_version, narrative)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
            ON CONFLICT (session_id) DO UPDATE SET
                ml_class=EXCLUDED.ml_class, confidence=EXCLUDED.confidence, anomaly=EXCLUDED.anomaly,
                risk=EXCLUDED.risk, probabilities=EXCLUDED.probabilities,
                model_version=EXCLUDED.model_version, narrative=EXCLUDED.narrative,
                predicted_at=NOW()
        """, (r["session_id"], r.get("ip"), r.get("device"), r.get("protocol"),
              pred.get("class"), pred.get("confidence"), pred.get("anomaly"), pred.get("risk"),
              json.dumps(pred.get("probabilities", {})), pred.get("model"), res.get("narrative")))
        scored += 1
    if scored:
        log.info("AI-scored %d session(s)", scored)
    return scored
