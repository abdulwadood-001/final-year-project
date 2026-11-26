"""
HoneyBot-IoT — Module 8 model definitions and inference (scope M8-FE-1/FE-2/FE-4).

Shared between training (ml/train.py) and serving (ml/ml_api.py, the API):
  * FEATURES      the canonical, ordered feature vector the models expect
  * CLASSES       the six attack classes (scope M8-FE-1)
  * vectorize()   one session-feature dict  → ordered float vector
  * Predictor     loads the trained XGBoost classifier + Isolation Forest and
                  returns {class, confidence, probabilities, anomaly, risk}

Risk score (M8-FE-4) is a transparent 0-100 combination of the classifier's
confidence in a non-benign class and the anomaly score — not a black box, so it
can be justified in the report. (A deep LSTM forecaster is noted as future work
in docs/MODEL_CARD.md; this risk score is what the dashboard shows today.)
"""

import os
import json
import threading

# Canonical feature order — MUST match ml/features.py FEATURE_SQL output (minus meta/label).
FEATURES = [
    "duration_s", "events_total", "auth_attempts", "auth_success", "distinct_usernames",
    "distinct_passwords", "commands", "download_attempts", "exec_attempts", "file_events",
    "http_requests", "http_404", "mqtt_publishes", "mqtt_control", "mqtt_wildcard_subs",
    "rtsp_requests", "rtsp_route_probes", "malformed", "state_changes", "cmd_download",
    "cmd_chmod", "cmd_busybox", "cmd_tmp_paths", "cmd_discovery", "mean_cmd_len",
    "mean_gap_s", "std_gap_s", "ip_protocols_1h", "ip_sessions_1h",
]
CLASSES = ["brute_force", "malware_delivery", "botnet_c2", "port_scan", "protocol_exploit", "normal"]
BENIGN = "normal"

MODEL_DIR = os.environ.get("ML_MODEL_DIR", os.path.join(os.path.dirname(__file__), "artifacts"))
CLF_PATH = os.path.join(MODEL_DIR, "xgb_classifier.json")
IFOREST_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
META_PATH = os.path.join(MODEL_DIR, "model_meta.json")


def vectorize(feat):
    """session-feature dict (from ml.features) → ordered list[float] in FEATURES order."""
    out = []
    for name in FEATURES:
        v = feat.get(name, 0)
        try:
            out.append(float(v))
        except (TypeError, ValueError):
            out.append(0.0)
    return out


def risk_score(top_class, confidence, anomaly):
    """0-100 risk. Benign sessions stay low; a confident malicious class and/or a high
    anomaly score push it up. anomaly is already 0-1 (1 = most anomalous)."""
    if top_class == BENIGN:
        base = 12.0 * confidence
    else:
        sev = {"malware_delivery": 1.0, "botnet_c2": 0.95, "protocol_exploit": 0.8,
               "brute_force": 0.6, "port_scan": 0.45}.get(top_class, 0.6)
        base = 100.0 * sev * (0.5 + 0.5 * confidence)
    score = 0.7 * base + 0.3 * (100.0 * anomaly)
    return round(max(0.0, min(100.0, score)), 1)


class Predictor:
    """Lazy-loading singleton around the trained models. Thread-safe."""

    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.clf = None
        self.iforest = None
        self.meta = {}
        self._load()

    @classmethod
    def get(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance

    def available(self):
        return self.clf is not None

    def _load(self):
        try:
            import xgboost as xgb
            if os.path.exists(CLF_PATH):
                self.clf = xgb.XGBClassifier()
                self.clf.load_model(CLF_PATH)
            if os.path.exists(IFOREST_PATH):
                import joblib
                self.iforest = joblib.load(IFOREST_PATH)
            if os.path.exists(META_PATH):
                with open(META_PATH) as f:
                    self.meta = json.load(f)
        except Exception as e:  # models not trained yet / libs missing
            import logging
            logging.getLogger("ml").warning("model load failed: %s", e)

    def predict(self, feat):
        """feat: session-feature dict → prediction dict. Falls back to a benign,
        low-risk verdict when the models are not trained."""
        if not self.available():
            return {"class": BENIGN, "confidence": 0.0, "probabilities": {}, "anomaly": 0.0,
                    "risk": 0.0, "model": "untrained"}
        import numpy as np
        x = np.array([vectorize(feat)], dtype="float32")
        proba = self.clf.predict_proba(x)[0]
        classes = self.meta.get("classes", CLASSES)
        probs = {c: round(float(p), 4) for c, p in zip(classes, proba)}
        top_i = int(proba.argmax())
        top_class = classes[top_i]
        confidence = float(proba[top_i])
        anomaly = 0.0
        if self.iforest is not None:
            # decision_function: higher = more normal; map to 0-1 where 1 = anomalous
            raw = float(self.iforest.decision_function(x)[0])
            lo, hi = self.meta.get("iforest_range", [-0.2, 0.2])
            anomaly = max(0.0, min(1.0, (hi - raw) / (hi - lo) if hi > lo else 0.0))
        return {"class": top_class, "confidence": round(confidence, 4), "probabilities": probs,
                "anomaly": round(anomaly, 4), "risk": risk_score(top_class, confidence, anomaly),
                "model": self.meta.get("version", "xgboost")}
