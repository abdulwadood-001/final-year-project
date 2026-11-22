"""
HoneyBot-IoT — Module 8 (AI) tests.

Pure-unit tests for the ML layer: feature vectorisation, the synthetic generator,
the classifier/anomaly/risk pipeline (trained on a small synthetic set in-test),
the weak-label mapping and the threat narrator. No PostgreSQL or ml_api needed.
"""
import os
import tempfile

import pytest

pytest.importorskip("numpy")
pytest.importorskip("sklearn")
xgboost = pytest.importorskip("xgboost")


def test_feature_order_matches_features_sql():
    # every model FEATURE must be a column produced by the feature SQL (no drift)
    from ml import model
    from ml.features import FEATURE_SQL
    for f in model.FEATURES:
        assert f in FEATURE_SQL, f


def test_vectorize_is_ordered_and_numeric():
    from ml.model import vectorize, FEATURES
    vec = vectorize({"auth_attempts": 5, "commands": "3", "unknown": 9})
    assert len(vec) == len(FEATURES)
    assert vec[FEATURES.index("auth_attempts")] == 5.0
    assert vec[FEATURES.index("commands")] == 3.0        # string coerced
    assert all(isinstance(v, float) for v in vec)


def test_risk_score_bounds_and_ordering():
    from ml.model import risk_score
    assert risk_score("normal", 0.9, 0.0) < 20
    assert risk_score("malware_delivery", 0.9, 0.5) > 70
    assert 0 <= risk_score("port_scan", 0.5, 1.0) <= 100
    # malware outranks a port scan at equal confidence/anomaly
    assert risk_score("malware_delivery", 0.8, 0.2) > risk_score("port_scan", 0.8, 0.2)


def test_synthetic_generator_shape_and_balance():
    from ml.synth import generate
    from ml.model import CLASSES, FEATURES
    rows, labels = generate(per_class=30, seed=1)
    assert len(rows) == len(labels) == 30 * len(CLASSES)
    for c in CLASSES:
        assert labels.count(c) == 30
    assert set(rows[0].keys()) == set(FEATURES)


def test_weak_label_mapping_covers_new_types():
    from ml.features import weak_label
    assert weak_label(["FALSE_DATA_INJECTION"]) == "botnet_c2"
    assert weak_label(["CREDENTIAL_DISCLOSURE"]) == "protocol_exploit"
    assert weak_label(["TOKEN_BRUTEFORCE"]) == "brute_force"
    assert weak_label(["ICS_DEVICE_SCAN"]) == "port_scan"
    assert weak_label([]) == "normal"
    # most-severe class wins when several apply
    assert weak_label(["RECONNAISSANCE", "MALWARE_DELIVERY"]) == "malware_delivery"


@pytest.fixture(scope="module")
def trained_model():
    """Train a small model into a temp dir and return a Predictor using it."""
    d = tempfile.mkdtemp(prefix="hb-ml-")
    os.environ["ML_MODEL_DIR"] = d
    import importlib
    from ml import model as model_mod
    importlib.reload(model_mod)            # pick up the temp ML_MODEL_DIR
    import ml.train as train
    importlib.reload(train)
    feats, labels = train.build_training_set(force_synth=120, synth_per_class=120)
    import numpy as np
    X = np.array([model_mod.vectorize(f) for f in feats], dtype="float32")
    y = np.array([model_mod.CLASSES.index(l) for l in labels])
    import xgboost as xgb
    clf = xgb.XGBClassifier(n_estimators=60, max_depth=4, num_class=len(model_mod.CLASSES),
                            eval_metric="mlogloss", verbosity=0)
    clf.fit(X, y)
    clf.save_model(model_mod.CLF_PATH)
    from sklearn.ensemble import IsolationForest
    import joblib
    iso = IsolationForest(n_estimators=80, random_state=0).fit(X)
    joblib.dump(iso, model_mod.IFOREST_PATH)
    import json
    with open(model_mod.META_PATH, "w") as f:
        json.dump({"version": "test", "classes": model_mod.CLASSES,
                   "iforest_range": [-0.2, 0.2]}, f)
    model_mod.Predictor._instance = None
    return model_mod.Predictor.get()


def test_classifier_predicts_expected_classes(trained_model):
    # a clearly brute-force feature vector
    brute = {"auth_attempts": 40, "distinct_passwords": 35, "distinct_usernames": 2,
             "events_total": 42, "commands": 0}
    out = trained_model.predict(brute)
    assert out["class"] in ("brute_force", "port_scan")   # credential-heavy classes
    assert 0.0 <= out["confidence"] <= 1.0
    assert set(out["probabilities"]) == set(trained_model.meta["classes"])
    assert 0 <= out["risk"] <= 100

    malware = {"commands": 10, "download_attempts": 3, "exec_attempts": 2, "cmd_download": 3,
               "cmd_busybox": 3, "cmd_chmod": 1, "auth_success": 1, "events_total": 16}
    assert trained_model.predict(malware)["class"] == "malware_delivery"


def test_predictor_untrained_is_safe(monkeypatch):
    from ml import model as model_mod
    monkeypatch.setattr(model_mod.Predictor, "_instance", None)
    monkeypatch.setattr(model_mod.Predictor, "available", lambda self: False)
    p = model_mod.Predictor()
    out = p.predict({"auth_attempts": 5})
    assert out["class"] == "normal" and out["risk"] == 0.0 and out["model"] == "untrained"


def test_narrator_template_is_deterministic_and_offline():
    from ml import narrator
    session = {"ip": "203.0.113.5", "device": "smartlock", "protocol": "SSH",
               "auth_attempts": 2, "commands": 9, "download_attempts": 2}
    pred = {"class": "malware_delivery", "confidence": 0.9, "anomaly": 0.7, "risk": 88.0}
    dets = [{"attack_type": "MALWARE_DELIVERY", "severity": "CRITICAL", "details": "dropper"}]
    a = narrator.narrate(session, pred, dets)
    b = narrator.narrate(session, pred, dets)
    assert a == b                                   # deterministic
    assert "malware delivery" in a and "88.0/100" in a
    assert "Escalate" in a                          # high-risk recommendation
    assert a.count("\n\n") == 2                     # three paragraphs
