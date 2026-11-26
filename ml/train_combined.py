"""
HoneyBot-IoT — train the shipped Module 8 classifier from all data sources, with honest evaluation.

Data (all in ml/datasets/):
  * cowrie_days/*.csv.gz + honeybot_cowrie_dataset.csv.gz
        real internet attacker sessions (CyberLab Cowrie honeynet, 7 days, SSH/Telnet)
  * honeybot_live_train.csv
        sessions captured by THIS honeypot stack (all 6 protocols), weakly labelled by the rule engine
  * synthetic sessions (ml.synth) for the two IoT-only classes Cowrie cannot contain

Evaluations written to ml/artifacts/model_meta.json:
  1. temporal   — real Cowrie: train on 6 days, test on an unseen 7th day (4 classes)
  2. live       — train WITHOUT any live data vs WITH the live training run, both tested on
                  honeybot_live_heldout.csv: a separate simulator run, different seeds and
                  different source IPs, never used for training
  3. shipped    — stratified 20 % hold-out of the final mixed training set

Run inside the ml_api image so the saved artifacts match the served library versions:
  docker run --rm -v "$PWD:/work" -w /work honeybot/ml-api:0.8 python -m ml.train_combined
"""
import collections
import csv
import glob
import gzip
import json
import os
import random

import numpy as np

from ml.model import FEATURES, CLASSES, vectorize
from ml.synth import generate

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "datasets")
OUT = os.environ.get("ML_MODEL_DIR", os.path.join(HERE, "artifacts"))
FOUR = ["brute_force", "malware_delivery", "port_scan", "normal"]
TEST_DAY = "2019-11-21"
LIVE_WEIGHT = 25.0          # a live session counts as this many Cowrie rows (domain adaptation)


def load(path):
    opener = gzip.open if path.endswith(".gz") else open
    rows, labels = [], []
    with opener(path, "rt") as f:
        for r in csv.DictReader(f):
            labels.append(r["label"])
            rows.append({k: float(r.get(k) or 0) for k in FEATURES})
    return rows, labels


def cap(rows, labels, per, classes=None, seed=0):
    rnd = random.Random(seed)
    by = collections.defaultdict(list)
    for r, lab in zip(rows, labels):
        if classes is None or lab in classes:
            by[lab].append(r)
    out, outl = [], []
    for lab in sorted(by):
        items = by[lab][:]
        rnd.shuffle(items)
        out += items[:per]
        outl += [lab] * min(per, len(items))
    return out, outl


def xy(rows, labels, classes):
    idx = {c: i for i, c in enumerate(classes)}
    return (np.array([vectorize(r) for r in rows], dtype="float32"),
            np.array([idx[lab] for lab in labels]))


def clf_for(n_classes):
    import xgboost as xgb
    return xgb.XGBClassifier(n_estimators=220, max_depth=5, learning_rate=0.2, subsample=0.9,
                             colsample_bytree=0.9, eval_metric="mlogloss", tree_method="hist",
                             random_state=0, verbosity=0,
                             **({"num_class": n_classes} if n_classes > 2 else {}))


def evaluate(name, clf, X, y, classes):
    from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
    pred = clf.predict(X)
    labels = list(range(len(classes)))
    acc, mf1 = accuracy_score(y, pred), f1_score(y, pred, average="macro", labels=sorted(set(y)))
    print(f"\n=== {name} ({len(y)} sessions) — accuracy {acc:.3f}  macro-F1 {mf1:.3f}")
    rep = classification_report(y, pred, labels=labels, target_names=classes, digits=3,
                                zero_division=0, output_dict=True)
    print(classification_report(y, pred, labels=labels, target_names=classes, digits=3, zero_division=0))
    return {"accuracy": round(float(acc), 4), "macro_f1": round(float(mf1), 4), "n_test": int(len(y)),
            "per_class_f1": {c: round(rep[c]["f1-score"], 3) for c in classes if rep[c]["support"]},
            "confusion_matrix": confusion_matrix(y, pred, labels=labels).astype(int).tolist(),
            "classes": classes}


def main():
    from sklearn.ensemble import IsolationForest
    from sklearn.model_selection import train_test_split
    import joblib

    # ── real Cowrie days ──
    days = {}
    for p in sorted(glob.glob(os.path.join(DATA, "cowrie_days", "*.csv.gz"))):
        days[os.path.basename(p).split(".")[0]] = load(p)
    days["2019-11-01"] = load(os.path.join(DATA, "honeybot_cowrie_dataset.csv.gz"))
    print("Cowrie days:", {d: len(v[1]) for d, v in days.items()})

    # 1. temporal evaluation on real data
    tr_r, tr_l = [], []
    for d, (r, lab) in days.items():
        if d != TEST_DAY:
            tr_r += r
            tr_l += lab
    a_r, a_l = cap(tr_r, tr_l, 900, FOUR)
    b_r, b_l = cap(*days[TEST_DAY], 500, FOUR, seed=1)
    Xa, ya = xy(a_r, a_l, FOUR)
    Xb, yb = xy(b_r, b_l, FOUR)
    temporal = evaluate(f"TEMPORAL real Cowrie: 6 days -> unseen {TEST_DAY}", clf_for(4).fit(Xa, ya), Xb, yb, FOUR)

    # base pool: all real days (balanced) + synthetic IoT-only classes
    all_r = [x for r, _ in days.values() for x in r]
    all_l = [x for _, lab in days.values() for x in lab]
    base_r, base_l = cap(all_r, all_l, 1500, FOUR)
    srows, slabels = generate(per_class=1300, seed=11)
    for r, lab in zip(srows, slabels):
        if lab in ("botnet_c2", "protocol_exploit"):
            base_r.append({k: float(r[k]) for k in FEATURES})
            base_l.append(lab)

    live_r, live_l = load(os.path.join(DATA, "honeybot_live_train.csv"))
    held_r, held_l = load(os.path.join(DATA, "honeybot_live_heldout.csv"))
    print("live train:", dict(collections.Counter(live_l)))
    print("live held-out:", dict(collections.Counter(held_l)))
    Xh, yh = xy(held_r, held_l, CLASSES)

    # 2a. without live data (the previous shipped recipe)
    Xn, yn = xy(base_r, base_l, CLASSES)
    no_live = evaluate("LIVE held-out — model trained WITHOUT live data", clf_for(6).fit(Xn, yn), Xh, yh, CLASSES)

    # 2b. with the live training run
    full_r, full_l = base_r + live_r, base_l + live_l
    w = np.array([1.0] * len(base_r) + [LIVE_WEIGHT] * len(live_r), dtype="float32")
    X, y = xy(full_r, full_l, CLASSES)
    with_live = evaluate("LIVE held-out — model trained WITH live data", clf_for(6).fit(X, y, sample_weight=w),
                         Xh, yh, CLASSES)

    # 3. stratified hold-out of the mixed set
    Xtr, Xte, ytr, yte, wtr, _ = train_test_split(X, y, w, test_size=0.2, stratify=y, random_state=0)
    shipped = evaluate("SHIPPED mixed set, 20 % hold-out", clf_for(6).fit(Xtr, ytr, sample_weight=wtr),
                       Xte, yte, CLASSES)

    # final model: every training source (the held-out live run stays unseen)
    os.makedirs(OUT, exist_ok=True)
    final = clf_for(6).fit(X, y, sample_weight=w)
    final.save_model(os.path.join(OUT, "xgb_classifier.json"))
    iso = IsolationForest(n_estimators=200, contamination=0.08, random_state=0).fit(X)
    joblib.dump(iso, os.path.join(OUT, "isolation_forest.joblib"))
    sc = iso.decision_function(X)
    import sklearn
    import xgboost
    meta = {
        "version": "xgb-real+live",
        "classes": CLASSES, "features": FEATURES, "n_samples": int(len(y)),
        "heldout_accuracy": shipped["accuracy"], "heldout_macro_f1": shipped["macro_f1"],
        "iforest_range": [round(float(np.percentile(sc, 1)), 4), round(float(np.percentile(sc, 99)), 4)],
        "data_source": ("real CyberLab Cowrie honeynet (7 days) + this honeypot's own live sessions "
                        "(all 6 protocols) + synthetic for IoT-only classes"),
        "temporal_eval": temporal, "test_day": TEST_DAY,
        "real_days_trained": sorted(d for d in days if d != TEST_DAY),
        "live_eval": {"without_live": no_live, "with_live": with_live, "live_weight": LIVE_WEIGHT},
        "shipped_eval": shipped,
        "training_counts": dict(collections.Counter(full_l)),
        "library_versions": {"xgboost": xgboost.__version__, "scikit-learn": sklearn.__version__},
    }
    with open(os.path.join(OUT, "model_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"\nsaved model + meta to {OUT}")


if __name__ == "__main__":
    main()
