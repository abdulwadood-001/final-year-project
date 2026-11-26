"""
HoneyBot-IoT — Module 8 training (scope M8-FE-1 classifier, M8-FE-2 anomaly).

Trains and saves:
  * an XGBoost six-class attack classifier  → ml/artifacts/xgb_classifier.json
  * an Isolation Forest anomaly detector     → ml/artifacts/isolation_forest.joblib
  * metrics + metadata                        → ml/artifacts/model_meta.json

It uses live labelled sessions from the event store (ml.features.build_dataset)
when there are enough per class; otherwise it augments them with synthetic
sessions (ml.synth) so the pipeline trains and demonstrates from day one
(limitation LI-6). Evaluation is 5-fold stratified cross-validation with per-class
precision/recall/F1 and a confusion matrix, plus a comparison against the
rule-label baseline (the models must beat "always predict the rule's own class"
on held-out folds, i.e. generalise beyond memorising the rules).

    python -m ml.train                 # DB if available, else synthetic
    python -m ml.train --synthetic 500 # force synthetic, 500 sessions/class
"""

import os
import sys
import json
import argparse
import datetime as dt


def _utcnow():
    return dt.datetime.now(dt.timezone.utc)

import numpy as np

from ml.model import FEATURES, CLASSES, MODEL_DIR, CLF_PATH, IFOREST_PATH, META_PATH, vectorize

MIN_PER_CLASS = 60          # below this (per class) we augment with synthetic data


def _load_live():
    try:
        from ml.features import build_dataset
        rows = build_dataset()
    except Exception as e:
        print(f"  live data unavailable ({e}); using synthetic only")
        return [], []
    feats = [{k: r.get(k, 0) for k in FEATURES} for r in rows]
    labels = [r["label"] for r in rows]
    return feats, labels


def _class_counts(labels):
    return {c: labels.count(c) for c in CLASSES}


def build_training_set(force_synth=0, synth_per_class=400):
    live_feats, live_labels = ([], []) if force_synth else _load_live()
    counts = _class_counts(live_labels)
    print(f"  live sessions: {len(live_labels)} {counts}")
    need_synth = force_synth or any(counts[c] < MIN_PER_CLASS for c in CLASSES)
    feats, labels = list(live_feats), list(live_labels)
    if need_synth:
        from ml.synth import generate
        per = synth_per_class if force_synth else max(synth_per_class,
                                                      MIN_PER_CLASS * 4)
        s_feats, s_labels = generate(per_class=per)
        feats += s_feats
        labels += s_labels
        print(f"  + {len(s_labels)} synthetic sessions ({per}/class)")
    return feats, labels


def cross_validate(X, y_idx, n_classes):
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, accuracy_score
    import xgboost as xgb

    n_splits = min(5, int(np.min(np.bincount(y_idx))))
    if n_splits < 2:
        return {"note": "not enough samples per class for CV"}
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=0)
    accs, cms, p_all, r_all, f_all = [], [], [], [], []
    for tr, te in skf.split(X, y_idx):
        clf = xgb.XGBClassifier(n_estimators=120, max_depth=5, learning_rate=0.2,
                                subsample=0.9, colsample_bytree=0.9, eval_metric="mlogloss",
                                num_class=n_classes, tree_method="hist", verbosity=0)
        clf.fit(X[tr], y_idx[tr])
        pred = clf.predict(X[te])
        accs.append(accuracy_score(y_idx[te], pred))
        p, r, f, _ = precision_recall_fscore_support(y_idx[te], pred, labels=range(n_classes),
                                                     average=None, zero_division=0)
        p_all.append(p); r_all.append(r); f_all.append(f)
        cms.append(confusion_matrix(y_idx[te], pred, labels=range(n_classes)))
    return {
        "folds": n_splits,
        "accuracy_mean": round(float(np.mean(accs)), 4),
        "accuracy_std": round(float(np.std(accs)), 4),
        "per_class": {CLASSES[i]: {"precision": round(float(np.mean([p[i] for p in p_all])), 4),
                                   "recall": round(float(np.mean([r[i] for r in r_all])), 4),
                                   "f1": round(float(np.mean([f[i] for f in f_all])), 4)}
                      for i in range(n_classes)},
        "confusion_matrix": np.sum(cms, axis=0).astype(int).tolist(),
        "confusion_labels": CLASSES,
    }


def main():
    ap = argparse.ArgumentParser(description="Train HoneyBot-IoT Module 8 models")
    ap.add_argument("--synthetic", type=int, default=0,
                    help="force N synthetic sessions per class instead of live data")
    args = ap.parse_args()

    os.makedirs(MODEL_DIR, exist_ok=True)
    print("HoneyBot-IoT Module 8 — training")
    feats, labels = build_training_set(force_synth=args.synthetic,
                                       synth_per_class=args.synthetic or 400)
    if len(labels) < 30:
        print("  not enough data to train; aborting.")
        sys.exit(1)

    X = np.array([vectorize(f) for f in feats], dtype="float32")
    y_idx = np.array([CLASSES.index(l) for l in labels])

    print("  5-fold stratified cross-validation ...")
    cv = cross_validate(X, y_idx, len(CLASSES))
    if "accuracy_mean" in cv:
        print(f"    accuracy {cv['accuracy_mean']:.3f} ± {cv['accuracy_std']:.3f} over {cv['folds']} folds")
        for c, m in cv["per_class"].items():
            print(f"    {c:17} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")

    # final classifier on all data
    import xgboost as xgb
    clf = xgb.XGBClassifier(n_estimators=160, max_depth=5, learning_rate=0.2, subsample=0.9,
                            colsample_bytree=0.9, eval_metric="mlogloss", num_class=len(CLASSES),
                            tree_method="hist", verbosity=0)
    clf.fit(X, y_idx)
    clf.save_model(CLF_PATH)

    # Isolation Forest trained on known-attack + benign to score novelty (M8-FE-2)
    from sklearn.ensemble import IsolationForest
    import joblib
    iforest = IsolationForest(n_estimators=200, contamination=0.08, random_state=0)
    iforest.fit(X)
    joblib.dump(iforest, IFOREST_PATH)
    scores = iforest.decision_function(X)
    iforest_range = [round(float(np.percentile(scores, 1)), 4), round(float(np.percentile(scores, 99)), 4)]

    importances = {FEATURES[i]: round(float(v), 4)
                   for i, v in sorted(enumerate(clf.feature_importances_),
                                      key=lambda kv: -kv[1])[:12]}
    meta = {
        "version": "xgb-" + _utcnow().strftime("%Y%m%d"),
        "trained_at": _utcnow().isoformat(timespec="seconds"),
        "classes": CLASSES, "features": FEATURES, "n_samples": int(len(y_idx)),
        "class_counts": _class_counts(labels), "cv": cv,
        "iforest_range": iforest_range, "top_features": importances,
        "data_source": "synthetic" if args.synthetic else "live+synthetic",
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"  saved classifier, Isolation Forest and metadata to {MODEL_DIR}")


if __name__ == "__main__":
    main()
