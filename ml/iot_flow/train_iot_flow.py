"""Flow-based IoT network-IDS classifier on the real IoT-IDS Lab dataset (Zenodo 24511639).
Multi-protocol IoT network windows (TCP/UDP/ICMP). Uses the dataset's own capture-level
train/test split so no window from a test capture is ever seen in training."""
import sys, csv, glob, json, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
import xgboost as xgb, joblib

import os
D = os.environ.get("IOTIDS_DIR", "/home/user/iot_flow_data/IoT-IDS-Lab-Dataset-v1.0.1")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))
# 26 model features (per the data dictionary: n_pkts onward)
FEATURES = ["n_pkts", "n_bytes", "len_mean", "len_std", "len_max", "n_small", "n_tcp", "n_udp",
            "n_icmp", "n_other", "n_syn", "n_synack", "n_rst", "n_fin", "n_ackonly", "n_psh",
            "rst_per_syn", "syn_without_synack", "u_syn_dport", "u_syn_sport", "u_syn_pairs",
            "u_tuples", "u_udp_dport", "iat_mean", "iat_std", "iat_min"]
CLASSES = ["BENIGN", "PORT_SCAN", "TCP_BURST", "UDP_BURST"]

# capture_id -> split
reg = {r["capture_id"]: r["split"] for r in csv.DictReader(open(f"{D}/metadata/CAPTURE_REGISTER.csv"))}


def load(window="w2"):
    data = {"train": [], "test": []}
    for f in glob.glob(f"{D}/windows/{window}/*.csv"):
        for row in csv.DictReader(open(f)):
            cap = row["capture"]
            # parent id for children like MIX_003_A -> MIX_003; register keys may be parent
            split = reg.get(cap) or reg.get(cap.split("_A")[0].split("_B")[0].split("_C")[0]) or "train"
            lbl = row["label"]
            if lbl not in CLASSES:
                continue
            vec = [float(row[k]) for k in FEATURES]
            bucket = "test" if split == "test" else ("train" if split in ("train", "train_extra", "val") else None)
            if bucket:
                data[bucket].append((vec, lbl))
    return data


def main():
    import os
    os.makedirs(OUT, exist_ok=True)
    for win in ("w1", "w2", "w5"):
        if glob.glob(f"{D}/windows/{win}/*.csv"):
            data = load(win)
            if data["train"] and data["test"]:
                break
    idx = {c: i for i, c in enumerate(CLASSES)}
    Xtr = np.array([v for v, _ in data["train"]], dtype="float32")
    ytr = np.array([idx[l] for _, l in data["train"]])
    Xte = np.array([v for v, _ in data["test"]], dtype="float32")
    yte = np.array([idx[l] for _, l in data["test"]])
    print(f"window={win} | train windows={len(ytr)} {dict(collections.Counter(l for _,l in data['train']))}")
    print(f"test windows={len(yte)} {dict(collections.Counter(l for _,l in data['test']))}")

    clf = xgb.XGBClassifier(n_estimators=250, max_depth=6, learning_rate=0.15, subsample=0.9,
                            colsample_bytree=0.9, num_class=len(CLASSES), eval_metric="mlogloss",
                            tree_method="hist", verbosity=0)
    # class weights for imbalance
    w = np.array([len(ytr) / (len(CLASSES) * max(1, (ytr == i).sum())) for i in range(len(CLASSES))])
    clf.fit(Xtr, ytr, sample_weight=w[ytr])
    pred = clf.predict(Xte)
    acc, mf1 = accuracy_score(yte, pred), f1_score(yte, pred, average="macro")
    print(f"\n=== IoT flow IDS — held-out TEST captures ({len(yte)} windows) ===")
    print(f"accuracy {acc:.3f}  macro-F1 {mf1:.3f}")
    print(classification_report(yte, pred, target_names=CLASSES, digits=3, zero_division=0))
    cm = confusion_matrix(yte, pred)
    for i, c in enumerate(CLASSES):
        print(f"  {c:>10}", cm[i].tolist())

    # train final on train+test-free? No — final model on ALL labelled windows for serving
    Xall = np.vstack([Xtr, Xte]); yall = np.concatenate([ytr, yte])
    wall = np.array([len(yall) / (len(CLASSES) * max(1, (yall == i).sum())) for i in range(len(CLASSES))])
    final = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.15, num_class=len(CLASSES),
                              eval_metric="mlogloss", tree_method="hist", verbosity=0)
    final.fit(Xall, yall, sample_weight=wall[yall])
    final.save_model(f"{OUT}/iot_flow_classifier.json")
    meta = {"version": "iot-flow-xgb", "classes": CLASSES, "features": FEATURES, "window": win,
            "source": "IoT-IDS Lab Dataset v1.0.1 (Zenodo 24511639, CC-BY/MIT)",
            "n_train": int(len(ytr)), "n_test": int(len(yte)),
            "heldout_accuracy": round(float(acc), 4), "heldout_macro_f1": round(float(mf1), 4),
            "confusion_matrix": cm.astype(int).tolist(),
            "per_class": classification_report(yte, pred, target_names=CLASSES, output_dict=True, zero_division=0)}
    json.dump(meta, open(f"{OUT}/iot_flow_meta.json", "w"), indent=2)
    print(f"\nsaved flow IDS model + meta to {OUT}/")


if __name__ == "__main__":
    main()
