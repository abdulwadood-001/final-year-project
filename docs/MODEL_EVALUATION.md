# HoneyBot-IoT — Module 8 Model Evaluation (trained models + datasets)

This records the **actual trained models, how they were trained, and their measured
accuracy** — including the test where the first model failed — so the results are
reproducible and the numbers are honest.

## Datasets (`ml/datasets/`)

| File | Rows | What it is |
|---|---|---|
| `honeybot_cowrie_dataset.csv.gz` + `cowrie_days/*.csv.gz` | 466 221 | **Real internet attacker data** — SSH/Telnet sessions from the public CyberLab honeynet (~50 Cowrie nodes, Zenodo record 3687527, CC-BY), 7 days spread across May 2019 – Jan 2020, parsed into our 29-feature schema with behaviour-based weak labels (`ml/parse_cowrie.py`). |
| `honeybot_live_train.csv` | 144 | Sessions captured by **this honeypot stack** (all 6 protocols) during a simulator run — 48 attacker containers, each with its own source IP — weakly labelled by the rule engine. |
| `honeybot_live_heldout.csv` | 96 | A **second, separate** live run (different random seeds, different source IPs). Never used for training — only for testing. |
| `honeybot_training_dataset.csv` | 3 600 | Balanced synthetic set (`ml/synth.py`); supplies the two IoT-only classes Cowrie can't contain (`botnet_c2`, `protocol_exploit`). |
| `iot_flow_windows.csv.gz` | — | 1-second traffic windows from the IoT-IDS Lab Dataset v1.0.1 (flow IDS, below). |

## Trained models (`ml/artifacts/`)

| Model | File | Purpose |
|---|---|---|
| XGBoost classifier | `xgb_classifier.json` | 6-class attack classification per session |
| Isolation Forest | `isolation_forest.joblib` | anomaly / novelty score |
| LSTM forecaster | `lstm_forecast.keras` | per-device 24-h escalation risk (val MAE 4.75 / 100) |
| XGBoost flow IDS | `ml/iot_flow/iot_flow_classifier.json` | network-level scan/flood detection on PCAP windows |

To reproduce: training runs **inside the `ml_api` image**, so the saved artifacts match the exact
library versions that serve them (xgboost 3.0.0, scikit-learn 1.5.2, TensorFlow 2.18):

```bash
docker run --rm -v "$PWD:/work" -w /work -e PYTHONPATH=/work honeybot/ml-api:0.8 python -m ml.train_combined
docker run --rm -v "$PWD:/work" -w /work -e PYTHONPATH=/work honeybot/ml-api:0.8 python -m ml.forecast
```

The script writes all the numbers below to `ml/artifacts/model_meta.json`.

## 1. Real internet data — temporal split

Trained on 6 days of real honeynet traffic, tested on a **completely unseen 7th day
(2019-11-21)** — different attack campaigns, months apart. Balanced, 500 sessions per class:

**Accuracy 1.000 · macro-F1 1.000** on 2 000 unseen real sessions (brute_force,
malware_delivery, port_scan, normal).

This shows the model generalises across time on Cowrie data. It does **not** show it works on
our honeypot — see the next test.

## 2. Our own honeypot — the test that matters

The first shipped model (Cowrie + synthetic only) was run against the full `docker compose`
stack. It labelled our own malware-download and reverse-shell sessions as `normal`. The cause
is **domain shift**: in Cowrie a Mirai-style infection is ~23 separate commands; our shell
logs `cd /tmp; wget …; chmod +x …; ./x` as **one** command line, and the other protocols
(MQTT, Modbus, RTSP, HTTP) don't exist in Cowrie at all.

To fix it, this honeypot's own live sessions were added to training (weighted ×25), and the
model was tested on a **separate live run** that it never saw in training:

| Live held-out run (96 sessions, 6 protocols) | accuracy | macro-F1 |
|---|---|---|
| model trained **without** live data (Cowrie + synthetic) | **0.365** | 0.374 |
| model trained **with** the live training run (shipped) | **0.917** | **0.943** |

Per-class F1 of the shipped model on the held-out live run:

| brute_force | malware_delivery | botnet_c2 | port_scan | protocol_exploit | normal |
|---|---|---|---|---|---|
| 0.826 | 1.000 | 1.000 | 0.927 | 1.000 | 0.906 |

The weakest class is `brute_force`: our simulator, like many real bots, tries one password per
SSH connection, so a single brute-force session looks like one ordinary login. The rule engine
(which counts attempts **per IP** across sessions) catches these. The per-session model is a
second opinion, not a replacement.

## 3. Mixed training set — stratified 20 % hold-out

**Accuracy 0.998 · macro-F1 0.998** on 1 749 held-out sessions. This number is high because
the hold-out comes from the same sources as training. The live held-out result above (0.917)
is the more realistic figure to quote.

## Ablation — does the classifier only re-learn the labelling rules?

The weak labels come from a few counters (downloads, logins, commands …).
`ml/artifacts/ablation.json` retrains with **all eight rule-derived features removed**
(`cmd_download`, `file_events`, `download_attempts`, `auth_attempts`, `auth_success`,
`commands`, `distinct_passwords`, `distinct_usernames`) on the real Cowrie data:

| Feature set | accuracy | macro-F1 |
|---|---|---|
| all 29 features | 0.999 | 0.999 |
| rule features removed (21 timing/ratio/protocol features) | **0.983** | **0.983** |

The model keeps 98 % accuracy from timing, byte-ratio and protocol behaviour alone, so it has
learned more than the labelling rules.

## Network-flow IDS (all protocols, packet level)

A second classifier works on **network traffic** rather than session logs. It is trained on the
**IoT-IDS Lab Dataset v1.0.1** (Zenodo 24511639), using the dataset's own capture-level
train/test split and 26 window features.

**Held-out test captures (1 452 windows): accuracy 0.995 · macro-F1 0.981**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| BENIGN | 0.998 | 1.000 | 0.999 | 1235 |
| PORT_SCAN | 0.977 | 0.956 | 0.966 | 90 |
| TCP_BURST (flood) | 0.981 | 0.981 | 0.981 | 103 |
| UDP_BURST (flood) | 1.000 | 0.958 | 0.979 | 24 |

**It runs live.** Every session's PCAP (including handshake-only connections, which is what scans and
floods consist of) is cut into 1-second windows per source IP (`ml/flow.py`), scored by
`ml_api` `POST /flow`, stored in `flow_detections` and shown on the dashboard's
*Network-flow IDS* panel. Confident windows (≥ 0.8) raise `FLOW_PORT_SCAN` (T1046/T0846) or
`FLOW_FLOOD` (T1498/T0814). Measured on the running stack:

- the simulator's port-scan scenario → `PORT_SCAN` at **0.90–0.99** confidence (5 of 5 scanning IPs);
- a 400-connection flood on the Modbus port → `TCP_BURST` → `FLOW_FLOOD` detection;
- a deliberately slow, spread-out sweep scored only 0.60 (below threshold), so slow scans are
  left to the rule engine's `PORT_SCAN` rule.

## Honest reading of the numbers (for the viva)

- Quote **0.917 on an unseen live honeypot run** as the realistic accuracy, and **1.000 on an
  unseen day of real internet traffic** as the cross-time result on real data.
- Without our own live data the model scored 0.365 on our honeypot. This is why scope **LI-6**
  says accuracy grows with live data: the more real sessions the deployed honeypot collects,
  the better the model fits its own traffic. Retraining is one command (above).
- The live labels are weak labels from the rule engine, and the live attackers are our own
  simulator. Real-world accuracy on internet attackers must be re-measured after deployment.
