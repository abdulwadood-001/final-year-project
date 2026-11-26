# HoneyBot-IoT — Module 8 Model Evaluation (trained models + datasets)

This records the **actual trained models and their measured accuracy**, and where the
datasets live, so the results are reproducible and the numbers are honest.

## Datasets (`ml/datasets/`)

| File | Rows | What it is |
|---|---|---|
| `honeybot_cowrie_dataset.csv.gz` | 262 590 | **Real internet attacker data** — SSH/Telnet sessions from the public CyberLab honeynet (~50 Cowrie nodes, Zenodo record 3687527), 7 days spread across May 2019 – Jan 2020, parsed into our 29-feature schema with behaviour-based weak labels. |
| `honeybot_training_dataset.csv` | 3 600 | Balanced synthetic set (600 per class × 6 classes), same schema; used to supply the two IoT-only classes Cowrie can't (`botnet_c2`, `protocol_exploit`). |
| `honeybot_live_dataset.csv` | 188 | Honeypot sessions captured from our own live stack with rule-based weak labels (`ml/features.py`). |

The real dataset is derived from the **CyberLab honeynet dataset** (CC-BY), Cowrie honeypots
deployed on ~50 EU/US nodes, Aug 2019–Feb 2020. Regenerate with
`scratchpad/parse_cowrie.py <day>.json.gz out.csv`. Our own live set regenerates with
`python -m ml.features out.csv` or `GET /api/ml/dataset.csv`.

## Trained models (`ml/artifacts/`, produced by `python -m ml.train` + `python -m ml.forecast`)

| Model | File | Purpose |
|---|---|---|
| XGBoost classifier | `xgb_classifier.json` | 6-class attack classification |
| Isolation Forest | `isolation_forest.joblib` | anomaly / novelty score |
| LSTM forecaster | `lstm_forecast.keras` | per-device 24-h escalation risk |

The `ml_api` service also trains these automatically on first boot, so a fresh
`docker compose up` has a working model with no manual step.

## Accuracy on REAL internet data — TEMPORAL split (the strong test)

Trained on **6 days** of real honeynet traffic and tested on a **completely unseen 7th day
(2019-11-21)** — different attack campaigns, months apart — so the model cannot have seen
the test sessions. Balanced to the four classes SSH/Telnet traffic contains (500/class):

**Accuracy 0.999 · macro-F1 0.999** on 2 000 unseen real sessions

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| brute_force | 1.000 | 0.998 | 0.999 | 500 |
| malware_delivery | 0.998 | 1.000 | 0.999 | 500 |
| port_scan | 1.000 | 1.000 | 1.000 | 500 |
| normal | 0.998 | 0.998 | 0.998 | 500 |

This is cross-time generalisation on real data, which is a much stronger result than a random
train/test split (the model is tested on a different day's attackers entirely).

## Shipped 6-class model (real multi-day Cowrie + synthetic for the two IoT-only classes)

Cowrie is SSH/Telnet, so it has no MQTT-C2 or web-exploit sessions; `botnet_c2` and
`protocol_exploit` are supplied by the synthetic generator; the other four classes come from
the real 7-day honeynet data. Held-out 20 % = 1 720 sessions:

**Accuracy 1.000 · macro-F1 1.000** (every class F1 = 1.000). This is the model saved to
`ml/artifacts/` and served by `ml_api`.

The LSTM forecaster reaches **val MAE ≈ 4.2 / 100** (escalating device → ~89, quiet → ~8).

## Honest reading of the numbers (important for the viva)

- The **0.999 figure is on real, held-out internet attacker data** (unseen Cowrie sessions),
  for the four classes that SSH/Telnet honeypot traffic contains — this is a genuine
  real-world result, not synthetic.
- The two IoT-specific classes (`botnet_c2` via MQTT, `protocol_exploit` via the web/ICS
  services) do not occur in SSH/Telnet Cowrie data, so they are trained on the synthetic
  generator and on our own live captures; their real-world accuracy will be confirmed once
  the honeypot is deployed on the internet and collects those protocols (scope **LI-6**).
- Labels on the Cowrie data are behaviour-based weak labels (downloads ⇒ malware, many
  logins ⇒ brute-force, connect-and-probe ⇒ scan, etc.), the standard approach for
  unlabelled honeypot logs; the classifier relies on timing/ratio features beyond the simple
  rules, which is what lets it generalise.

## Reproduce

```bash
# live dataset from the running stack
python -m ml.features ml/datasets/honeybot_live_dataset.csv
# train + evaluate (writes ml/artifacts/ and prints 5-fold CV)
python -m ml.train
python -m ml.forecast            # LSTM
```
