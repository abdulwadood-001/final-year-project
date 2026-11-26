# Module 8 datasets

- `honeybot_cowrie_dataset.csv.gz` + `cowrie_days/*.csv.gz` — **real internet attacker data**:
  SSH/Telnet sessions from the public CyberLab honeynet (~50 Cowrie nodes, 7 days
  May 2019 – Jan 2020, Zenodo 3687527, CC-BY), parsed into the 29-feature schema with
  behaviour-based weak labels (`python -m ml.parse_cowrie <day>.json.gz out.csv`).
- `honeybot_live_train.csv` — 144 sessions captured by this honeypot stack (all 6 protocols),
  weakly labelled by the rule engine. Used for training.
- `honeybot_live_heldout.csv` — 96 sessions from a separate live run (different seeds and source
  IPs). Used **only** for testing.
- `honeybot_training_dataset.csv` — balanced synthetic set (3 600 sessions, 6 classes);
  supplies the two IoT-only classes (botnet_c2, protocol_exploit) Cowrie lacks.
- `iot_flow_windows.csv.gz` — IoT-IDS Lab traffic windows for the network-flow IDS.

Export a new live set from a running stack with `python -m ml.features out.csv`
or `GET /api/ml/dataset.csv`, then retrain with `python -m ml.train_combined`.

Shipped model: 0.917 accuracy on the unseen live honeypot run, 1.000 on an unseen day of
real internet traffic. Details in `docs/MODEL_EVALUATION.md`.
