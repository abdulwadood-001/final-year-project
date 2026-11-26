# Module 8 datasets

- `honeybot_cowrie_dataset.csv.gz` — **real internet attacker data**: 58,957 SSH/Telnet
  sessions from the public CyberLab honeynet (~50 Cowrie nodes, Zenodo 3687527, CC-BY),
  parsed into the 29-feature schema with behaviour-based weak labels. `gunzip` to use.
- `honeybot_training_dataset.csv` — balanced synthetic set (3600 sessions, 6 classes);
  supplies the two IoT-only classes (botnet_c2, protocol_exploit) Cowrie lacks.
- `honeybot_live_dataset.csv` — sessions from our own live stack (rule-based weak labels).

The shipped model (`ml/artifacts/`) is trained on real Cowrie data + synthetic for the two
IoT-only classes: 99.9% held-out accuracy on real data (4 classes), 99.8% on the full
6-class model. See `docs/MODEL_EVALUATION.md`.
