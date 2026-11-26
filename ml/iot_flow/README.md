# Flow-based IoT network IDS (multi-protocol)

A complementary classifier to the session-based Module-8 model, trained on **real
multi-protocol IoT network traffic** (TCP/UDP/ICMP) rather than SSH/Telnet session logs.

- **Dataset:** IoT-IDS Lab Dataset v1.0.1 (Zenodo 24511639, CC-BY data / MIT code) — real
  captures from an ESP8266 IoT lab: benign telemetry plus port scanning and TCP/UDP flood
  attacks. Shipped as `ml/datasets/iot_flow_windows.csv.gz` (10,542 labelled time windows,
  26 flow features).
- **Model:** `iot_flow_classifier.json` (XGBoost, 4 classes: BENIGN, PORT_SCAN, TCP_BURST,
  UDP_BURST), trained with the dataset's own **capture-level train/test split** (no window
  from a test capture appears in training).
- **Result (held-out test captures):** accuracy 0.995, macro-F1 0.981 — see
  `iot_flow_meta.json` and `docs/MODEL_EVALUATION.md`.

Reproduce: download the dataset, then `IOTIDS_DIR=<dir> python ml/iot_flow/train_iot_flow.py`.

This operates on network-flow features (packets/bytes/flags/timing), a different feature
space from the honeypot session model — the two are complementary: session-level attacker
behaviour (SSH/Telnet) + network-level IoT traffic anomalies (all protocols).
