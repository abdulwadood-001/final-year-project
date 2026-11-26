# HoneyBot-IoT — Scope Coverage (100%)

This maps every module and feature of the approved scope (SP23-BCT final scope review)
to its implementation, so an evaluator can check each item against runnable code.

## Module 1 — IoT Device Emulation
| Scope item | Status | Where |
|---|---|---|
| CCTV camera emulator (RTSP with a **real H.264 video stream**, HTTP panel, firmware banner, motion→MQTT) | ✅ | `rtsp_honeypot/` (+ `media/cctv.h264`), `http_honeypot/` (cctv app), `device_state/` |
| Smart lock emulator (SSH/Telnet shell, REST API, MQTT control) | ✅ | `ssh_honeypot/`, `http_honeypot/` (lock app), `mqtt_honeypot/` |
| Industrial sensor emulator (MQTT telemetry, HTTP HMI, Telnet + SSH, Modbus, thresholds) | ✅ | `telnet_honeypot/`, `ssh_honeypot/` (`SSH_DEVICE=sensor`, port 2223), `http_honeypot/` (sensor app), `modbus_honeypot/` |
| Device State Manager (shared state across protocols) | ✅ | `device_state/`, `common/state.py` |
| **Each device as its own machine** (own hostname/IP/MAC) | ✅ (v0.8) | `device_machine.py`, `docker-compose.yml` |
| **Real restricted shell on login** | ✅ (v0.8) | `sandbox/`, `common/realshell.py`, `vm/` |

## Module 2 — Multi-Protocol Handler
| Protocol | Status | Where |
|---|---|---|
| SSH (Paramiko) · Telnet · HTTP/HTTPS (FastAPI) · MQTT · RTSP | ✅ | respective `*_honeypot/` |
| **Modbus/TCP (6th protocol, ICS)** | ✅ (v0.8) | `modbus_honeypot/` |
| Unified session registry, cross-protocol correlation | ✅ | `common/db.py`, `intel/correlate.py` |

## Module 3 — Attack Detection & Forensic Logging
| Scope item | Status | Where |
|---|---|---|
| Reconnaissance / brute-force / credential logging | ✅ | `intel/rules.py`, `common/db.py` |
| Command capture (full I/O) | ✅ | `common/fakeshell.py`, `common/realshell.py` |
| File capture (SHA-256, MIME, arch) + YARA | ✅ | `common/capture.py`, `intel/yara_scan.py` |
| **PCAP recording per session** | ✅ (v0.9) | `common/pcap.py`, `/api/pcaps` |
| PostgreSQL indexed log store + full-text search | ✅ | `init.sql`, `/api/search` |

## Module 4 — Threat Intelligence
| Scope item | Status | Where |
|---|---|---|
| Attack classification storage (indexed to sessions) | ✅ | `ml_predictions` table, `ml/score.py` |
| Cross-session correlation / campaigns | ✅ | `intel/correlate.py` |
| GeoIP (MaxMind) | ✅ | `intel/geo.py` |
| **GreyNoise IP reputation** | ✅ (v0.9) | `intel/reputation.py` |
| MITRE ATT&CK tagging (Enterprise + ICS) | ✅ | `intel/mitre.py` |
| STIX 2.1 export + daily/weekly reports | ✅ | `intel/stix.py`, `intel/report.py` |

## Module 5 — Real-Time Monitoring Dashboard
| Scope item | Status | Where |
|---|---|---|
| Live attack feed (WebSocket) | ✅ | `dashboard/`, `/api/ws` |
| Geographic visualisation (offline map + heat) | ✅ | `dashboard/src/components/dashboard/world-map.tsx` |
| Protocol statistics (Recharts) | ✅ | `dashboard/src/routes/index.tsx` |
| Device status monitor | ✅ | `dashboard/src/routes/devices.*` |
| **AI threat-summary panel (narratives, risk, forecast)** | ✅ (v0.9) | `dashboard/src/routes/intelligence.tsx` |
| Export & reporting (PDF / CSV / STIX) | ✅ | `dashboard/src/routes/reports.tsx` |

## Module 6 — Alert & Notification System
| Scope item | Status | Where |
|---|---|---|
| E-mail (SMTP, HTML, PDF attach) | ✅ | `alerts/notifier.py` |
| Telegram push | ✅ | `alerts/notifier.py` |
| **Slack webhook** | ✅ (v0.9) | `alerts/notifier.py` `send_slack` |
| Threshold engine + dedup/escalation | ✅ | `alerts/notifier.py`, `alerts/alerts.yaml` |

## Module 7 — Containerized Deployment & Sandbox
| Scope item | Status | Where |
|---|---|---|
| Per-service Docker containers | ✅ | `docker-compose.yml`, `Dockerfile.*` |
| Network isolation (inbound-only, iptables) | ✅ | `deploy/firewall.sh`, `Dockerfile.firewall` |
| Orchestration (Compose, named networks, volumes) | ✅ | `docker-compose.yml` |
| Resource monitoring (Prometheus + Grafana + cAdvisor) | ✅ | `monitoring/` |
| Backup & recovery (pg_dump + samples, SHA-256) | ✅ | `deploy/backup.sh` |
| **Sandbox (real throw-away device machine per login)** | ✅ (v0.8) | `sandbox/`, `vm/` |

## Module 8 — AI Integration & Intelligent Threat Analysis
| Scope item (M8-FE) | Status | Where |
|---|---|---|
| FE-1 ML attack classifier (XGBoost, 6 classes, 5-fold CV) | ✅ | `ml/train.py`, `ml/model.py` |
| FE-2 Anomaly detector (Isolation Forest) | ✅ | `ml/train.py`, `ml/model.py` |
| FE-3 LLM threat narrator (template / GPT-4o / Ollama) | ✅ | `ml/narrator.py` |
| FE-4 Predictive threat scoring (LSTM, per device, 24 h) | ✅ | `ml/forecast.py` |
| ML serving microservice (FastAPI `ml_api`) | ✅ | `ml/ml_api.py`, `Dockerfile.ml` |
| Feature store / dataset (real Cowrie honeynet + IoT-IDS Lab + live) | ✅ | `ml/features.py`, `ml/datasets/`, `/api/ml/dataset.csv` |
| Network-flow IDS on live PCAPs (all protocols) | ✅ | `ml/flow.py`, `ml/iot_flow/`, `/api/ml/flow` |
| Evaluation: temporal split, unseen live honeypot run (91.7 %), ablation | ✅ | `docs/MODEL_EVALUATION.md`, `ml/artifacts/ablation.json` |

## Constraints honoured
- **LI-6** classifier trained on real internet data (CyberLab Cowrie, IoT-IDS Lab); the two IoT-only classes still rely on synthetic + live data — documented in `docs/MODEL_EVALUATION.md`.
- **LI-7** offline operation — template narrator and trend forecaster need no network; GreyNoise/LLM are opt-in.
- **LI-8** no physical-proximity attacks (Bluetooth/NFC) — out of scope.
- **LI-9** biometric / smart-bulb devices — deferred, not added.
- **LI-11** research lab only — isolation enforced, passive capture, samples never executed.

## Honest caveats (not gaps in scope, but worth stating in the viva)
- Device "machines" are hardened containers (own hostname/IP/MAC, per-session throw-away
  BusyBox machine), not hypervisor VMs — the approved scope (Module 7) specifies Docker.
- Slack, Telegram, GreyNoise and OpenAI paths are unit-tested with mocked endpoints; they need
  your own keys/webhooks to run live.
- The sandbox service holds the Docker socket to start per-session machines; it is isolated on
  an internal network and never exposed to attackers.
- Slow port sweeps are detected by the rule engine; the flow model alerts on normal-speed scans
  and floods (see `docs/MODEL_EVALUATION.md`).
- Session classifier: 91.7 % on an unseen live run of our own honeypot; it only reached 36.5 %
  before our own live data was added to training. Re-measure after internet deployment.

Every item in the approved scope is implemented and covered by automated tests
(`pytest`, `npm test`) and the end-to-end Docker run (`docs/TEST_REPORT.md`,
`docs/DEVICE_MACHINES.md`, `docs/MODULE8_AI.md`).

## End-to-end verification (full `docker compose` stack)
All 13 services (including the outbound-isolation firewall) were built and started with
`docker compose up`, then attacked with the simulator — 80 attacker containers, each with its
own source IP — across all 16 scenarios. Result: 240 sessions on all 6 protocols, 245
detections of 30 attack types, AI scoring of every session, LSTM risk per device, a live
`FLOW_PORT_SCAN`/`FLOW_FLOOD` from the flow IDS, and every dashboard page loading with no
console errors. Screenshots: `docs/screenshots/`.
