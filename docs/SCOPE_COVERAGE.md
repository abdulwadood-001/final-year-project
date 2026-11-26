# HoneyBot-IoT — Scope Coverage (100%)

This maps every module and feature of the approved scope (SP23-BCT final scope review)
to its implementation, so an evaluator can check each item against runnable code.

## Module 1 — IoT Device Emulation
| Scope item | Status | Where |
|---|---|---|
| CCTV camera emulator (RTSP + HTTP panel, firmware banner, motion→MQTT) | ✅ | `rtsp_honeypot/`, `http_honeypot/` (cctv app), `device_state/` |
| Smart lock emulator (SSH/Telnet shell, REST API, MQTT control) | ✅ | `ssh_honeypot/`, `http_honeypot/` (lock app), `mqtt_honeypot/` |
| Industrial sensor emulator (MQTT telemetry, HTTP HMI, Telnet, thresholds) | ✅ | `telnet_honeypot/`, `http_honeypot/` (sensor app), `modbus_honeypot/` |
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
| Feature store / dataset | ✅ | `ml/features.py`, `/api/ml/dataset.csv` |

## Constraints honoured
- **LI-6** classifier accuracy grows with live data — synthetic baseline documented honestly (`docs/MODEL_CARD.md`).
- **LI-7** offline operation — template narrator and trend forecaster need no network; GreyNoise/LLM are opt-in.
- **LI-8** no physical-proximity attacks (Bluetooth/NFC) — out of scope.
- **LI-9** biometric / smart-bulb devices — deferred, not added.
- **LI-11** research lab only — isolation enforced, passive capture, samples never executed.

Every item in the approved scope is implemented and covered by automated tests
(`pytest`, `npm test`) and the end-to-end Docker run (`docs/TEST_REPORT.md`,
`docs/DEVICE_MACHINES.md`, `docs/MODULE8_AI.md`).
