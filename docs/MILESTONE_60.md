# HoneyBot-IoT — 60% Milestone Report

This document maps the implemented code to the scope document and to the 60% plan, so an
evaluator can check each deliverable against something runnable.

## 1. Summary

At 60%, the system does end-to-end what the scope promises for the non-AI modules:

- **All 5 protocols, all 3 devices** work and respond realistically.
- **Every interaction** across every protocol lands in **one unified event store**.
- **Rule-based classification** labels each attack and tags it with **MITRE ATT&CK**
  (Enterprise + ICS) technique IDs.
- **Threat intelligence**: cross-session correlation per IP, GeoIP, credential-reuse
  campaigns, and indicators of compromise (URLs, IPs, file hashes).
- **Real-time alerting** (Telegram + e-mail) with thresholds and deduplication.
- **A live dashboard**: world map, device-status cards, protocol charts, MITRE ranking,
  detection feed, IOCs, and full-text search.
- **Safe deployment**: outbound isolation, API not public, hardened containers, pinned
  dependencies, secrets in `.env`.

The AI/ML module (M8), STIX 2.1 export, WebSocket push, PCAP, Prometheus/Grafana and the
automated PDF report are deliberately left for the 100% milestone. **All attacker behaviour
needed to train the ML classifier is already being recorded**, and the detection rules
double as the weak labels for it.

## 2. "Fix first" defects from the plan — status

| Defect in the 30% code | Status at 60% |
|---|---|
| Isolation not enforced (honeynet could reach internet) | **Fixed** — `deploy/firewall.sh` drops all NEW outbound from the honeynet subnet (DOCKER-USER, conntrack NEW) |
| API public & unauthenticated on :5000 | **Fixed** — API no longer published; only Nginx :80 with HTTP basic auth, rate-limited |
| `sessions` table never filled | **Fixed** — every connection creates a `sessions` row; `attackers` holds the cross-protocol correlation |
| SSH logged no commands, ignored exec requests | **Fixed** — interactive **and** `exec` channels captured; one connection serves multiple channels |
| Brute-force counted over all time | **Fixed** — all rules use time windows (`BF_WINDOW_MIN`, default 10 min) |
| MQTT parser broke on packets > 127 bytes / short reads | **Fixed** — variable-length integer decode + `recv_exact` loop + QoS 1/2 packet IDs |
| Fingerprintable responses, "COMSATS" footer, exact-match commands | **Fixed** — footer removed, realistic vendor banners, argument-tolerant BusyBox-style shell |
| Hard-coded DB password in compose | **Fixed** — moved to `.env` (git-ignored); `.env.example` provided |
| No `requirements.txt`, no tests | **Fixed** — pinned `requirements-*.txt`, `pytest` suite, `bandit` lint, CI workflow |

## 3. The 11 scope deliverables — status

| # | Deliverable | Where | Done when (from plan) | Status |
|---|---|---|---|---|
| 1 | RTSP CCTV honeypot (OPTIONS/DESCRIBE/SETUP/PLAY, Basic+Digest, valid SDP) | `rtsp_honeypot/` | `ffprobe` gets an SDP, creds in DB | **Done** |
| 2 | Unified `events` table + `sessions` per connection | `init.sql`, `common/db.py` | every honeypot writes through `log_event()` | **Done** (old tables kept as views) |
| 3 | Device State Manager in Redis, shared across SSH/HTTP/MQTT | `common/state.py`, `device_state/` | unlock via HTTP changes MQTT + SSH view | **Done** |
| 4 | Higher-interaction shell: fake FS, URL capture, exec requests | `common/fakeshell.py` | Mirai chain runs without "not found"; URLs stored | **Done** |
| 5 | HTTP device routes (CCTV panel, lock REST, sensor HMI), logs every path | `http_honeypot/` | scanner path probes all logged | **Done** |
| 6 | MQTT fixes + live telemetry from Redis; control topics change state | `mqtt_honeypot/` | `mosquitto_pub -t lock/cmd -m unlock` changes state | **Done** |
| 7 | Session correlation + GeoIP | `intel/correlate.py`, `intel/geo.py` | `/api/sessions` returns country/city/lat/lon, protocols | **Done** |
| 8 | MITRE ATT&CK tagging by rule | `intel/mitre.py` | each detection row has technique IDs on dashboard | **Done** |
| 9 | Telegram alert with 10-min dedupe + threshold config | `alerts/notifier.py`, `alerts/alerts.yaml` | a brute-force run sends exactly one message | **Done** (e-mail added too) |
| 10 | Dashboard: Leaflet map, device cards, MITRE column, RTSP in charts | `dashboard/dist/index.html` | map shows markers for attacking IPs | **Done** |
| 11 | Outbound blocking + API not public | `deploy/firewall.sh`, compose, nginx | outbound request from inside a honeypot fails | **Done** |

## 4. Module-by-module coverage vs. scope

| Scope module | 60% coverage | What exists now |
|---|---|---|
| M1 Device Emulation | ~85% | 3 devices, RTSP camera, lock REST API, sensor HMI, shared state, fake filesystem, vulnerability profiles. *(100%: richer firmware quirks)* |
| M2 Multi-Protocol Handler | ~90% | 5 protocol servers, unified session registry, SSH exec, HTTPS. *(100%: more protocol edge-cases)* |
| M3 Detection & Logging | ~75% | unified events, SSH+Telnet command capture, URL/file capture with SHA-256, full-text search, time-windowed rules. *(100%: YARA scan, PCAP sidecar)* |
| M4 Threat Intelligence | ~70% | correlation, GeoIP, MITRE tags, campaigns, IOC store. *(100%: STIX 2.1 export, scheduled reports, external reputation feeds)* |
| M5 Dashboard | ~75% | map, device cards, charts, MITRE, feed, IOCs, search, CSV export. *(100%: WebSocket live-push, PDF export, AI panel)* |
| M6 Alerts | ~85% | Telegram + e-mail, thresholds, dedup/escalation, alert log. *(100%: per-user routing)* |
| M7 Deployment | ~75% | hardened compose, outbound firewall, Redis, non-root/read-only/cap-drop, pinned deps, CI. *(100%: Prometheus/Grafana, automated pg_dump backups)* |
| M8 AI/ML | 0% (by plan) | **not started** — this is the 100% milestone. Training data is already being collected. |

## 5. How the 6 ML classes are already prepared

Each detection rule emits a label that maps onto one of the planned classifier classes, so the
rule output is the weak-label source for Module 8:

| Planned ML class | Rule detections that produce it |
|---|---|
| brute-force | `BRUTE_FORCE`, `CREDENTIAL_STUFFING` |
| malware delivery | `MALWARE_DELIVERY`, `MIRAI_SIGNATURE` |
| botnet C2 | `BOTNET_C2`, `ICS_UNAUTHORIZED_COMMAND` |
| port scan | `RECONNAISSANCE`, `WEB_SCAN`, `RTSP_ROUTE_ENUM` |
| protocol exploit | `PROTOCOL_EXPLOIT` |
| normal / benign | sessions with none of the above |

`tests/simulate_attacks.py` generates labelled traffic for every one of these classes.

## 6. Agreed scope simplifications (confirm with supervisor)

The scope document plans 35 weeks; the practical build uses lighter tools that keep each
objective. Get these signed off so the evaluators judge the agreed version:

| Scope promise | Built instead | Why defensible |
|---|---|---|
| React 18 + TS + Next.js + shadcn + Zustand | single-file dashboard (Chart.js + Leaflet) | same features; a rewrite adds no capability |
| RTSP with real GStreamer H.264 stream | RTSP signalling + auth capture + valid SDP | attackers brute-force RTSP auth; stream content is secondary |
| Kubernetes (K3s) | Docker Compose only | single-host research deployment (LI-11) |
| Celery job queue | background worker loop | low volume |
| ClamAV + VirusTotal + AlienVault OTX | (100%) YARA; VirusTotal by hash if time | YARA covers malware-family ID |
| Slack + Telegram + e-mail | Telegram + e-mail | two channels prove the design |
| PyTorch *and* TensorFlow | (100%) scikit-learn + XGBoost | fewer heavy deps, smaller images |

## 7. Supervisor-name fix

The scope document used both "Mrs. Sara Ali" and "Mrs. Sara Naveed", and the old README said
"Sara Ali". This repository uses **Mrs. Sara Naveed** consistently (README, docs). Confirm the
correct name and apply it to the scope document too.
