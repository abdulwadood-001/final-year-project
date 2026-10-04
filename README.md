# HoneyBot-IoT — High-Interaction Multi-Protocol IoT Honeypot

**COMSATS University Islamabad — BS Cyber Security (2023–2026) Final Year Project**
Abdul Wadood (CIIT/SP23-BCT-001/ISB) · Abdul Rahman (CIIT/SP23-BCT-003/ISB)
Supervisor: **Mrs. Sara Naveed**

> **Milestone: 60%.** This build delivers all five protocols across three emulated IoT
> devices, a single unified event store, rule-based threat classification with MITRE
> ATT&CK tagging, GeoIP + cross-session correlation, real-time alerts, and a live
> dashboard. The AI/ML module (Module 8), STIX export, WebSocket live-push,
> Prometheus/Grafana and PCAP capture are the remaining **100%** work.

---

## What it does

HoneyBot-IoT pretends to be three commonly-attacked IoT devices and records everything an
attacker does to them, from the first port scan to post-exploitation commands, then
classifies each attack and shows it on a dashboard in real time.

| Emulated device | Protocols | Port(s) |
|---|---|---|
| **CCTV Camera** | RTSP, HTTP(S) | 554, 8080, 8443 |
| **Smart Lock** | SSH, HTTP REST, MQTT | 2222, 8081, 1883 |
| **Industrial Sensor** | Telnet, MQTT, HTTP | 2323, 1883, 8082 |

All three share **one consistent state** (the Device State Manager): unlock the lock over the
HTTP REST API and the change is visible over MQTT (`lock/status`) and over SSH
(`cat /etc/lock_state`). That cross-protocol coherence is what makes it *high-interaction*.

---

## Quick start

```bash
cp .env.example .env            # then edit .env — at minimum change POSTGRES_PASSWORD
# set a dashboard password:
docker run --rm httpd:alpine htpasswd -nbB admin 'YourStrongPassword' > nginx/.htpasswd

docker compose up --build -d    # starts the whole stack
```

Open the dashboard at **http://localhost/** (log in with the credentials above).

Optional but recommended on a real host — enforce outbound isolation and add GeoIP:

```bash
sudo deploy/firewall.sh         # drop all outbound from the honeypots (inbound-only)
deploy/get_geoip.sh             # download an offline GeoIP city database
docker compose restart api intel
```

### Try it / run the demo

```bash
# from inside the cluster (6 simulated source IPs):
docker compose --profile sim up --build --scale attacker=6

# or from your machine against the local stack:
python3 tests/simulate_attacks.py --host 127.0.0.1
```

Then watch the dashboard, or force an immediate classification pass:
`curl -u admin:... -X POST http://localhost/api/detect`.

---

## Architecture

```
                         Internet / Attacker
                                 │
        ┌────────────────────────▼─────────────────────────┐
        │  honeynet (bridge)   — outbound DROP via iptables │
        │  SSH:2222  Telnet:2323  HTTP:8080/1/2  HTTPS:8443 │
        │  MQTT:1883  RTSP:554     device_state (internal)  │
        └────────────────────────┬─────────────────────────┘
                                  │ every interaction → log_event()
        ┌─────────────────────────▼────────────────────────┐
        │  backnet (internal only)                          │
        │  PostgreSQL  ◄──  Redis (state + event bus)       │
        │      ▲   ▲                                         │
        │      │   └── intel engine (rules→MITRE→correlate→ │
        │      │         GeoIP→alerts: Telegram / e-mail)    │
        │   FastAPI API ──  Nginx (basic auth) ── Dashboard │
        └───────────────────────────────────────────────────┘
                                  │
                           http://localhost/  (the ONLY exposed web port)
```

Honeypots never talk to the database directly — they call `common.db.log_event()`, which
writes through one background thread into the unified `events` table and publishes each
event on Redis. The API is **not** published to the host; only Nginx is. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and the database ER model.

---

## Repository layout

```
honeybot-full/
├── common/            shared library
│   ├── db.py          unified event logging (Session, log_event) + async writer
│   ├── state.py       Device State Manager (Redis-backed, in-memory fallback)
│   ├── fakeshell.py   high-interaction BusyBox-style shell (SSH + Telnet)
│   └── creds.py       per-device default-credential (vulnerability) profiles
├── ssh_honeypot/      SSH — Smart Lock (Paramiko, exec + shell, brute-force delay)
├── telnet_honeypot/   Telnet — Industrial Sensor (asyncio, IAC negotiation)
├── http_honeypot/     HTTP/HTTPS — 3 device web UIs + lock REST API
├── mqtt_honeypot/     MQTT 3.1.1 broker (correct var-length parsing, live telemetry)
├── rtsp_honeypot/     RTSP — CCTV (OPTIONS/DESCRIBE/SETUP/PLAY, Basic+Digest auth)
├── device_state/      state simulation loop (telemetry, alarms, auto re-lock)
├── intel/             rules.py · mitre.py · geo.py · correlate.py · engine.py
├── alerts/            notifier.py (Telegram + e-mail) + alerts.yaml (thresholds/dedupe)
├── api/               FastAPI REST backend (dashboard + CSV export + search)
├── dashboard/dist/    single-file dashboard (Chart.js + Leaflet map)
├── deploy/            firewall.sh (outbound isolation) · get_geoip.sh
├── tests/             pytest suite + simulate_attacks.py (traffic generator)
├── init.sql           PostgreSQL schema (events, sessions, attackers, detections, iocs…)
├── docker-compose.yml  full stack (hardened: non-root, read-only, cap_drop ALL)
└── docs/              ARCHITECTURE.md · MILESTONE_60.md · TEST_REPORT.md · MODEL_CARD.md
```

---

## Key API endpoints

All are served under `/api/` through Nginx (basic auth). Swagger: `GET /api` isn't exposed
publicly; the endpoints are documented in `docs/ARCHITECTURE.md`.

| Endpoint | Purpose |
|---|---|
| `/api/stats` | protocol/session/event/detection totals |
| `/api/attacks/recent` | unified live event feed |
| `/api/detections` | rule detections + MITRE technique IDs |
| `/api/sessions` | per-attacker correlation (geo, protocols, threat score, campaign) |
| `/api/sessions/{id}` | full event timeline of one session, per-command MITRE tags |
| `/api/map` · `/api/countries` | attack-origin map data |
| `/api/mitre/summary` | ATT&CK technique frequency |
| `/api/iocs` · `/api/campaigns` | indicators of compromise, grouped campaigns |
| `/api/search?q=` | full-text search over commands & payloads |
| `/api/export/events.csv` | raw event export (CSV) |
| `/api/detect` (POST) | run a detection pass now |

---

## Safety & ethics

This is a **research tool for a controlled, isolated environment** — not for production
networks (scope limitation LI-11).

- The honeypot is **passive**: captured download URLs are logged as IOCs but **never
  fetched**, and "uploaded" files are stored, never executed.
- `deploy/firewall.sh` enforces **inbound-only** networking so a compromised container can
  never reach the internet or be used to attack anyone else.
- Containers run **non-root, read-only, `cap_drop: ALL`, `no-new-privileges`** with CPU/memory
  limits.
- Do not publish raw attacker IPs or credentials outside your report. Handling of captured
  samples must comply with Pakistan's **PECA 2016** and applicable law (LI-10); get
  supervisor approval before exposing the system to the internet.
- `tests/simulate_attacks.py` is a test harness — only ever point it at a honeypot you operate.

---

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q                        # unit tests (parsers, fake shell, MITRE, creds)
bandit -r . -x ./tests -ll       # security lint (findings reviewed in docs/TEST_REPORT.md)
```

See **`docs/MILESTONE_60.md`** for exactly how each deliverable maps to the scope document,
and **`docs/TEST_REPORT.md`** for the verification evidence.
