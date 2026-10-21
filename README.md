# HoneyBot-IoT — High-Interaction Multi-Protocol IoT Honeypot

**COMSATS University Islamabad — BS Cyber Security (2023–2026) Final Year Project**
Abdul Wadood (CIIT/SP23-BCT-001/ISB) · Abdul Rahman (CIIT/SP23-BCT-003/ISB)
Supervisor: **Mrs. Sara Naveed**

> **Milestone: 70% (v0.7) + device-machine build (v0.8).** Three emulated IoT devices (CCTV
> camera, smart lock, industrial sensor) over six protocols (SSH, Telnet, HTTP/HTTPS, MQTT,
> RTSP, Modbus/TCP); a unified event store; rule-based detection with MITRE ATT&CK; malware
> capture with YARA; STIX 2.1 export; PDF threat reports; a React/TypeScript SOC dashboard
> with WebSocket live push; automatic network isolation; backups; and Prometheus/Grafana
> monitoring. Module 8 (AI) has started: the labelled ML dataset is produced live.
>
> **New in v0.8:** each device now runs as its **own machine** (container) exposing only its
> protocols; a successful SSH/Telnet login drops the attacker into a **real but restricted
> BusyBox shell** in a throw-away, network-less sandbox that is wiped at logout; an
> industrial **Modbus/TCP** service; and emulation of **real IoT web CVEs** (Hikvision
> CVE-2021-36260, Dahua bypass, GPON, Realtek, Huawei) whose injected commands run in the
> device's shell. See **`docs/DEVICE_MACHINES.md`**; the 70% status is in
> **`docs/MILESTONE_70.md`**.

---

## What it does

Each device is its own machine (container) with its own hostname, IP and MAC, exposing only
its own protocols:

| Device machine | Protocols | What attackers get |
|---|---|---|
| CCTV camera (IPC-HFW2431S) | RTSP :554, HTTP :8080 / HTTPS :8443 | Boa web panel with login, live view and firmware upload; RTSP Basic and Digest auth with a valid H.264 SDP; **real IoT CVE endpoints** |
| Smart lock (SL-200) | SSH :2222, HTTP REST :8081, MQTT :1883 | **Real restricted BusyBox shell** with `lockctl`; token REST API; `lock/cmd` topic. Unlocking on one protocol is visible on all |
| Industrial sensor (ISN-4000) | Telnet :2323, Modbus/TCP :502, MQTT :1883, HTTP HMI :8082 | **Real restricted BusyBox shell** with `sensorctl`; live telemetry; writable alarm thresholds, also over Modbus registers |

On a successful SSH/Telnet login the attacker gets a **real but heavily restricted shell** in
a throw-away device container (no network, read-only root, CPU/memory/process/time limits,
wiped at logout). Set `SHELL_MODE=fake` for the in-process emulated shell. See
**`docs/DEVICE_MACHINES.md`**.

Every interaction is stored as one row in `events`. Every 30 s the threat-intelligence engine:
- YARA-scans newly captured samples;
- classifies activity into 16 attack types tagged with MITRE ATT&CK (Enterprise and ICS);
- correlates attackers across protocols, adding GeoIP, credential-reuse campaigns, IOCs and a threat score;
- alerts on Telegram and e-mail with thresholds and de-duplication.

## Quick start

```bash
cp .env.example .env          # edit it: at least POSTGRES_PASSWORD (and DATABASE_URL), DASHBOARD_PASSWORD
docker compose up -d --build  # builds the honeypots, API, dashboard and firewall images
docker compose ps             # every service should be Up / healthy
```

Open **http://localhost/** and log in as `admin` with your `DASHBOARD_PASSWORD`. If you left it
empty, a random password was generated:

```bash
docker compose logs auth-init
```

Optional, on a real host:

```bash
deploy/get_geoip.sh && docker compose restart api intel      # real GeoIP (offline DB)
docker compose --profile monitoring up -d                     # Grafana http://127.0.0.1:3000, Prometheus :9090
```

### Run the demo traffic

```bash
docker compose --profile sim run --rm attacker                # 13 attack scenarios from inside the honeynet
python3 tests/simulate_attacks.py --host 127.0.0.1 --confirm-own-honeypot   # or from your machine (all ports on localhost)
```

Detections appear within 30 s; **Detect now** on the overview page runs a pass at once.

## Network isolation (always on)

The `firewall` service (host network, `CAP_NET_ADMIN`) inserts tagged rules into Docker's
`DOCKER-USER` chain. Every connection a honeypot tries to open is dropped and logged as
`HONEYBOT-OUTBOUND-DROP`, except replies to attackers and traffic to the stack's own
subnets. The rules are re-checked every 30 s and survive Docker restarts. Honeypots start
only after the firewall healthcheck passes. To inspect them:

```bash
docker compose exec firewall firewall.sh status
```

> Rootless Docker has no `DOCKER-USER` chain. There you would have to set `HONEYBOT_FIREWALL=off`,
> which runs **without isolation**. Never expose such a setup to the internet.

## Dashboard

| Page | Shows |
|---|---|
| Overview | live counters, attack timeline, offline world map with heat layer, top threats, live event feed |
| Attackers / attacker detail | ranked profiles, campaigns, credentials, commands; full per-IP history, detections, IOCs, samples |
| Detections | live feed with severity and type filters, MITRE ranking |
| Devices / device detail | shared device state, sensor history chart and thresholds, lock/unlock log, probed camera stream paths, service health |
| Sessions / session replay | every connection; attacker input vs honeypot output, with MITRE tags per command |
| Malware | quarantined samples, YARA families, CPU architectures |
| IOCs & MITRE | indicators (hits = distinct sightings), STIX 2.1 download, technique coverage |
| Reports & Alerts | analyst summary, PDF / STIX / CSV / ML-dataset downloads, alert delivery log |

Source and development instructions: `dashboard/README.md`.

## Key API endpoints (all under `/api`, behind the dashboard login)

| Endpoint | Purpose |
|---|---|
| `GET /stats`, `/timeline`, `/attacks/recent`, `/map` | overview data |
| `GET /attackers/top`, `/attackers/{ip}` | attacker ranking and full profile |
| `GET /detections`, `/mitre/summary`, `/iocs`, `/campaigns`, `/alerts` | threat intel |
| `GET /devices`, `/devices/{device}` | device state, history, change log |
| `GET /sessions/list`, `/sessions/{id}` | sessions and replay |
| `GET /captures`, `/captures/{sha256}` | malware samples (metadata only) |
| `GET /search?q=` | full-text search over commands and payloads, plus IP and credential |
| `GET /export/events.csv`, `/export/stix`, `/report`, `/report.pdf` | exports and reports |
| `GET /ml/summary`, `/ml/dataset.csv` | Module 8 labelled dataset |
| `GET /metrics` | Prometheus exposition |
| `POST /detect` | run an intel pass now |
| `WS /ws` | live push: events, detections, device state |

## Backups

The `backup` service writes `pg_dump` and a sample archive to `./backups` every
`BACKUP_INTERVAL_HOURS` (SHA-256 verified, keeps `BACKUP_KEEP` sets).

```bash
docker compose run --rm backup once | list | verify <stamp> | restore <stamp>
```

A restore verifies the checksums first, then restores the database. Samples are restored
when the `captures` volume is mounted read-write.

## Repository layout

```
common/           db.py (unified logging) · state.py (device state) · fakeshell.py · capture.py · creds.py · schema.py
                  cmdintel.py (command parsing) · realshell.py (real-shell client + devctl bridge)
device_machine.py one-container-per-device supervisor
vm/               Dockerfile + rootfs/ for the per-device machine images (real shell)
sandbox/          sandbox.py — starts/destroys the throw-away device containers (Docker API)
ssh_honeypot/ telnet_honeypot/ http_honeypot/ (+ exploits.py) mqtt_honeypot/ rtsp_honeypot/ modbus_honeypot/ device_state/
intel/            engine.py · rules.py · mitre.py · correlate.py · geo.py · yara_scan.py · yara_rules/ · stix.py · report.py
alerts/           notifier.py · alerts.yaml
api/              api.py (REST + WebSocket)
ml/               features.py (Module 8 dataset)
dashboard/        React + TypeScript SPA (built into the Nginx image)
deploy/           firewall.sh · auth-init.sh · backup.sh · get_geoip.sh
monitoring/       prometheus.yml · alerts.yml · grafana/
nginx/            nginx.conf
tests/            pytest suites · simulate_attacks.py
docs/             MILESTONE_70 · TEST_REPORT · ARCHITECTURE · DATA_DICTIONARY · MODEL_CARD · MILESTONE_60
```

## Safety & ethics

This is a **research tool for a controlled, isolated environment**, not for production
networks (scope limitation LI-11).

- The honeypot is **passive**. Captured download URLs are logged as IOCs but **never
  fetched**. Uploaded samples are stored read-only (0400) in a quarantine volume and **never
  executed**. The API never serves sample files.
- Outbound isolation is enforced automatically (see above).
- Containers run **non-root, `cap_drop: ALL`, `no-new-privileges`**, with CPU/memory limits;
  honeypots also run with a read-only root filesystem.
- No credential is stored in the repository. The dashboard hash is generated at start-up
  (bcrypt).
- Do not publish raw attacker IPs or credentials outside your report. Handling of captured
  samples must comply with Pakistan's **PECA 2016** and applicable law (LI-10). Get supervisor
  approval before exposing the system to the internet.
- `tests/simulate_attacks.py` is a test harness. Only ever point it at a honeypot you operate.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q                              # 78 tests (DB-backed ones skip automatically without PostgreSQL)
cd dashboard && npm ci && npm test && npm run build
bandit -r . -x ./tests,./dashboard -ll
```

Results and the end-to-end Docker test are in **`docs/TEST_REPORT.md`**.
