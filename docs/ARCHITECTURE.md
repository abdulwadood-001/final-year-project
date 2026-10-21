# HoneyBot-IoT — Architecture (v0.7)

## 1. Design principles

1. **One way in, one way out of the data layer.** Honeypots never touch PostgreSQL directly.
   They create a `common.db.Session` and call `log_event()`. A single background writer thread
   serialises all writes (session row before its events), neutralises NUL bytes, and
   publishes each event on Redis. A slow database never blocks an attacker connection.
2. **One consistent device, many protocols.** The Device State Manager keeps each device's
   state in a Redis hash. SSH, Telnet, HTTP and MQTT read and change the same state, so the
   attacker sees a coherent device whatever protocol they use. This is the core of
   *high interaction*.
3. **Passive and inbound-only.** Download URLs are logged, never fetched. Uploaded samples
   are quarantined read-only, never executed. Every connection a honeypot tries to open is
   dropped by the `firewall` service, and honeypots do not start until it is active.
4. **Least privilege, one public entry.** Containers are non-root, `cap_drop: ALL` and
   `no-new-privileges`; honeypots also run read-only. Only Nginx (bcrypt basic auth) and the
   honeypot ports are exposed. The API is on an internal network.

## 2. Component diagram

```
                                Internet / Attacker
                                        │
 ┌──────────────────────────────────────▼──────────────────────────────────────────┐
 │ honeynet 172.31.66.0/24   every outbound connection → DROP  (firewall service)    │
 │                                                                                   │
 │  ssh_honeypot   telnet_honeypot   http_honeypot        mqtt_honeypot  rtsp_honeypot│
 │  :2222 SSH      :2323 Telnet      :8080/8443 CCTV      :1883 MQTT     :554 RTSP    │
 │  (Smart lock)   (Sensor)          :8081 Lock :8082 HMI (Lock+Sensor)  (CCTV)       │
 │       │              │                │                    │             │         │
 │       └── FakeShell ─┘                │                    │             │         │
 │             └───────── common.db.Session.log_event()  ·  common.capture.store() ──┘
 └──────────────┬────────────────────────────────┬──────────────────────────────────┘
                │ events / sessions               │ samples (0400, never executed)
 ┌──────────────▼────────────────────────────────▼───────────────────────────────────┐
 │ backnet 172.31.67.0/24 (internal: true)                    captures volume (quarantine)│
 │                                                                                    │
 │  Redis ◄── device_state (sensor sim, auto-lock) ── device:* · history:* · changes:* │
 │    │  pub/sub honeybot:events / detections / state                                 │
 │    │                                                                               │
 │  PostgreSQL 16: sessions · events · file_captures · detections · attackers ·       │
 │                 campaigns · iocs · ioc_sightings · alerts · intel_state            │
 │    ▲                           ▲                                                   │
 │    │      intel/engine.py (every 30 s)                       api/api.py (FastAPI)  │
 │    │      YARA → rules → MITRE → correlate/GeoIP/IOCs        REST + /api/ws        │
 │    │      → alerts → daily/weekly PDF report                 STIX · PDF · metrics  │
 │    │              │ egress network                                  │              │
 │  backup service   └──► Telegram / SMTP                              │              │
 │  (pg_dump + samples, SHA-256) → ./backups                           │              │
 └─────────────────────────────────────────────────────────────────────┼──────────────┘
                                                                       │
 ┌─ frontnet ──────────────────────────────────────────────────────────▼──────────────┐
 │  Nginx :80  — bcrypt basic auth, CSP, React SPA (dashboard/), /api + /api/ws proxy   │
 └──────────────────────────────────────────────────────────────────────────────────────┘
   optional --profile monitoring: Prometheus (api /api/metrics + cAdvisor) → Grafana
```

## 3. Data flow of one attack

1. The attacker connects to, say, SSH on :2222. A `Session` row is queued and a `connect`
   event is published on Redis. The dashboard feed updates through the WebSocket.
2. Login attempts are checked against the device's weak-credential profile
   (`common/creds.py`) and logged as `auth` events. Repeated failures from one IP are
   delayed progressively.
3. After a successful login, commands run in `FakeShell`, a BusyBox-like shell with a fake
   filesystem. `wget`/`curl`/`tftp` targets are logged as `download_attempt` (IOC) and
   **never fetched**. Files the attacker writes, or pushes over SSH stdin or `scp`, are
   quarantined by `common/capture.py`.
4. `lockctl unlock`, the REST API or MQTT `lock/cmd` change the shared device state. Every
   protocol now reports the lock as open, and the change is logged.
5. Every 30 s the intel engine YARA-scans new samples, then runs the rules over the time
   windows. It stores detections with MITRE IDs and pushes them to the dashboard. It updates
   per-IP correlation, GeoIP, campaigns and IOCs, and sends de-duplicated Telegram/e-mail
   alerts.
6. Analysts browse the dashboard and export STIX 2.1, CSV, the PDF report or the ML dataset.

## 4. Networks and ports

| Network | Members | Purpose |
|---|---|---|
| honeynet | 5 honeypots (+ simulator) | attacker-facing; outbound blocked |
| backnet (internal) | db, redis, device_state, honeypots, api, intel, nginx, backup, monitoring | data plane, no internet route |
| frontnet | nginx (+ prometheus, grafana) | publishes the dashboard |
| egress | intel | Telegram / SMTP only |

| Host port | Service |
|---|---|
| 2222 / 2323 | SSH / Telnet honeypots |
| 8080 / 8443 / 8081 / 8082 | CCTV web (HTTP/HTTPS) / smart-lock REST / sensor HMI |
| 1883 / 554 | MQTT / RTSP |
| 80 | dashboard (auth) |
| 127.0.0.1:9090 / :3000 | Prometheus / Grafana (monitoring profile, localhost only) |

The full schema is in `docs/DATA_DICTIONARY.md`.
