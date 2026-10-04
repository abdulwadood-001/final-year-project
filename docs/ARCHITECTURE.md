# HoneyBot-IoT — Architecture

## 1. Design principles

1. **One way in, one way out of the data layer.** Honeypots never touch PostgreSQL directly.
   They create a `common.db.Session` and call `log_event()`; a single background writer
   thread serialises all writes (session row before its events) and publishes each event on
   Redis. A slow database therefore never blocks an attacker connection.
2. **One consistent device, many protocols.** The Device State Manager keeps each device's
   state in a Redis hash. SSH, HTTP and MQTT all read and mutate the same state, so the
   attacker sees a coherent device regardless of protocol — the core of *high interaction*.
3. **Inbound-only and least privilege.** The honeypots sit on a bridge whose outbound NEW
   connections are dropped by iptables; containers are non-root, read-only, `cap_drop: ALL`.
   Only Nginx (basic auth) is exposed.

## 2. Component diagram

```
                              Internet / Attacker
                                      │
   ┌──────────────────────────────────▼──────────────────────────────────────┐
   │ honeynet (172.31.66.0/24)   outbound NEW → DROP (deploy/firewall.sh)      │
   │                                                                           │
   │  ssh_honeypot   telnet_honeypot   http_honeypot   mqtt_honeypot   rtsp_*  │
   │   :2222 SSH       :2323 Telnet    :8080/1/2/8443   :1883 MQTT    :554 RTSP│
   │  (SmartLock)      (Sensor)        (CCTV+Lock+Sen)  (Lock+Sensor) (CCTV)   │
   │       │               │                │               │           │     │
   │       └───────────────┴────── common.db.Session.log_event() ───────┘     │
   └───────────────────────────────────┬───────────────────────────────────── ┘
                                        │ (writes + Redis publish)
   ┌────────────────────────────────────▼───────────────────────────────────── ┐
   │ backnet (internal: true)                                                   │
   │                                                                            │
   │   Redis  ◄── device_state (simulation loop) ──►  Redis                     │
   │     ▲   device:cctv / device:smartlock / device:sensor  +  honeybot:events │
   │     │                                                                      │
   │   PostgreSQL 16  ◄───────────────┬──────────────────────────────┐         │
   │   events/sessions/attackers/     │                              │         │
   │   detections/iocs/campaigns/     │                              │         │
   │   alerts                         │                              │         │
   │     ▲                     intel/engine.py                   api/api.py     │
   │     │                 rules→MITRE→correlate→GeoIP→alerts     (FastAPI)      │
   │     │                     (every 30 s)                          │          │
   │     │                          │                               │          │
   │     │                   alerts/notifier.py                 Nginx :80       │
   │     │                   Telegram + e-mail                 (basic auth) ────┼──► Dashboard
   └──────────────────────────────────────────────────────────────────────────┘
```

## 3. Database schema (ER summary)

```
sessions(session_id PK) 1───∞ events(session_id FK)
   session_id, ip, src_port, dst_port, device, protocol, started_at, ended_at,
   auth_attempts, login_success, username, commands, client_version, meta(jsonb)

events(id PK)
   ts, session_id FK, ip, src_port, device, protocol, event_type,
   username, password, success, command, payload, raw(jsonb)
   event_type ∈ {connect, disconnect, auth, command, http_request,
                 mqtt_connect/publish/subscribe, rtsp_request, download_attempt,
                 exec_attempt, file_write, file_upload, state_change, malformed, …}
   GIN index on to_tsvector(command || payload)  → full-text search

attackers(ip PK)        one row per source IP (correlation + GeoIP + threat score)
campaigns(campaign_id PK)  IPs grouped by shared credential sets
detections(id PK)       ip, attack_type, severity, protocol, device, details,
                        mitre[], mitre_names[], session_id, dedupe_key UNIQUE
iocs(id PK)             (type, value) UNIQUE — url / domain / ipv4 / sha256
alerts(id PK)           notification log: channel, status(sent/suppressed/…), error

Backwards-compatible VIEWS: ssh_attempts, telnet_attempts, http_attempts,
mqtt_attempts, rtsp_attempts  (so older queries keep working).
```

## 4. Event lifecycle

```
attacker connects ─► Session(proto, device, ip)             → sessions row + 'connect' event
attacker logs in  ─► session.auth(user, pass, ok)           → 'auth' event (+ delay if failed)
attacker runs cmd ─► FakeShell.run(line) → session.command  → 'command' event
                     wget URL seen        → 'download_attempt' (URL stored, NEVER fetched)
                     ./x executed         → 'exec_attempt'
attacker unlocks  ─► STATE.lock_action()  → 'state_change'   (visible to all protocols)
disconnect        ─► session.close()      → 'disconnect' + session row updated
                              │
   intel/engine.py (every 30 s):
     rules.run_rules()  → detections (time-windowed)
     mitre.techniques_for() → ATT&CK IDs stored on each detection
     correlate.run()    → attackers, GeoIP, campaigns, IOCs
     notifier.notify()  → Telegram/e-mail (threshold + dedupe) → alerts log
```

## 5. Why these technology choices (viva prep)

- **PostgreSQL, not Elasticsearch** — relational integrity between sessions/events/detections,
  JSONB for the flexible `raw` column, and a GIN full-text index gives search without a second
  datastore to run and secure.
- **Redis** — sub-millisecond shared device state across processes, plus a pub/sub event bus
  that the 100% WebSocket feed will consume. In-memory fallback keeps unit tests dependency-free.
- **Paramiko** — mature SSH server interface; lets us capture both shell and `exec` channels.
- **asyncio for Telnet & RTSP** — many idle attacker sockets, little CPU; a thread-per-connection
  model is used only for SSH (Paramiko) and MQTT where it is simpler.
- **Rule engine before ML** — the rules are explainable, need no training data, and their output
  becomes the weak labels for the Module-8 classifier. The viva answer to "isn't the model just
  learning your rules?" is: compare against this rule baseline and show the cases where they differ.

## 6. Extending to 100%

- **M8 AI/ML** — feature extraction from `events` per session → XGBoost classifier (6 classes),
  Isolation Forest anomaly score, LLM narrator, risk score; served from a `ml_api` container that
  the intel engine calls when a session closes.
- **STIX 2.1 export** — new `/api/export/stix` building a bundle from the `iocs` table.
- **WebSocket** — FastAPI endpoint subscribing to the existing `honeybot:events` Redis channel.
- **PCAP** — a `tcpdump` sidecar sharing each honeypot's network namespace.
- **Prometheus/Grafana** — cAdvisor + node metrics; the Device Status cards already model the idea.
