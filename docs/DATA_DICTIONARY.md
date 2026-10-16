# HoneyBot-IoT — Data Dictionary (v0.7 schema, `init.sql`)

> **For the SDS (§5.1):** the SDS data dictionary still describes the original design tables
> (`honeypot_sessions`, `credential_attempts`, `command_records`, `file_captures`,
> `threat_events`). The implementation uses a **unified event store**: one `events` table
> for every interaction on every protocol. This keeps the high-volume write path to a single
> indexed table and makes cross-protocol queries trivial. The mapping below lets the SDS
> table be updated 1:1.

| SDS entity | Implemented as |
|---|---|
| `honeypot_sessions` | `sessions` |
| `credential_attempts` | `events WHERE event_type='auth'` (views `ssh_attempts`, `telnet_attempts`, …) |
| `command_records` | `events WHERE event_type='command'` (`payload` holds the emulated output) |
| `file_captures` | `file_captures` (same name, v0.7) |
| `threat_events` | `detections` (MITRE IDs) + `attackers` (GeoIP, threat score) + `iocs`; STIX produced on demand |
| `threat_events.attack_class / confidence / anomaly_score / risk_score / llm_narrative` | Module 8 (100% milestone); weak labels already exported by `ml/features.py` |

## Tables

### sessions — one row per attacker connection
| Column | Type | Notes |
|---|---|---|
| session_id | UUID PK | generated on connect |
| ip, src_port, dst_port | TEXT, INT, INT | attacker address, honeypot port |
| device | TEXT | `cctv` · `smartlock` · `sensor` |
| protocol | TEXT | `SSH` · `Telnet` · `HTTP` · `MQTT` · `RTSP` |
| started_at, ended_at | TIMESTAMPTZ | `ended_at` NULL while active |
| auth_attempts, login_success, username, commands | INT, BOOL, TEXT, INT | written on close |
| client_version | TEXT | SSH banner / HTTP user-agent / MQTT client id / RTSP UA |
| meta | JSONB | extra connection metadata |

### events — every interaction (unified store)
| Column | Type | Notes |
|---|---|---|
| id | BIGSERIAL PK | |
| ts | TIMESTAMPTZ | indexed with ip, type, protocol |
| session_id | UUID FK → sessions | `ON DELETE CASCADE` |
| ip, src_port, device, protocol | | denormalised for fast filtering |
| event_type | TEXT | connect, disconnect, auth, command, http_request, mqtt_publish, mqtt_subscribe, rtsp_request, rtsp_route_probe, download_attempt, exec_attempt, file_write, file_upload, file_capture, state_change, stream_access, malformed, … |
| username, password, success | TEXT, TEXT, BOOL | for `auth` |
| command | TEXT | shell command / HTTP request line / RTSP request (full-text indexed) |
| payload | TEXT | command output, request body, MQTT payload, URL (full-text indexed) |
| raw | JSONB | protocol-specific fields (topic, status, sha256, method, …) |

NUL bytes are stored as the literal text `\x00` (see `common.db.sanitize`).

### file_captures — quarantined malware samples (v0.7)
| Column | Type | Notes |
|---|---|---|
| id | BIGSERIAL PK | one row per sighting |
| ts, session_id, ip, protocol, device | | where it came from |
| source | TEXT | `http_upload` · `http_body` · `ssh_stdin` · `shell_write` · `mqtt_payload` |
| filename | TEXT | path or upload name supplied by the attacker |
| sha256, md5 | CHAR(64), CHAR(32) | sha256 indexed |
| size | BIGINT | capped at `CAPTURE_MAX_BYTES` (10 MB) |
| mime_type, arch | TEXT | magic-byte sniffing; ELF CPU architecture, e.g. `ARM (32-bit LE)` |
| storage_path | TEXT | `/app/captures/<sha[:2]>/<sha>.bin`, mode 0400, never exposed by the API |
| yara_result | TEXT | `CLEAN` · comma-separated families · `UNAVAILABLE` · NULL = not scanned yet |
| yara_matches | TEXT[] | rule names |
| scanned_at | TIMESTAMPTZ | set by the intel engine |

### detections — rule-engine classifications
`id, timestamp, ip, attack_type, severity (LOW|MEDIUM|HIGH|CRITICAL), protocol, device, details,
mitre TEXT[], mitre_names TEXT[], session_id, dedupe_key UNIQUE, alerted`

### attackers — per-IP cross-protocol correlation
`ip PK, first_seen, last_seen, sessions, events, auth_attempts, auth_success, commands,
downloads, protocols[], devices[], country, country_code, city, lat, lon,
geo_source (maxmind|dbip|demo|private|unknown), campaign_id, threat_level, threat_score 0-100,
attack_types[]`

### campaigns — IPs sharing a credential wordlist
`campaign_id PK, fingerprint, first_seen, last_seen, ips[], credentials[], description`

### iocs / ioc_sightings — indicators of compromise
`iocs(type url|domain|ipv4|sha256, value, first_seen, last_seen, source_ip, session_id, protocol,
context, hits)`. `hits` = number of distinct rows in
`ioc_sightings(source event|detection|capture, source_id, type, value)`.

### alerts — every notification decision
`ts, detection_id, ip, attack_type, severity, channel (telegram|email|dedupe), status
(sent|suppressed|failed|disabled), message, error`. Daily and weekly reports are logged here
as `DAILY_REPORT` / `WEEKLY_REPORT`.

### intel_state — engine key/value store
`key PK, value, updated_at` (e.g. `last_daily_report`).

## Redis keys
| Key | Purpose |
|---|---|
| `device:{cctv,smartlock,sensor}` | shared device state (hash) |
| `history:sensor` | last 720 telemetry samples (list, 5 s apart) |
| `changes:{device}` | last 200 attacker-made state changes (list) |
| `hb:{service}` | service heartbeat (expires after 30 s) |
| channel `honeybot:events` / `honeybot:detections` / `honeybot:state` | live push to the dashboard WebSocket |
