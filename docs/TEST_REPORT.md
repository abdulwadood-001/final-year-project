# HoneyBot-IoT — Test Report (70% milestone, v0.7)

All results below were produced on the v0.7 code. The Docker results come from a full
`docker compose up --build` deployment (Docker 29, iptables firewall backend) with the
bundled simulator as the traffic source.

## 1. Automated tests

| Suite | Command | Result |
|---|---|---|
| Backend, with PostgreSQL 16 + Redis 7 | `pytest -q` | **78 passed** |
| Backend, no database / no Redis | `pytest -q` | **45 passed, 33 skipped** in 0.3 s (DB tests skip cleanly) |
| Dashboard unit tests | `cd dashboard && npm test` | **17 passed** (routing incl. the detail-route fix, session replay, helpers) |
| Dashboard type-check (strict TS) | `npm run typecheck` | 0 errors |
| Dashboard lint | `npm run lint` | 0 problems |
| Shell scripts | `bash -n` / `sh -n` | OK |

Backend coverage by file:
- `tests/test_parsers.py` (31): MQTT variable-length integers and parsing, RTSP Digest,
  fake-shell behaviour, MITRE mapping, credentials.
- `tests/test_api.py` (12): API smoke tests.
- `tests/test_v07.py` (35):
  - NUL sanitising; scheme-less downloads (wget, curl, busybox wget, tftp)
  - ELF architecture sniffing; shell-drop capture into a read-only quarantine; YARA family identification
  - sensor-config whitelist; sensor history; Telnet IAC split across TCP reads; PDF rendering; weak-label priority
  - DB-backed: NUL rows stored, capture indexed and YARA-scanned, MALWARE_FAMILY detection, idempotent IOC hits,
    **STIX bundle validated by the OASIS `stix2` library**, ML dataset labels, every new endpoint,
    attacker/session detail, PDF/STIX/metrics/CSV exports, `api_token` never exposed,
    **WebSocket relays live events**, report severity ranking.

## 2. Deployment test (`docker compose up --build`)

| Check | Result |
|---|---|
| 13 long-running services + `auth-init` | all **Up**; `db`, `api`, `firewall` healthy; `auth-init` exited 0 |
| Honeypots wait for the firewall | honeypots start only after the `firewall` healthcheck passes |
| Schema auto-migration | API and intel log `schema up to date`; also verified against an existing v0.6 DB and a SQL_ASCII DB |
| Dashboard on :80 (E4) | `401` without or with a wrong password, `200` with the configured one; SPA deep links (`/attackers/<ip>`) return 200 |
| API not published | host port 5000 closed; API reachable only through Nginx |
| Generated password (E6) | `docker compose logs auth-init` prints a random 20-character password when `DASHBOARD_PASSWORD` is empty; stored as bcrypt |
| Security headers | CSP `default-src 'self'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy` |
| Service heartbeats | 7/7 services online |

## 3. Network isolation (E5), real iptables

From inside `honeybot_ssh` (honeynet):

| Destination | Result |
|---|---|
| `1.1.1.1:80` (internet) | blocked (timeout) |
| `8.8.8.8:53` (external DNS) | blocked |
| `192.168.1.1:22` (LAN) | blocked |
| `db:5432` (internal) | reachable |

The `DOCKER-USER` DROP counter went from 0 to 9 and `HONEYBOT-OUTBOUND-DROP` lines appear in
the kernel log. The intel container, which is not on the honeynet and needs egress for
Telegram/SMTP, did **not** increase the counter. Script checks: `apply` is idempotent
(re-applying leaves exactly 5 rules), `check` detects a deleted rule, `ensure` repairs it,
and `flush` removes only HoneyBot rules.

## 4. End-to-end detection (simulator inside the honeynet)

`docker compose --profile sim run --rm attacker` (10 scenarios) followed by one intel pass
produced detections in all 15 rule classes:

```
BOTNET_C2 · BRUTE_FORCE · CREDENTIAL_COMPROMISE · CREDENTIAL_STUFFING · DENIAL_OF_VIEW
ICS_UNAUTHORIZED_COMMAND · MALWARE_DELIVERY · MIRAI_SIGNATURE · MULTI_PROTOCOL_ATTACK
POST_EXPLOITATION · PROTOCOL_EXPLOIT · RECONNAISSANCE · RTSP_ROUTE_ENUM
VIDEO_STREAM_ACCESS · WEB_SCAN
```

The 16th class, `MALWARE_FAMILY` (YARA on a captured sample), is covered by
`test_detections_include_malware_family`. Cross-protocol state stayed consistent: the sensor
threshold changed over Telnet was reflected in Redis, on the device page, over MQTT and in
the change log.

## 5. Dashboard in a real browser (headless Chromium through Nginx with basic auth)

Every page was opened against the live stack:

| Page | Result |
|---|---|
| Overview, Attackers, attacker detail, Detections, Devices, CCTV / Smart lock / Sensor detail, Sessions, session replay, Malware, IOCs & MITRE, Reports & Alerts, Search, 404 | rendered with live data; **0 console errors, 0 failed API calls** |
| WebSocket | sidebar shows **live** (connected through Nginx `/api/ws`) |
| PDF report download | HTTP 200, valid `%PDF` |
| STIX download | 59 objects: identity, indicator, sighting, attack-pattern, relationship |

## 6. Backup and recovery

`docker compose run --rm backup once` writes a dump, a sample archive and a `.sha256` file.
`verify` checked both files (OK). `restore <stamp>` verified the checksums first, then
restored the database. Event and detection counts were identical afterwards.

## 7. Security lint

`bandit -r . -x ./tests,./dashboard -lll` → 0 high-severity findings. Medium findings are the
reviewed false positives listed in v0.6, for example interval literals cast to `int()` in
SQL, and `0.0.0.0` binds that honeypots need.

## 8. Not yet tested (100% milestone)

Load testing (events/s), ML model evaluation (accuracy, F1, confusion matrix), a
real-internet baseline on a VPS, and live Telegram/SMTP delivery with real credentials. The
delivery code paths are covered, and in the lab the `disabled` status is recorded.
