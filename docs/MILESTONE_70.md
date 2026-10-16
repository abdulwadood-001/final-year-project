# HoneyBot-IoT — 70% Milestone Report (v0.7)

This document maps the v0.7 code to the scope document (SP23-BCT final scope review) and the
SDS, so an evaluator can check every claim against something runnable. The 60% report is
kept in `docs/MILESTONE_60.md` for history.

## 1. Summary

v0.7 does three things on top of the 60% build:

1. **Fixes every defect found in the 60% review**, each with a regression test (§2).
2. **Completes the non-AI scope items that were open at 60%**: malware capture and YARA
   (M3), STIX 2.1 export and scheduled reports (M4), the React/TypeScript dashboard with
   WebSocket live push and PDF export (M5), and Prometheus/Grafana monitoring, automated
   backups and automatic network isolation (M7).
3. **Starts Module 8 (AI)** with WBS 10.1, *ML data preparation & feature engineering*: a
   labelled per-session feature dataset is produced live from the event store (§5).

The whole stack was built and run with `docker compose up` and attacked with the bundled
simulator. Every dashboard page was opened in a real browser with zero console or API errors
(see `docs/TEST_REPORT.md`).

## 2. Defects from the 60% review — all fixed

| # | Defect in v0.6 | Fix in v0.7 | Verified by |
|---|---|---|---|
| E1 | Events containing a NUL byte (binary uploads, `echo -e '\x00…'`, MQTT blobs) were silently dropped: PostgreSQL rejects `0x00` in TEXT/JSONB | `common/db.py` `sanitize()` rewrites NUL as the visible escape `\x00` in every column, JSON field and Redis message | `test_sanitize_nul_everywhere`, `test_nul_rows_are_stored` |
| E2 | Scheme-less downloads (`wget 1.2.3.4/bins/arm7`, `curl -O host/x`) produced no `download_attempt`, so no IOC and no `MALWARE_DELIVERY` | fake shell normalises the URL to `http://…` and logs every download exactly once per command line | `test_downloads_logged` (wget, curl, busybox wget, tftp) |
| E3 | Malware samples were never stored; README claimed they were | new quarantine store `common/capture.py` + `file_captures` table + YARA (§3) | `test_shell_drop_is_captured_and_quarantined`, `test_capture_indexed_and_yara_scanned` |
| E4 | Dashboard unreachable: Nginx published :80 on an `internal: true` network | Nginx moved to a new `frontnet` (and `backnet` to reach the API) | `docker compose up`, then `curl -u … http://localhost/` returns 200 |
| E5 | Outbound isolation off unless `firewall.sh` was run by hand; not persistent; all DNS allowed | `firewall` service (host network, CAP_NET_ADMIN) applies it on start and repairs it every 30 s; honeypots start only when its healthcheck passes; DNS and every non-internal destination dropped; iptables backend auto-detected | real iptables test: honeypot → 1.1.1.1 / 8.8.8.8:53 / 192.168.1.1 all dropped, DB still reachable |
| E6 | `nginx/.htpasswd` (MD5-apr1 hash) shipped in the archive | removed; the `auth-init` service writes a **bcrypt** hash from `DASHBOARD_PASSWORD`, or generates a random password and prints it once | 401 without and with a wrong password, 200 with the right one |
| E7 | IOC `hits` grew on every 30-s pass (~20× inflation) | `ioc_sightings` table: a hit is counted once per source event, detection or capture | `test_ioc_hits_are_idempotent` |
| E8 | Demo GeoIP on by default and indistinguishable from real data | code default off; when on, rows are `geo_source='demo'`, the dashboard shows a **DEMO** tag and reports say "lab address, demo location" | UI + report text |
| — | `sensor_config(**kwargs)`: a form field named `actor` crashed the HMI | takes a plain dict and whitelists keys | `test_sensor_config_rejects_unknown_and_actor_key` |
| — | Telnet IAC command split across two TCP reads was stored as data | carry buffer in `TelnetIO._fill` | `test_telnet_iac_split_across_reads` |
| — | SSH socket leaked on the rate-limited path | socket closed in `finally` | code review |
| — | DB pool raised `PoolError` (HTTP 500) under dashboard bursts | waits up to 10 s for a free connection; pool size 20 | UI test opens 15 pages back-to-back with no errors |
| — | Hard-coded DB password in the code fallback; `psycopg2-binary==2.9.9` does not install on Python 3.13 | password removed from fallback; pinned 2.9.10 | install on 3.12 and 3.13 |
| — | Connection used the server's default encoding (SQL_ASCII → non-ASCII attacker text failed) | `client_encoding=UTF8` on every connection | schema applied on a SQL_ASCII database |
| — | v0.6 UI (Lovable export): detail routes were children of list routes without an `<Outlet/>`, so `/attackers/<ip>` showed the list | list pages are index routes | `src/test/app-routing.test.tsx` |
| — | Report "max severity" used alphabetical `max()` (MEDIUM > HIGH > CRITICAL) | ranked with `array_position` | `test_report_max_severity_is_ranked_not_alphabetical` |

## 3. New in v0.7 (by scope module)

**M3 Attack detection & forensic logging**
- **Malware capture** (`common/capture.py`): HTTP firmware uploads and binary bodies, SSH
  `cat > f` / `dd of=` / `tee` over exec stdin, `scp -t` uploads (minimal SCP sink), files
  dropped in the fake shell, and binary MQTT payloads. Samples are content-addressed
  (`<sha256>.bin`), stored **read-only (0400), never executed**, and indexed in
  `file_captures` (SDS data dictionary) with SHA-256, MD5, size, MIME type and **ELF CPU
  architecture** (ARM/MIPS/PowerPC/SuperH…).
- **YARA** (`intel/yara_scan.py`, `intel/yara_rules/iot_malware.yar`): the intel engine scans
  every new sample. Rules cover Mirai-family, Gafgyt/Bashlite, Mozi, Tsunami, shell
  droppers, coin-miners, UPX packing and embedded-CPU ELF. A match raises a new
  **MALWARE_FAMILY** detection (CRITICAL), and every sample hash becomes an IOC.

**M4 Threat intelligence**
- **STIX 2.1 export** (`intel/stix.py`, `GET /api/export/stix`): indicators (URL, domain,
  IPv4, file SHA-256), sightings with exact counts, ATT&CK attack-patterns (Enterprise and
  ICS), malware families and `indicates` relationships. IDs are deterministic (UUIDv5), so a
  SIEM de-duplicates. The output is validated against the OASIS `stix2` library in tests.
- **Threat reports** (`intel/report.py`): JSON and **PDF with embedded charts**, plus a
  **daily** e-mail (and weekly on Mondays) with the PDF attached when SMTP is configured.
  The analyst paragraph is rule-based for now; the LLM narrator is M8-FE-3.

**M5 Real-time monitoring dashboard** (`dashboard/`)
- The UI you supplied (React 19 + TypeScript + Tailwind + Recharts) is now **fully wired to
  the API**; nothing is mocked. It was converted from a Lovable/TanStack-Start SSR app to a
  static SPA that Nginx serves, with no Node server in production.
- **WebSocket live push** (`/api/ws`, relays Redis pub/sub): the event feed and detections
  update instantly, critical detections pop a toast, and polling remains as a fallback.
- **Offline world map** with a heat layer (d3-geo and a bundled atlas). It needs no tile
  server, works on an isolated honeynet, and runs under a strict CSP. Fonts are bundled too.
- New pages: **Malware**, **Reports & Alerts** (PDF / STIX / CSV / ML-dataset downloads and
  the alert log) and **Search**. Device pages show live sensor history, the lock's
  lock/unlock log and the camera's probed stream paths.

**M6 Alerts**: MALWARE_FAMILY alerts; e-mail supports PDF attachments for reports.

**M7 Deployment**
- Automatic outbound firewall service (E5).
- **Backups**: `backup` service writes `pg_dump` and a sample archive to `./backups` with
  SHA-256 checksums, keeps the last N sets, and supports `verify` / `restore`.
- **Monitoring profile**: Prometheus (app metrics from `/api/metrics` plus cAdvisor container
  CPU/memory/network/disk), alert rules, and a provisioned Grafana dashboard.
- **Schema auto-migration**: the API and intel engine re-apply the idempotent `init.sql`
  under an advisory lock, so an existing v0.6 database upgrades in place.

## 4. Module coverage vs. scope

| Scope module | 60% | 70% (v0.7) | Still open for 100% |
|---|---|---|---|
| M1 Device emulation | 85% | **90%** | richer firmware quirks, startup/shutdown banners |
| M2 Multi-protocol handler | 90% | **92%** | SFTP subsystem, more protocol edge cases |
| M3 Detection & forensic logging | 75% | **88%** | PCAP recording per session, ClamAV |
| M4 Threat intelligence | 70% | **88%** | external reputation feeds (GreyNoise / VirusTotal / OTX) |
| M5 Dashboard | 75% | **92%** | AI threat-summary panel (needs M8) |
| M6 Alerts | 85% | **90%** | Slack webhook (agreed simplification) |
| M7 Deployment | 75% | **92%** | K3s (descoped: single-host research deployment, LI-11) |
| M8 AI / ML | 0% | **15%** | XGBoost classifier, Isolation Forest, LLM narrator, risk score, ML API |

**Overall progress, weighted by the WBS effort (weeks):**

| WBS | weeks | done | weighted |
|---|---|---|---|
| 1.0 Planning, 2.0 Environment | 6 | 100% | 6.0 |
| 3.0 M1 · 4.0 M2 | 5 + 5 | 90% · 92% | 9.1 |
| 5.0 M3 · 6.0 M4 | 4 + 3 | 88% · 88% | 6.2 |
| 7.0 M5 · 8.0 M6 · 9.0 M7 | 5 + 2 + 2 | 92% · 90% · 92% | 8.2 |
| 10.0 M8 AI | 6 | 15% | 0.9 |
| 11.0 Integration & testing | 4 | 40% | 1.6 |
| 12.0 Documentation · 13.0 Closure | 3 + 2 | 30% · 0% | 0.9 |
| **Total** | **47** | | **32.9 / 47 ≈ 70%** |

## 5. Module 8 — what is ready

- `ml/features.py` builds one row per session: duration, auth counts and success ratio,
  distinct usernames/passwords, command counts, download/exec/file events, HTTP 404s, MQTT
  control publishes and wildcard subscriptions, RTSP probes, malformed packets, command
  keyword flags, inter-event timing (mean/std), and the IP's protocol mix within ±1 h.
- **Weak label** from rule detections into the scope's six classes. It can be downloaded as
  CSV (`/api/ml/dataset.csv`, the Reports page, or `python -m ml.features out.csv`).
- Next (100%): train XGBoost with 5-fold CV, an Isolation Forest, a FastAPI inference
  endpoint and the LLM narrator, then compare against the rule baseline (see `MODEL_CARD.md`).

## 6. Agreed simplifications (unchanged from 60%; confirm with the supervisor)

| Scope promise | Built | Why |
|---|---|---|
| Next.js + shadcn + Zustand | React 19 + TS + TanStack Router/Query SPA | same UX; static files behind Nginx, no Node server to secure |
| Leaflet.js map | d3-geo SVG map with heat layer | works offline on an isolated honeynet (no tile server), strict CSP |
| Socket.IO | native WebSocket (FastAPI) | no extra dependency; same push semantics |
| RTSP H.264 stream via GStreamer | RTSP signalling + auth capture + valid SDP | attackers brute-force RTSP auth; stream content is secondary |
| Kubernetes (K3s), Celery | Docker Compose, background worker loop | single-host research deployment |
| Slack + Telegram + e-mail | Telegram + e-mail | two channels prove the design |
| ClamAV + VirusTotal + OTX | YARA (offline) | no outbound lookups from the honeynet; reputation feeds are 100% work |
