"""
HoneyBot-IoT — REST + WebSocket API (dashboard backend), v0.7

Reachable ONLY through Nginx (basic auth); port 5000 is not published.
All queries run on the unified `events` / `sessions` store.

v0.7 additions
  WS   /api/ws                      live push: events, detections, device-state changes
  GET  /api/attackers/{ip}          full attacker profile (sessions, events, detections, IOCs, samples)
  GET  /api/devices/{device}        device detail: state, history, change log, sessions, attacks
  GET  /api/captures[/{sha256}]     quarantined malware samples + YARA verdicts
  GET  /api/export/stix             STIX 2.1 bundle of IOCs, techniques, malware families
  GET  /api/report  · /api/report.pdf   threat summary report (JSON / PDF with charts)
  GET  /api/metrics                 Prometheus exposition format (scraped by monitoring profile)
  GET  /api/ml/dataset.csv · /api/ml/summary   Module-8 labelled feature dataset
"""

import os
import io
import csv
import sys
import json
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Query, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, Response, PlainTextResponse

from common.db import fetchall, fetchdicts, scalar
from common.state import STATE, redis_client, REDIS_URL
from common.schema import ensure_schema

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("api")

VERSION = "0.7"


@asynccontextmanager
async def lifespan(_app):
    # upgrades a v0.6 database in place (new tables / views); idempotent
    await asyncio.to_thread(ensure_schema)
    yield


app = FastAPI(title="HoneyBot-IoT API", version=VERSION, lifespan=lifespan,
              description="Threat-intelligence API of the HoneyBot-IoT multi-protocol IoT honeypot.")

PROTOCOLS = ["SSH", "Telnet", "HTTP", "MQTT", "RTSP"]
ACTIVITY = ("auth", "command", "http_request", "mqtt_publish", "mqtt_subscribe", "rtsp_request",
            "download_attempt", "state_change", "malformed", "file_write", "file_upload", "file_capture",
            "exec_attempt", "stream_access")
SERVICES = ("ssh", "telnet", "http", "mqtt", "rtsp", "device_state", "intel")
DEVICES = {
    "cctv": {"name": "CCTV Camera", "protocols": ["RTSP", "HTTP"], "services": ["rtsp", "http"]},
    "smartlock": {"name": "Smart Lock", "protocols": ["SSH", "HTTP", "MQTT"], "services": ["ssh", "http", "mqtt"]},
    "sensor": {"name": "Industrial Sensor", "protocols": ["Telnet", "MQTT", "HTTP"],
               "services": ["telnet", "mqtt", "http"]},
}
SECRET_FIELDS = ("api_token",)


def _iso(rows):
    for r in rows:
        for k, v in list(r.items()):
            if hasattr(v, "isoformat"):
                r[k] = v.isoformat()
            elif k in ("session_id",) and v is not None:
                r[k] = str(v)
            elif isinstance(v, str) and k == "sha256":
                r[k] = v.strip()
    return rows


def _services():
    r = redis_client()
    out = {}
    for svc in SERVICES:
        hb = None
        if r:
            try:
                hb = r.get(f"hb:{svc}")
            except Exception:
                hb = None
        out[svc] = {"up": bool(hb), **(json.loads(hb) if hb else {})}
    return out


def _public_state(device):
    st = STATE.get(device)
    for k in SECRET_FIELDS:
        st.pop(k, None)
    return st


# ── health / summary ────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "version": VERSION, "db": bool(fetchall("SELECT 1")),
            "redis": redis_client() is not None}


@app.get("/api/stats")
def stats():
    per = {p: 0 for p in PROTOCOLS}
    for proto, n in fetchall("SELECT protocol, COUNT(*) FROM sessions GROUP BY protocol"):
        per[proto] = n
    auth = dict(fetchall("""SELECT protocol, COUNT(*) FROM events WHERE event_type='auth' GROUP BY protocol"""))
    services = _services()
    return {
        "version": VERSION,
        "sessions": per,
        "auth_attempts": {p: auth.get(p, 0) for p in PROTOCOLS},
        "total_sessions": sum(per.values()),
        "total_events": scalar("SELECT COUNT(*) FROM events"),
        "events_24h": scalar("SELECT COUNT(*) FROM events WHERE ts > NOW() - INTERVAL '24 hours'"),
        "unique_ips": scalar("SELECT COUNT(DISTINCT ip) FROM sessions"),
        "successful_logins": scalar("SELECT COUNT(*) FROM events WHERE event_type='auth' AND success"),
        "commands": scalar("SELECT COUNT(*) FROM events WHERE event_type='command'"),
        "detections": scalar("SELECT COUNT(*) FROM detections"),
        "critical": scalar("SELECT COUNT(*) FROM detections WHERE severity='CRITICAL'"),
        "iocs": scalar("SELECT COUNT(*) FROM iocs"),
        "samples": scalar("SELECT COUNT(DISTINCT sha256) FROM file_captures"),
        "malicious_samples": scalar("""SELECT COUNT(DISTINCT sha256) FROM file_captures
                                       WHERE yara_result NOT IN ('CLEAN','UNAVAILABLE','ERROR')"""),
        "alerts_sent": scalar("SELECT COUNT(*) FROM alerts WHERE status='sent'"),
        "active_sessions": scalar("""SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL
                                      AND started_at > NOW() - INTERVAL '30 minutes'"""),
        "services_up": sum(1 for s in services.values() if s["up"]),
        "services_total": len(services),
    }


@app.get("/api/attacks/recent")
def recent(limit: int = Query(60, le=500), protocol: str = None, device: str = None, ip: str = None):
    where, params = ["e.event_type IN %s"], [ACTIVITY]
    for col, val in (("e.protocol", protocol), ("e.device", device), ("e.ip", ip)):
        if val:
            where.append(f"{col} = %s")
            params.append(val)
    rows = fetchdicts(f"""
        SELECT e.id, e.ts, e.ip, e.protocol, e.device, e.event_type, e.username, e.password, e.success,
               left(e.command, 160) AS command, left(e.payload, 120) AS payload, e.session_id,
               a.country_code, a.country
        FROM events e LEFT JOIN attackers a ON a.ip = e.ip
        WHERE {' AND '.join(where)}
        ORDER BY e.id DESC LIMIT %s
    """, (*params, limit))
    return _iso(rows)


@app.get("/api/attackers/top")
def top_attackers(limit: int = Query(10, le=200)):
    return _iso(fetchdicts("""
        SELECT ip, events AS attempts, sessions, auth_attempts, auth_success, commands, downloads,
               protocols, devices, country, country_code, city, geo_source, threat_level, threat_score,
               campaign_id, attack_types, first_seen, last_seen
        FROM attackers ORDER BY threat_score DESC, events DESC LIMIT %s""", (limit,)))


@app.get("/api/attackers/{ip}")
def attacker_detail(ip: str):
    a = fetchdicts("SELECT * FROM attackers WHERE ip = %s", (ip,))
    if not a:
        n = scalar("SELECT COUNT(*) FROM events WHERE ip = %s", (ip,))
        if not n:
            raise HTTPException(404, "no activity recorded for this IP")
        a = [{"ip": ip, "events": n, "threat_level": "LOW", "threat_score": 0, "protocols": [],
              "devices": [], "note": "not yet correlated by the intel engine"}]
    camp = None
    if a[0].get("campaign_id"):
        c = fetchdicts("SELECT * FROM campaigns WHERE campaign_id = %s", (a[0]["campaign_id"],))
        camp = _iso(c)[0] if c else None
    return {
        "attacker": _iso(a)[0],
        "campaign": camp,
        "sessions": _iso(fetchdicts("""
            SELECT session_id, ip, src_port, dst_port, device, protocol, started_at, ended_at,
                   auth_attempts, login_success, username, commands, client_version
            FROM sessions WHERE ip = %s ORDER BY started_at DESC LIMIT 200""", (ip,))),
        "events": _iso(fetchdicts("""
            SELECT id, ts, protocol, device, event_type, username, password, success,
                   left(command, 300) AS command, left(payload, 300) AS payload, session_id
            FROM events WHERE ip = %s AND event_type <> 'connect' ORDER BY id DESC LIMIT 300""", (ip,))),
        "detections": _iso(fetchdicts("""
            SELECT id, timestamp, attack_type, severity, protocol, device, details, mitre, mitre_names, session_id
            FROM detections WHERE ip = %s ORDER BY timestamp DESC LIMIT 200""", (ip,))),
        "iocs": _iso(fetchdicts("""
            SELECT type, value, first_seen, last_seen, protocol, hits, context
            FROM iocs WHERE source_ip = %s ORDER BY last_seen DESC LIMIT 200""", (ip,))),
        "samples": _iso(fetchdicts("""
            SELECT id, ts, sha256, filename, size, mime_type, arch, source, yara_result, protocol
            FROM file_captures WHERE ip = %s ORDER BY ts DESC LIMIT 100""", (ip,))),
        "credentials": fetchdicts("""
            SELECT username, password, COUNT(*) AS count, string_agg(DISTINCT protocol, ',') AS protocols,
                   bool_or(success) AS worked
            FROM events WHERE ip = %s AND event_type='auth'
            GROUP BY username, password ORDER BY count DESC LIMIT 30""", (ip,)),
    }


@app.get("/api/timeline")
def timeline(hours: int = Query(24, le=168)):
    rows = fetchall(f"""
        SELECT date_trunc('hour', ts) AS hr, protocol, COUNT(*)
        FROM events WHERE ts > NOW() - INTERVAL '{int(hours)} hours' AND event_type IN %s
        GROUP BY hr, protocol ORDER BY hr
    """, (ACTIVITY,))
    # one bucket per hour, including empty hours, so charts have a continuous x-axis
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    out = {}
    for i in range(int(hours) - 1, -1, -1):
        h = (now.timestamp() - i * 3600)
        out[datetime.fromtimestamp(h, timezone.utc).isoformat()] = {p.lower(): 0 for p in PROTOCOLS}
    for hr, proto, n in rows:
        out.setdefault(hr.astimezone(timezone.utc).isoformat(), {p.lower(): 0 for p in PROTOCOLS})[proto.lower()] = n
    return [{"hour": h, **v} for h, v in sorted(out.items())]


@app.get("/api/detections")
def detections(limit: int = Query(30, le=500), severity: str = None, attack_type: str = None,
               ip: str = None, device: str = None):
    where, params = [], []
    for col, val in (("d.severity", severity), ("d.attack_type", attack_type), ("d.ip", ip), ("d.device", device)):
        if val:
            where.append(f"{col} = %s")
            params.append(val)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    return _iso(fetchdicts(f"""
        SELECT d.id, d.timestamp, d.ip, d.attack_type, d.severity, d.protocol, d.device, d.details,
               d.mitre, d.mitre_names, d.session_id, d.alerted, a.country_code
        FROM detections d LEFT JOIN attackers a ON a.ip = d.ip {w}
        ORDER BY d.timestamp DESC LIMIT %s""", (*params, limit)))


@app.get("/api/sessions")
def attacker_sessions(limit: int = Query(50, le=500)):
    """Cross-protocol correlation per attacker: geo, protocols, devices, threat, campaign."""
    return _iso(fetchdicts("""
        SELECT ip, first_seen, last_seen, sessions, events, auth_attempts, auth_success, commands,
               downloads, protocols, devices, country, country_code, city, lat, lon, geo_source,
               threat_level, threat_score, attack_types, campaign_id
        FROM attackers
        ORDER BY threat_score DESC, last_seen DESC LIMIT %s""", (limit,)))


@app.get("/api/sessions/list")
def session_list(limit: int = Query(50, le=1000), ip: str = None, device: str = None, protocol: str = None,
                 active: bool = False):
    where, params = [], []
    for col, val in (("ip", ip), ("device", device), ("protocol", protocol)):
        if val:
            where.append(f"{col} = %s")
            params.append(val)
    if active:
        where.append("ended_at IS NULL AND started_at > NOW() - INTERVAL '30 minutes'")
    w = ("WHERE " + " AND ".join(where)) if where else ""
    return _iso(fetchdicts(f"""
        SELECT session_id, ip, src_port, dst_port, device, protocol, started_at, ended_at,
               auth_attempts, login_success, username, commands, client_version
        FROM sessions {w} ORDER BY started_at DESC LIMIT %s""", (*params, limit)))


@app.get("/api/sessions/{session_id}")
def session_detail(session_id: str):
    s = fetchdicts("SELECT * FROM sessions WHERE session_id::text = %s", (session_id,))
    if not s:
        raise HTTPException(404, "session not found")
    events = fetchdicts("""SELECT id, ts, event_type, username, password, success, command, payload, raw
                           FROM events WHERE session_id::text = %s ORDER BY id""", (session_id,))
    from intel.mitre import tag_command, name
    for e in events:
        if e["event_type"] == "command":
            e["mitre"] = [{"id": t, "name": name(t)} for t in tag_command(e["command"])]
    dets = fetchdicts("""SELECT id, timestamp, attack_type, severity, details, mitre, mitre_names
                         FROM detections WHERE session_id::text = %s""", (session_id,))
    samples = fetchdicts("""SELECT sha256, filename, size, mime_type, arch, source, yara_result
                            FROM file_captures WHERE session_id::text = %s""", (session_id,))
    return {"session": _iso(s)[0], "events": _iso(events), "detections": _iso(dets), "samples": _iso(samples)}


@app.get("/api/map")
def attack_map():
    return _iso(fetchdicts("""
        SELECT ip, lat, lon, city, country, country_code, geo_source, events, threat_level, threat_score, protocols
        FROM attackers WHERE lat IS NOT NULL ORDER BY events DESC LIMIT 1000"""))


@app.get("/api/countries")
def countries():
    return fetchdicts("""SELECT country, country_code, bool_or(geo_source = 'demo') AS demo,
                                COUNT(*) AS ips, SUM(events) AS events
                         FROM attackers WHERE country IS NOT NULL
                         GROUP BY country, country_code ORDER BY events DESC LIMIT 20""")


# ── devices ─────────────────────────────────────────────────────────────────
def _device_summary(services):
    active = dict(fetchall("""SELECT protocol, COUNT(*) FROM sessions WHERE ended_at IS NULL
                              AND started_at > NOW() - INTERVAL '30 minutes' GROUP BY protocol"""))
    active_dev = dict(fetchall("""SELECT device, COUNT(*) FROM sessions WHERE ended_at IS NULL
                                  AND started_at > NOW() - INTERVAL '30 minutes' GROUP BY device"""))
    last = {d: (t.isoformat() if t else None) for d, t in
            fetchall("SELECT device, max(ts) FROM events WHERE event_type <> 'connect' GROUP BY device")}
    counts = dict(fetchall("SELECT device, COUNT(*) FROM events WHERE ts > NOW() - INTERVAL '24 hours' "
                           "GROUP BY device"))
    dets = dict(fetchall("SELECT device, COUNT(*) FROM detections WHERE timestamp > NOW() - INTERVAL '24 hours' "
                         "GROUP BY device"))
    devs = {}
    for k, meta in DEVICES.items():
        d = dict(meta)
        d["state"] = _public_state(k)
        d["online"] = all(services[s]["up"] for s in d["services"])
        d["active_sessions"] = active_dev.get(k, 0)
        d["last_attack"] = last.get(k)
        d["events_24h"] = counts.get(k, 0)
        d["detections_24h"] = dets.get(k, 0)
        devs[k] = d
    return devs, active


@app.get("/api/devices")
def devices():
    """Device Status Monitor: emulated device state + honeypot service health."""
    services = _services()
    devs, active = _device_summary(services)
    return {"devices": devs, "services": services, "active_by_protocol": active}


@app.get("/api/devices/{device}")
def device_detail(device: str):
    if device not in DEVICES:
        raise HTTPException(404, "unknown device")
    services = _services()
    devs, _ = _device_summary(services)
    d = devs[device]
    extra = {}
    if device == "sensor":
        extra["history"] = list(reversed(STATE.history("sensor", 360)))     # oldest → newest, 30 min
    if device == "cctv":
        extra["stream_paths"] = fetchdicts("""
            SELECT raw->>'path' AS path, COUNT(*) AS requests, COUNT(DISTINCT ip) AS ips
            FROM events WHERE device='cctv' AND event_type IN ('rtsp_request','rtsp_route_probe','stream_access')
              AND raw->>'path' IS NOT NULL
            GROUP BY 1 ORDER BY 2 DESC LIMIT 15""")
        extra["stream_opens"] = scalar("SELECT COUNT(*) FROM events WHERE event_type='stream_access'")
        extra["web_logins"] = dict(fetchall("""
            SELECT CASE WHEN success THEN 'success' ELSE 'failed' END, COUNT(*) FROM events
            WHERE device='cctv' AND event_type='auth' GROUP BY 1"""))
    return {
        "device": device, **d,
        "services_detail": {s: services[s] for s in d["services"]},
        "changes": STATE.changes(device, 50),
        "sessions": _iso(fetchdicts("""
            SELECT session_id, ip, src_port, dst_port, protocol, started_at, ended_at, auth_attempts,
                   login_success, username, commands, client_version
            FROM sessions WHERE device = %s ORDER BY started_at DESC LIMIT 50""", (device,))),
        "events": _iso(fetchdicts("""
            SELECT id, ts, ip, protocol, event_type, username, password, success,
                   left(command, 200) AS command, left(payload, 200) AS payload, session_id
            FROM events WHERE device = %s AND event_type IN %s ORDER BY id DESC LIMIT 100""",
                                  (device, ACTIVITY))),
        "detections": _iso(fetchdicts("""
            SELECT id, timestamp, ip, attack_type, severity, protocol, details, mitre, mitre_names
            FROM detections WHERE device = %s ORDER BY timestamp DESC LIMIT 50""", (device,))),
        "credentials": fetchdicts("""
            SELECT username, password, COUNT(*) AS count, bool_or(success) AS worked
            FROM events WHERE device = %s AND event_type='auth' AND password IS NOT NULL
            GROUP BY username, password ORDER BY count DESC LIMIT 10""", (device,)),
        **extra,
    }


# ── credentials / commands / MITRE / IOCs / alerts / campaigns ─────────────
@app.get("/api/credentials/top")
def top_creds(limit: int = Query(15, le=100), protocol: str = None):
    where = "AND protocol = %s" if protocol else ""
    params = (protocol, limit) if protocol else (limit,)
    return fetchdicts(f"""
        SELECT username, password, COUNT(*) AS count, string_agg(DISTINCT protocol, ',') AS protocols,
               bool_or(success) AS worked
        FROM events WHERE event_type='auth' AND password IS NOT NULL {where}
        GROUP BY username, password ORDER BY count DESC LIMIT %s""", params)


@app.get("/api/commands/top")
def top_commands(limit: int = Query(15, le=100)):
    return fetchdicts("""SELECT left(command, 120) AS command, COUNT(*) AS count FROM events
                         WHERE event_type='command' GROUP BY 1 ORDER BY 2 DESC LIMIT %s""", (limit,))


@app.get("/api/mitre/summary")
def mitre_summary():
    return fetchdicts("""
        SELECT t.id AS technique, t.name, COUNT(*) AS detections, COUNT(DISTINCT d.ip) AS ips
        FROM detections d, LATERAL unnest(d.mitre, d.mitre_names) AS t(id, name)
        GROUP BY t.id, t.name ORDER BY detections DESC""")


@app.get("/api/iocs")
def iocs(limit: int = Query(50, le=1000), type: str = None):
    where = "WHERE type = %s" if type else ""
    params = (type, limit) if type else (limit,)
    return _iso(fetchdicts(f"""SELECT type, value, first_seen, last_seen, source_ip, protocol, hits, context
                               FROM iocs {where} ORDER BY last_seen DESC LIMIT %s""", params))


@app.get("/api/alerts")
def alerts(limit: int = Query(50, le=500)):
    return _iso(fetchdicts("""SELECT id, ts, ip, attack_type, severity, channel, status, error, detection_id
                              FROM alerts ORDER BY id DESC LIMIT %s""", (limit,)))


@app.get("/api/campaigns")
def campaigns():
    return _iso(fetchdicts("SELECT * FROM campaigns ORDER BY last_seen DESC LIMIT 50"))


# ── malware samples ─────────────────────────────────────────────────────────
@app.get("/api/captures")
def captures(limit: int = Query(100, le=1000)):
    """One row per distinct sample (SHA-256) with where/how often it was seen."""
    return _iso(fetchdicts("""
        SELECT sha256, max(md5) AS md5, max(size) AS size, max(mime_type) AS mime_type, max(arch) AS arch,
               max(yara_result) AS yara_result, max(array_to_string(yara_matches, ',')) AS yara_rules,
               min(ts) AS first_seen, max(ts) AS last_seen, COUNT(*) AS times,
               array_agg(DISTINCT ip) AS ips, array_agg(DISTINCT protocol) AS protocols,
               array_agg(DISTINCT source) AS sources, max(filename) AS filename,
               bool_or(scanned_at IS NOT NULL) AS scanned
        FROM file_captures GROUP BY sha256 ORDER BY max(ts) DESC LIMIT %s""", (limit,)))


@app.get("/api/captures/{sha256}")
def capture_detail(sha256: str):
    rows = _iso(fetchdicts("""SELECT * FROM file_captures WHERE sha256 = %s ORDER BY ts""", (sha256.lower(),)))
    if not rows:
        raise HTTPException(404, "sample not found")
    for r in rows:
        r.pop("storage_path", None)          # never expose filesystem paths
    return {"sha256": sha256.lower(), "sightings": rows}


# ── search / export / reports ───────────────────────────────────────────────
@app.get("/api/search")
def search(q: str = Query(..., min_length=2), limit: int = Query(100, le=1000)):
    """Full-text search over commands and payloads (GIN index) + exact IP / credential match."""
    return _iso(fetchdicts("""
        SELECT ts, ip, protocol, device, event_type, left(command,200) AS command, left(payload,200) AS payload,
               username, password, session_id
        FROM events
        WHERE to_tsvector('simple', coalesce(command,'') || ' ' || coalesce(payload,''))
              @@ plainto_tsquery('simple', %s)
           OR ip = %s OR username = %s OR password = %s
        ORDER BY ts DESC LIMIT %s""", (q, q, q, q, limit)))


@app.get("/api/export/events.csv")
def export_csv(hours: int = Query(24, le=24 * 90)):
    rows = fetchall(f"""SELECT ts, session_id, ip, src_port, device, protocol, event_type, username, password,
                               success, command, payload FROM events
                        WHERE ts > NOW() - INTERVAL '{int(hours)} hours' ORDER BY id""")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ts", "session_id", "ip", "src_port", "device", "protocol", "event_type", "username",
                "password", "success", "command", "payload"])
    w.writerows(rows)
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=honeybot_events.csv"})


@app.get("/api/export/stix")
def export_stix(hours: int = Query(24 * 7, ge=1, le=24 * 90)):
    from intel.stix import bundle_json
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(bundle_json(hours), media_type="application/stix+json;version=2.1",
                    headers={"Content-Disposition": f"attachment; filename=honeybot-iocs-{stamp}.stix.json"})


@app.get("/api/report")
def report_json(hours: int = Query(24, ge=1, le=24 * 90)):
    from intel.report import build_report
    return build_report(hours)


@app.get("/api/report.pdf")
def report_pdf(hours: int = Query(24, ge=1, le=24 * 90)):
    from intel.report import build_report, render_pdf
    pdf = render_pdf(build_report(hours))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=honeybot-report-{hours}h-{stamp}.pdf"})


@app.post("/api/detect")
def run_detect():
    """Run one threat-intelligence pass now (normally every 30 s)."""
    from intel.engine import run_once
    return {"status": "ok", **run_once()}


# ── Module 8 data preparation ───────────────────────────────────────────────
@app.get("/api/ml/summary")
def ml_summary(days: int = Query(30, ge=1, le=365)):
    from ml.features import build_dataset, summary
    return summary(build_dataset(days))


@app.get("/api/ml/dataset.csv")
def ml_dataset(days: int = Query(30, ge=1, le=365)):
    from ml.features import build_dataset, to_csv
    return Response(to_csv(build_dataset(days)), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=honeybot_ml_dataset.csv"})


# ── Prometheus metrics (scope M7 resource / service monitoring) ─────────────
@app.get("/api/metrics", response_class=PlainTextResponse)
def metrics():
    lines = []

    def metric(name, mtype, help_, samples):
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {mtype}")
        for labels, value in samples:
            lab = ",".join(f'{k}="{str(v).replace(chr(34), "")}"' for k, v in labels.items())
            lines.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    metric("honeybot_events_total", "counter", "Events recorded, by protocol and type",
           [({"protocol": p, "type": t}, n) for p, t, n in
            fetchall("SELECT protocol, event_type, COUNT(*) FROM events GROUP BY 1, 2")])
    metric("honeybot_sessions_total", "counter", "Attacker sessions, by protocol",
           [({"protocol": p}, n) for p, n in fetchall("SELECT protocol, COUNT(*) FROM sessions GROUP BY 1")])
    metric("honeybot_active_sessions", "gauge", "Open attacker sessions, by protocol",
           [({"protocol": p}, n) for p, n in fetchall("""SELECT protocol, COUNT(*) FROM sessions
               WHERE ended_at IS NULL AND started_at > NOW() - INTERVAL '30 minutes' GROUP BY 1""")])
    metric("honeybot_auth_attempts_total", "counter", "Login attempts, by protocol and result",
           [({"protocol": p, "result": "success" if s else "failure"}, n) for p, s, n in
            fetchall("SELECT protocol, COALESCE(success,false), COUNT(*) FROM events WHERE event_type='auth' GROUP BY 1,2")])
    metric("honeybot_detections_total", "counter", "Rule-engine detections, by type and severity",
           [({"type": t, "severity": s}, n) for t, s, n in
            fetchall("SELECT attack_type, severity, COUNT(*) FROM detections GROUP BY 1, 2")])
    metric("honeybot_iocs", "gauge", "Indicators of compromise, by type",
           [({"type": t}, n) for t, n in fetchall("SELECT type, COUNT(*) FROM iocs GROUP BY 1")])
    metric("honeybot_samples", "gauge", "Distinct captured malware samples, by YARA verdict",
           [({"verdict": v or "pending"}, n) for v, n in
            fetchall("SELECT yara_result, COUNT(DISTINCT sha256) FROM file_captures GROUP BY 1")])
    metric("honeybot_alerts_total", "counter", "Alert decisions, by channel and status",
           [({"channel": c, "status": s}, n) for c, s, n in
            fetchall("SELECT channel, status, COUNT(*) FROM alerts GROUP BY 1, 2")])
    metric("honeybot_unique_attackers", "gauge", "Distinct attacker IPs", [({}, scalar("SELECT COUNT(*) FROM attackers"))])
    svcs = _services()
    metric("honeybot_service_up", "gauge", "Honeypot service heartbeat (1 = alive)",
           [({"service": s}, 1 if v["up"] else 0) for s, v in svcs.items()])
    metric("honeybot_service_uptime_seconds", "gauge", "Service uptime reported by its heartbeat",
           [({"service": s}, v.get("uptime", 0)) for s, v in svcs.items() if v["up"]])
    return "\n".join(lines) + "\n"


# ── WebSocket live push (scope M5: real-time feed) ──────────────────────────
WS_CHANNELS = {"honeybot:events": "event", "honeybot:detections": "detection", "honeybot:state": "state"}


@app.websocket("/api/ws")
async def ws_live(websocket: WebSocket):
    """Relays Redis pub/sub to the browser as {"channel": "event|detection|state", "data": {...}}."""
    await websocket.accept()
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=2)
        ps = r.pubsub()
        await ps.subscribe(*WS_CHANNELS)
    except Exception as e:
        await websocket.send_text(json.dumps({"channel": "error", "data": {"message": f"live feed unavailable: {e}"}}))
        await websocket.close()
        return
    await websocket.send_text(json.dumps({"channel": "hello", "data": {"version": VERSION}}))

    async def pump():
        last_ping = asyncio.get_running_loop().time()
        while True:
            msg = await ps.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg.get("type") == "message":
                try:
                    data = json.loads(msg["data"])
                except Exception:
                    continue
                await websocket.send_text(json.dumps({"channel": WS_CHANNELS.get(msg["channel"], "event"),
                                                      "data": data}))
            now = asyncio.get_running_loop().time()
            if now - last_ping > 25:          # keep idle proxies from closing the socket
                await websocket.send_text('{"channel":"ping"}')
                last_ping = now

    async def drain():
        while True:
            await websocket.receive_text()    # raises WebSocketDisconnect when the browser leaves

    tasks = [asyncio.create_task(pump()), asyncio.create_task(drain())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    finally:
        for t in tasks:
            t.cancel()
        try:
            await ps.unsubscribe()
            await ps.aclose() if hasattr(ps, "aclose") else await ps.close()
            await r.aclose() if hasattr(r, "aclose") else await r.close()
        except Exception:
            pass
