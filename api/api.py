"""
HoneyBot-IoT — REST API (dashboard backend), v0.6

Reachable ONLY through Nginx (basic auth) – port 5000 is no longer published.
All queries run on the unified `events` / `sessions` store.
"""

import os
import io
import csv
import sys
import json
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import StreamingResponse

from common.db import fetchall, fetchdicts, scalar
from common.state import STATE, redis_client

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("api")

app = FastAPI(title="HoneyBot-IoT API", version="0.6",
              description="Threat-intelligence API of the HoneyBot-IoT multi-protocol IoT honeypot.")

PROTOCOLS = ["SSH", "Telnet", "HTTP", "MQTT", "RTSP"]
ACTIVITY = ("auth", "command", "http_request", "mqtt_publish", "mqtt_subscribe", "rtsp_request",
            "download_attempt", "state_change", "malformed", "file_write", "file_upload")


def _iso(rows):
    for r in rows:
        for k, v in list(r.items()):
            if hasattr(v, "isoformat"):
                r[k] = v.isoformat()
            elif k in ("session_id",) and v is not None:
                r[k] = str(v)
    return rows


@app.get("/api/health")
def health():
    return {"status": "ok", "db": bool(fetchall("SELECT 1")), "redis": redis_client() is not None}


@app.get("/api/stats")
def stats():
    per = {p: 0 for p in PROTOCOLS}
    for proto, n in fetchall("SELECT protocol, COUNT(*) FROM sessions GROUP BY protocol"):
        per[proto] = n
    auth = dict(fetchall("""SELECT protocol, COUNT(*) FROM events WHERE event_type='auth' GROUP BY protocol"""))
    return {
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
        "alerts_sent": scalar("SELECT COUNT(*) FROM alerts WHERE status='sent'"),
        "active_sessions": scalar("""SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL
                                      AND started_at > NOW() - INTERVAL '30 minutes'"""),
    }


@app.get("/api/attacks/recent")
def recent(limit: int = Query(60, le=500), protocol: str = None):
    rows = fetchdicts(f"""
        SELECT e.ts, e.ip, e.protocol, e.device, e.event_type, e.username, e.password, e.success,
               left(e.command, 160) AS command, left(e.payload, 120) AS payload, e.session_id,
               a.country_code, a.country
        FROM events e LEFT JOIN attackers a ON a.ip = e.ip
        WHERE e.event_type IN %s {"AND e.protocol = %s" if protocol else ""}
        ORDER BY e.id DESC LIMIT %s
    """, (ACTIVITY, protocol, limit) if protocol else (ACTIVITY, limit))
    return _iso(rows)


@app.get("/api/attackers/top")
def top_attackers(limit: int = Query(10, le=100)):
    return _iso(fetchdicts("""
        SELECT ip, events AS attempts, sessions, auth_attempts, auth_success, commands, downloads,
               protocols, country, country_code, city, threat_level, threat_score, campaign_id
        FROM attackers ORDER BY events DESC LIMIT %s""", (limit,)))


@app.get("/api/timeline")
def timeline(hours: int = Query(24, le=168)):
    rows = fetchall(f"""
        SELECT date_trunc('hour', ts) AS hr, protocol, COUNT(*)
        FROM events WHERE ts > NOW() - INTERVAL '{int(hours)} hours' AND event_type IN %s
        GROUP BY hr, protocol ORDER BY hr
    """, (ACTIVITY,))
    out = {}
    for hr, proto, n in rows:
        out.setdefault(hr.isoformat(), {p.lower(): 0 for p in PROTOCOLS})[proto.lower()] = n
    return [{"hour": h, **v} for h, v in out.items()]


@app.get("/api/detections")
def detections(limit: int = Query(30, le=500), severity: str = None):
    where = "WHERE severity = %s" if severity else ""
    params = (severity, limit) if severity else (limit,)
    return _iso(fetchdicts(f"""
        SELECT d.id, d.timestamp, d.ip, d.attack_type, d.severity, d.protocol, d.device, d.details,
               d.mitre, d.mitre_names, d.session_id, d.alerted, a.country_code
        FROM detections d LEFT JOIN attackers a ON a.ip = d.ip {where}
        ORDER BY d.timestamp DESC LIMIT %s""", params))


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
def session_list(limit: int = Query(50, le=500), ip: str = None):
    where = "WHERE ip = %s" if ip else ""
    params = (ip, limit) if ip else (limit,)
    return _iso(fetchdicts(f"""
        SELECT session_id, ip, src_port, dst_port, device, protocol, started_at, ended_at,
               auth_attempts, login_success, username, commands, client_version
        FROM sessions {where} ORDER BY started_at DESC LIMIT %s""", params))


@app.get("/api/sessions/{session_id}")
def session_detail(session_id: str):
    s = fetchdicts("SELECT * FROM sessions WHERE session_id = %s", (session_id,))
    if not s:
        raise HTTPException(404, "session not found")
    events = fetchdicts("""SELECT ts, event_type, username, password, success, command, payload, raw
                           FROM events WHERE session_id=%s ORDER BY id""", (session_id,))
    from intel.mitre import tag_command, name
    for e in events:
        if e["event_type"] == "command":
            e["mitre"] = [{"id": t, "name": name(t)} for t in tag_command(e["command"])]
    dets = fetchdicts("SELECT attack_type, severity, details, mitre FROM detections WHERE session_id=%s",
                      (session_id,))
    return {"session": _iso(s)[0], "events": _iso(events), "detections": _iso(dets)}


@app.get("/api/map")
def attack_map():
    return _iso(fetchdicts("""
        SELECT ip, lat, lon, city, country, country_code, geo_source, events, threat_level, protocols
        FROM attackers WHERE lat IS NOT NULL ORDER BY events DESC LIMIT 1000"""))


@app.get("/api/countries")
def countries():
    return fetchdicts("""SELECT country, country_code, COUNT(*) AS ips, SUM(events) AS events
                         FROM attackers WHERE country IS NOT NULL
                         GROUP BY country, country_code ORDER BY events DESC LIMIT 20""")


@app.get("/api/devices")
def devices():
    """Device Status Monitor: emulated device state + honeypot service health."""
    r = redis_client()
    services = {}
    for svc in ("ssh", "telnet", "http", "mqtt", "rtsp", "device_state", "intel"):
        hb = r.get(f"hb:{svc}") if r else None
        services[svc] = {"up": bool(hb), **(json.loads(hb) if hb else {})}
    active = dict(fetchall("""SELECT protocol, COUNT(*) FROM sessions WHERE ended_at IS NULL
                              AND started_at > NOW() - INTERVAL '30 minutes' GROUP BY protocol"""))
    last = {d: (t.isoformat() if t else None) for d, t in
            fetchall("SELECT device, max(ts) FROM events WHERE event_type <> 'connect' GROUP BY device")}
    counts = dict(fetchall("SELECT device, COUNT(*) FROM events WHERE ts > NOW() - INTERVAL '24 hours' "
                           "GROUP BY device"))
    devs = {
        "cctv": {"name": "CCTV Camera", "protocols": ["RTSP", "HTTP"], "services": ["rtsp", "http"]},
        "smartlock": {"name": "Smart Lock", "protocols": ["SSH", "HTTP", "MQTT"],
                      "services": ["ssh", "http", "mqtt"]},
        "sensor": {"name": "Industrial Sensor", "protocols": ["Telnet", "MQTT", "HTTP"],
                   "services": ["telnet", "mqtt", "http"]},
    }
    for k, d in devs.items():
        st = STATE.get(k)
        st.pop("api_token", None)
        d["state"] = st
        d["online"] = all(services[s]["up"] for s in d["services"])
        d["active_sessions"] = sum(active.get(p, 0) for p in d["protocols"])
        d["last_attack"] = last.get(k)
        d["events_24h"] = counts.get(k, 0)
    return {"devices": devs, "services": services, "active_by_protocol": active}


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
def alerts(limit: int = Query(30, le=500)):
    return _iso(fetchdicts("""SELECT ts, ip, attack_type, severity, channel, status, error
                              FROM alerts ORDER BY id DESC LIMIT %s""", (limit,)))


@app.get("/api/campaigns")
def campaigns():
    return _iso(fetchdicts("SELECT * FROM campaigns ORDER BY last_seen DESC LIMIT 50"))


@app.get("/api/search")
def search(q: str = Query(..., min_length=2), limit: int = Query(100, le=1000)):
    """Full-text search over commands and payloads (GIN index)."""
    return _iso(fetchdicts("""
        SELECT ts, ip, protocol, device, event_type, left(command,200) AS command, left(payload,200) AS payload,
               session_id
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


@app.post("/api/detect")
def run_detect():
    """Run one threat-intelligence pass now (normally every 30 s)."""
    from intel.engine import run_once
    return {"status": "ok", **run_once()}
