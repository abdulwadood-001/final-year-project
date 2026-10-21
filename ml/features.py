"""
HoneyBot-IoT — Module 8 data preparation (WBS 10.1 "ML Data Preparation & Feature Eng.").

One feature vector per attacker SESSION, aggregated from the unified `events` table,
plus a WEAK LABEL derived from the rule engine's detections. This is the training set
for the XGBoost classifier and the Isolation Forest of the 100% milestone.

    GET /api/ml/dataset.csv   – full labelled dataset (CSV)
    GET /api/ml/summary       – class balance + feature list
    python -m ml.features out.csv   – same, from the command line

Weak-label mapping (docs/MILESTONE_60.md §5, scope M8-FE-1 six classes):
    malware_delivery  ← MALWARE_DELIVERY, MALWARE_FAMILY, MIRAI_SIGNATURE
    botnet_c2         ← BOTNET_C2, ICS_UNAUTHORIZED_COMMAND, DENIAL_OF_VIEW
    protocol_exploit  ← PROTOCOL_EXPLOIT
    brute_force       ← BRUTE_FORCE, CREDENTIAL_STUFFING, CREDENTIAL_COMPROMISE
    port_scan         ← RECONNAISSANCE, WEB_SCAN, RTSP_ROUTE_ENUM
    normal            ← no detection touches the session
When several apply, the most severe class (top of the list) wins.

Caveat (stated in docs/MODEL_CARD.md): a model trained on rule labels can learn the
rules. The evaluation must therefore compare against the rule baseline and use
features that the rules do NOT look at (timing, ratios, protocol mix).
"""

import csv
import io
import sys

from common.db import fetchdicts

CLASS_PRIORITY = ["malware_delivery", "botnet_c2", "protocol_exploit", "brute_force", "port_scan", "normal"]
TYPE_TO_CLASS = {
    "MALWARE_DELIVERY": "malware_delivery", "MALWARE_FAMILY": "malware_delivery",
    "MIRAI_SIGNATURE": "malware_delivery",
    "BOTNET_C2": "botnet_c2", "ICS_UNAUTHORIZED_COMMAND": "botnet_c2", "DENIAL_OF_VIEW": "botnet_c2",
    "PROTOCOL_EXPLOIT": "protocol_exploit",
    "BRUTE_FORCE": "brute_force", "CREDENTIAL_STUFFING": "brute_force", "CREDENTIAL_COMPROMISE": "brute_force",
    "RECONNAISSANCE": "port_scan", "WEB_SCAN": "port_scan", "RTSP_ROUTE_ENUM": "port_scan",
}

FEATURE_SQL = """
WITH s AS (
    SELECT * FROM sessions WHERE started_at > NOW() - INTERVAL '{days} days'
    ORDER BY started_at DESC LIMIT {limit}
),
ev AS (
    SELECT e.session_id,
           COUNT(*)                                                         AS events_total,
           COUNT(*) FILTER (WHERE e.event_type='auth')                      AS auth_attempts,
           COUNT(*) FILTER (WHERE e.event_type='auth' AND e.success)        AS auth_success,
           COUNT(DISTINCT e.username) FILTER (WHERE e.event_type='auth')    AS distinct_usernames,
           COUNT(DISTINCT e.password) FILTER (WHERE e.event_type='auth')    AS distinct_passwords,
           COUNT(*) FILTER (WHERE e.event_type='command')                   AS commands,
           COUNT(*) FILTER (WHERE e.event_type='download_attempt')          AS download_attempts,
           COUNT(*) FILTER (WHERE e.event_type='exec_attempt')              AS exec_attempts,
           COUNT(*) FILTER (WHERE e.event_type IN ('file_write','file_upload','file_capture')) AS file_events,
           COUNT(*) FILTER (WHERE e.event_type='http_request')              AS http_requests,
           COUNT(*) FILTER (WHERE e.event_type='http_request' AND e.raw->>'status' = '404') AS http_404,
           COUNT(*) FILTER (WHERE e.event_type='mqtt_publish')              AS mqtt_publishes,
           COUNT(*) FILTER (WHERE e.event_type='mqtt_publish' AND (e.raw->>'control')::boolean) AS mqtt_control,
           COUNT(*) FILTER (WHERE e.event_type='mqtt_subscribe' AND e.payload LIKE '%%#%%') AS mqtt_wildcard_subs,
           COUNT(*) FILTER (WHERE e.event_type='rtsp_request')              AS rtsp_requests,
           COUNT(*) FILTER (WHERE e.event_type='rtsp_route_probe')          AS rtsp_route_probes,
           COUNT(*) FILTER (WHERE e.event_type='malformed')                 AS malformed,
           COUNT(*) FILTER (WHERE e.event_type='state_change')              AS state_changes,
           COUNT(*) FILTER (WHERE e.command ~* '\\m(wget|curl|tftp|ftpget)\\M') AS cmd_download,
           COUNT(*) FILTER (WHERE e.command ~* '\\mchmod\\M')                AS cmd_chmod,
           COUNT(*) FILTER (WHERE e.command ~* 'busybox')                   AS cmd_busybox,
           COUNT(*) FILTER (WHERE e.command ~* '/tmp/|/var/tmp|/dev/shm')   AS cmd_tmp_paths,
           COUNT(*) FILTER (WHERE e.command ~* '\\m(uname|whoami|id|ps|ifconfig|netstat|cpuinfo|free|df)\\M')
                                                                            AS cmd_discovery,
           COALESCE(avg(length(e.command)) FILTER (WHERE e.event_type='command'), 0) AS mean_cmd_len
    FROM events e JOIN s ON s.session_id = e.session_id
    GROUP BY e.session_id
),
gaps AS (
    SELECT session_id, avg(gap) AS mean_gap_s, coalesce(stddev_samp(gap), 0) AS std_gap_s
    FROM (SELECT e.session_id,
                 EXTRACT(EPOCH FROM e.ts - lag(e.ts) OVER (PARTITION BY e.session_id ORDER BY e.id)) AS gap
          FROM events e JOIN s ON s.session_id = e.session_id) g
    WHERE gap IS NOT NULL GROUP BY session_id
),
ipctx AS (
    SELECT s.session_id,
           (SELECT COUNT(DISTINCT s2.protocol) FROM sessions s2
             WHERE s2.ip = s.ip AND s2.started_at BETWEEN s.started_at - INTERVAL '1 hour'
                                                      AND s.started_at + INTERVAL '1 hour') AS ip_protocols_1h,
           (SELECT COUNT(*) FROM sessions s2
             WHERE s2.ip = s.ip AND s2.started_at BETWEEN s.started_at - INTERVAL '1 hour'
                                                      AND s.started_at + INTERVAL '1 hour') AS ip_sessions_1h
    FROM s
),
lab AS (
    SELECT s.session_id, array_agg(DISTINCT d.attack_type) AS attack_types
    FROM s JOIN detections d
      ON d.session_id = s.session_id
      OR (d.session_id IS NULL AND d.ip = s.ip
          AND (d.protocol IS NULL OR d.protocol = s.protocol)
          AND d.timestamp BETWEEN s.started_at - INTERVAL '5 minutes'
                              AND COALESCE(s.ended_at, s.started_at) + INTERVAL '30 minutes')
    GROUP BY s.session_id
)
SELECT s.session_id::text, s.ip, s.protocol, s.device, s.started_at,
       EXTRACT(EPOCH FROM COALESCE(s.ended_at, NOW()) - s.started_at) AS duration_s,
       COALESCE(ev.events_total, 0) AS events_total, COALESCE(ev.auth_attempts, 0) AS auth_attempts,
       COALESCE(ev.auth_success, 0) AS auth_success, COALESCE(ev.distinct_usernames, 0) AS distinct_usernames,
       COALESCE(ev.distinct_passwords, 0) AS distinct_passwords, COALESCE(ev.commands, 0) AS commands,
       COALESCE(ev.download_attempts, 0) AS download_attempts, COALESCE(ev.exec_attempts, 0) AS exec_attempts,
       COALESCE(ev.file_events, 0) AS file_events, COALESCE(ev.http_requests, 0) AS http_requests,
       COALESCE(ev.http_404, 0) AS http_404, COALESCE(ev.mqtt_publishes, 0) AS mqtt_publishes,
       COALESCE(ev.mqtt_control, 0) AS mqtt_control, COALESCE(ev.mqtt_wildcard_subs, 0) AS mqtt_wildcard_subs,
       COALESCE(ev.rtsp_requests, 0) AS rtsp_requests, COALESCE(ev.rtsp_route_probes, 0) AS rtsp_route_probes,
       COALESCE(ev.malformed, 0) AS malformed, COALESCE(ev.state_changes, 0) AS state_changes,
       COALESCE(ev.cmd_download, 0) AS cmd_download, COALESCE(ev.cmd_chmod, 0) AS cmd_chmod,
       COALESCE(ev.cmd_busybox, 0) AS cmd_busybox, COALESCE(ev.cmd_tmp_paths, 0) AS cmd_tmp_paths,
       COALESCE(ev.cmd_discovery, 0) AS cmd_discovery, round(COALESCE(ev.mean_cmd_len, 0)::numeric, 2) AS mean_cmd_len,
       round(COALESCE(gaps.mean_gap_s, 0)::numeric, 3) AS mean_gap_s,
       round(COALESCE(gaps.std_gap_s, 0)::numeric, 3) AS std_gap_s,
       ipctx.ip_protocols_1h, ipctx.ip_sessions_1h,
       COALESCE(lab.attack_types, '{{}}') AS attack_types
FROM s
LEFT JOIN ev ON ev.session_id = s.session_id
LEFT JOIN gaps ON gaps.session_id = s.session_id
LEFT JOIN ipctx ON ipctx.session_id = s.session_id
LEFT JOIN lab ON lab.session_id = s.session_id
ORDER BY s.started_at
"""

META_COLS = ["session_id", "ip", "protocol", "device", "started_at"]


def weak_label(attack_types):
    classes = {TYPE_TO_CLASS[t] for t in (attack_types or []) if t in TYPE_TO_CLASS}
    for c in CLASS_PRIORITY:
        if c in classes:
            return c
    return "normal"


def build_dataset(days=30, limit=200_000):
    rows = fetchdicts(FEATURE_SQL.format(days=int(days), limit=int(limit)))
    for r in rows:
        r["label"] = weak_label(r.get("attack_types"))
        r["attack_types"] = ";".join(sorted(r.get("attack_types") or []))
        for k, v in list(r.items()):
            if hasattr(v, "isoformat"):
                r[k] = v.isoformat()
            elif v is not None and type(v).__name__ == "Decimal":
                r[k] = float(v)
    return rows


def feature_names(rows):
    if not rows:
        return []
    return [k for k in rows[0] if k not in META_COLS + ["label", "attack_types"]]


def to_csv(rows):
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return buf.getvalue()


def summary(rows):
    counts = {c: 0 for c in CLASS_PRIORITY}
    for r in rows:
        counts[r["label"]] = counts.get(r["label"], 0) + 1
    return {"sessions": len(rows), "classes": counts, "features": feature_names(rows),
            "label_source": "weak labels from rule-engine detections (see ml/features.py)"}


if __name__ == "__main__":                      # python -m ml.features dataset.csv
    out = sys.argv[1] if len(sys.argv) > 1 else "honeybot_ml_dataset.csv"
    data = build_dataset()
    with open(out, "w", newline="") as f:
        f.write(to_csv(data))
    print(f"wrote {len(data)} sessions to {out}: {summary(data)['classes']}")
