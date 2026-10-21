"""
HoneyBot-IoT — threat summary reports (scope M4 "automated daily and weekly threat
summary reports delivered via the dashboard and email", M5 "on-demand PDF report
generation with embedded charts").

    build_report(hours)   -> dict   (also served as JSON by GET /api/report)
    render_pdf(report)    -> bytes  (GET /api/report.pdf, e-mail attachment)
    maybe_send_daily()            called by the intel engine every pass; sends the
                                  daily report once per day after REPORT_HOUR_UTC and a
                                  7-day report on Mondays, if SMTP is configured.

The "analyst summary" paragraph is rule-based text generated from the numbers. The
LLM threat narrator (scope M8-FE-3) will replace it at the 100% milestone.
"""

import io
import os
import logging
from datetime import datetime, timezone

from common.db import fetchall, fetchdicts, scalar, execute

log = logging.getLogger("report")

PROTOCOLS = ["SSH", "Telnet", "HTTP", "MQTT", "RTSP"]
REPORT_HOUR_UTC = int(os.environ.get("REPORT_HOUR_UTC", 6))


def _iso(rows):
    for r in rows:
        for k, v in list(r.items()):
            if hasattr(v, "isoformat"):
                r[k] = v.isoformat()
            elif k == "session_id" and v is not None:
                r[k] = str(v)
    return rows


def build_report(hours=24):
    hours = max(1, min(int(hours), 24 * 90))
    w = f"INTERVAL '{hours} hours'"
    per_proto = dict(fetchall(f"SELECT protocol, COUNT(*) FROM events WHERE ts > NOW() - {w} GROUP BY 1"))
    sev = dict(fetchall(f"SELECT severity, COUNT(*) FROM detections WHERE timestamp > NOW() - {w} GROUP BY 1"))
    rep = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window_hours": hours,
        "totals": {
            "events": scalar(f"SELECT COUNT(*) FROM events WHERE ts > NOW() - {w}"),
            "sessions": scalar(f"SELECT COUNT(*) FROM sessions WHERE started_at > NOW() - {w}"),
            "unique_ips": scalar(f"SELECT COUNT(DISTINCT ip) FROM events WHERE ts > NOW() - {w}"),
            "auth_attempts": scalar(f"SELECT COUNT(*) FROM events WHERE event_type='auth' AND ts > NOW() - {w}"),
            "successful_logins": scalar(f"SELECT COUNT(*) FROM events WHERE event_type='auth' AND success "
                                        f"AND ts > NOW() - {w}"),
            "commands": scalar(f"SELECT COUNT(*) FROM events WHERE event_type='command' AND ts > NOW() - {w}"),
            "detections": sum(sev.values()),
            "samples": scalar(f"SELECT COUNT(DISTINCT sha256) FROM file_captures WHERE ts > NOW() - {w}"),
            "iocs": scalar(f"SELECT COUNT(*) FROM iocs WHERE last_seen > NOW() - {w}"),
            "alerts_sent": scalar(f"SELECT COUNT(*) FROM alerts WHERE status='sent' AND ts > NOW() - {w}"),
        },
        "events_by_protocol": {p: per_proto.get(p, 0) for p in PROTOCOLS},
        "detections_by_severity": {s: sev.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "detections_by_type": fetchdicts(f"""
            SELECT attack_type, COUNT(*) AS count,
                   -- rank, not alphabetical max (alphabetically MEDIUM > HIGH > CRITICAL)
                   (ARRAY['LOW','MEDIUM','HIGH','CRITICAL'])[
                       max(array_position(ARRAY['LOW','MEDIUM','HIGH','CRITICAL'], severity))] AS max_severity
            FROM detections WHERE timestamp > NOW() - {w}
            GROUP BY attack_type ORDER BY count DESC"""),
        "top_attackers": _iso(fetchdicts(f"""
            SELECT a.ip, a.country, a.country_code, a.geo_source, a.threat_level, a.threat_score,
                   a.protocols, COUNT(e.*) AS events
            FROM attackers a JOIN events e ON e.ip = a.ip AND e.ts > NOW() - {w}
            GROUP BY a.ip, a.country, a.country_code, a.geo_source, a.threat_level, a.threat_score, a.protocols
            ORDER BY a.threat_score DESC, events DESC LIMIT 10""")),
        "top_credentials": fetchdicts(f"""
            SELECT username, password, COUNT(*) AS count, bool_or(success) AS worked
            FROM events WHERE event_type='auth' AND password IS NOT NULL AND ts > NOW() - {w}
            GROUP BY username, password ORDER BY count DESC LIMIT 10"""),
        "top_commands": fetchdicts(f"""
            SELECT left(command, 90) AS command, COUNT(*) AS count FROM events
            WHERE event_type='command' AND ts > NOW() - {w} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"""),
        "mitre": fetchdicts(f"""
            SELECT t.id AS technique, t.name, COUNT(*) AS detections
            FROM detections d, LATERAL unnest(d.mitre, d.mitre_names) AS t(id, name)
            WHERE d.timestamp > NOW() - {w} GROUP BY t.id, t.name ORDER BY 3 DESC LIMIT 12"""),
        "samples": _iso(fetchdicts(f"""
            SELECT sha256, max(size) AS size, max(mime_type) AS mime_type, max(arch) AS arch,
                   max(yara_result) AS yara_result, COUNT(*) AS times, string_agg(DISTINCT ip, ', ') AS ips
            FROM file_captures WHERE ts > NOW() - {w} GROUP BY sha256 ORDER BY times DESC LIMIT 15""")),
        "new_iocs": _iso(fetchdicts(f"""
            SELECT type, value, hits, source_ip FROM iocs WHERE first_seen > NOW() - {w}
            ORDER BY hits DESC LIMIT 20""")),
        "campaigns": _iso(fetchdicts(f"""
            SELECT campaign_id, array_length(ips, 1) AS ips, description FROM campaigns
            WHERE last_seen > NOW() - {w} ORDER BY last_seen DESC LIMIT 10""")),
    }
    rep["summary"] = summarize(rep)
    return rep


def summarize(r):
    """Rule-based analyst paragraph (placeholder for the M8 LLM narrator)."""
    t = r["totals"]
    if not t["events"]:
        return (f"No attacker activity was recorded in the last {r['window_hours']} hours. "
                "All honeypot services should be checked for availability.")
    busiest = max(r["events_by_protocol"], key=r["events_by_protocol"].get)
    crit = r["detections_by_severity"]["CRITICAL"]
    parts = [f"In the last {r['window_hours']} hours the honeynet recorded {t['events']:,} events from "
             f"{t['unique_ips']} source IPs across {t['sessions']} sessions; {busiest} was the most targeted "
             f"protocol."]
    if t["auth_attempts"]:
        rate = 100.0 * t["successful_logins"] / t["auth_attempts"]
        parts.append(f"{t['auth_attempts']:,} login attempts were made and {t['successful_logins']} "
                     f"({rate:.1f}%) succeeded with default credentials, giving attackers shell access.")
    if r["detections_by_type"]:
        top = ", ".join(f"{d['attack_type']} ({d['count']})" for d in r["detections_by_type"][:3])
        parts.append(f"The rule engine raised {t['detections']} detections ({crit} critical); the most "
                     f"frequent were {top}.")
    if t["samples"]:
        fams = sorted({f.strip() for s in r["samples"] for f in (s.get("yara_result") or "").split(",")
                       if f.strip() and f.strip() not in ("CLEAN", "UNAVAILABLE", "ERROR")})
        parts.append(f"{t['samples']} distinct malware sample(s) were captured"
                     + (f"; YARA identified: {', '.join(fams)}." if fams else "."))
    if r["top_attackers"]:
        a = r["top_attackers"][0]
        where = a.get("country") or "unknown location"
        if a.get("geo_source") == "demo":
            where = "lab address, demo location"
        parts.append(f"The highest-risk source was {a['ip']} ({where}, threat score {a['threat_score']}/100).")
    parts.append("Recommended actions: block the listed IOCs at the perimeter, rotate any default "
                 "credentials on real devices of these types, and disable Telnet / anonymous MQTT where "
                 "possible.")
    return " ".join(parts)


# ── PDF ─────────────────────────────────────────────────────────────────────
def render_pdf(r):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.barcharts import VerticalBarChart, HorizontalBarChart

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm,
                            title=f"HoneyBot-IoT threat report ({r['window_hours']} h)", author="HoneyBot-IoT")
    ss = getSampleStyleSheet()
    h1, h2, body = ss["Title"], ss["Heading2"], ss["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    teal = colors.HexColor("#0f766e")

    def table(rows, widths, header=True):
        rows = [[Paragraph(str(c) if c is not None else "–", small) for c in row] for row in rows]
        tb = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                 ("VALIGN", (0, 0), (-1, -1), "TOP")]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0"))]
        tb.setStyle(TableStyle(style))
        return tb

    story = [Paragraph("HoneyBot-IoT — Threat Summary Report", h1),
             Paragraph(f"Window: last {r['window_hours']} hours &nbsp;·&nbsp; generated {r['generated_at']} UTC",
                       small), Spacer(1, 6),
             Paragraph("Analyst summary", h2), Paragraph(r["summary"], body), Spacer(1, 6)]

    t = r["totals"]
    story += [Paragraph("Key figures", h2), table([
        ["Events", "Sessions", "Unique IPs", "Logins (ok)", "Commands", "Detections", "Samples", "IOCs"],
        [f"{t['events']:,}", t["sessions"], t["unique_ips"], f"{t['auth_attempts']} ({t['successful_logins']})",
         t["commands"], t["detections"], t["samples"], t["iocs"]]], [22 * mm] * 8)]

    # chart 1: events by protocol
    d = Drawing(170 * mm, 55 * mm)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 12 * mm, 8 * mm, 150 * mm, 42 * mm
    bc.data = [[r["events_by_protocol"][p] for p in PROTOCOLS]]
    bc.categoryAxis.categoryNames = PROTOCOLS
    bc.valueAxis.valueMin = 0
    bc.bars[0].fillColor = teal
    bc.barLabelFormat, bc.barLabels.nudge = "%d", 6
    d.add(bc)
    story += [Spacer(1, 6), Paragraph("Events by protocol", h2), d]

    # chart 2: detections by type
    types = r["detections_by_type"][:10]
    if types:
        d2 = Drawing(170 * mm, max(30, 7 * len(types)) * mm)
        hb = HorizontalBarChart()
        hb.x, hb.y = 52 * mm, 4 * mm
        hb.width, hb.height = 110 * mm, (7 * len(types) - 6) * mm
        hb.data = [[x["count"] for x in reversed(types)]]
        hb.categoryAxis.categoryNames = [x["attack_type"] for x in reversed(types)]
        hb.categoryAxis.labels.fontSize = 7
        hb.valueAxis.valueMin = 0
        hb.bars[0].fillColor = colors.HexColor("#c2410c")
        d2.add(hb)
        story += [Paragraph("Detections by attack type", h2), d2]

    if r["top_attackers"]:
        story += [Paragraph("Top attackers", h2), table(
            [["IP", "Country", "Threat", "Score", "Events", "Protocols"]] +
            [[a["ip"], a.get("country"), a["threat_level"], a["threat_score"], a["events"],
              ", ".join(a.get("protocols") or [])] for a in r["top_attackers"]],
            [32 * mm, 30 * mm, 20 * mm, 14 * mm, 18 * mm, 64 * mm])]
    if r["mitre"]:
        story += [Paragraph("MITRE ATT&CK techniques", h2), table(
            [["Technique", "Name", "Detections"]] + [[m["technique"], m["name"], m["detections"]]
                                                       for m in r["mitre"]],
            [24 * mm, 130 * mm, 24 * mm])]
    if r["top_credentials"]:
        story += [Paragraph("Most-tried credentials", h2), table(
            [["Username", "Password", "Tries", "Worked"]] +
            [[c["username"], c["password"], c["count"], "yes" if c["worked"] else "no"]
             for c in r["top_credentials"]], [50 * mm, 70 * mm, 25 * mm, 25 * mm])]
    if r["samples"]:
        story += [Paragraph("Captured malware samples", h2), table(
            [["SHA-256", "Type / arch", "Size", "YARA", "Seen"]] +
            [[s["sha256"][:32] + "…", s.get("arch") or s.get("mime_type"), s["size"], s.get("yara_result") or "pending",
              s["times"]] for s in r["samples"]],
            [62 * mm, 40 * mm, 18 * mm, 40 * mm, 14 * mm])]
    if r["new_iocs"]:
        story += [Paragraph("New indicators of compromise", h2), table(
            [["Type", "Value", "Hits", "Source"]] + [[i["type"], i["value"][:80], i["hits"], i["source_ip"]]
                                                       for i in r["new_iocs"]],
            [16 * mm, 110 * mm, 14 * mm, 34 * mm])]
    story += [Spacer(1, 8), Paragraph(
        "Generated automatically by the HoneyBot-IoT research honeypot. Indicators are observed attacker "
        "behaviour on an isolated honeynet; validate before blocking in production.", small)]
    doc.build(story)
    return buf.getvalue()


# ── scheduled delivery ──────────────────────────────────────────────────────
def _state(key):
    rows = fetchall("SELECT value FROM intel_state WHERE key=%s", (key,))
    return rows[0][0] if rows else None


def _set_state(key, value):
    execute("""INSERT INTO intel_state (key, value, updated_at) VALUES (%s,%s,NOW())
               ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()""", (key, value))


def maybe_send_daily(now=None):
    """Send the daily (and Monday weekly) report once, after REPORT_HOUR_UTC."""
    from alerts import notifier
    now = now or datetime.now(timezone.utc)
    if now.hour < REPORT_HOUR_UTC or not notifier.email_configured():
        return None
    today = now.strftime("%Y-%m-%d")
    sent = []
    jobs = [("daily", 24, "last_daily_report")]
    if now.weekday() == 0:
        jobs.append(("weekly", 24 * 7, "last_weekly_report"))
    for name, hours, key in jobs:
        if _state(key) == today:
            continue
        r = build_report(hours)
        pdf = render_pdf(r)
        status, err = notifier.send_email(
            f"[HoneyBot-IoT] {name} threat report — {today}",
            f"<p>{r['summary']}</p><p>The full report is attached as PDF.</p>", r["summary"],
            attachments=[(f"honeybot-{name}-report-{today}.pdf", pdf, "application/pdf")])
        execute("""INSERT INTO alerts (ip, attack_type, severity, channel, status, message, error)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                ("-", f"{name.upper()}_REPORT", "LOW", "email", status, r["summary"][:2000], err))
        if status in ("sent", "failed"):      # one attempt per day – never spam on SMTP errors
            _set_state(key, today)
        sent.append((name, status))
        log.info("%s report: %s %s", name, status, err or "")
    return sent
