"""
HoneyBot-IoT — Alert & Notification system (scope Module 6).

* channels   : Telegram Bot API and SMTP e-mail (HTML)
* thresholds : alerts.yaml – global min severity + per attack-type overrides
* dedupe     : one alert per attacker IP per window; a higher-severity detection
               inside the window is escalated once, everything else is stored
               as status='suppressed' (visible on the dashboard, not sent)
Every decision is written to the `alerts` table, so you can prove in the demo
that a 500-attempt Hydra run produced exactly ONE Telegram message.
"""

import os
import json
import html
import smtplib
import logging
import urllib.request
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

import yaml

from common.db import fetchall, execute

log = logging.getLogger("alerts")

CONFIG_PATH = os.environ.get("ALERTS_CONFIG", os.path.join(os.path.dirname(__file__), "alerts.yaml"))
SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ICON = {"LOW": "🔵", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}

_cfg = None


def config():
    global _cfg
    if _cfg is None:
        try:
            with open(CONFIG_PATH) as f:
                _cfg = yaml.safe_load(f) or {}
        except Exception as e:
            log.warning("alerts.yaml not loaded (%s) – using defaults", e)
            _cfg = {}
    return _cfg


def _passes_threshold(det):
    cfg = config()
    tcfg = (cfg.get("types") or {}).get(det["attack_type"], {})
    if tcfg.get("enabled") is False:
        return False
    need = tcfg.get("min_severity", cfg.get("min_severity", "HIGH"))
    return SEV_RANK.get(det["severity"], 0) >= SEV_RANK.get(need, 3)


def _recent_sent(ip, window):
    rows = fetchall(f"""
        SELECT severity FROM alerts
        WHERE ip=%s AND status IN ('sent','failed','disabled')
          AND ts > NOW() - INTERVAL '{int(window)} minutes'
    """, (ip,))
    return max([SEV_RANK.get(r[0], 0) for r in rows], default=0)


def format_text(det, geo):
    loc = f" ({geo})" if geo else ""
    mitre = ", ".join(f"{t} {n}" for t, n in zip(det.get("mitre") or [], det.get("mitre_names") or []))
    return (f"{ICON.get(det['severity'], '⚠️')} HoneyBot-IoT {det['severity']} — {det['attack_type']}\n"
            f"Attacker: {det['ip']}{loc}\n"
            f"Target: {det.get('device') or '-'} / {det.get('protocol') or '-'}\n"
            f"Details: {det['details']}\n"
            f"MITRE ATT&CK: {mitre or '-'}\n"
            f"Time: {det.get('timestamp')}")


def format_html(det, geo):
    rows = [("Attacker IP", det["ip"] + (f" ({geo})" if geo else "")),
            ("Attack type", det["attack_type"]), ("Severity", det["severity"]),
            ("Device / protocol", f"{det.get('device') or '-'} / {det.get('protocol') or '-'}"),
            ("Details", det["details"]),
            ("MITRE ATT&CK", ", ".join(f"{t} – {n}" for t, n in
                                       zip(det.get("mitre") or [], det.get("mitre_names") or []))),
            ("Detected", str(det.get("timestamp")))]
    color = {"CRITICAL": "#c62828", "HIGH": "#ef6c00", "MEDIUM": "#f9a825"}.get(det["severity"], "#1565c0")
    trs = "".join(f"<tr><td style='padding:6px 12px;color:#555'><b>{html.escape(k)}</b></td>"
                  f"<td style='padding:6px 12px'>{html.escape(str(v))}</td></tr>" for k, v in rows)
    return (f"<div style='font-family:Arial'><h2 style='background:{color};color:#fff;padding:10px'>"
            f"HoneyBot-IoT alert — {html.escape(det['attack_type'])}</h2><table>{trs}</table>"
            "<p style='color:#888;font-size:12px'>Automated alert from the HoneyBot-IoT research honeypot.</p></div>")


def send_telegram(text):
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (token and chat) or not (config().get("channels") or {}).get("telegram", {}).get("enabled", True):
        return "disabled", "TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set"
    data = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "true"}).encode()
    try:
        with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data, timeout=10) as r:
            body = json.loads(r.read().decode())
            return ("sent", None) if body.get("ok") else ("failed", str(body)[:300])
    except Exception as e:
        return "failed", str(e)[:300]


def email_configured():
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("ALERT_EMAIL_TO")) and \
        (config().get("channels") or {}).get("email", {}).get("enabled", True)


def send_email(subject, html_body, text_body, attachments=None):
    """attachments: list of (filename, bytes, mime) – used for the PDF threat reports."""
    to = os.environ.get("ALERT_EMAIL_TO")
    host = os.environ.get("SMTP_HOST")
    if not email_configured():
        return "disabled", "SMTP_HOST / ALERT_EMAIL_TO not set"
    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(text_body, "plain", "utf-8"))
    alt.attach(MIMEText(html_body, "html", "utf-8"))
    if attachments:
        msg = MIMEMultipart("mixed")
        msg.attach(alt)
        for name, data, mime in attachments:
            part = MIMEApplication(data, _subtype=mime.split("/")[-1])
            part.add_header("Content-Disposition", "attachment", filename=name)
            msg.attach(part)
    else:
        msg = alt
    msg["Subject"] = subject
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "honeybot@localhost"))
    msg["To"] = to
    try:
        port = int(os.environ.get("SMTP_PORT", 587))
        with smtplib.SMTP(host, port, timeout=15) as s:
            if port != 25:
                s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            s.sendmail(msg["From"], [a.strip() for a in to.split(",")], msg.as_string())
        return "sent", None
    except Exception as e:
        return "failed", str(e)[:300]


def _record(det, channel, status, message, error=None):
    execute("""INSERT INTO alerts (detection_id, ip, attack_type, severity, channel, status, message, error)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (det.get("id"), det["ip"], det["attack_type"], det["severity"], channel, status,
             message[:2000], error))


def notify(detections):
    """Process newly created detections (list of dicts incl. id, mitre, mitre_names)."""
    window = config().get("dedupe_window_minutes", 10)
    sent = 0
    # strongest first, so one Hydra run → one message with the highest severity
    for det in sorted(detections, key=lambda d: -SEV_RANK.get(d["severity"], 0)):
        if not _passes_threshold(det):
            continue
        geo_row = fetchall("SELECT city, country FROM attackers WHERE ip=%s", (det["ip"],))
        geo = ", ".join(x for x in (geo_row[0] if geo_row else ()) if x)
        text = format_text(det, geo)
        last = _recent_sent(det["ip"], window)
        if last and SEV_RANK.get(det["severity"], 0) <= last:
            _record(det, "dedupe", "suppressed", text, f"already alerted for {det['ip']} in last {window} min")
            continue
        escalation = bool(last)
        if escalation:
            text = "⬆️ ESCALATION\n" + text
        tg_status, tg_err = send_telegram(text)
        _record(det, "telegram", tg_status, text, tg_err)
        em_status, em_err = send_email(f"[HoneyBot-IoT] {det['severity']} {det['attack_type']} from {det['ip']}",
                                       format_html(det, geo), text)
        _record(det, "email", em_status, text, em_err)
        execute("UPDATE detections SET alerted=TRUE WHERE id=%s", (det.get("id"),))
        sent += 1
        log.info("ALERT %s %s %s | telegram=%s email=%s", det["severity"], det["attack_type"], det["ip"],
                 tg_status, em_status)
    return sent
