"""
HoneyBot-IoT — rule-based attack detection (scope M3 + M4).

All rules work on the unified `events` table and use TIME WINDOWS
(fix: v0.3 counted brute-force attempts over all time).
Each rule returns a list of detection dicts; engine.py stores them with a
dedupe key  ip | type | protocol | time-bucket  so a sustained attack gives
one detection per bucket instead of one per run.

The six ML classes planned for Module 8 map onto these rule outputs, so the
rules double as weak labels for the classifier later:
    brute-force      ← BRUTE_FORCE, CREDENTIAL_STUFFING
    malware delivery ← MALWARE_DELIVERY, MIRAI_SIGNATURE, MALWARE_FAMILY
    botnet C2        ← BOTNET_C2, ICS_UNAUTHORIZED_COMMAND
    port scan        ← RECONNAISSANCE, WEB_SCAN, RTSP_ROUTE_ENUM
    protocol exploit ← PROTOCOL_EXPLOIT
    normal           ← sessions with none of the above
"""

import os
import re

from common.db import fetchall

BF_WINDOW_MIN = int(os.environ.get("BF_WINDOW_MIN", 10))
BF_THRESHOLD = int(os.environ.get("BF_THRESHOLD", 5))
SCAN_WINDOW_MIN = 5
WEB404_THRESHOLD = 10

DEVICE_TOPICS_RE = r"^(sensor|lock|camera|devices)/"

EXPLOIT_PATTERNS = [
    (r"\.\./|%2e%2e|\.\.%2f|%252e",                    "path traversal"),
    (r"(;|\||`|\$\(|%3b|%7c|%60)\s*(wget|curl|sh|busybox|tftp|cd|echo|rm|nc)\b", "command injection"),
    (r"/shell\?|/cgi-bin/.*\b(cmd|exec)=",             "web shell / CGI command execution"),
    (r"/HNAP1|/GponForm/diag_Form|/boaform/admin/formPing|/tmUnblock\.cgi|/picsdesc\.xml"
     r"|/ctrlt/DeviceUpgrade_1|/setup\.cgi\?next_file|/goform/|/cgi-bin/luci/;stok="
     r"|/language/Swedish|/apply\.cgi|/HNAP1/",        "known IoT exploit path"),
    (r"/\.env|/\.git/|/wp-login\.php|/phpmyadmin|/actuator/|/vendor/phpunit", "web app probe"),
    (r"<script|%3cscript|union\s+select|' or '1'='1",  "XSS / SQL injection"),
    (r"\$\{jndi:",                                     "Log4Shell"),
]
_EXPLOIT = [(re.compile(rx, re.I), name) for rx, name in EXPLOIT_PATTERNS]

DISCOVERY_RE = re.compile(r"\b(uname|cat /proc/(cpuinfo|version|meminfo)|nproc|ps|ifconfig|id|whoami|"
                          r"netstat|free|df|ls|cat /etc/passwd|route|w)\b")
MIRAI_RE = re.compile(r"/bin/busybox\s+[A-Z]{4,}|\b(ECCHI|MIRAI|SATORI|OKIRU|MASUTA|GAFGYT)\b|"
                      r"/bin/busybox\s+(ps|cat|echo|wget|tftp)|cat /proc/mounts", re.I)

# ── v0.8 behavioural patterns (seen in the REAL restricted shell) ───────────
# Each maps (regex over a session's commands) → (attack_type, severity, label).
BEHAVIOURS = [
    (re.compile(r"\bcrontab\b|/etc/cron|/etc/init\.d/|/etc/rc\.local|>>?\s*\S*rcS\b|"
                r"\bupdate-rc\.d\b|/etc/rc\d?\.d/", re.I),
     "PERSISTENCE", "HIGH", "boot/cron persistence"),
    (re.compile(r"\b(pkill|kill(all)?)\s+(-9\s+)?(watchdog|dropbear|telnetd|lockd|sensor_daemon|sonia)\b|"
                r">\s*/dev/watchdog|\bwatchdog\b.*\b(stop|disable)\b", re.I),
     "DEFENSE_EVASION", "HIGH", "watchdog / security daemon kill"),
    (re.compile(r"\bhistory\s+-c\b|>\s*/root/\.\w*history|\brm\s+-f?\s*/var/log|"
                r"\biptables\s+-F\b|\bunset\s+HISTFILE", re.I),
     "DEFENSE_EVASION", "MEDIUM", "log / history / firewall tampering"),
    (re.compile(r":\(\)\s*\{\s*:\|\s*:&\s*\}\s*;?\s*:|\bwhile\s*:\s*;\s*do\b|"
                r"\bdd\s+if=/dev/zero\b|\b(yes|cat)\s+/dev/urandom\b", re.I),
     "DENIAL_OF_SERVICE", "HIGH", "fork bomb / resource exhaustion"),
    (re.compile(r"\b(xmrig|minerd|cpuminer|cgminer|ccminer)\b|stratum\+tcp://|"
                r"\b(pool\.minexmr|nanopool|supportxmr|coinhive)\b|--donate-level", re.I),
     "CRYPTO_MINING", "HIGH", "crypto-miner deployment"),
    (re.compile(r"\bnsenter\b|/proc/1/(root|ns)|\bchroot\s+/proc|\bunshare\b|/dev/mem\b|"
                r"\binsmod\b|\bdocker(\.sock)?\b|/var/run/docker|cgroup.*release_agent|"
                r"\bcapsh\b|/sys/kernel", re.I),
     "CONTAINER_ESCAPE", "CRITICAL", "sandbox / container escape attempt"),
    (re.compile(r"/dev/tcp/\d|\bnc\b[^\n]*\s-e\b|\bncat\b[^\n]*--exec|mkfifo\s+\S+;.*\|\s*(/bin/)?sh|"
                r"python[0-9]?\s+-c\s+['\"].*socket|\bsh\s+-i\b.*>&|\bsocat\b.*exec", re.I),
     "REVERSE_SHELL", "CRITICAL", "reverse-shell / bind-shell attempt"),
]


def _det(ip, attack_type, severity, details, protocol=None, device=None, session_id=None):
    return dict(ip=ip, attack_type=attack_type, severity=severity, details=details,
                protocol=protocol, device=device, session_id=session_id)


def brute_force():
    out = []
    rows = fetchall(f"""
        SELECT ip, protocol, min(device), COUNT(*) FILTER (WHERE success IS NOT TRUE) AS fails,
               COUNT(*) FILTER (WHERE success) AS ok, COUNT(DISTINCT username) AS users,
               COUNT(DISTINCT password) AS pwds
        FROM events
        WHERE event_type='auth' AND ts > NOW() - INTERVAL '{BF_WINDOW_MIN} minutes'
        GROUP BY ip, protocol
        HAVING COUNT(*) FILTER (WHERE success IS NOT TRUE) >= %s
    """, (BF_THRESHOLD,))
    for ip, proto, dev, fails, ok, users, pwds in rows:
        sev = "CRITICAL" if fails >= 50 else "HIGH" if fails >= 20 else "MEDIUM"
        out.append(_det(ip, "BRUTE_FORCE", sev,
                        f"{fails} failed {proto} logins in {BF_WINDOW_MIN} min "
                        f"({users} usernames, {pwds} passwords){'; ' + str(ok) + ' succeeded' if ok else ''}",
                        proto, dev))
    return out


def credential_compromise():
    """Successful default-credential logins, aggregated per IP/device/protocol."""
    rows = fetchall("""
        SELECT e.ip, e.protocol, e.device,
               string_agg(DISTINCT coalesce(e.username,'') || ':' || coalesce(e.password,''), ', '),
               COUNT(*), max(e.session_id::text),
               SUM((SELECT COUNT(*) FROM events f WHERE f.ip=e.ip AND f.event_type='auth'
                      AND f.success IS NOT TRUE AND f.ts < e.ts
                      AND f.ts > e.ts - INTERVAL '30 minutes')) AS prior
        FROM events e
        WHERE e.event_type='auth' AND e.success AND e.ts > NOW() - INTERVAL '15 minutes'
        GROUP BY e.ip, e.protocol, e.device
    """)
    out = []
    for ip, proto, dev, creds, n, sid, prior in rows:
        sev = "HIGH" if (prior or 0) >= 3 else "MEDIUM"
        creds = creds if creds and creds.strip(" ,:") else "(anonymous)"
        out.append(_det(ip, "CREDENTIAL_COMPROMISE", sev,
                        f"Default credentials accepted on {dev}/{proto}: {creds[:120]} "
                        f"({n} successful logins after {prior or 0} failures)", proto, dev,
                        sid if sid else None))
    return out


def credential_stuffing():
    rows = fetchall("""
        SELECT ip, password, COUNT(DISTINCT username), string_agg(DISTINCT username, ','),
               string_agg(DISTINCT protocol, ',')
        FROM events
        WHERE event_type='auth' AND password IS NOT NULL AND password <> ''
          AND ts > NOW() - INTERVAL '30 minutes'
        GROUP BY ip, password HAVING COUNT(DISTINCT username) >= 3
    """)
    return [_det(ip, "CREDENTIAL_STUFFING", "MEDIUM",
                 f"Password '{pw}' tried with {n} usernames ({users[:60]}) over {protos}", protos.split(",")[0])
            for ip, pw, n, users, protos in rows]


def reconnaissance():
    out = []
    rows = fetchall(f"""
        SELECT s.ip, COUNT(DISTINCT s.dst_port), string_agg(DISTINCT s.protocol, ','),
               COUNT(*) FILTER (WHERE s.auth_attempts = 0 AND s.commands = 0)
        FROM sessions s
        WHERE s.started_at > NOW() - INTERVAL '{SCAN_WINDOW_MIN} minutes'
        GROUP BY s.ip HAVING COUNT(DISTINCT s.dst_port) >= 3
    """)
    for ip, ports, protos, empty in rows:
        sev = "MEDIUM" if ports >= 5 else "LOW"
        out.append(_det(ip, "RECONNAISSANCE", sev,
                        f"Probed {ports} honeypot ports in {SCAN_WINDOW_MIN} min ({protos}); "
                        f"{empty} connections without login", None))
    rows = fetchall("""
        SELECT ip, COUNT(*), COUNT(DISTINCT raw->>'path')
        FROM events WHERE event_type='http_request' AND (raw->>'status')::int = 404
          AND ts > NOW() - INTERVAL '10 minutes'
        GROUP BY ip HAVING COUNT(*) >= %s
    """, (WEB404_THRESHOLD,))
    for ip, n, paths in rows:
        out.append(_det(ip, "WEB_SCAN", "MEDIUM" if n < 100 else "HIGH",
                        f"{n} requests to {paths} non-existent paths (vulnerability scanner)", "HTTP"))
    rows = fetchall("""
        SELECT ip, COUNT(DISTINCT payload) FROM events
        WHERE event_type='rtsp_route_probe' AND ts > NOW() - INTERVAL '10 minutes'
        GROUP BY ip HAVING COUNT(DISTINCT payload) >= 3
    """)
    for ip, n in rows:
        out.append(_det(ip, "RTSP_ROUTE_ENUM", "MEDIUM",
                        f"{n} RTSP stream paths enumerated (Cameradar-style)", "RTSP", "cctv"))
    return out


def malware_delivery():
    out = []
    rows = fetchall("""
        SELECT ip, protocol, device, session_id, string_agg(DISTINCT payload, ' ' ORDER BY payload),
               COUNT(*)
        FROM events WHERE event_type='download_attempt' AND ts > NOW() - INTERVAL '15 minutes'
        GROUP BY ip, protocol, device, session_id
    """)
    for ip, proto, dev, sid, urls, n in rows:
        executed = fetchall("SELECT COUNT(*) FROM events WHERE session_id=%s AND event_type='exec_attempt'",
                            (sid,))
        sev = "CRITICAL" if executed and executed[0][0] else "HIGH"
        out.append(_det(ip, "MALWARE_DELIVERY", sev,
                        f"Download of {n} payload(s): {urls[:180]}"
                        + (" — and attempted to execute it" if sev == "CRITICAL" else ""),
                        proto, dev, sid))
    # samples quarantined by common/capture.py (uploads, SSH stdin/scp, shell drops, MQTT blobs)
    rows = fetchall("""
        SELECT ip, protocol, device, session_id, COUNT(*), string_agg(DISTINCT coalesce(arch, mime_type), ', '),
               string_agg(DISTINCT source, ', ')
        FROM file_captures WHERE ts > NOW() - INTERVAL '15 minutes'
        GROUP BY ip, protocol, device, session_id
    """)
    for ip, proto, dev, sid, n, kinds, sources in rows:
        out.append(_det(ip, "MALWARE_DELIVERY", "HIGH",
                        f"{n} sample(s) captured via {sources}: {kinds}", proto, dev, sid))
    return out


def malware_family():
    """YARA identified a known IoT malware family in a captured sample."""
    rows = fetchall("""
        SELECT ip, protocol, device, session_id, string_agg(DISTINCT yara_result, '; '),
               string_agg(DISTINCT left(sha256, 16), ', ')
        FROM file_captures
        WHERE scanned_at > NOW() - INTERVAL '30 minutes'
          AND yara_result NOT IN ('CLEAN', 'UNAVAILABLE', 'ERROR')
        GROUP BY ip, protocol, device, session_id
    """)
    out = []
    for ip, proto, dev, sid, fams, shas in rows:
        generic_only = all(f.strip() in ("generic-iot-elf", "upx-packed")
                           for part in (fams or "").split(";") for f in part.split(","))
        out.append(_det(ip, "MALWARE_FAMILY", "HIGH" if generic_only else "CRITICAL",
                        f"YARA: {fams} (sha256 {shas}…)", proto, dev, sid))
    return out


def mirai_and_post_exploitation():
    out = []
    rows = fetchall("""
        SELECT session_id, ip, protocol, device, array_agg(command ORDER BY ts)
        FROM events WHERE event_type='command' AND ts > NOW() - INTERVAL '15 minutes'
        GROUP BY session_id, ip, protocol, device
    """)
    for sid, ip, proto, dev, cmds in rows:
        cmds = [c for c in cmds if c]
        joined = " ; ".join(cmds)
        preamble = sum(1 for c in cmds if c.strip() in ("enable", "system", "shell", "sh", "linuxshell"))
        if MIRAI_RE.search(joined) or preamble >= 3:
            out.append(_det(ip, "MIRAI_SIGNATURE", "HIGH",
                            f"Mirai-family bot command pattern: {joined[:160]}", proto, dev, sid))
        disc = sum(1 for c in cmds if DISCOVERY_RE.search(c))
        if disc >= 3:
            out.append(_det(ip, "POST_EXPLOITATION", "MEDIUM",
                            f"{disc} system-discovery commands after login ({len(cmds)} commands total)",
                            proto, dev, sid))
    return out


def behavioural():
    """Post-exploitation behaviour visible in the real restricted shell: persistence,
    defence evasion, DoS, crypto-mining, container escape, reverse shells."""
    out = []
    rows = fetchall("""
        SELECT session_id, ip, protocol, device, string_agg(command, ' ; ' ORDER BY ts)
        FROM events WHERE event_type='command' AND command IS NOT NULL
          AND ts > NOW() - INTERVAL '15 minutes'
        GROUP BY session_id, ip, protocol, device
    """)
    for sid, ip, proto, dev, joined in rows:
        joined = joined or ""
        for rx, atype, sev, label in BEHAVIOURS:
            if rx.search(joined):
                m = rx.search(joined)
                snippet = joined[max(0, m.start() - 10):m.start() + 120]
                out.append(_det(ip, atype, sev, f"{label}: …{snippet.strip()}…", proto, dev, sid))
    return out


def modbus_ics():
    """Modbus/TCP ICS activity: register writes (parameter tampering) and scanning."""
    out = []
    rows = fetchall("""
        SELECT ip, device, session_id,
               COUNT(*) FILTER (WHERE event_type='modbus_write'),
               COUNT(*) FILTER (WHERE event_type='modbus_request'),
               string_agg(DISTINCT payload, '; ') FILTER (WHERE event_type='modbus_write')
        FROM events WHERE protocol='Modbus' AND ts > NOW() - INTERVAL '15 minutes'
        GROUP BY ip, device, session_id
    """)
    for ip, dev, sid, writes, reads, wpayload in rows:
        if writes:
            out.append(_det(ip, "ICS_PARAMETER_TAMPERING", "CRITICAL",
                            f"{writes} Modbus register write(s): {(wpayload or '')[:160]}",
                            "Modbus", dev, sid))
        if reads >= 10 and not writes:
            out.append(_det(ip, "ICS_DEVICE_SCAN", "MEDIUM",
                            f"{reads} Modbus reads (register/coil enumeration)", "Modbus", dev, sid))
    return out


def mqtt_and_ics():
    out = []
    rows = fetchall(f"""
        SELECT ip, COUNT(*) FILTER (WHERE event_type='mqtt_publish' AND raw->>'topic' !~ '{DEVICE_TOPICS_RE}'),
               COUNT(*) FILTER (WHERE event_type='mqtt_subscribe' AND payload IN ('#','$SYS/#','+/#')),
               COUNT(*) FILTER (WHERE event_type='mqtt_publish'),
               string_agg(DISTINCT raw->>'topic', ',')
        FROM events WHERE protocol='MQTT' AND ts > NOW() - INTERVAL '10 minutes'
        GROUP BY ip
    """)
    for ip, foreign_pub, wildcard_sub, pubs, topics in rows:
        if pubs >= int(os.environ.get("MQTT_FLOOD_THRESHOLD", 50)):
            out.append(_det(ip, "MQTT_FLOOD", "HIGH",
                            f"MQTT publish flood: {pubs} messages in 10 min", "MQTT"))
        if foreign_pub >= 3 or (wildcard_sub and pubs >= 5):
            out.append(_det(ip, "BOTNET_C2", "HIGH",
                            f"Broker abused as C2 channel: {pubs} publishes ({foreign_pub} to non-device topics), "
                            f"wildcard subscriptions={wildcard_sub}; topics: {(topics or '')[:120]}", "MQTT"))
        elif wildcard_sub:
            out.append(_det(ip, "ICS_PROCESS_MONITORING", "LOW",
                            "Subscribed to all topics (#) – monitoring live process values", "MQTT", "sensor"))
    rows = fetchall("""
        SELECT ip, protocol, device, session_id, string_agg(payload, '; ')
        FROM events WHERE event_type='state_change' AND ts > NOW() - INTERVAL '15 minutes'
        GROUP BY ip, protocol, device, session_id
    """)
    for ip, proto, dev, sid, changes in rows:
        sev = "CRITICAL" if "unlocked" in (changes or "") else "HIGH"
        out.append(_det(ip, "ICS_UNAUTHORIZED_COMMAND", sev,
                        f"Device state changed by attacker via {proto}: {changes[:160]}", proto, dev, sid))
        if "recording" in (changes or "") and "off" in (changes or ""):
            out.append(_det(ip, "DENIAL_OF_VIEW", "HIGH", "Camera recording disabled", proto, "cctv", sid))
    return out


def protocol_exploit():
    out = []
    rows = fetchall("""
        SELECT ip, protocol, device, session_id, command, payload FROM events
        WHERE event_type IN ('http_request','rtsp_request','command') AND ts > NOW() - INTERVAL '15 minutes'
    """)
    seen = set()
    for ip, proto, dev, sid, cmd, payload in rows:
        if proto not in ("HTTP", "RTSP"):
            continue
        text = f"{cmd or ''} {payload or ''}"
        for rx, name in _EXPLOIT:
            if rx.search(text) and (ip, name) not in seen:
                seen.add((ip, name))
                out.append(_det(ip, "PROTOCOL_EXPLOIT", "HIGH", f"{name}: {text.strip()[:160]}",
                                proto, dev, sid))
    rows = fetchall("""
        SELECT ip, protocol, COUNT(*), min(payload) FROM events
        WHERE event_type IN ('malformed','stream_injection_attempt','port_forward_request','channel_request')
          AND ts > NOW() - INTERVAL '15 minutes'
        GROUP BY ip, protocol
    """)
    for ip, proto, n, sample in rows:
        out.append(_det(ip, "PROTOCOL_EXPLOIT", "MEDIUM" if n < 5 else "HIGH",
                        f"{n} malformed/abusive {proto} packets, e.g. {str(sample)[:100]}", proto))
    return out


def stream_access():
    rows = fetchall("""
        SELECT ip, session_id, min(payload) FROM events
        WHERE event_type='stream_access' AND ts > NOW() - INTERVAL '15 minutes'
        GROUP BY ip, session_id
    """)
    return [_det(ip, "VIDEO_STREAM_ACCESS", "MEDIUM", f"Camera stream opened with default credentials: {url}",
                 "RTSP", "cctv", sid) for ip, sid, url in rows]


def multi_protocol():
    rows = fetchall("""
        SELECT ip, COUNT(DISTINCT protocol), string_agg(DISTINCT protocol, ','),
               COUNT(DISTINCT device)
        FROM events WHERE ts > NOW() - INTERVAL '60 minutes' AND event_type <> 'connect'
        GROUP BY ip HAVING COUNT(DISTINCT protocol) >= 2
    """)
    return [_det(ip, "MULTI_PROTOCOL_ATTACK", "CRITICAL" if n >= 3 else "HIGH",
                 f"Same source attacked {n} protocols ({protos}) on {devs} device(s) within 1 h")
            for ip, n, protos, devs in rows]


ALL_RULES = [brute_force, credential_compromise, credential_stuffing, reconnaissance,
             malware_delivery, malware_family, mirai_and_post_exploitation, behavioural, modbus_ics,
             mqtt_and_ics, protocol_exploit, stream_access, multi_protocol]


def run_rules():
    dets = []
    for rule in ALL_RULES:
        try:
            dets.extend(rule())
        except Exception as e:  # one broken rule must not stop the others
            import logging
            logging.getLogger("rules").error("%s failed: %s", rule.__name__, e)
    return dets
