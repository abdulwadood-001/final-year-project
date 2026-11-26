"""Parse the CyberLab (Cowrie) honeynet dataset into HoneyBot-IoT session features + weak labels.
Real internet SSH/Telnet attacker sessions -> the same 29-feature schema as ml/features.py.
Run with -I; pass the .json.gz path and output CSV path."""
import sys, gzip, json, re, csv, collections, statistics

import os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.model import FEATURES, CLASSES

DL = re.compile(r"\b(wget|curl|tftp|ftpget)\b", re.I)
CHMOD = re.compile(r"\bchmod\b", re.I)
BUSYBOX = re.compile(r"busybox", re.I)
TMP = re.compile(r"/tmp|/var/tmp|/dev/shm", re.I)
DISC = re.compile(r"\b(uname|whoami|id|ps|ifconfig|netstat|cpuinfo|free|df|cat /proc)\b", re.I)
MIRAI = re.compile(r"/bin/busybox\s+[A-Z]{4,}|\b(ECCHI|MIRAI|GAFGYT|enable|system|shell|linuxshell)\b")
EXPLOIT = re.compile(r"\$\{jndi:|\.\./|union\s+select|/bin/sh|nc\s+-e|/dev/tcp", re.I)


def feat0():
    return {f: 0.0 for f in FEATURES}


def label(f, cmds_joined):
    if f["cmd_download"] > 0 or f["file_events"] > 0 or f["download_attempts"] > 0:
        return "malware_delivery"
    if MIRAI.search(cmds_joined) and f["commands"] >= 2:
        return "botnet_c2"
    if EXPLOIT.search(cmds_joined):
        return "protocol_exploit"
    if f["auth_attempts"] >= 5:
        return "brute_force"
    if f["auth_success"] == 0 and f["auth_attempts"] <= 1 and f["commands"] == 0:
        return "port_scan"
    return "normal"


def parse(path, limit):
    # first pass: sessions-per-source-ip-per-hour for ip_sessions_1h
    ipbucket = collections.Counter()
    rows = []
    n = 0
    with gzip.open(path, "rt", errors="replace") as fh:
        for line in fh:
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            for _sid, events in obj.items():
                if not events:
                    continue
                f = feat0()
                users, passwords, cmdlens, ts, cmds = set(), set(), [], [], []
                src = None
                hour = None
                for e in events:
                    eid = e.get("eventid", "")
                    src = src or e.get("src_ip_identifier")
                    t = e.get("timestamp")
                    if t:
                        ts.append(t)
                        hour = hour or t[:13]
                    if eid in ("cowrie.login.success", "cowrie.login.failed"):
                        f["auth_attempts"] += 1
                        if eid.endswith("success"):
                            f["auth_success"] += 1
                        if e.get("username") is not None:
                            users.add(e.get("username"))
                        if e.get("password") is not None:
                            passwords.add(e.get("password"))
                    elif eid == "cowrie.command.input":
                        c = e.get("message") or e.get("input") or ""
                        c = re.sub(r"^CMD:\s*", "", str(c))
                        cmds.append(c)
                        cmdlens.append(len(c))
                        f["commands"] += 1
                        if DL.search(c):
                            f["cmd_download"] += 1
                        if CHMOD.search(c):
                            f["cmd_chmod"] += 1
                        if BUSYBOX.search(c):
                            f["cmd_busybox"] += 1
                        if TMP.search(c):
                            f["cmd_tmp_paths"] += 1
                        if DISC.search(c):
                            f["cmd_discovery"] += 1
                    elif "file_download" in eid or "file_upload" in eid:
                        f["file_events"] += 1
                        if e.get("url"):
                            f["download_attempts"] += 1
                    elif eid == "cowrie.session.closed" and e.get("duration"):
                        f["duration_s"] = float(e.get("duration") or 0)
                f["events_total"] = len(events)
                f["distinct_usernames"] = len(users)
                f["distinct_passwords"] = len(passwords)
                f["mean_cmd_len"] = statistics.mean(cmdlens) if cmdlens else 0.0
                # inter-event gaps
                import datetime
                secs = []
                for a, b in zip(ts, ts[1:]):
                    try:
                        da = datetime.datetime.fromisoformat(a.replace("Z", "+00:00"))
                        db = datetime.datetime.fromisoformat(b.replace("Z", "+00:00"))
                        secs.append((db - da).total_seconds())
                    except Exception:
                        pass
                f["mean_gap_s"] = statistics.mean(secs) if secs else 0.0
                f["std_gap_s"] = statistics.pstdev(secs) if len(secs) > 1 else 0.0
                f["ip_protocols_1h"] = 1
                if src and hour:
                    ipbucket[(src, hour)] += 1
                lbl = label(f, " ; ".join(cmds))
                rows.append((f, lbl, src, hour))
                n += 1
                if n >= limit:
                    break
            if n >= limit:
                break
    # second pass fill ip_sessions_1h
    out = []
    for f, lbl, src, hour in rows:
        f["ip_sessions_1h"] = float(ipbucket.get((src, hour), 1)) if src and hour else 1.0
        out.append((f, lbl))
    return out


def main():
    path, outcsv = sys.argv[1], sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 60000
    data = parse(path, limit)
    with open(outcsv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(FEATURES + ["label"])
        for f, lbl in data:
            w.writerow([round(f[k], 3) for k in FEATURES] + [lbl])
    counts = collections.Counter(l for _, l in data)
    print(f"parsed {len(data)} real Cowrie sessions -> {outcsv}")
    print("label distribution:", dict(counts))


if __name__ == "__main__":
    main()
