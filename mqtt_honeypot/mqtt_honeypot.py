"""
HoneyBot-IoT — MQTT 3.1 / 3.1.1 broker honeypot  (Smart Lock + Industrial Sensor, port 1883)

Fixes vs. v0.3:
  * remaining-length decoded as the variable-length integer (packets > 127 bytes)
  * recv_exact() loops until the whole packet has arrived (no short reads)
  * PUBLISH QoS 1/2 handled (packet IDs, PUBACK / PUBREC / PUBCOMP)
  * SUBSCRIBE with several topic filters, + and # wildcards, UNSUBSCRIBE
New:
  * live telemetry every N seconds, read from the shared Device State (Redis)
  * control topics really change state:   lock/cmd  "unlock"   → lock unlocked
                                           sensor/config/set  {"temp_threshold":20}
  * $SYS/# answers like an old Mosquitto
Safety: messages published by one attacker are NEVER relayed to other clients,
so the honeypot cannot be used as a C2 relay between real bots.
"""

import os
import sys
import json
import time
import socket
import struct
import logging
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.db import Session
from common.state import STATE, start_heartbeat
from common.creds import is_weak
from common import capture

PORT = int(os.environ.get("MQTT_PORT", 1883))
ALLOW_ANONYMOUS = os.environ.get("MQTT_ALLOW_ANONYMOUS", "true").lower() == "true"
MAX_PACKET = 256 * 1024
TELEMETRY_INTERVAL = float(os.environ.get("MQTT_TELEMETRY_INTERVAL", 5))

logging.basicConfig(level=logging.INFO, format="%(asctime)s | mqtt | %(message)s")
log = logging.getLogger("mqtt")

CONTROL_TOPICS = ("lock/cmd", "lock/set", "sensor/config/set", "sensor/cmd", "camera/cmd")


class Malformed(Exception):
    pass


# ── encoding helpers ────────────────────────────────────────────────────────
def encode_remaining_length(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            return bytes(out)


def decode_remaining_length(read_byte):
    mult, value = 1, 0
    for _ in range(4):
        b = read_byte()
        value += (b & 0x7F) * mult
        if not b & 0x80:
            return value
        mult *= 128
    raise Malformed("remaining length > 4 bytes")


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf.extend(chunk)
    return bytes(buf)


def read_packet(sock):
    first = recv_exact(sock, 1)[0]
    rem = decode_remaining_length(lambda: recv_exact(sock, 1)[0])
    if rem > MAX_PACKET:
        raise Malformed(f"packet too large ({rem})")
    return first >> 4, first & 0x0F, recv_exact(sock, rem) if rem else b""


def read_str(data, off):
    if off + 2 > len(data):
        raise Malformed("string length out of range")
    ln = struct.unpack("!H", data[off:off + 2])[0]
    off += 2
    if off + ln > len(data):
        raise Malformed("string overruns packet")
    return data[off:off + ln].decode("utf-8", "replace"), off + ln


def read_bin(data, off):
    if off + 2 > len(data):
        raise Malformed("binary length out of range")
    ln = struct.unpack("!H", data[off:off + 2])[0]
    return data[off + 2:off + 2 + ln], off + 2 + ln


def parse_connect(data):
    proto, off = read_str(data, 0)
    if proto not in ("MQTT", "MQIsdp"):
        raise Malformed(f"bad protocol name {proto!r}")
    level = data[off]; flags = data[off + 1]
    keepalive = struct.unpack("!H", data[off + 2:off + 4])[0]
    off += 4
    client_id, off = read_str(data, off)
    will_topic = will_msg = None
    if flags & 0x04:
        will_topic, off = read_str(data, off)
        wm, off = read_bin(data, off)
        will_msg = wm.decode("utf-8", "replace")
    user = pwd = None
    if flags & 0x80:
        user, off = read_str(data, off)
    if flags & 0x40:
        pb, off = read_bin(data, off)
        pwd = pb.decode("utf-8", "replace")
    return dict(proto=proto, level=level, flags=flags, keepalive=keepalive, client_id=client_id,
                will_topic=will_topic, will_msg=will_msg, username=user, password=pwd)


def parse_publish(flags, data):
    qos = (flags >> 1) & 0x03
    topic, off = read_str(data, 0)
    pid = None
    if qos:
        pid = struct.unpack("!H", data[off:off + 2])[0]
        off += 2
    return topic, data[off:], qos, pid, bool(flags & 1)


def parse_subscribe(data):
    pid = struct.unpack("!H", data[:2])[0]
    off, topics = 2, []
    while off < len(data):
        t, off = read_str(data, off)
        q = data[off] if off < len(data) else 0
        off += 1
        topics.append((t, q))
    if not topics:
        raise Malformed("SUBSCRIBE without topics")
    return pid, topics


def parse_unsubscribe(data):
    pid = struct.unpack("!H", data[:2])[0]
    off, topics = 2, []
    while off < len(data):
        t, off = read_str(data, off)
        topics.append(t)
    return pid, topics


def pkt(ptype, flags, body=b""):
    return bytes([(ptype << 4) | flags]) + encode_remaining_length(len(body)) + body


def publish_pkt(topic, payload, retain=False):
    tb = topic.encode()
    return pkt(3, 1 if retain else 0, struct.pack("!H", len(tb)) + tb + payload.encode())


def topic_matches(flt, topic):
    if flt == "#":
        return not topic.startswith("$")
    f, t = flt.split("/"), topic.split("/")
    for i, part in enumerate(f):
        if part == "#":
            return True
        if i >= len(t):
            return False
        if part != "+" and part != t[i]:
            return False
    return len(f) == len(t)


# ── device topics derived from shared state ────────────────────────────────
def device_topics():
    s, l, c = STATE.get("sensor"), STATE.get("smartlock"), STATE.get("cctv")
    return {
        "sensor/temperature": s["temperature"], "sensor/pressure": s["pressure"],
        "sensor/humidity": s["humidity"], "sensor/alarm": s["alarm"],
        "sensor/config": json.dumps({k: s[k] for k in ("temp_threshold", "pressure_threshold",
                                                       "interval", "mode")}),
        "lock/status": l["lock_state"], "lock/battery": l["battery"], "lock/door": l["door"],
        "camera/motion": c["motion"], "camera/status": c["status"],
        f"devices/{l['serial']}/online": "1", f"devices/{s['serial']}/online": "1",
    }


SYS_TOPICS = {"$SYS/broker/version": "mosquitto version 1.4.15",
              "$SYS/broker/uptime": lambda: f"{int(time.time()) % 900000 + 86400} seconds",
              "$SYS/broker/clients/connected": "3"}


def device_for_topic(topic):
    if topic.startswith("lock"):
        return "smartlock"
    if topic.startswith("camera"):
        return "cctv"
    return "sensor"


# ── control topics ─────────────────────────────────────────────────────────
def apply_control(topic, payload, ip):
    p = payload.strip()
    if topic in ("lock/cmd", "lock/set"):
        try:
            p = json.loads(p).get("action", p) if p.startswith("{") else p
        except Exception:
            pass
        new = STATE.lock_action(str(p), actor=f"mqtt:{ip}")
        return {"lock_state": new} if new else None
    if topic in ("sensor/config/set", "sensor/cmd"):
        cfg = {}
        try:
            cfg = json.loads(p) if p.startswith("{") else dict(x.split("=", 1) for x in p.split(",") if "=" in x)
        except Exception:
            cfg = {}
        changed = STATE.sensor_config(f"mqtt:{ip}", cfg if isinstance(cfg, dict) else {})
        return changed or None
    if topic == "camera/cmd":
        if p.lower() in ("stop", "off", "disable"):
            STATE.set("cctv", actor=f"mqtt:{ip}", recording="off")
            return {"recording": "off"}
        if p.lower() in ("start", "on", "enable"):
            STATE.set("cctv", actor=f"mqtt:{ip}", recording="on")
            return {"recording": "on"}
    return None


# ── per-client handler ─────────────────────────────────────────────────────
class Client:
    def __init__(self, conn, addr):
        self.conn, self.ip, self.sport = conn, addr[0], addr[1]
        self.subs = {}
        self.send_lock = threading.Lock()
        self.alive = True
        self.connected = False
        self.s = Session("MQTT", "sensor", self.ip, self.sport, PORT)
        self.client_id = ""

    def send(self, data):
        with self.send_lock:
            self.conn.sendall(data)

    def push_matching(self, filters=None):
        topics = device_topics()
        sent = 0
        for flt in (filters or list(self.subs)):
            for t, v in topics.items():
                if topic_matches(flt, t):
                    self.send(publish_pkt(t, v, retain=True)); sent += 1
            if flt.startswith("$SYS"):
                for t, v in SYS_TOPICS.items():
                    if topic_matches(flt, t):
                        self.send(publish_pkt(t, v() if callable(v) else v, retain=True)); sent += 1
        return sent

    def telemetry_loop(self):
        while self.alive:
            time.sleep(TELEMETRY_INTERVAL)
            if self.alive and self.connected and self.subs:
                try:
                    self.push_matching()
                except Exception:
                    return

    def run(self):
        threading.Thread(target=self.telemetry_loop, daemon=True).start()
        try:
            self.conn.settimeout(90)
            # first packet MUST be CONNECT
            ptype, flags, data = read_packet(self.conn)
            if ptype != 1:
                raise Malformed(f"first packet type {ptype} is not CONNECT")
            c = parse_connect(data)
            self.client_id = c["client_id"]
            self.s.set_client_version(f"{c['proto']}/{c['level']} id={c['client_id']}"[:200])
            if c["username"] is None and c["password"] is None:
                ok = ALLOW_ANONYMOUS
            else:
                ok = is_weak("mqtt", c["username"], c["password"])
            self.s.auth(c["username"] or "", c["password"] or "", ok, client_id=c["client_id"],
                        keepalive=c["keepalive"], proto=c["proto"], level=c["level"],
                        will_topic=c["will_topic"], will_msg=c["will_msg"], mqtt_action="CONNECT")
            log.info("%s | CONNECT id=%s %s:%s | %s", self.ip, c["client_id"], c["username"],
                     c["password"], "OK" if ok else "FAIL")
            self.send(pkt(2, 0, bytes([0x00, 0x00 if ok else 0x04])))
            if not ok:
                return
            self.connected = True
            if c["keepalive"]:
                self.conn.settimeout(max(c["keepalive"] * 1.5, 10))
            while True:
                ptype, flags, data = read_packet(self.conn)
                if ptype == 3:
                    self.on_publish(flags, data)
                elif ptype == 8:
                    pid, topics = parse_subscribe(data)
                    for t, q in topics:
                        self.subs[t] = min(q, 1)
                        self.s.event("mqtt_subscribe", payload=t, topic=t, qos=q,
                                     client_id=self.client_id, target_device=device_for_topic(t))
                    log.info("%s | SUBSCRIBE %s", self.ip, [t for t, _ in topics])
                    self.send(pkt(9, 0, struct.pack("!H", pid) + bytes(min(q, 1) for _, q in topics)))
                    self.push_matching([t for t, _ in topics])
                elif ptype == 10:
                    pid, topics = parse_unsubscribe(data)
                    for t in topics:
                        self.subs.pop(t, None)
                    self.s.event("mqtt_unsubscribe", payload=",".join(topics), client_id=self.client_id)
                    self.send(pkt(11, 0, struct.pack("!H", pid)))
                elif ptype == 6:            # PUBREL -> PUBCOMP
                    self.send(pkt(7, 0, data[:2]))
                elif ptype in (4, 5, 7):   # PUBACK / PUBREC / PUBCOMP from client
                    continue
                elif ptype == 12:
                    self.send(pkt(13, 0))
                elif ptype == 14:
                    self.s.event("mqtt_disconnect", client_id=self.client_id)
                    return
                else:
                    raise Malformed(f"unexpected packet type {ptype}")
        except Malformed as e:
            self.s.event("malformed", payload=str(e), client_id=self.client_id)
            log.info("%s | MALFORMED %s", self.ip, e)
        except (ConnectionError, socket.timeout, OSError):
            pass
        except Exception as e:
            self.s.event("malformed", payload=f"{type(e).__name__}: {e}"[:300])
        finally:
            self.alive = False
            self.s.close()
            try:
                self.conn.close()
            except Exception:
                pass

    def on_publish(self, flags, data):
        topic, payload_b, qos, pid, retain = parse_publish(flags, data)
        payload = payload_b.decode("utf-8", "replace")
        if capture.looks_interesting(payload_b):        # binary blob pushed through the broker
            capture.store(self.s, payload_b, "mqtt_payload", filename=topic)
        changed = None
        if topic in CONTROL_TOPICS:
            changed = apply_control(topic, payload, self.ip)
        self.s.event("mqtt_publish", payload=payload[:4000], topic=topic, qos=qos, retain=retain,
                     client_id=self.client_id, target_device=device_for_topic(topic),
                     control=topic in CONTROL_TOPICS, state_change=changed)
        log.info("%s | PUBLISH %s = %s%s", self.ip, topic, payload[:80],
                 f"  -> {changed}" if changed else "")
        if changed:
            self.s.event("state_change", payload=json.dumps(changed), via="mqtt", topic=topic)
        if qos == 1:
            self.send(pkt(4, 0, struct.pack("!H", pid)))
        elif qos == 2:
            self.send(pkt(5, 0, struct.pack("!H", pid)))
        # echo state topics back to this client only (never to other clients)
        if changed:
            self.push_matching([f for f in self.subs])


def main():
    STATE.init_defaults()
    start_heartbeat("mqtt", port=PORT, device="smartlock,sensor", protocol="MQTT")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(200)
    log.info("MQTT broker honeypot listening on :%d (anonymous=%s)", PORT, ALLOW_ANONYMOUS)
    while True:
        try:
            c, a = s.accept()
            threading.Thread(target=Client(c, a).run, daemon=True).start()
        except Exception as e:
            log.error(e)


if __name__ == "__main__":
    main()
