"""
HoneyBot-IoT — Device State Manager (scope M1-FE-4).

Keeps ONE consistent state per emulated device in Redis so that every protocol
handler tells the attacker the same story:

    HTTP  POST /api/v1/lock {"action":"unlock"}   ─┐
    MQTT  publish lock/cmd  "unlock"               ─┼─► redis hash device:smartlock
    SSH   lockctl unlock                           ─┘        │
                                                             ▼
    MQTT lock/status, HTTP /api/v1/status, SSH `cat /etc/lock_state` all read it.

If Redis is not reachable (unit tests, local runs) an in-memory dict is used.
Every change is published on Redis channel `honeybot:state`.
"""

import os
import json
import time
import random
import logging
import threading
from datetime import datetime, timezone

log = logging.getLogger("state")

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

DEVICES = ("cctv", "smartlock", "sensor")

DEFAULTS = {
    "cctv": {
        "model": "IPC-HFW2431S", "vendor": "IPCam", "firmware": "V5.5.3 build 180512",
        "serial": "6C02E1A4B9F3", "status": "online", "recording": "on",
        "motion": "false", "last_motion": "", "viewers": "0", "resolution": "2688x1520",
        "channels": "4",
    },
    "smartlock": {
        "model": "SL-200", "vendor": "SecureHome", "firmware": "2.1.4",
        "serial": "SL200-0009A3F1", "lock_state": "locked", "door": "closed",
        "battery": "87", "auto_lock": "on", "last_action": "", "last_actor": "",
        "last_change": "", "api_token": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    },
    "sensor": {
        "model": "ISN-4000", "vendor": "IndusSense", "firmware": "1.0.7",
        "serial": "ISN4K-21-00417", "temperature": "24.3", "pressure": "101.3",
        "humidity": "61.2", "temp_threshold": "80", "pressure_threshold": "150",
        "alarm": "none", "interval": "5", "mode": "auto", "plc_link": "up",
    },
}

_redis_client = None
_redis_checked = 0.0


def redis_client():
    """Return a connected redis client, or None if Redis is unavailable."""
    global _redis_client, _redis_checked
    if _redis_client is not None:
        return _redis_client
    if time.time() - _redis_checked < 5:
        return None
    _redis_checked = time.time()
    try:
        import redis
        c = redis.Redis.from_url(REDIS_URL, decode_responses=True,
                                 socket_connect_timeout=1, socket_timeout=2)
        c.ping()
        _redis_client = c
        log.info("Redis connected (%s)", REDIS_URL)
    except Exception as e:
        log.warning("Redis unavailable (%s) – using in-memory state", e)
        _redis_client = None
    return _redis_client


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DeviceState:
    def __init__(self):
        self._mem = {d: dict(v) for d, v in DEFAULTS.items()}
        self._lock = threading.Lock()

    # ── basic access ──────────────────────────────────────────────────────
    def init_defaults(self):
        r = redis_client()
        if r:
            for dev, fields in DEFAULTS.items():
                for k, v in fields.items():
                    r.hsetnx(f"device:{dev}", k, v)

    def get(self, device):
        r = redis_client()
        if r:
            try:
                data = r.hgetall(f"device:{device}")
                if data:
                    return {**DEFAULTS.get(device, {}), **data}
            except Exception:
                pass
        with self._lock:
            return dict(self._mem.get(device, {}))

    def field(self, device, name, default=""):
        return self.get(device).get(name, default)

    def set(self, device, actor="system", **fields):
        fields = {k: str(v) for k, v in fields.items()}
        r = redis_client()
        written = False
        if r:
            try:
                r.hset(f"device:{device}", mapping=fields)
                r.publish("honeybot:state", json.dumps(
                    {"device": device, "actor": actor, "fields": fields, "ts": _now()}))
                written = True
            except Exception:
                pass
        if not written:
            with self._lock:
                self._mem.setdefault(device, {}).update(fields)
        return fields

    # ── device-level actions (used by every protocol) ─────────────────────
    def lock_action(self, action, actor):
        action = (action or "").strip().lower()
        if action in ("unlock", "open", "0", "off", "false"):
            new = "unlocked"
        elif action in ("lock", "close", "1", "on", "true"):
            new = "locked"
        else:
            return None
        self.set("smartlock", actor=actor, lock_state=new, last_action=action,
                 last_actor=actor, last_change=_now())
        return new

    def sensor_config(self, actor, **cfg):
        allowed = {"temp_threshold", "pressure_threshold", "interval", "mode", "alarm"}
        clean = {k: v for k, v in cfg.items() if k in allowed}
        if clean:
            self.set("sensor", actor=actor, **clean)
        return clean

    # ── simulation tick (run by the device_state service) ─────────────────
    def tick(self):
        s = self.get("sensor")
        try:
            t, p, h = float(s["temperature"]), float(s["pressure"]), float(s["humidity"])
            # random walk with mean reversion towards realistic baselines
            t += (24.5 - t) * 0.15 + random.uniform(-0.6, 0.6)
            p += (101.3 - p) * 0.15 + random.uniform(-0.8, 0.8)
            h += (60.0 - h) * 0.10 + random.uniform(-0.5, 0.5)
            # rare spike so threshold breaches are observable to attackers
            if random.random() < 0.01:
                t += random.uniform(55, 70)
            t, p, h = max(10.0, min(t, 120.0)), max(90.0, min(p, 160.0)), max(20.0, min(h, 95.0))
            alarm = "none"
            if t > float(s.get("temp_threshold", 80)):
                alarm = "TEMP_HIGH"
            elif p > float(s.get("pressure_threshold", 150)):
                alarm = "PRESSURE_HIGH"
            self.set("sensor", temperature=f"{t:.1f}", pressure=f"{p:.1f}",
                     humidity=f"{h:.1f}", alarm=alarm)
        except (KeyError, ValueError):
            self.set("sensor", **DEFAULTS["sensor"])

        cam = self.get("cctv")
        if random.random() < 0.08:
            self.set("cctv", motion="true", last_motion=_now())
        elif cam.get("motion") == "true":
            self.set("cctv", motion="false")

        lock = self.get("smartlock")
        if random.random() < 0.02:
            b = max(5, int(lock.get("battery", 87)) - 1)
            self.set("smartlock", battery=b)
        # auto re-lock 60 s after an unlock
        if lock.get("lock_state") == "unlocked" and lock.get("auto_lock") == "on":
            try:
                changed = datetime.fromisoformat(lock.get("last_change"))
                if (datetime.now(timezone.utc) - changed).total_seconds() > 60:
                    self.set("smartlock", actor="auto_lock", lock_state="locked",
                             last_action="auto_lock", last_actor="system",
                             last_change=_now())
            except Exception:
                pass


STATE = DeviceState()


# ── service heartbeats (Device Status Monitor on the dashboard) ─────────────

def start_heartbeat(service, interval=10, **info):
    def _beat():
        started = time.time()
        while True:
            r = redis_client()
            if r:
                try:
                    r.setex(f"hb:{service}", interval * 3, json.dumps(
                        {"service": service, "ts": _now(),
                         "uptime": int(time.time() - started), **info}))
                except Exception:
                    pass
            time.sleep(interval)
    threading.Thread(target=_beat, daemon=True, name=f"hb-{service}").start()
