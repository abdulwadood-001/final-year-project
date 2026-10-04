"""
HoneyBot-IoT — configurable vulnerability profiles (scope M1-FE-4).

Default credentials each emulated device accepts.  These are the kind of
factory defaults that Mirai-family bots try first, so attackers get in and
we capture post-exploitation behaviour.  Override with the env var
WEAK_CREDS_<DEVICE>="user:pass,user:pass".
"""

import os

_COMMON = {("root", "root"), ("admin", "admin"), ("root", "12345"), ("root", "123456"),
           ("admin", "1234"), ("admin", "password"), ("user", "user"), ("root", "admin"),
           ("admin", ""), ("root", ""), ("admin", "admin123"), ("support", "support")}

DEFAULTS = {
    "smartlock": _COMMON | {("root", "smartlock"), ("admin", "4711")},
    "sensor":    _COMMON | {("root", "vizxv"), ("root", "xc3511"), ("root", "default"),
                            ("admin", "sensor"), ("operator", "operator")},
    "cctv":      _COMMON | {("admin", "12345"), ("admin", "888888"), ("admin", "666666"),
                            ("root", "xmhdipc"), ("admin", "admin1234")},
    "mqtt":      _COMMON | {("mqtt", "mqtt"), ("device", "device"), ("", "")},
}


def _load(device):
    env = os.environ.get(f"WEAK_CREDS_{device.upper()}")
    if not env:
        return DEFAULTS.get(device, _COMMON)
    pairs = set()
    for item in env.split(","):
        if ":" in item:
            u, p = item.split(":", 1)
            pairs.add((u.strip(), p.strip()))
    return pairs


_CACHE = {}


def is_weak(device, username, password):
    if device not in _CACHE:
        _CACHE[device] = _load(device)
    return (username or "", password or "") in _CACHE[device]
