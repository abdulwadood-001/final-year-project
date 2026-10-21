"""
HoneyBot-IoT — device machine supervisor.

Each emulated IoT device runs as its OWN container ("machine") on the honeynet,
with its own hostname, IP and MAC, serving exactly the protocols that device
exposes:

    cctv       RTSP :554            + HTTP/HTTPS :8080/:8443   (Boa camera panel)
    smartlock  SSH :2222 + MQTT :1883 + HTTP :8081            (SecureHome hub)
    sensor     Telnet :2323 + Modbus :502 + HTTP :8082        (ISN-4000 node)

This supervisor launches that device's protocol front-ends as child processes,
restarts any that crash, reports a per-machine heartbeat, and shuts them all
down on SIGTERM/SIGINT. The front-ends are unchanged; HTTP is scoped with
HTTP_DEVICES so a machine serves only its own web service.

    DEVICE=sensor python device_machine.py
"""

import os
import sys
import time
import signal
import logging
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common.state import STATE, start_heartbeat, redis_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s | machine | %(message)s")
log = logging.getLogger("machine")

DEVICE = os.environ.get("DEVICE", "").strip()

# device -> list of (process name, python module, extra env)
SERVICES = {
    "cctv": [
        ("rtsp", "rtsp_honeypot.rtsp_honeypot", {}),
        ("http", "http_honeypot.http_honeypot", {"HTTP_DEVICES": "cctv"}),
    ],
    "smartlock": [
        ("ssh", "ssh_honeypot.ssh_honeypot", {}),
        ("mqtt", "mqtt_honeypot.mqtt_honeypot", {}),
        ("http", "http_honeypot.http_honeypot", {"HTTP_DEVICES": "smartlock"}),
    ],
    "sensor": [
        ("telnet", "telnet_honeypot.telnet_honeypot", {}),
        ("modbus", "modbus_honeypot.modbus_honeypot", {}),
        ("http", "http_honeypot.http_honeypot", {"HTTP_DEVICES": "sensor"}),
    ],
}

_procs = {}          # name -> Popen
_stop = False


def _spawn(name, module, extra):
    env = dict(os.environ, **extra)
    p = subprocess.Popen([sys.executable, "-m", module], env=env)
    _procs[name] = p
    log.info("started %s (%s) pid=%d", name, module, p.pid)
    return p


def _terminate_all():
    for name, p in _procs.items():
        if p.poll() is None:
            p.terminate()
    deadline = time.time() + 8
    for name, p in _procs.items():
        try:
            p.wait(max(0.1, deadline - time.time()))
        except subprocess.TimeoutExpired:
            p.kill()


def main():
    global _stop
    if DEVICE not in SERVICES:
        log.error("DEVICE must be one of %s (got %r)", ",".join(SERVICES), DEVICE)
        sys.exit(2)

    def _sig(_signo, _frame):
        global _stop
        _stop = True
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    for _ in range(30):
        if redis_client():
            break
        time.sleep(1)
    STATE.init_defaults()
    start_heartbeat(f"machine_{DEVICE}", interval=10, device=DEVICE, role="device-machine")

    services = SERVICES[DEVICE]
    for name, module, extra in services:
        _spawn(name, module, extra)

    log.info("device machine '%s' up with services: %s", DEVICE, ", ".join(n for n, _, _ in services))
    backoff = {}
    while not _stop:
        time.sleep(1)
        for name, module, extra in services:
            p = _procs.get(name)
            if p and p.poll() is not None and not _stop:
                code = p.returncode
                wait = min(backoff.get(name, 1) * 2, 30)
                backoff[name] = wait
                log.error("service %s exited (code %s); restarting in %ds", name, code, wait)
                time.sleep(wait)
                if not _stop:
                    _spawn(name, module, extra)

    log.info("shutting down device machine '%s'", DEVICE)
    _terminate_all()


if __name__ == "__main__":
    main()
