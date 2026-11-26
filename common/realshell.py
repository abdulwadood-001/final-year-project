"""
HoneyBot-IoT — real (restricted) shell client used by the SSH and Telnet front-ends.

After a successful login the attacker is attached to a throw-away device machine run
by the sandbox service (sandbox/sandbox.py). This module:

  * relays bytes between the attacker's channel and the sandbox shell;
  * reconstructs each command line from the keystroke/exec stream and logs it as a
    `command` event — so the dashboard session replay looks the same as before;
  * records `download_attempt` (IOC) and `exec_attempt` events from those command
    lines, without ever fetching anything;
  * serves the device-control bridge (/run/devctl) so `lockctl` / `sensorctl` /
    `camctl` run inside the sandbox change the SHARED device state, keeping every
    protocol consistent;
  * on logout, pulls every file the attacker wrote to the writable tmpfs dirs and
    quarantines it through common.capture.

If the sandbox service is unreachable or over capacity the caller falls back to the
in-process FakeShell, so the honeypot never goes dark.
"""

import os
import json
import time
import base64
import errno
import socket
import logging
import threading

from common import capture
from common.cmdintel import download_targets, exec_targets
from common.state import STATE

log = logging.getLogger("realshell")

SANDBOX_HOST = os.environ.get("SANDBOX_HOST", "sandbox")
SANDBOX_PORT = int(os.environ.get("SANDBOX_PORT", 7070))
SANDBOX_TOKEN = os.environ.get("SANDBOX_TOKEN", "")
SANDBOX_TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", 900))
IPC_DIR = os.environ.get("SANDBOX_IPC_DIR", "/run/vm-ipc")   # host side of honeybot_vm_ipc


def enabled_for(device):
    """SHELL_MODE / SHELL_MODE_<DEVICE> = real | fake (default fake)."""
    mode = os.environ.get(f"SHELL_MODE_{device.upper()}") or os.environ.get("SHELL_MODE", "fake")
    return mode.strip().lower() == "real"


def _connect():
    s = socket.create_connection((SANDBOX_HOST, SANDBOX_PORT), timeout=30)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def _send_header(sock, obj):
    obj = dict(obj)
    if SANDBOX_TOKEN:
        obj["token"] = SANDBOX_TOKEN
    sock.sendall(json.dumps(obj).encode() + b"\n")


def _read_line(sock):
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    line, _, _ = buf.partition(b"\n")
    return json.loads(line) if line else {}


# ── device-control bridge (devctl FIFOs, one pair per session) ──────────────

class DevctlBridge:
    """Serves /run/devctl/{req,resp} inside the sandbox (a per-session sub-path of the
    shared IPC volume). `lockctl`/`sensorctl`/`camctl` write a request line and read a
    reply; we apply it to the shared Device State and log a `state_change` event."""

    def __init__(self, session, device):
        self.session, self.device = session, device
        self.dir = os.path.join(IPC_DIR, session.id)
        self.req = os.path.join(self.dir, "req")
        self.resp = os.path.join(self.dir, "resp")
        self._stop = False
        self._thread = None

    def start(self):
        # The sandbox (root) has already created self.dir and the req/resp FIFOs 0666;
        # the device machine (uid 10001) only needs to OPEN them, which it may even in a
        # root-owned dir. Wait briefly for them to appear.
        end = time.time() + 5
        while time.time() < end and not (os.path.exists(self.req) and os.path.exists(self.resp)):
            time.sleep(0.1)
        if not (os.path.exists(self.req) and os.path.exists(self.resp)):
            log.warning("devctl bridge unavailable (FIFOs not created): device control will error in-sandbox")
            return self
        self._thread = threading.Thread(target=self._serve, daemon=True, name=f"devctl-{self.session.id[:8]}")
        self._thread.start()
        return self

    def _serve(self):
        while not self._stop:
            try:
                fd = os.open(self.req, os.O_RDONLY | os.O_NONBLOCK)
            except OSError:
                time.sleep(0.2)
                continue
            try:
                line = self._read_fifo(fd)
            finally:
                os.close(fd)
            if line is None:
                time.sleep(0.1)
                continue
            try:
                reply = self._handle(line.strip())
            except Exception as e:
                reply = f"devctl: error: {e}"
            try:
                wfd = os.open(self.resp, os.O_WRONLY | os.O_NONBLOCK)
                os.write(wfd, (reply + "\n").encode("utf-8", "replace"))
                os.close(wfd)
            except OSError:
                pass

    def _read_fifo(self, fd):
        data = b""
        end = time.time() + SANDBOX_TIMEOUT
        while time.time() < end and not self._stop:
            try:
                chunk = os.read(fd, 4096)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    if data:
                        return data.decode("utf-8", "replace")
                    time.sleep(0.1)
                    continue
                return None
            if not chunk:
                return data.decode("utf-8", "replace") if data else None
            data += chunk
            if b"\n" in chunk or len(data) > 4096:
                return data.decode("utf-8", "replace")
        return None

    def _handle(self, line):
        parts = line.split()
        if not parts:
            return ""
        tool, args = parts[0], parts[1:]
        ip = self.session.ip
        if tool == "lockctl" and self.device == "smartlock":
            sub = args[0] if args else "status"
            if sub in ("lock", "unlock"):
                new = STATE.lock_action(sub, actor=f"{self.session.protocol.lower()}:{ip}")
                self.session.event("state_change", payload=f"lock_state={new}",
                                   device_field="lock_state", value=new)
                return f"lockd: door {new}"
            s = STATE.get("smartlock")
            return (f"state: {s['lock_state']}\ndoor: {s['door']}\nbattery: {s['battery']}%\n"
                    f"auto_lock: {s['auto_lock']}\nfirmware: {s['firmware']}")
        if tool == "sensorctl" and self.device == "sensor":
            if args[:1] == ["set"] and len(args) >= 3:
                changed = STATE.sensor_config(f"telnet:{ip}", {args[1]: args[2]})
                if changed:
                    self.session.event("state_change", payload=f"{args[1]}={args[2]}",
                                       device_field=args[1], value=args[2])
                    return f"OK {args[1]}={args[2]}"
                return f"sensorctl: unknown key '{args[1]}'"
            s = STATE.get("sensor")
            return "".join(f"{k:<20}{s.get(k)}\n" for k in
                           ("temperature", "pressure", "humidity", "alarm", "temp_threshold",
                            "pressure_threshold", "interval", "mode", "plc_link"))
        if tool == "camctl" and self.device == "cctv":
            if args[:1] == ["record"] and len(args) >= 2 and args[1] in ("on", "off"):
                STATE.set("cctv", actor=f"http:{ip}", recording=args[1])
                self.session.event("state_change", payload=f"recording={args[1]}",
                                   device_field="recording", value=args[1])
                return f"recording {args[1]}"
            s = STATE.get("cctv")
            return (f"status: {s['status']}\nrecording: {s['recording']}\n"
                    f"resolution: {s['resolution']}\nmotion: {s['motion']}")
        return f"devctl: unknown control '{tool}'"

    def stop(self):
        self._stop = True
        try:
            import shutil
            shutil.rmtree(self.dir, ignore_errors=True)
        except Exception:
            pass


# ── command-stream logging ──────────────────────────────────────────────────

def log_command(session, line):
    """Log one reconstructed command line as the fake shell would: a `command` event
    plus `download_attempt` (IOC) / `exec_attempt`. Output is not known in the real
    shell, so it is left empty (replay shows input with the live tty capture)."""
    line = (line or "").strip()
    if not line:
        return
    session.command(line, output="")
    for url, tool in download_targets(line):
        session.event("download_attempt", payload=url, url=url, command=line[:500], tool=tool)
    for tgt in exec_targets(line):
        session.event("exec_attempt", payload=tgt, path=tgt, args=line[:300])


class LineRecorder:
    """Reconstructs command lines from the attacker's raw keystrokes on an interactive
    tty (handles CR/LF, backspace and Ctrl-C) and logs each completed line."""

    def __init__(self, session):
        self.session, self.buf = session, bytearray()

    def feed(self, data: bytes):
        for b in data:
            if b in (13, 10):
                self._flush()
            elif b in (8, 127):
                if self.buf:
                    self.buf.pop()
            elif b == 3:
                self.buf.clear()
            elif b == 9:
                continue
            elif 32 <= b < 127 or b >= 160:
                if len(self.buf) < 8192:
                    self.buf.append(b)

    def _flush(self):
        if self.buf:
            try:
                log_command(self.session, self.buf.decode("utf-8", "replace"))
            except Exception as e:
                log.debug("cmd log: %s", e)
            self.buf.clear()

    def close(self):
        self._flush()


# ── sample collection on logout ─────────────────────────────────────────────

def collect_and_quarantine(session, sock):
    """Ask the sandbox for the files the attacker dropped and quarantine each one."""
    try:
        _send_header(sock, {"op": "collect", "session_id": session.id})
        reply = _read_line(sock)
    except Exception as e:
        log.debug("collect failed: %s", e)
        return
    for item in reply.get("files", []):
        data_b64 = item.get("data_b64")
        if not data_b64:
            continue
        try:
            data = base64.b64decode(data_b64)
        except Exception:
            continue
        path = item.get("path")
        if capture.looks_interesting(data) or item.get("mode", 0) & 0o111:
            capture.store(session, data, "sandbox_drop", filename=path)
            session.event("file_upload", payload=f"dropped {path} ({len(data)} bytes)",
                          path=path, size=len(data), via="sandbox")
    procs = reply.get("processes")
    if procs:
        session.event("sandbox_processes", payload=procs[:2000])


# ── session orchestration (called by the SSH / Telnet front-ends) ───────────

class SandboxUnavailable(Exception):
    """Raised when no sandbox could be opened; the caller falls back to FakeShell."""


def exec_once(session, device, cmd, timeout=20):
    """Run one command line in the device machine and return its combined output as
    text. Used by the HTTP CVE/command-injection endpoints so an injected command
    really executes in that device's shell (downloads logged, drops quarantined).
    Falls back to the in-process FakeShell if the sandbox is unavailable."""
    try:
        rs = RealShellSession(session, device, "root")
        rs.open(tty=False, cmd=cmd)
        out = bytearray()
        rs.sock.settimeout(timeout)
        try:
            while True:
                data = rs.sock.recv(65536)
                if not data:
                    break
                out.extend(data)
        except OSError:
            pass
        rs.close()
        return out.decode("utf-8", "replace")
    except SandboxUnavailable:
        from common.fakeshell import FakeShell
        shell = FakeShell(device, session=session, user="root")
        output, _ = shell.run(cmd)
        shell.finalize()
        return output


class RealShellSession:
    """One attacker shell on one throw-away device machine. Use as a context manager:

        with RealShellSession(session, device, user) as rs:
            rs.open(tty=True, cols=.., rows=..)     # or tty=False, cmd="wget .."
            rs.attach(read_from_attacker, write_to_attacker)   # blocks until exit
    """

    def __init__(self, session, device, user="root"):
        self.session = session
        self.device = device
        self.user = user if user in ("root", "admin") else "root"
        self.sock = None
        self.bridge = None
        self.tty = False
        self.recorder = None
        self.exit_code = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def open(self, tty=True, cols=80, rows=24, cmd=None, term="vt100"):
        try:
            self.sock = _connect()
            _send_header(self.sock, {"op": "open", "session_id": self.session.id,
                                     "device": self.device, "ip": self.session.ip,
                                     "user": self.user, "tty": tty, "cmd": cmd,
                                     "cols": cols, "rows": rows, "term": term})
            reply = _read_line(self.sock)
        except Exception as e:
            self._abort()
            raise SandboxUnavailable(str(e))
        if not reply.get("ok"):
            self._abort()
            raise SandboxUnavailable(reply.get("error", "unknown"))
        # the machine (and its 0777 IPC dir) now exist: wire up the device-control bridge
        self.bridge = DevctlBridge(self.session, self.device).start()
        self.tty = tty
        self.session.event("sandbox_open", payload=f"{self.device} machine {reply.get('sandbox', '')}",
                           sandbox=reply.get("sandbox"), mode="tty" if tty else "exec")
        if cmd:
            log_command(self.session, cmd)
        elif tty:
            self.recorder = LineRecorder(self.session)
        return self

    def send(self, data: bytes):
        if self.recorder is not None:
            self.recorder.feed(data)
        self.sock.sendall(data)

    def recv(self, n=65536):
        return self.sock.recv(n)

    def attach(self, reader, writer):
        """Pump bytes until the shell exits. `reader()` returns attacker input (b'' on
        EOF); `writer(bytes)` sends sandbox output to the attacker."""
        def up():
            try:
                while True:
                    data = reader()
                    if not data:
                        break
                    self.send(data)
            except Exception:
                pass
            finally:
                try:
                    self.sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        t = threading.Thread(target=up, daemon=True)
        t.start()
        try:
            while True:
                data = self.sock.recv(65536)
                if not data:
                    break
                writer(data)
        except OSError:
            pass

    def _abort(self):
        if self.bridge:
            self.bridge.stop()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def close(self):
        if self.recorder is not None:
            self.recorder.close()
        if self.sock is not None:
            # a second connection collects dropped files and destroys the machine
            try:
                col = _connect()
                collect_and_quarantine(self.session, col)
                col.close()
            except Exception as e:
                log.debug("close/collect: %s", e)
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        if self.bridge:
            self.bridge.stop()
