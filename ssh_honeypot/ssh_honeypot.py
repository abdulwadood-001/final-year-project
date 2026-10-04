"""
HoneyBot-IoT — SSH honeypot  (device: Smart Lock, port 2222)

* Paramiko ServerInterface: logs every password / public-key attempt
* Interactive shell AND exec requests (`ssh host "wget …"` – how most bots work)
* Every command goes through the shared FakeShell and is logged as an event
* Progressive delay after failed logins from the same IP (brute-force realism)
* Banner matches the device (Dropbear, as on real embedded locks)
"""

import os
import sys
import time
import socket
import logging
import threading
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paramiko
from common.db import Session
from common.fakeshell import FakeShell
from common.state import STATE, start_heartbeat
from common.creds import is_weak

PORT = int(os.environ.get("SSH_PORT", 2222))
DEVICE = "smartlock"
KEY_FILE = os.environ.get("SSH_HOST_KEY", "/app/data/ssh_host_rsa_key")
SERVER_VERSION = "SSH-2.0-dropbear_2019.78"
MAX_CONN_PER_IP = 20

logging.basicConfig(level=logging.INFO, format="%(asctime)s | ssh | %(message)s")
log = logging.getLogger("ssh")
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

_failures = defaultdict(int)          # ip -> recent failed logins
_conn_count = defaultdict(int)
_lock = threading.Lock()


def get_host_key():
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    if not os.path.exists(KEY_FILE):
        paramiko.RSAKey.generate(2048).write_private_key_file(KEY_FILE)
    return paramiko.RSAKey(filename=KEY_FILE)


class HoneySSH(paramiko.ServerInterface):
    def __init__(self, session):
        self.s = session
        self.term = None
        self.channels = {}          # chanid -> {"event": Event, "exec": str|None}

    def _chan(self, chanid):
        return self.channels.setdefault(chanid, {"event": threading.Event(), "exec": None})

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        ok = is_weak(DEVICE, username, password)
        with _lock:
            fails = _failures[self.s.ip]
        if not ok and fails:
            time.sleep(min(0.4 * fails, 3.0))       # intentional brute-force delay
        with _lock:
            _failures[self.s.ip] = 0 if ok else fails + 1
        self.s.auth(username, password, ok, method="password")
        log.info("%s | %s:%s | %s", self.s.ip, username, password, "ACCEPT" if ok else "REJECT")
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.s.auth(username, None, False, method="publickey",
                    key_type=key.get_name(), fingerprint=key.get_fingerprint().hex())
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        self.s.event("channel_request", payload=kind, kind=kind)   # e.g. direct-tcpip tunnelling
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        self.term = term
        return True

    def check_channel_shell_request(self, channel):
        self._chan(channel.get_id())["event"].set()
        return True

    def check_channel_exec_request(self, channel, command):
        c = self._chan(channel.get_id())
        c["exec"] = command.decode("utf-8", "replace")
        c["event"].set()
        return True

    def check_channel_env_request(self, channel, name, value):
        return True

    def check_port_forward_request(self, address, port):
        self.s.event("port_forward_request", payload=f"{address}:{port}")
        return False


def interactive(chan, shell, session):
    motd = ("\r\nSmartLock-OS 2.1.4 (SL-200)  —  SecureHome Inc.\r\n"
            "Firmware build 2021-03-09.  Type 'lockctl help' for device control.\r\n\r\n")
    chan.send(motd.encode())
    chan.send(shell.prompt.encode())
    buf, last = "", ""
    while True:
        data = chan.recv(4096)
        if not data:
            break
        for ch in data.decode("utf-8", "replace"):
            if ch in ("\r", "\n"):
                if ch == "\n" and last == "\r":      # CRLF -> one line
                    last = ch
                    continue
                chan.send(b"\r\n")
                out, ex = shell.run(buf)
                buf = ""
                if out:
                    chan.send(out.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace") + b"\r\n")
                if ex:
                    return
                chan.send(shell.prompt.encode())
            elif ch in ("\x7f", "\x08"):
                if buf:
                    buf = buf[:-1]
                    chan.send(b"\x08 \x08")
            elif ch == "\x03":                 # Ctrl-C
                buf = ""
                chan.send(b"^C\r\n" + shell.prompt.encode())
            elif ch == "\x04":                 # Ctrl-D
                if not buf:
                    chan.send(b"logout\r\n")
                    return
            elif ch == "\t" or ch == "\x1b":
                continue
            else:
                buf += ch
                chan.send(ch.encode("utf-8", "replace"))
            last = ch


def serve_channel(chan, meta, session):
    shell = FakeShell(DEVICE, session=session, user=session.username or "root")
    try:
        if meta["exec"] is not None:
            out, _ = shell.run(meta["exec"])
            if out:
                chan.sendall(out.replace("\n", "\r\n").encode("utf-8", "replace") + b"\r\n")
            chan.send_exit_status(0)
            try:
                chan.shutdown_write()
                time.sleep(0.2)
            except Exception:
                pass
        else:
            interactive(chan, shell, session)
    except Exception as e:
        log.debug("channel error: %s", e)
    finally:
        try:
            chan.close()
        except Exception:
            pass


def handle(sock, addr):
    ip, sport = addr[0], addr[1]
    with _lock:
        _conn_count[ip] += 1
        too_many = _conn_count[ip] > MAX_CONN_PER_IP
    session = Session("SSH", DEVICE, ip, sport, PORT)
    transport = None
    try:
        if too_many:
            session.event("rate_limited")
            return
        transport = paramiko.Transport(sock)
        transport.local_version = SERVER_VERSION
        transport.add_server_key(HOST_KEY)
        server = HoneySSH(session)
        try:
            transport.start_server(server=server)
        except (paramiko.SSHException, EOFError) as e:
            session.event("malformed", payload=str(e)[:200])
            return
        session.set_client_version(transport.remote_version)
        # one SSH connection can open several channels (bots often do
        # `ssh host "cmd"` several times over one transport, or a shell + exec)
        served = 0
        while transport.is_active() and served < 25:
            chan = transport.accept(20)
            if chan is None:
                break
            served += 1
            meta = server._chan(chan.get_id())
            meta["event"].wait(10)
            threading.Thread(target=serve_channel, args=(chan, meta, session), daemon=True).start()
        # give in-flight channels a moment to finish
        time.sleep(0.3)
    except Exception as e:
        log.debug("error %s: %s", ip, e)
    finally:
        session.close()
        with _lock:
            _conn_count[ip] -= 1
        if transport:
            transport.close()


HOST_KEY = None


def main():
    global HOST_KEY
    HOST_KEY = get_host_key()
    STATE.init_defaults()
    start_heartbeat("ssh", port=PORT, device=DEVICE, protocol="SSH")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(200)
    log.info("SSH honeypot (Smart Lock) listening on :%d", PORT)
    while True:
        try:
            c, a = srv.accept()
            c.settimeout(120)
            threading.Thread(target=handle, args=(c, a), daemon=True).start()
        except Exception as e:
            log.error(e)


if __name__ == "__main__":
    main()
