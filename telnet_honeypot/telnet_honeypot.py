"""
HoneyBot-IoT — Telnet honeypot  (device: Industrial Sensor, port 2323)

* asyncio server, proper Telnet IAC negotiation (WILL ECHO / SGA) and stripping
* BusyBox-style `login:` with 3 attempts per connection (bots try several)
* cleartext credentials and every command logged through common.db
* shared FakeShell with sensor-specific files (/proc/sensor, sensorctl …)
"""

import os
import sys
import socket
import asyncio
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.db import Session
from common.fakeshell import FakeShell
from common.state import STATE, start_heartbeat
from common.creds import is_weak
from common import realshell

PORT = int(os.environ.get("TELNET_PORT", 2323))
DEVICE = "sensor"
IDLE_TIMEOUT = 60

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA = 1, 3

logging.basicConfig(level=logging.INFO, format="%(asctime)s | telnet | %(message)s")
log = logging.getLogger("telnet")

BANNER = "\r\nISN-4000 Industrial Sensor Node  (fw 1.0.7)\r\n\r\n"


class TelnetIO:
    def __init__(self, reader, writer):
        self.r, self.w = reader, writer
        self.buf = bytearray()
        self.carry = bytearray()
        self.negotiation = []

    async def negotiate(self):
        self.w.write(bytes([IAC, WILL, ECHO, IAC, WILL, SGA, IAC, DO, SGA]))
        await self.w.drain()

    async def _fill(self):
        data = await asyncio.wait_for(self.r.read(1024), timeout=IDLE_TIMEOUT)
        if not data:
            raise ConnectionError("eof")
        # an IAC command can be split across two TCP reads – keep the tail for next time
        data = bytes(self.carry) + data
        self.carry = bytearray()
        tail = 0
        if data[-1:] == bytes([IAC]) and not data.endswith(bytes([IAC, IAC])):
            tail = 1
        elif len(data) >= 2 and data[-2] == IAC and data[-1] in (DO, DONT, WILL, WONT, SB):
            tail = 2
        if tail:
            self.carry = bytearray(data[-tail:])
            data = data[:-tail]
        i = 0
        while i < len(data):
            b = data[i]
            if b == IAC and i + 1 < len(data):
                cmd = data[i + 1]
                if cmd == IAC:
                    self.buf.append(IAC); i += 2; continue
                if cmd == SB:
                    end = data.find(bytes([IAC, SE]), i)
                    self.negotiation.append(data[i:end + 2 if end != -1 else len(data)].hex())
                    i = end + 2 if end != -1 else len(data)
                    continue
                if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data) + 1:
                    self.negotiation.append(f"{cmd}:{data[i + 2] if i + 2 < len(data) else -1}")
                    i += 3; continue
                i += 2; continue
            self.buf.append(b)
            i += 1

    async def readline(self, echo=True):
        line = bytearray()
        while True:
            if not self.buf:
                await self._fill()
            b = self.buf.pop(0)
            if b in (10, 13):
                if b == 13 and self.buf[:1] in (b"\n", b"\x00"):
                    self.buf.pop(0)
                self.w.write(b"\r\n"); await self.w.drain()
                return line.decode("utf-8", "replace")
            if b == 0:
                continue
            if b in (8, 127):
                if line:
                    line.pop()
                    if echo:
                        self.w.write(b"\x08 \x08")
                continue
            if b == 3:      # Ctrl-C
                return ""
            line.append(b)
            if echo:
                self.w.write(bytes([b]))
            if len(line) > 8192:
                return line.decode("utf-8", "replace")

    async def send(self, text):
        self.w.write(text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace"))
        await self.w.drain()


def _strip_iac(data, carry):
    """Remove Telnet IAC command sequences from a raw byte chunk, returning the data
    bytes to forward to the shell. `carry` is a bytearray holding an IAC sequence split
    across reads. Attacker→server negotiation is otherwise ignored here."""
    out = bytearray()
    buf = bytes(carry) + data
    carry.clear()
    i, n = 0, len(buf)
    while i < n:
        b = buf[i]
        if b == IAC:
            if i + 1 >= n:
                carry.append(IAC)
                break
            cmd = buf[i + 1]
            if cmd == IAC:
                out.append(IAC)
                i += 2
                continue
            if cmd == SB:
                end = buf.find(bytes([IAC, SE]), i)
                if end == -1:
                    carry.extend(buf[i:])
                    break
                i = end + 2
                continue
            if cmd in (DO, DONT, WILL, WONT):
                if i + 2 >= n:
                    carry.extend(buf[i:])
                    break
                i += 3
                continue
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


async def _telnet_real_shell(io, session, user):
    """Attach the Telnet client to a throw-away device machine (real restricted shell)."""
    loop = asyncio.get_event_loop()
    rs = realshell.RealShellSession(session, DEVICE, "root" if user != "operator" else "admin")
    rs.open(tty=True, cols=80, rows=24, term="vt100")
    sock = rs.sock
    carry = bytearray()

    async def client_to_shell():
        try:
            while True:
                data = await asyncio.wait_for(io.r.read(4096), timeout=rs_timeout)
                if not data:
                    break
                payload = _strip_iac(data, carry)
                if payload:
                    if rs.recorder is not None:
                        rs.recorder.feed(payload)            # reconstruct command lines
                    await loop.run_in_executor(None, sock.sendall, payload)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    async def shell_to_client():
        try:
            while True:
                data = await loop.run_in_executor(None, sock.recv, 65536)
                if not data:
                    break
                io.w.write(data)
                await io.w.drain()
        except (ConnectionError, OSError):
            pass

    try:
        await asyncio.gather(client_to_shell(), shell_to_client())
    finally:
        await loop.run_in_executor(None, rs.close)


rs_timeout = int(os.environ.get("SANDBOX_TIMEOUT", 900))


async def handle(reader, writer):
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    ip, sport = peer[0], peer[1]
    session = Session("Telnet", DEVICE, ip, sport, PORT)
    io = TelnetIO(reader, writer)
    shell = None
    try:
        await io.negotiate()
        await io.send(BANNER)
        user = None
        for attempt in range(3):
            await io.send("sensor-node login: ")
            username = (await io.readline(echo=True)).strip()
            await io.send("Password: ")
            password = (await io.readline(echo=False)).strip()
            ok = is_weak(DEVICE, username, password)
            session.auth(username, password, ok, attempt=attempt + 1)
            log.info("%s | %s:%s | %s", ip, username, password, "ACCEPT" if ok else "REJECT")
            if ok:
                user = username
                break
            await asyncio.sleep(1.0 + attempt * 0.5)
            await io.send("Login incorrect\r\n")
        if io.negotiation:
            session.event("telnet_negotiation", payload=",".join(io.negotiation[:40]))
        if not user:
            return
        if realshell.enabled_for(DEVICE):
            try:
                await _telnet_real_shell(io, session, user)
                return
            except realshell.SandboxUnavailable as e:
                log.warning("sandbox unavailable, using fake shell: %s", e)
        shell = FakeShell(DEVICE, session=session, user="root" if user != "operator" else "operator")
        await io.send(f"\r\nBusyBox v1.24.1 (2020-08-17 09:10:02 UTC) built-in shell (ash)\r\n"
                      "Enter 'help' for a list of built-in commands.\r\n\r\n")
        while True:
            await io.send(shell.prompt)
            line = await io.readline(echo=True)
            if not line.strip():
                continue
            out, ex = shell.run(line)
            if out:
                await io.send(out + "\n")
            if ex:
                break
    except (ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    except Exception as e:
        log.debug("error %s: %s", ip, e)
    finally:
        if shell is not None:
            shell.finalize()          # capture any files the attacker dropped
        session.close()
        try:
            writer.close()
        except Exception:
            pass


async def main():
    STATE.init_defaults()
    start_heartbeat("telnet", port=PORT, device=DEVICE, protocol="Telnet")
    server = await asyncio.start_server(handle, "0.0.0.0", PORT)
    log.info("Telnet honeypot (Industrial Sensor) listening on :%d", PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
