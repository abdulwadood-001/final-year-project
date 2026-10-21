"""
HoneyBot-IoT — Modbus/TCP honeypot  (device: Industrial Sensor ISN-4000, port 502)

The sensor node's `ps` has always advertised `modbusd -p 502`; this makes that
service real to an attacker. It speaks enough Modbus/TCP for the usual ICS
recon-and-tamper tools (modbus-cli, pymodbus, Metasploit `modbus*`, PLCScan):

  * FC 1/2   read coils / discrete inputs      (alarm + relay bits)
  * FC 3/4   read holding / input registers    (live telemetry from shared state)
  * FC 6/16  write single / multiple registers (changes thresholds → shared state)
  * FC 5     write single coil                 (alarm reset / relay)
  * FC 17    report server id                  (device fingerprint)
  * anything else → Modbus exception 0x01 (illegal function)

Register map (holding registers, 1-based 40001…, scaled ×10 like real gear):

    40001 temperature ×10      40004 temp_threshold         (writable)
    40002 pressure ×10         40005 pressure_threshold     (writable)
    40003 humidity ×10         40006 interval               (writable)
                               40007 mode  0=auto 1=manual  (writable)

Writing a register updates the SHARED device state, so the change is visible over
Telnet `sensorctl`, the HMI and MQTT too — and is logged as a `state_change` /
`modbus_write` event the intel engine turns into an ICS detection.
"""

import os
import sys
import socket
import struct
import logging
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.db import Session
from common.state import STATE, start_heartbeat

PORT = int(os.environ.get("MODBUS_PORT", 502))
DEVICE = "sensor"
UNIT_ID = int(os.environ.get("MODBUS_UNIT_ID", 1))
SERVER_ID = os.environ.get("MODBUS_SERVER_ID", "ISN-4000")
MAX_CONN_PER_IP = 20

logging.basicConfig(level=logging.INFO, format="%(asctime)s | modbus | %(message)s")
log = logging.getLogger("modbus")

# holding-register index (0-based) -> shared-state field + scale + writability
HOLDING = {
    0: ("temperature", 10, False),
    1: ("pressure", 10, False),
    2: ("humidity", 10, False),
    3: ("temp_threshold", 10, True),
    4: ("pressure_threshold", 10, True),
    5: ("interval", 1, True),
    6: ("mode", 1, True),           # 0=auto 1=manual
}
MODE_NUM = {"auto": 0, "manual": 1}
MODE_STR = {0: "auto", 1: "manual"}

EXC_ILLEGAL_FUNCTION = 0x01
EXC_ILLEGAL_ADDRESS = 0x02
EXC_ILLEGAL_VALUE = 0x03


def _reg_value(idx):
    field, scale, _ = HOLDING[idx]
    raw = STATE.field("sensor", field, "0")
    try:
        if field == "mode":
            return MODE_NUM.get(str(raw), 0)
        return int(round(float(raw) * scale)) & 0xFFFF
    except (TypeError, ValueError):
        return 0


def _coils():
    # 0: alarm active, 1: plc_link up, 2: recording (n/a), 3: auto mode
    s = STATE.get("sensor")
    return [s.get("alarm", "none") != "none", s.get("plc_link", "up") == "up",
            False, s.get("mode", "auto") == "auto"]


class ModbusConn:
    def __init__(self, sock, session):
        self.sock, self.s = sock, session
        self.unit = UNIT_ID

    def run(self):
        self.sock.settimeout(60)
        try:
            while True:
                header = self._recvn(7)
                if not header:
                    break
                tid, pid, length, unit = struct.unpack(">HHHB", header)
                if pid != 0 or not (1 <= length <= 253):
                    self.s.event("malformed", payload=f"bad MBAP pid={pid} len={length}")
                    break
                body = self._recvn(length - 1)
                if body is None:
                    break
                self.unit = unit
                resp = self._dispatch(body)
                if resp is not None:
                    self.sock.sendall(struct.pack(">HHHB", tid, 0, len(resp) + 1, unit) + resp)
        except (socket.timeout, ConnectionError, OSError):
            pass
        except Exception as e:
            log.debug("conn error %s: %s", self.s.ip, e)

    def _recvn(self, n):
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                return None
            if not chunk:
                return None if buf else b""
            buf.extend(chunk)
        return bytes(buf)

    def _exc(self, fc, code):
        return struct.pack(">BB", fc | 0x80, code)

    def _dispatch(self, body):
        fc = body[0]
        data = body[1:]
        try:
            if fc in (3, 4):
                return self._read_registers(fc, data)
            if fc in (1, 2):
                return self._read_bits(fc, data)
            if fc == 6:
                return self._write_single(data)
            if fc == 16:
                return self._write_multiple(data)
            if fc == 5:
                return self._write_coil(data)
            if fc == 17:
                return self._report_id()
        except struct.error:
            return self._exc(fc, EXC_ILLEGAL_VALUE)
        self.s.event("modbus_request", payload=f"unsupported function {fc}", function=fc,
                     command=f"modbus fc={fc}")
        return self._exc(fc, EXC_ILLEGAL_FUNCTION)

    def _read_registers(self, fc, data):
        addr, count = struct.unpack(">HH", data[:4])
        if count < 1 or count > 125:
            return self._exc(fc, EXC_ILLEGAL_VALUE)
        regs = []
        for i in range(addr, addr + count):
            regs.append(_reg_value(i) if i in HOLDING else 0)
        self.s.event("modbus_request", payload=f"read fc={fc} addr={addr} count={count}",
                     function=fc, address=addr, count=count,
                     command=f"modbus read holding {40001 + addr}+{count}")
        return struct.pack(">BB", fc, count * 2) + b"".join(struct.pack(">H", r) for r in regs)

    def _read_bits(self, fc, data):
        addr, count = struct.unpack(">HH", data[:4])
        coils = _coils()
        bits = [(coils[i] if i < len(coils) else False) for i in range(addr, addr + count)]
        nbytes = (count + 7) // 8
        out = bytearray(nbytes)
        for i, on in enumerate(bits):
            if on:
                out[i // 8] |= 1 << (i % 8)
        self.s.event("modbus_request", payload=f"read bits fc={fc} addr={addr} count={count}",
                     function=fc, address=addr, count=count, command=f"modbus read coils {addr}+{count}")
        return struct.pack(">BB", fc, nbytes) + bytes(out)

    def _apply_write(self, idx, value):
        field, scale, writable = HOLDING[idx]
        if not writable:
            return False
        if field == "mode":
            newval = MODE_STR.get(value & 1, "auto")
        else:
            newval = value / scale
            newval = int(newval) if field == "interval" else round(newval, 1)
        changed = STATE.sensor_config(f"modbus:{self.s.ip}", {field: newval})
        if changed:
            self.s.event("state_change", payload=f"{field}={newval}", device_field=field,
                         value=str(newval), via="modbus")
            self.s.event("modbus_write", payload=f"{40001 + idx}={value} ({field}={newval})",
                         function=6, address=idx, command=f"modbus write {40001 + idx}={value}")
        return True

    def _write_single(self, data):
        addr, value = struct.unpack(">HH", data[:4])
        if addr not in HOLDING:
            self.s.event("modbus_write", payload=f"write unknown reg {40001 + addr}={value}",
                         address=addr, command=f"modbus write {40001 + addr}={value}")
            return self._exc(6, EXC_ILLEGAL_ADDRESS)
        if not self._apply_write(addr, value):
            return self._exc(6, EXC_ILLEGAL_ADDRESS)         # read-only telemetry register
        return struct.pack(">BHH", 6, addr, value)

    def _write_multiple(self, data):
        addr, count, _nbytes = struct.unpack(">HHB", data[:5])
        values = struct.unpack(">" + "H" * count, data[5:5 + count * 2])
        wrote = 0
        for i, v in enumerate(values):
            if (addr + i) in HOLDING and self._apply_write(addr + i, v):
                wrote += 1
        self.s.event("modbus_write", payload=f"write multi addr={addr} count={count} applied={wrote}",
                     address=addr, count=count, command=f"modbus write {40001 + addr}+{count}")
        return struct.pack(">BHH", 16, addr, count)

    def _write_coil(self, data):
        addr, value = struct.unpack(">HH", data[:4])
        on = value == 0xFF00
        if addr == 0:                                        # coil 0 = alarm reset
            STATE.sensor_config(f"modbus:{self.s.ip}", {"alarm": "none" if not on else "MANUAL"})
            self.s.event("state_change", payload=f"alarm_coil={on}", device_field="alarm", via="modbus")
        self.s.event("modbus_write", payload=f"write coil {addr}={'ON' if on else 'OFF'}",
                     address=addr, command=f"modbus write coil {addr}={'ON' if on else 'OFF'}")
        return struct.pack(">BHH", 5, addr, value)

    def _report_id(self):
        ident = SERVER_ID.encode()
        self.s.event("modbus_request", payload="report server id (FC17)", function=17,
                     command="modbus report-server-id")
        body = struct.pack(">BBB", len(ident) + 1, 0xFF, 1) + ident   # count? no: len, run-status
        # FC17: byte count, then server id bytes + run indicator (0xFF = ON)
        payload = ident + b"\xFF"
        return struct.pack(">BB", 17, len(payload)) + payload


_conn_count = {}
_lock = threading.Lock()


def handle(sock, addr):
    ip, sport = addr[0], addr[1]
    with _lock:
        _conn_count[ip] = _conn_count.get(ip, 0) + 1
        too_many = _conn_count[ip] > MAX_CONN_PER_IP
    session = Session("Modbus", DEVICE, ip, sport, PORT)
    try:
        if too_many:
            session.event("rate_limited")
            return
        ModbusConn(sock, session).run()
    finally:
        session.close()
        with _lock:
            _conn_count[ip] -= 1
        try:
            sock.close()
        except OSError:
            pass


def main():
    STATE.init_defaults()
    start_heartbeat("modbus", port=PORT, device=DEVICE, protocol="Modbus")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(200)
    log.info("Modbus/TCP honeypot (Industrial Sensor) listening on :%d", PORT)
    while True:
        try:
            c, a = srv.accept()
            threading.Thread(target=handle, args=(c, a), daemon=True).start()
        except Exception as e:
            log.error(e)


if __name__ == "__main__":
    main()
