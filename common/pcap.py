"""
HoneyBot-IoT — per-session PCAP recording (scope M3 "PCAP Recording").

Full packet-level capture per attacker session, written in standard libpcap format
for forensic replay and protocol-level analysis in Wireshark/tshark. It is
dependency-free: each protocol handler feeds the bytes it reads from and writes to
the attacker into a `PcapTap`, and on session close the tap synthesises a valid
Ethernet/IPv4/TCP stream (3-way handshake, correct sequence/acknowledgement numbers,
a closing FIN) around that application data and writes `<session_id>.pcap`.

Synthesising the framing (rather than sniffing with raw sockets) means no
CAP_NET_RAW, no privileged side-car, and a deterministic, unit-testable capture that
contains exactly the one session — which is what "per session" forensic replay needs.
For TLS/SSH the recorded payload is the decrypted application data (the useful part),
so the PCAP shows what the attacker actually did.

    PCAP_DIR      output directory (default /app/pcap)
    PCAP_ENABLED  "1" to record (default on); captures are capped at PCAP_MAX_BYTES
"""

import os
import time
import struct
import logging
import threading

log = logging.getLogger("pcap")

PCAP_DIR = os.environ.get("PCAP_DIR", "/app/pcap")
PCAP_ENABLED = os.environ.get("PCAP_ENABLED", "1") == "1"
PCAP_MAX_BYTES = int(os.environ.get("PCAP_MAX_BYTES", 8 * 1024 * 1024))
MTU = 1460                                   # max TCP payload per synthesised segment

_SRV_MAC = b"\x02\x00\x00\x00\x00\x01"       # locally-administered, honeypot side
_CLI_MAC = b"\x02\x00\x00\x00\x00\x02"       # attacker side
_SRV_IP = os.environ.get("PCAP_SERVER_IP", "172.31.66.10")


def _ip_to_bytes(ip):
    try:
        parts = [int(x) & 0xFF for x in ip.split(".")]
        if len(parts) == 4:
            return bytes(parts)
    except (ValueError, AttributeError):
        pass
    return b"\x0a\x00\x00\x01"               # 10.0.0.1 for non-IPv4 / unknown peers


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ipv4(src, dst, proto, payload, ident):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF, 0x4000, 64, proto, 0, src, dst)
    chk = _checksum(hdr)
    return hdr[:10] + struct.pack("!H", chk) + hdr[12:] + payload


def _tcp(sport, dport, seq, ack, flags, src_ip, dst_ip, payload=b""):
    off = (5 << 4)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      off, flags, 65535, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    chk = _checksum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", chk) + hdr[18:] + payload


class RecordingSocket:
    """Transparent wrapper around a socket that feeds every byte read/written into a
    PcapTap. Used by the socket-based servers (SSH, Modbus, MQTT); for SSH this captures
    the real on-the-wire (encrypted) bytes, exactly as a network tap would see them."""

    def __init__(self, sock, tap):
        self._sock = sock
        self._tap = tap

    def recv(self, n, *a, **k):
        data = self._sock.recv(n, *a, **k)
        if data and self._tap:
            self._tap.inbound(data)
        return data

    def recv_into(self, buf, *a, **k):
        n = self._sock.recv_into(buf, *a, **k)
        if n and self._tap:
            try:
                self._tap.inbound(bytes(buf[:n]))
            except Exception:
                pass
        return n

    def send(self, data, *a, **k):
        n = self._sock.send(data, *a, **k)
        if self._tap and n:
            self._tap.outbound(bytes(data[:n]))
        return n

    def sendall(self, data, *a, **k):
        if self._tap and data:
            self._tap.outbound(bytes(data))
        return self._sock.sendall(data, *a, **k)

    def __getattr__(self, name):
        return getattr(self._sock, name)


class PcapTap:
    """Collects the bytes exchanged in one session and writes a libpcap file on flush."""

    def __init__(self, session_id, client_ip, client_port, server_port, device=None, protocol=None):
        self.session_id = session_id
        self.client_ip = client_ip or "0.0.0.0"
        self.client_port = int(client_port or 0) & 0xFFFF
        self.server_port = int(server_port or 0) & 0xFFFF
        self.device, self.protocol = device, protocol
        self.frames = []                     # (ts, from_client: bool, data)
        self.total = 0
        self.truncated = False
        self._lock = threading.Lock()
        self.path = None

    def inbound(self, data):
        """Bytes received FROM the attacker."""
        self._add(True, data)

    def outbound(self, data):
        """Bytes sent TO the attacker."""
        self._add(False, data)

    def _add(self, from_client, data):
        if not PCAP_ENABLED or not data:
            return
        with self._lock:
            if self.total >= PCAP_MAX_BYTES:
                self.truncated = True
                return
            if isinstance(data, str):
                data = data.encode("utf-8", "replace")
            data = bytes(data)[:PCAP_MAX_BYTES - self.total]
            self.total += len(data)
            self.frames.append((time.time(), from_client, data))

    def _packets(self):
        """Yield (ts, raw_ethernet_frame) reconstructing the TCP conversation."""
        cli_ip, srv_ip = _ip_to_bytes(self.client_ip), _ip_to_bytes(_SRV_IP)
        cseq = ssq = 1
        ident = 1
        t0 = self.frames[0][0] if self.frames else time.time()

        def eth(from_client, ip_payload):
            dst, src = (_SRV_MAC, _CLI_MAC) if from_client else (_CLI_MAC, _SRV_MAC)
            return dst + src + b"\x08\x00" + ip_payload

        def seg(ts, from_client, flags, payload=b""):
            nonlocal cseq, ssq, ident
            if from_client:
                sp, dp, sip, dip, seq, ack = self.client_port, self.server_port, cli_ip, srv_ip, cseq, ssq
            else:
                sp, dp, sip, dip, seq, ack = self.server_port, self.client_port, srv_ip, cli_ip, ssq, cseq
            tcp = _tcp(sp, dp, seq, ack, flags, sip, dip, payload)
            ident += 1
            frame = eth(from_client, _ipv4(sip, dip, 6, tcp, ident))
            return ts, frame

        # 3-way handshake
        yield seg(t0, True, 0x02)                         # SYN
        cseq += 1
        yield seg(t0, False, 0x12)                        # SYN-ACK
        ssq += 1
        yield seg(t0, True, 0x10)                         # ACK

        for ts, from_client, data in self.frames:
            for i in range(0, len(data), MTU):
                chunk = data[i:i + MTU]
                yield seg(ts, from_client, 0x18, chunk)   # PSH|ACK
                if from_client:
                    cseq += len(chunk)
                else:
                    ssq += len(chunk)

        tn = self.frames[-1][0] if self.frames else t0
        yield seg(tn, True, 0x11)                         # FIN|ACK (client)
        cseq += 1
        yield seg(tn, False, 0x11)                        # FIN|ACK (server)
        ssq += 1
        yield seg(tn, True, 0x10)                         # ACK

    def flush(self):
        """Write the .pcap file. Returns its path, or None when nothing was captured."""
        if not PCAP_ENABLED or not self.frames:
            return None
        try:
            os.makedirs(PCAP_DIR, exist_ok=True)
            path = os.path.join(PCAP_DIR, f"{self.session_id}.pcap")
            tmp = path + ".part"
            with open(tmp, "wb") as f:
                f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
                for ts, frame in self._packets():
                    sec = int(ts)
                    usec = int((ts - sec) * 1_000_000)
                    f.write(struct.pack("!IIII", sec, usec, len(frame), len(frame)))
                    f.write(frame)
            os.replace(tmp, path)
            self.path = path
            return path
        except OSError as e:
            log.warning("could not write pcap for %s: %s", self.session_id[:8], e)
            return None
