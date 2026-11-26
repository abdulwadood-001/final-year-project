"""
HoneyBot-IoT — RTSP honeypot  (device: CCTV camera, port 8554 → publish as 554)

RFC 2326 signalling implemented with asyncio:
    OPTIONS · DESCRIBE · SETUP · PLAY · PAUSE · TEARDOWN · GET_PARAMETER · SET_PARAMETER
    ANNOUNCE / RECORD (stream-injection attempts) are logged and refused.
Authentication: Basic AND Digest (MD5).  Basic gives us the cleartext password;
for Digest we test the response against the device's weak-credential list and
store the digest fields so they can be cracked offline.
DESCRIBE returns a valid H.264 SDP built from a real encoded CCTV clip, and PLAY
streams that clip as RTP (H.264, RFC 6184 single-NAL + FU-A) interleaved over the
RTSP TCP connection, so VLC / ffplay / Cameradar show live camera video.
UDP transport is answered with 461 Unsupported Transport: clients fall back to
TCP-interleaved, and the honeypot never originates UDP (outbound isolation holds).
"""

import os
import sys
import time
import random
import asyncio
import hashlib
import logging
import secrets
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.db import Session
from common.state import STATE, start_heartbeat
from common.creds import is_weak, DEFAULTS as CRED_DEFAULTS

PORT = int(os.environ.get("RTSP_PORT", 8554))
DEVICE = "cctv"
REALM = "IP Camera(21AB9)"
SERVER = "Rtsp Server/3.0"
VALID_ROUTES = ("/cam/realmonitor", "/Streaming/Channels/101", "/Streaming/Channels/102",
                "/stream1", "/stream2", "/h264", "/live", "/live/ch00_0", "/onvif1", "/11", "/12",
                "/ch0_0.h264", "/video1", "/")
PUBLIC = "OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER"
MEDIA = os.environ.get("RTSP_MEDIA", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                     "media", "cctv.h264"))
FPS = int(os.environ.get("RTSP_FPS", 10))
STREAM_MAX_SECONDS = int(os.environ.get("RTSP_STREAM_MAX_SECONDS", 300))
RTP_MTU = 1400

logging.basicConfig(level=logging.INFO, format="%(asctime)s | rtsp | %(message)s")
log = logging.getLogger("rtsp")

SDP_TEMPLATE = (
    "v=0\r\n"
    "o=- {sess} 1 IN IP4 0.0.0.0\r\n"
    "s=Media Server\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "t=0 0\r\n"
    "a=control:*\r\n"
    "a=packetization-supported:DH\r\n"
    "a=rtppayloadinfo:1\r\n"
    "a=range:npt=now-\r\n"
    "m=video 0 RTP/AVP 96\r\n"
    "a=control:trackID=0\r\n"
    "a=framerate:25.000000\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 packetization-mode=1;profile-level-id=64001F;"
    "sprop-parameter-sets=Z2QAH6zZQFAFuhAAAAMAEAAAAwPI8YMZYA==,aOvjyyLA\r\n"
    "a=recvonly\r\n"
    "m=audio 0 RTP/AVP 8\r\n"
    "a=control:trackID=1\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=recvonly\r\n"
)


# ── real H.264 media: Annex-B clip -> access units of NAL units ────────────
def _split_nals(data):
    """Split an Annex-B byte stream into NAL units (start codes removed)."""
    nals, i, n = [], 0, len(data)
    starts = []
    while i < n - 3:
        if data[i] == 0 and data[i + 1] == 0 and (data[i + 2] == 1 or
                                                   (data[i + 2] == 0 and i + 3 < n and data[i + 3] == 1)):
            sc = 3 if data[i + 2] == 1 else 4
            starts.append((i, i + sc))
            i += sc
        else:
            i += 1
    for k, (_s, b) in enumerate(starts):
        e = starts[k + 1][0] if k + 1 < len(starts) else n
        nal = data[b:e].rstrip(b"\x00") if k + 1 < len(starts) else data[b:e]
        if nal:
            nals.append(nal)
    return nals


def load_media(path=MEDIA):
    """Return (access_units, sps, pps). An access unit = list of NALs ending in a VCL NAL."""
    try:
        with open(path, "rb") as f:
            nals = _split_nals(f.read())
    except OSError as e:
        log.warning("no RTSP media (%s) – PLAY will send no video", e)
        return [], None, None
    sps = next((x for x in nals if x[0] & 0x1F == 7), None)
    pps = next((x for x in nals if x[0] & 0x1F == 8), None)
    aus, cur = [], []
    for nal in nals:
        cur.append(nal)
        if nal[0] & 0x1F in (1, 5):          # slice → end of access unit
            aus.append(cur)
            cur = []
    return aus, sps, pps


ACCESS_UNITS, SPS, PPS = [], None, None


def build_sdp():
    import base64
    plid = SPS[1:4].hex().upper() if SPS else "42C01E"
    sprop = (base64.b64encode(SPS).decode() + "," + base64.b64encode(PPS).decode()) if SPS and PPS else ""
    return ("v=0\r\n"
            f"o=- {random.randint(10**9, 10**10)} 1 IN IP4 0.0.0.0\r\n"
            "s=Media Server\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\na=control:*\r\n"
            "a=range:npt=now-\r\n"
            "m=video 0 RTP/AVP 96\r\na=control:trackID=0\r\n"
            f"a=framerate:{FPS}.000000\r\na=rtpmap:96 H264/90000\r\n"
            f"a=fmtp:96 packetization-mode=1;profile-level-id={plid};sprop-parameter-sets={sprop}\r\n"
            "a=recvonly\r\n")


def rtp_packets(nal, seq, ts, ssrc, marker):
    """Packetise one NAL unit (RFC 6184): a single-NAL packet, or FU-A fragments when it
    exceeds the MTU. Returns (list_of_rtp_packets, next_seq)."""
    import struct as _st

    def hdr(m, sq):
        return _st.pack("!BBHII", 0x80, (0x80 if m else 0) | 96, sq & 0xFFFF, ts & 0xFFFFFFFF, ssrc)
    if len(nal) <= RTP_MTU:
        return [hdr(marker, seq) + nal], seq + 1
    out, nh, payload, first = [], nal[0], nal[1:], True
    fu_ind = (nh & 0xE0) | 28
    while payload:
        chunk, payload = payload[:RTP_MTU - 2], payload[RTP_MTU - 2:]
        last = not payload
        fu_hdr = (0x80 if first else 0) | (0x40 if last else 0) | (nh & 0x1F)
        out.append(hdr(marker and last, seq) + bytes([fu_ind, fu_hdr]) + chunk)
        seq += 1
        first = False
    return out, seq


def parse_auth_header(value):
    scheme, _, rest = value.partition(" ")
    params = {k: a or b for k, a, b in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]*))', rest)}
    return scheme.lower(), rest.strip(), params


def digest_check(params, method):
    """Return the matching password from the weak list, or None."""
    user = params.get("username", "")
    for u, p in CRED_DEFAULTS["cctv"]:
        if u != user:
            continue
        # MD5 is mandated by RTSP/HTTP Digest auth (RFC 2617); not our own secret
        ha1 = hashlib.md5(f"{u}:{params.get('realm', REALM)}:{p}".encode(), usedforsecurity=False).hexdigest()
        ha2 = hashlib.md5(f"{method}:{params.get('uri', '')}".encode(), usedforsecurity=False).hexdigest()
        if params.get("qop"):
            exp = hashlib.md5(f"{ha1}:{params.get('nonce')}:{params.get('nc')}:"
                              f"{params.get('cnonce')}:{params.get('qop')}:{ha2}".encode(), usedforsecurity=False).hexdigest()
        else:
            exp = hashlib.md5(f"{ha1}:{params.get('nonce')}:{ha2}".encode(), usedforsecurity=False).hexdigest()
        if exp == params.get("response"):
            return p
    return None


class RTSPConn:
    def __init__(self, reader, writer):
        self.r, self.w = reader, writer
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        self.ip, self.sport = peer[0], peer[1]
        self.s = Session("RTSP", DEVICE, self.ip, self.sport, PORT)
        self.s.start_pcap()
        self.nonce = secrets.token_hex(16)
        self.authed = False
        self.rtsp_session = None
        self.playing = False
        self.requests = 0
        self.channel = 0                     # RTP interleaved channel (RTCP = channel + 1)
        self.stream_task = None
        self.ssrc = random.getrandbits(32)
        self.bytes_streamed = 0

    async def read_request(self):
        # while streaming, clients send RTCP as interleaved "$" frames on the same socket
        while True:
            first = await asyncio.wait_for(self.r.readexactly(1), timeout=60)
            if first != b"$":
                break
            hdr = await self.r.readexactly(3)
            await self.r.readexactly(int.from_bytes(hdr[1:3], "big"))
        head = first + await asyncio.wait_for(self.r.readuntil(b"\r\n\r\n"), timeout=60)
        self.s.pcap_in(head)
        if len(head) > 16384:
            raise ValueError("header too large")
        text = head.decode("utf-8", "replace")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("RTSP/"):
            return None, lines[0], {}, b""
        method, url, _ = parts
        headers = {}
        for l in lines[1:]:
            if ":" in l:
                k, v = l.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body = b""
        cl = int(headers.get("content-length", "0") or 0)
        if 0 < cl < 65536:
            body = await self.r.readexactly(cl)
            self.s.pcap_in(body)
        return method.upper(), url, headers, body

    def reply(self, code, reason, cseq, extra=None, body=""):
        hdr = [f"RTSP/1.0 {code} {reason}", f"CSeq: {cseq}", f"Server: {SERVER}",
               f"Date: {time.strftime('%a, %b %d %Y %H:%M:%S GMT', time.gmtime())}"]
        items = extra if isinstance(extra, list) else list((extra or {}).items())
        for k, v in items:
            hdr.append(f"{k}: {v}")
        if body:
            hdr.append(f"Content-Length: {len(body.encode())}")
        raw = ("\r\n".join(hdr) + "\r\n\r\n" + body).encode()
        self.s.pcap_out(raw)
        self.w.write(raw)

    def unauthorized(self, cseq):
        # many cameras advertise both – naive brute-forcers then send cleartext Basic
        self.reply(401, "Unauthorized", cseq, [
            ("WWW-Authenticate", f'Digest realm="{REALM}", nonce="{self.nonce}", stale="FALSE"'),
            ("WWW-Authenticate", f'Basic realm="{REALM}"')])

    def check_auth(self, method, headers):
        h = headers.get("authorization")
        if not h:
            return False
        scheme, raw, params = parse_auth_header(h)
        if scheme == "basic":
            import base64
            try:
                u, _, p = base64.b64decode(raw).decode("utf-8", "replace").partition(":")
            except Exception:
                u, p = "", ""
            ok = is_weak(DEVICE, u, p)
            self.s.auth(u, p, ok, method="basic", rtsp_method=method)
        elif scheme == "digest":
            pw = digest_check(params, method)
            ok = pw is not None
            self.s.auth(params.get("username", ""), pw, ok, method="digest", rtsp_method=method,
                        digest={k: params.get(k) for k in ("realm", "nonce", "uri", "response",
                                                            "qop", "nc", "cnonce")})
        else:
            return False
        log.info("%s | %s auth %s | %s", self.ip, scheme, self.s.username or params.get("username", ""),
                 "ACCEPT" if ok else "REJECT")
        if ok:
            self.authed = True
        return ok

    async def run(self):
        try:
            while True:
                method, url, headers, body = await self.read_request()
                self.requests += 1
                if method is None:
                    self.s.event("malformed", payload=url[:300])
                    self.w.write(b"RTSP/1.0 400 Bad Request\r\n\r\n")
                    await self.w.drain()
                    return
                cseq = headers.get("cseq", "0")
                path = re.sub(r"^rtsp://[^/]*", "", url).split("?")[0] or "/"
                self.s.event("rtsp_request", command=f"{method} {url}"[:500],
                             payload=body.decode("utf-8", "replace")[:2000] if body else None,
                             method=method, url=url[:500], path=path,
                             user_agent=headers.get("user-agent"), cseq=cseq)
                if self.requests == 1:
                    self.s.set_client_version(headers.get("user-agent", "")[:200])
                await self.dispatch(method, url, path, headers, body, cseq)
                await self.w.drain()
                if method == "TEARDOWN":
                    return
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError,
                asyncio.LimitOverrunError):
            pass
        except Exception as e:
            self.s.event("malformed", payload=f"{type(e).__name__}: {e}"[:300])
        finally:
            self.stop_stream()
            if self.bytes_streamed:
                self.s.event("stream_bytes", payload=f"{self.bytes_streamed} bytes of H.264 RTP sent",
                             bytes=self.bytes_streamed)
            if self.playing:
                v = max(0, int(STATE.field("cctv", "viewers", "1") or 1) - 1)
                STATE.set("cctv", actor="system", viewers=v)
            self.s.close()
            try:
                self.w.close()
            except Exception:
                pass

    async def stream(self):
        """Send the CCTV clip as RTP over the RTSP connection, paced at FPS, looping."""
        if not ACCESS_UNITS:
            return
        seq, ts, step = random.randint(0, 30000), random.getrandbits(32), 90000 // FPS
        t0 = time.time()
        try:
            while time.time() - t0 < STREAM_MAX_SECONDS:
                for au in ACCESS_UNITS:
                    for k, nal in enumerate(au):
                        pkts, seq = rtp_packets(nal, seq, ts, self.ssrc, k == len(au) - 1)
                        for p in pkts:
                            self.w.write(b"$" + bytes([self.channel]) + len(p).to_bytes(2, "big") + p)
                            self.bytes_streamed += len(p) + 4
                    await self.w.drain()
                    ts += step
                    await asyncio.sleep(1.0 / FPS)
        except (ConnectionError, asyncio.CancelledError, OSError):
            pass

    def stop_stream(self):
        if self.stream_task and not self.stream_task.done():
            self.stream_task.cancel()

    async def dispatch(self, method, url, path, headers, body, cseq):
        if method == "OPTIONS":
            return self.reply(200, "OK", cseq, {"Public": PUBLIC})
        if method in ("ANNOUNCE", "RECORD"):
            self.s.event("stream_injection_attempt", payload=url, method=method)
            return self.reply(405, "Method Not Allowed", cseq, {"Allow": PUBLIC})
        if method not in ("DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN",
                          "GET_PARAMETER", "SET_PARAMETER"):
            return self.reply(501, "Not Implemented", cseq)
        if not self.authed and not self.check_auth(method, headers):
            await asyncio.sleep(0.3)
            return self.unauthorized(cseq)
        base_path = path.split("/trackID")[0].rstrip("/") or "/"
        if method == "DESCRIBE":
            if not any(base_path == r or base_path.startswith(r + "/") or
                       (r != "/" and base_path.startswith(r)) for r in VALID_ROUTES):
                self.s.event("rtsp_route_probe", payload=path)
                return self.reply(404, "Stream Not Found", cseq)
            sdp = build_sdp()
            return self.reply(200, "OK", cseq, {"Content-Base": url.rstrip("/") + "/",
                                                "Content-Type": "application/sdp",
                                                "x-Accept-Dynamic-Rate": "1"}, sdp)
        if method == "SETUP":
            self.rtsp_session = self.rtsp_session or f"{random.randint(10**8, 10**9)}"
            transport = headers.get("transport", "RTP/AVP;unicast;client_port=5000-5001")
            if "interleaved" not in transport and "RTP/AVP/TCP" not in transport.upper():
                # UDP would make the honeypot originate traffic: ask for TCP instead
                self.s.event("rtsp_request", payload="UDP transport requested -> 461", method="SETUP")
                return self.reply(461, "Unsupported Transport", cseq,
                                  {"Session": f"{self.rtsp_session};timeout=60"})
            m = re.search(r"interleaved=(\d+)", transport)
            self.channel = int(m.group(1)) if m else 0
            tr = f"RTP/AVP/TCP;unicast;interleaved={self.channel}-{self.channel + 1};ssrc={self.ssrc:08X}"
            return self.reply(200, "OK", cseq, {"Session": f"{self.rtsp_session};timeout=60",
                                                "Transport": tr})
        if method == "PLAY":
            if not self.playing:
                self.playing = True
                v = int(STATE.field("cctv", "viewers", "0") or 0) + 1
                STATE.set("cctv", actor=f"rtsp:{self.ip}", viewers=v)
                self.s.event("stream_access", payload=url, path=path)
            self.reply(200, "OK", cseq, {"Session": self.rtsp_session or "0",
                                         "Range": "npt=0.000-",
                                         "RTP-Info": f"url={url.rstrip('/')}/trackID=0;seq=0;rtptime=0"})
            await self.w.drain()
            if not self.stream_task or self.stream_task.done():
                self.stream_task = asyncio.ensure_future(self.stream())
            return None
        if method in ("PAUSE", "TEARDOWN"):
            self.stop_stream()
        if method in ("PAUSE", "GET_PARAMETER", "SET_PARAMETER", "TEARDOWN"):
            return self.reply(200, "OK", cseq, {"Session": self.rtsp_session or "0"})


async def handle(reader, writer):
    await RTSPConn(reader, writer).run()


async def main():
    global ACCESS_UNITS, SPS, PPS
    ACCESS_UNITS, SPS, PPS = load_media()
    log.info("RTSP media: %d frames from %s", len(ACCESS_UNITS), MEDIA)
    STATE.init_defaults()
    start_heartbeat("rtsp", port=PORT, device=DEVICE, protocol="RTSP")
    server = await asyncio.start_server(handle, "0.0.0.0", PORT, limit=32768)
    log.info("RTSP honeypot (CCTV) listening on :%d", PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
