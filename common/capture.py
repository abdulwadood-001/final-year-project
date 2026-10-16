"""
HoneyBot-IoT — malware sample capture (scope M3: "File Capture").

Every honeypot hands attacker-supplied file content to `store()`:

    HTTP   firmware upload / binary request bodies        source=http_upload | http_body
    SSH    `cat > /tmp/x`, `dd of=…`, `scp -t` over exec   source=ssh_stdin
    Shell  files written with echo/printf redirects        source=shell_write
    MQTT   binary publish payloads                         source=mqtt_payload

Samples are stored content-addressed in a QUARANTINE directory
    $CAPTURE_DIR/<sha256[:2]>/<sha256>.bin      mode 0400, never executed
and indexed in the `file_captures` table (SHA-256, MD5, size, MIME, ELF CPU
architecture). The intel engine later scans unscanned rows with YARA
(intel/yara_scan.py) and writes the verdict back.

Nothing here ever executes or opens a captured file other than to write it once.
"""

import os
import hashlib
import logging
import threading

from common.db import enqueue_capture, sanitize

log = logging.getLogger("capture")

CAPTURE_DIR = os.environ.get("CAPTURE_DIR", "/app/captures")
MAX_SAMPLE = int(os.environ.get("CAPTURE_MAX_BYTES", 10 * 1024 * 1024))
MIN_SAMPLE = 16

# ELF e_machine values seen in IoT malware (Mirai alone ships ~10 architectures)
ELF_MACHINES = {
    0x02: "SPARC", 0x03: "x86", 0x04: "m68k", 0x08: "MIPS", 0x14: "PowerPC",
    0x15: "PowerPC64", 0x28: "ARM", 0x2A: "SuperH", 0x32: "IA-64", 0x3E: "x86-64",
    0xB7: "AArch64", 0xF3: "RISC-V", 0x5D: "ARC",
}

_seen_lock = threading.Lock()
_seen = set()           # (session_id, sha256) already recorded in this process


def sniff(data: bytes):
    """Return (mime_type, arch) from magic bytes – no libmagic dependency."""
    if data[:4] == b"\x7fELF":
        arch = None
        if len(data) >= 20:
            little = data[5:6] != b"\x02"
            machine = int.from_bytes(data[18:20], "little" if little else "big")
            arch = ELF_MACHINES.get(machine, f"e_machine=0x{machine:x}")
            bits = "64" if data[4:5] == b"\x02" else "32"
            arch = f"{arch} ({bits}-bit {'LE' if little else 'BE'})"
        return "application/x-elf", arch
    if data[:2] == b"MZ":
        return "application/x-dosexec", None
    if data[:2] == b"\x1f\x8b":
        return "application/gzip", None
    if data[:4] == b"PK\x03\x04":
        return "application/zip", None
    if data[:3] == b"BZh":
        return "application/x-bzip2", None
    if data[:6] == b"\xfd7zXZ\x00":
        return "application/x-xz", None
    if b"UPX!" in data[:1024]:
        return "application/x-upx", None
    if data[:2] == b"#!":
        return "text/x-shellscript", None
    sample = data[:4096]
    if sample and all(32 <= b < 127 or b in (9, 10, 13) for b in sample):
        if any(k in sample for k in (b"wget ", b"curl ", b"tftp ", b"chmod ", b"busybox")):
            return "text/x-shellscript", None
        return "text/plain", None
    return "application/octet-stream", None


def looks_interesting(data: bytes) -> bool:
    """Heuristic used for generic bodies/payloads: is this worth keeping as a sample?"""
    if len(data) < MIN_SAMPLE:
        return False
    mime, _ = sniff(data)
    if mime != "text/plain":
        return True
    return len(data) >= 4096          # large text blobs (scripts, configs) too


def _write_sample(sha, data):
    sub = os.path.join(CAPTURE_DIR, sha[:2])
    path = os.path.join(sub, f"{sha}.bin")
    if os.path.exists(path):
        return path
    os.makedirs(sub, exist_ok=True)
    tmp = f"{path}.part"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o400)               # read-only, never executable
    os.replace(tmp, path)
    return path


def store(session, data, source, filename=None):
    """Quarantine `data` and index it. Returns the capture dict, or None if skipped."""
    if data is None:
        return None
    if isinstance(data, str):
        data = data.encode("latin-1", "replace")
    data = bytes(data)
    if len(data) < MIN_SAMPLE:
        return None
    truncated = len(data) > MAX_SAMPLE
    if truncated:
        data = data[:MAX_SAMPLE]
    sha = hashlib.sha256(data).hexdigest()
    sid = getattr(session, "id", None)
    with _seen_lock:
        if (sid, sha) in _seen:
            return None
        _seen.add((sid, sha))
        if len(_seen) > 50_000:
            _seen.clear()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    mime, arch = sniff(data)
    path = None
    try:
        path = _write_sample(sha, data)
    except OSError as e:                   # read-only FS in unit tests, disk full …
        log.warning("could not quarantine %s: %s", sha[:12], e)
    cap = dict(sha256=sha, md5=md5, size=len(data), mime_type=mime, arch=arch,
               storage_path=path, source=source, filename=sanitize(filename)[:255] if filename else None,
               truncated=truncated)
    enqueue_capture(session, cap)
    if session is not None:
        session.event("file_capture", payload=f"{cap['filename'] or ''} {mime} {len(data)} bytes".strip(),
                      sha256=sha, md5=md5, size=len(data), mime_type=mime, arch=arch,
                      source=source, filename=cap["filename"])
    log.info("captured %s %s (%d bytes, %s%s) via %s", sha[:16], cap["filename"] or "", len(data), mime,
             f", {arch}" if arch else "", source)
    return cap
