"""
HoneyBot-IoT — YARA scanning of captured samples (scope M3 "automatic YARA scan
result for malware family identification").

The intel engine calls `scan_pending()` every pass: rows of `file_captures` with
`scanned_at IS NULL` are read from the quarantine volume (read-only mount), matched
against intel/yara_rules/*.yar, and the verdict is written back:

    yara_result  = 'CLEAN'  |  'mirai, generic-iot-elf'  |  'UNAVAILABLE' (file missing)
    yara_matches = rule names
"""

import os
import glob
import logging

from common.db import fetchall, execute

log = logging.getLogger("yara")

RULES_DIR = os.environ.get("YARA_RULES_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules"))
CAPTURE_DIR = os.environ.get("CAPTURE_DIR", "/app/captures")

_rules = None
_rules_error = None


def rules():
    """Compile every .yar file once. Returns None (and logs once) if yara is unavailable."""
    global _rules, _rules_error
    if _rules is not None or _rules_error is not None:
        return _rules
    try:
        import yara
        files = {os.path.basename(p): p for p in sorted(glob.glob(os.path.join(RULES_DIR, "*.yar")))}
        if not files:
            raise FileNotFoundError(f"no .yar files in {RULES_DIR}")
        _rules = yara.compile(filepaths=files)
        log.info("YARA: compiled %d rule file(s) from %s", len(files), RULES_DIR)
    except Exception as e:
        _rules_error = str(e)
        log.warning("YARA disabled: %s", e)
    return _rules


def scan_bytes(data: bytes):
    """Return (verdict, [rule names], [families]) for one sample."""
    r = rules()
    if r is None:
        return None, [], []
    matches = r.match(data=data, timeout=30)
    names = [m.rule for m in matches]
    fams = []
    for m in matches:
        fam = m.meta.get("family", m.rule)
        if fam not in fams:
            fams.append(fam)
    # a specific family is more informative than the generic "embedded ELF" label
    specific = [f for f in fams if f not in ("generic-iot-elf", "upx-packed")]
    ordered = specific + [f for f in fams if f not in specific]
    return (", ".join(ordered) if ordered else "CLEAN"), names, ordered


def _resolve(path, sha):
    # the path recorded by a honeypot is inside ITS container; the intel engine
    # mounts the same volume, so fall back to the content-addressed location
    for p in (path, os.path.join(CAPTURE_DIR, sha[:2], f"{sha}.bin")):
        if p and os.path.isfile(p):
            return p
    return None


def scan_pending(limit=50):
    if rules() is None:
        return 0
    rows = fetchall("""SELECT id, sha256, storage_path FROM file_captures
                       WHERE scanned_at IS NULL ORDER BY id LIMIT %s""", (limit,))
    done = 0
    cache = {}
    for cid, sha, path in rows:
        sha = sha.strip()
        if sha not in cache:
            p = _resolve(path, sha)
            if p is None:
                cache[sha] = ("UNAVAILABLE", [], [])
            else:
                try:
                    with open(p, "rb") as f:
                        cache[sha] = scan_bytes(f.read())
                except Exception as e:
                    log.error("scan of %s failed: %s", sha[:12], e)
                    cache[sha] = ("ERROR", [], [])
        verdict, names, _fams = cache[sha]
        execute("""UPDATE file_captures SET yara_result=%s, yara_matches=%s, scanned_at=NOW()
                   WHERE id=%s""", (verdict, names, cid))
        done += 1
        if names:
            log.info("YARA %s → %s", sha[:16], verdict)
    return done
