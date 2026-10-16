"""
HoneyBot-IoT — STIX 2.1 IOC export (scope M4: "STIX 2.1 formatted IOC export for
SIEM integration").

`build_bundle(hours)` returns a STIX 2.1 bundle (plain dict, JSON-serialisable):

    identity        the HoneyBot-IoT sensor (creator of every object)
    indicator       one per IOC: url / domain / ipv4 / file SHA-256, STIX patterns
    attack-pattern  one per MITRE ATT&CK technique seen in detections
    malware         one per malware family identified by YARA
    relationship    indicator --indicates--> malware   (sample hash → family)
                    indicator --indicates--> attack-pattern (attacker IP → techniques)
    sighting        how often / when each indicator was observed on the honeynet

IDs are UUIDv5 of the indicator value, so re-exporting the same IOC always yields
the same STIX id and a SIEM de-duplicates instead of duplicating.
The tests validate the output with the OASIS `stix2` library.
"""

import json
import uuid
from datetime import datetime, timezone

from common.db import fetchall
from intel import mitre

NS = uuid.UUID("6f1c3b0e-6c2a-4b47-9d6e-2b8f0f1d9a10")       # HoneyBot-IoT namespace
SPEC = "2.1"
IDENTITY_ID = f"identity--{uuid.uuid5(NS, 'honeybot-iot-sensor')}"
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"   # TLP:AMBER (STIX 2.1 standard)

FAMILY_TYPES = {
    "mirai": ["bot", "worm"], "gafgyt": ["bot"], "mozi": ["bot", "worm"], "tsunami": ["bot"],
    "dropper-script": ["dropper"], "coinminer": ["resource-exploitation"], "upx-packed": ["unknown"],
    "generic-iot-elf": ["unknown"],
}


def _ts(dt=None):
    dt = dt or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _sid(kind, key):
    return f"{kind}--{uuid.uuid5(NS, f'{kind}:{key}')}"


def _esc(v):
    """Escape a value for use inside a single-quoted STIX pattern string."""
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


def _pattern(typ, value):
    if typ == "url":
        return f"[url:value = '{_esc(value)}']"
    if typ == "domain":
        return f"[domain-name:value = '{_esc(value)}']"
    if typ == "ipv4":
        return f"[ipv4-addr:value = '{_esc(value)}']"
    if typ == "sha256":
        return f"[file:hashes.'SHA-256' = '{_esc(value.lower())}']"
    return None


def _common(created, modified=None):
    return {"spec_version": SPEC, "created": _ts(created), "modified": _ts(modified or created),
            "created_by_ref": IDENTITY_ID, "object_marking_refs": [TLP_AMBER]}


def build_bundle(hours=24 * 7):
    hours = max(1, int(hours))
    now = datetime.now(timezone.utc)
    objects = [{
        "type": "identity", "id": IDENTITY_ID, "spec_version": SPEC,
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "name": "HoneyBot-IoT honeynet sensor", "identity_class": "system",
        "description": "High-interaction multi-protocol IoT honeypot (CCTV camera, smart lock, "
                       "industrial sensor over SSH, Telnet, HTTP, MQTT, RTSP).",
    }]
    indicators = {}            # (type, value) -> indicator id

    for typ, value, first, last, src, proto, hits, ctx in fetchall(f"""
            SELECT type, value, first_seen, last_seen, source_ip, protocol, hits, context
            FROM iocs WHERE last_seen > NOW() - INTERVAL '{hours} hours'
            ORDER BY last_seen DESC LIMIT 5000"""):
        pat = _pattern(typ, value)
        if not pat:
            continue
        iid = _sid("indicator", f"{typ}:{value}")
        indicators[(typ, value)] = iid
        first = first or now
        last = max(last or first, first)
        kind = {"url": "malware download URL", "domain": "malware distribution domain",
                "ipv4": "attacker / distribution IP", "sha256": "malware sample"}.get(typ, typ)
        objects.append({
            "type": "indicator", "id": iid, **_common(first, last),
            "name": f"{kind}: {value[:200]}",
            "description": f"Observed by the HoneyBot-IoT honeypot via {proto or 'multiple protocols'}"
                           f" from {src or 'n/a'}. {ctx or ''}".strip()[:1000],
            "indicator_types": ["malicious-activity"],
            "pattern": pat, "pattern_type": "stix", "pattern_version": "2.1",
            "valid_from": _ts(first),
            "labels": ["honeypot", typ],
            "confidence": 85 if typ in ("url", "sha256") else 60,
        })
        objects.append({
            "type": "sighting", "id": _sid("sighting", f"{typ}:{value}"), **_common(first, last),
            "sighting_of_ref": iid, "count": max(1, int(hits or 1)),
            "first_seen": _ts(first), "last_seen": _ts(last if last > first else first),
            "where_sighted_refs": [IDENTITY_ID],
        })

    # MITRE ATT&CK techniques observed in detections
    techniques = {}
    for tid, tname, first, last, ips in fetchall(f"""
            SELECT t.id, t.name, min(d.timestamp), max(d.timestamp), array_agg(DISTINCT d.ip)
            FROM detections d, LATERAL unnest(d.mitre, d.mitre_names) AS t(id, name)
            WHERE d.timestamp > NOW() - INTERVAL '{hours} hours'
            GROUP BY t.id, t.name"""):
        aid = _sid("attack-pattern", tid)
        techniques[tid] = aid
        src = "mitre-ics-attack" if tid.startswith("T0") else "mitre-attack"
        url_tid = tid.replace(".", "/")
        url = (f"https://attack.mitre.org/techniques/{url_tid}/" if src == "mitre-attack"
               else f"https://attack.mitre.org/techniques/{tid}/")
        objects.append({
            "type": "attack-pattern", "id": aid, **_common(first, last),
            "name": mitre.name(tid).replace("ICS: ", ""),
            "external_references": [{"source_name": src, "external_id": tid, "url": url}],
        })
        for ip in ips or []:
            ind = indicators.get(("ipv4", ip))
            if ind:
                objects.append({
                    "type": "relationship", "id": _sid("relationship", f"{ind}>{aid}"),
                    **_common(first, last), "relationship_type": "indicates",
                    "source_ref": ind, "target_ref": aid,
                })

    # malware families identified by YARA on captured samples
    for sha, verdict, first, last in fetchall(f"""
            SELECT sha256, max(yara_result), min(ts), max(ts) FROM file_captures
            WHERE ts > NOW() - INTERVAL '{hours} hours' AND yara_result IS NOT NULL
              AND yara_result NOT IN ('CLEAN','UNAVAILABLE','ERROR')
            GROUP BY sha256"""):
        ind = indicators.get(("sha256", sha.strip()))
        for fam in [f.strip() for f in verdict.split(",") if f.strip()]:
            mid = _sid("malware", fam)
            if not any(o["id"] == mid for o in objects):
                objects.append({
                    "type": "malware", "id": mid, **_common(first, last), "name": fam,
                    "is_family": True, "malware_types": FAMILY_TYPES.get(fam, ["unknown"]),
                    "description": f"IoT malware family identified by HoneyBot-IoT YARA rule set ({fam}).",
                })
            if ind:
                objects.append({
                    "type": "relationship", "id": _sid("relationship", f"{ind}>{mid}"),
                    **_common(first, last), "relationship_type": "indicates",
                    "source_ref": ind, "target_ref": mid,
                })

    # de-duplicate by id (the same relationship can be produced twice)
    seen, uniq = set(), []
    for o in objects:
        if o["id"] not in seen:
            seen.add(o["id"])
            uniq.append(o)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": uniq}


def bundle_json(hours=24 * 7):
    return json.dumps(build_bundle(hours), indent=2)
