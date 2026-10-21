"""
HoneyBot-IoT — cross-session correlation, GeoIP enrichment and IOC extraction (scope M4).

* attackers  : one row per source IP, aggregated across ALL sessions, protocols and devices
* campaigns  : IPs whose credential lists overlap strongly (Jaccard >= 0.6, >= 5 pairs)
               are grouped – the same wordlist/botnet working from several addresses
* threat score 0-100 per IP from its detections, logins and downloads
* iocs       : URLs, domains, IPs and SHA-256 hashes extracted from events
"""

import re
import hashlib
import logging
from urllib.parse import urlparse

from common.db import fetchall, execute
from intel import geo

log = logging.getLogger("correlate")

SEV_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def update_attackers():
    execute("""
        INSERT INTO attackers (ip, first_seen, last_seen, sessions, events, auth_attempts, auth_success,
                               commands, downloads, protocols, devices, updated_at)
        SELECT e.ip, min(e.ts), max(e.ts), COUNT(DISTINCT e.session_id), COUNT(*),
               COUNT(*) FILTER (WHERE e.event_type='auth'),
               COUNT(*) FILTER (WHERE e.event_type='auth' AND e.success),
               COUNT(*) FILTER (WHERE e.event_type='command'),
               COUNT(*) FILTER (WHERE e.event_type='download_attempt'),
               array_agg(DISTINCT e.protocol), array_agg(DISTINCT e.device), NOW()
        FROM events e
        WHERE e.ip IN (SELECT DISTINCT ip FROM events WHERE ts > NOW() - INTERVAL '10 minutes')
        GROUP BY e.ip
        ON CONFLICT (ip) DO UPDATE SET
            first_seen=EXCLUDED.first_seen, last_seen=EXCLUDED.last_seen, sessions=EXCLUDED.sessions,
            events=EXCLUDED.events, auth_attempts=EXCLUDED.auth_attempts,
            auth_success=EXCLUDED.auth_success, commands=EXCLUDED.commands,
            downloads=EXCLUDED.downloads, protocols=EXCLUDED.protocols, devices=EXCLUDED.devices,
            updated_at=NOW()
    """)
    # GeoIP for IPs not located yet
    for (ip,) in fetchall("SELECT ip FROM attackers WHERE geo_source IS NULL LIMIT 500"):
        g = geo.lookup(ip)
        execute("""UPDATE attackers SET country=%s, country_code=%s, city=%s, lat=%s, lon=%s, geo_source=%s
                   WHERE ip=%s""", (g["country"], g["country_code"], g["city"], g["lat"], g["lon"],
                                    g["geo_source"], ip))
    # threat score / level from detections + behaviour
    rows = fetchall("""
        SELECT a.ip, a.auth_success, a.downloads,
               COALESCE(array_agg(DISTINCT d.attack_type) FILTER (WHERE d.id IS NOT NULL), '{}'),
               COALESCE(array_agg(d.severity) FILTER (WHERE d.id IS NOT NULL), '{}')
        FROM attackers a LEFT JOIN detections d ON d.ip = a.ip
        WHERE a.updated_at > NOW() - INTERVAL '15 minutes'
        GROUP BY a.ip, a.auth_success, a.downloads
    """)
    for ip, succ, dl, types, sevs in rows:
        # worst severity + breadth of behaviour + successful logins + payload downloads
        score = max([SEV_WEIGHT.get(s, 0) for s in sevs] or [0]) + 6 * len(types)
        score += min(succ, 3) * 8 + min(dl, 3) * 10
        score = max(0, min(100, score))
        level = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 15 else "LOW"
        execute("UPDATE attackers SET threat_score=%s, threat_level=%s, attack_types=%s WHERE ip=%s",
                (score, level, list(types), ip))


def update_campaigns(min_pairs=5, threshold=0.6):
    rows = fetchall("""
        SELECT ip, array_agg(DISTINCT coalesce(username,'') || ':' || coalesce(password,''))
        FROM events WHERE event_type='auth' AND ts > NOW() - INTERVAL '7 days'
        GROUP BY ip HAVING COUNT(DISTINCT coalesce(username,'') || ':' || coalesce(password,'')) >= %s
    """, (min_pairs,))
    sets = {ip: set(c) for ip, c in rows}
    ips = sorted(sets)
    parent = {ip: ip for ip in ips}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i, a in enumerate(ips):
        for b in ips[i + 1:]:
            inter = len(sets[a] & sets[b])
            if inter and inter / len(sets[a] | sets[b]) >= threshold:
                parent[find(a)] = find(b)
    groups = {}
    for ip in ips:
        groups.setdefault(find(ip), []).append(ip)
    for members in groups.values():
        if len(members) < 2:
            continue
        common = set.intersection(*(sets[m] for m in members))
        fp = hashlib.sha1("|".join(sorted(common)).encode(), usedforsecurity=False).hexdigest()
        cid = "CMP-" + fp[:8].upper()
        execute("""
            INSERT INTO campaigns (campaign_id, fingerprint, first_seen, last_seen, ips, credentials, description)
            SELECT %s, %s, min(first_seen), max(last_seen), %s, %s, %s FROM attackers WHERE ip = ANY(%s)
            ON CONFLICT (campaign_id) DO UPDATE SET ips=EXCLUDED.ips, last_seen=EXCLUDED.last_seen,
                   credentials=EXCLUDED.credentials, description=EXCLUDED.description
        """, (cid, fp, members, sorted(common)[:50],
              f"{len(members)} IPs sharing {len(common)} identical credential pairs (same wordlist/botnet)",
              members))
        execute("UPDATE attackers SET campaign_id=%s WHERE ip = ANY(%s)", (cid, members))


def _upsert_ioc(typ, value, ip, sid, proto, context, source, source_id, seen_at=None):
    """Record one sighting of an IOC.

    `hits` counts DISTINCT sightings (one per source event / detection / capture).
    v0.6 did `hits+1` on every 30-s pass over the last 10 min of events, inflating
    the counter ~20x. The sighting row is inserted with ON CONFLICT DO NOTHING, and
    the IOC counter only grows when that insert actually created a row.
    """
    value = (value or "")[:1000]
    if not value:
        return
    execute("""
        WITH s AS (
            INSERT INTO ioc_sightings (source, source_id, type, value, seen_at)
            VALUES (%s, %s, %s, %s, COALESCE(%s, NOW()))
            ON CONFLICT DO NOTHING
            RETURNING 1
        )
        INSERT INTO iocs (type, value, source_ip, session_id, protocol, context, first_seen, last_seen, hits)
        SELECT %s, %s, %s, %s, %s, %s, COALESCE(%s, NOW()), COALESCE(%s, NOW()), 1
        WHERE EXISTS (SELECT 1 FROM s)
        ON CONFLICT (type, value) DO UPDATE
           SET hits = iocs.hits + 1,
               last_seen = GREATEST(iocs.last_seen, EXCLUDED.last_seen),
               first_seen = LEAST(iocs.first_seen, EXCLUDED.first_seen)
    """, (source, source_id, typ, value, seen_at,
          typ, value, ip, sid, proto, context[:300] if context else None, seen_at, seen_at))


def extract_iocs():
    # events are re-scanned over a sliding window so rows committed late by a
    # honeypot writer are never missed; sightings make the re-scan idempotent
    rows = fetchall("""
        SELECT e.id, e.ts, e.ip, e.session_id, e.protocol, e.event_type, e.payload,
               e.raw->>'sha256', e.command
        FROM events e
        WHERE e.event_type IN ('download_attempt','file_write','file_upload')
          AND e.ts > NOW() - INTERVAL '30 minutes'
    """)
    for eid, ts, ip, sid, proto, et, payload, sha, cmd in rows:
        if et == "download_attempt" and payload:
            _upsert_ioc("url", payload, ip, sid, proto, cmd or "", "event", eid, ts)
            host = urlparse(payload).hostname or ""
            if host:
                _upsert_ioc("ipv4" if IP_RE.match(host) else "domain", host, ip, sid, proto,
                            f"payload host for {payload}", "event", eid, ts)
        elif sha and et in ("file_write", "file_upload"):
            _upsert_ioc("sha256", sha, ip, sid, proto, f"{et}: {(payload or '')[:80]}", "event", eid, ts)
    # every stored malware sample is an IOC (with its YARA verdict as context)
    for cid, ts, ip, sid, proto, sha, fname, verdict in fetchall("""
            SELECT id, ts, ip, session_id, protocol, sha256, filename, yara_result FROM file_captures
            WHERE ts > NOW() - INTERVAL '30 minutes'"""):
        _upsert_ioc("sha256", sha, ip, sid, proto,
                    f"captured sample {fname or ''} [{verdict or 'not scanned'}]".strip(), "capture", cid, ts)
    # attacker IPs with HIGH/CRITICAL activity become IOCs too (one sighting per detection)
    for did, ts, ip in fetchall("""SELECT id, timestamp, ip FROM detections
                                   WHERE severity IN ('HIGH','CRITICAL')
                                     AND timestamp > NOW() - INTERVAL '30 minutes'"""):
        if not geo.is_private(ip) or geo.DEMO:
            _upsert_ioc("ipv4", ip, ip, None, None, "attacker source address", "detection", did, ts)


def run():
    update_attackers()
    update_campaigns()
    extract_iocs()
