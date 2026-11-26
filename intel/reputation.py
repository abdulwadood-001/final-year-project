"""
HoneyBot-IoT — external IP reputation enrichment (scope M4).

Queries the GreyNoise Community API for each attacker IP and caches the verdict on
the `attackers` row: whether the IP is known internet background noise (mass
scanners), a known-benign common service (RIOT), its classification
(malicious / benign / unknown) and any actor/tag name.

This is the one component that reaches an external feed. It is strictly optional
and fail-safe (scope LI-7, LI-11):
  * no GREYNOISE_API_KEY  → reputation_source = 'disabled', nothing sent out;
  * host unreachable / error → reputation_source = 'unavailable', retried later;
  * a successful lookup is cached for REPUTATION_TTL_DAYS so the honeynet makes at
    most one request per IP per window.

Private / lab IPs are never sent to the feed.
"""

import os
import json
import logging
import ipaddress
import urllib.request
from datetime import datetime, timezone

from common.db import fetchall, execute

log = logging.getLogger("reputation")

API_KEY = os.environ.get("GREYNOISE_API_KEY", "").strip()
API_URL = "https://api.greynoise.io/v3/community/{ip}"
TTL_DAYS = int(os.environ.get("REPUTATION_TTL_DAYS", 7))
BATCH = int(os.environ.get("REPUTATION_BATCH", 25))
_disabled_logged = False


def _is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup(ip):
    """Return a reputation dict for one IP. Never raises."""
    if not API_KEY:
        return {"reputation_source": "disabled"}
    if not _is_public(ip):
        return {"reputation_source": "disabled", "reputation": "benign",
                "reputation_name": "private/lab address"}
    req = urllib.request.Request(API_URL.format(ip=ip), headers={"key": API_KEY,
                                 "Accept": "application/json", "User-Agent": "HoneyBot-IoT"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:                       # GreyNoise has never seen this IP
            return {"reputation_source": "greynoise", "reputation": "unknown",
                    "reputation_noise": False, "reputation_riot": False}
        return {"reputation_source": "unavailable"}
    except Exception as e:
        log.debug("greynoise lookup %s failed: %s", ip, e)
        return {"reputation_source": "unavailable"}
    return {
        "reputation_source": "greynoise",
        "reputation": d.get("classification") or "unknown",
        "reputation_name": d.get("name") or None,
        "reputation_noise": bool(d.get("noise")),
        "reputation_riot": bool(d.get("riot")),
    }


def enrich_pending(limit=BATCH):
    """Look up attackers that have never been checked or whose cache has expired.
    Returns the number of IPs updated."""
    global _disabled_logged
    if not API_KEY:
        if not _disabled_logged:
            log.info("GREYNOISE_API_KEY not set — IP reputation enrichment disabled")
            _disabled_logged = True
        # still mark rows so the dashboard shows 'disabled' rather than a blank
        execute("""UPDATE attackers SET reputation_source='disabled'
                   WHERE reputation_source IS NULL""")
        return 0
    rows = fetchall(f"""
        SELECT ip FROM attackers
        WHERE reputation_checked_at IS NULL
           OR reputation_checked_at < NOW() - INTERVAL '{TTL_DAYS} days'
        ORDER BY last_seen DESC NULLS LAST LIMIT {int(limit)}
    """)
    n = 0
    now = datetime.now(timezone.utc)
    for (ip,) in rows:
        rep = lookup(ip)
        execute("""UPDATE attackers SET reputation=%s, reputation_name=%s, reputation_noise=%s,
                       reputation_riot=%s, reputation_source=%s, reputation_checked_at=%s
                   WHERE ip=%s""",
                (rep.get("reputation"), rep.get("reputation_name"), rep.get("reputation_noise"),
                 rep.get("reputation_riot"), rep.get("reputation_source"),
                 now if rep.get("reputation_source") != "unavailable" else None, ip))
        if rep.get("reputation_source") == "greynoise":
            n += 1
    if n:
        log.info("reputation-enriched %d IP(s) via GreyNoise", n)
    return n
