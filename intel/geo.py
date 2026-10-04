"""
HoneyBot-IoT — IP geolocation (scope M4).

Order of lookup:
  1. MaxMind GeoLite2-City or DB-IP City Lite .mmdb file (offline, no API calls)
     path: GEOIP_DB (default /app/geoip/GeoLite2-City.mmdb, then dbip-city-lite.mmdb)
     download with deploy/get_geoip.sh
  2. private / lab addresses (Docker 172.x, 10.x, 192.168.x):
       GEO_DEMO_MODE=true  → deterministic demo location, clearly marked
                             geo_source='demo' so the report never mixes it with real data
       otherwise           → geo_source='private', no coordinates
"""

import os
import hashlib
import ipaddress
import logging

log = logging.getLogger("geo")

CANDIDATES = [os.environ.get("GEOIP_DB", "/app/geoip/GeoLite2-City.mmdb"),
              "/app/geoip/dbip-city-lite.mmdb", "/app/geoip/GeoLite2-City.mmdb"]
DEMO = os.environ.get("GEO_DEMO_MODE", "true").lower() == "true"

# Plausible attack-origin cities used ONLY for lab traffic in demo mode
DEMO_CITIES = [
    ("China", "CN", "Shanghai", 31.23, 121.47), ("Russia", "RU", "Moscow", 55.75, 37.62),
    ("United States", "US", "Ashburn", 39.04, -77.49), ("Brazil", "BR", "Sao Paulo", -23.55, -46.63),
    ("India", "IN", "Mumbai", 19.08, 72.88), ("Vietnam", "VN", "Hanoi", 21.03, 105.85),
    ("Netherlands", "NL", "Amsterdam", 52.37, 4.90), ("Iran", "IR", "Tehran", 35.69, 51.39),
    ("Germany", "DE", "Frankfurt", 50.11, 8.68), ("Korea", "KR", "Seoul", 37.57, 126.98),
    ("Indonesia", "ID", "Jakarta", -6.21, 106.85), ("Turkey", "TR", "Istanbul", 41.01, 28.98),
    ("Ukraine", "UA", "Kyiv", 50.45, 30.52), ("Singapore", "SG", "Singapore", 1.35, 103.82),
    ("Egypt", "EG", "Cairo", 30.04, 31.24), ("Pakistan", "PK", "Karachi", 24.86, 67.01),
]

_reader = None
_reader_tried = False


def _get_reader():
    global _reader, _reader_tried
    if _reader_tried:
        return _reader
    _reader_tried = True
    try:
        import geoip2.database
        for path in CANDIDATES:
            if path and os.path.exists(path):
                _reader = geoip2.database.Reader(path)
                log.info("GeoIP database loaded: %s", path)
                break
        else:
            log.warning("No GeoIP .mmdb found – run deploy/get_geoip.sh (public IPs stay unlocated)")
    except Exception as e:
        log.warning("GeoIP unavailable: %s", e)
    return _reader


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return True


def lookup(ip):
    """Return dict(country, country_code, city, lat, lon, geo_source)."""
    empty = dict(country=None, country_code=None, city=None, lat=None, lon=None)
    if is_private(ip):
        if DEMO:
            c = DEMO_CITIES[int(hashlib.sha1(ip.encode(), usedforsecurity=False).hexdigest(), 16) % len(DEMO_CITIES)]
            return dict(country=c[0], country_code=c[1], city=c[2], lat=c[3], lon=c[4], geo_source="demo")
        return {**empty, "geo_source": "private"}
    r = _get_reader()
    if r is None:
        return {**empty, "geo_source": "unknown"}
    try:
        res = r.city(ip)
        return dict(country=res.country.name, country_code=res.country.iso_code,
                    city=res.city.name, lat=res.location.latitude, lon=res.location.longitude,
                    geo_source="maxmind" if "GeoLite2" in (r.metadata().database_type or "") else "dbip")
    except Exception:
        return {**empty, "geo_source": "unknown"}
