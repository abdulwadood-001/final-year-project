#!/usr/bin/env bash
# Download an offline GeoIP city database into ./geoip/
#
#   MaxMind GeoLite2 (free, needs a licence key):
#       MAXMIND_LICENSE_KEY=xxxx deploy/get_geoip.sh
#   DB-IP City Lite (free, no key, CC-BY-4.0) — default fallback:
#       deploy/get_geoip.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p geoip

if [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
    echo "[*] Downloading MaxMind GeoLite2-City…"
    url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
    curl -sSL "$url" -o /tmp/geo.tgz
    tar -xzf /tmp/geo.tgz -C /tmp
    find /tmp -name GeoLite2-City.mmdb -exec cp {} geoip/GeoLite2-City.mmdb \;
    echo "[+] geoip/GeoLite2-City.mmdb ready"
else
    month=$(date +%Y-%m)
    echo "[*] Downloading DB-IP City Lite ($month)…"
    curl -sSL "https://download.db-ip.com/free/dbip-city-lite-${month}.mmdb.gz" -o /tmp/dbip.mmdb.gz
    gunzip -f /tmp/dbip.mmdb.gz
    cp /tmp/dbip.mmdb geoip/dbip-city-lite.mmdb
    echo "[+] geoip/dbip-city-lite.mmdb ready"
fi
echo "[*] Restart the api + intel containers to load it:  docker compose restart api intel"
