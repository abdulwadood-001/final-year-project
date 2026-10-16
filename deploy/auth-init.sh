#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════
#  HoneyBot-IoT — dashboard login (runs once before Nginx starts)
#
#  v0.6 shipped nginx/.htpasswd (an MD5-apr1 hash) inside the project archive.
#  v0.7 never stores a credential in the repository: the bcrypt hash is generated
#  here into the `nginx_auth` volume.
#    DASHBOARD_PASSWORD set in .env  → (re)written on every start
#    not set, hash already exists     → kept
#    not set, first start             → a random password is generated and
#                                       printed once:  docker compose logs auth-init
# ═══════════════════════════════════════════════════════════════════════════
set -eu
F=/auth/.htpasswd
U="${DASHBOARD_USER:-admin}"

if [ -n "${DASHBOARD_PASSWORD:-}" ]; then
    htpasswd -bcB -C 12 "$F" "$U" "$DASHBOARD_PASSWORD" >/dev/null 2>&1
    echo "[auth-init] dashboard login for user '$U' set from DASHBOARD_PASSWORD"
elif [ -s "$F" ]; then
    echo "[auth-init] keeping existing dashboard credentials"
else
    P="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
    htpasswd -bcB -C 12 "$F" "$U" "$P" >/dev/null 2>&1
    echo "[auth-init] ================================================================"
    echo "[auth-init]  generated dashboard login:   user: $U    password: $P"
    echo "[auth-init]  (set DASHBOARD_PASSWORD in .env to choose your own)"
    echo "[auth-init] ================================================================"
fi
chmod 644 "$F"
