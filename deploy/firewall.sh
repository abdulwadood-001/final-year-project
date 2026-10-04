#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  HoneyBot-IoT — outbound isolation (scope: inbound-only honeypot)
#
#  Drops every NEW outbound connection started from the honeynet subnet, so a
#  "compromised" honeypot can accept attacker traffic but can NEVER reach the
#  internet or your LAN — it cannot be used to attack anyone else, fetch the
#  malware it was told to download, or join a botnet.
#
#  Established/related replies to inbound attacker connections are allowed, as
#  is DNS and traffic to the internal backnet (DB / Redis / API).
#
#  Run on the Docker host AFTER `docker compose up`:
#      sudo deploy/firewall.sh            # apply
#      sudo deploy/firewall.sh status     # show the rules
#      sudo deploy/firewall.sh flush      # remove the rules
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

SUBNET="${HONEYNET_SUBNET:-172.31.66.0/24}"
CHAIN="DOCKER-USER"

need_root() { [ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }; }

apply() {
    need_root
    flush_quiet
    # allow replies to already-established inbound attacker sessions
    iptables -I "$CHAIN" 1 -s "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    # allow traffic between containers on the Docker bridges (backnet etc.)
    iptables -I "$CHAIN" 2 -s "$SUBNET" -d 172.16.0.0/12 -j RETURN
    # allow DNS so name resolution inside the container still works
    iptables -I "$CHAIN" 3 -s "$SUBNET" -p udp --dport 53 -j RETURN
    iptables -I "$CHAIN" 4 -s "$SUBNET" -p tcp --dport 53 -j RETURN
    # log + DROP every other NEW connection the honeypots try to OPEN
    iptables -I "$CHAIN" 5 -s "$SUBNET" -m conntrack --ctstate NEW \
             -j LOG --log-prefix "HONEYBOT-OUTBOUND-DROP " --log-level 4
    iptables -I "$CHAIN" 6 -s "$SUBNET" -m conntrack --ctstate NEW -j DROP
    echo "[+] Outbound isolation applied for $SUBNET"
    echo "    Verify:  docker exec honeybot_ssh python -c \"import urllib.request;urllib.request.urlopen('http://example.com',timeout=5)\"  → should hang/fail"
}

flush_quiet() { iptables-save | grep -q "HONEYBOT-OUTBOUND-DROP" && \
    iptables -S "$CHAIN" | grep "$SUBNET" | sed 's/^-A/-D/' | while read -r r; do iptables $r; done || true; }

case "${1:-apply}" in
    apply)  apply ;;
    flush)  need_root; flush_quiet; echo "[+] Rules removed" ;;
    status) iptables -L "$CHAIN" -n -v --line-numbers | grep -E "HONEYBOT|$SUBNET|Chain" || echo "no HoneyBot rules" ;;
    *) echo "usage: $0 {apply|flush|status}"; exit 1 ;;
esac
