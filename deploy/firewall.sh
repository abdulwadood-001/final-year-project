#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  HoneyBot-IoT — outbound isolation (scope M7: "honeypot containers can receive
#  attacker connections but cannot initiate any outbound connections")
#
#  Every packet that a honeypot ORIGINATES from the honeynet subnet is dropped,
#  except replies to inbound attacker connections and traffic to the stack's own
#  internal subnets. A "compromised" honeypot therefore cannot reach the
#  internet or your LAN: it cannot attack anyone, fetch the malware it was told
#  to download, or join a botnet. (DNS from the honeynet is dropped as well;
#  container names like `db` resolve through Docker's embedded resolver.)
#
#  v0.7: runs automatically as the `firewall` service of docker-compose.yml
#  (network_mode: host, CAP_NET_ADMIN) and re-checks the rules every 30 s, so
#  isolation is ON by default and survives Docker restarts. The honeypots only
#  start after its healthcheck (`check`) passes.
#
#  Manual use on the Docker host:
#      sudo deploy/firewall.sh apply | check | status | flush
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

HONEYNET="${HONEYNET_SUBNET:-172.31.66.0/24}"
INTERNAL="${HONEYBOT_INTERNAL_SUBNETS:-${HONEYNET_SUBNET:-172.31.66.0/24} ${BACKNET_SUBNET:-172.31.67.0/24}}"
CHAIN="DOCKER-USER"
TAG="honeybot-isolation"

log() { echo "[firewall] $*"; }

# Docker may program either the nft or the legacy iptables backend; use the one
# that actually holds the DOCKER-USER chain, otherwise our rules are invisible.
pick_iptables() {
    local b
    for b in iptables iptables-nft iptables-legacy; do
        if command -v "$b" >/dev/null 2>&1 && "$b" -w -n -L "$CHAIN" >/dev/null 2>&1; then
            echo "$b"; return 0
        fi
    done
    return 1
}

need_ipt() {
    IPT="$(pick_iptables)" || { log "ERROR: chain $CHAIN not found (is Docker running with iptables enabled? rootless Docker is not supported)"; exit 2; }
}

expected_rules() {
    # ESTABLISHED + one per internal subnet + LOG + DROP
    local n=3
    for _ in $INTERNAL; do n=$((n + 1)); done
    echo "$n"
}

present_rules() {
    "$IPT" -w -S "$CHAIN" 2>/dev/null | grep -c -- "$TAG" || true
}

flush_rules() {
    local r rules
    # `|| true`: no tagged rules yet is normal (grep exits 1, which pipefail/set -e would abort on)
    rules="$("$IPT" -w -S "$CHAIN" | grep -- "$TAG" || true)"
    [ -z "$rules" ] && return 0
    while read -r r; do
        eval "$IPT -w ${r/#-A /-D }"
    done <<< "$rules"
}

apply_rules() {
    flush_rules
    local pos=1 net
    "$IPT" -w -I "$CHAIN" $pos -s "$HONEYNET" -m conntrack --ctstate ESTABLISHED,RELATED \
        -m comment --comment "$TAG: replies to inbound attackers" -j RETURN
    for net in $INTERNAL; do
        pos=$((pos + 1))
        "$IPT" -w -I "$CHAIN" $pos -s "$HONEYNET" -d "$net" \
            -m comment --comment "$TAG: internal $net" -j RETURN
    done
    pos=$((pos + 1))
    "$IPT" -w -I "$CHAIN" $pos -s "$HONEYNET" -m conntrack --ctstate NEW -m limit --limit 20/min \
        -m comment --comment "$TAG: log" -j LOG --log-prefix "HONEYBOT-OUTBOUND-DROP " --log-level 4
    pos=$((pos + 1))
    "$IPT" -w -I "$CHAIN" $pos -s "$HONEYNET" \
        -m comment --comment "$TAG: drop everything else" -j DROP
    log "outbound isolation applied for $HONEYNET via $IPT (internal: $INTERNAL)"
}

case "${1:-apply}" in
    apply)
        need_ipt; apply_rules ;;
    ensure)      # re-apply only if rules went missing (Docker restart, manual flush …)
        need_ipt
        if [ "$(present_rules)" -ne "$(expected_rules)" ]; then apply_rules; fi ;;
    check)       # healthcheck: 0 = isolation active (or explicitly disabled by the operator)
        if [ "${HONEYBOT_FIREWALL:-on}" = "off" ]; then
            log "WARNING: HONEYBOT_FIREWALL=off – honeypots are NOT isolated"; exit 0
        fi
        need_ipt
        [ "$(present_rules)" -eq "$(expected_rules)" ] ;;
    loop)        # container entrypoint
        if [ "${HONEYBOT_FIREWALL:-on}" = "off" ]; then
            log "WARNING: HONEYBOT_FIREWALL=off – outbound isolation disabled by configuration"
            exec sleep infinity
        fi
        need_ipt; apply_rules
        # rules are deliberately LEFT IN PLACE on shutdown: isolation fails closed
        while true; do sleep 30; "$0" ensure; done ;;
    status)
        need_ipt; "$IPT" -w -L "$CHAIN" -n -v --line-numbers ;;
    flush)
        need_ipt; flush_rules; log "rules removed – honeypots can reach the network again" ;;
    *)
        echo "usage: $0 {apply|ensure|check|loop|status|flush}"; exit 1 ;;
esac
