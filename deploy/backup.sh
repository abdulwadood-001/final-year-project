#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════
#  HoneyBot-IoT — backup & recovery (scope M7: "automated scheduled backups of the
#  PostgreSQL log database and PCAP/sample archive with SHA256 integrity
#  verification and clean-image restore capability")
#
#  Runs as the `backup` service (postgres:16-alpine image, so pg_dump matches the
#  server). Every BACKUP_INTERVAL_HOURS it writes to ./backups on the host:
#      honeybot-db-<stamp>.dump         pg_dump custom format
#      honeybot-samples-<stamp>.tar.gz  quarantined malware samples
#      honeybot-<stamp>.sha256          checksums of both
#  and keeps the newest BACKUP_KEEP sets.
#
#  Commands (docker compose run --rm backup <cmd>):
#      once                     take one backup now
#      verify [stamp]           check SHA-256 of a set (default: newest)
#      restore <stamp>          verify, then restore DB (+ samples) — clean restore
#      list                     show available backup sets
# ═══════════════════════════════════════════════════════════════════════════
set -eu
DIR=/backups
SAMPLES=/app/captures
KEEP="${BACKUP_KEEP:-7}"
INTERVAL_H="${BACKUP_INTERVAL_HOURS:-24}"
export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD not set}"
DBARGS="-h ${PGHOST:-db} -U ${POSTGRES_USER:-honeybot} -d ${POSTGRES_DB:-honeybot}"

log() { echo "[backup] $(date -u +%FT%TZ) $*"; }

latest() { ls -1 "$DIR"/honeybot-*.sha256 2>/dev/null | sed 's/.*honeybot-\(.*\)\.sha256/\1/' | sort | tail -1; }

take() {
    mkdir -p "$DIR"
    stamp="$(date -u +%Y%m%d-%H%M%S)"
    db="honeybot-db-$stamp.dump"; tar="honeybot-samples-$stamp.tar.gz"
    # shellcheck disable=SC2086
    pg_dump $DBARGS -Fc -f "$DIR/$db.part" && mv "$DIR/$db.part" "$DIR/$db"
    if [ -d "$SAMPLES" ]; then
        tar -czf "$DIR/$tar.part" -C "$SAMPLES" . && mv "$DIR/$tar.part" "$DIR/$tar"
    else
        tar -czf "$DIR/$tar" -T /dev/null
    fi
    (cd "$DIR" && sha256sum "$db" "$tar" > "honeybot-$stamp.sha256")
    log "backup $stamp written ($(du -h "$DIR/$db" | cut -f1) db, $(du -h "$DIR/$tar" | cut -f1) samples)"
    # retention: keep the newest $KEEP sets
    ls -1 "$DIR"/honeybot-*.sha256 | sort -r | tail -n "+$((KEEP + 1))" | while read -r old; do
        s="$(echo "$old" | sed 's/.*honeybot-\(.*\)\.sha256/\1/')"
        rm -f "$DIR/honeybot-db-$s.dump" "$DIR/honeybot-samples-$s.tar.gz" "$old"
        log "pruned old backup $s"
    done
}

verify() {
    s="${1:-$(latest)}"
    [ -n "$s" ] || { log "no backups found"; exit 1; }
    (cd "$DIR" && sha256sum -c "honeybot-$s.sha256") && log "backup $s integrity OK"
}

restore() {
    s="${1:?usage: restore <stamp>  (see: list)}"
    verify "$s"
    log "restoring database from $s (existing objects are dropped first)"
    # shellcheck disable=SC2086
    pg_restore $DBARGS --clean --if-exists --no-owner "$DIR/honeybot-db-$s.dump"
    if [ -w "$SAMPLES" ]; then
        tar -xzf "$DIR/honeybot-samples-$s.tar.gz" -C "$SAMPLES" && log "samples restored"
    else
        log "sample volume is read-only here – samples not restored (mount it rw to restore them)"
    fi
    log "restore of $s complete"
}

case "${1:-loop}" in
    loop)
        log "scheduled backups every ${INTERVAL_H}h, keeping $KEEP"
        sleep 60                                    # let the database settle after start-up
        while true; do take || log "backup FAILED"; sleep "$((INTERVAL_H * 3600))"; done ;;
    once)    take ;;
    verify)  verify "${2:-}" ;;
    restore) restore "${2:-}" ;;
    list)    ls -1 "$DIR"/honeybot-*.sha256 2>/dev/null | sed 's/.*honeybot-\(.*\)\.sha256/\1/' | sort ;;
    *) echo "usage: $0 {loop|once|verify [stamp]|restore <stamp>|list}"; exit 1 ;;
esac
