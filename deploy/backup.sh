#!/bin/sh
# Nightly pg_dump at $BACKUP_AT (local time), keeping $BACKUP_KEEP_DAYS days.
# Restore: docker compose exec -T db pg_restore -U netsec -d netsec --clean < backups/<file>.dump
set -eu

dump() {
  f="/backups/netsec-$(date +%Y%m%d-%H%M).dump"
  pg_dump --format=custom --file="$f.partial" && mv "$f.partial" "$f"
  echo "$(date) backup written: $f ($(du -h "$f" | cut -f1))"
  find /backups -name 'netsec-*.dump' -mtime +"$BACKUP_KEEP_DAYS" -delete
}

dump  # one at startup, so a fresh deploy is never unprotected
while true; do
  now=$(date +%s)
  target=$(date -d "$(date +%Y-%m-%d) $BACKUP_AT" +%s 2>/dev/null || date -D '%Y-%m-%d %H:%M' -d "$(date +%Y-%m-%d) $BACKUP_AT" +%s)
  [ "$target" -le "$now" ] && target=$((target + 86400))
  sleep $((target - now))
  dump || echo "$(date) BACKUP FAILED" >&2
done
