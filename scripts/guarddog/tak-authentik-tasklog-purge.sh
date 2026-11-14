#!/bin/bash
# Guard Dog: Authentik task log purge (v0.9.26 — fixed VACUUM-in-transaction).
# Removes authentik_tasks_task + authentik_tasks_tasklog rows in tiers:
#   Tier 1: rows older than 7 days (gentle, keeps weekly audit trail)
#   Tier 2: rows older than 24h (if size still ≥ 100 MB after Tier 1)
#   Tier 3: rows older than 1h  (if size still ≥ 100 MB after Tier 2)
# Each tier runs in its own `psql -c` invocation; the final VACUUM ANALYZE
# also runs in a SEPARATE psql -c so it is NOT wrapped in a transaction.
# Old v0.9.5 single-call script failed every Sunday with
#   ERROR: VACUUM cannot run inside a transaction block
# v0.9.26 fix lives both here AND inline in app.py
# (_auto_authentik_tasklog_purge); the inline helper runs on every console
# boot regardless of the timer, so even if THIS script is broken the
# console boot path keeps the tables healthy.
set -u
LOG=/var/log/takguard/authentik-tasklog-purge.log
STAMP_FILE=/opt/tak-guarddog/authentik_tasklog_purge_last.txt
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
mkdir -p /var/log/takguard
echo "[$TS] Starting Authentik task log purge (v0.9.26 multi-tier)" >> "$LOG"

if [ -z "$(docker ps -q --filter name=authentik-postgresql-1 2>/dev/null)" ]; then
  echo "[$TS] authentik-postgresql-1 not running — skipping" >> "$LOG"
  echo "$TS" > "$STAMP_FILE" 2>/dev/null || true
  exit 0
fi

size_mb() {
  docker exec authentik-postgresql-1 psql -U authentik -d authentik -t -A -c \
    "SELECT (pg_total_relation_size('authentik_tasks_tasklog') + pg_total_relation_size('authentik_tasks_task')) / 1024 / 1024" 2>/dev/null \
    | tr -dc "0-9" || echo 0
}

row_counts() {
  docker exec authentik-postgresql-1 psql -U authentik -d authentik -t -A -c \
    "SELECT (SELECT count(*) FROM authentik_tasks_task) || '/' || (SELECT count(*) FROM authentik_tasks_tasklog)" 2>/dev/null || echo "?/?"
}

delete_older_than() {
  local interval="$1"
  docker exec authentik-postgresql-1 psql -U authentik -d authentik -c "
DELETE FROM authentik_tasks_tasklog WHERE task_id IN (
  SELECT message_id FROM authentik_tasks_task WHERE mtime < NOW() - INTERVAL '$interval'
);
DELETE FROM authentik_tasks_task WHERE mtime < NOW() - INTERVAL '$interval';
" >> "$LOG" 2>&1
}

INITIAL=$(size_mb)
INITIAL=${INITIAL:-0}
INITIAL_ROWS=$(row_counts)
THRESHOLD=100
echo "[$TS] Initial size: ${INITIAL} MB (task/tasklog rows: ${INITIAL_ROWS}), threshold ${THRESHOLD} MB" >> "$LOG"

if [ "$INITIAL" -lt "$THRESHOLD" ] 2>/dev/null; then
  echo "[$TS] No cleanup needed — already healthy" >> "$LOG"
  echo "$TS" > "$STAMP_FILE" 2>/dev/null || true
  exit 0
fi

echo "[$TS] Tier 1 — DELETE rows older than 7 days" >> "$LOG"
delete_older_than "7 days" || echo "[$TS] Tier 1 returned non-zero (continuing)" >> "$LOG"
AFTER_7D=$(size_mb); AFTER_7D=${AFTER_7D:-$INITIAL}
echo "[$TS] After 7-day pass: ${AFTER_7D} MB" >> "$LOG"

if [ "$AFTER_7D" -ge "$THRESHOLD" ] 2>/dev/null; then
  echo "[$TS] Tier 2 — DELETE rows older than 24 hours" >> "$LOG"
  delete_older_than "24 hours" || echo "[$TS] Tier 2 returned non-zero (continuing)" >> "$LOG"
fi
AFTER_24H=$(size_mb); AFTER_24H=${AFTER_24H:-$AFTER_7D}
echo "[$TS] After 24h pass: ${AFTER_24H} MB" >> "$LOG"

if [ "$AFTER_24H" -ge "$THRESHOLD" ] 2>/dev/null; then
  echo "[$TS] Tier 3 (nuclear) — DELETE rows older than 1 hour" >> "$LOG"
  delete_older_than "1 hour" || echo "[$TS] Tier 3 returned non-zero (continuing)" >> "$LOG"
fi

echo "[$TS] VACUUM ANALYZE (separate invocation — NOT in transaction)" >> "$LOG"
docker exec authentik-postgresql-1 psql -U authentik -d authentik -c \
  "VACUUM ANALYZE authentik_tasks_task, authentik_tasks_tasklog;" >> "$LOG" 2>&1 || \
  echo "[$TS] VACUUM returned non-zero (table sizes still updated)" >> "$LOG"

FINAL=$(size_mb); FINAL=${FINAL:-0}
FINAL_ROWS=$(row_counts)
echo "[$TS] Final size: ${FINAL} MB (task/tasklog rows: ${FINAL_ROWS}), freed $(( INITIAL - FINAL )) MB" >> "$LOG"
echo "$TS" > "$STAMP_FILE" 2>/dev/null || true
echo "[$TS] Authentik task log purge complete" >> "$LOG"
exit 0
