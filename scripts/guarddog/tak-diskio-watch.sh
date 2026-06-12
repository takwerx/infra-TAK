#!/bin/bash
# Guard Dog Disk I/O Performance Monitor
# Runs a lightweight dd benchmark every 15 minutes, logs results to CSV,
# detects sustained degradation, and sends an email alert.
#
# Log: /var/lib/takguard/diskio_history.csv  (timestamp,mb_per_sec)
# Alert: fires when the last-hour average drops below WARN_MBPS or
#        falls to less than 30% of the 24-hour rolling average.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
HISTORY="/var/lib/takguard/diskio_history.csv"
LAT_HISTORY="/var/lib/takguard/diskio_latency.csv"
ALERT_SENT_FILE="/var/lib/takguard/diskio_alert_sent"
WARN_MBPS=50
TEST_SIZE_MB=10
RETENTION_HOURS=744
# v0.9.54: small-block (4 KB) sync-write latency probe. Postgres commits are small
# and synchronous, so they live in the 4 KB-latency regime — NOT the 1 MB sequential
# throughput regime the benchmark above measures (a throttled disk can read 80 MB/s
# sequentially while a 4 KB fsync takes 16 ms). WARN_MS_PER_COMMIT is a FLEET CONSTANT
# (field-validated: test8 ≈16 ms trips, test6 ≈1 ms stays quiet) — never per-box,
# never operator-typed, never max(cur,target). Healthy ≈ 1–3 ms.
WARN_MS_PER_COMMIT=10
LAT_OPS=256

mkdir -p /var/lib/takguard

# ── 1. Run benchmark (10 MB sync write — takes <1s on healthy disk) ──
RAW=$(dd if=/dev/zero of=/tmp/.gd_diskio_test bs=1M count=$TEST_SIZE_MB oflag=dsync 2>&1)
rm -f /tmp/.gd_diskio_test

SPEED=$(echo "$RAW" | grep -oP '[\d.]+ [KMGT]?B/s' | tail -1)
if [ -z "$SPEED" ]; then
  logger -t takguard-diskio "Benchmark failed — dd returned no speed"
  exit 0
fi

# Normalise to MB/s
MB_S=$(echo "$SPEED" | awk '{
  val = $1
  unit = $2
  if (unit == "kB/s" || unit == "KB/s") val = val / 1024
  else if (unit == "GB/s")              val = val * 1024
  else if (unit == "B/s")               val = val / 1048576
  printf "%.1f", val
}')

# ── 1b. Latency probe (256 × 4 KB sync writes — the small-block fsync regime) ──
# Additive to the throughput benchmark above; failure here never blocks throughput.
# ms_per_commit is derived from the normalised aggregate rate (4 KB ÷ KB/s × 1000 =
# 4000 ÷ KB/s ms), i.e. average per-commit latency over LAT_OPS — sidesteps the
# locale-sensitive "copied, X s" parse and reuses the proven speed-parse path.
LAT_KB_S=""
MS_PER_COMMIT=""
LRAW=$(dd if=/dev/zero of=/tmp/.gd_diskio_lat bs=4k count=$LAT_OPS oflag=dsync 2>&1)
rm -f /tmp/.gd_diskio_lat
LAT_SPEED=$(echo "$LRAW" | grep -oP '[\d.]+ [KMGT]?B/s' | tail -1)
if [ -n "$LAT_SPEED" ]; then
  LAT_KB_S=$(echo "$LAT_SPEED" | awk '{
    val = $1
    unit = $2
    if (unit == "MB/s")      val = val * 1024
    else if (unit == "GB/s") val = val * 1048576
    else if (unit == "B/s")  val = val / 1024
    printf "%.1f", val
  }')
  MS_PER_COMMIT=$(awk -v k="$LAT_KB_S" 'BEGIN { if (k+0 > 0) printf "%.2f", 4000 / k; else print "" }')
else
  logger -t takguard-diskio "Latency probe failed — dd returned no speed (throughput path unaffected)"
fi

TS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# ── 2. Append to history CSV ──
if [ ! -f "$HISTORY" ]; then
  echo "timestamp,mb_per_sec" > "$HISTORY"
fi
echo "$TS,$MB_S" >> "$HISTORY"

# Latency series (only when the probe produced a reading)
if [ -n "$MS_PER_COMMIT" ]; then
  if [ ! -f "$LAT_HISTORY" ]; then
    echo "timestamp,kb_per_sec,ms_per_commit" > "$LAT_HISTORY"
  fi
  echo "$TS,$LAT_KB_S,$MS_PER_COMMIT" >> "$LAT_HISTORY"
fi

# ── 3. Trim old entries (keep RETENTION_HOURS) ──
CUTOFF=$(date -u -d "-${RETENTION_HOURS} hours" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
         date -u -v-${RETENTION_HOURS}H '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")
if [ -n "$CUTOFF" ]; then
  TMPF=$(mktemp)
  head -1 "$HISTORY" > "$TMPF"
  tail -n +2 "$HISTORY" | awk -F, -v cutoff="$CUTOFF" '$1 >= cutoff' >> "$TMPF"
  mv "$TMPF" "$HISTORY"
  if [ -f "$LAT_HISTORY" ]; then
    TMPF=$(mktemp)
    head -1 "$LAT_HISTORY" > "$TMPF"
    tail -n +2 "$LAT_HISTORY" | awk -F, -v cutoff="$CUTOFF" '$1 >= cutoff' >> "$TMPF"
    mv "$TMPF" "$LAT_HISTORY"
  fi
fi

# ── 4. Compute averages ──
NOW_EPOCH=$(date -u '+%s')
HOUR_AGO=$((NOW_EPOCH - 3600))
DAY_AGO=$((NOW_EPOCH - 86400))

AVG_1H=$(tail -n +2 "$HISTORY" | awk -F, -v ha="$HOUR_AGO" '
  {
    cmd = "date -u -d \"" $1 "\" +%s 2>/dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ \"" $1 "\" +%s 2>/dev/null"
    cmd | getline ep; close(cmd)
    if (ep >= ha) { sum += $2; n++ }
  }
  END { if (n > 0) printf "%.1f", sum/n; else print "0" }')

AVG_24H=$(tail -n +2 "$HISTORY" | awk -F, -v da="$DAY_AGO" '
  {
    cmd = "date -u -d \"" $1 "\" +%s 2>/dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ \"" $1 "\" +%s 2>/dev/null"
    cmd | getline ep; close(cmd)
    if (ep >= da) { sum += $2; n++ }
  }
  END { if (n > 0) printf "%.1f", sum/n; else print "0" }')

SAMPLES_24H=$(tail -n +2 "$HISTORY" | wc -l | tr -d ' ')

# Latency 1h average (ms/commit, column 3) — only when the latency series exists
LAT_AVG_1H=""
if [ -f "$LAT_HISTORY" ]; then
  LAT_AVG_1H=$(tail -n +2 "$LAT_HISTORY" | awk -F, -v ha="$HOUR_AGO" '
    {
      cmd = "date -u -d \"" $1 "\" +%s 2>/dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ \"" $1 "\" +%s 2>/dev/null"
      cmd | getline ep; close(cmd)
      if (ep >= ha) { sum += $3; n++ }
    }
    END { if (n > 0) printf "%.2f", sum/n; else print "" }')
fi

logger -t takguard-diskio "Benchmark: ${MB_S} MB/s | 1h avg: ${AVG_1H} MB/s | 24h avg: ${AVG_24H} MB/s (${SAMPLES_24H} samples)"
if [ -n "$MS_PER_COMMIT" ]; then
  logger -t takguard-diskio "Latency: ${MS_PER_COMMIT} ms/commit (${LAT_KB_S} kB/s 4k) | 1h avg: ${LAT_AVG_1H:-n/a} ms/commit (ceiling ${WARN_MS_PER_COMMIT} ms)"
fi

# ── 5. Decide if alert is needed ──
# Need at least 4 samples (1 hour of data) before alerting
[ "$SAMPLES_24H" -lt 4 ] && exit 0

NEED_ALERT=false
ALERT_REASON=""

if [ "$(echo "$AVG_1H < $WARN_MBPS" | bc -l 2>/dev/null)" = "1" ]; then
  NEED_ALERT=true
  ALERT_REASON="Last-hour average (${AVG_1H} MB/s) is below ${WARN_MBPS} MB/s threshold"
fi

# Use scale>=2 for the division — scale=0 truncates AVG_1H/AVG_24H to 0 whenever it is <1,
# which incorrectly yields a 100% "drop" and spams alerts on normal noise (~1% swings).
if [ "$(echo "$AVG_24H > 0" | bc -l 2>/dev/null)" = "1" ]; then
  DROP_PCT=$(echo "scale=2; (1 - $AVG_1H / $AVG_24H) * 100" | bc -l 2>/dev/null || echo "0")
  if [ "$(echo "$DROP_PCT >= 70" | bc -l 2>/dev/null)" = "1" ]; then
    NEED_ALERT=true
    ALERT_REASON="${ALERT_REASON:+$ALERT_REASON\n}Last-hour average dropped ${DROP_PCT}% from 24h average (${AVG_24H} MB/s → ${AVG_1H} MB/s)"
  fi
fi

# Latency-ceiling gate — the signal the throughput gates miss. A chronically-slow
# disk reads fine sequentially (passing both gates above) while small-block fsync
# latency — where Postgres commits live — climbs into the seconds. Fleet constant.
if [ -n "$LAT_AVG_1H" ] && [ "$(echo "$LAT_AVG_1H > $WARN_MS_PER_COMMIT" | bc -l 2>/dev/null)" = "1" ]; then
  NEED_ALERT=true
  ALERT_REASON="${ALERT_REASON:+$ALERT_REASON\n}Disk commit latency (${LAT_AVG_1H} ms/commit 1h avg) exceeds ${WARN_MS_PER_COMMIT} ms ceiling — small-block fsync stall (Postgres commits affected)"
fi

# ── 6. Send alert (max once per 6 hours) ──
# Skip email/SMS only when /opt/tak-guarddog/diskio_email_off exists (set from Guard Dog UI).
# Benchmark + CSV + syslog above still run.
if $NEED_ALERT; then
  if [ -f /opt/tak-guarddog/diskio_email_off ]; then
    logger -t takguard-diskio "Alert condition met — email/SMS disabled for disk I/O (UI); not sending."
  elif [ ! -f "$ALERT_SENT_FILE" ] || [ "$(find "$ALERT_SENT_FILE" -mmin +360 2>/dev/null)" ]; then
    touch "$ALERT_SENT_FILE"

    RECENT=$(tail -n 8 "$HISTORY" | tail -n +1)
    SUBJ="⚠ Disk I/O Degradation on $SERVER_IDENTIFIER"
    BODY="Guard Dog detected degraded disk I/O performance.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

$(echo -e "$ALERT_REASON")

Throughput (1 MB sequential):
  Current reading:   ${MB_S} MB/s
  Last-hour average: ${AVG_1H} MB/s
  24-hour average:   ${AVG_24H} MB/s
Commit latency (4 KB sync — where Postgres lives):
  Current reading:   ${MS_PER_COMMIT:-n/a} ms/commit
  Last-hour average: ${LAT_AVG_1H:-n/a} ms/commit (ceiling ${WARN_MS_PER_COMMIT} ms)
Samples (24h):     ${SAMPLES_24H}

Recent readings:
$RECENT

This usually indicates noisy-neighbor disk contention on shared VPS
hosting. If sustained, consider requesting a node migration from your
VPS provider.

— Guard Dog"

    [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
    if [ -f /opt/tak-guarddog/sms_send.sh ]; then
      TMPF="/tmp/gd-sms-$$.txt"
      printf '%s' "$BODY" > "$TMPF"
      /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
      rm -f "$TMPF"
    fi
  fi
else
  rm -f "$ALERT_SENT_FILE"
fi

exit 0
