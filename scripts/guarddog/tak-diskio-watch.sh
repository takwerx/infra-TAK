#!/bin/bash
# Guard Dog Disk I/O Performance Monitor
# Runs a lightweight dd benchmark every 15 minutes, logs results to CSV,
# detects sustained degradation, and sends an email alert.
#
# Log: /var/lib/takguard/diskio_history.csv  (timestamp,mb_per_sec)
# Alert: fires on a problem a user would notice or that puts data at risk:
#        - 4 KB commit latency above WARN_MS_PER_COMMIT on EVERY reading of the
#          last 3 hours (sustained), or above SEVERE_MS_PER_COMMIT on each of the
#          last 3 readings (a real stall, alerts within the hour) — ops #429;
#        - or throughput below WARN_MBPS / under 30% of the 24-hour average —
#          over the last hour if latency is degraded or unknown; but with commit
#          latency measured and healthy, only a COLLAPSE counts: EVERY reading of
#          the last 3 hours under TP_COLLAPSE_MBPS (ops #229, ops #429 round 2).
#        At most one email per box per 7 days (per 24 h for a stall), plus one
#        "recovered" email when an alert that was sent clears.

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
# ops #229: the 10 MB dsync throughput benchmark dips below WARN_MBPS for an hour
# whenever the box does its own heavy I/O (a CloudTAK --no-cache build, a console
# deploy, a startup retention DELETE) while commits stay fast. With commit latency
# healthy, throughput alone alerts only when EVERY one of the last SUSTAIN_SAMPLES
# readings (3 h at the 15-min timer) is below the floor, all taken in the last
# SUSTAIN_MAX_AGE_S — a disk that is actually throttled, not a busy hour. Fleet
# constants, replayed against a month of test6/test8/test12/nuc history.
SUSTAIN_SAMPLES=12
SUSTAIN_MAX_AGE_S=14400
# ops #429: a 1-hour latency average just over WARN_MS_PER_COMMIT (10.2 to 13.5 ms)
# is not a problem anyone notices: test6 sent 7 emails in 2.5 days and garesponder
# 1, all with single probes swinging between 2 and 46 ms and nothing down. Latency
# now counts as degraded only when it is (a) over the ceiling on EVERY one of the
# last LAT_SUSTAIN_SAMPLES readings, all taken in the last SUSTAIN_MAX_AGE_S, or
# (b) over SEVERE_MS_PER_COMMIT on each of the last SEVERE_SAMPLES readings, all
# in the last SEVERE_MAX_AGE_S (3 readings at the 15-min timer = a real stall,
# flagged inside the hour). Fleet constants. One email per ALERT_EVERY_MIN, and
# a "recovered" email follows an alert that was sent (DEGRADED_FILE).
LAT_SUSTAIN_SAMPLES=12
SEVERE_MS_PER_COMMIT=30
SEVERE_SAMPLES=3
SEVERE_MAX_AGE_S=4500
ALERT_EVERY_MIN=1440
# ops #429 round 2: test6's normal 10 MB dsync throughput is 40 to 50 MB/s (median
# 44.6 over Oct 28 to Nov 3), so a 50 MB/s floor sat inside normal and a busy 3 h
# (all 12 readings 8 to 46 MB/s, commits 5 to 34 ms) still sent the email. While
# commit latency is measured and healthy, throughput alone alerts only on a collapse
# (every reading of the last 3 h under TP_COLLAPSE_MBPS), the way a throttled disk
# looks. WARN_MBPS still applies to the 1-hour average when latency is degraded or
# unmeasured. Anything short of a stall repeats at most weekly; a stall daily.
TP_COLLAPSE_MBPS=25
ALERT_REPEAT_MIN=10080
DEGRADED_FILE="/var/lib/takguard/diskio_degraded"

mkdir -p /var/lib/takguard

# ── 1. Run benchmark (10 MB sync write — takes <1s on healthy disk) ──
# ops #633: a fresh mktemp file each run, not a fixed /tmp name.
_DIO_F="$(mktemp /tmp/.gd_diskio.XXXXXX)"
RAW=$(dd if=/dev/zero of="$_DIO_F" bs=1M count=$TEST_SIZE_MB oflag=dsync 2>&1)
rm -f "$_DIO_F"

# GNU dd prints rates under 1 MB/s as "kB/s" (lowercase k) — the class must include it.
SPEED=$(echo "$RAW" | grep -oP '[\d.]+ [kKMGT]?B/s' | tail -1)
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
_DIO_F="$(mktemp /tmp/.gd_diskio.XXXXXX)"
LRAW=$(dd if=/dev/zero of="$_DIO_F" bs=4k count=$LAT_OPS oflag=dsync 2>&1)
rm -f "$_DIO_F"
# ops #229: this used to be [KMGT], so every probe slower than ~3.9 ms/commit (under
# 1 MB/s, which dd prints as "kB/s") was dropped as "probe failed". The series kept
# only the fast readings and the WARN_MS_PER_COMMIT gate below could never trip.
LAT_SPEED=$(echo "$LRAW" | grep -oP '[\d.]+ [kKMGT]?B/s' | tail -1)
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
# One pass over each CSV. Every timestamp is written above as fixed-format UTC
# ISO-8601 (date -u '+%Y-%m-%dT%H:%M:%SZ'), which sorts as text, so the 1 h and 24 h
# windows are plain string compares against two cutoffs, the way the trim step and
# the sustain checks below already work. This used to start a `date` process for every
# row, three times a run: about 3 minutes on a 31-day history (ops #467).
NOW_EPOCH=$(date -u '+%s')
iso_ago() {
  date -u -d "@$((NOW_EPOCH - $1))" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
    date -u -r "$((NOW_EPOCH - $1))" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo ""
}
HOUR_AGO_ISO=$(iso_ago 3600)
DAY_AGO_ISO=$(iso_ago 86400)

# 1 h average, 24 h average and the row count of the throughput history ("0" = no rows in the window).
read -r AVG_1H AVG_24H SAMPLES_24H <<<"$(awk -F, -v ha="$HOUR_AGO_ISO" -v da="$DAY_AGO_ISO" '
  NR > 1 {
    rows++
    if (ha != "" && $1 >= ha) { s1 += $2; n1++ }
    if (da != "" && $1 >= da) { s24 += $2; n24++ }
  }
  END {
    printf "%s %s %d\n", (n1 > 0 ? sprintf("%.1f", s1 / n1) : "0"), (n24 > 0 ? sprintf("%.1f", s24 / n24) : "0"), rows
  }' "$HISTORY")"

# Latency 1h average (ms/commit, column 3) — only when the latency series exists
LAT_AVG_1H=""
if [ -f "$LAT_HISTORY" ]; then
  LAT_AVG_1H=$(awk -F, -v ha="$HOUR_AGO_ISO" '
    NR > 1 && ha != "" && $1 >= ha { sum += $3; n++ }
    END { if (n > 0) printf "%.2f", sum / n; else print "" }' "$LAT_HISTORY")
fi

# Best (highest) of the last SUSTAIN_SAMPLES readings, or empty unless there are
# that many and all are recent (a box that was off must not mix in stale readings).
# ISO-8601 UTC sorts as text, as in the trim step above.
SUSTAIN_CUTOFF=$(date -u -d "@$((NOW_EPOCH - SUSTAIN_MAX_AGE_S))" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
                 date -u -r "$((NOW_EPOCH - SUSTAIN_MAX_AGE_S))" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")
MAX_SUSTAIN=$(tail -n +2 "$HISTORY" | tail -n "$SUSTAIN_SAMPLES" | awk -F, -v c="$SUSTAIN_CUTOFF" -v want="$SUSTAIN_SAMPLES" '
  c != "" && $1 >= c { if (n == 0 || $2 + 0 > m) m = $2 + 0; n++ }
  END { if (n == want) printf "%.1f", m; else print "" }')

# Lowest of the last N latency readings, or empty unless there are N and all are
# newer than the cutoff. Lowest > threshold means every reading is over it.
lat_lowest() {
  [ -f "$LAT_HISTORY" ] || return 0
  tail -n +2 "$LAT_HISTORY" | tail -n "$1" | awk -F, -v c="$2" -v want="$1" '
    c != "" && $1 >= c { if (n == 0 || $3 + 0 < m) m = $3 + 0; n++ }
    END { if (n == want) printf "%.2f", m }'
}
LAT_LOWEST_SUSTAIN=$(lat_lowest "$LAT_SUSTAIN_SAMPLES" "$SUSTAIN_CUTOFF")
LAT_LOWEST_SEVERE=$(lat_lowest "$SEVERE_SAMPLES" "$(iso_ago "$SEVERE_MAX_AGE_S")")

logger -t takguard-diskio "Benchmark: ${MB_S} MB/s | 1h avg: ${AVG_1H} MB/s | 24h avg: ${AVG_24H} MB/s (${SAMPLES_24H} samples)"
if [ -n "$MS_PER_COMMIT" ]; then
  logger -t takguard-diskio "Latency: ${MS_PER_COMMIT} ms/commit (${LAT_KB_S} kB/s 4k) | 1h avg: ${LAT_AVG_1H:-n/a} ms/commit (ceiling ${WARN_MS_PER_COMMIT} ms)"
fi

# ── 5. Decide if alert is needed ──
# Need at least 4 samples (1 hour of data) before alerting
[ "$SAMPLES_24H" -lt 4 ] && exit 0

NEED_ALERT=false
ALERT_REASON=""
ALERT_STALL=false

# Latency gate — the signal the throughput gates miss. A chronically-slow
# disk reads fine sequentially while small-block fsync latency — where Postgres
# commits live — climbs into the seconds. Fleet constants; sustained or severe only
# (ops #429), never one busy hour hovering just over the ceiling.
LAT_BAD=false
LAT_DESC=""
if [ -n "$LAT_LOWEST_SEVERE" ] && [ "$(echo "$LAT_LOWEST_SEVERE > $SEVERE_MS_PER_COMMIT" | bc -l 2>/dev/null)" = "1" ]; then
  LAT_BAD=true
  ALERT_STALL=true
  LAT_DESC="Disk commit latency is stalling: each of the last ${SEVERE_SAMPLES} readings is over ${SEVERE_MS_PER_COMMIT} ms/commit (lowest ${LAT_LOWEST_SEVERE} ms; 1h avg ${LAT_AVG_1H} ms) — Postgres commits affected"
elif [ -n "$LAT_LOWEST_SUSTAIN" ] && [ "$(echo "$LAT_LOWEST_SUSTAIN > $WARN_MS_PER_COMMIT" | bc -l 2>/dev/null)" = "1" ]; then
  LAT_BAD=true
  LAT_DESC="Disk commit latency has been over the ${WARN_MS_PER_COMMIT} ms ceiling on every reading for the last 3 hours (lowest ${LAT_LOWEST_SUSTAIN} ms; 1h avg ${LAT_AVG_1H} ms) — small-block fsync stall (Postgres commits affected)"
fi

# Throughput gates. With commit latency measured and healthy, a low hour is the box's
# own I/O, not the disk (ops #229): only the best of the last 3 h counts, so every
# reading must be low. Latency degraded or not measured: the last-hour average, as before.
TP_FLOOR="$WARN_MBPS"
if [ -n "$LAT_AVG_1H" ] && ! $LAT_BAD; then
  TP_VAL="$MAX_SUSTAIN"
  TP_FLOOR="$TP_COLLAPSE_MBPS"
  TP_DESC="Every reading for the last 3 hours (best ${MAX_SUSTAIN} MB/s)"
else
  TP_VAL="$AVG_1H"
  TP_DESC="Last-hour average (${AVG_1H} MB/s)"
fi

if [ -n "$TP_VAL" ]; then
  if [ "$(echo "$TP_VAL < $TP_FLOOR" | bc -l 2>/dev/null)" = "1" ]; then
    NEED_ALERT=true
    ALERT_REASON="${TP_DESC} is below ${TP_FLOOR} MB/s threshold"
  fi

  # Use scale>=2 for the division — scale=0 truncates TP_VAL/AVG_24H to 0 whenever it is <1,
  # which incorrectly yields a 100% "drop" and spams alerts on normal noise (~1% swings).
  if [ "$(echo "$AVG_24H > 0" | bc -l 2>/dev/null)" = "1" ]; then
    DROP_PCT=$(echo "scale=2; (1 - $TP_VAL / $AVG_24H) * 100" | bc -l 2>/dev/null || echo "0")
    if [ "$(echo "$DROP_PCT >= 70" | bc -l 2>/dev/null)" = "1" ]; then
      NEED_ALERT=true
      ALERT_REASON="${ALERT_REASON:+$ALERT_REASON\n}${TP_DESC} is ${DROP_PCT}% below the 24h average (${AVG_24H} MB/s)"
    fi
  fi
fi

if $LAT_BAD; then
  NEED_ALERT=true
  ALERT_REASON="${ALERT_REASON:+$ALERT_REASON\n}${LAT_DESC}"
fi

# ── 6. Send alert (once a week, once a day for a stall, then a "recovered" email) ──
# Skip email/SMS only when /opt/tak-guarddog/diskio_email_off exists (set from Guard Dog UI).
# Benchmark + CSV + syslog above still run.
if $NEED_ALERT; then
  REPEAT_MIN="$ALERT_REPEAT_MIN"
  $ALERT_STALL && REPEAT_MIN="$ALERT_EVERY_MIN"
  if [ -f /opt/tak-guarddog/diskio_email_off ]; then
    logger -t takguard-diskio "Alert condition met — email/SMS disabled for disk I/O (UI); not sending."
  elif [ ! -f "$ALERT_SENT_FILE" ] || [ "$(find "$ALERT_SENT_FILE" -mmin +"$REPEAT_MIN" 2>/dev/null)" ]; then
    touch "$ALERT_SENT_FILE" "$DEGRADED_FILE"

    RECENT=$(tail -n 8 "$HISTORY" | tail -n +1)
    SUBJ="⚠ Disk I/O Degradation on $SERVER_IDENTIFIER"
    BODY="Guard Dog detected degraded disk I/O performance.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

$(echo -e "$ALERT_REASON")

Throughput (1 MB sequential):
  Current reading:   ${MB_S} MB/s
  Last-hour average: ${AVG_1H} MB/s
  Last 3 h (best):   ${MAX_SUSTAIN:-n/a} MB/s
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

    echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
    if [ -f /opt/tak-guarddog/sms_send.sh ]; then
      TMPF="$(mktemp /tmp/gd-sms.XXXXXX)"
      printf '%s' "$BODY" > "$TMPF"
      /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
      rm -f "$TMPF"
    fi
  fi
fi

# ── 7. Recovered (ops #429): one short email after an alert that was actually sent ──
# DEGRADED_FILE exists only after an alert email went out. It is cleared the first
# run the alert condition is gone and the 1-hour latency average is back under the
# ceiling (or not measured), so a flapping disk can't produce "recovered" mails
# without a matching alert. Honors diskio_email_off like the alert does.
if ! $NEED_ALERT && [ -f "$DEGRADED_FILE" ]; then
  LAT_OK=true
  if [ -n "$LAT_AVG_1H" ] && [ "$(echo "$LAT_AVG_1H > $WARN_MS_PER_COMMIT" | bc -l 2>/dev/null)" = "1" ]; then
    LAT_OK=false
  fi
  if $LAT_OK; then
    rm -f "$DEGRADED_FILE"
    if [ ! -f /opt/tak-guarddog/diskio_email_off ]; then
      SUBJ="✅ Disk I/O recovered on $SERVER_IDENTIFIER"
      BODY="Guard Dog: disk I/O is back to normal.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

Throughput (1 MB sequential): ${MB_S} MB/s now, ${AVG_1H} MB/s last-hour average
Commit latency (4 KB sync): ${MS_PER_COMMIT:-n/a} ms/commit now, ${LAT_AVG_1H:-n/a} ms/commit last-hour average (ceiling ${WARN_MS_PER_COMMIT} ms)

No action needed.

— Guard Dog"
      echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
    fi
  fi
fi

# NOTE: there is deliberately NO `else rm -f "$ALERT_SENT_FILE"` here.
# Clearing the sentinel on a single good reading defeats the 6h debounce entirely:
# this timer fires every 15 minutes, so a disk that flaps degraded -> OK -> degraded
# alerted on EVERY degraded reading. Field evidence (Charles Laird/NC, 2026-09-12):
# three alerts for one server in 6h31m against a documented 6h floor.
# That is worst precisely when the alert matters most -- noisy-neighbor VPS
# contention, the condition this check exists to detect, is intermittent by nature.
# The `-mmin +ALERT_EVERY_MIN` age gate above is the whole debounce: the sentinel is
# touched only when an alert is actually sent, so a sustained problem re-alerts
# every 7 days, or every 24h while it is a stall (was 6h until ops #429), and a
# genuinely new incident alerts at most that long later. Do not "fix" this by resetting on recovery. (v10.1.70 W2)

exit 0
