#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# One cell of the box-history matrix, start to verdict (ops #285):
# restore the cell's snapshot -> facts before -> drive the console -> facts after -> judge -> delete the run box.
#
#   run-scenario.sh CELL [--candidate SHA] [--keep] [--out DIR]
#
# Needs: az logged in to the takwerx subscription, INFRATAK_CONSOLE_PASSWORD_FILE (mode 600, the
# console password of the history boxes: it is the same on every box built by the replay, and it is
# never printed), and CLIENT_CHECK_CMD: a command that gets the box IP as $1, exits 0 when the client
# check passes and whose last output line ends in "anon=N (named=X ...)" like takdev-client-check.
# With no CLIENT_CHECK_CMD the client check counts as NOT RUN, and the cell fails: a run that never
# asked the clients is not a pass.
#
# Runs in the foreground and finishes before it returns. The run box is deleted on exit (or kept
# with --keep); if this script is killed, the box still stops itself at the auto-shutdown time and
# expires on its tag. The longest wait is the OS upgrade itself (about 40 minutes).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
H=(python3 -I "$HERE/histories.py")
D=(python3 -I "$HERE/drive.py" --insecure --wait-ready 900)   # restored test boxes are addressed by IP and are self-signed
B=(bash "$HERE/box.sh")

CELL="${1:?CELL (histories.py list)}"; shift || true
CANDIDATE=""; KEEP=0; OUT="${PWD}/histories-out"
while [ $# -gt 0 ]; do
  case "$1" in
    --candidate) CANDIDATE="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ -n "${INFRATAK_CONSOLE_PASSWORD_FILE:-}" ] || { echo "set INFRATAK_CONSOLE_PASSWORD_FILE" >&2; exit 2; }

mkdir -p "$OUT"
J() { python3 -I -c 'import json,sys; d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k]
print(json.dumps(d) if isinstance(d,(dict,list)) else d)' "$1"; }
CELLJSON="$("${H[@]}" cell "$CELL")"
SNAP="$(J snapshot <<<"$CELLJSON")"; RUNKIND="$(J run <<<"$CELLJSON")"; RESULT="$(J expect.result <<<"$CELLJSON")"
read -r -a BOXES <<<"$(python3 -I -c 'import json,sys; print(" ".join(json.load(sys.stdin)["boxes"]))' <<<"$CELLJSON")"
STAMP="$(date -u +%m%d%H%M)"
SHORT="$(tr -c 'a-z0-9' '-' <<<"${CELL%%-*}${CELL#*:}" | cut -c1-12 | sed 's/-*$//')"
name_of() { echo "r${STAMP}-${SHORT}-$1"; }
PREFIX="$OUT/${CELL//:/_}-$STAMP"

cleanup() {
  if [ "$KEEP" = 1 ]; then echo "kept the run boxes of $CELL (they stop themselves at the auto-shutdown time); delete with box.sh delete NAME" >&2; return; fi
  local b; for b in "${BOXES[@]}"; do "${B[@]}" delete "$(name_of "$b")" || echo "COULD NOT DELETE $(name_of "$b"): delete it by hand" >&2; done
}
trap cleanup EXIT

# 1. restore. The first box uses SNAP, a second box (database server) uses SNAP-db.
for b in "${BOXES[@]}"; do
  s="$SNAP"; [ "$b" != "${BOXES[0]}" ] && s="$SNAP-$b"
  "${B[@]}" restore "$s" "$(name_of "$b")" --role "$b"
done
IP="$("${B[@]}" ip "$(name_of "${BOXES[0]}")")"
"${B[@]}" open-ports "$(name_of "${BOXES[0]}")" "5001,443,8089,8443,8446"
URL="https://$IP:5001"

# 1b. the snapshots hold released history (v10.2.x, before the OS upgrade existed): put the candidate on the box the way
# a customer does, Update Now, on CANDIDATE_CHANNEL (main = the latest release, dev = the integration branch)
[ "$RUNKIND" = os-upgrade ] && "${D[@]}" "$URL" update-now --channel "${CANDIDATE_CHANNEL:-main}" --wait > "$PREFIX-update.json"

collect() { "${B[@]}" facts "$(name_of "$1")"; }
# 2. facts before. An os-upgrade cell takes them after the operator's preparation (below): Install updates and Reboot
# change packages and the boot id, and that is not the console's doing.
facts_before() { local b; for b in "${BOXES[@]}"; do collect "$b" > "$PREFIX-$b-before.json"; done; }
[ "$RUNKIND" = os-upgrade ] || facts_before

# 3. drive
echo '{}' > "$PREFIX-preflight.json"; echo '{}' > "$PREFIX-start.json"; FINAL=''
case "$RUNKIND" in
  os-upgrade)
    # a snapshot gets older every day: do what the operator does first, Install updates and Reboot, until only a real refusal is left
    "${D[@]}" "$URL" prepare > /dev/null
    # what the cell's history says is true on the box, and a reboot undoes (a cluster started by hand does not come back by itself)
    while IFS= read -r c; do [ -n "$c" ] && "${B[@]}" ssh "$(name_of "${BOXES[0]}")" "$c"; done < <(python3 -I -c 'import json,sys; print("\n".join(json.load(sys.stdin).get("post_prepare") or []))' <<<"$CELLJSON")
    facts_before
    "${D[@]}" "$URL" preflight > "$PREFIX-preflight.json"
    "${D[@]}" "$URL" start > "$PREFIX-start.json"
    if [ "$RESULT" = refused ]; then
      sleep 20      # give a wrongly accepted Start time to show itself in the status
    else
      if [ "$(J http_status < "$PREFIX-start.json")" = 200 ]; then
        "${D[@]}" "$URL" wait-status --timeout 7200 > "$PREFIX-status.json" || true
      else
        echo "Start was refused (the cell fails, nothing to wait for): $(head -c 300 "$PREFIX-start.json")" >&2
        echo '{}' > "$PREFIX-status.json"
      fi
      FINAL="$(J raw < "$PREFIX-status.json" 2>/dev/null || true)"
      if [ "$(J expect.also_upgrade_db_box <<<"$CELLJSON" 2>/dev/null || echo False)" = True ]; then
        "${D[@]}" "$URL" --target dbserver start > "$PREFIX-db-start.json" || true
        "${D[@]}" "$URL" --target dbserver wait-status --timeout 5400 > "$PREFIX-db-status.json" || true
      fi
    fi ;;
  update-now-then-wait)
    "${D[@]}" "$URL" update-now --channel "${CANDIDATE_CHANNEL:-main}" > "$PREFIX-update.json" || true
    # the console restarts onto the candidate and the heal finishes the upgrade by itself; no reboot is asked of the operator
    "${D[@]}" "$URL" wait-status --timeout 1800 --ignore-failed-for 1200 > "$PREFIX-status.json" || true
    FINAL="$(J raw < "$PREFIX-status.json" 2>/dev/null || true)" ;;
  *) echo "unknown run kind $RUNKIND" >&2; exit 2 ;;
esac

# 4. facts after (the box may still be coming up after its reboot)
for b in "${BOXES[@]}"; do
  for _ in 1 2 3 4 5 6; do collect "$b" > "$PREFIX-$b-after.json" 2>/dev/null && break; sleep 20; done
done

# 5. client check
echo '{"passed": false, "reason": "CLIENT_CHECK_CMD not set: not run"}' > "$PREFIX-client.json"
if [ -n "${CLIENT_CHECK_CMD:-}" ]; then
  if out="$($CLIENT_CHECK_CMD "$IP" 2>&1)"; then ok=true; else ok=false; fi
  anon="$(sed -n 's/.*anon=[0-9]* (named=\([0-9]*\).*/\1/p' <<<"$out" | tail -1)"
  python3 -I -c 'import json,sys; print(json.dumps({"passed": sys.argv[1]=="true", "anon_named": int(sys.argv[2] or 0), "output": sys.argv[3][-400:]}))' \
    "$ok" "${anon:-0}" "$out" > "$PREFIX-client.json"
fi

# 6. judge
"${H[@]}" assemble --prefix "$PREFIX" --boxes "$(IFS=,; echo "${BOXES[*]}")" --final "$FINAL" --candidate "$CANDIDATE" > "$PREFIX-input.json"
"${H[@]}" judge "$CELL" "$PREFIX-input.json" --stage end > "$PREFIX-result.json" && rc=0 || rc=$?
echo "result: $PREFIX-result.json (exit $rc)" >&2
exit "$rc"
