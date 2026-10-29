#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# Replays ONE step of a box history ON the lane VM, as root, the way a customer does it: through the
# README Quick Start and the console's own API calls (ops #285). Run by box.sh/ssh, one step per call:
#
#   replay.sh image
#   replay.sh infratak-install REF            README Quick Start at a released tag (git clone -b REF + ./start.sh)
#   replay.sh takserver-deploy VERSION        upload the package + Deploy on the TAK Server page (5.7 | 5.8)
#   replay.sh os-upgrade-released REF         pinned console update, then START the OS upgrade (the caller waits from outside)
#   replay.sh console-update REF              the git steps of 'Update Now', pinned to REF (see below)
#   replay.sh takserver-58-migrate            upload the 5.8 package, the guided 5.8 update (PG 15 -> 18)
#   replay.sh takserver-update VERSION        upload a newer package for a box already on 5.8, press Update (e.g. 5.8-RELEASE92)
#   replay.sh start-old-cluster 15/main      pg_ctlcluster 15 main start (the way an operator might)
#   replay.sh module-deploy MODULE            authentik | broker | docker-modules | docker-tak
#
# Files expected in /tmp/h (copied up by the operator, never in the repo): pass (console password,
# mode 600), drive-start.py, the tak.gov packages named in PKG_* below. The password is read from
# the file and never printed. Each finished step appends its label to the provenance log.
#
# 'console-update' note: the console's Update Now always jumps to the NEWEST release, so a history
# that needs "updated to v10.2.30" cannot be replayed by clicking it today. This runs the same git
# steps (fetch the tag, force checkout, restart the service) pinned to REF.
set -uo pipefail

H=/tmp/h; OUT=$H/out; mkdir -p "$OUT"
CK=$H/cookies; API=https://127.0.0.1:5001
PROV=/var/lib/infratak-histories/provenance.log
PKG_57="${PKG_57:-takserver_5.7-RELEASE43_all.deb}"
PKG_58="${PKG_58:-takserver_5.8-RELEASE84_all.deb}"
POL_57="${POL_57:-deb_policy_5.7.pol}"
POL_58="${POL_58:-deb_policy_5.8.pol}"
KEY="${KEY:-takserver-public-gpg.key}"

step() { echo "== $(date -u +%H:%M:%S) $*" | tee -a "$OUT/steps.log"; }
fail() { step "FAIL: $*"; exit 1; }
note() { mkdir -p "$(dirname "$PROV")"; echo "$1" >> "$PROV"; }
curlc() { curl -sk --max-time 60 -b "$CK" -c "$CK" -H "Origin: $API" "$@"; }
login() {
    python3 -I -c 'import sys,urllib.parse; print("password="+urllib.parse.quote(open(sys.argv[1]).read().strip()), end="")' "$H/pass" \
        | curlc -o /dev/null -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- "$API/login"
}
wait_console() {
    local ok=0 _
    for _ in $(seq 1 60); do
        [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$API/login")" = 200 ] && { ok=1; break; }
        sleep 5
    done
    [ $ok -eq 1 ] || fail "console not answering on :5001"
    rm -f "$CK"; login
    [ "$(curlc -o /dev/null -w '%{http_code}' "$API/console")" = 200 ] || fail "console login failed"
}

# poll LOGPATH INDEXPARAM OUTFILE MAXSEC -> complete | error | stopped | running
poll() {
    local path="$1" param="$2" file="$3" max="$4" after=0 state=running j prev deadline
    deadline=$(( $(date +%s) + max )); : > "$file"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        j=$(curlc "$API$path?$param=$after")
        if ! printf '%s' "$j" | python3 -I -c 'import sys,json; json.load(sys.stdin)' 2>/dev/null; then
            login; sleep 10; continue
        fi
        prev=$after
        read -r after state < <(printf '%s' "$j" | python3 -I -c '
import sys, json
d = json.load(sys.stdin)
with open(sys.argv[1], "a") as f:
    for e in d["entries"]:
        f.write((e if isinstance(e, str) else json.dumps(e)) + "\n")
print(d["total"], "error" if d.get("error") else "complete" if d.get("complete") else "running" if d.get("running") else "stopped")' "$file")
        [ -n "$after" ] || { after=$prev; state=running; }
        [ "$state" = running ] || break
        sleep 10
    done
    echo "$state"
}

upload() {  # upload FILE...
    local args=() f
    for f in "$@"; do args+=(-F "files=@$H/$f"); done
    curlc --max-time 1800 "${args[@]}" "$API/api/upload/takserver" > "$OUT/upload.json"
    grep -q '"packages": *\[ *{' "$OUT/upload.json" || fail "upload rejected: $(head -c 300 "$OUT/upload.json")"
}

tak_answers() {  # wait until TAK Server answers its API with the admin cert
    local _
    for _ in $(seq 1 90); do
        [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --cert /opt/tak/certs/files/admin.pem \
             --key /opt/tak/certs/files/admin.key --pass atakatak https://127.0.0.1:8443/Marti/api/version)" = 200 ] && return 0
        sleep 10
    done
    return 1
}

case "${1:-}" in
image)
    step "waiting for cloud-init"
    timeout 600 cloud-init status --wait >/dev/null 2>&1 || true
    note image ;;

infratak-install)
    REF="${2:?REF}"
    step "README Quick Start at $REF"
    cd /root || fail "cd /root"
    rm -rf infra-TAK
    git clone --depth 1 -b "$REF" https://github.com/takwerx/infra-TAK.git > "$OUT/clone.log" 2>&1 || fail "git clone -b $REF"
    cd infra-TAK || fail "no clone"
    python3 "$H/drive-start.py" "$(cat "$H/pass")" 1800 > "$OUT/start.sh.log" 2>&1 || fail "start.sh exit $?"
    wait_console
    note "infratak-install:$REF" ;;

console-update|os-upgrade-released)
    REF="${2:?REF}"
    step "console update to $REF (pinned)"
    D="$(systemctl show -p WorkingDirectory --value takwerx-console 2>/dev/null)"; [ -n "$D" ] || D=/opt/infratak
    U="$(stat -c %U "$D/.git")"
    sudo -u "$U" git -C "$D" fetch --depth 1 origin "+refs/tags/$REF:refs/tags/$REF" > "$OUT/update.log" 2>&1 || fail "fetch $REF"
    sudo -u "$U" git -C "$D" checkout --force "refs/tags/$REF" >> "$OUT/update.log" 2>&1 || fail "checkout $REF"
    systemctl restart takwerx-console || fail "restart console"
    wait_console
    if [ "$1" = os-upgrade-released ]; then
        # Start the console's OS upgrade with that RELEASED code. The box reboots part-way, which would kill
        # this script, so it only STARTS the job; the operator waits for the expected status from outside
        # (drive.py wait-status) and then records the step with box.sh note-step NAME os-upgrade-released:REF.
        step "start the OS upgrade with $REF's code"
        curlc --max-time 300 -H 'Content-Type: application/json' -X POST "$API/api/console/os-upgrade/start" \
            -d "$(python3 -I -c 'import json,sys; print(json.dumps({"admin_password": open(sys.argv[1]).read().strip(), "acknowledge": "I have a snapshot", "stack_backup": False}))' "$H/pass")" > "$OUT/os-upgrade-start.json"
        grep -q '"success": *true\|"started": *true\|"ok": *true' "$OUT/os-upgrade-start.json" || fail "OS upgrade did not start: $(head -c 300 "$OUT/os-upgrade-start.json")"
    else
        note "console-update:$REF"
    fi ;;

takserver-deploy)
    VER="${2:?VERSION 5.7|5.8}"
    case "$VER" in 5.7) PKG="$PKG_57"; POL="$POL_57" ;; 5.8) PKG="$PKG_58"; POL="$POL_58" ;; *) fail "version $VER" ;; esac
    step "upload TAK Server $VER + key + policy"
    login; upload "$PKG" "$KEY" "$POL"
    step "deploy TAK Server $VER"
    curlc -H 'Content-Type: application/json' -X POST "$API/api/deploy/takserver" -d '{
      "cert_country":"US","cert_state":"CA","cert_city":"SACRAMENTO","cert_org":"TAKWERX","cert_ou":"HIST",
      "root_ca_name":"ROOT-CA-01","intermediate_ca_name":"INTERMEDIATE-CA-01",
      "intermediate_ca_validity_days":730,"issued_cert_validity_days":"",
      "enable_admin_ui":false,"enable_webtak":false,"webadmin_password":"","deployment_mode":"single_server"}' > "$OUT/deploy-start.json"
    grep -q '"success": *true' "$OUT/deploy-start.json" || fail "deploy refused: $(head -c 300 "$OUT/deploy-start.json")"
    st=$(poll /api/deploy/log after "$OUT/deploy-$VER.log" 3600)
    [ "$st" = complete ] || fail "TAK $VER deploy ended: $st"
    tak_answers || fail "TAK Server $VER never answered"
    pg_lsclusters > "$OUT/clusters-after-$VER.txt" 2>&1
    note "takserver-deploy:$VER" ;;

takserver-58-migrate)
    step "upload TAK Server 5.8 package"
    login; upload "$PKG_58"
    curlc "$API/api/takserver/58-preflight" > "$OUT/58-preflight.json"
    step "guided TAK Server 5.8 update"
    curlc -H 'Content-Type: application/json' -X POST "$API/api/takserver/58-migrate" \
        -d "$(python3 -I -c 'import json,sys; print(json.dumps({"password": open(sys.argv[1]).read().strip()}))' "$H/pass")" > "$OUT/58-start.json"
    grep -q '"success": *true' "$OUT/58-start.json" || fail "5.8 update refused: $(head -c 300 "$OUT/58-start.json")"
    st=$(poll /api/takserver/58-migrate/log index "$OUT/58-migrate.log" 5400)
    [ "$st" = complete ] || fail "5.8 update ended: $st"
    tak_answers || fail "TAK Server 5.8 never answered"
    pg_lsclusters > "$OUT/clusters-after-58.txt" 2>&1
    note "takserver-58-migrate:5.8" ;;

takserver-update)
    VER="${2:?VERSION e.g. 5.8-RELEASE92}"
    wait_console
    step "upload the TAK Server $VER package"
    upload "takserver_${VER}_all.deb"
    step "TAK Server update (the console's Update button, newest upload)"
    curlc -X POST "$API/api/takserver/update" > "$OUT/takserver-update-start.json"
    grep -q '"success": *true' "$OUT/takserver-update-start.json" || fail "update refused: $(head -c 300 "$OUT/takserver-update-start.json")"
    st=$(poll /api/takserver/update/log index "$OUT/takserver-update.log" 3600)
    [ "$st" = complete ] || fail "TAK Server update ended: $st"
    tak_answers || fail "TAK Server $VER never answered"
    pg_lsclusters > "$OUT/clusters-after-update.txt" 2>&1
    note "takserver-update:$VER" ;;

start-old-cluster)
    C="${2:-15/main}"; CV="${C%%/*}"; CN="${C#*/}"; [ "$CN" != "$C" ] || CN=main
    step "start PostgreSQL $CV $CN again"
    pg_ctlcluster "$CV" "$CN" start || fail "pg_ctlcluster $CV $CN start"
    pg_lsclusters > "$OUT/clusters-after-start-old.txt" 2>&1
    note "start-old-cluster:$CV/$CN" ;;

module-deploy)
    MOD="${2:?MODULE}"
    login
    case "$MOD" in
    authentik) EP=/api/authentik/deploy; LOG=/api/authentik/deploy/log; P=index ;;
    nodered|docker-modules) MOD=docker-modules; EP=/api/nodered/deploy; LOG=/api/nodered/deploy/log; P=index ;;   # a Docker module (Node-RED)
    broker)   # the privileged broker is installed by start.sh itself; there is nothing to deploy, only to confirm it is the history
        systemctl is-active --quiet takwerx-broker || fail "takwerx-broker is not running"
        note "module-deploy:broker"; step "done: $*"; exit 0 ;;
    *) fail "module $MOD: not automated yet" ;;
    esac
    step "deploy module $MOD"
    curlc -H 'Content-Type: application/json' -X POST "$API$EP" -d '{}' > "$OUT/module-$MOD-start.json"
    grep -q '"success": *true' "$OUT/module-$MOD-start.json" || fail "$MOD deploy refused: $(head -c 300 "$OUT/module-$MOD-start.json")"
    st=$(poll "$LOG" "$P" "$OUT/module-$MOD.log" 3600)
    [ "$st" = complete ] || fail "$MOD deploy ended: $st"
    note "module-deploy:$MOD" ;;

*) echo "usage: replay.sh image|infratak-install REF|console-update REF|takserver-deploy VER|takserver-58-migrate|takserver-update VER|start-old-cluster C|module-deploy MOD" >&2; exit 2 ;;
esac
step "done: $*"
