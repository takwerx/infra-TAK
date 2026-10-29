#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# Runs ON a test box as root and prints ONE JSON object of facts about it (ops #285).
# Read-only: it changes nothing. box.sh facts sends it over ssh:
#     ssh azureuser@IP 'sudo bash -s' < collect-facts.sh
# histories.py judge reads what it prints. The last 400 KB of the upgrade log are included.
# shellcheck disable=SC2155  # a failed read must give an empty value here, not stop the script
set -u
STATE=/var/lib/infratak-os-upgrade
LOG=/var/log/infratak-os-upgrade.log
PROV=/var/lib/infratak-histories/provenance.log

. /etc/os-release 2>/dev/null
export OS_RELEASE="${VERSION_ID:-}"
export BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
export STATUS="$(cat "$STATE/status" 2>/dev/null)"
export CLUSTERS="$(pg_lsclusters --no-header 2>/dev/null)"
export PROVENANCE="$(cat "$PROV" 2>/dev/null)"
export PKG_HASH="$(dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort | sha256sum | cut -d' ' -f1)"
export APT_CONF_LEFT=0
[ -e /etc/apt/apt.conf.d/99infratak-os-upgrade ] || [ -e /etc/update-manager/release-upgrades.d/infratak.cfg ] && APT_CONF_LEFT=1
export DOCKER_PS="$(docker ps -a --format '{{.Names}}|{{.State}}|{{.Status}}' 2>/dev/null)"
export UNITS="$(systemctl is-active takserver takwerx-console takwerx-broker docker 2>/dev/null | tr '\n' ' ')"
INSTALL_DIR="$(systemctl show -p WorkingDirectory --value takwerx-console 2>/dev/null)"
[ -n "$INSTALL_DIR" ] && [ -d "$INSTALL_DIR" ] || INSTALL_DIR=/opt/infra-TAK
export INFRATAK_VERSION="$(cat "$INSTALL_DIR/VERSION" 2>/dev/null)"
export INFRATAK_SHA="$(git -c safe.directory='*' -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null)"
export BASELINE_JSON="$(cat "$STATE/baseline.json" 2>/dev/null)"
# The log goes through a file, not the environment: one environment string over 128 KB makes exec fail
# with "Argument list too long" (the first real 24.04 box, ops #285).
export LOG_COPY="$(mktemp)"; trap 'rm -f "$LOG_COPY"' EXIT
tail -c 400000 "$LOG" > "$LOG_COPY" 2>/dev/null

python3 -I - <<'PY'
import json, os

e = os.environ
clusters = [l.split()[:4] for l in e.get('CLUSTERS', '').splitlines() if len(l.split()) >= 4]
units = dict(zip(['takserver', 'takwerx-console', 'takwerx-broker', 'docker'], e.get('UNITS', '').split()))
running, unhealthy = [], []
for line in e.get('DOCKER_PS', '').splitlines():
    name, state, status = (line.split('|') + ['', '', ''])[:3]
    if state == 'running':
        running.append(name)
    if state in ('restarting', 'dead') or 'unhealthy' in status:
        unhealthy.append(name)
try:
    base = json.loads(e.get('BASELINE_JSON') or '{}')
except ValueError:
    base = {}
facts = {
    'os_release': e.get('OS_RELEASE', ''),
    'boot_id': e.get('BOOT_ID', ''),
    'status': e.get('STATUS', ''),
    'clusters': clusters,
    'services': units,
    'containers': {'running': running, 'unhealthy': unhealthy},
    'baseline_services': base.get('services') or {},
    'baseline_containers': base.get('containers') or [],
    'apt_conf_left': e.get('APT_CONF_LEFT') == '1',
    'pkg_hash': e.get('PKG_HASH', ''),
    'provenance': [l for l in e.get('PROVENANCE', '').splitlines() if l.strip()],
    'infratak_version': e.get('INFRATAK_VERSION', '').strip(),
    'infratak_sha': e.get('INFRATAK_SHA', '').strip(),
    'log': open(e['LOG_COPY'], encoding='utf-8', errors='replace').read(),
}
print(json.dumps(facts))
PY
