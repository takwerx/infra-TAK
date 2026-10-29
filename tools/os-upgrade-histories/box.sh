#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# Lane test boxes for the box-history matrix (ops #285): build a starting state once, snapshot it,
# restore the snapshot for every run, delete the run box. A one-way upgrade then never costs the
# only box in that state (the test12 problem).
#
#   box.sh create NAME [--role core|db] [--cell CELL]   new 22.04 VM, auto-shutdown set right away
#   box.sh note-step NAME LABEL                         record a replayed history step on the box
#   box.sh facts NAME                                   JSON facts about the box (collect-facts.sh)
#   box.sh snapshot NAME SNAPSHOT [--cell CELL]         stop, snapshot the OS disk (incremental), keep NAME stopped
#   box.sh restore SNAPSHOT NAME [--role core|db]       new run box from the snapshot; the snapshot is untouched
#   box.sh open-ports NAME PORT[,PORT...]               allow these ports from THIS Mac's address only
#   box.sh put NAME FILE...                             copy files to /tmp/h on the box
#   box.sh ip NAME | ssh NAME CMD... (alias: exec) | start NAME | stop NAME
#   box.sh delete NAME                                  VM + disk + NIC + IP + NSG
#   box.sh sweep [--delete-expired]                     what is running / expired in the resource group
#
# DRY_RUN=1 prints every az command and runs nothing.
#
# Cloud VM rules (ops OPS-WORKER.md, incident Oct 26-27, 2026) built in:
#   1. auto-shutdown is set the moment the VM exists, before anything is installed. If it cannot
#      be set the VM is deleted again. Nothing here relies on a last step to turn a box off.
#   2. every resource carries owner=<claude-lane> and expires=<date> and lives in its own
#      resource group (scenarios.json: defaults.azure).
#   3. nothing runs in the background: every command here finishes before it returns.
#   4. only the subscription named in HIST_AZURE_SUBSCRIPTION is ever touched: checked before every command.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN="${DRY_RUN:-0}"
KEY="${HIST_SSH_KEY:-$HOME/.ssh/id_ed25519_infratak}"
ADMIN_USER="${HIST_ADMIN_USER:-azureuser}"

cfg() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1]))["defaults"]["azure"]; print(d[sys.argv[2]])' "$HERE/scenarios.json" "$1"; }
RG="$(cfg resource_group)"; REGION="$(cfg region)"; OWNER="$(cfg owner)"
IMAGE="$(cfg image)"; SIZE_CORE="$(cfg size_core)"; SIZE_DB="$(cfg size_db)"; DISK_GB="$(cfg os_disk_gb)"
SHUTDOWN_UTC="$(cfg auto_shutdown_utc)"; SNAP_DAYS="$(cfg snapshot_expires_days)"; RUN_DAYS="$(cfg run_expires_days)"

die() { echo "box.sh: $*" >&2; exit 1; }
# The subscription id is not kept in this (public) repo: the operator names it.
SUB="${HIST_AZURE_SUBSCRIPTION:-}"
case "${1:-help}" in help|-h|--help) ;; *) [ -n "$SUB" ] || die "set HIST_AZURE_SUBSCRIPTION to the Azure subscription id the lane boxes live in" ;; esac
say() { echo "box.sh: $*" >&2; }

# Run az, or print it. Output of a real run is passed through.
az_() {
  if [ "$DRY_RUN" = 1 ]; then echo "+ az $*"; return 0; fi
  az "$@"
}

expires_in() { python3 -I -c 'import datetime,sys; print((datetime.date.today()+datetime.timedelta(days=int(sys.argv[1]))).isoformat())' "$1"; }

guard_subscription() {
  if [ "$DRY_RUN" = 1 ]; then echo "+ az account show  (must be the HIST_AZURE_SUBSCRIPTION one)"; return 0; fi
  local have; have="$(az account show --query id -o tsv 2>/dev/null)" || die "not logged in to Azure (az login)"
  [ "$have" = "$SUB" ] || die "az is on subscription $have, not the lane one (HIST_AZURE_SUBSCRIPTION). Run: az account set --subscription <that id>"
}

source_cidr() {
  if [ -n "${HIST_SOURCE_CIDR:-}" ]; then echo "$HIST_SOURCE_CIDR"; return; fi
  if [ "$DRY_RUN" = 1 ]; then echo "203.0.113.9/32"; return; fi
  local ip; ip="$(curl -fsS --max-time 10 https://api.ipify.org)" || die "could not find this Mac's public address (set HIST_SOURCE_CIDR)"
  echo "$ip/32"
}

# One shared network for every box in the group, so a delete of one box never takes the network
# from another, and a core + database-server pair can reach each other privately.
VNET=hist-vnet
ensure_rg() {
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ az group create -n $RG -l $REGION --tags owner=$OWNER purpose=box-histories"
    echo "+ az network vnet create -g $RG -n $VNET --address-prefix 10.50.0.0/16 --subnet-name default --subnet-prefix 10.50.0.0/24"
    return 0
  fi
  if [ "$(az group exists -n "$RG")" != "true" ]; then
    az group create -n "$RG" -l "$REGION" --tags "owner=$OWNER" "purpose=box-histories" -o none
  fi
  if ! az network vnet show -g "$RG" -n "$VNET" -o none 2>/dev/null; then
    az network vnet create -g "$RG" -n "$VNET" --address-prefix 10.50.0.0/16 --subnet-name default \
      --subnet-prefix 10.50.0.0/24 --tags "owner=$OWNER" -o none
  fi
}

# Auto-shutdown (deallocate) at 06:00 UTC = 11 PM PT. Fails the whole create if it cannot be set.
set_auto_shutdown() {
  local name="$1"
  if ! az_ vm auto-shutdown -g "$RG" -n "$name" --time "$SHUTDOWN_UTC" -o none; then
    say "auto-shutdown could not be set on $name: deleting the VM again (a box with no stop is not allowed)"
    az_ vm delete -g "$RG" -n "$name" --yes -o none || true
    die "auto-shutdown failed for $name"
  fi
}

ssh_opts=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=15 -o ServerAliveInterval=30)
vm_ip() {
  if [ "$DRY_RUN" = 1 ]; then echo "198.51.100.7"; return; fi
  az vm list-ip-addresses -g "$RG" -n "$1" --query '[0].virtualMachine.network.publicIpAddresses[0].ipAddress' -o tsv
}
wait_ssh() {
  local ip="$1"
  [ "$DRY_RUN" = 1 ] && { echo "+ wait for ssh on $ip"; return 0; }
  for _ in $(seq 1 40); do
    ssh "${ssh_opts[@]}" "$ADMIN_USER@$ip" true 2>/dev/null && return 0
    sleep 6
  done
  die "ssh to $ip did not come up in 4 minutes"
}

role_size() { case "${1:-core}" in db) echo "$SIZE_DB" ;; core) echo "$SIZE_CORE" ;; *) die "--role is core or db" ;; esac; }

cmd_create() {
  local name="${1:?NAME}"; shift || true
  local role=core cell=""
  while [ $# -gt 0 ]; do case "$1" in --role) role="$2"; shift 2 ;; --cell) cell="$2"; shift 2 ;; *) die "unknown option $1" ;; esac; done
  guard_subscription; ensure_rg
  local exp; exp="$(expires_in "$RUN_DAYS")"
  [ -f "$KEY.pub" ] || [ "$DRY_RUN" = 1 ] || die "no SSH key $KEY.pub (set HIST_SSH_KEY)"
  az_ vm create -g "$RG" -n "$name" -l "$REGION" --image "$IMAGE" --size "$(role_size "$role")" \
    --os-disk-size-gb "$DISK_GB" --admin-username "$ADMIN_USER" --ssh-key-values "$KEY.pub" \
    --public-ip-sku Standard --nsg-rule NONE --vnet-name "$VNET" --subnet default \
    --tags "owner=$OWNER" "expires=$exp" "role=$role" ${cell:+"history=$cell"} -o none
  set_auto_shutdown "$name"
  allow_ports "$name" 22
  say "created $name (expires $exp, auto-shutdown $SHUTDOWN_UTC UTC)"
  wait_ssh "$(vm_ip "$name")"
}

nsg_of() { echo "${1}NSG"; }
allow_ports() {
  local name="$1" ports="$2" nsg src prio=200
  nsg="$(nsg_of "$name")"; src="$(source_cidr)"
  az_ network nsg rule create -g "$RG" --nsg-name "$nsg" -n "allow-${ports//,/-}-from-lane" \
    --priority "$((prio + RANDOM % 700))" --access Allow --direction Inbound --protocol Tcp \
    --source-address-prefixes "$src" --destination-port-ranges ${ports//,/ } -o none
}
cmd_open_ports() { guard_subscription; allow_ports "${1:?NAME}" "${2:?PORT[,PORT]}"; }

cmd_ip() { guard_subscription; vm_ip "${1:?NAME}"; }
cmd_ssh() { local name="${1:?NAME}"; shift; guard_subscription; ssh "${ssh_opts[@]}" "$ADMIN_USER@$(vm_ip "$name")" "$@"; }
# Copy local files to /tmp/h on the box (replay.sh reads its packages and the console password from there).
cmd_put() {
  local name="${1:?NAME}"; shift; [ $# -gt 0 ] || die "put NAME FILE..."; guard_subscription
  local ip; ip="$(vm_ip "$name")"
  ssh "${ssh_opts[@]}" "$ADMIN_USER@$ip" "mkdir -p /tmp/h"
  scp "${ssh_opts[@]}" "$@" "$ADMIN_USER@$ip:/tmp/h/"
}
cmd_start() { guard_subscription; az_ vm start -g "$RG" -n "${1:?NAME}" -o none; wait_ssh "$(vm_ip "$1")"; }
cmd_stop() { guard_subscription; az_ vm deallocate -g "$RG" -n "${1:?NAME}" -o none; }

cmd_facts() {
  local name="${1:?NAME}"; guard_subscription
  if [ "$DRY_RUN" = 1 ]; then echo "+ ssh $ADMIN_USER@\$IP 'sudo bash -s' < collect-facts.sh"; return 0; fi
  ssh "${ssh_opts[@]}" "$ADMIN_USER@$(vm_ip "$name")" 'sudo bash -s' < "$HERE/collect-facts.sh"
}

# One line per replayed step, appended on the box. judge --stage start compares the list with the matrix.
cmd_note_step() {
  local name="${1:?NAME}" label="${2:?LABEL}"; guard_subscription
  case "$label" in *[!A-Za-z0-9:._-]*) die "label may only use letters, digits and : . _ -" ;; esac
  if [ "$DRY_RUN" = 1 ]; then echo "+ ssh \$IP 'sudo tee -a /var/lib/infratak-histories/provenance.log' <<< $label"; return 0; fi
  ssh "${ssh_opts[@]}" "$ADMIN_USER@$(vm_ip "$name")" \
    "sudo mkdir -p /var/lib/infratak-histories && echo '$label' | sudo tee -a /var/lib/infratak-histories/provenance.log >/dev/null"
}

cmd_snapshot() {
  local name="${1:?NAME}" snap="${2:?SNAPSHOT}"; shift 2 || true
  local cell=""
  while [ $# -gt 0 ]; do case "$1" in --cell) cell="$2"; shift 2 ;; *) die "unknown option $1" ;; esac; done
  guard_subscription
  local exp; exp="$(expires_in "$SNAP_DAYS")"
  az_ vm deallocate -g "$RG" -n "$name" -o none
  local disk_id
  if [ "$DRY_RUN" = 1 ]; then disk_id="<os-disk-id-of-$name>"; echo "+ az vm show -g $RG -n $name --query storageProfile.osDisk.managedDisk.id -o tsv"
  else disk_id="$(az vm show -g "$RG" -n "$name" --query storageProfile.osDisk.managedDisk.id -o tsv)"; fi
  az_ snapshot create -g "$RG" -n "$snap" -l "$REGION" --source "$disk_id" --incremental true \
    --tags "owner=$OWNER" "expires=$exp" "source=$name" ${cell:+"history=$cell"} -o none
  say "snapshot $snap taken from $name (expires $exp). $name stays stopped; delete it with: box.sh delete $name"
}

cmd_restore() {
  local snap="${1:?SNAPSHOT}" name="${2:?NAME}"; shift 2 || true
  local role=core
  while [ $# -gt 0 ]; do case "$1" in --role) role="$2"; shift 2 ;; *) die "unknown option $1" ;; esac; done
  guard_subscription; ensure_rg
  local exp; exp="$(expires_in "$RUN_DAYS")"
  az_ disk create -g "$RG" -n "${name}-osdisk" -l "$REGION" --source "$snap" --sku Premium_LRS \
    --tags "owner=$OWNER" "expires=$exp" "restored_from=$snap" -o none
  az_ vm create -g "$RG" -n "$name" -l "$REGION" --attach-os-disk "${name}-osdisk" --os-type Linux \
    --size "$(role_size "$role")" --public-ip-sku Standard --nsg-rule NONE --vnet-name "$VNET" --subnet default \
    --tags "owner=$OWNER" "expires=$exp" "role=$role" "restored_from=$snap" -o none
  set_auto_shutdown "$name"
  allow_ports "$name" 22
  say "restored $snap as $name (expires $exp, auto-shutdown $SHUTDOWN_UTC UTC)"
  wait_ssh "$(vm_ip "$name")"
}

cmd_delete() {
  local name="${1:?NAME}"; guard_subscription
  az_ vm delete -g "$RG" -n "$name" --yes -o none || true
  az_ disk delete -g "$RG" -n "${name}-osdisk" --yes -o none 2>/dev/null || true
  if [ "$DRY_RUN" != 1 ]; then
    # the OS disk of a VM made from the image has an Azure-generated name: remove what is left under the VM's tag
    local d
    for d in $(az disk list -g "$RG" --query "[?starts_with(name, '${name}_OsDisk')].name" -o tsv); do az disk delete -g "$RG" -n "$d" --yes -o none; done
  fi
  az_ network nic delete -g "$RG" -n "${name}VMNic" -o none 2>/dev/null || true
  az_ network public-ip delete -g "$RG" -n "${name}PublicIP" -o none 2>/dev/null || true
  az_ network nsg delete -g "$RG" -n "$(nsg_of "$name")" -o none 2>/dev/null || true
  # Azure keeps the auto-shutdown schedule after the VM is gone
  az_ resource delete -g "$RG" -n "shutdown-computevm-$name" --resource-type microsoft.devtestlab/schedules -o none 2>/dev/null || true
  say "deleted $name and what hangs off it"
}

cmd_sweep() {
  local del=0; [ "${1:-}" = "--delete-expired" ] && del=1
  guard_subscription
  if [ "$DRY_RUN" = 1 ]; then echo "+ az vm list -g $RG -d ; az snapshot list -g $RG ; az disk list -g $RG"; return 0; fi
  [ "$(az group exists -n "$RG")" = "true" ] || { echo "no resource group $RG: nothing is running"; return 0; }
  local today; today="$(date -u +%F)"
  echo "== VMs in $RG (running ones cost money)"
  az vm list -g "$RG" -d --query "[].{name:name, state:powerState, size:hardwareProfile.vmSize, owner:tags.owner, expires:tags.expires}" -o table
  echo "== snapshots"
  az snapshot list -g "$RG" --query "[].{name:name, gb:diskSizeGb, owner:tags.owner, expires:tags.expires, history:tags.history}" -o table
  echo "== disks not attached to a VM"
  az disk list -g "$RG" --query "[?managedBy==null].{name:name, gb:diskSizeGb, expires:tags.expires}" -o table
  if [ "$del" = 1 ]; then
    local n
    for n in $(az vm list -g "$RG" --query "[?tags.owner=='$OWNER' && tags.expires<'$today'].name" -o tsv); do cmd_delete "$n"; done
    for n in $(az snapshot list -g "$RG" --query "[?tags.owner=='$OWNER' && tags.expires<'$today'].name" -o tsv); do az snapshot delete -g "$RG" -n "$n"; done
    for n in $(az disk list -g "$RG" --query "[?managedBy==null && tags.owner=='$OWNER' && tags.expires<'$today'].name" -o tsv); do az disk delete -g "$RG" -n "$n" --yes -o none; done
  fi
}

sub="${1:-help}"; shift || true
case "$sub" in
  create) cmd_create "$@" ;;
  note-step) cmd_note_step "$@" ;;
  facts) cmd_facts "$@" ;;
  snapshot) cmd_snapshot "$@" ;;
  restore) cmd_restore "$@" ;;
  open-ports) cmd_open_ports "$@" ;;
  put) cmd_put "$@" ;;
  exec) cmd_ssh "$@" ;;
  ip) cmd_ip "$@" ;;
  ssh) cmd_ssh "$@" ;;
  start) cmd_start "$@" ;;
  stop) cmd_stop "$@" ;;
  delete) cmd_delete "$@" ;;
  sweep) cmd_sweep "$@" ;;
  help|-h|--help) sed -n '8,26p' "${BASH_SOURCE[0]}" ;;
  *) die "unknown command $sub (box.sh help)" ;;
esac
