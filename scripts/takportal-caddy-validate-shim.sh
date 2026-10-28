#!/bin/bash
# infratak-caddy-validate-shim
#
# Installed by infra-TAK as ~/.local/bin/caddy for the NON-ROOT console user (the account
# TAK Portal SSHes in as). Ops #298.
#
# Why: TAK Portal's Marketplace "Deploy To Caddy" runs `caddy validate` over SSH as that
# user. Validate provisions the config, which opens the access-log writer
# (/var/log/caddy/takportal-access.log, 0644 caddy:caddy) for append, and can read
# client-CA/cert files under /var/lib/caddy (0750 caddy:caddy). The console user can do
# neither, so validate exits 1 with "permission denied" and the Portal reports "Caddy
# rejected the updated file" for a perfectly good file. The caddy service has no such
# problem. Same carve-out as infra-TAK's own _caddy_validate_config().
#
# What it does: `caddy validate` runs for real. If it fails and EVERY error it printed is a
# "permission denied", the result is inconclusive, not bad: it says so and exits 0. Any
# other error (a parse error, an unknown directive, anything beyond permission denied)
# keeps Caddy's own exit code and output. Every other caddy subcommand is exec'd untouched.
# The Portal reloads right after validate and puts the old file back if Caddy refuses it.

# Find the real caddy: first `caddy` on PATH that is not this file. `-ef` (same inode) is a
# bash builtin test, so this still works with a bare PATH, and a symlink back to us is skipped.
REAL=""
IFS=: read -ra _DIRS <<< "$PATH"
for _d in "${_DIRS[@]}" /usr/bin /usr/local/bin; do
  _c="${_d:-.}/caddy"
  if [ -x "$_c" ] && [ ! -d "$_c" ] && ! [ "$_c" -ef "$0" ]; then
    REAL="$_c"; break
  fi
done
if [ -z "$REAL" ]; then
  echo "caddy: not found" >&2
  exit 127
fi

if [ "${1:-}" != "validate" ]; then
  exec "$REAL" "$@"
fi

OUT=$("$REAL" "$@" 2>&1)
RC=$?
printf '%s\n' "$OUT" >&2
[ "$RC" -eq 0 ] && exit 0

ERRS=$(printf '%s\n' "$OUT" | grep -E '"level":"(error|fatal|panic)"|^Error:' || true)
if [ -n "$ERRS" ] && ! printf '%s\n' "$ERRS" | grep -qiv 'permission denied'; then
  echo "infra-TAK: caddy validate could not open a file only the caddy service can read (permission denied). The config parsed; the caddy service will load it. Treating as OK." >&2
  exit 0
fi
exit "$RC"
