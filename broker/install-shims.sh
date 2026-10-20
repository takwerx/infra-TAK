#!/bin/bash
# infra-TAK broker PATH-shims  (v10.0.5 non-root)
#
# Generates /opt/infratak/.shims/<cmd> wrappers that route privileged commands
# through the root broker. Putting this dir FIRST on PATH lets ANY shell command
# the non-root console runs — module-deploy shell strings via _module_run, and
# external scripts (nodered/deploy.sh, cloudtak.sh) — reach docker/systemctl/etc
# WITHOUT giving takwerx real privilege. As root, or with no broker socket, the
# shims fall through to the real binary, so behaviour is unchanged.
#
# Two shim kinds:
#   * ALWAYS-route binaries (docker, systemctl, ufw, dnf, …): every invocation is
#     privileged; route unconditionally. The broker allowlist still gates them.
#   * PATH-AWARE coreutils (mkdir, mv, cp, chmod, chown, install, tee, ln, rm,
#     touch): route ONLY when an argument is a privileged path (/etc /opt /usr
#     /var …); otherwise exec the real binary so non-priv use (e.g. mkdir /tmp/x)
#     is untouched. docker also stages `cp container:->host` so the dest is
#     user-owned (see the docker shim).
#
# $2 is the client the shims exec — since v10.2.2 the light, stdlib-only
# broker/takwerx_brokerctl.py (same `exec --` contract as `takwerx_broker.py
# exec`, ~2.5x cheaper per call). `-I -S` keeps site/.pth processing and the
# script dir off the import path; the client needs neither. Any client that
# speaks `exec --` works here, including takwerx_broker.py itself.
set -eu
SHIM_DIR="${1:-/opt/infratak/.shims}"
BROKER="${2:-/opt/infratak/broker/takwerx_brokerctl.py}"
mkdir -p "$SHIM_DIR"

ALWAYS=(docker systemctl systemd-run journalctl loginctl ufw firewall-cmd dnf apt apt-get yum
        semanage semodule restorecon chcon fail2ban-client swapon swapoff mkswap
        fallocate sysctl gpg dpkg pg_createcluster postconf postmap
        debconf-set-selections newaliases runuser)
PATHAWARE=(mkdir rmdir mv cp chmod chown install tee ln rm touch)

# ops #113: the broker restarts itself once a day (idle recycle) and on every source
# change, and for ~2-3 s the socket is gone. A shim that fell through to the real binary
# then failed as takwerx (`docker ps` -> permission denied -> "Node-RED container not
# running", test6 2026-10-20). So a missing socket is waited for, up to 30 s, while systemd
# says the broker is up or on its way back; a stopped or failed broker falls through at
# once, as before. Real systemctl, resolved now: the systemctl SHIM would wait on itself.
_SYSTEMCTL="$(PATH=/usr/bin:/bin command -v systemctl 2>/dev/null || echo /usr/bin/systemctl)"
_WAIT="_w=0
while [ ! -S /run/takwerx-broker.sock ] && [ \$_w -lt 120 ]; do
  case \"\$($_SYSTEMCTL is-active takwerx-broker 2>/dev/null)\" in active|activating|deactivating|reloading) ;; *) break ;; esac
  sleep 0.25; _w=\$((_w+1))
done"

# --- always-route binaries (docker handled specially below) ---
for c in "${ALWAYS[@]}"; do
  [ "$c" = "docker" ] && continue
  cat > "$SHIM_DIR/$c" <<EOF
#!/bin/bash
if [ "\$(id -u)" -ne 0 ] && [ -f "$BROKER" ]; then
$_WAIT
  if [ -S /run/takwerx-broker.sock ]; then exec python3 -I -S "$BROKER" exec -- $c "\$@"; fi
fi
exec $(command -v "$c" 2>/dev/null || echo "/usr/bin/$c") "\$@"
EOF
done

# --- docker: route + stage `cp container:->host` so dest is user-owned ---
# v10.1.5 WS4: the staged copy's final `cp` MUST be the REAL binary. The shim dir
# is first on PATH, so bare `cp` resolved back into the cp SHIM, which re-entered
# the broker AS ROOT: enforcing brokers DENY console-repo destinations ("path not
# in allow-list: .../nodered/flows.json", test6 flow sync exit 126), and
# permissive brokers executed it as root — planting the root-owned files inside
# the console tree that the ownership heal keeps having to fix. The whole point
# of staging is that the CONSOLE USER writes the destination itself.
_REALCP="$(PATH=/usr/bin:/bin command -v cp || echo /usr/bin/cp)"
cat > "$SHIM_DIR/docker" <<EOF
#!/bin/bash
_real() { exec $(command -v docker 2>/dev/null || echo /usr/bin/docker) "\$@"; }
if [ "\$(id -u)" -eq 0 ] || [ ! -f "$BROKER" ]; then _real "\$@"; fi
$_WAIT
if [ ! -S /run/takwerx-broker.sock ]; then _real "\$@"; fi
if [ "\${1:-}" = "cp" ]; then
  _a=( "\$@" ); _n=\${#_a[@]}; _src="\${_a[_n-2]}"; _dst="\${_a[_n-1]}"
  if [[ "\$_src" == *:* && "\$_dst" != *:* ]]; then
    _sd=\$(mktemp -d); _rc=0
    if python3 -I -S "$BROKER" exec -- docker cp "\$_src" "\$_sd/f"; then "$_REALCP" -f "\$_sd/f" "\$_dst" || _rc=\$?; else _rc=1; fi
    rm -rf "\$_sd"; exit \$_rc
  fi
fi
exec python3 -I -S "$BROKER" exec -- docker "\$@"
EOF

# --- path-aware coreutils ---
for c in "${PATHAWARE[@]}"; do
  cat > "$SHIM_DIR/$c" <<EOF
#!/bin/bash
_real="$(command -v "$c" 2>/dev/null || echo "/usr/bin/$c")"
if [ "\$(id -u)" -ne 0 ] && [ -f "$BROKER" ]; then
  for _a in "\$@"; do
    case "\$_a" in
      /etc/*|/opt/*|/usr/*|/var/*|/run/*|/boot/*|/swapfile)
$_WAIT
        if [ -S /run/takwerx-broker.sock ]; then exec python3 -I -S "$BROKER" exec -- $c "\$@"; fi
        break ;;
    esac
  done
fi
exec "\$_real" "\$@"
EOF
done

chmod 755 "$SHIM_DIR"/*
echo "installed $(ls "$SHIM_DIR" | wc -l) broker shims in $SHIM_DIR"
