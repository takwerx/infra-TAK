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
set -eu
SHIM_DIR="${1:-/opt/infratak/.shims}"
BROKER="${2:-/opt/infratak/broker/takwerx_broker.py}"
mkdir -p "$SHIM_DIR"

ALWAYS=(docker systemctl systemd-run journalctl loginctl ufw firewall-cmd dnf apt apt-get yum
        semanage semodule restorecon chcon fail2ban-client swapon swapoff mkswap
        fallocate sysctl gpg dpkg pg_createcluster postconf postmap
        debconf-set-selections newaliases runuser)
PATHAWARE=(mkdir rmdir mv cp chmod chown install tee ln rm touch)

# --- always-route binaries (docker handled specially below) ---
for c in "${ALWAYS[@]}"; do
  [ "$c" = "docker" ] && continue
  cat > "$SHIM_DIR/$c" <<EOF
#!/bin/bash
if [ "\$(id -u)" -ne 0 ] && [ -S /run/takwerx-broker.sock ] && [ -f "$BROKER" ]; then
  exec python3 "$BROKER" exec -- $c "\$@"
fi
exec $(command -v "$c" 2>/dev/null || echo "/usr/bin/$c") "\$@"
EOF
done

# --- docker: route + stage `cp container:->host` so dest is user-owned ---
cat > "$SHIM_DIR/docker" <<EOF
#!/bin/bash
_real() { exec $(command -v docker 2>/dev/null || echo /usr/bin/docker) "\$@"; }
if [ "\$(id -u)" -eq 0 ] || [ ! -S /run/takwerx-broker.sock ] || [ ! -f "$BROKER" ]; then _real "\$@"; fi
if [ "\${1:-}" = "cp" ]; then
  _a=( "\$@" ); _n=\${#_a[@]}; _src="\${_a[_n-2]}"; _dst="\${_a[_n-1]}"
  if [[ "\$_src" == *:* && "\$_dst" != *:* ]]; then
    _sd=\$(mktemp -d); _rc=0
    if python3 "$BROKER" exec -- docker cp "\$_src" "\$_sd/f"; then cp -f "\$_sd/f" "\$_dst" || _rc=\$?; else _rc=1; fi
    rm -rf "\$_sd"; exit \$_rc
  fi
fi
exec python3 "$BROKER" exec -- docker "\$@"
EOF

# --- path-aware coreutils ---
for c in "${PATHAWARE[@]}"; do
  cat > "$SHIM_DIR/$c" <<EOF
#!/bin/bash
_real="$(command -v "$c" 2>/dev/null || echo "/usr/bin/$c")"
if [ "\$(id -u)" -ne 0 ] && [ -S /run/takwerx-broker.sock ] && [ -f "$BROKER" ]; then
  for _a in "\$@"; do
    case "\$_a" in
      /etc/*|/opt/*|/usr/*|/var/*|/run/*|/boot/*|/swapfile)
        exec python3 "$BROKER" exec -- $c "\$@" ;;
    esac
  done
fi
exec "\$_real" "\$@"
EOF
done

chmod 755 "$SHIM_DIR"/*
echo "installed $(ls "$SHIM_DIR" | wc -l) broker shims in $SHIM_DIR"
