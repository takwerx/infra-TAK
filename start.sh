#!/bin/bash
##############################################################################
# infra-TAK - Launcher
# Team Awareness Kit Infrastructure Platform
#
# This is the ONLY script users need to run.
# Everything else happens in the browser.
##############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$INSTALL_DIR/.config"
AUTH_FILE="$CONFIG_DIR/auth.json"
SETTINGS_FILE="$CONFIG_DIR/settings.json"

clear
echo ""
echo -e "${CYAN}${BOLD}  ╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}  ║  infra-TAK                                           ║${NC}"
echo -e "${CYAN}${BOLD}  ║  Team Awareness Kit Infrastructure Platform          ║${NC}"
echo -e "${CYAN}${BOLD}  ╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo "Please run: sudo $0"
    exit 1
fi

# ==========================================
# Server IP detection (v0.9.29)
# ==========================================
# Prefer public/external IP for cloud deployments (Azure/AWS/GCP).
# `hostname -I` on those VMs returns the private/internal IP, which is wrong for:
#   - SSL self-signed cert SAN (CN/IP)
#   - settings.server_ip used by TAK Server reachability + console "Access URL"
#   - Caddy / SSL bootstrap that builds the public-facing console URL
# Detection order (each step has its own timeout, falls through on failure):
#   1. Azure Instance Metadata Service (no internet egress required)
#   2. AWS Instance Metadata Service v1 (token-less, still works on older AMIs)
#   3. External IP echo (api.ipify.org → ifconfig.me)
#   4. Fallback: hostname -I (private/LAN — correct for on-prem / no public IP)
detect_server_ip() {
    local public_ip=""
    public_ip=$(curl -s --max-time 2 -H "Metadata: true" \
        "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" \
        2>/dev/null || true)
    if [ -z "$public_ip" ]; then
        # AWS IMDSv2 (token) — modern AMIs (esp. ARM/Graviton) default to
        # HttpTokens=required, which 401s the token-less IMDSv1 call below.
        local aws_tok
        aws_tok=$(curl -s --max-time 2 -X PUT \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
            http://169.254.169.254/latest/api/token 2>/dev/null || true)
        if [ -n "$aws_tok" ]; then
            public_ip=$(curl -s --max-time 2 \
                -H "X-aws-ec2-metadata-token: $aws_tok" \
                http://169.254.169.254/latest/meta-data/public-ipv4 \
                2>/dev/null || true)
        fi
    fi
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -s --max-time 2 \
            http://169.254.169.254/latest/meta-data/public-ipv4 \
            2>/dev/null || true)
    fi
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || true)
    fi
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -s --max-time 3 https://ifconfig.me 2>/dev/null || true)
    fi
    if echo "$public_ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
        echo "$public_ip"
    else
        hostname -I 2>/dev/null | awk '{print $1}'
    fi
}

# ==========================================
# VPS Disk I/O Check
# ==========================================
check_disk_io() {
    echo -e "  ${BOLD}Checking disk I/O performance...${NC}"
    local write_output
    write_output=$(dd if=/dev/zero of=/tmp/.infratak-disktest bs=1M count=256 oflag=dsync 2>&1)
    rm -f /tmp/.infratak-disktest
    local speed_str
    speed_str=$(echo "$write_output" | tail -1 | grep -oP '[\d.]+ [MGk]?B/s' | tail -1)
    local speed_mb=0
    if echo "$speed_str" | grep -q "GB/s"; then
        speed_mb=$(echo "$speed_str" | grep -oP '[\d.]+' | head -1 | awk '{printf "%d", $1 * 1024}')
    elif echo "$speed_str" | grep -q "MB/s"; then
        speed_mb=$(echo "$speed_str" | grep -oP '[\d.]+' | head -1 | awk '{printf "%d", $1}')
    elif echo "$speed_str" | grep -q "kB/s"; then
        speed_mb=0
    fi

    if [ "$speed_mb" -ge 400 ] 2>/dev/null; then
        echo -e "  ${GREEN}✓ Disk write: ${speed_str} — excellent${NC}"
    elif [ "$speed_mb" -ge 200 ] 2>/dev/null; then
        echo -e "  ${GREEN}✓ Disk write: ${speed_str} — acceptable${NC}"
    elif [ "$speed_mb" -gt 0 ] 2>/dev/null; then
        echo -e "  ${YELLOW}⚠ Disk write: ${speed_str} — slow (< 200 MB/s)${NC}"
        echo -e "  ${YELLOW}  Deploys may be slow. Consider migrating to a faster VPS node.${NC}"
        echo -e "  ${YELLOW}  Contact your provider about SSD-backed storage.${NC}"
    else
        echo -e "  ${YELLOW}⚠ Could not measure disk speed (${speed_str:-unknown})${NC}"
    fi
    echo ""
}

# ==========================================
# Detect Operating System
# ==========================================
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
    else
        echo -e "${RED}ERROR: Cannot detect operating system${NC}"
        exit 1
    fi

    case "$OS_ID" in
        ubuntu)
            if [[ "$OS_VERSION" == "22.04"* ]]; then
                OS_TYPE="ubuntu-22.04"
                PKG_MGR="apt"
            elif [[ "$OS_VERSION" == "24.04"* ]]; then
                OS_TYPE="ubuntu-24.04"
                PKG_MGR="apt"
            else
                echo -e "${YELLOW}WARNING: Ubuntu $OS_VERSION not tested. Ubuntu 22.04 recommended.${NC}"
                OS_TYPE="ubuntu-$OS_VERSION"
                PKG_MGR="apt"
            fi
            ;;
        debian)
            if [[ "$OS_VERSION" == "12"* ]]; then
                OS_TYPE="debian-12"
                PKG_MGR="apt"
            else
                echo -e "${YELLOW}WARNING: Debian $OS_VERSION not tested. Debian 12 recommended.${NC}"
                OS_TYPE="debian-$OS_VERSION"
                PKG_MGR="apt"
            fi
            ;;
        rocky|rhel|almalinux|centos)
            # v10.0.1: whole EL9 family (RHEL/Rocky/AlmaLinux/CentOS Stream),
            # not just "rocky" — same dnf/firewalld/SELinux/CRB behavior. The
            # os_type prefix stays "rocky-" so existing `'rocky' in os_type`
            # checks keep matching; the real family signal is PKG_MGR=dnf.
            if [[ "$OS_VERSION" == 9* ]]; then
                OS_TYPE="rocky-9"
                PKG_MGR="dnf"
            else
                echo -e "${YELLOW}WARNING: $OS_NAME not tested. EL9 (Rocky/RHEL/Alma 9) recommended.${NC}"
                OS_TYPE="rocky-$OS_VERSION"
                PKG_MGR="dnf"
            fi
            ;;
        *)
            echo -e "${YELLOW}WARNING: $OS_NAME is not officially supported.${NC}"
            echo -e "${YELLOW}Supported: Ubuntu 22.04/24.04, Debian 12, EL9 (Rocky/RHEL/AlmaLinux/CentOS 9)${NC}"
            OS_TYPE="$OS_ID-$OS_VERSION"
            PKG_MGR="unknown"
            ;;
    esac

    # v10.0.1: CPU architecture (amd64 | arm64). arm64 targets NVIDIA Jetson
    # Orin (JetPack 6 / Ubuntu 22.04), Ampere, Graviton. Anything unrecognized
    # falls back to amd64 — the field-validated default path. app.py reads this
    # via _host_arch() to force the container TAK path on arm64 (no native arm
    # TAK package exists).
    case "$(uname -m)" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)              ARCH="amd64" ;;
    esac

    echo -e "  Detected: ${GREEN}$OS_NAME${NC}"
    echo -e "  Type:     ${GREEN}$OS_TYPE${NC}"
    echo -e "  Arch:     ${GREEN}$ARCH${NC}"
    echo ""
}

# ==========================================
# Wait for unattended-upgrades / apt-daily / dpkg lock
# ==========================================
# Fresh VPS images often run automatic updates at first boot. apt-get in
# install_dependencies() fails with "Could not get lock" if we don't wait.
wait_for_upgrades() {
    local waited=0
    local max_wait=3600
    local busy=1

    while [ "$waited" -lt "$max_wait" ]; do
        busy=0
        # apt-daily / explicit apt & dpkg (real work)
        if pgrep -f apt.systemd.daily > /dev/null 2>&1 \
            || pgrep -x apt-get > /dev/null 2>&1 \
            || pgrep -x apt > /dev/null 2>&1 \
            || pgrep -x dpkg > /dev/null 2>&1; then
            busy=1
        fi
        # Do NOT treat unattended-upgrade-shutdown as busy — it stays running forever on Ubuntu.
        while read -r _u_line; do
            case "$_u_line" in
                *unattended-upgrade-shutdown*) ;;
                *) busy=1; break ;;
            esac
        done < <(pgrep -af unattended-upgrade 2>/dev/null)
        if command -v fuser > /dev/null 2>&1; then
            for lock in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock; do
                [ -e "$lock" ] || continue
                if fuser "$lock" > /dev/null 2>&1; then
                    busy=1
                    break
                fi
            done
        fi
        if [ "$busy" -eq 0 ]; then
            if [ "$waited" -gt 0 ]; then
                echo ""
                echo -e "  ${GREEN}✓ Package manager is idle${NC}"
                echo ""
            fi
            return 0
        fi
        if [ "$waited" -eq 0 ]; then
            echo -e "${YELLOW}  Automatic updates / apt are using the package manager (common on first boot). Waiting...${NC}"
        fi
        printf "\r  Waiting... %02d:%02d elapsed" $((waited / 60)) $((waited % 60))
        sleep 2
        waited=$((waited + 2))
    done
    echo ""
    echo -e "${RED}  Still waiting after 1 hour. Reboot or run: sudo systemctl status unattended-upgrades${NC}"
    exit 1
}

# ==========================================
# Install Python Dependencies
# ==========================================
install_dependencies() {
    echo -e "  Installing dependencies..."

    local apt_log="/tmp/infratak-apt-$$.log"

    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            export NEEDRESTART_MODE=a
            if ! apt-get update -qq > "$apt_log" 2>&1; then
                echo -e "${RED}  apt-get update failed:${NC}"
                tail -20 "$apt_log"
                rm -f "$apt_log"
                exit 1
            fi
            if ! NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get install -y \
                -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
                python3 python3-pip python3-venv openssl sshpass git wget > "$apt_log" 2>&1; then
                echo -e "${RED}  apt-get install failed:${NC}"
                tail -30 "$apt_log"
                rm -f "$apt_log"
                exit 1
            fi
            rm -f "$apt_log"
            ;;
        dnf)
            if ! dnf install -y python3 python3-pip openssl sshpass git wget > "$apt_log" 2>&1; then
                echo -e "${RED}  dnf install failed:${NC}"
                tail -30 "$apt_log"
                rm -f "$apt_log"
                exit 1
            fi
            rm -f "$apt_log"
            ;;
        *)
            echo -e "${RED}  Cannot auto-install dependencies for $PKG_MGR${NC}"
            echo "  Please install: python3, python3-pip, python3-venv, openssl, sshpass"
            exit 1
            ;;
    esac

    # Create virtual environment if it doesn't exist
    if [ ! -d "$INSTALL_DIR/.venv" ]; then
        if ! python3 -m venv "$INSTALL_DIR/.venv" && ! python3 -m venv "$INSTALL_DIR/.venv" --without-pip; then
            echo -e "${RED}  python3 -m venv failed. Install package python3-venv (apt) and re-run.${NC}"
            exit 1
        fi
    fi

    if [ ! -x "$INSTALL_DIR/.venv/bin/pip" ]; then
        echo -e "${RED}  No pip in .venv. Install python3-venv, remove $INSTALL_DIR/.venv, re-run.${NC}"
        exit 1
    fi

    if ! "$INSTALL_DIR/.venv/bin/pip" install --quiet flask psutil werkzeug gunicorn 2>"$apt_log"; then
        echo -e "${RED}  pip install failed:${NC}"
        tail -20 "$apt_log"
        rm -f "$apt_log"
        exit 1
    fi
    rm -f "$apt_log"

    echo -e "  ${GREEN}✓ Dependencies installed${NC}"
    echo ""
}

# ==========================================
# First-Time Setup (password only)
# ==========================================
first_time_setup() {
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    echo -e "${BOLD}  First-time setup${NC}"
    echo ""

    # Set admin password
    while true; do
        read -s -p "  Set admin password: " ADMIN_PASS
        echo ""
        read -s -p "  Confirm password:   " ADMIN_PASS_CONFIRM
        echo ""

        if [ -z "$ADMIN_PASS" ]; then
            echo -e "  ${RED}Password cannot be empty${NC}"
            continue
        fi

        if [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
            echo -e "  ${RED}Passwords do not match${NC}"
            continue
        fi

        break
    done

    # Hash the password using Python
    PASS_HASH=$("$INSTALL_DIR/.venv/bin/python3" -c "
from werkzeug.security import generate_password_hash
import sys
print(generate_password_hash(sys.argv[1]))
" "$ADMIN_PASS")

    # Save auth config
    cat > "$AUTH_FILE" << EOF
{
    "password_hash": "$PASS_HASH",
    "created": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
EOF
    chmod 600 "$AUTH_FILE"

    # Detect server IP — public-preferring (cloud-aware). See detect_server_ip()
    # near the top of the script for the detection order. On Azure/AWS/GCP this
    # picks the public IP from the cloud's metadata service; on on-prem hosts
    # it falls back to the first interface from `hostname -I`.
    SERVER_IP=$(detect_server_ip)

    # Save settings — always start in IP/self-signed mode
    # FQDN setup happens in the browser through the Caddy module
    cat > "$SETTINGS_FILE" << EOF
{
    "ssl_mode": "self-signed",
    "fqdn": "",
    "server_ip": "$SERVER_IP",
    "os_type": "$OS_TYPE",
    "os_name": "$OS_NAME",
    "pkg_mgr": "$PKG_MGR",
    "arch": "$ARCH",
    "console_port": 5001,
    "install_dir": "$INSTALL_DIR",
    "created": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
EOF
    chmod 600 "$SETTINGS_FILE"

    echo ""
    echo -e "  ${GREEN}✓ Configuration saved${NC}"
}

# ==========================================
# Generate Self-Signed Certificate
# ==========================================
generate_self_signed_cert() {
    CERT_DIR="$CONFIG_DIR/ssl"
    mkdir -p "$CERT_DIR"

    if [ ! -f "$CERT_DIR/console.key" ]; then
        echo -e "  Generating self-signed certificate..."

        # v0.9.29: use the same public-preferring detection so the cert SAN
        # matches the IP operators actually browse to on cloud VMs.
        SERVER_IP=$(detect_server_ip)

        openssl req -x509 -newkey rsa:4096 \
            -keyout "$CERT_DIR/console.key" \
            -out "$CERT_DIR/console.crt" \
            -sha256 -days 3650 -nodes \
            -subj "/C=US/ST=TAK/L=TAK/O=TAKWERX/CN=$SERVER_IP" \
            -addext "subjectAltName=IP:$SERVER_IP,IP:127.0.0.1,DNS:localhost" \
            2>/dev/null

        chmod 600 "$CERT_DIR/console.key"
        chmod 644 "$CERT_DIR/console.crt"
        
        echo -e "  ${GREEN}✓ Self-signed certificate generated${NC}"
    fi
}

# ==========================================
# Create systemd Service
# ==========================================
# If the service already exists and points to a directory that has .config/auth.json,
# keep using that directory so "git pull" or running start.sh from another clone
# doesn't switch to a path that has no auth (password would stop working).
create_service() {
    SERVICE_FILE="/etc/systemd/system/takwerx-console.service"
    USE_DIR="$INSTALL_DIR"
    if [ -f "$SERVICE_FILE" ]; then
        EXISTING_DIR=$(grep -E '^WorkingDirectory=' "$SERVICE_FILE" 2>/dev/null | cut -d= -f2- | tr -d ' ')
        if [ -n "$EXISTING_DIR" ] && [ -d "$EXISTING_DIR" ] && [ -f "$EXISTING_DIR/.config/auth.json" ]; then
            USE_DIR="$EXISTING_DIR"
        fi
    fi

    # Build gunicorn command with SSL if certs exist
    CERT_DIR="$USE_DIR/.config/ssl"
    GUNICORN_BIN="$USE_DIR/.venv/bin/gunicorn"
    PORT=$("$USE_DIR/.venv/bin/python3" -c "
import json, os
try:
    with open(os.path.join('$USE_DIR', '.config', 'settings.json')) as f:
        print(json.load(f).get('console_port', 5001))
except Exception:
    print(5001)
" 2>/dev/null || echo 5001)

    GUNICORN_ARGS="--bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 300 --graceful-timeout 30"
    if [ -f "$CERT_DIR/console.crt" ] && [ -f "$CERT_DIR/console.key" ]; then
        GUNICORN_ARGS="$GUNICORN_ARGS --certfile=$CERT_DIR/console.crt --keyfile=$CERT_DIR/console.key"
    fi

    # v0.9.12: pin HOME so shell commands like `cd ~/authentik` work under systemd.
    # systemd does NOT inherit HOME from login env; without this, /bin/sh can't
    # expand ~/. Same documented pattern as v0.2.7-alpha takupdatesguard.service.
    SERVICE_HOME="${HOME:-/root}"
    if [ -z "$SERVICE_HOME" ] || [ "$SERVICE_HOME" = "/" ]; then
        SERVICE_HOME="/root"
    fi

    # v10.0.1 (RHEL/SELinux): under SELinux enforcing, systemd (init_t) cannot
    # traverse the operator's home (user_home_dir_t) nor exec the gunicorn venv
    # there (user_home_t) — the service crash-loops with 203/EXEC and nothing
    # binds the console port. Relabeling the venv does NOT help (the /home
    # traversal is still denied). The console is a trusted root admin service, so
    # run it in the unconfined service domain; the rest of the box (TAK Server,
    # etc.) stays confined/enforcing. Validated on Rocky 9.6 under Enforcing with
    # DEFAULT labels (no relabel, no relocation): exec + import compiled deps +
    # read app.py + bind socket all succeed, zero AVC denials. On Debian/Ubuntu
    # `getenforce` is absent, so the directive is omitted and the unit is
    # byte-identical to today's.
    SELINUX_DIRECTIVE=""
    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
        SELINUX_DIRECTIVE="SELinuxContext=system_u:system_r:unconfined_service_t:s0"
    fi

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=infra-TAK - Team Awareness Kit Infrastructure Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
${SELINUX_DIRECTIVE:+$SELINUX_DIRECTIVE
}ExecStart=$GUNICORN_BIN $GUNICORN_ARGS app:app
WorkingDirectory=$USE_DIR
Restart=always
RestartSec=5
RuntimeMaxSec=24h
Environment=PYTHONUNBUFFERED=1
Environment=CONFIG_DIR=$USE_DIR/.config
Environment=HOME=$SERVICE_HOME

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable takwerx-console > /dev/null 2>&1
}

# v10.0.1 (RHEL/SELinux): install the console's SELinux policy module so systemd
# (init_t) can traverse the in-home clone, read+exec the gunicorn venv entrypoint
# there, and transition into the unconfined service domain (paired with the
# unit's SELinuxContext directive). Without it the service crash-loops 203/EXEC
# under enforcing. Compiled on-box from the shipped .te so it matches the host's
# policy version. No-op on non-SELinux hosts (Debian/Ubuntu: getenforce absent).
# Validated on Rocky 9.6 under Enforcing (systemd-run init_t exec+import+read+bind
# all succeed, zero denials).
install_selinux_console_policy() {
    command -v getenforce >/dev/null 2>&1 || return 0
    [ "$(getenforce 2>/dev/null)" = "Disabled" ] && return 0
    local te="$INSTALL_DIR/selinux/takwerx_console.te"
    [ -f "$te" ] || { echo -e "${YELLOW}  ⚠ SELinux policy source missing ($te) — console may not start under enforcing${NC}"; return 0; }
    # already current? (idempotent re-runs skip the rebuild)
    if semodule -l 2>/dev/null | grep -q '^takwerx_console'; then
        echo "  ✓ SELinux console policy already installed"
        return 0
    fi
    if ! command -v checkmodule >/dev/null 2>&1; then
        dnf install -y checkpolicy >/dev/null 2>&1 || true
    fi
    if ! command -v checkmodule >/dev/null 2>&1 || ! command -v semodule_package >/dev/null 2>&1; then
        echo -e "${YELLOW}  ⚠ SELinux policy tools unavailable — console may not start under enforcing${NC}"
        return 0
    fi
    local tmp; tmp=$(mktemp -d)
    if checkmodule -M -m -o "$tmp/takwerx_console.mod" "$te" >/dev/null 2>&1 \
       && semodule_package -o "$tmp/takwerx_console.pp" -m "$tmp/takwerx_console.mod" >/dev/null 2>&1 \
       && semodule -i "$tmp/takwerx_console.pp" >/dev/null 2>&1; then
        echo "  ✓ SELinux console policy installed (takwerx_console)"
    else
        echo -e "${YELLOW}  ⚠ SELinux console policy failed to install — console may not start under enforcing${NC}"
    fi
    rm -rf "$tmp"
}

# ==========================================
# Main
# ==========================================
detect_os
check_disk_io
wait_for_upgrades

install_dependencies

# First-time setup if no auth file exists
if [ ! -f "$AUTH_FILE" ]; then
    first_time_setup
fi

# Always use self-signed cert for console (Caddy handles FQDN SSL)
generate_self_signed_cert

# RHEL/SELinux: install the console policy module before the unit starts
install_selinux_console_policy

# Create and start systemd service
create_service

# Stop existing instance if running
systemctl stop takwerx-console 2>/dev/null || true
sleep 1

# Start the console
systemctl start takwerx-console

# Host firewall: keep the console + SSH reachable, and on RHEL bring up ALWAYS-ON
# firewalld (operator decision 2026-06-21 — many deploys aren't in a cloud with a
# security group, and the Cyber-Controls W4 checks need a host firewall to assert
# against). On Debian, ufw is enabled later by the TAK Server deploy; just open 5001.
if [ "$PKG_MGR" = "dnf" ]; then
    # Install firewalld if the image didn't ship it (cloud RHEL AMIs often strip it).
    command -v firewall-cmd >/dev/null 2>&1 || dnf install -y firewalld >/dev/null 2>&1
    if command -v firewall-cmd >/dev/null 2>&1; then
        # Start firewalld FIRST — `firewall-cmd` (even --permanent) needs the daemon
        # running, and the default `public` zone already allows ssh, so SSH survives.
        systemctl enable --now firewalld >/dev/null 2>&1 || true
        # Now add console + SSH explicitly, then seed from current PUBLIC listeners so a
        # re-run on a box that already has modules doesn't strand their ports (a fresh box
        # only has SSH + console here). Module deploys open their ports later via the shim.
        firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=5001/tcp >/dev/null 2>&1 || true
        for _p in $(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -vE '^127\.0\.0\.1:|^\[::1\]:' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un); do
            [ "$_p" = "111" ] && continue   # rpcbind — never expose
            firewall-cmd --permanent --add-port=${_p}/tcp >/dev/null 2>&1 || true
        done
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
else
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 5001/tcp >/dev/null 2>&1 || true
    fi
fi

# Get access URL — on Azure/AWS the private IP is returned by hostname -I
# Try to resolve the public IP so operators get the right URL
SERVER_IP=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || echo "")

echo ""
echo -e "${GREEN}${BOLD}  ╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}  ║  infra-TAK is running!                               ║${NC}"
echo -e "${GREEN}${BOLD}  ╚══════════════════════════════════════════════════════╝${NC}"
echo ""
if [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "$SERVER_IP" ]; then
    echo -e "  ${BOLD}Access (public):${NC}  https://$PUBLIC_IP:5001"
    echo -e "  ${BOLD}Access (private):${NC} https://$SERVER_IP:5001"
else
    echo -e "  ${BOLD}Access:${NC} https://$SERVER_IP:5001"
fi
echo -e "  ${YELLOW}(Accept the self-signed certificate warning in your browser)${NC}"
echo ""
echo -e "  ${BOLD}Service:${NC} systemctl status takwerx-console"
echo -e "  ${BOLD}Logs:${NC}    journalctl -u takwerx-console -f"
echo ""
echo -e "  ${CYAN}Tip: Set up a domain name through the Caddy module${NC}"
echo -e "  ${CYAN}in the console for proper SSL and full functionality.${NC}"
echo ""
