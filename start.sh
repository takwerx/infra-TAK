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
        rocky|rhel)
            if [[ "$OS_VERSION" == 9* ]]; then
                OS_TYPE="rocky-9"
                PKG_MGR="dnf"
            else
                echo -e "${YELLOW}WARNING: $OS_NAME not tested. Rocky 9 recommended.${NC}"
                OS_TYPE="rocky-$OS_VERSION"
                PKG_MGR="dnf"
            fi
            ;;
        *)
            echo -e "${YELLOW}WARNING: $OS_NAME is not officially supported.${NC}"
            echo -e "${YELLOW}Supported: Ubuntu 22.04/24.04, Debian 12, Rocky Linux 9${NC}"
            OS_TYPE="$OS_ID-$OS_VERSION"
            PKG_MGR="unknown"
            ;;
    esac

    echo -e "  Detected: ${GREEN}$OS_NAME${NC}"
    echo -e "  Type:     ${GREEN}$OS_TYPE${NC}"
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
                python3 python3-pip python3-venv openssl sshpass > "$apt_log" 2>&1; then
                echo -e "${RED}  apt-get install failed:${NC}"
                tail -30 "$apt_log"
                rm -f "$apt_log"
                exit 1
            fi
            rm -f "$apt_log"
            ;;
        dnf)
            if ! dnf install -y python3 python3-pip openssl sshpass > "$apt_log" 2>&1; then
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

    GUNICORN_ARGS="--bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 300 --graceful-timeout 30"
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

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=infra-TAK - Team Awareness Kit Infrastructure Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$GUNICORN_BIN $GUNICORN_ARGS app:app
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

# Create and start systemd service
create_service

# Stop existing instance if running
systemctl stop takwerx-console 2>/dev/null || true
sleep 1

# Start the console
systemctl start takwerx-console

# Ensure backdoor port 5001 is allowed (so when UFW is enabled later, e.g. by TAK Server deploy, we don't lock ourselves out)
if command -v ufw >/dev/null 2>&1; then
    ufw allow 5001/tcp >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=5001/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
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
