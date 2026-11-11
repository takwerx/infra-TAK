#!/bin/bash
# Reset the infra-TAK console admin password. Run on the server from the directory
# the console actually runs from (shown by:
#   systemctl cat takwerx-console | grep WorkingDirectory
# ), e.g.:
#   cd /opt/infratak   # or your install path
#   sudo ./reset-console-password.sh
set -e
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# v10.1.24 (W7): a box can carry multiple clones (stale /root/infra-TAK next to the
# live /opt/infratak). This script writes ITS OWN clone's .config/auth.json — run from
# the wrong clone it reports "Password updated… Done" while changing nothing the
# running console reads (field hit 2026-08-05: reset "succeeded", login rejected).
# The systemd unit is the authority on where the console runs — refuse a mismatch.
UNIT_DIR=$(systemctl cat takwerx-console 2>/dev/null | grep -oP '^WorkingDirectory=\K.*' | head -1)
if [ -n "$UNIT_DIR" ] && [ "$UNIT_DIR" != "$INSTALL_DIR" ]; then
    echo "Error: this copy is in $INSTALL_DIR, but the console runs from $UNIT_DIR."
    echo "The console runs from $UNIT_DIR — run the copy there:"
    echo "  cd $UNIT_DIR && sudo ./reset-console-password.sh"
    exit 1
fi

CONFIG_DIR="$INSTALL_DIR/.config"
# The unit may pin the config path (Environment=CONFIG_DIR=…, written by start.sh /
# fix-console-after-pull.sh) — that value is what the console actually reads; prefer it.
UNIT_CONFIG_DIR=$(systemctl cat takwerx-console 2>/dev/null | grep -oP '^Environment=CONFIG_DIR=\K.*' | head -1)
if [ -n "$UNIT_CONFIG_DIR" ]; then
    CONFIG_DIR="$UNIT_CONFIG_DIR"
fi
AUTH_FILE="$CONFIG_DIR/auth.json"

if [ ! -d "$INSTALL_DIR/.venv" ]; then
    echo "Error: .venv not found. Run this from the infra-TAK install directory."
    exit 1
fi

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# ops #638: same floor as app.py CONSOLE_PASSWORD_MIN_LEN and start.sh. The console is
# root and its login page can be reached from the internet.
CONSOLE_PASSWORD_MIN_LEN=12

echo ""
echo "Reset console admin password (install: $INSTALL_DIR)"
echo "The password needs at least $CONSOLE_PASSWORD_MIN_LEN characters."
echo ""

read -rs -p "New password: " NEW_PASS
echo ""
read -rs -p "Confirm:      " NEW_PASS_CONFIRM
echo ""

if [ -z "$NEW_PASS" ]; then
    echo "Password cannot be empty."
    exit 1
fi
if [ "${#NEW_PASS}" -lt "$CONSOLE_PASSWORD_MIN_LEN" ]; then
    echo "Password must be at least $CONSOLE_PASSWORD_MIN_LEN characters."
    exit 1
fi
if [ "$NEW_PASS" != "$NEW_PASS_CONFIRM" ]; then
    echo "Passwords do not match."
    exit 1
fi

# pbkdf2:sha256 = app.py PASSWORD_HASH_METHOD (GH #137). werkzeug's default, scrypt, is
# missing from FIPS-mode OpenSSL — this script is the way out for a box stuck on one.
# ops #638: the password goes in on stdin (printf is a bash builtin, so no process ever
# carries it in argv); as an argument any local user could read it in `ps`.
PASS_HASH=$(printf '%s' "$NEW_PASS" | "$INSTALL_DIR/.venv/bin/python3" -c "
from werkzeug.security import generate_password_hash
import sys
pw = sys.stdin.read()
print(generate_password_hash(pw, method='pbkdf2:sha256'))
")
unset NEW_PASS NEW_PASS_CONFIRM

cat > "$AUTH_FILE" << EOF
{
    "password_hash": "$PASS_HASH",
    "password_min_len_ok": true,
    "created": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
EOF
chmod 600 "$AUTH_FILE"

echo "Password updated. Restarting console..."
systemctl restart takwerx-console 2>/dev/null || true
echo "Done. Log in at https://<this-server-ip>:5001 with the new password."
echo ""
