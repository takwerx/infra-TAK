#!/bin/bash
# Guard Dog: send the MediaMTX stream cert from Caddy to the remote MediaMTX host (daily timer).
# Installed only on a box with a remote MediaMTX and a domain (the MediaMTX deploy).
# The console fills in the domain and where to send it. This script finds the cert and
# key itself, in Caddy's store, so it sends nothing else (ops #645 W2 part 2b).
set -u
DOMAIN="MTX_DOMAIN_PLACEHOLDER"
REMOTE_HOST="MTX_HOST_PLACEHOLDER"
REMOTE_USER="MTX_USER_PLACEHOLDER"
PORT="MTX_PORT_PLACEHOLDER"
SSH_KEY="MTX_KEYFILE_PLACEHOLDER"
STORE=/var/lib/caddy/.local/share/caddy/certificates

# Newest issuer folder that holds both files for this domain (Caddy keeps the old
# CA's copy when it switches issuer; see _caddy_acme_cert_base in app.py).
CERT=""
KEY=""
for c in "$STORE"/*/"$DOMAIN"/"$DOMAIN".crt; do
    k="${c%.crt}.key"
    if [ -f "$c" ] && [ ! -L "$c" ] && [ -f "$k" ] && [ ! -L "$k" ]; then
        if [ -z "$CERT" ] || [ "$c" -nt "$CERT" ]; then
            CERT="$c"
            KEY="$k"
        fi
    fi
done
[ -n "$CERT" ] || exit 0

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes)
if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ] && [ ! -L "$SSH_KEY" ]; then
    SSH_OPTS+=(-i "$SSH_KEY")
fi

scp -P "$PORT" "${SSH_OPTS[@]}" -- "$CERT" "$REMOTE_USER@$REMOTE_HOST:/etc/mediamtx/certs/stream.crt" 2>/dev/null
scp -P "$PORT" "${SSH_OPTS[@]}" -- "$KEY" "$REMOTE_USER@$REMOTE_HOST:/etc/mediamtx/certs/stream.key" 2>/dev/null
ssh -p "$PORT" "${SSH_OPTS[@]}" -- "$REMOTE_USER@$REMOTE_HOST" "chown root:takwerx /etc/mediamtx/certs/stream.crt /etc/mediamtx/certs/stream.key && chmod 640 /etc/mediamtx/certs/stream.crt /etc/mediamtx/certs/stream.key && systemctl restart mediamtx" 2>/dev/null
