#!/usr/bin/env bash
# connectivity-anchor-bootstrap.sh — Connectivity Wizard (v10.1.0) anchor VPS bootstrap
#
# Stands up the public "mailbox" that a CGNAT or portable infra-TAK box dials OUT to:
#   internet client ──▶ anchor public IP :80/:443/:8089/:8443/:8446 (+ video) ──kernel DNAT──▶ WireGuard ──▶ box
#
# The forward is PURE L4 (kernel PREROUTING DNAT over a WireGuard p2p tunnel).
# The anchor has no TLS stack in the path at all — TAK's mutual-TLS handshake
# passes through UNTOUCHED. See TE-v10.1.0-anchor-l4-passthrough.md for the
# proof procedure (cert-fingerprint + client-CA comparison + live enrollment).
#
# Target: a tiny always-free VPS (Oracle Free Tier Ubuntu 22.04 / Oracle Linux;
# apt and dnf both handled; x86 or ARM64 — everything here is arch-neutral).
# Run as root ON THE ANCHOR VPS, not on the infra-TAK box.
#
# Usage:
#   ./connectivity-anchor-bootstrap.sh setup
#   ./connectivity-anchor-bootstrap.sh add-box <box-wireguard-public-key>
#   ./connectivity-anchor-bootstrap.sh status
#
# Cloud-side reminder (the script cannot do this for you): open ingress in the
# provider firewall (OCI Security List / NSG) for BOTH udp/51820 and udp/443 (the
# tunnel and its alternate — the box dials the one it was configured with, so the
# other being closed strands it), plus tcp/{80,443,8089,8443,8446} and, if you
# stream, tcp/{8554,8322} + udp/8890. The setup run prints the exact list at the
# end. (The :5099 prober is tunnel-only since v10.1.3 — no cloud ingress.)

set -euo pipefail

WG_IF="wg0"
# Field-proven default (2026-07-07, fire-station Starlink): restrictive guest networks
# filter uncommon high UDP ports (51820) but pass UDP 443 — it looks like HTTPS/QUIC.
# 443 is the portable-survivor default; override with WG_PORT=51820 on permissive networks.
WG_PORT="${WG_PORT:-443}"
# The relay serves BOTH udp ports and redirects the alternate to the live one, so a
# box can switch without touching the cloud firewall. Defined here (not inside
# apply_forward_rules) because the UDP forward loop has to exclude both.
WG_ALT_PORT=$([ "${WG_PORT}" = "443" ] && echo 51820 || echo 443)
WG_NET="172.31.99.0/24"          # deliberately NOT in 100.64/10 — must never collide with carrier CGNAT space
ANCHOR_WG_IP="172.31.99.1"
BOX_WG_IP="172.31.99.2"
TAK_PORTS="${TAK_PORTS:-8089 8443 8446}"   # streaming / Marti+WebTAK / cert enrollment
WEB_PORTS="${WEB_PORTS:-80 443}"           # Caddy: Let's Encrypt ACME challenge + all web UIs
                                           # (Portal, Authentik, CloudTAK, console). Without these a
                                           # relayed box can never get a cert or serve the web side.
# v10.1.10: MediaMTX video. The configurator offers RTSP, RTSPS and SRT, so a relayed
# box carries all three.
MEDIA_PORTS="${MEDIA_PORTS:-8554 8322}"    # 8554 RTSP · 8322 RTSPS
# v10.1.28: EUD Remote Assist. CoTURN listens on 3479 (the Remote-Assist fleet
# constant — 3478 is NetBird's) for TCP and UDP, and relays the actual media over
# the UDP range pinned in our turnserver.conf (min-port=50000/max-port=50050).
# Without these a relayed box can run Remote Assist locally but no remote peer can
# ever complete NAT traversal through the relay.
# v10.1.52 (GH #62): 8448 is the EUD Remote Assist DEVICE API — the port the
# enrolment QR itself encodes (PUBLIC_BASE_URL=https://<host>:8448). It was opened in
# the box firewall and baked into the QR, but named in NO forward list here, so on a
# relayed box the phone dialled a port the relay never forwarded and reported only
# "Unable to connect". The admin portal is on 443 and worked throughout, which is what
# made it look like a device or app problem. Reported by Eggman1414, who diagnosed it
# to this script and fixed it by hand with the equivalent DNAT + FORWARD pair.
#
# Note this is a DIFFERENT QR from ATAK/iTAK certificate enrolment (8446, in TAK_PORTS
# above and forwarded since day one). Both are "scan a QR to enrol", which is why a
# relay walkthrough that exercised 8446 gave no signal about 8448.
RA_PORTS="${RA_PORTS:-3479 8448}"          # 3479 CoTURN STUN/TURN control · 8448 device API (QR target)
RA_UDP_RANGE="${RA_UDP_RANGE:-50000:50050}"  # CoTURN relayed media (pinned range)
# v10.1.28: the console's own port, so a relayed box has the SAME direct-IP
# backdoor every other box has (README "Recovery / backdoor"). Not forwarding it
# gave relayed boxes a quietly different security posture from the rest of the
# fleet — and made the documented recovery path impossible on exactly the boxes
# least able to fall back on anything else. Parity is the rule: open on a Standard
# box, closed by Hardening W1, which drops it at the box's own firewall whether it
# arrives over the tunnel or off the LAN.
CONSOLE_PORT="${CONSOLE_PORT:-5001}"       # infra-TAK console (W1 closes it box-side)
FWD_PORTS="$WEB_PORTS $TAK_PORTS $MEDIA_PORTS $RA_PORTS $CONSOLE_PORT"   # TCP forwards
# UDP forwards. SRT is UDP by protocol design, and until v10.1.10 this script only ever
# wrote `-p tcp` rules — which made SRT look like something a relay fundamentally could
# not carry. It isn't: DNAT handles UDP, the MASQUERADE and ESTABLISHED/RELATED rules
# below are protocol-agnostic, and WireGuard carries UDP natively. It was simply never
# written. RTSP's UDP transport (8000/8001) stays out on purpose — our MediaMTX ships
# `rtspTransports: [tcp]`, so no client negotiates it.
UDP_FWD_PORTS="${UDP_FWD_PORTS:-8890 3479}"   # 8890 SRT · 3479 CoTURN control
PROBER_PORT="5099"
PROBER_DIR="/opt/takwerx-prober"
PROBER_TOKEN_FILE="/etc/takwerx-prober.token"
WG_DIR="/etc/wireguard"

[ "$(id -u)" = "0" ] || { echo "Run as root (sudo)."; exit 1; }

pkg_install() {
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q "$@"
    else
        echo "No apt-get or dnf found — unsupported base image."; exit 1
    fi
}

public_ip() {
    curl -s4 --max-time 8 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'
}

# Insert an iptables rule only if it is not already present (idempotent re-runs).
ipt_ensure() {
    local table="$1"; shift
    if ! iptables -t "$table" -C "$@" 2>/dev/null; then
        iptables -t "$table" -I "$@"
    fi
}

persist_iptables() {
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    elif command -v service >/dev/null 2>&1 && [ -f /etc/sysconfig/iptables ]; then
        service iptables save >/dev/null 2>&1 || true
    fi
}

apply_forward_rules() {
    # DNAT the TAK ports to the box's overlay IP. MASQUERADE on the tunnel so the
    # return path works without policy routing on the box. Known v1 tradeoff: TAK
    # sees the anchor's overlay IP as the client source, not the client's real IP.
    for p in $FWD_PORTS; do
        ipt_ensure nat PREROUTING -p tcp --dport "$p" -j DNAT --to-destination "${BOX_WG_IP}:${p}"
        # Oracle images ship a FORWARD chain ending in REJECT — insert, don't append.
        ipt_ensure filter FORWARD -d "$BOX_WG_IP" -p tcp --dport "$p" -j ACCEPT
    done
    # UDP forwards (SRT). Guarded against the WireGuard ports: DNAT'ing the port the
    # tunnel itself listens on would send the dial-in down the tunnel it is trying to
    # establish and strand the relay.
    for p in $UDP_FWD_PORTS; do
        if [ "$p" = "$WG_PORT" ] || [ "$p" = "$WG_ALT_PORT" ]; then
            echo "  ⚠ skipping UDP $p — that is the WireGuard tunnel port"
            continue
        fi
        ipt_ensure nat PREROUTING -p udp --dport "$p" -j DNAT --to-destination "${BOX_WG_IP}:${p}"
        ipt_ensure filter FORWARD -d "$BOX_WG_IP" -p udp --dport "$p" -j ACCEPT
    done
    # UDP RANGE forwards (CoTURN relayed media). A range needs a PORT-LESS DNAT
    # target: `--to-destination IP:min-max` remaps to an arbitrary port inside the
    # range, which breaks TURN — the peer must reach the exact port CoTURN handed
    # out in its allocation. `--to-destination IP` with no port preserves the
    # original destination port, which is what a media relay requires.
    for r in $RA_UDP_RANGE; do
        ipt_ensure nat PREROUTING -p udp --dport "$r" -j DNAT --to-destination "$BOX_WG_IP"
        ipt_ensure filter FORWARD -d "$BOX_WG_IP" -p udp --dport "$r" -j ACCEPT
    done
    ipt_ensure nat POSTROUTING -o "$WG_IF" -d "$BOX_WG_IP" -j MASQUERADE
    ipt_ensure filter FORWARD -s "$BOX_WG_IP" -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Anchor-local inbound: WireGuard dial-in (Oracle INPUT chain also ends in REJECT).
    ipt_ensure filter INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    # v10.1.3: the prober is reachable ONLY over the tunnel (it binds the wg0 overlay
    # IP) — accept on wg0 and strip the public accept that earlier bootstraps added.
    ipt_ensure filter INPUT -i "$WG_IF" -p tcp --dport "$PROBER_PORT" -j ACCEPT
    iptables -t filter -D INPUT -p tcp --dport "$PROBER_PORT" -j ACCEPT 2>/dev/null || true
    # Serve WireGuard on BOTH udp/443 and udp/51820, whichever is primary: cellular
    # carriers run QUIC-aware middleboxes that eat non-QUIC udp/443 return traffic
    # (field-hit 2026-07-11: AT&T hotspot — box's initiations arrived, anchor's
    # responses never delivered; the identical exchange works on udp/51820), while
    # some restrictive venue firewalls allow ONLY 443. Redirect the alternate port
    # to the primary so a box can use either endpoint port without reprovisioning.
    ipt_ensure filter INPUT -p udp --dport "$WG_ALT_PORT" -j ACCEPT
    ipt_ensure nat PREROUTING -p udp --dport "$WG_ALT_PORT" -j REDIRECT --to-ports "$WG_PORT"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ufw allow "${WG_PORT}/udp" >/dev/null
        ufw allow "${WG_ALT_PORT}/udp" >/dev/null
        ufw delete allow "${PROBER_PORT}/tcp" >/dev/null 2>&1 || true
        for p in $FWD_PORTS; do ufw allow "${p}/tcp" >/dev/null; done
        for p in $UDP_FWD_PORTS; do
            [ "$p" = "$WG_PORT" ] || [ "$p" = "$WG_ALT_PORT" ] || ufw allow "${p}/udp" >/dev/null
        done
        for r in $RA_UDP_RANGE; do ufw allow "${r}/udp" >/dev/null; done
    fi
    persist_iptables
}

write_prober() {
    mkdir -p "$PROBER_DIR"
    # v10.1.3: dedicated no-login system user — the prober never runs as root.
    id -u takwerx-prober >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin takwerx-prober
    if [ ! -s "$PROBER_TOKEN_FILE" ]; then
        head -c 24 /dev/urandom | base64 | tr -d '=+/' > "$PROBER_TOKEN_FILE"
    fi
    chown takwerx-prober "$PROBER_TOKEN_FILE"
    chmod 400 "$PROBER_TOKEN_FILE"
    cat > "$PROBER_DIR/prober.py" <<'PYEOF'
#!/usr/bin/env python3
"""takwerx VERIFY prober (v10.1.0 seed; v10.1.3 hardening) — answers 'can the public
internet TCP-connect to these ports on this host?' from the anchor's outside vantage.
GET /probe?host=<ip-or-fqdn>&ports=8089,8443,8446&token=<token>
Token-gated; ports restricted to the TAK/console set; targets restricted to publicly
routable addresses (a probe of metadata/RFC1918/overlay space answers a question the
prober exists to answer only about the public internet — and is an SSRF oracle);
binds the wg0 overlay IP, so only tunnel peers can reach it at all."""
import hmac, ipaddress, json, os, re, socket, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = open('/etc/takwerx-prober.token').read().strip()
ALLOWED_PORTS = {80, 443, 5001, 8089, 8443, 8446}
HOST_RE = re.compile(r'^[A-Za-z0-9.\-]{1,253}$')

def resolve_public(host):
    """Resolve once and return the first address, or None unless EVERY resolved
    address is publicly routable (kills 169.254.169.254, RFC1918, CGNAT, loopback,
    the WG overlay — and multi-record rebinding tricks). Connect to the returned
    IP, never re-resolve the name."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    addrs = [i[4][0] for i in infos]
    if not addrs:
        return None
    for a in addrs:
        if not ipaddress.ip_address(a).is_global:
            return None
    return addrs[0]

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path != '/probe':
            return self._send(404, {'error': 'not found'})
        q = parse_qs(u.query)
        token = (q.get('token') or [''])[0]
        if not hmac.compare_digest(token, TOKEN):
            time.sleep(1)
            return self._send(403, {'error': 'bad token'})
        host = (q.get('host') or [''])[0]
        if not HOST_RE.match(host):
            return self._send(400, {'error': 'bad host'})
        target = resolve_public(host)
        if not target:
            return self._send(400, {'error': 'host not publicly routable'})
        try:
            ports = [int(p) for p in (q.get('ports') or [''])[0].split(',') if p][:8]
        except ValueError:
            return self._send(400, {'error': 'bad ports'})
        if not ports or any(p not in ALLOWED_PORTS for p in ports):
            return self._send(400, {'error': 'ports restricted to %s' % sorted(ALLOWED_PORTS)})
        results = {}
        for p in ports:
            try:
                with socket.create_connection((target, p), timeout=4):
                    results[str(p)] = 'green'
            except OSError as ex:
                results[str(p)] = 'red: %s' % getattr(ex, 'strerror', str(ex))
        self._send(200, {'host': host, 'results': results, 'vantage': 'anchor-public'})

if __name__ == '__main__':
    ThreadingHTTPServer((os.environ.get('PROBER_BIND', '127.0.0.1'), 5099), H).serve_forever()
PYEOF
    chmod 755 "$PROBER_DIR/prober.py"
    # v10.1.3: non-root, tunnel-only. Binds the wg0 overlay IP (After= the tunnel;
    # Restart=always rides out a bind race at boot). TLS stays a future build.
    cat > /etc/systemd/system/takwerx-prober.service <<EOF
[Unit]
Description=takwerx VERIFY reachability prober
After=network-online.target wg-quick@${WG_IF}.service

[Service]
User=takwerx-prober
Environment=PROBER_BIND=${ANCHOR_WG_IP}
ExecStart=/usr/bin/python3 $PROBER_DIR/prober.py
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now takwerx-prober >/dev/null
    systemctl restart takwerx-prober >/dev/null 2>&1 || true
}

cmd_setup() {
    echo "── anchor setup ──"
    pkg_install wireguard-tools curl || pkg_install wireguard curl
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-takwerx-anchor.conf
    sysctl -p /etc/sysctl.d/99-takwerx-anchor.conf >/dev/null
    mkdir -p "$WG_DIR"; chmod 700 "$WG_DIR"
    if [ ! -s "$WG_DIR/anchor.key" ]; then
        (umask 077; wg genkey > "$WG_DIR/anchor.key")
        wg pubkey < "$WG_DIR/anchor.key" > "$WG_DIR/anchor.pub"
    fi
    if [ ! -s "$WG_DIR/$WG_IF.conf" ]; then
        cat > "$WG_DIR/$WG_IF.conf" <<EOF
[Interface]
Address = ${ANCHOR_WG_IP}/24
ListenPort = ${WG_PORT}
MTU = 1280
PrivateKey = $(cat "$WG_DIR/anchor.key")
EOF
        chmod 600 "$WG_DIR/$WG_IF.conf"
    fi
    systemctl enable --now "wg-quick@${WG_IF}" >/dev/null
    apply_forward_rules
    write_prober
    # Persist the DNAT/forward/INPUT rules across reboots (Oracle images don't by default).
    if ! command -v netfilter-persistent >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive pkg_install iptables-persistent >/dev/null 2>&1 || true
    fi
    persist_iptables
    local pub_ip; pub_ip=$(public_ip)
    echo ""
    echo "✓ Anchor is up.  Public IP: ${pub_ip}"
    echo "  WireGuard public key : $(cat "$WG_DIR/anchor.pub")"
    echo "  Forwarded ports      : tcp ${FWD_PORTS} · udp ${UDP_FWD_PORTS} → ${BOX_WG_IP} (kernel DNAT, no TLS in path)"
    echo "  VERIFY prober        : http://${ANCHOR_WG_IP}:${PROBER_PORT}/probe (tunnel-only)  token: $(cat "$PROBER_TOKEN_FILE")"
    echo ""
    echo "NEXT: 1) open udp/{${WG_PORT},${WG_ALT_PORT},${UDP_FWD_PORTS// /,}} AND tcp/{${FWD_PORTS// /,}} in the cloud"
    echo "         provider firewall (OCI NSG / Security List) — the script cannot reach that."
    echo "         ⚠ udp/443 AND tcp/443 are BOTH needed — different protocols (tunnel vs HTTPS)."
    echo "         ⚠ OCI TRAP: put the port in DESTINATION Port Range, leave SOURCE blank."
    echo "         A port in the Source field matches nothing and silently drops all traffic."
    echo "      2) on the infra-TAK box: wg genkey, then run:  $0 add-box <box-public-key>"
}

cmd_add_box() {
    local box_pub="${1:-}"
    [ -n "$box_pub" ] || { echo "Usage: $0 add-box <box-wireguard-public-key>"; exit 1; }
    wg set "$WG_IF" peer "$box_pub" allowed-ips "${BOX_WG_IP}/32"
    if ! grep -q "$box_pub" "$WG_DIR/$WG_IF.conf"; then
        cat >> "$WG_DIR/$WG_IF.conf" <<EOF

[Peer]
PublicKey = ${box_pub}
AllowedIPs = ${BOX_WG_IP}/32
EOF
    fi
    local pub_ip; pub_ip=$(public_ip)
    echo "✓ Box peer added. Paste this on the infra-TAK box as /etc/wireguard/wg0.conf:"
    echo ""
    echo "[Interface]"
    echo "Address = ${BOX_WG_IP}/24"
    echo "PrivateKey = <the box private key — never leaves the box>"
    echo ""
    echo "[Peer]"
    echo "PublicKey = $(cat "$WG_DIR/anchor.pub")"
    echo "Endpoint = ${pub_ip}:${WG_PORT}"
    echo "AllowedIPs = ${ANCHOR_WG_IP}/32"
    echo "PersistentKeepalive = 25"
    echo ""
    echo "then:  systemctl enable --now wg-quick@wg0   (on the box)"
}

cmd_status() {
    wg show "$WG_IF" || true
    echo ""
    echo "DNAT forwards:"
    iptables -t nat -S PREROUTING | grep DNAT || echo "  (none)"
    echo ""
    echo "prober: $(systemctl is-active takwerx-prober 2>/dev/null)"
}

case "${1:-}" in
    setup)   cmd_setup ;;
    add-box) cmd_add_box "${2:-}" ;;
    status)  cmd_status ;;
    *)       echo "Usage: $0 {setup|add-box <pubkey>|status}"; exit 1 ;;
esac
