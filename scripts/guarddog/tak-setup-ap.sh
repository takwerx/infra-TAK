#!/bin/bash
# infra-TAK Setup AP engine — v10.1.0 Leg 6b.
#
# When the box has no way onto the internet, it broadcasts its OWN wifi
# (`infraTAK-setup-<host>`, WPA2) so an operator can join from a laptop, land on
# the infra-TAK console login (captive redirect), and use the WiFi card to pick a
# real network. The box has ONE radio: broadcasting the AP means it is NOT a wifi
# client, so this is only ever used when there is no uplink to lose.
#
# Usage: tak-setup-ap.sh {start|stop|status}
#
# CARDINAL RULE — never strand the box: `start` must, on ANY failure, tear the AP
# down and hand the radio back to the normal client stack (so a known network can
# re-join). The `trap` below guarantees that. `stop` always restores the client.
#
# Multiplatform:
#   - NetworkManager present (RHEL / any nmcli box): `nmcli device wifi hotspot`
#     does AP + DHCP in one managed step; stop = bring the hotspot down + let NM
#     re-autoconnect. Preferred when available (fewer moving parts).
#   - netplan / no NM (Ubuntu server): hostapd (AP) + dnsmasq (DHCP + captive DNS),
#     with the client wpa_supplicant released first and `netplan apply` to restore.
set -u

STATE_DIR="/var/lib/takguard"
CONF="$STATE_DIR/setup-ap.conf"          # written by the console: SSID_SUFFIX/PASS/etc.
ACTIVE_FLAG="$STATE_DIR/setup-ap.active"
AP_IP="10.42.0.1"
AP_CIDR="24"
AP_RANGE_LO="10.42.0.50"
AP_RANGE_HI="10.42.0.150"
HOSTAPD_CONF="/tmp/takwerx-hostapd.conf"
DNSMASQ_CONF="/tmp/takwerx-dnsmasq-ap.conf"
LOG="/var/log/takguard/setup-ap.log"
# CONSOLE_PORT is written into the conf by the console (which knows CONFIG_DIR —
# it is NOT reliably /root/.config on non-root boxes; N1). Default 5001.
CONSOLE_PORT="5001"

mkdir -p "$STATE_DIR" /var/log/takguard 2>/dev/null
log(){ echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" >> "$LOG"; }

# ---- config (SSID + password) ----------------------------------------------
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"
AP_SSID="infraTAK-setup-${HOSTNAME_SHORT}"
AP_PASS=""
# Parse the conf by ASSIGNMENT, never `source` it — the values are operator-typed
# and sourcing would execute shell metacharacters as root (finding D). cut -d= -f2-
# keeps '=' inside a value intact; the value is assigned verbatim, never evaluated.
conf_get(){ grep -m1 "^$1=" "$CONF" 2>/dev/null | cut -d= -f2-; }
if [ -r "$CONF" ]; then
    _s="$(conf_get SETUP_AP_SSID)"; [ -n "$_s" ] && AP_SSID="$_s"
    _p="$(conf_get SETUP_AP_PASS)"; [ -n "$_p" ] && AP_PASS="$_p"
    _cp="$(conf_get SETUP_AP_CONSOLE_PORT)"
    case "$_cp" in ''|*[!0-9]*) : ;; *) CONSOLE_PORT="$_cp" ;; esac
    CONSOLE_URL="$(conf_get SETUP_AP_CONSOLE_URL)"
fi
# Where the captive page sends the laptop. If the box has a trusted cert, this is
# the console's Caddy vhost by NAME (the AP wildcard DNS resolves it to the box →
# Caddy serves the real cert → no warning). Otherwise the box's own self-signed
# https (accept-the-warning floor for fresh/no-domain boxes).
CONSOLE_URL="${CONSOLE_URL:-}"
# The OFFLINE setup AP cannot do SSO (Caddy :443 -> Authentik forward_auth hangs with
# no internet) and the full dashboard crawls offline (dozens of subprocess probes). So
# send the laptop STRAIGHT to the light /connectivity page on the console's OWN port
# (bypasses Caddy/Authentik), addressed by the FQDN by name when we have one (the AP
# wildcard DNS resolves it to the box) so it is still "the domain name". Self-signed
# cert on :CONSOLE_PORT -> accept-the-warning floor (a valid-cert + no-SSO path would
# need a Caddy setup-vhost, tracked separately). Field-hit 2026-07-10 home AP test.
NEXT_PATH="/login?next=/connectivity"
if [ -n "$CONSOLE_URL" ]; then
    _fqdn_host="${CONSOLE_URL#*://}"; _fqdn_host="${_fqdn_host%%/*}"; _fqdn_host="${_fqdn_host%%:*}"
    OPEN_URL="https://${_fqdn_host}:${CONSOLE_PORT}${NEXT_PATH}"
else
    OPEN_URL="https://${AP_IP}:${CONSOLE_PORT}${NEXT_PATH}"
fi
OPEN_TRUSTED=0
# WPA2 requires 8..63 chars. If unset/short, generate a RANDOM PSK once and persist
# it (root-600) — NEVER derive it from the hostname (finding B: the hostname is
# advertised in the SSID, so a host-derived key is effectively public). The console
# reveals this generated key so the operator can type it.
if [ "${#AP_PASS}" -lt 8 ]; then
    AP_PASS="$(tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 14)"
    [ "${#AP_PASS}" -ge 8 ] || AP_PASS="infratak-$(date +%s | tail -c 6)"
    _auto="$(conf_get SETUP_AP_AUTO)"; [ -n "$_auto" ] || _auto=1
    _cport="$(conf_get SETUP_AP_CONSOLE_PORT)"; [ -n "$_cport" ] || _cport="$CONSOLE_PORT"
    umask 077
    { echo "# infra-TAK Setup AP config (password auto-generated $(date -u +%FT%TZ))"
      echo "SETUP_AP_SSID=$AP_SSID"
      echo "SETUP_AP_PASS=$AP_PASS"
      echo "SETUP_AP_CONSOLE_PORT=$_cport"
      echo "SETUP_AP_AUTO=$_auto"
    } > "$CONF" 2>/dev/null || true
    chmod 600 "$CONF" 2>/dev/null || true
fi

wifi_iface(){
    for n in $(ls /sys/class/net 2>/dev/null); do
        [ -d "/sys/class/net/$n/wireless" ] && { echo "$n"; return; }
    done
    command -v iw >/dev/null 2>&1 && iw dev 2>/dev/null | awk '/Interface/{print $2; exit}'
}
IFACE="$(wifi_iface)"

have_nm(){ command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; }

# ---- capability guard -------------------------------------------------------
ap_capable(){
    command -v iw >/dev/null 2>&1 || return 0   # can't check → let it try
    iw list 2>/dev/null | awk '/Supported interface modes/{f=1} f&&/\* AP$/{print;exit}' | grep -q AP
}

# ---- restore the client (the never-strand path) -----------------------------
restore_client(){
    log "restore_client: handing radio back to the client stack"
    rm -f "$ACTIVE_FLAG"
    pkill -f "hostapd $HOSTAPD_CONF" 2>/dev/null
    pkill -f "dnsmasq.*$DNSMASQ_CONF" 2>/dev/null
    # drop the captive :80 redirect responder + firewall rule
    pkill -f 'takwerx-captive' 2>/dev/null
    if [ -n "$IFACE" ]; then
        iptables -t nat -D PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-ports 8088 2>/dev/null
        # Tear down the interface-isolation rules added in apply_isolation (finding A).
        while iptables -D INPUT -i "$IFACE" -j takwerx_setupap 2>/dev/null; do :; done
        while iptables -D FORWARD -i "$IFACE" -j DROP 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -i "$IFACE" -j DROP 2>/dev/null; do :; done
        iptables -F takwerx_setupap 2>/dev/null
        iptables -X takwerx_setupap 2>/dev/null
        # RHEL/firewalld: remove the runtime captive/console port opens added in
        # apply_isolation (the iface is still in its zone here — nmcli down is below).
        if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
            # HARDCODED nm-shared — never --get-zone-of-interface here: on teardown it
            # can resolve to 'public' and this --remove-port would then strip the
            # console's legit 80/443/5001 off the PUBLIC zone (field-hit 2026-07-11,
            # bricked console/FQDN access). The AP's ports only ever live in nm-shared.
            FWZONE=nm-shared
            for _p in 80 443 8088 "$CONSOLE_PORT"; do
                firewall-cmd --zone="$FWZONE" --remove-port="${_p}/tcp" >>"$LOG" 2>/dev/null || true
            done
            firewall-cmd --zone="$FWZONE" --remove-forward-port="port=80:proto=tcp:toport=8088:toaddr=${AP_IP}" >>"$LOG" 2>/dev/null || true
        fi
        ip addr flush dev "$IFACE" 2>/dev/null
        ip link set "$IFACE" down 2>/dev/null
    fi
    if have_nm; then
        nmcli connection down takwerx-hotspot 2>/dev/null
        nmcli radio wifi on 2>/dev/null
        # NM re-autoconnects known profiles on its own.
    else
        [ -n "$IFACE" ] && ip link set "$IFACE" up 2>/dev/null
        netplan apply 2>>"$LOG" || log "restore_client: netplan apply returned non-zero"
    fi
}

# Firewall-isolate the AP interface (finding A). A device that joins the setup AP
# must reach ONLY the console login, the captive responder, and DHCP/DNS on the box
# — never SSH, TAK (native OR Docker-published), CloudTAK, MediaMTX, etc. Covers all
# three packet paths:
#   INPUT       — host-local services (native SSH/TAK/console)
#   FORWARD     — anything routed off the AP interface (blocks reaching containers,
#                 and there's no upstream anyway — the setup AP is not an internet AP)
#   DOCKER-USER — Docker's own hook; container-published ports DNAT past INPUT
# Plus the captive :80→:8088 redirect + responder. Applies to NM and hostapd alike.
apply_isolation(){
    iptables -N takwerx_setupap 2>/dev/null || iptables -F takwerx_setupap
    iptables -A takwerx_setupap -p udp --dport 67 -j ACCEPT               # DHCP
    iptables -A takwerx_setupap -p udp --dport 53 -j ACCEPT               # captive DNS
    iptables -A takwerx_setupap -p tcp --dport 53 -j ACCEPT
    iptables -A takwerx_setupap -p tcp --dport 80 -j ACCEPT               # → REDIRECT :8088
    iptables -A takwerx_setupap -p tcp --dport 8088 -j ACCEPT             # captive responder
    iptables -A takwerx_setupap -p tcp --dport "$CONSOLE_PORT" -j ACCEPT  # console login (self-signed fallback)
    iptables -A takwerx_setupap -p tcp --dport 443 -j ACCEPT             # Caddy (trusted-cert console vhost)
    iptables -A takwerx_setupap -p icmp -j ACCEPT
    iptables -A takwerx_setupap -j DROP                                   # everything else
    iptables -I INPUT -i "$IFACE" -j takwerx_setupap
    # Block everything routed FROM the AP interface (containers + no-internet-by-design).
    iptables -I FORWARD -i "$IFACE" -j DROP
    # Docker publishes container ports via DNAT that bypasses INPUT; DOCKER-USER is the
    # sanctioned hook and is consulted before the per-container ACCEPTs. No-op if absent.
    iptables -I DOCKER-USER -i "$IFACE" -j DROP 2>/dev/null || true

    # RHEL/firewalld: the raw iptables above is a no-op under nftables, AND NM's
    # method=shared drops the AP iface into the `nm-shared` zone (services: dhcp dns
    # ssh + a priority-32767 reject) — so the captive + console HTTP ports are
    # REJECTED and nothing HTTP is reachable on the AP (field-hit 2026-07-10, home
    # Setup-AP test: DHCP worked, http/5001 refused). Open them on the AP iface's
    # firewalld zone at runtime (cleared on reload/reboot; removed on AP stop below)
    # — the firewalld equivalent of the iptables allowlist above. Isolation still
    # holds: only these ports are opened, and the zone's default-reject stands.
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        # HARDCODED nm-shared — the NM method=shared AP interface lives in firewalld's
        # nm-shared zone. Do NOT derive the zone from the interface: during teardown
        # `--get-zone-of-interface` can resolve to 'public', and then restore_client's
        # `--remove-port` strips the console's legit 80/443/5001 off the PUBLIC zone —
        # bricking console + FQDN access mid AP cycle (field-hit 2026-07-11).
        FWZONE=nm-shared
        for _p in 80 443 8088 "$CONSOLE_PORT"; do
            firewall-cmd --zone="$FWZONE" --add-port="${_p}/tcp" >>"$LOG" 2>&1 || true
        done
        # Captive redirect, RHEL/nftables equivalent of the raw `iptables REDIRECT`
        # below (which is a no-op under firewalld): DNAT AP-client :80 -> the captive
        # responder :8088 so the OS captive-check (captive.apple.com etc., pointed at us
        # by the dnsmasq wildcard) lands on the dumb 200 page and the "join" popup fires.
        # Without it, :80 is Caddy, which answers with a redirect and SUPPRESSES the
        # popup (field gap 2026-07-11 vs cfd2474's hostapd+iptables DNAT that pops
        # reliably on Debian). Scoped to nm-shared so only AP clients are affected.
        firewall-cmd --zone="$FWZONE" --add-forward-port="port=80:proto=tcp:toport=8088:toaddr=${AP_IP}" >>"$LOG" 2>&1 || true
        log "apply_isolation: opened captive/console ports + :80->:8088 captive DNAT on firewalld zone $FWZONE"
    fi

    # captive :80 responder on :8088; redirect AP :80 to it. Serves a real HTML
    # landing page (200, tap-through button) — macOS's Captive Network Assistant
    # renders it (it silently ignores a 302 to self-signed HTTPS). The button points
    # at OPEN_URL: the trusted Caddy vhost by name when the box has a real cert (no
    # warning), else the box's self-signed https (accept-the-warning floor).
    iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-ports 8088
    CAP_AP_IP="$AP_IP" CAP_URL="$OPEN_URL" CAP_IPURL="https://${AP_IP}:${CONSOLE_PORT}${NEXT_PATH}" CAP_TRUSTED="$OPEN_TRUSTED" setsid bash -c "exec -a takwerx-captive python3 - <<'PY'
import os, http.server, socketserver
PORT = 8088
IP = os.environ.get('CAP_AP_IP', '10.42.0.1')
URL = os.environ.get('CAP_URL', 'https://%s:5001/' % IP)
IPURL = os.environ.get('CAP_IPURL', 'https://%s:5001/' % IP)
TRUSTED = os.environ.get('CAP_TRUSTED', '0') == '1'
if TRUSTED:
    # Primary is the trusted Caddy URL (no warning); keep the self-signed IP as a
    # secondary fallback in case Caddy is momentarily unavailable.
    NOTE = ('<p>If the button doesn&#39;t load, try <code>%s</code> and accept the '
            'security warning.</p>' % IPURL)
else:
    NOTE = ('<p>If the button does nothing, open your browser and go to <code>%s</code> — '
            'accept the security warning (it is this box&#39;s own certificate).</p>' % URL)
PAGE = ('<!doctype html><html><head><meta charset=utf-8>'
        '<meta name=viewport content=\"width=device-width,initial-scale=1\">'
        '<title>infra-TAK setup</title>'
        '<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f1219;'
        'color:#f1f5f9;margin:0;padding:40px 22px;text-align:center}'
        'h1{font-size:20px;margin:0 0 6px}p{color:#94a3b8;font-size:14px;line-height:1.5;max-width:420px;margin:10px auto}'
        'a.btn{display:inline-block;margin-top:22px;background:#3b82f6;color:#fff;text-decoration:none;'
        'font-weight:600;font-size:16px;padding:14px 26px;border-radius:10px}'
        'code{background:#1e2736;padding:2px 7px;border-radius:5px;color:#cbd5e1}</style></head>'
        '<body><h1>infra-TAK setup</h1>'
        '<p>You are connected to this box&#39;s setup network. Open the console to choose a WiFi network for it to join.</p>'
        '<a class=btn href=\"%s\">Open setup console</a>%s'
        '</body></html>') % (URL, NOTE)
BODY = PAGE.encode()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        # Standard captive-portal contract: any request that is not for the portal
        # itself gets a 302 to the plain-http portal URL; only the portal URL serves
        # the landing page. Android needs the redirect as its portal signal — a
        # direct 200-with-body on its probe (Samsung sends plain 'GET /', not
        # generate_204) is classified as broken internet, NOT a portal, and no
        # sign-in flow appears (field-hit 2026-07-11, Galaxy Tab S8). iOS follows
        # the 302 to plain http and renders the landing page in CNA — only a 302
        # to self-signed httpS would suppress the popup.
        # Match the portal host:port EXACTLY. Samsung/Android-15 probes the bare
        # gateway (Host: 10.42.0.1, no port) and must be 302d like any foreign
        # host — a 200 there reads as broken-network, not portal (field-hit
        # 2026-07-11, Galaxy Tab S8: startswith(IP) served it the landing page and
        # no sign-in flow ever appeared). The redirect Location carries :8088, so
        # the follow-up request Hosts as portal and gets the page.
        # NOTE this python lives inside a double-quoted bash -c string: NO double
        # quotes, backticks, or dollar signs anywhere in this heredoc.
        host = s.headers.get('Host', '')
        if host != '%s:%d' % (IP, PORT):
            s.send_response(302)
            s.send_header('Location', 'http://%s:%d/' % (IP, PORT))
            s.send_header('Content-Length', '0')
            s.send_header('Cache-Control', 'no-store')
            s.end_headers()
            return
        # Request addressed to the portal itself: serve the landing page with 200
        # (a 200 'Success' body on the probe host would instead make the OS think
        # there's real internet and suppress the popup).
        s.send_response(200)
        s.send_header('Content-Type', 'text/html; charset=utf-8')
        s.send_header('Content-Length', str(len(BODY)))
        s.send_header('Cache-Control', 'no-store')
        s.end_headers()
        s.wfile.write(BODY)
    def log_message(s, *a): pass
socketserver.TCPServer.allow_reuse_address = True
# Bind the AP address only — never 0.0.0.0 (finding E).
socketserver.TCPServer((IP, PORT), H).serve_forever()
PY" >>"$LOG" 2>&1 &
}

start_ap(){
    [ -f "$ACTIVE_FLAG" ] && { log "start: AP already active"; echo "already-active"; return 0; }
    if [ -z "$IFACE" ]; then log "start: no wifi interface"; echo "no-wifi-interface"; return 2; fi
    if ! ap_capable; then log "start: radio has no AP mode"; echo "no-ap-mode"; return 3; fi
    log "start: bringing up AP ssid='$AP_SSID' iface='$IFACE' nm=$(have_nm && echo yes || echo no)"

    # ANY failure past this point restores the client and reports failure.
    trap 'log "start: FAILED — restoring client"; restore_client; echo "start-failed"; exit 9' ERR

    if have_nm; then
        # Rocky/RHEL images ship NM with ignore-carrier=* — an unplugged NIC keeps
        # its activation AND its metric-100 default route, blackholing all egress
        # even after a successful wifi join (field-hit 2026-07-11: OXFORD leased in
        # 2s post-Stop, tunnel dead until the cable returned). Assert carrier
        # honoring for ethernet (wifi semantics untouched). Root-side here because
        # the console broker deliberately cannot write /etc/NetworkManager. The
        # console's join path ALSO explicitly disconnects cable-less ethernet
        # (_conn_clear_dead_ethernet) — this conf is the boot-time belt.
        NMCARRIER="/etc/NetworkManager/conf.d/99-takwerx-ethernet-carrier.conf"
        if [ ! -f "$NMCARRIER" ]; then
            printf '[device-takwerx-ethernet-carrier]\nmatch-device=type:ethernet\nignore-carrier=no\n' > "$NMCARRIER"
            chmod 644 "$NMCARRIER"
            systemctl reload NetworkManager 2>/dev/null || true
            log "start: wrote $NMCARRIER (ethernet honors carrier loss)"
        fi
        set -e
        nmcli radio wifi on
        nmcli device disconnect "$IFACE" 2>/dev/null || true
        nmcli connection delete takwerx-hotspot 2>/dev/null || true
        # Write the profile keyfile directly (mode 600) rather than passing the PSK
        # on the nmcli command line — argv is world-readable via /proc/<pid>/cmdline
        # and the non-root console user could read the key during the modify window
        # (finding C). NM reads the psk from the 600 keyfile instead.
        NMCONN="/etc/NetworkManager/system-connections/takwerx-hotspot.nmconnection"
        umask 077
        cat > "$NMCONN" <<EOF
[connection]
id=takwerx-hotspot
type=wifi
interface-name=$IFACE
autoconnect=false

[wifi]
mode=ap
band=bg
# Pin a universally-legal 2.4GHz channel. Left unpinned, NM can pick ch 12/13
# (EU-only) and US-domain phones/tablets can't even SEE the setup SSID
# (field-hit 2026-07-11: Android tablet blind to the AP on ch 13). The hostapd
# path below already pins channel=6; keep the NM path identical.
channel=6
ssid=$AP_SSID

[wifi-security]
key-mgmt=wpa-psk
# pmf=1 (disable) keeps NM from advertising WPA3-SAE transition mode (it
# expands key-mgmt to 'WPA-PSK WPA-PSK-SHA256 SAE' otherwise). Older Android
# EUDs refuse to associate to transition-mode APs entirely (field-hit
# 2026-07-11: Android tablet 'tries' then drops back, zero frames reaching
# the AP). Pure WPA2-PSK is the compatibility floor every EUD speaks; fine
# for a short-lived, client-isolated provisioning AP. Matches the hostapd
# path (wpa=2, WPA-PSK, no ieee80211w).
pmf=1
psk=$AP_PASS

[ipv4]
method=shared

[ipv6]
method=ignore
EOF
        chmod 600 "$NMCONN"
        # NM method=shared serves DHCP + DNS via its own dnsmasq (the package is
        # pulled by the console before start, while the box was still online). Drop a
        # shared-dnsmasq wildcard so EVERY name — including the box FQDN — resolves to
        # the AP IP on the isolated setup net; that is what makes the captive/console
        # reachable BY NAME here, mirroring the hostapd path's `address=/#/AP_IP`.
        # NM includes /etc/NetworkManager/dnsmasq-shared.d/*.conf in the shared dnsmasq.
        mkdir -p /etc/NetworkManager/dnsmasq-shared.d
        printf 'address=/#/%s\n' "$AP_IP" > /etc/NetworkManager/dnsmasq-shared.d/50-takwerx-captive.conf
        chmod 644 /etc/NetworkManager/dnsmasq-shared.d/50-takwerx-captive.conf
        nmcli connection reload
        nmcli connection up takwerx-hotspot
        set +e
    else
        command -v hostapd  >/dev/null 2>&1 || { log "start: installing hostapd";  DEBIAN_FRONTEND=noninteractive apt-get install -y hostapd  >>"$LOG" 2>&1; }
        command -v dnsmasq  >/dev/null 2>&1 || { log "start: installing dnsmasq";  DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq  >>"$LOG" 2>&1; }
        # Mask the packaged units so they never auto-start on boot and fight our
        # script-managed instances. Debian ENABLES dnsmasq.service on install — on
        # the next reboot it would bind :53 on all interfaces before/against our
        # AP dnsmasq (bind-interfaces would then fail), and a stray hostapd.service
        # could seize the radio. We drive both by hand (hostapd -B / dnsmasq
        # --conf-file), so the distro units must stay inert. Idempotent; masking a
        # running unit also stops it. `mask --now` is systemd-native (Ubuntu/RHEL).
        systemctl disable --now dnsmasq.service 2>/dev/null || true
        systemctl disable --now hostapd.service 2>/dev/null || true
        systemctl mask dnsmasq.service hostapd.service 2>/dev/null || true
        set -e
        # release the client so hostapd can own the radio
        systemctl stop "wpa_supplicant@${IFACE}.service" 2>/dev/null || true
        pkill -f "wpa_supplicant.*${IFACE}" 2>/dev/null || true
        ip addr flush dev "$IFACE"
        ip link set "$IFACE" down; ip link set "$IFACE" up
        ip addr add "${AP_IP}/${AP_CIDR}" dev "$IFACE"

        cat > "$HOSTAPD_CONF" <<EOF
interface=$IFACE
driver=nl80211
ssid=$AP_SSID
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=$AP_PASS
ignore_broadcast_ssid=0
EOF
        chmod 600 "$HOSTAPD_CONF"

        cat > "$DNSMASQ_CONF" <<EOF
interface=$IFACE
bind-interfaces
except-interface=lo
dhcp-range=${AP_RANGE_LO},${AP_RANGE_HI},255.255.255.0,12h
dhcp-option=3,${AP_IP}
dhcp-option=6,${AP_IP}
address=/#/${AP_IP}
no-resolv
no-hosts
EOF
        chmod 600 "$DNSMASQ_CONF"

        # hostapd FIRST (brings the radio into AP mode + starts beaconing), give it
        # a moment to settle, THEN dnsmasq binds DHCP/DNS to the now-live AP
        # interface. Starting dnsmasq before the AP was a latent ordering bug.
        hostapd -B "$HOSTAPD_CONF" >>"$LOG" 2>&1
        sleep 2
        dnsmasq --conf-file="$DNSMASQ_CONF" --pid-file=/tmp/takwerx-dnsmasq-ap.pid
        set +e
    fi

    # Isolation + captive apply to BOTH the NM and hostapd paths (finding A re-review:
    # the NM/RHEL path had none, and Docker-published ports route via FORWARD, not
    # INPUT). Run AFTER the AP is up regardless of how it was created.
    apply_isolation

    trap - ERR
    touch "$ACTIVE_FLAG"
    log "start: AP UP ssid='$AP_SSID' ip=$AP_IP"
    echo "started"
}

case "${1:-}" in
    start)  start_ap ;;
    stop)   restore_client; log "stop: done"; echo "stopped" ;;
    status)
        if [ -f "$ACTIVE_FLAG" ]; then
            echo "active ssid=$AP_SSID ip=$AP_IP"
        else
            echo "inactive"
        fi
        ;;
    *) echo "usage: $0 {start|stop|status}"; exit 1 ;;
esac
