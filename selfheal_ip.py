#!/usr/bin/env python3
"""infra-TAK — server_ip self-heal (v10.0.4).

Runs as the console systemd unit's ExecStartPre, i.e. BEFORE gunicorn binds. A
cloud box (AWS especially) is handed a NEW auto-assigned public IP on every
stop/start; settings.server_ip then points at a dead address, which (in IP-only
mode) breaks the self-signed console cert SAN and pins UFW/firewalld rules to the
old IP. This re-detects the box's current IP and, only when it has CHANGED,
repairs settings + cert + firewall scoping.

Design rules (see docs/PLAN-v10.0.4-network-posture.md):
  * STDLIB ONLY — never imports app.py, so a broken app import can't strand the
    pre-start hook. The unit references it with a leading '-' so any failure here
    is non-fatal and the console still starts.
  * Acts ONLY on a genuine change: detected IP must be a valid IPv4, differ from
    the stored value, AND the stored value must be non-empty (a first-fill is the
    job of app.py's _heal_settings_core_keys, not this). Never blows away a good
    cert because a metadata probe blipped.
  * settings.json write is atomic (tempfile + os.replace) and reads the FULL dict
    first, so no core key is ever dropped (the v10.0.3 torn-write shield, in
    spirit) — see memory settings-json-tornwrite-race.
  * Cert regen is IP-only-mode only. In FQDN mode Caddy/Let's Encrypt owns the
    cert; we still refresh server_ip + firewall scoping.
  * Firewall rescope drives ufw OR firewalld, mirroring the _fw_* shims and the
    rule formats written by /api/firewall/restrict-source in app.py.
"""
import os
import re
import sys
import json
import ipaddress
import subprocess
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.environ.get('CONFIG_DIR') or os.path.join(BASE_DIR, '.config')
SETTINGS_FILE = os.path.join(CONFIG_DIR, 'settings.json')
SSL_DIR = os.path.join(CONFIG_DIR, 'ssl')
_IPV4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def log(msg):
    print(f"[selfheal-ip] {msg}", flush=True)


def _valid_routable_ipv4(ip):
    """True for a syntactically-valid IPv4 that is a plausible server_ip. Private
    is allowed (on-prem LAN boxes legitimately use a `hostname -I` address);
    loopback / link-local (incl. 169.254 metadata) / multicast / unspecified are
    rejected so a failed probe never poisons settings."""
    if not ip or not _IPV4.match(ip):
        return False
    try:
        a = ipaddress.IPv4Address(ip)
    except Exception:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_multicast
                or a.is_unspecified or a.is_reserved)


def _curl(args, timeout=3):
    try:
        r = subprocess.run(['curl', '-s', '--max-time', str(timeout)] + args,
                           capture_output=True, text=True, timeout=timeout + 2)
        return (r.stdout or '').strip()
    except Exception:
        return ''


def detect_ip():
    """Current public/host IP, cloud-aware. Mirrors start.sh detect_server_ip()
    order: Azure IMDS → AWS IMDSv2 → AWS IMDSv1 → ipify/ifconfig → hostname -I."""
    ip = _curl(['-H', 'Metadata: true',
                'http://169.254.169.254/metadata/instance/network/interface/0/'
                'ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text'], 2)
    if _IPV4.match(ip):
        return ip
    tok = ''
    try:
        r = subprocess.run(['curl', '-s', '--max-time', '2', '-X', 'PUT',
                            '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 60',
                            'http://169.254.169.254/latest/api/token'],
                           capture_output=True, text=True, timeout=4)
        tok = (r.stdout or '').strip()
    except Exception:
        tok = ''
    if tok:
        ip = _curl(['-H', f'X-aws-ec2-metadata-token: {tok}',
                    'http://169.254.169.254/latest/meta-data/public-ipv4'], 2)
        if _IPV4.match(ip):
            return ip
    ip = _curl(['http://169.254.169.254/latest/meta-data/public-ipv4'], 2)
    if _IPV4.match(ip):
        return ip
    for url in ('https://api.ipify.org', 'https://ifconfig.me'):
        ip = _curl([url], 3)
        if _IPV4.match(ip):
            return ip
    try:
        r = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=4)
        first = (r.stdout or '').strip().split()
        if first and _IPV4.match(first[0]):
            return first[0]
    except Exception:
        pass
    return ''


def load_settings():
    with open(SETTINGS_FILE) as f:
        return json.load(f)


def save_settings_atomic(settings):
    """Atomic, mode-600 write of the FULL settings dict (no key loss possible)."""
    fd, tmp = tempfile.mkstemp(dir=CONFIG_DIR, prefix='.settings-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(settings, f, indent=4)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, SETTINGS_FILE)
        tmp = None
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except Exception:
                pass


def regen_self_signed_cert(ip):
    """Regenerate the console self-signed cert with `ip` in CN + SAN. Same openssl
    invocation as start.sh generate_self_signed_cert() — including DNS:host.docker.internal
    (v10.1.3) so the CloudTAK api container can validate the cert when it reaches the
    console at https://host.docker.internal:5001, rather than disabling TLS verify."""
    os.makedirs(SSL_DIR, exist_ok=True)
    crt = os.path.join(SSL_DIR, 'console.crt')
    key = os.path.join(SSL_DIR, 'console.key')
    subprocess.run(
        ['openssl', 'req', '-x509', '-newkey', 'rsa:4096',
         '-keyout', key, '-out', crt, '-sha256', '-days', '3650', '-nodes',
         '-subj', f'/C=US/ST=TAK/L=TAK/O=TAKWERX/CN={ip}',
         '-addext', f'subjectAltName=IP:{ip},IP:127.0.0.1,DNS:localhost,DNS:host.docker.internal'],
        check=True, capture_output=True, timeout=60)
    os.chmod(key, 0o600)
    os.chmod(crt, 0o644)


def _have(cmd):
    return subprocess.run(f'command -v {cmd} >/dev/null 2>&1', shell=True).returncode == 0


def rescope_firewall(old_ip, new_ip):
    """Repoint any source-scoped firewall rule pinned to old_ip → new_ip. Drives
    firewalld rich-rules or ufw `from <ip>` rules, matching the formats written by
    /api/firewall/restrict-source. Best-effort and fully logged; never raises."""
    if not old_ip or not _IPV4.match(old_ip):
        return
    # RHEL prefers firewalld; otherwise ufw (consistent with _fw_backend()).
    is_rhel = os.path.exists('/etc/redhat-release')
    if (is_rhel and _have('firewall-cmd')) or (not _have('ufw') and _have('firewall-cmd')):
        try:
            out = subprocess.run(['firewall-cmd', '--list-rich-rules'],
                                 capture_output=True, text=True, timeout=15).stdout or ''
        except Exception as e:
            log(f"firewalld rule read failed: {str(e)[:120]}")
            return
        changed = 0
        for line in out.splitlines():
            line = line.strip()
            if not line or old_ip not in line:
                continue
            new_line = line.replace(old_ip, new_ip)
            subprocess.run(['firewall-cmd', '--permanent', f'--remove-rich-rule={line}'],
                           capture_output=True, text=True, timeout=15)
            subprocess.run(['firewall-cmd', '--permanent', f'--add-rich-rule={new_line}'],
                           capture_output=True, text=True, timeout=15)
            changed += 1
            log(f"firewalld: repinned rich-rule {old_ip} → {new_ip}")
        if changed:
            subprocess.run(['firewall-cmd', '--reload'], capture_output=True, text=True, timeout=15)
        else:
            log("firewalld: no rules pinned to old IP")
        return
    if _have('ufw'):
        try:
            out = subprocess.run('ufw status 2>/dev/null', shell=True,
                                 capture_output=True, text=True, timeout=12).stdout or ''
        except Exception as e:
            log(f"ufw rule read failed: {str(e)[:120]}")
            return
        # Lines look like: "8080/tcp   ALLOW   <old_ip>"  /  "8080   ALLOW   <old_ip>"
        changed = 0
        for line in out.splitlines():
            if old_ip not in line:
                continue
            cols = line.split()
            if len(cols) < 3:
                continue
            to, action = cols[0], cols[1].lower()
            if action not in ('allow', 'deny'):
                continue
            m = re.match(r'^(\d{1,5})(?:/(tcp|udp))?$', to)
            if not m:
                continue
            port = m.group(1)
            proto = m.group(2) or 'tcp'
            # delete old, add new — ufw rules can't be edited in place.
            subprocess.run(f'ufw --force delete {action} from {old_ip} to any port {port} proto {proto}',
                           shell=True, capture_output=True, text=True, timeout=12)
            subprocess.run(f'ufw {action} from {new_ip} to any port {port} proto {proto}',
                           shell=True, capture_output=True, text=True, timeout=12)
            changed += 1
            log(f"ufw: repinned {action} {port}/{proto} {old_ip} → {new_ip}")
        if not changed:
            log("ufw: no rules pinned to old IP")


def main():
    try:
        settings = load_settings()
    except Exception as e:
        log(f"no readable settings.json ({str(e)[:80]}) — skipping")
        return 0
    cur = (settings.get('server_ip') or '').strip()
    new = detect_ip()
    if not _valid_routable_ipv4(new):
        log(f"detected IP not usable ('{new}') — leaving settings untouched")
        return 0
    if not cur:
        # first-fill is _heal_settings_core_keys()'s job inside the app; not ours.
        log("server_ip empty — deferring to in-app core-key heal")
        return 0
    if new == cur:
        log(f"server_ip unchanged ({cur}) — no-op")
        return 0

    log(f"server_ip changed: {cur} → {new}")
    settings['server_ip'] = new
    try:
        save_settings_atomic(settings)
        log("settings.json updated (atomic)")
    except Exception as e:
        log(f"settings write failed ({str(e)[:120]}) — aborting heal")
        return 0

    # Regenerate the IP-SAN console cert ONLY in genuine IP-only mode. In 'fqdn'
    # (Caddy/Let's Encrypt) and 'custom' (BYO cert) modes the operator reaches the
    # console via the FQDN and that cert is owned elsewhere — don't touch it.
    ssl_mode = (settings.get('ssl_mode') or '').strip().lower()
    has_fqdn = bool((settings.get('fqdn') or '').strip())
    if ssl_mode in ('fqdn', 'custom') or has_fqdn:
        log(f"ssl_mode={ssl_mode or 'unset'}{' (fqdn set)' if has_fqdn else ''} "
            f"— console cert owned elsewhere; skipping cert regen")
    else:
        try:
            regen_self_signed_cert(new)
            log("self-signed console cert regenerated with new SAN")
        except Exception as e:
            log(f"cert regen failed (non-fatal): {str(e)[:120]}")

    try:
        rescope_firewall(cur, new)
    except Exception as e:
        log(f"firewall rescope failed (non-fatal): {str(e)[:120]}")
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:  # absolute backstop — never block console start
        log(f"unexpected error (non-fatal): {str(e)[:160]}")
        sys.exit(0)
