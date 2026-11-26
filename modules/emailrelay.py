"""Email Relay (Postfix) — the first registry-resident module (v10.1.22).

Moved from app.py (SOLID Wave 3, PLAN v10.1.22 §4-W4), behavior-preserving at
the URL/response-shape level except the two deliberate security fixes:
uninstall is admin-password-gated (via the generic registry preamble) and the
plaintext SMTP creds are purged from /etc/postfix on uninstall.

This file imports NOTHING from app.py — every seam (settings, privileged
file IO, package shim, sudo wrap, Authentik SMTP hook, portal push) arrives
through the ctx dict handed to register(ctx).
"""
import os
import re
import subprocess

from . import register_module, job_log

# Constant since v10.1.22: the 'custom' provider's host/port flow through the
# deploy params — request handlers no longer mutate this dict.
PROVIDERS = {
    'brevo':   {'name': 'Brevo',   'host': 'smtp-relay.brevo.com', 'port': '587', 'url': 'https://app.brevo.com/settings/keys/smtp'},
    'smtp2go': {'name': 'SMTP2GO', 'host': 'mail.smtp2go.com',     'port': '587', 'url': 'https://app.smtp2go.com/settings/users/smtp'},
    'mailgun': {'name': 'Mailgun', 'host': 'smtp.mailgun.org',      'port': '587', 'url': 'https://app.mailgun.com/mg/sending/domains'},
    'custom':  {'name': 'Custom',  'host': '',                      'port': '587', 'url': ''},
}

# ops #1200 (infra-TAK GH #703): only the Custom provider may send with no login. It is for
# a company's own mail relay or Microsoft 365 Direct Send, which allow mail by source address.
# The three hosted providers always need a login, whatever the request says.
TLS_MODES = ('may', 'encrypt', 'none')   # opportunistic (the old fixed value), required, off
_CTRL_RE = re.compile(r'[\x00-\x20\x7f]')


def relay_configured(relay):
    """Is the relay set up? A login-less Custom relay has no smtp_user, so the old test
    `relay_host and smtp_user` called it unconfigured. Every Email Relay card, the portal
    push, diagnostics and the health check use this one test (ops #1200)."""
    relay = relay or {}
    if not relay.get('relay_host'):
        return False
    return bool(relay.get('smtp_user')) or relay.get('smtp_auth') is False


def render_main_cf_block(relay_host, relay_port, smtp_auth=True, tls='may'):
    """The TAKWERX block appended to main.cf. With smtp_auth False there is no SASL map, so
    Postfix never looks for credentials. TLS is its own setting and does not depend on the
    login (ops #1200). Access control is unchanged: mynetworks stays local plus Docker."""
    tls = tls if tls in TLS_MODES else 'may'
    lines = [
        '',
        '# TAKWERX Email Relay \u2014 managed by TAK-infra',
        'inet_interfaces = all',
        'mynetworks = 127.0.0.0/8 [::1]/128 172.16.0.0/12',
        '# Send-only smarthost: never treat the base domain as a local destination',
        '# (default mydestination includes $mydomain -> 550 "User unknown in local',
        '# recipient table" for any address at the TAK base domain, GH #48)',
        'mydestination = $myhostname, localhost.localdomain, localhost',
        f'relayhost = [{relay_host}]:{relay_port}',
    ]
    if smtp_auth:
        lines += ['smtp_sasl_auth_enable = yes',
                  'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd',
                  'smtp_sasl_security_options = noanonymous']
    else:
        lines += ['smtp_sasl_auth_enable = no']
    lines += [f'smtp_tls_security_level = {tls}']
    if tls != 'none':
        lines += ['smtp_use_tls = yes']
    lines += ['header_size_limit = 4096000',
              'smtp_generic_maps = hash:/etc/postfix/generic']
    return '\n'.join(lines) + '\n'


def accepted_message(settings, to_addr):
    """What a successful test send actually proves, in words (v10.2.8 W6, GH #87).

    `sendmail` returning means the provider ACCEPTED the message — nothing more. Brevo then
    drops mail silently for an unauthorized IP, an unverified sender, or a domain without
    DKIM/DMARC, and the console never hears about it. "Test email sent" read as "delivered",
    so a reporter whose mail never arrived concluded the relay worked and the problem was
    elsewhere. Say what we know, and where the provider shows the rest.
    """
    relay = (settings or {}).get('email_relay') or {}
    key = (relay.get('provider') or '').strip()
    name = PROVIDERS.get(key, {}).get('name', '') if key and key != 'custom' else ''
    if name:
        where = ' (Transactional \u2192 Logs)' if key == 'brevo' else ''
        return (f"Handed to {name} for delivery to {to_addr}. If it hasn't arrived in a few "
                f"minutes, check {name}'s sending log{where}. The console can confirm {name} "
                f"accepted the message, not that it was delivered.")
    return (f"Handed to the email relay for delivery to {to_addr}. If it hasn't arrived in a "
            f"few minutes, check your email provider's sending log. The console can confirm the "
            f"provider accepted the message, not that it was delivered.")


def _plog(msg):
    return job_log('emailrelay', msg)


def detect(ctx):
    """`which postfix` + `systemctl is-active` — unchanged logic, moved from the
    detect_modules() inline block."""
    installed = ctx['probe_run'](['which', 'postfix']).returncode == 0
    running = False
    if installed:
        r = ctx['probe_run'](ctx['_sudo_wrap'](['systemctl', 'is-active', 'postfix']), text=True)
        running = (r.stdout or '').strip() == 'active'
    return {'installed': installed, 'running': running}


# ---- Mail for root (GH #667) ----------------------------------------------------
# The OS mails sudo denials, cron failures and unattended-upgrades reports to `root`.
# Postfix writes that as root@<name>, where <name> is /etc/mailname, `hostname -f` or
# $myhostname, depending on the sender. The relay is send-only (the FQDN is NOT in
# mydestination, GH #48), so root@<FQDN> went to the smarthost and bounced, and the
# generic map only knew `hostname -f`. A virtual alias is the one Postfix table that is
# applied before both the "local" and the "smarthost" decision, so it works for every
# name. Never add the FQDN to mydestination to get the same result: that is GH #48 again.
ROOT_ALIAS_MAP = '/etc/postfix/virtual_root'
MAIN_CF = '/etc/postfix/main.cf'
_HOSTNAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$')


NOTIFY_KEY = 'system_notify_email'


def root_destination(ctx, settings, from_addr=''):
    """Who reads the host's own mail, first match wins (ops #1140):
    1. the "Send system notifications to" box on the Email Relay page,
    2. Guard Dog's alert address(es), an address somebody already monitors,
    3. the relay From address (what the generic map always used, so nothing changes
       for a box that sets neither)."""
    safe = ctx['_safe_alert_emails']
    for key in (NOTIFY_KEY, 'guarddog_alert_email'):
        got = safe((settings or {}).get(key))
        if got:
            return got
    fa = from_addr or ((settings or {}).get('email_relay') or {}).get('from_addr') or ''
    return safe(fa)[:1]


def root_destination_source(ctx, settings):
    """Which of the three places root_destination() reads from: 'notify', 'guarddog'
    or 'from' (the page says it in words)."""
    safe = ctx['_safe_alert_emails']
    if safe((settings or {}).get(NOTIFY_KEY)):
        return 'notify'
    if safe((settings or {}).get('guarddog_alert_email')):
        return 'guarddog'
    return 'from'


_ADDR_SPLIT_RE = re.compile(r'[,;\s]+')
NOTIFY_MAX_ADDRESSES = 5


def parse_notify_to(ctx, value):
    """Validate the box. Returns (comma_joined_addresses, error). An empty value is
    valid and clears the setting. Every address goes through the same allowlist as
    Guard Dog's alert address (ctx['_safe_alert_emails']); one bad entry rejects the
    whole save, so a typo never silently drops an address."""
    value = (value or '').strip()
    if len(value) > 1000:
        return None, 'Too long'
    good = ctx['_safe_alert_emails'](value)
    keep = {g.lower() for g in good}
    bad = [t for t in _ADDR_SPLIT_RE.split(value) if t and t.lower() not in keep]
    if bad:
        return None, 'Invalid email address: ' + ', '.join(bad[:3])
    if len(good) > NOTIFY_MAX_ADDRESSES:
        return None, f'At most {NOTIFY_MAX_ADDRESSES} addresses'
    return ','.join(good), None


def render_root_alias_map(names, dests):
    """Body of /etc/postfix/virtual_root. With no destination it is comments only: the
    file must always exist, because main.cf names it and Postfix defers mail when a
    named table is missing."""
    lines = ['# TAKWERX Email Relay: mail the host sends to root goes to a person (GH #667).',
             '# Managed by TAK-infra. Rewritten on every relay deploy and Guard Dog address save.']
    if dests:
        lines += [f"root@{n}    {', '.join(dests)}" for n in names]
    return '\n'.join(lines) + '\n'


def with_root_alias_map(cf):
    """main.cf text with our map in the effective virtual_alias_maps. An operator's own
    maps stay (ours is added after them). Returns (text, changed)."""
    ours = f'hash:{ROOT_ALIAS_MAP}'
    hits = re.findall(r'(?m)^[ \t]*virtual_alias_maps[ \t]*=(.*)$', cf or '')
    current = hits[-1].strip() if hits else ''
    if ours in current.split():
        return cf, False
    merged = (current + ' ' + ours).strip()
    return (cf or '').rstrip('\n') + f'\nvirtual_alias_maps = {merged}\n', True


def sync_root_alias(ctx, settings, plog=None, from_addr='', reload=True, names=None):
    """Write the root alias map and make main.cf use it. Safe to repeat. Never raises:
    mail for root is a convenience and must not fail a deploy or a settings save.
    Returns (ok, message)."""
    plog = plog or (lambda m: None)
    try:
        names = names if names is not None else postfix_local_names(settings)
        dests = root_destination(ctx, settings, from_addr)
        # Sender rewrite for every host name (a box deployed before GH #667 only had one).
        sender = (from_addr or ((settings or {}).get('email_relay') or {}).get('from_addr') or '').strip()
        if sender and ctx['_safe_alert_emails'](sender):
            ctx['_write_priv']('/etc/postfix/generic', _generic_map_text(sender, *names)[0])
            _postmap(ctx, '/etc/postfix/generic', plog)
        # Map first, then main.cf: main.cf must never name a table that does not exist.
        ctx['_write_priv'](ROOT_ALIAS_MAP, render_root_alias_map(names, dests))
        if not _postmap(ctx, ROOT_ALIAS_MAP, plog):
            return False, 'could not build the root alias map'
        cf = ctx['_read_priv'](MAIN_CF)
        new_cf, changed = with_root_alias_map(cf)
        if changed:
            ctx['_write_priv'](MAIN_CF, new_cf)
            if reload:
                subprocess.run(ctx['_sudo_wrap'](['systemctl', 'reload', 'postfix']),
                               capture_output=True, text=True, timeout=60)
        if dests:
            plog(f"✓ Mail for root goes to {', '.join(dests)}")
            return True, f"Mail for root goes to {', '.join(dests)}"
        plog("⚠ No address for root's mail: set a Guard Dog alert address")
        return True, 'no address for root mail'
    except Exception as e:
        plog(f"⚠ Could not set up mail for root: {e}")
        return False, str(e)[:200]


def _postmap(ctx, path, plog):
    """Rebuild a postfix lookup table, privileged, and SAY SO if it fails.

    Two faults, both v10.1.48 W2. /etc/postfix is root-owned, so an unwrapped
    `postmap` is denied outright on a non-root console — and because the result
    was captured and discarded, the deploy still printed "Credentials written
    and hashed" over a .db that was never built. Postfix then has no SASL map
    and mail queues silently. `postmap` is on the broker allow-list precisely
    for this, so route it and check the return code.
    """
    r = subprocess.run(ctx['_sudo_wrap'](['postmap', path]),
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        detail = ((r.stderr or '') + (r.stdout or '')).strip()[-300:]
        plog(f"✗ postmap {path} failed (rc={r.returncode}): {detail or 'no output'}")
        return False
    return True


def _resolve_fqdn(settings):
    """The mail name this relay uses, plus what `hostname -f` says right now.

    Prefer the administrator-saved FQDN; fall back to `hostname -f`, then `hostname`.
    `hostname -f` can return an unresolvable name on some VPS configs, causing mydomain
    to be derived as "0" and the postfix install to fail with
    "meter mydomain: bad parameter value: 0". Returns (fqdn, hostname_f).
    """
    r = subprocess.run(['hostname', '-f'], capture_output=True, text=True)
    hostname_f = (r.stdout or '').strip() if r.returncode == 0 else ''
    if not hostname_f:
        r2 = subprocess.run(['hostname'], capture_output=True, text=True)
        hostname_f = (r2.stdout or '').strip()
    fqdn = ((settings or {}).get('fqdn') or hostname_f or 'localhost').strip()
    if not fqdn or fqdn == '0':
        fqdn = (settings or {}).get('fqdn', 'localhost')
    return fqdn, hostname_f


def _generic_map_text(from_addr, *origins):
    """Body of /etc/postfix/generic: one `root@<name>  <from_addr>` line per distinct name.

    ops #1142 (infra-TAK GH #665). Postfix stamps local mail from root with whatever its
    origin is: /etc/mailname on Debian/Ubuntu (the saved FQDN), $myhostname elsewhere
    (`hostname -f`). The map used to be keyed only on a bare `hostname -f`, so on a host
    where that differs from the saved FQDN the key never matched and the sender was never
    rewritten, with no message. Key every name Postfix could stamp; duplicates and blanks
    are dropped, order is kept (first = the saved FQDN).
    """
    seen, lines = set(), []
    for name in origins:
        name = (name or '').strip()
        if not name or name == '0' or name.lower() in seen:
            continue
        seen.add(name.lower())
        lines.append(f"root@{name}    {from_addr}")
    return '\n'.join(lines) + '\n', sorted(seen)


def _read_name_file(path):
    """First line of a name file such as /etc/mailname; '' when absent or unreadable."""
    try:
        with open(path, encoding='utf-8') as f:
            return (f.readline() or '').strip()
    except OSError:
        return ''


def _postfix_origins():
    """The names Postfix itself will stamp on root's mail: `postconf -h -x myorigin` (a file
    path such as /etc/mailname is read) and `myhostname`. Asking Postfix beats guessing:
    on Rocky `myhostname` is `<host>.localdomain`, which neither the saved FQDN nor
    `hostname -f` ever equals. A failed query just returns fewer names. The flags are sent
    apart (`-h -x`, never `-hx`) because the broker's postconf rule reads one flag per
    argument and refuses a combined one when it enforces (ops #1171)."""
    names = []
    for param in ('myorigin', 'myhostname'):
        try:
            r = subprocess.run(['postconf', '-h', '-x', param], capture_output=True,
                               text=True, timeout=15)
            val = (r.stdout or '').strip() if r.returncode == 0 else ''
        except (OSError, subprocess.SubprocessError):
            val = ''
        if val.startswith('/'):
            val = _read_name_file(val)
        names.append(val)
    return names


def postfix_local_names(settings):
    """THE list of names Postfix may put after `root@` for mail the host sends itself.

    One discovery for both maps: the sender rewrite (/etc/postfix/generic) and the root
    recipient map (/etc/postfix/virtual_root) are built from this list, so they can never
    disagree (GH #665 and GH #667). Order: the saved FQDN first, then what Postfix reports
    (`postconf -h -x myorigin`, which reads /etc/mailname, and `myhostname`), then
    `hostname -f`. Names that are not plain host names are dropped, because they go into a
    Postfix table."""
    fqdn, hostname_f = _resolve_fqdn(settings)
    names = []
    for n in (fqdn, *_postfix_origins(), hostname_f):
        n = (n or '').strip().lower()
        if n and n != '0' and _HOSTNAME_RE.match(n) and n not in names:
            names.append(n)
    return names


def deploy_validate(data):
    """Request-side validation for /deploy and /swap (the byte-identical clone
    collapsed onto one view). Resolves the relay host/port here so the custom
    provider never mutates PROVIDERS.

    ops #1200: the Custom provider may turn the SMTP login off (`smtp_auth` false), for a
    company mail relay or Microsoft 365 Direct Send. Only Custom: any other provider keeps
    the login required, so a hand-made request cannot skip it."""
    provider = data.get('provider', 'brevo')
    smtp_user = (data.get('smtp_user') or '').strip()
    smtp_pass = (data.get('smtp_pass') or '').strip()
    from_addr = (data.get('from_addr') or '').strip()
    from_name = (data.get('from_name') or '').strip()
    smtp_auth = not (provider == 'custom' and data.get('smtp_auth') in (False, 'false', 'no', 0, '0'))
    if smtp_auth:
        if not smtp_user or not smtp_pass or not from_addr:
            return None, 'SMTP username, password, and from address are required'
    else:
        if not from_addr:
            return None, 'From address is required'
        smtp_user, smtp_pass = '', ''   # nothing typed in the hidden boxes is ever stored
    p = PROVIDERS.get(provider, PROVIDERS['brevo'])
    relay_host, relay_port = p['host'], p['port']
    smtp_tls = 'may'
    if provider == 'custom':
        relay_host = (data.get('custom_host') or '').strip()
        relay_port = (data.get('custom_port') or '587').strip()
        if not relay_host:
            return None, 'Custom host is required'
        # The host and port go into main.cf as one line: no space, no line break.
        if _CTRL_RE.search(relay_host) or not relay_port.isdigit():
            return None, 'Custom host or port is not valid'
        smtp_tls = (data.get('smtp_tls') or 'may').strip().lower()
        if smtp_tls not in TLS_MODES:
            return None, 'TLS mode must be one of: ' + ', '.join(TLS_MODES)
    return {'provider': provider, 'smtp_user': smtp_user, 'smtp_pass': smtp_pass,
            'from_addr': from_addr, 'from_name': from_name,
            'relay_host': relay_host, 'relay_port': relay_port,
            'smtp_auth': smtp_auth, 'smtp_tls': smtp_tls}, None


def deploy(ctx, job, params):
    plog = _plog
    provider_key = params['provider']
    smtp_user, smtp_pass = params['smtp_user'], params['smtp_pass']
    from_addr, from_name = params['from_addr'], params['from_name']
    relay_host, relay_port = params['relay_host'], params['relay_port']
    smtp_auth = params.get('smtp_auth', True)       # ops #1200: False = no SMTP login
    smtp_tls = params.get('smtp_tls', 'may')
    try:
        settings = ctx['load_settings']()
        provider = PROVIDERS.get(provider_key, PROVIDERS['brevo'])

        plog("📧 Step 1/5 — Installing Postfix...")
        if ctx['os_type']() == 'debian':
            ctx['wait_for_apt_lock'](plog, job['log'])
            # Mail name: see _resolve_fqdn (ops #1142 shares it with the generic map below).
            fqdn, _ = _resolve_fqdn(settings)
            # `fqdn` comes from settings.json — an administrator types it into the
            # console. It used to be interpolated into a root shell string here
            # (v10.1.48 W2). The pre-seed lines go in on STDIN instead: no shell,
            # nothing to quote, and the broker forwards stdin on non-root boxes.
            subprocess.run(
                ctx['_sudo_wrap'](['debconf-set-selections']),
                input=(f'postfix postfix/mailname string {fqdn}\n'
                       'postfix postfix/main_mailer_type string Internet Site\n'),
                text=True, capture_output=True, timeout=30)
            ok, out = ctx['_pkg_install'](['postfix', 'libsasl2-modules'], log_fn=plog, timeout=300)
            if not ok:
                # Attempt recovery: set myhostname/mydomain explicitly then retry dpkg --configure
                plog("⚠ Postfix install hit error, attempting recovery (mydomain fix)...")
                mydomain = fqdn.split('.', 1)[-1] if '.' in fqdn else fqdn
                for _pc in (f'myhostname={fqdn}', f'mydomain={mydomain}'):
                    subprocess.run(ctx['_sudo_wrap'](['postconf', '-e', _pc]),
                                   capture_output=True, timeout=30)
                subprocess.run(ctx['_sudo_wrap'](['dpkg', '--configure', 'postfix']),
                               capture_output=True, timeout=60)
                r = subprocess.run(['dpkg', '-l', 'postfix'], capture_output=True, text=True)
                if 'ii' not in r.stdout:
                    plog(f"✗ Postfix install failed: {r.stdout[-500:]}")
                    job.update({'running': False, 'error': True})
                    return
        else:
            ok, out = ctx['_pkg_install'](['postfix', 'cyrus-sasl-plain'], log_fn=plog, timeout=300)
            if not ok:
                plog(f"✗ Postfix install failed: {out[-500:]}")
                job.update({'running': False, 'error': True})
                return
        plog("✓ Postfix installed")

        plog("📧 Step 2/5 — Configuring main.cf...")
        main_cf_additions = render_main_cf_block(relay_host, relay_port, smtp_auth, smtp_tls)
        # Read existing main.cf and strip any previous TAKWERX block. v10.0.5
        # non-root: /etc/postfix is root-owned — read+write via the broker (raw
        # open(...,'w') EPERM'd as the takwerx console: [Errno 13] /etc/postfix/main.cf).
        main_cf_path = '/etc/postfix/main.cf'
        try:
            existing = ctx['_read_priv'](main_cf_path)
        except Exception:
            existing = ''
        if existing:
            # Remove previous TAKWERX block if present
            existing = re.sub(r'\n# TAKWERX Email Relay.*', '', existing, flags=re.DOTALL)
            # Remove any existing relayhost line (Ubuntu default has a blank one)
            existing = re.sub(r'^\s*relayhost\s*=.*$', '', existing, flags=re.MULTILINE)
            # Remove any existing mynetworks (we set it in our block for Docker relay)
            existing = re.sub(r'^\s*mynetworks\s*=.*$', '', existing, flags=re.MULTILINE)
            # Remove any existing mydestination (package default includes $mydomain,
            # which makes same-domain mail bounce locally — GH #48; ours wins)
            existing = re.sub(r'^\s*mydestination\s*=.*$', '', existing, flags=re.MULTILINE)
            existing = existing.rstrip()
        ctx['_write_priv'](main_cf_path, existing + '\n' + main_cf_additions)
        plog("✓ main.cf configured")

        if smtp_auth:
            plog("📧 Step 3/5 — Writing credentials...")
            sasl_line = f"[{relay_host}]:{relay_port}    {smtp_user}:{smtp_pass}"
            # ops #632: empty and 0600 FIRST, then the password. The chmod below only ran
            # after postmap succeeded, so a failed postmap left the SMTP password 0644.
            ctx['_write_priv']('/etc/postfix/sasl_passwd', '', perm=0o600)
            ctx['_write_priv']('/etc/postfix/sasl_passwd', sasl_line + '\n', perm=0o600)
            if not _postmap(ctx, '/etc/postfix/sasl_passwd', plog):
                # Without the hashed map postfix cannot authenticate to the smarthost
                # and every message queues forever. Fail the deploy rather than report
                # a relay that is configured but cannot send.
                plog("✗ SASL credential map could not be built — relay would queue mail silently")
                job.update({'running': False, 'error': True})
                return
            subprocess.run(ctx['_sudo_wrap'](['chmod', '600', '/etc/postfix/sasl_passwd', '/etc/postfix/sasl_passwd.db']), capture_output=True)
        else:
            # ops #1200: no login. Remove credentials an earlier provider left behind, so a
            # password for a service the box no longer uses does not stay on disk.
            plog("📧 Step 3/5 — No SMTP login: skipping credentials, removing old ones...")
            subprocess.run(ctx['_sudo_wrap'](['rm', '-f', '/etc/postfix/sasl_passwd',
                                              '/etc/postfix/sasl_passwd.db']),
                           capture_output=True, timeout=30)

        # Generic map for from address rewriting. One list of names feeds this map and the
        # root recipient map (sync_root_alias below): the saved FQDN, what Postfix says it
        # stamps (myorigin, e.g. /etc/mailname, and myhostname) and `hostname -f`.
        # ops #1142 (GH #665) and GH #667.
        names = postfix_local_names(settings)
        generic_text, generic_names = _generic_map_text(from_addr, *names)
        if len(generic_names) > 1:
            plog(f"⚠ Host names disagree ({', '.join(generic_names)}); "
                 "sender rewrite covers each of them")
        ctx['_write_priv']('/etc/postfix/generic', generic_text)
        _postmap(ctx, '/etc/postfix/generic', plog)
        plog("✓ Credentials written and hashed" if smtp_auth else "✓ Sender map written (no SMTP login)")
        # GH #667: mail the host sends to root reaches a person. Postfix restarts in
        # Step 4, so no reload here.
        sync_root_alias(ctx, settings, plog, from_addr=from_addr, reload=False, names=names)

        plog("📧 Step 4/5 — Enabling and starting Postfix...")
        subprocess.run(ctx['_sudo_wrap'](['systemctl', 'enable', 'postfix']), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        r = subprocess.run(ctx['_sudo_wrap'](['systemctl', 'restart', 'postfix']), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
        if r.returncode != 0:
            plog(f"✗ Postfix restart failed: {r.stdout}")
            job.update({'running': False, 'error': True})
            return
        plog("✓ Postfix running")
        # ops #345: mail queued while the old login was failing waits out Postfix's retry
        # back-off (up to hours). Retry it now, so a fixed login shows as fixed at once.
        # Any user may flush; a failure here must never fail the deploy.
        try:
            subprocess.run(['postqueue', '-f'], capture_output=True, timeout=30)
        except Exception:
            pass

        plog("📧 Step 5/5 — Saving configuration...")
        settings['email_relay'] = {
            'provider': provider_key,
            'relay_host': relay_host,
            'relay_port': relay_port,
            'smtp_user': smtp_user,
            'from_addr': from_addr,
            'from_name': from_name,
        }
        # Store password separately (still in settings.json, local only)
        settings['email_relay']['smtp_pass'] = smtp_pass
        # ops #1200: written only when it differs from the old behavior, so a box that has
        # never used it keeps the exact settings it had before.
        if not smtp_auth:
            settings['email_relay']['smtp_auth'] = False
        if smtp_tls != 'may':
            settings['email_relay']['smtp_tls'] = smtp_tls
        ctx['save_settings'](settings)
        plog("✓ Configuration saved")
        plog("")
        plog("✅ Email Relay deployed successfully!")
        plog(f"   Provider: {provider['name'] if provider_key != 'custom' else 'Custom'}")
        plog(f"   Relay:    {relay_host}:{relay_port}")
        plog(f"   Login:    {'SMTP login' if smtp_auth else 'none (relay allows this server without a login)'}")
        plog(f"   From:     {from_name} <{from_addr}>")

        # Auto-configure Authentik if installed (SMTP + recovery flow)
        ak_dir = os.path.expanduser('~/authentik')
        if os.path.exists(os.path.join(ak_dir, 'docker-compose.yml')):
            plog("")
            plog("🔑 Step 6/6 — Configuring Authentik (SMTP + password recovery)...")
            try:
                ak_msg = ctx['_configure_authentik_smtp_and_recovery'](from_addr, plog)
                plog(f"✓ {ak_msg}")
            except Exception as e:
                plog(f"⚠ Authentik auto-config failed: {e}")
                plog("  You can configure it manually via the 'Configure Authentik' button.")
        else:
            plog("")
            plog("📋 Configure apps to use SMTP:")
            plog("   Host: localhost   Port: 25   No auth required")

        # v10.1.20: the relay is authoritative for TAK Portal's email transport — push the
        # updated settings now so the portal Email panel reflects the new provider without
        # a manual "Update config & reconnect" (operator request 2026-08-04).
        if ctx['_takportal_push_settings'](plog):
            plog("✓ TAK Portal email settings updated from relay config")

        job.update({'running': False, 'complete': True, 'error': False})

    except Exception as e:
        plog(f"✗ Deploy failed: {str(e)}")
        job.update({'running': False, 'error': True})


def uninstall(ctx, job, params):
    subprocess.run(ctx['_sudo_wrap'](['systemctl', 'stop', 'postfix']), capture_output=True, timeout=90)
    subprocess.run(ctx['_sudo_wrap'](['systemctl', 'disable', 'postfix']), capture_output=True, timeout=90)
    # v10.1.22 security fix: purge the plaintext SMTP creds — `apt-get remove`
    # (no purge) leaves /etc/postfix behind, credentials included.
    # The root alias map stays on purpose: main.cf names it and survives `apt remove`, and
    # Postfix defers mail (or fails to start on a reinstall) when a named table is missing.
    # It holds addresses only, no secret.
    subprocess.run(ctx['_sudo_wrap'](['rm', '-f', '/etc/postfix/sasl_passwd', '/etc/postfix/sasl_passwd.db']), capture_output=True, timeout=15)
    ctx['_pkg_remove']('postfix', timeout=120)
    settings = ctx['load_settings']()
    settings.pop('email_relay', None)
    settings.pop(NOTIFY_KEY, None)
    ctx['save_settings'](settings)
    return {'success': True, 'steps': ['Postfix stopped and removed', 'SMTP credentials removed', 'Configuration cleared']}


def register(ctx):
    from flask import request, jsonify

    def test_view():
        data = request.get_json(silent=True) or {}
        to_addr = (data.get('to') or '').strip()
        if not to_addr:
            return jsonify({'success': False, 'error': 'Recipient address required'})
        settings = ctx['load_settings']()
        relay_config = settings.get('email_relay', {})
        from_addr = relay_config.get('from_addr', 'noreply@localhost')
        from_name = relay_config.get('from_name', 'TAK-infra')
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            msg = MIMEMultipart()
            msg['From'] = f'{from_name} <{from_addr}>'
            msg['To'] = to_addr
            msg['Subject'] = 'TAK-infra Test Email'
            msg.attach(MIMEText('Test email from TAK-infra Email Relay.\n\nIf you received this, your email relay is working correctly.', 'plain'))
            with smtplib.SMTP('localhost', 25, timeout=15) as s:
                s.sendmail(from_addr, [to_addr], msg.as_string())
            return jsonify({'success': True, 'output': accepted_message(settings, to_addr)})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)[:200]})

    def notify_to_view():
        """Save the "Send system notifications to" box and apply it at once (ops #1140).
        Empty clears it: root's mail then follows Guard Dog's alert address, else the
        relay From address."""
        data = request.get_json(silent=True) or {}
        value, err = parse_notify_to(ctx, data.get('notify_to'))
        if err:
            return jsonify({'success': False, 'error': err}), 400
        settings = ctx['load_settings']()
        if not settings.get('email_relay'):
            return jsonify({'success': False,
                            'error': 'Email Relay is not set up. Deploy the relay first.'}), 400
        if value:
            settings[NOTIFY_KEY] = value
        else:
            settings.pop(NOTIFY_KEY, None)
        ctx['save_settings'](settings)
        ok, msg = sync_root_alias(ctx, settings)
        resp = {'success': bool(ok), 'saved': value,
                'source': root_destination_source(ctx, settings),
                'goes_to': ','.join(root_destination(ctx, settings)), 'message': msg}
        if not ok:
            resp['error'] = 'Saved, but the server could not apply it: ' + msg
            return jsonify(resp), 500
        return jsonify(resp)

    def configure_authentik_view():
        """Push Email Relay settings into Authentik and set up recovery flow (SMTP + Forgot password?)."""
        settings = ctx['load_settings']()
        relay = settings.get('email_relay') or {}
        if not relay.get('from_addr'):
            return jsonify({'success': False, 'error': 'Email Relay not configured. Deploy the relay first.'}), 400
        deploy_cfg = ctx['_get_module_deployment_config'](settings, 'authentik_deployment')
        # v10.1.23: only remote mode gates on the deployed flag — local deploys never set
        # it historically (only _run_authentik_deploy_remote did), which left this button
        # dead 400-ing "Authentik is not installed" on every locally-deployed box. Local
        # mode trusts the on-disk compose check below instead.
        if deploy_cfg.get('target_mode') == 'remote':
            if not deploy_cfg.get('deployed'):
                return jsonify({'success': False, 'error': 'Authentik is not installed.'}), 400
            try:
                message = ctx['_configure_authentik_smtp_and_recovery_remote'](
                    deploy_cfg, relay.get('from_addr', ''), settings)
                return jsonify({'success': True, 'message': message})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)[:300]}), 500
        ak_dir = os.path.expanduser('~/authentik')
        if not os.path.exists(os.path.join(ak_dir, 'docker-compose.yml')):
            return jsonify({'success': False, 'error': 'Authentik is not installed.'}), 400
        try:
            message = ctx['_configure_authentik_smtp_and_recovery'](relay.get('from_addr', ''))
            return jsonify({'success': True, 'message': message})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)[:200]}), 500

    register_module({
        # identity / UI
        'key': 'emailrelay',
        'name': 'Email Relay',
        'description': 'Postfix relay — notifications for TAK Portal & MediaMTX',
        'icon': '📧',
        'route': '/emailrelay',
        'template': 'email_relay.html',
        'priority': 9,
        # state probes + lifecycle
        'detect': detect,
        'deploy': deploy,
        'deploy_validate': deploy_validate,
        'deploy_aliases': ['/api/emailrelay/swap'],
        'uninstall': uninstall,
        'control_map': {
            'restart': ['systemctl', 'restart', 'postfix'],
            'stop':    ['systemctl', 'stop', 'postfix'],
            'start':   ['systemctl', 'start', 'postfix'],
        },
        # bespoke routes stay bespoke, visible, and enumerable
        'extra_routes': [
            {'url': '/api/emailrelay/test', 'methods': ['POST'],
             'endpoint': 'emailrelay_test', 'view': test_view},
            {'url': '/api/emailrelay/notify-to', 'methods': ['POST'],
             'endpoint': 'emailrelay_notify_to', 'view': notify_to_view},
            {'url': '/api/emailrelay/configure-authentik', 'methods': ['POST'],
             'endpoint': 'emailrelay_configure_authentik', 'view': configure_authentik_view},
        ],
        # facts (data for later waves — recorded so 10.1.23+ don't re-survey)
        'ports': [],                    # opens no firewall ports (SMTP is localhost:25)
        'service_units': ['postfix'],
        'settings_keys': ['email_relay', NOTIFY_KEY],
    })
