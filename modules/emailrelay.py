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


def deploy_validate(data):
    """Request-side validation for /deploy and /swap (the byte-identical clone
    collapsed onto one view). Resolves the relay host/port here so the custom
    provider never mutates PROVIDERS."""
    provider = data.get('provider', 'brevo')
    smtp_user = (data.get('smtp_user') or '').strip()
    smtp_pass = (data.get('smtp_pass') or '').strip()
    from_addr = (data.get('from_addr') or '').strip()
    from_name = (data.get('from_name') or '').strip()
    if not smtp_user or not smtp_pass or not from_addr:
        return None, 'SMTP username, password, and from address are required'
    p = PROVIDERS.get(provider, PROVIDERS['brevo'])
    relay_host, relay_port = p['host'], p['port']
    if provider == 'custom':
        relay_host = (data.get('custom_host') or '').strip()
        relay_port = (data.get('custom_port') or '587').strip()
        if not relay_host:
            return None, 'Custom host is required'
    return {'provider': provider, 'smtp_user': smtp_user, 'smtp_pass': smtp_pass,
            'from_addr': from_addr, 'from_name': from_name,
            'relay_host': relay_host, 'relay_port': relay_port}, None


def deploy(ctx, job, params):
    plog = _plog
    provider_key = params['provider']
    smtp_user, smtp_pass = params['smtp_user'], params['smtp_pass']
    from_addr, from_name = params['from_addr'], params['from_name']
    relay_host, relay_port = params['relay_host'], params['relay_port']
    try:
        settings = ctx['load_settings']()
        provider = PROVIDERS.get(provider_key, PROVIDERS['brevo'])

        plog("📧 Step 1/5 — Installing Postfix...")
        if ctx['os_type']() == 'debian':
            ctx['wait_for_apt_lock'](plog, job['log'])
            # Resolve mailname: prefer saved FQDN, fall back to hostname -f, hard-fallback to hostname
            # hostname -f can return an unresolvable name on some VPS configs, causing
            # mydomain to be derived as "0" and postfix install to fail with
            # "meter mydomain: bad parameter value: 0"
            fqdn_result = subprocess.run('hostname -f 2>/dev/null || hostname', shell=True, capture_output=True, text=True)
            fqdn = (settings.get('fqdn') or fqdn_result.stdout.strip() or 'localhost').strip()
            if not fqdn or fqdn == '0':
                fqdn = settings.get('fqdn', 'localhost')
            subprocess.run(
                f'echo "postfix postfix/mailname string {fqdn}" | debconf-set-selections && '
                'echo "postfix postfix/main_mailer_type string Internet Site" | debconf-set-selections',
                shell=True, capture_output=True, timeout=30)
            ok, out = ctx['_pkg_install'](['postfix', 'libsasl2-modules'], log_fn=plog, timeout=300)
            if not ok:
                # Attempt recovery: set myhostname/mydomain explicitly then retry dpkg --configure
                plog("⚠ Postfix install hit error, attempting recovery (mydomain fix)...")
                subprocess.run(
                    f'postconf -e "myhostname={fqdn}" 2>/dev/null; '
                    f'postconf -e "mydomain={fqdn.split(".", 1)[-1] if "." in fqdn else fqdn}" 2>/dev/null; '
                    'dpkg --configure postfix 2>&1 || true',
                    shell=True, capture_output=True, timeout=60)
                r = subprocess.run('dpkg -l postfix 2>&1', shell=True, capture_output=True, text=True)
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
        main_cf_additions = f"""
# TAKWERX Email Relay — managed by TAK-infra
inet_interfaces = all
mynetworks = 127.0.0.0/8 [::1]/128 172.16.0.0/12
# Send-only smarthost: never treat the base domain as a local destination
# (default mydestination includes $mydomain -> 550 "User unknown in local
# recipient table" for any address at the TAK base domain, GH #48)
mydestination = $myhostname, localhost.localdomain, localhost
relayhost = [{relay_host}]:{relay_port}
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = may
smtp_use_tls = yes
header_size_limit = 4096000
smtp_generic_maps = hash:/etc/postfix/generic
"""
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

        plog("📧 Step 3/5 — Writing credentials...")
        sasl_line = f"[{relay_host}]:{relay_port}    {smtp_user}:{smtp_pass}"
        ctx['_write_priv']('/etc/postfix/sasl_passwd', sasl_line + '\n')
        subprocess.run('postmap /etc/postfix/sasl_passwd', shell=True, capture_output=True)
        subprocess.run(ctx['_sudo_wrap'](['chmod', '600', '/etc/postfix/sasl_passwd', '/etc/postfix/sasl_passwd.db']), capture_output=True)

        # Generic map for from address rewriting
        hostname = subprocess.run('hostname -f', shell=True, capture_output=True, text=True).stdout.strip()
        generic_line = f"root@{hostname}    {from_addr}"
        ctx['_write_priv']('/etc/postfix/generic', generic_line + '\n')
        subprocess.run('postmap /etc/postfix/generic', shell=True, capture_output=True)
        plog("✓ Credentials written and hashed")

        plog("📧 Step 4/5 — Enabling and starting Postfix...")
        subprocess.run(ctx['_sudo_wrap'](['systemctl', 'enable', 'postfix']), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        r = subprocess.run(ctx['_sudo_wrap'](['systemctl', 'restart', 'postfix']), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
        if r.returncode != 0:
            plog(f"✗ Postfix restart failed: {r.stdout}")
            job.update({'running': False, 'error': True})
            return
        plog("✓ Postfix running")

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
        ctx['save_settings'](settings)
        plog("✓ Configuration saved")
        plog("")
        plog("✅ Email Relay deployed successfully!")
        plog(f"   Provider: {provider['name'] if provider_key != 'custom' else 'Custom'}")
        plog(f"   Relay:    {relay_host}:{relay_port}")
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
    subprocess.run(ctx['_sudo_wrap'](['rm', '-f', '/etc/postfix/sasl_passwd', '/etc/postfix/sasl_passwd.db']), capture_output=True, timeout=15)
    ctx['_pkg_remove']('postfix', timeout=120)
    settings = ctx['load_settings']()
    settings.pop('email_relay', None)
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
            return jsonify({'success': True, 'output': f'Test email sent to {to_addr}'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)[:200]})

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
            {'url': '/api/emailrelay/configure-authentik', 'methods': ['POST'],
             'endpoint': 'emailrelay_configure_authentik', 'view': configure_authentik_view},
        ],
        # facts (data for later waves — recorded so 10.1.23+ don't re-survey)
        'ports': [],                    # opens no firewall ports (SMTP is localhost:25)
        'service_units': ['postfix'],
        'settings_keys': ['email_relay'],
    })
