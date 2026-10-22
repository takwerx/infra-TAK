# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""A TAK client with a bad certificate no longer locks the admin out of the console.

test12, 2026-10-21: one ATAK device with a certificate the server no longer trusted
retried :8089 every 15 s. 20 failures in 5 min banned the address with `action = ufw`,
which is every port: console, Authentik, SSH. Three of those a day escalated through
recidive to 7 days, all ports. Now the takserver jail blocks TAK's ports only, recidive
ignores its bans, existing boxes converge at startup, and the Fail2ban page and ban
e-mail say in plain words what happened. The functions run from the shipped app.py text.
"""

import ast
import os
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'fail2ban.html').read_text(encoding='utf-8')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    out = [ast.get_source_segment(APP, n) for n in TREE.body
           if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets)]
    assert len(out) == len(names), names
    return '\n'.join(out)


def _ns(consts=(), funcs=(), **extra):
    ns = {'re': re, 'os': os}
    ns.update(extra)
    exec(_consts(*consts) if consts else '', ns)
    for f in funcs:
        exec(_func(f), ns)
    return ns


def _notify_module():
    ns = _ns(consts=('_F2B_NOTIFY_SCRIPT',))
    mod = types.ModuleType('infratak_f2b_notify')
    exec(compile(ns['_F2B_NOTIFY_SCRIPT'], 'infratak-f2b-notify', 'exec'), mod.__dict__)
    return mod


CLASSIFY = ('_f2b_tak_failure_kind', '_f2b_tak_failures', '_f2b_duration_label',
            '_f2b_tak_ban_explain')
CLASSIFY_CONSTS = ('_F2B_TAK_FAIL_RE', '_F2B_TAK_SUBJECT_RE')

# Real TAK lines (test12, 2026-10-21), addresses changed.
PFX = ('2026-10-21-23:54:47.930 [epollEventLoopGroup-4-17] ERROR c.b.m.n.n.h.NioNettyHandlerBase - '
       'NioNettyServerHandler error. Cause: ')
BAD_CERT = (PFX + 'javax.net.ssl.SSLHandshakeException: General OpenSslEngine problem. Additional info: '
            'Remote address: 203.0.113.9; Remote port: 48372; Local port: 8089; '
            'Certificate error: peer not verified; ')
NO_CERT = (PFX + 'io.netty.handler.ssl.ReferenceCountedOpenSslEngine$OpenSslHandshakeException: '
           'error:100000c0:SSL routines:OPENSSL_internal:PEER_DID_NOT_RETURN_A_CERTIFICATE. '
           'Additional info: Remote address: 198.51.100.7; Remote port: 1; Local port: 8089; '
           'Certificate error: peer not verified; ')
NOT_TLS = (PFX + 'io.netty.handler.ssl.NotSslRecordException: not an SSL/TLS record. Additional info: '
           'Remote address: 192.0.2.44; Remote port: 2; Local port: 8089; Certificate error: peer not verified; ')
RESET_WITH_SUBJECT = (PFX + 'recvAddress(..) failed with error(-104): Connection reset by peer. '
                      'Additional info: Remote address: 203.0.113.9; Remote port: 3; Local port: 8089; '
                      'Peer certificate Subject DN: CN=admin, OU=IT, O=FIRE; ')
SUBJECT = (PFX + 'javax.net.ssl.SSLHandshakeException: General OpenSslEngine problem. Additional info: '
           'Remote address: 203.0.113.10; Remote port: 4; Local port: 8089; '
           'Peer certificate Subject DN: CN=old-phone, OU=IT, O=FIRE; ')


# ── 1. The takserver jail bans TAK's ports, nothing else ─────────────────────────────

def test_tak_banaction_blocks_only_tak_ports():
    ns = _ns(consts=('_F2B_TAK_PORTS_TCP',), funcs=('_f2b_banaction_tak',))
    action = ns['_f2b_banaction_tak']()
    assert action.startswith('iptables-multiport[')
    ports = set(re.search(r'port="([^"]+)"', action).group(1).split(','))
    assert {'8089', '8443', '8446', '9000', '9001'} == ports
    assert not ports & {'22', '80', '443', '5001'}
    assert 'ufw' not in action and 'allports' not in action


def test_tak_jail_is_written_with_the_tak_only_action_on_both_families():
    for family in ('debian', 'rhel'):
        written = {}
        ns = _ns(consts=('_F2B_TAK_PORTS_TCP',),
                 funcs=('_f2b_banaction', '_f2b_banaction_tak', '_f2b_write_tak_jail_config'),
                 _distro_family=lambda f=family: f,
                 _makedirs_priv=lambda *a, **k: None,
                 _write_priv=lambda p, c, **k: written.__setitem__(p, c),
                 _f2b_trusted_ignoreip=lambda extra='': '127.0.0.1/8 ::1 ' + extra)
        ns['_f2b_write_tak_jail_config'](20, 300, 3600, '')
        conf = written['/etc/fail2ban/jail.d/infratak-takserver.conf']
        action = re.search(r'^action\s*=\s*(.*)$', conf, re.M).group(1)
        assert action.startswith('iptables-multiport[name=takserver'), (family, conf)


# ── 2. recidive never escalates a takserver ban ──────────────────────────────────────

def _recidive_ignoreregex():
    written = {}
    ns = _ns(consts=('_F2B_RECIDIVE_BANTIME',),
             funcs=('_f2b_banaction', '_f2b_write_recidive_config'),
             _distro_family=lambda: 'debian',
             _makedirs_priv=lambda *a, **k: None,
             _write_priv=lambda p, c, **k: written.__setitem__(p, c),
             _read_priv=lambda p: '[Definition]\ndbfile = x\n',
             _sudo_wrap=lambda c: c,
             _f2b_trusted_ignoreip=lambda extra='': '127.0.0.1/8',
             subprocess=types.SimpleNamespace(run=lambda *a, **k: None))
    ns['_f2b_write_recidive_config'](3, 86400)
    conf = written['/etc/fail2ban/jail.d/infratak-recidive.conf']
    return re.compile(re.search(r'^ignoreregex = (.*)$', conf, re.M).group(1))


def test_recidive_ignores_takserver_and_media_bans_but_not_the_rest():
    ign = _recidive_ignoreregex()
    line = '2026-10-21 23:00:18,534 fail2ban.actions        [65528]: NOTICE  [%s] Ban 203.0.113.9'
    assert ign.search(line % 'takserver')
    assert ign.search(line % 'mediamtx-rtsp')
    for jail in ('sshd', 'authentik', 'takportal'):
        assert not ign.search(line % jail), jail     # brute force still escalates


# ── 3. Existing boxes converge at console start ──────────────────────────────────────

class _Box:
    """The few files and calls the converges touch."""

    def __init__(self, files):
        self.files = dict(files)
        self.reloads = 0
        self.cmds = []

    def read(self, path):
        return self.files.get(path)

    def write(self, path, content, **_k):
        self.files[path] = content

    def run(self, cmd, **_k):
        self.cmds.append(cmd)
        if 'reload' in cmd:
            self.reloads += 1


TAK_JAIL = '/etc/fail2ban/jail.d/infratak-takserver.conf'
TAK_ACT = '/etc/fail2ban/action.d/infratak-guarddog-takserver.conf'
NOTIFY = '/usr/local/sbin/infratak-f2b-notify'
RECIDIVE = '/etc/fail2ban/jail.d/infratak-recidive.conf'

OLD_TAK_JAIL = ('[takserver]\nenabled  = true\nfilter   = takserver\n'
                'logpath  = /opt/tak/logs/takserver-messaging.log\nmaxretry = 25\nfindtime = 600\n'
                'bantime  = 7200\nignoreip = 127.0.0.1/8 ::1 198.51.100.50\n'
                'action   = ufw\n         infratak-guarddog-takserver\n')


def _converge_ns(box):
    ns = _ns(consts=('_F2B_TAK_PORTS_TCP', '_F2B_TAK_GUARDDOG_ACTION', '_F2B_NOTIFY_SCRIPT'),
             funcs=('_f2b_banaction_tak', '_startup_converge_tak_banaction'),
             _f2b_read_text=box.read,
             _write_priv=box.write,
             _sudo_wrap=lambda c: c,
             subprocess=types.SimpleNamespace(run=box.run),
             _f2b_tak_jail_enabled=lambda: TAK_JAIL in box.files,
             _f2b_read_tak_jail_config=lambda: {'maxretry': 25, 'findtime': 600, 'bantime': 7200,
                                                'ignoreip': '127.0.0.1/8 ::1 198.51.100.50'},
             _f2b_operator_extra=lambda s: '198.51.100.50')
    calls = []

    def write_jail(maxretry, findtime, bantime, ignoreip=''):
        calls.append((maxretry, findtime, bantime, ignoreip))
        box.files[TAK_JAIL] = f'action   = {ns["_f2b_banaction_tak"]()}\n'
    ns['_f2b_write_tak_jail_config'] = write_jail
    return ns, calls


def test_old_all_ports_tak_jail_converges_and_keeps_operator_tuning():
    box = _Box({TAK_JAIL: OLD_TAK_JAIL, TAK_ACT: 'old action', NOTIFY: 'old notifier'})
    ns, calls = _converge_ns(box)
    ns['_startup_converge_tak_banaction']()
    assert calls == [(25, 600, 7200, '198.51.100.50')]
    assert 'iptables-multiport[name=takserver' in box.files[TAK_JAIL]
    assert box.files[TAK_ACT] == ns['_F2B_TAK_GUARDDOG_ACTION']
    assert box.files[NOTIFY] == ns['_F2B_NOTIFY_SCRIPT']
    # A plain reload drops an action that is new to a running jail (fail2ban 0.11.2, seen on
    # test6): the jail is restarted instead, which restores its bans onto the new action.
    assert box.cmds == [['fail2ban-client', 'reload', '--restart', 'takserver']]
    # Second start: nothing left to do.
    ns['_startup_converge_tak_banaction']()
    assert len(calls) == 1 and box.reloads == 1


def test_only_the_action_file_changed_needs_just_a_plain_reload():
    box = _Box({TAK_ACT: 'old action'})
    ns, calls = _converge_ns(box)
    ns['_startup_converge_tak_banaction']()
    assert calls == [] and box.cmds == [['fail2ban-client', 'reload']]


def test_converge_never_creates_the_jail_or_notifier_on_a_box_without_them():
    box = _Box({})
    ns, calls = _converge_ns(box)
    ns['_startup_converge_tak_banaction']()
    assert calls == [] and box.files == {} and box.reloads == 0


def test_recidive_converge_adds_the_takserver_exemption_on_v10_1_30_boxes():
    box = _Box({RECIDIVE: '[recidive]\nignoreregex = \\[mediamtx-rtsp\\] Ban\n'})
    rewrites = []
    ns = _ns(funcs=('_startup_converge_recidive_tak_exempt',),
             _f2b_recidive_enabled=lambda: True,
             _f2b_read_text=box.read,
             _f2b_read_recidive_config=lambda: {'maxretry': 4, 'findtime': 43200},
             _f2b_write_recidive_config=lambda m, f: (rewrites.append((m, f)),
                                                      box.write(RECIDIVE, 'takserver')),
             _sudo_wrap=lambda c: c,
             subprocess=types.SimpleNamespace(run=box.run))
    ns['_startup_converge_recidive_tak_exempt']()
    assert rewrites == [(4, 43200)] and box.reloads == 1
    ns['_startup_converge_recidive_tak_exempt']()
    assert rewrites == [(4, 43200)] and box.reloads == 1


def test_converges_run_in_startup_migrations_after_the_broker_gate():
    i = APP.index('def _startup_migrations(')
    body = APP[i:]
    gate = body.index('_startup_converge_recidive_bantime()')
    assert body.index('_startup_converge_tak_banaction()') > gate
    assert body.index('_startup_converge_recidive_tak_exempt()') > gate


# ── 4. Plain words: what the ban means and what to do ────────────────────────────────

def test_bad_cert_device_is_explained_with_the_fix():
    ns = _ns(consts=CLASSIFY_CONSTS, funcs=CLASSIFY)
    found = ns['_f2b_tak_failures']([BAD_CERT] * 20 + [RESET_WITH_SUBJECT, NO_CERT, NOT_TLS],
                                    ['203.0.113.9', '198.51.100.7', '192.0.2.44'])
    assert found['203.0.113.9'] == {'kind': 'bad_cert', 'count': 20, 'subject': ''}   # reset skipped
    assert found['198.51.100.7']['kind'] == 'no_cert'
    assert found['192.0.2.44']['kind'] == 'not_tak'
    msg = ns['_f2b_tak_ban_explain']('203.0.113.9', 'bad_cert', '', ns['_f2b_duration_label'](3600))
    assert msg == ("A device at 203.0.113.9 kept failing TAK's certificate check, so it's blocked "
                   "from TAK for 1 h. Usually that's an ATAK/iTAK profile with an old certificate. "
                   "Re-enroll it or remove that server from the device.")


def test_cert_subject_is_shown_when_tak_logs_one():
    ns = _ns(consts=CLASSIFY_CONSTS, funcs=CLASSIFY)
    rec = ns['_f2b_tak_failures']([SUBJECT], ['203.0.113.10'])['203.0.113.10']
    assert rec['subject'] == 'CN=old-phone, OU=IT, O=FIRE'
    assert 'Certificate: CN=old-phone, OU=IT, O=FIRE.' in ns['_f2b_tak_ban_explain'](
        '203.0.113.10', rec['kind'], rec['subject'], '1 h')


def test_ban_details_cover_every_banned_ip_even_without_log_lines():
    ns = _ns(consts=CLASSIFY_CONSTS + ('_F2B_TAK_LOG', '_F2B_TAK_LOG_TAIL_BYTES'),
             funcs=CLASSIFY + ('_f2b_tak_ban_details',),
             _diag_tail=lambda p, n: [BAD_CERT])
    det = ns['_f2b_tak_ban_details'](['203.0.113.9', '192.0.2.200'], 3600)
    assert det['203.0.113.9']['kind'] == 'bad_cert'
    assert det['192.0.2.200']['explain'] == ("192.0.2.200 kept failing to connect to TAK, so it's "
                                             "blocked from TAK for 1 h.")
    ns['_diag_tail'] = lambda p, n: None                 # log unreadable: still an answer
    assert ns['_f2b_tak_ban_details'](['203.0.113.9'], 1800)['203.0.113.9']['kind'] == 'other'


def test_takserver_status_api_returns_the_explanations():
    src = _func('fail2ban_tak_status_api')
    assert "status['ban_details'] = _f2b_tak_ban_details(" in src


def test_ban_email_uses_the_same_words_as_the_console():
    ns = _ns(consts=CLASSIFY_CONSTS, funcs=CLASSIFY)
    mod = _notify_module()
    for line in (BAD_CERT, NO_CERT, NOT_TLS, SUBJECT, PFX + 'x.Y: z. Additional info: Remote address: 1.2.3.4; '):
        m1, m2 = ns['_F2B_TAK_FAIL_RE'].search(line), mod._TAK_FAIL_RE.search(line)
        assert ns['_f2b_tak_failure_kind'](m1['cause'], m1['rest']) == \
            mod._tak_failure_kind(m2['cause'], m2['rest'])
    for kind in ('bad_cert', 'no_cert', 'not_tak', 'other'):
        for subject in ('', 'CN=x'):
            assert ns['_f2b_tak_ban_explain']('203.0.113.9', kind, subject, '1 h') == \
                mod._tak_explain('203.0.113.9', kind, subject, '1 h')
    for secs in (60, 1800, 3600, 7200, 86400, 604800):
        assert ns['_f2b_duration_label'](secs) == mod._duration_label(secs)


def test_ban_email_reads_the_tak_log_and_jail(tmp_path):
    mod = _notify_module()
    log = tmp_path / 'takserver-messaging.log'
    log.write_text('\n'.join([BAD_CERT] * 20 + [SUBJECT]) + '\n')
    jail = tmp_path / 'infratak-takserver.conf'
    jail.write_text('[takserver]\nbantime  = 7200\n')
    mod.TAK_LOG, mod.TAK_JAIL = str(log), str(jail)
    text = mod._tak_reason('203.0.113.9')
    assert text.startswith("A device at 203.0.113.9 kept failing TAK's certificate check, so it's "
                           "blocked from TAK for 2 h.")
    assert "Only TAK's ports are blocked. The console, Authentik and SSH still work" in text


def test_page_shows_bad_cert_bans_up_front_and_escapes_them():
    assert 'id="tak-badcert-note"' in TEMPLATE
    assert "x.kind === 'bad_cert'" in TEMPLATE
    assert '_takEsc(window._takBanDetails[ip].explain)' in TEMPLATE
    assert "A TAK Server ban blocks only TAK's ports" in TEMPLATE


# ── 5. recidive panel matches what the firewall actually blocks ─────────────────────

UFW_STATUS = """Status: active

To                         Action      From
--                         ------      ----
Anywhere                   REJECT      203.0.113.50            # by Fail2Ban after 3 attempts against recidive
22/tcp                     ALLOW       Anywhere
Anywhere (v6)              REJECT      2001:db8::5
8089/tcp                   ALLOW       Anywhere
"""


def test_recidive_ban_without_a_firewall_rule_is_reported():
    ns = _ns(funcs=('_f2b_ufw_blocked_ips', '_f2b_recidive_not_enforced'),
             _distro_family=lambda: 'debian',
             _sudo_wrap=lambda c: c,
             subprocess=types.SimpleNamespace(
                 run=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=UFW_STATUS)))
    assert ns['_f2b_recidive_not_enforced'](
        ['203.0.113.50', '198.51.100.23', '2001:db8::5']) == ['198.51.100.23']


def test_recidive_check_stays_quiet_when_the_firewall_cannot_be_read():
    for family, out in (('rhel', UFW_STATUS), ('debian', 'ERROR: problem running')):
        ns = _ns(funcs=('_f2b_ufw_blocked_ips', '_f2b_recidive_not_enforced'),
                 _distro_family=lambda f=family: f,
                 _sudo_wrap=lambda c: c,
                 subprocess=types.SimpleNamespace(
                     run=lambda *a, o=out, **k: types.SimpleNamespace(returncode=1, stdout=o)))
        assert ns['_f2b_recidive_not_enforced'](['198.51.100.23']) == []
    assert "status['not_enforced'] = _f2b_recidive_not_enforced(" in _func('fail2ban_recidive_status_api')
    assert 'not in firewall' in TEMPLATE
