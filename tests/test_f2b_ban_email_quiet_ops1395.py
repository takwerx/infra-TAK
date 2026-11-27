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
"""Routine fail2ban bans send no email (ops #1395).

10.4.7 to 10.4.9 mailed one message per banned address. test6 sent about 25 in 6 hours,
almost all from the SSH jail (the shared Guard Dog action called every jail "authentik").
Now a ban mails only when a person is needed: a TAK device that showed a certificate, or
failed SSH passwords for a real local account. Each name is mailed once a day and a box
at most 3 times a day. An optional daily summary is off by default. The script runs from
the shipped app.py text, with its log files, state file and SMTP replaced.
"""

import ast
import json
import os
import pathlib
import threading
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'fail2ban.html').read_text(encoding='utf-8')


def _script_text():
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == '_F2B_NOTIFY_SCRIPT'
                                             for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError('_F2B_NOTIFY_SCRIPT was renamed or removed')


class _Mail:
    def __init__(self):
        self.sent = []


def _pw(name, uid, shell='/bin/bash'):
    return types.SimpleNamespace(pw_name=name, pw_uid=uid, pw_shell=shell)


class _Box:
    """One fake box: settings, fail2ban.log, TAK log, ssh log, state file, SMTP."""

    def __init__(self, tmp_path, settings=None):
        self.tmp = tmp_path
        self.mail = _Mail()
        self.f2b_log = tmp_path / 'fail2ban.log'
        self.tak_log = tmp_path / 'takserver-messaging.log'
        self.ssh_log = ''
        self.smtp_down = False
        self.f2b_log.write_text('')
        self.tak_log.write_text('')
        self.settings_path = tmp_path / 'settings.json'
        base = {'guarddog_alert_email': 'owner@example.org', 'server_nickname': 'box1'}
        base.update(settings or {})
        self.settings_path.write_text(json.dumps(base))
        self.accounts = {
            'root': _pw('root', 0), 'postgres': _pw('postgres', 110),
            'nobody': _pw('nobody', 65534, '/usr/sbin/nologin'),
            'jsmith': _pw('jsmith', 1001), 'mary': _pw('mary', 1002),
            'ann': _pw('ann', 1003), 'bob': _pw('bob', 1004),
            'takwerx': _pw('takwerx', os.getuid()),
        }

    def ban(self, jail, ip, hint='authentik', ts=None):
        """fail2ban logs `[jail] Ban ip` first, then runs the action."""
        t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts or time.time()))
        with open(self.f2b_log, 'a') as f:
            f.write(f'{t},123 fail2ban.actions        [1003]: NOTICE  [{jail}] Ban {ip}\n')
        return self.run(ip, hint)

    def run(self, ip, hint):
        mod = types.ModuleType('infratak_f2b_notify')
        exec(compile(_script_text(), 'infratak-f2b-notify', 'exec'), mod.__dict__)
        mail = self.mail
        box = self

        class SMTP:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def sendmail(self, frm, to, text):
                if box.smtp_down:
                    raise OSError('connection refused')
                mail.sent.append((frm, to, text))

        mod.smtplib = types.SimpleNamespace(SMTP=SMTP)
        mod._find_settings = lambda: str(self.settings_path)
        mod.STATE_PATH = str(self.tmp / 'takguard' / 'state.json')
        mod.F2B_LOG = str(self.f2b_log)
        mod.TAK_LOG = str(self.tak_log)
        mod.TAK_JAIL = str(self.tmp / 'none')
        mod.TAK_BADCERT_JAIL = str(self.tmp / 'none2')
        mod._ssh_log_text = lambda: self.ssh_log

        class _Pwd:
            @staticmethod
            def getpwnam(name):
                if name not in self.accounts:
                    raise KeyError(name)
                return self.accounts[name]
        mod.pwd = _Pwd
        mod.sys = types.SimpleNamespace(argv=['x', ip, hint], stderr=open(os.devnull, 'w'),
                                        exit=lambda c=0: (_ for _ in ()).throw(SystemExit(c)))
        try:
            mod.main()
        except SystemExit:
            pass
        return mod

    def ssh_fail(self, user, ip, invalid=False):
        who = f'invalid user {user}' if invalid else user
        self.ssh_log += (f'2026-11-27T15:57:44.408041+00:00 responder sshd[1]: '
                         f'Failed password for {who} from {ip} port 50006 ssh2\n')

    def tak_line(self, ip, subject=''):
        extra = f'Peer certificate Subject DN: {subject}; ' if subject else \
            'Certificate error: peer not verified; '
        self.tak_log.write_text(self.tak_log.read_text() + (
            '2026-11-27-09:56:23.112 [x] ERROR y - NioNettyServerHandler error. Cause: '
            'javax.net.ssl.SSLHandshakeException: General OpenSslEngine problem. '
            f'Additional info: Remote address: {ip}; Remote port: 1; Local port: 8089; '
            + extra + '\n'))


# ── the proof test: a burst of routine bans sends nothing, one real-user ban sends one ──

def test_burst_of_50_routine_bans_sends_no_email_and_one_real_user_ban_sends_one(tmp_path):
    box = _Box(tmp_path)
    for i in range(50):
        ip = f'203.0.113.{i + 1}'
        name = ('root', 'admin', 'postgres', 'ubuntu', 'oracle')[i % 5]
        box.ssh_fail(name, ip, invalid=name in ('admin', 'ubuntu', 'oracle'))
        # the shared action passes 'authentik' for every jail; most bans are sshd
        box.ban('sshd' if i % 5 else 'authentik', ip)
    assert box.mail.sent == [], 'routine bans must not email'
    box.ssh_fail('jsmith', '198.51.100.9')
    box.ban('sshd', '198.51.100.9')
    assert len(box.mail.sent) == 1
    text = box.mail.sent[0][2]
    assert 'jsmith' in text and '198.51.100.9' in text
    assert box.mail.sent[0][1] == ['owner@example.org']


def test_scanners_on_tak_jails_send_nothing_but_a_device_with_a_certificate_sends_one(tmp_path):
    box = _Box(tmp_path)
    for i in range(20):
        box.tak_line(f'192.0.2.{i + 1}')                       # no client certificate
        box.ban('takserver', f'192.0.2.{i + 1}', hint='takserver')
    assert box.mail.sent == []
    box.tak_line('203.0.113.50', 'CN=old-phone, OU=IT, O=FIRE')
    box.ban('takserver', '203.0.113.50', hint='takserver')
    assert len(box.mail.sent) == 1
    text = box.mail.sent[0][2]
    assert 'old-phone' in text and 'real user may be locked out' in text


def test_the_old_action_that_always_says_authentik_cannot_mail_a_routine_ban(tmp_path):
    box = _Box(tmp_path)
    box.f2b_log.unlink()                 # jail unknown: falls back to the argument
    box.ssh_fail('jsmith', '203.0.113.7')
    box.run('203.0.113.7', 'authentik')
    box.run('203.0.113.7', 'authentik')
    assert box.mail.sent == []


def test_authentik_unknown_names_are_routine(tmp_path):
    box = _Box(tmp_path)
    for i in range(10):
        box.ban('authentik', f'203.0.113.{i + 1}')
    assert box.mail.sent == []


# ── what counts as a real account ───────────────────────────────────────────────────

def test_root_system_accounts_and_made_up_names_are_not_real_users(tmp_path):
    box = _Box(tmp_path)
    for name in ('root', 'postgres', 'nobody', 'admin', 'oracle', 'x;rm -rf'):
        box.ssh_fail(name, '203.0.113.8')
    box.ban('sshd', '203.0.113.8')
    assert box.mail.sent == []


def test_invalid_user_lines_never_count_even_for_a_real_name(tmp_path):
    box = _Box(tmp_path)
    box.ssh_fail('jsmith', '203.0.113.8', invalid=True)
    box.ban('sshd', '203.0.113.8')
    assert box.mail.sent == []


def test_the_console_user_counts_as_a_real_account(tmp_path):
    box = _Box(tmp_path)
    box.ssh_fail('takwerx', '203.0.113.8')
    box.ban('sshd', '203.0.113.8')
    assert len(box.mail.sent) == 1


def test_a_failure_from_another_address_does_not_count(tmp_path):
    box = _Box(tmp_path)
    box.ssh_fail('jsmith', '198.51.100.1')
    box.ban('sshd', '203.0.113.8')
    assert box.mail.sent == []


# ── even a real attack cannot flood ─────────────────────────────────────────────────

def test_the_same_name_is_mailed_once_a_day(tmp_path):
    box = _Box(tmp_path)
    for i in range(5):
        ip = f'203.0.113.{i + 1}'
        box.ssh_fail('jsmith', ip)
        box.ban('sshd', ip)
    assert len(box.mail.sent) == 1


def test_a_box_is_mailed_at_most_three_times_a_day(tmp_path):
    box = _Box(tmp_path)
    for i, who in enumerate(('jsmith', 'mary', 'ann', 'bob')):
        ip = f'203.0.113.{i + 1}'
        box.ssh_fail(who, ip)
        box.ban('sshd', ip)
    assert len(box.mail.sent) == 3


def test_the_slot_comes_back_when_the_mail_could_not_be_sent(tmp_path):
    box = _Box(tmp_path)
    box.ssh_fail('jsmith', '203.0.113.1')
    mod = box.ban('sshd', '203.0.113.1')
    assert len(box.mail.sent) == 1
    state = json.loads((tmp_path / 'takguard' / 'state.json').read_text())
    mod._person_undo(state, 'ssh:jsmith', time.time())
    assert state['person_sent'] == [] and 'ssh:jsmith' not in state['person_seen']


def test_a_burst_of_copies_writing_the_state_at_once_stays_exact(tmp_path):
    box = _Box(tmp_path)
    mod = box.run('203.0.113.1', 'authentik')
    now, verdicts = time.time(), []

    def one(i):
        v, ok = mod._locked_state(lambda st: mod._person_gate(st, f'ssh:u{i}', now))
        assert ok
        verdicts.append(v)
    threads = [threading.Thread(target=one, args=(i,)) for i in range(30)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert verdicts.count('send') == 3 and verdicts.count('cap') == 27
    assert json.loads((tmp_path / 'takguard' / 'state.json').read_text())['person_sent']


def test_a_broken_state_file_does_not_hide_a_real_user_ban(tmp_path):
    box = _Box(tmp_path)
    (tmp_path / 'takguard').mkdir()
    (tmp_path / 'takguard' / 'state.json').write_text('{not json')
    box.ssh_fail('jsmith', '203.0.113.1')
    box.ban('sshd', '203.0.113.1')
    assert len(box.mail.sent) == 1


# ── the owner's settings still rule ─────────────────────────────────────────────────

def test_paused_alerts_send_nothing(tmp_path):
    box = _Box(tmp_path, {'guarddog_alerts_paused': True})
    box.ssh_fail('jsmith', '203.0.113.1')
    box.ban('sshd', '203.0.113.1')
    assert box.mail.sent == []


def test_no_alert_address_sends_nothing_and_exits_clean(tmp_path):
    box = _Box(tmp_path, {'guarddog_alert_email': ''})
    box.ssh_fail('jsmith', '203.0.113.1')
    box.ban('sshd', '203.0.113.1')
    assert box.mail.sent == []


def test_a_box_with_no_mail_relay_exits_clean_and_the_next_ban_can_still_mail(tmp_path):
    box = _Box(tmp_path)
    box.smtp_down = True
    box.ssh_fail('jsmith', '203.0.113.1')
    box.ban('sshd', '203.0.113.1')                      # SMTP refused: no crash, nothing sent
    assert box.mail.sent == []
    box.smtp_down = False
    box.ban('sshd', '203.0.113.1')                      # the slot was given back, so this mails
    assert len(box.mail.sent) == 1


def test_a_failed_summary_mail_is_tried_again_at_the_next_ban(tmp_path):
    box = _Box(tmp_path, {'f2b_daily_summary': True})
    box.smtp_down = True
    box.ban('sshd', '203.0.113.1')
    assert box.mail.sent == []
    box.smtp_down = False
    box.ban('sshd', '203.0.113.2')
    assert len(box.mail.sent) == 1


def test_several_recipients_all_get_the_mail(tmp_path):
    box = _Box(tmp_path, {'guarddog_alert_email': 'a@example.org, b@example.org'})
    box.ssh_fail('jsmith', '203.0.113.1')
    box.ban('sshd', '203.0.113.1')
    assert box.mail.sent[0][1] == ['a@example.org', 'b@example.org']


def test_a_certificate_name_cannot_inject_a_mail_header(tmp_path):
    box = _Box(tmp_path)
    box.tak_line('203.0.113.50', 'CN=evil\r\nBcc: x@evil.test, O=FIRE')
    box.ban('takserver', '203.0.113.50', hint='takserver')
    head = box.mail.sent[0][2].split('\n\n', 1)[0]
    assert '\nBcc:' not in head and '\r' not in head


# ── the optional daily summary ──────────────────────────────────────────────────────

def test_summary_is_off_by_default(tmp_path):
    box = _Box(tmp_path)
    for i in range(10):
        box.ban('sshd', f'203.0.113.{i + 1}')
    assert box.mail.sent == []


def test_summary_when_on_sends_one_mail_a_day_with_counts_and_top_sources(tmp_path):
    box = _Box(tmp_path, {'f2b_daily_summary': True})
    for i in range(6):
        box.ban('sshd', '203.0.113.1')
    box.ban('sshd', '203.0.113.2')
    box.ban('authentik', '203.0.113.3')
    assert len(box.mail.sent) == 1, 'one summary, not one per ban'
    assert box.mail.sent[0][2].count('Subject: [box1] fail2ban:') == 1


def test_summary_text_has_the_count_the_jails_and_the_top_sources(tmp_path):
    box = _Box(tmp_path)
    for i in range(6):
        box.ban('sshd', '203.0.113.1')
    box.ban('sshd', '203.0.113.2')
    box.ban('authentik', '203.0.113.3')
    mod = box.run('203.0.113.99', 'authentik')
    text = mod._summary_text('box1', mod._recent_bans(time.time()))
    assert 'Bans:     8 from 3 addresses' in text
    assert 'sshd 7, authentik 1' in text
    assert '203.0.113.1  (6 bans)' in text


def test_summary_waits_24_hours_then_sends_again(tmp_path):
    box = _Box(tmp_path, {'f2b_daily_summary': True})
    box.ban('sshd', '203.0.113.1')
    assert len(box.mail.sent) == 1
    state = tmp_path / 'takguard' / 'state.json'
    st = json.loads(state.read_text())
    st['summary_at'] = time.time() - 90000
    state.write_text(json.dumps(st))
    box.ban('sshd', '203.0.113.2')
    assert len(box.mail.sent) == 2


def test_summary_ignores_bans_older_than_a_day(tmp_path):
    box = _Box(tmp_path, {'f2b_daily_summary': True})
    box.ban('sshd', '203.0.113.9', ts=time.time() - 3 * 86400)
    box.mail.sent.clear()
    mod = box.run('203.0.113.1', 'authentik')
    assert [b for b in mod._recent_bans(time.time()) if b[1] == '203.0.113.9'] == []


# ── what stays the same, and how it reaches a box ───────────────────────────────────

def test_the_dashboard_line_is_still_written_for_every_ban():
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == '_F2B_AUTHENTIK_GUARDDOG_ACTION'
                                             for t in n.targets):
            action = ast.literal_eval(n.value)
            assert '>> /var/log/takguard/restarts.log' in action
            assert 'fail2ban: Banned <ip>' in action
            assert 'infratak-f2b-notify <ip> authentik' in action   # action unchanged
            return
    raise AssertionError('action constant missing')


def test_an_existing_box_gets_the_new_script_at_the_next_console_start():
    src = APP[APP.index("notify_path = '/usr/local/sbin/infratak-f2b-notify'\n        cur = _f2b_read_text"):]
    assert 'cur != _F2B_NOTIFY_SCRIPT' in src[:300]


def test_summary_route_is_login_protected_off_by_default_and_the_page_has_the_checkbox():
    i = APP.index("@app.route('/api/fail2ban/ban-summary'")
    chunk = APP[i:i + 900]
    assert '@login_required' in chunk and "s.get('f2b_daily_summary', False)" in chunk
    assert 'id="f2b-daily-summary"' in TEMPLATE
    assert "fetch('/api/fail2ban/ban-summary'" in TEMPLATE


def test_the_state_file_sits_in_fail2bans_own_folder_so_selinux_lets_fail2ban_write_it():
    # Rocky/RHEL runs the ban action as fail2ban_t, which owns /var/lib/fail2ban
    # (fail2ban_var_lib_t) but is not known to create files in /var/log/takguard (var_log_t).
    assert "STATE_PATH = '/var/lib/fail2ban/infratak-f2b-notify-state.json'" in _script_text()


def test_uninstall_removes_the_state_files():
    assert "'/var/lib/fail2ban/infratak-f2b-notify-state.json'" in APP
    assert "'/var/lib/fail2ban/infratak-f2b-notify-state.json.lock'" in APP
