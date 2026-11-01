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
"""fail2ban jails that read a log file keep reading it on Ubuntu 24.04 (infra-TAK #338).

Ubuntu 24.04's fail2ban ships `[DEFAULT] backend = systemd` in jail.d/defaults-debian.conf.
Our jail files set a logpath and no backend, so after a 22.04 -> 24.04 upgrade (and on a
fresh 24.04 box) the takserver, takportal, authentik and recidive jails read the journal,
reported `No file is currently monitored`, and never banned. Every jail we write now names
`backend = auto`, existing files are repaired at console start, a jail that still tails no
file is reported dead, and the Fail2ban page no longer asks for a manual-bans jail that does
not exist. The functions run from the shipped app.py text.
"""

import ast
import configparser
import os
import pathlib
import re
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


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


def _pin():
    ns = {'re': re}
    exec(_func('_f2b_pin_file_backend'), ns)
    return ns['_f2b_pin_file_backend']


def _section(text):
    cp = configparser.ConfigParser(interpolation=None, strict=True)
    cp.read_string(text)
    return cp[cp.sections()[0]]


# What v10.3.2 wrote, verbatim shape.
OLD_TAK = ('[takserver]\nenabled  = true\nfilter   = takserver\n'
           'logpath  = /opt/tak/logs/takserver-messaging.log\nmaxretry = 20\nfindtime = 300\n'
           'bantime  = 3600\nignoreip = 127.0.0.1/8 ::1\n'
           'action   = iptables-multiport[name=takserver, port="8089", protocol=tcp]\n'
           '         infratak-guarddog-takserver\n')


# ── 1. Every jail we write that reads a file names its backend ───────────────────────

def test_every_writer_that_sets_a_logpath_also_sets_the_file_backend():
    writers = []
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef):
            src = ast.get_source_segment(APP, n)
            if re.search(r'''^\s*f?"logpath  = ''', src, re.M):
                writers.append(n.name)
                assert 'backend  = auto' in src, n.name
    # takserver, takportal, authentik (x2), recidive, sshd, clientfeed, manual
    assert len(writers) >= 7, writers


def test_takserver_jail_is_written_reading_its_file():
    written = {}
    ns = {'re': re, 'os': os}
    exec(_consts('_F2B_TAK_PORTS_TCP'), ns)
    for f in ('_f2b_banaction_tak', '_f2b_write_tak_jail_config'):
        exec(_func(f), ns)
    ns.update(_makedirs_priv=lambda *a, **k: None,
              _write_priv=lambda p, c, **k: written.__setitem__(p, c),
              _f2b_trusted_ignoreip=lambda extra='': '127.0.0.1/8 ::1',
              _f2b_write_tak_badcert_jail_config=lambda ignoreip='': None)   # its own test
    ns['_f2b_write_tak_jail_config'](20, 300, 3600, '')
    sec = _section(written['/etc/fail2ban/jail.d/infratak-takserver.conf'])
    assert sec['backend'] == 'auto'
    assert sec['logpath'] == '/opt/tak/logs/takserver-messaging.log'


def test_sshd_on_the_journal_stays_on_the_journal():
    src = _func('_f2b_write_ssh_jail_config')
    assert '"backend  = systemd\\n"' in src          # no syslog file: journal, no logpath


# ── 2. The repair for jail files already on disk ─────────────────────────────────────

def test_pin_adds_auto_under_the_header_and_keeps_everything_else():
    new = _pin()(OLD_TAK)
    assert new.startswith('[takserver]\nbackend  = auto\nenabled  = true\n')
    assert new.replace('backend  = auto\n', '', 1) == OLD_TAK
    sec = _section(new)
    assert sec['backend'] == 'auto'
    assert 'infratak-guarddog-takserver' in sec['action']   # continuation line intact


def test_pin_is_idempotent_and_leaves_other_jails_alone():
    pin = _pin()
    once = pin(OLD_TAK)
    assert pin(once) == once
    journal = '[sshd]\nenabled = true\nbackend  = systemd\nfilter = sshd\n'
    assert pin(journal) == journal                       # names its backend already
    nolog = '[infratak-x]\nenabled = true\nfilter = x\n'
    assert pin(nolog) == nolog                           # no file to read


def test_pin_keeps_a_multiline_logpath_intact():
    text = '[custom]\nenabled = true\nlogpath = /var/log/a.log\n          /var/log/b.log\nfilter = x\n'
    sec = _section(_pin()(text))
    assert sec['backend'] == 'auto'
    assert sec['logpath'].split() == ['/var/log/a.log', '/var/log/b.log']


class _Run:
    def __init__(self, active='active'):
        self.calls = []
        self.active = active

    def __call__(self, cmd, **_k):
        self.calls.append(list(cmd))
        return types.SimpleNamespace(returncode=0, stdout=self.active + '\n', stderr='')


def _guard(tmp_path, run):
    jaild = tmp_path / 'jail.d'
    jaild.mkdir()
    ns = {'re': re, 'os': os, 'subprocess': types.SimpleNamespace(run=run)}
    exec(_consts('_F2B_SELF_OWNED_LOGS', '_F2B_PARK_SUFFIX', '_F2B_NO_FILE_CACHE'), ns)
    for f in ('_f2b_pin_file_backend', '_f2b_enabled_jail_files', '_f2b_guard_jail_logpaths'):
        exec(_func(f).replace("'/etc/fail2ban/jail.d'", repr(str(jaild))), ns)
    ns.update(_f2b_is_available=lambda: True, _sudo_wrap=lambda c: c,
              _write_priv=lambda p, c, **k: pathlib.Path(p).write_text(c),
              TAKPORTAL_CADDY_LOG='/var/log/caddy/takportal-access.log')
    return ns, jaild


def test_console_start_repairs_existing_jails_and_reloads(tmp_path):
    run = _Run()
    ns, jaild = _guard(tmp_path, run)
    log = tmp_path / 'takserver-messaging.log'
    log.write_text('')
    (jaild / 'infratak-takserver.conf').write_text(OLD_TAK.replace(
        '/opt/tak/logs/takserver-messaging.log', str(log)))
    parked = jaild / 'infratak-authentik.conf.parked-missing-log'
    parked.write_text('[authentik]\nenabled  = true\nlogpath  = /nonexistent/auth.log\n')
    journal = '[sshd]\nenabled  = true\nfilter   = sshd\nbackend  = systemd\n'
    (jaild / 'infratak-sshd.conf').write_text(journal)
    ns['_F2B_NO_FILE_CACHE']['takserver'] = (time.monotonic(), True)
    said = []

    assert ns['_f2b_guard_jail_logpaths'](said.append) is True
    assert _section((jaild / 'infratak-takserver.conf').read_text())['backend'] == 'auto'
    assert 'backend  = auto' in parked.read_text()   # re-arms reading its file, not the journal
    assert (jaild / 'infratak-sshd.conf').read_text() == journal
    assert ['fail2ban-client', 'reload'] in run.calls
    assert ns['_F2B_NO_FILE_CACHE'] == {}            # the page re-asks after the repair
    assert any('infratak-takserver.conf' in m and 'backend = auto' in m for m in said)

    run.calls.clear()                                # second start: nothing left to do
    assert ns['_f2b_guard_jail_logpaths'](said.append) is False
    assert run.calls == []


def test_guard_runs_before_the_dead_jail_warning_at_startup():
    body = APP[APP.index('def _startup_migrations('):]
    assert body.index('_f2b_guard_jail_logpaths(') < body.index('_dead = _f2b_dead_jails()')


def test_sshd_falling_back_to_the_journal_names_one_backend(tmp_path):
    jaild = tmp_path / 'jail.d'
    jaild.mkdir()
    (jaild / 'infratak-sshd.conf').write_text(
        '[sshd]\nenabled  = true\nfilter   = sshd\nlogpath  = /nonexistent/auth.log\n'
        'backend  = auto\nmaxretry = 5\n')
    ns = {'re': re, 'os': os, 'subprocess': types.SimpleNamespace(run=_Run())}
    exec(_func('_f2b_selfheal_sshd_backend').replace("'/etc/fail2ban/jail.d'", repr(str(jaild))), ns)
    ns.update(_f2b_is_available=lambda: True, _sudo_wrap=lambda c: c,
              _write_priv=lambda p, c, **k: pathlib.Path(p).write_text(c))
    assert ns['_f2b_selfheal_sshd_backend']() is True
    sec = _section((jaild / 'infratak-sshd.conf').read_text())   # strict: one backend key
    assert sec['backend'] == 'systemd' and 'logpath' not in sec


# ── 3. A jail that tails no file is reported, not shown as protection ────────────────

NO_FILE = 'No file is currently monitored\n'
HAS_FILE = 'Current monitored log file(s):\n`- /opt/tak/logs/takserver-messaging.log\n'


def _probe(answer):
    calls = []

    def run(cmd, **_k):
        calls.append(list(cmd))
        return types.SimpleNamespace(returncode=0, stdout=answer, stderr='')
    ns = {'time': time, 'subprocess': types.SimpleNamespace(run=run), '_sudo_wrap': lambda c: c}
    exec(_consts('_F2B_NO_FILE_TTL', '_F2B_NO_FILE_CACHE'), ns)
    exec(_func('_f2b_jail_reads_no_file'), ns)
    return ns, calls


def test_probe_reads_fail2ban_and_caches_its_answer():
    ns, calls = _probe(NO_FILE)
    assert ns['_f2b_jail_reads_no_file']('takserver') is True
    assert ns['_f2b_jail_reads_no_file']('takserver') is True
    assert calls == [['fail2ban-client', 'get', 'takserver', 'logpath']]
    ns, _ = _probe(HAS_FILE)
    assert ns['_f2b_jail_reads_no_file']('takserver') is False


def test_probe_never_convicts_on_an_error():
    ns = {'time': time, '_sudo_wrap': lambda c: c,
          'subprocess': types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(
              returncode=255, stdout=NO_FILE, stderr='UnknownJailException'))}
    exec(_consts('_F2B_NO_FILE_TTL', '_F2B_NO_FILE_CACHE'), ns)
    exec(_func('_f2b_jail_reads_no_file'), ns)
    assert ns['_f2b_jail_reads_no_file']('takserver') is False


def _dead(tmp_path, reads_no_file):
    jail = tmp_path / 'infratak-takserver.conf'
    log = tmp_path / 'takserver-messaging.log'
    log.write_text('a line\n')
    jail.write_text(OLD_TAK.replace('/opt/tak/logs/takserver-messaging.log', str(log)))
    ns = {'re': re, 'os': os}
    exec(_func('_f2b_dead_jails'), ns)
    ns.update(_f2b_loaded_jails=lambda: ['takserver'],
              _f2b_enabled_jail_files=lambda: [('takserver', 'takserver', str(jail))],
              _f2b_jail_reads_no_file=lambda j: reads_no_file,
              _f2b_log_has_rotated_history=lambda p: False)
    return ns['_f2b_dead_jails']()


def test_deaf_jail_is_reported_dead_with_the_way_out(tmp_path):
    dead = _dead(tmp_path, True)
    assert len(dead) == 1 and dead[0][0] == 'takserver'
    assert 'No file is currently monitored' in dead[0][2]
    assert 'toggle this jail off and on' in dead[0][2]
    assert _dead(tmp_path, False) == []


# ── 4. No polling of a manual-bans jail that does not exist ──────────────────────────

def test_manual_bans_jail_is_not_asked_for_by_name_until_it_is_loaded():
    calls = []
    ns = {'ipaddress': __import__('ipaddress'), '_sudo_wrap': lambda c: c,
          'subprocess': types.SimpleNamespace(run=lambda cmd, **k: calls.append(cmd) or
                                              types.SimpleNamespace(returncode=0, stdout='')),
          '_f2b_parse_status': lambda raw: {'banned_ips': []}}
    exec(_consts('_F2B_MANUAL_JAIL'), ns)
    exec(_func('_f2b_manual_banned'), ns)
    ns['_f2b_loaded_jails'] = lambda: ['sshd', 'takserver']
    assert ns['_f2b_manual_banned']() is None and calls == []
    ns['_f2b_loaded_jails'] = lambda: ['sshd', 'infratak-manual']
    assert ns['_f2b_manual_banned']() == {}
    assert calls == [['fail2ban-client', 'status', 'infratak-manual']]
