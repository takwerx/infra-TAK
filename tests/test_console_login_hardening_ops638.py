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
"""Console password login hardening (ops #638).

The contract pinned here:
- every failed console password login (POST /login and POST /) writes one line with the
  real client address to the file the `infratak-console` fail2ban jail reads; the password
  is never written; a good login writes nothing;
- the shipped filter matches exactly that line, and not the seed line;
- the jail bans the console and web ports only, and reaches existing boxes on console start;
- start.sh, reset-console-password.sh and the console page refuse a password under 12
  characters, and the scripts never put the password in a process's argv;
- a password not known to meet the floor shows a change-password banner.
"""

import ast
import datetime
import ipaddress
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)


def _src(names, assigns=()):
    parts, found = [], set()
    for node in _TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            parts.append(ast.get_source_segment(APP, node))
            found.add(node.name)
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], 'id', None) in assigns):
            parts.append(ast.get_source_segment(APP, node))
            found.add(node.targets[0].id)
    missing = (set(names) | set(assigns)) - found
    assert not missing, 'not in app.py: %s' % sorted(missing)
    return '\n\n'.join(parts)


def _func_body(name):
    node = next(n for n in _TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(APP, node)


# --------------------------------------------------------------------------- #
# Failed logins are recorded (POST /login and POST /)
# --------------------------------------------------------------------------- #

flask = pytest.importorskip('flask')
werkzeug_security = pytest.importorskip('werkzeug.security')

RIGHT = 'correct-horse-battery'


@pytest.fixture
def login_app(tmp_path):
    cfg = tmp_path / 'config'
    cfg.mkdir()
    auth_path = cfg / 'auth.json'
    auth_path.write_text(json.dumps(
        {'password_hash': werkzeug_security.generate_password_hash(RIGHT, method='pbkdf2:sha256')}))
    audits, printed = [], []

    def load_auth():
        return json.loads(auth_path.read_text())

    def save_auth(d):
        auth_path.write_text(json.dumps(d))

    app = flask.Flask('ops638')
    app.secret_key = 'test'
    g = {
        'os': os, 'json': json, 'datetime': datetime.datetime, 'ipaddress': ipaddress, 'time': __import__('time'),
        'CONFIG_DIR': str(cfg),
        'request': flask.request, 'session': flask.session, 'redirect': flask.redirect,
        'url_for': flask.url_for,
        'render_template': lambda tpl, **kw: 'page error=%s' % kw.get('error'),
        'load_auth': load_auth, 'save_auth': save_auth,
        'check_password_hash': werkzeug_security.check_password_hash,
        '_upgrade_password_hash': lambda auth, pw: None,
        'stored_hash_unusable': lambda h: None,
        '_apply_authentik_session': lambda: False,
        '_login_logo_url': lambda: None,
        '_stamp_session_login': lambda: None,   # session stamp from a parallel login change, if present
        'audit': lambda ev, detail='': audits.append((ev, detail)),
        'VERSION': 'test',
        'print': lambda *a, **kw: printed.append(' '.join(str(x) for x in a)),
    }
    exec(_src({'_client_ip', '_safe_next_path', '_console_log_failed_login', '_note_password_length',
               '_console_password_needs_change', 'login', 'index'},
              {'CONSOLE_PASSWORD_MIN_LEN', 'CONSOLE_LOGIN_FAIL_LOG', 'CONSOLE_LOGIN_FAIL_LOG_MAX'}), g)
    app.add_url_rule('/login', 'login', g['login'], methods=['GET', 'POST'])
    app.add_url_rule('/', 'index', g['index'], methods=['GET', 'POST'])
    app.add_url_rule('/console', 'console_page', lambda: 'console')
    g.update(app=app, audits=audits, printed=printed, log=cfg / 'console-auth.log', auth_path=auth_path)
    return g


def _lines(path):
    return path.read_text().splitlines() if path.exists() else []


@pytest.mark.parametrize('path', ['/login', '/'])
def test_failed_login_writes_one_line_with_the_client_address(login_app, path):
    c = login_app['app'].test_client()
    r = c.post(path, data={'password': 'wrong-guess-123'}, environ_base={'REMOTE_ADDR': '203.0.113.7'})
    assert r.status_code == 200 and 'Invalid password' in r.get_data(as_text=True)
    lines = _lines(login_app['log'])
    assert len(lines) == 1
    assert re.fullmatch(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d console: failed login from 203\.0\.113\.7', lines[0])
    assert 'wrong-guess-123' not in login_app['log'].read_text()
    assert oct(stat.S_IMODE(os.stat(login_app['log']).st_mode)) == '0o600'
    # and the operator sees it in the journal (stdout), and W3 audit gets it
    assert any('failed console password login from 203.0.113.7' in p for p in login_app['printed'])
    assert login_app['audits'] and login_app['audits'][-1][0] == 'auth:login-failed'


def test_behind_caddy_the_real_client_is_recorded(login_app):
    c = login_app['app'].test_client()
    c.post('/login', data={'password': 'x'}, headers={'X-Forwarded-For': '198.51.100.9'},
           environ_base={'REMOTE_ADDR': '127.0.0.1'})
    assert _lines(login_app['log'])[-1].endswith('from 198.51.100.9')


def test_a_junk_forwarded_header_falls_back_to_the_peer(login_app):
    c = login_app['app'].test_client()
    c.post('/login', data={'password': 'x'}, headers={'X-Forwarded-For': 'not an ip'},
           environ_base={'REMOTE_ADDR': '127.0.0.1'})
    assert _lines(login_app['log'])[-1].endswith('from 127.0.0.1')


def test_a_good_login_writes_nothing_and_notes_the_length(login_app):
    c = login_app['app'].test_client()
    r = c.post('/login', data={'password': RIGHT}, environ_base={'REMOTE_ADDR': '203.0.113.7'})
    assert r.status_code == 302
    assert _lines(login_app['log']) == []
    assert json.loads(login_app['auth_path'].read_text())['password_min_len_ok'] is True
    assert login_app['_console_password_needs_change']() is False


def test_a_short_password_login_keeps_the_banner(login_app):
    login_app['auth_path'].write_text(json.dumps(
        {'password_hash': werkzeug_security.generate_password_hash('short', method='pbkdf2:sha256')}))
    assert login_app['_console_password_needs_change']() is True   # set before the fix
    login_app['app'].test_client().post('/', data={'password': 'short'})
    assert json.loads(login_app['auth_path'].read_text())['password_min_len_ok'] is False
    assert login_app['_console_password_needs_change']() is True


def test_the_log_rolls_and_keeps_writing(login_app):
    login_app['log'].write_text('x' * (login_app['CONSOLE_LOGIN_FAIL_LOG_MAX'] + 1))
    login_app['app'].test_client().post('/login', data={'password': 'x'})
    assert (login_app['log'].parent / 'console-auth.log.1').exists()
    assert len(_lines(login_app['log'])) == 1


# --------------------------------------------------------------------------- #
# The fail2ban filter matches the producer's line
# --------------------------------------------------------------------------- #

def _filter_regexes():
    ns = {}
    exec(_src(set(), {'_F2B_OWNED_FILTERS'}), ns)
    text = ns['_F2B_OWNED_FILTERS']['infratak-console']
    m = re.search(r'^failregex = (.*)$', text, re.M)
    assert m
    # fail2ban's <HOST> → a capture; the rest is plain Python re
    return text, re.compile(m.group(1).replace('<HOST>', r'(?P<host>[0-9a-fA-F:.]+)'))


def test_filter_matches_the_logged_line_with_and_without_the_date():
    text, rx = _filter_regexes()
    for line in ('2026-11-10 21:54:43 console: failed login from 203.0.113.7',
                 'console: failed login from 203.0.113.7',
                 '2026-11-10 21:54:43 console: failed login from 2001:db8::5'):
        m = rx.search(line)
        assert m, line
        assert m.group('host') in ('203.0.113.7', '2001:db8::5')
    assert 'datepattern = ^%%Y-%%m-%%d %%H:%%M:%%S' in text


def test_filter_ignores_the_seed_line_and_trailing_junk():
    _t, rx = _filter_regexes()
    assert not rx.search('2026-11-10 21:54:43 console: jail armed (no failed logins yet)')
    assert not rx.search('2026-11-10 21:54:43 console: failed login from 1.2.3.4 extra')


# --------------------------------------------------------------------------- #
# The jail
# --------------------------------------------------------------------------- #

@pytest.fixture
def jail_ns(tmp_path):
    files, runs, removed, selinux = {}, [], [], {'mode': ''}

    class R:
        def __init__(self, rc=0, out=''):
            self.returncode, self.stdout, self.stderr = rc, out, ''

    def run(cmd, **kw):
        if cmd == ['getenforce']:
            if not selinux['mode']:
                raise FileNotFoundError('getenforce')   # Debian: no SELinux tools
            return R(0, selinux['mode'] + '\n')
        runs.append(cmd)
        return R(0)

    def remove_jail(jail_file, why, plog=None):
        removed.append((jail_file, why))
        files.pop('/etc/fail2ban/jail.d/' + jail_file, None)
        return True

    g = {
        'os': os, 're': re, 'datetime': datetime.datetime,
        'CONFIG_DIR': str(tmp_path),
        'load_settings': lambda: {'console_port': 5001},
        '_caddy_http_port': lambda s: 80, '_caddy_https_port': lambda s: 443,
        '_f2b_trusted_ignoreip': lambda extra='': ('127.0.0.1/8 ::1 ' + extra).strip(),
        '_f2b_operator_extra': lambda stored: ' '.join(t for t in stored.split() if t not in ('127.0.0.1/8', '::1')),
        '_f2b_is_available': lambda: True,
        '_makedirs_priv': lambda p, exist_ok=True: None,
        '_write_priv': lambda p, c: files.__setitem__(p, c),
        '_f2b_read_text': lambda p: files.get(p),
        '_f2b_loaded_jails': lambda: ['sshd'] + (['infratak-console'] if runs else []),
        '_sudo_wrap': lambda a: a,
        '_f2b_remove_jail': remove_jail,
        'subprocess': type('S', (), {'run': staticmethod(run)}),
    }
    exec(_src({'_f2b_banaction_console', '_f2b_console_jail_text', '_f2b_arm_console_jail',
               '_f2b_console_log_selinux_block'},
              {'CONSOLE_LOGIN_FAIL_LOG', '_F2B_OWNED_FILTERS', 'CONSOLE_F2B_JAIL', 'CONSOLE_F2B_JAIL_PATH',
               'CONSOLE_F2B_FILTER_PATH', 'CONSOLE_F2B_MAXRETRY', 'CONSOLE_F2B_FINDTIME',
               'CONSOLE_F2B_BANTIME', '_F2B_READABLE_SELINUX_TYPES'}), g)
    g.update(files=files, runs=runs, removed=removed, selinux=selinux)
    return g


def test_jail_reads_the_failure_log_and_bans_console_ports_only(jail_ns):
    text = jail_ns['_f2b_console_jail_text']()
    assert text.startswith('[infratak-console]\nenabled  = true\nfilter   = infratak-console\n')
    assert 'logpath  = %s\n' % jail_ns['CONSOLE_LOGIN_FAIL_LOG'] in text
    assert 'iptables-multiport[name=infratak-console, port="80,443,5001", protocol=tcp]' in text
    assert 'ufw' not in text and 'allports' not in text   # never cuts TAK or SSH
    for p in ('8089', '8443', '8446', '22'):
        assert p not in text.split('action')[1]


def test_arm_writes_filter_jail_and_seed_then_is_idempotent(jail_ns):
    ok, msg = jail_ns['_f2b_arm_console_jail']()
    assert ok, msg
    assert jail_ns['files'][jail_ns['CONSOLE_F2B_FILTER_PATH']] == jail_ns['_F2B_OWNED_FILTERS']['infratak-console']
    assert jail_ns['files'][jail_ns['CONSOLE_F2B_JAIL_PATH']] == jail_ns['_f2b_console_jail_text']()
    assert ['fail2ban-client', 'reload'] in jail_ns['runs']
    assert ['fail2ban-client', 'status', 'infratak-console'] in jail_ns['runs']
    seed = pathlib.Path(jail_ns['CONSOLE_LOGIN_FAIL_LOG']).read_text()
    assert 'jail armed' in seed and os.path.getsize(jail_ns['CONSOLE_LOGIN_FAIL_LOG']) > 0
    n = len(jail_ns['runs'])
    ok, msg = jail_ns['_f2b_arm_console_jail']()
    assert ok and 'already' in msg and len(jail_ns['runs']) == n


def test_arm_keeps_an_operator_ignoreip_entry(jail_ns):
    jail_ns['_f2b_arm_console_jail']()
    p = jail_ns['CONSOLE_F2B_JAIL_PATH']
    jail_ns['files'][p] = jail_ns['files'][p].replace('ignoreip = 127.0.0.1/8 ::1', 'ignoreip = 127.0.0.1/8 ::1 192.0.2.50')
    jail_ns['_f2b_arm_console_jail']()
    assert 'ignoreip = 127.0.0.1/8 ::1 192.0.2.50\n' in jail_ns['files'][p]


def _label(monkeypatch, typ):
    monkeypatch.setattr(os, 'getxattr', lambda p, name: ('system_u:object_r:%s:s0\x00' % typ).encode(),
                        raising=False)


@pytest.mark.parametrize('typ', ['admin_home_t', 'user_home_t'])
def test_selinux_home_install_is_not_armed_and_an_old_jail_is_removed(jail_ns, monkeypatch, typ):
    """fail2ban_t cannot read a log under /root or /home; a jail on it would stop fail2ban."""
    jail_ns['files'][jail_ns['CONSOLE_F2B_JAIL_PATH']] = '[infratak-console]\n'
    jail_ns['selinux']['mode'] = 'Enforcing'
    _label(monkeypatch, typ)
    ok, msg = jail_ns['_f2b_arm_console_jail']()
    assert ok is False and typ in msg and 'still logged' in msg
    assert jail_ns['CONSOLE_F2B_JAIL_PATH'] not in jail_ns['files']
    assert jail_ns['removed'] and jail_ns['removed'][0][0] == 'infratak-console.conf'
    assert jail_ns['runs'] == []


@pytest.mark.parametrize('mode,typ', [('Enforcing', 'usr_t'), ('Permissive', 'admin_home_t')])
def test_selinux_readable_or_permissive_is_armed(jail_ns, monkeypatch, mode, typ):
    jail_ns['selinux']['mode'] = mode
    _label(monkeypatch, typ)
    ok, msg = jail_ns['_f2b_arm_console_jail']()
    assert ok, msg
    assert jail_ns['CONSOLE_F2B_JAIL_PATH'] in jail_ns['files']


def test_no_fail2ban_is_not_an_error(jail_ns):
    jail_ns['_f2b_is_available'] = lambda: False
    ok, msg = jail_ns['_f2b_arm_console_jail']()
    assert ok is False and 'not installed' in msg and jail_ns['files'] == {}


def test_jail_reaches_new_and_existing_boxes():
    assert '_f2b_arm_console_jail()' in _func_body('_startup_migrations')
    assert '_f2b_arm_console_jail()' in _func_body('fail2ban_install_api')
    assert '_f2b_arm_console_jail()' in _func_body('_f2b_rewrite_all_jails')
    un = _func_body('fail2ban_uninstall_api')
    assert 'CONSOLE_F2B_JAIL_PATH' in un and 'CONSOLE_F2B_FILTER_PATH' in un


# --------------------------------------------------------------------------- #
# 12-character floor
# --------------------------------------------------------------------------- #

def test_console_page_change_needs_12(tmp_path):
    saved = []
    h = werkzeug_security.generate_password_hash('old', method='pbkdf2:sha256')
    g = {
        'request': flask.request, 'jsonify': flask.jsonify, 'datetime': datetime.datetime,
        'login_required': lambda f: f,
        'load_auth': lambda: {'password_hash': h},
        'save_auth': saved.append,
        'check_password_hash': werkzeug_security.check_password_hash,
        'generate_password_hash': lambda p: 'H(%s)' % p,
        '_detached_console_restart': lambda: None,
        '_stamp_session_login': lambda: None,
    }
    exec(_src({'console_password_reset'}, {'CONSOLE_PASSWORD_MIN_LEN'}), g)
    app = flask.Flask('ops638b')
    app.secret_key = 'x'
    eleven = 'a' * 11
    with app.test_request_context(json={'current_password': 'old', 'new_password': eleven,
                                        'new_password_confirm': eleven}):
        resp, status = g['console_password_reset']()
    assert status == 400 and '12' in resp.get_json()['error'] and not saved
    twelve = 'a' * 12
    with app.test_request_context(json={'current_password': 'old', 'new_password': twelve,
                                        'new_password_confirm': twelve}):
        g['console_password_reset']()
    assert saved and saved[0]['password_min_len_ok'] is True


def test_help_form_and_banner_say_12():
    help_html = (REPO / 'templates' / 'help.html').read_text(encoding='utf-8')
    assert 'neu.length<12' in help_html and 'neu.length<8' not in help_html
    assert 'id="reset-console-password"' in help_html
    console = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')
    assert '{% if console_password_needs_change %}' in console
    assert '/help#reset-console-password' in console
    assert 'console_password_needs_change=_console_password_needs_change()' in _func_body('console_page')


bash = shutil.which('bash')
needs_bash = pytest.mark.skipif(not bash, reason='bash not available')


def _fake_venv(root, argv_log):
    """INSTALL_DIR/.venv/bin/python3 that records its argv, then runs the real python."""
    b = root / '.venv' / 'bin'
    b.mkdir(parents=True)
    py = b / 'python3'
    py.write_text('#!/bin/sh\nprintf "%%s\\n" "$@" >> "%s"\nexec "%s" "$@"\n' % (argv_log, sys.executable))
    py.chmod(0o755)


@needs_bash
@pytest.mark.parametrize('pw,ok', [('a' * 11, False), ('Long-enough-12', True)])
def test_reset_script_floor_and_no_argv(tmp_path, pw, ok):
    root = tmp_path / 'infratak'
    root.mkdir()
    shutil.copy(REPO / 'reset-console-password.sh', root / 'reset-console-password.sh')
    argv_log = tmp_path / 'argv.log'
    _fake_venv(root, argv_log)
    env = dict(os.environ, PATH='/usr/bin:/bin')   # no systemctl unit to redirect us
    r = subprocess.run([bash, str(root / 'reset-console-password.sh')], input='%s\n%s\n' % (pw, pw),
                       capture_output=True, text=True, timeout=60, env=env, cwd=str(root))
    auth = root / '.config' / 'auth.json'
    if not ok:
        assert r.returncode != 0
        assert 'at least 12 characters' in r.stdout
        assert not auth.exists()
        return
    assert r.returncode == 0, r.stdout + r.stderr
    data = json.loads(auth.read_text())
    assert data['password_min_len_ok'] is True
    assert werkzeug_security.check_password_hash(data['password_hash'], pw)
    assert pw not in argv_log.read_text()


def _first_time_setup_harness(tmp_path):
    text = (REPO / 'start.sh').read_text(encoding='utf-8')
    # Ends at the `}` before the next section banner (the auth.json heredoc has a `}` too).
    m = re.search(r'^first_time_setup\(\) \{\n.*?^\}\n(?=\n# =+\n)', text, re.M | re.S)
    assert m
    floor = re.search(r'^CONSOLE_PASSWORD_MIN_LEN=(\d+)', text, re.M)
    assert floor, 'start.sh must define CONSOLE_PASSWORD_MIN_LEN'
    root = tmp_path / 'infratak'
    root.mkdir()
    argv_log = tmp_path / 'argv.log'
    _fake_venv(root, argv_log)
    script = tmp_path / 'harness.sh'
    script.write_text(
        'set -e\n'
        f'INSTALL_DIR="{root}"; CONFIG_DIR="$INSTALL_DIR/.config"\n'
        'AUTH_FILE="$CONFIG_DIR/auth.json"; SETTINGS_FILE="$CONFIG_DIR/settings.json"\n'
        f'CONSOLE_PASSWORD_MIN_LEN={floor.group(1)}\n'
        "RED=''; GREEN=''; BOLD=''; NC=''\n"
        'detect_server_ip() { echo 192.0.2.1; }\n'
        + m.group(0) + 'first_time_setup\n')
    return root, script, argv_log


@needs_bash
def test_start_sh_refuses_a_short_password(tmp_path):
    root, script, _ = _first_time_setup_harness(tmp_path)
    short = 'a' * 11
    r = subprocess.run([bash, str(script)], input='%s\n%s\n' % (short, short),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0   # asked again, then stdin ran out
    assert 'at least 12 characters' in r.stdout
    assert not (root / '.config' / 'auth.json').exists()


@needs_bash
def test_start_sh_accepts_12_and_keeps_it_out_of_argv(tmp_path):
    root, script, argv_log = _first_time_setup_harness(tmp_path)
    short, good = 'a' * 11, 'Long-enough-12'
    r = subprocess.run([bash, str(script)], input='%s\n%s\n%s\n%s\n' % (short, short, good, good),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    data = json.loads((root / '.config' / 'auth.json').read_text())
    assert werkzeug_security.check_password_hash(data['password_hash'], good)
    assert data['password_min_len_ok'] is True
    assert good not in argv_log.read_text()
