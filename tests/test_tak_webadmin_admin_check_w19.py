"""v10.3.5 W19: TAK Server handing webadmin no admin role after a box reboot (test8, 2026-11-03).

The once-per-TAK-start check logs in as webadmin on 8446 and restarts TAK only when TAK says
the session is not admin — never just because the boot heal ran (GH #83)."""
import ast
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _src(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _ns(**extra):
    ns = {'os': os, 'subprocess': subprocess, 'tempfile': tempfile, 'shutil': shutil, 'time': time,
          'threading': threading}
    for c in ('_TAK_WEBADMIN_CHECK_MIN_UPTIME_S', '_TAK_WEBADMIN_RESTART_MIN_GAP_S'):
        exec(_const(c), ns)
    ns.update(extra)
    return ns


# ── the 8446 login probe ────────────────────────────────────────────────────

def _probe_ns(token_code, is_admin_body, seen):
    def fake_run(argv, **kw):
        seen.append(list(argv))
        if argv[-1].endswith('/oauth/token'):
            pw_arg = [a for a in argv if a.startswith('password@')][0]
            path = pw_arg.split('@', 1)[1]
            seen.append(('pwfile', open(path).read(), oct(os.stat(path).st_mode & 0o777)))
            return types.SimpleNamespace(returncode=0, stdout=token_code, stderr='')
        return types.SimpleNamespace(returncode=0, stdout=is_admin_body, stderr='')
    ns = _ns(_tcp_accepts=lambda port: True)
    ns['subprocess'] = types.SimpleNamespace(run=fake_run)
    exec(_src('_tak_webadmin_login_is_admin'), ns)
    return ns['_tak_webadmin_login_is_admin']


@pytest.mark.parametrize('body,want', [('true', True), ('false', False), ('<html>', None)])
def test_probe_reads_tak_isadmin(body, want):
    seen = []
    assert _probe_ns('200', body, seen)('s3cret') is want


def test_probe_never_puts_the_password_on_the_command_line():
    seen = []
    _probe_ns('200', 'true', seen)('s3cret-pw')
    argvs = [a for a in seen if isinstance(a, list)]
    assert all('s3cret-pw' not in ' '.join(a) for a in argvs)
    pwfile = [a for a in seen if isinstance(a, tuple)][0]
    assert pwfile[1] == 's3cret-pw' and pwfile[2] == '0o600'


def test_probe_refused_login_is_unknown_not_false():
    seen = []
    assert _probe_ns('400', 'false', seen)('wrong') is None
    assert len([a for a in seen if isinstance(a, list)]) == 1   # never asked isAdmin


# ── the once-per-TAK-start auto check ───────────────────────────────────────

def _check_ns(verdicts, settings, started_ago=600, busy=False):
    restarts, logs = [], []
    store = {'s': dict(settings)}
    now = time.time()
    it = iter(verdicts)
    ns = _ns(
        load_settings=lambda: dict(store['s']),
        save_settings=lambda s: store.update(s=dict(s)),
        _tak_started_epoch=lambda: now - started_ago,
        _tak_cert_job_busy=lambda: busy,
        _tak_webadmin_login_is_admin=lambda pw: next(it),
        _tak_webadmin_probe_after_restart=lambda pw: next(it),
        _tak_restart_and_wait=lambda plog, tag: restarts.append(tag) or True,
        _tak_webadmin_fix_lock=threading.Lock(),
    )
    os_stub = types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True))
    ns['os'] = os_stub
    exec(_src('_tak_webadmin_admin_check'), ns)
    return ns['_tak_webadmin_admin_check'], restarts, logs, store


def test_admin_session_means_no_restart_and_no_recheck():
    check, restarts, logs, store = _check_ns([True], {'webadmin_password': 'pw'})
    check(logs.append, ldap_ok=True)
    check(logs.append, ldap_ok=True)          # second tick: already done for this TAK start
    assert restarts == [] and store['s']['tak_webadmin_check']['outcome'] == 'admin'


def test_admin_session_logs_a_line_so_the_console_log_shows_it_ran():
    # ops #465: the "all fine" path used to log nothing; only the saved state showed it ran.
    check, restarts, logs, store = _check_ns([True], {'webadmin_password': 's3cret-pw'})
    check(logs.append, ldap_ok=True)
    assert len(logs) == 1
    assert 'webadmin admin check' in logs[0] and 'TAK says admin' in logs[0] and 'no restart' in logs[0]
    assert 's3cret-pw' not in logs[0]
    check(logs.append, ldap_ok=True)          # already done for this TAK start: no second line
    assert len(logs) == 1 and restarts == []


def test_not_admin_restarts_tak_once():
    check, restarts, logs, store = _check_ns([False, True], {'webadmin_password': 'pw'})
    check(logs.append, ldap_ok=True)
    assert len(restarts) == 1
    assert any('admin again' in m for m in logs)


def test_not_admin_twice_inside_six_hours_does_not_loop_restarts():
    check, restarts, logs, store = _check_ns(
        [False], {'webadmin_password': 'pw', 'tak_webadmin_check': {'last_restart': time.time() - 600}})
    check(logs.append, ldap_ok=True)
    assert restarts == [] and any('not restarting again' in m for m in logs)


@pytest.mark.parametrize('kw,settings', [
    ({'started_ago': 60}, {'webadmin_password': 'pw'}),       # TAK still settling (box boot)
    ({}, {}),                                                 # no stored password
    ({'busy': True}, {'webadmin_password': 'pw'}),            # cert job running
])
def test_check_stays_out_of_the_way(kw, settings):
    check, restarts, logs, store = _check_ns([False], settings, **kw)
    check(logs.append, ldap_ok=True)
    assert restarts == []


def test_broken_ldap_never_restarts_tak():
    check, restarts, logs, store = _check_ns([False], {'webadmin_password': 'pw'})
    check(logs.append, ldap_ok=False)
    assert restarts == []


def test_unknown_three_times_gives_up_without_restart():
    check, restarts, logs, store = _check_ns([None, None, None], {'webadmin_password': 'pw'})
    for _ in range(4):
        check(logs.append, ldap_ok=True)
    assert restarts == [] and store['s']['tak_webadmin_check']['done'] is True


# ── wiring ──────────────────────────────────────────────────────────────────

def test_watchdog_runs_the_check_with_the_ldap_verdict():
    loop = _src('_authentik_ldap_sa_bind_watchdog_loop')
    assert "_tak_webadmin_admin_check(" in loop and "ldap_ok=(_verdict == 'ok')" in loop


def test_fix_routes_require_login():
    for route in ("'/api/takserver/webadmin-fix-admin', methods=['POST']",
                  "'/api/takserver/webadmin-fix-admin/status'"):
        i = APP.index(route)
        assert '@login_required' in APP[i:i + 120]


def test_button_is_on_the_tak_server_page():
    html = (REPO / 'templates' / 'takserver.html').read_text()
    js = (REPO / 'static' / 'takserver.js').read_text()
    assert 'onclick="fixWebadminAdmin()"' in html and 'async function fixWebadminAdmin()' in js
    assert "/api/takserver/webadmin-fix-admin/status" in js
