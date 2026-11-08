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
"""ops #563 — one connection reset (curl exit 56) fetching the PostgreSQL signing key
killed the whole TAK Server install on a fresh Ubuntu 22.04 box. The key fetch and the
PGDG `apt-get update` now try three times (5 s, then 15 s apart) before giving up with the
same clear message as before.
"""

import pathlib
import re
import subprocess
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

KEY = b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n' + b'A' * 200 + b'\n-----END PGP PUBLIC KEY BLOCK-----\n'
URL = 'https://www.postgresql.org/media/keys/ACCC4CF8.asc'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _ns(**extra):
    """The retry helpers plus the PGDG key functions, executed on their own."""
    s = APP[APP.index('_NET_RETRY_DELAYS = '):APP.index('def _apt_update_capture(')]
    ns = dict(re=re, time=time, subprocess=subprocess, _PGDG_KEY_URL=URL)
    exec(s, ns)
    for n in ('_pgdg_key_ok', '_pgdg_key_fetch', '_apt_update_capture', '_setup_pgdg_apt_source'):
        exec(_fn(n), ns)
    ns.update(extra)
    return ns


def _curl(results, calls):
    """A subprocess.run stand-in: each call hands back the next (returncode, stdout)."""
    def run(argv, **kw):
        calls.append(argv)
        rc, out = results[min(len(calls), len(results)) - 1]
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=b'')
    return run


def _with_run(ns, run):
    ns['subprocess'] = types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired)
    return ns


def test_key_fetch_survives_one_connection_reset():
    calls, sleeps = [], []
    ns = _with_run(_ns(), _curl([(56, b''), (0, KEY)], calls))
    rc, key = ns['_pgdg_key_fetch'](sleep=sleeps.append)
    assert (rc, key) == (0, KEY)
    assert len(calls) == 2 and sleeps == [5]
    assert calls[0][:2] == ['curl', '-fsSL'] and '--connect-timeout' in calls[0]


def test_key_fetch_gives_up_after_three_tries_with_the_last_result():
    calls, sleeps, logs = [], [], []
    ns = _with_run(_ns(), _curl([(56, b'')], calls))
    rc, key = ns['_pgdg_key_fetch'](logs.append, sleep=sleeps.append)
    assert (rc, key) == (56, b'')
    assert len(calls) == 3 and sleeps == [5, 15]
    assert any('retrying in 5s' in l for l in logs) and any('retrying in 15s' in l for l in logs)


def test_key_fetch_retries_a_html_error_page_and_a_raising_curl():
    calls, sleeps = [], []
    seq = [(0, b'<html>blip</html>'), 'boom', (0, KEY)]

    def run(argv, **kw):
        calls.append(argv)
        r = seq[len(calls) - 1]
        if r == 'boom':
            raise OSError('curl missing for a moment')
        return types.SimpleNamespace(returncode=r[0], stdout=r[1], stderr=b'')

    ns = _with_run(_ns(), run)
    assert ns['_pgdg_key_fetch'](sleep=sleeps.append) == (0, KEY) and len(calls) == 3


def _setup_ns(curl_results, calls, sleeps, logs, apt=(True, '')):
    writes = []
    ns = _with_run(_ns(
        _distro_family=lambda: 'debian',
        _pgdg_existing_apt_sources=lambda: [],
        log_step=logs.append,
        _apt_codename=lambda: 'jammy',
        _write_priv=lambda path, data, perm=None: writes.append((path, data)),
        _pgdg_gis_pin_ensure=lambda *_a, **_k: True,
        wait_for_package_lock=lambda: None,
        _apt_update_capture=lambda **_k: apt,
        _PGDG_KEYRING='/usr/share/keyrings/pgdg.asc',
        _PGDG_LIST='/etc/apt/sources.list.d/pgdg.list',
        _PGDG_APT_HOST='apt.postgresql.org',
        _sudo_wrap=lambda a: a,
        os=types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: False)),
    ), _curl(curl_results, calls))
    real_fetch = ns['_pgdg_key_fetch']
    ns['_pgdg_key_fetch'] = lambda log_fn=None, sleep=None: real_fetch(log_fn, sleeps.append)
    return ns, writes


def test_deploy_goes_on_when_the_first_key_fetch_fails_and_the_second_works():
    calls, sleeps, logs = [], [], []
    ns, writes = _setup_ns([(56, b''), (0, KEY)], calls, sleeps, logs)
    assert ns['_setup_pgdg_apt_source']() is True
    assert len(calls) == 2 and sleeps == [5]
    assert ('/usr/share/keyrings/pgdg.asc', KEY) in writes
    assert not any('FATAL' in l for l in logs)


def test_deploy_still_stops_with_the_clear_message_when_every_try_fails():
    calls, sleeps, logs = [], [], []
    ns, writes = _setup_ns([(56, b'')], calls, sleeps, logs)
    assert ns['_setup_pgdg_apt_source']() is False
    assert len(calls) == 3 and writes == []
    text = '\n'.join(logs)
    assert 'FATAL: could not fetch the PostgreSQL signing key' in text
    assert 'curl exit 56, 0 bytes received' in text


def _apt_ns(outputs, sleeps, logs=None):
    """apt_update_capture with apt-get scripted: outputs is [(returncode, stderr), ...]."""
    seen = []

    def run(cmd, **kw):
        seen.append(cmd)
        rc, err = outputs[min(len(seen), len(outputs)) - 1]
        return types.SimpleNamespace(returncode=rc, stdout='', stderr=err)

    ns = _with_run(_ns(_broker_shim_env=lambda: None, _apt_disable_dead_local_sources=lambda: [],
                       _caddy_apt_repo_heal=lambda: 'ok'), run)
    ns['time'] = types.SimpleNamespace(sleep=sleeps.append)
    ns['_retry_transient'].__globals__['time'] = ns['time']
    return ns, seen


def test_apt_update_retries_a_network_blip_but_not_a_dead_repo():
    sleeps = []
    ns, seen = _apt_ns([(100, 'W: Failed to fetch http://x  Could not resolve host\nE: Some index files failed'),
                        (0, '')], sleeps)
    ok, _out = ns['_apt_update_capture']()
    assert ok is True and len(seen) == 2 and sleeps == [5]

    sleeps2 = []
    ns, seen = _apt_ns([(100, 'E: Failed to fetch https://dl.cloudsmith.io/x  402  Payment Required')], sleeps2)
    ok, _out = ns['_apt_update_capture']()
    assert ok is False and len(seen) == 1 and sleeps2 == []


def test_remote_server_one_key_fetch_fails_on_http_errors_and_retries():
    line = next(l for l in APP.splitlines() if "sudo curl" in l and '{_PGDG_KEY_URL} --output {_PGDG_KEYRING}' in l
                and '_PGDG_REMOTE' not in l)
    for flag in ('-fsSL', '--retry 3', '--retry-delay 5', '--retry-all-errors', '--connect-timeout 15'):
        assert flag in line, flag
