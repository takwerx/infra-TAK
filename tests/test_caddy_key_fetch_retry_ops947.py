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
"""The Caddy signing-key fetch tries again and says why it failed (ops #947).

In the 10.4.2 Ubuntu 22.04 update test, Cloudsmith answered badly once. The one-shot
`curl -1sLf ... | gpg --dearmor` stopped the Caddy install with only "no valid OpenPGP data
found" (curl -f hides the HTTP status), and every later module failed with it.
`_caddy_fetch_shell` now tries 5 times, 10 s apart, and prints the HTTP status on each failed try.
The helper is cut out of app.py and its shell text is run for real against a fake `curl`.
"""

import ast
import os
import pathlib
import subprocess
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

KEY_URL = 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key'


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _load():
    ns = {}
    for name in ('CADDY_FETCH_TRIES', 'CADDY_FETCH_DELAY', 'CADDY_FETCH_TIMEOUT', '_caddy_fetch_shell'):
        exec(_segment(name), ns)
    return ns


def _fake_curl(bin_dir, script):
    p = bin_dir / 'curl'
    p.write_text('#!/bin/sh\n' + textwrap.dedent(script))
    p.chmod(0o755)


# Fake curl: reads its call counter from $COUNT_FILE. Calls 1..$FAIL_FIRST answer HTTP $FAIL_CODE
# (exit 0, no file, as curl does without -f); later calls write KEYDATA to the -o file, print 200.
FAKE = '''
    out=""
    while [ $# -gt 0 ]; do
      if [ "$1" = "-o" ]; then out="$2"; shift; fi
      shift
    done
    n=$(cat "$COUNT_FILE" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$COUNT_FILE"
    if [ "$n" -le "$FAIL_FIRST" ]; then
      [ "$FAIL_CODE" = 000 ] && { printf 000; exit 6; }
      printf '%s' "$FAIL_CODE"; exit 0
    fi
    printf KEYDATA > "$out"; printf 200
'''


def _run(tmp_path, fail_first, fail_code='503', tries=None, sink='cat > "$OUT_FILE"'):
    ns = _load()
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir(exist_ok=True)
    _fake_curl(bin_dir, FAKE)
    kw = {'delay': 0}
    if tries:
        kw['tries'] = tries
    cmd = ns['_caddy_fetch_shell'](KEY_URL, sink, **kw)
    env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}',
           'COUNT_FILE': str(tmp_path / 'count'), 'FAIL_FIRST': str(fail_first),
           'FAIL_CODE': fail_code, 'OUT_FILE': str(tmp_path / 'key.out')}
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60, env=env)
    calls = int((tmp_path / 'count').read_text().strip())
    return r, calls, tmp_path / 'key.out'


def test_defaults_are_five_tries_ten_seconds_apart():
    ns = _load()
    assert ns['CADDY_FETCH_TRIES'] == 5
    assert ns['CADDY_FETCH_DELAY'] == 10
    cmd = ns['_caddy_fetch_shell'](KEY_URL, 'cat')
    assert '-lt 5' in cmd and 'sleep 10' in cmd


def test_one_bad_answer_then_good_installs_the_key(tmp_path):
    r, calls, out = _run(tmp_path, fail_first=1)
    assert r.returncode == 0, r.stderr
    assert calls == 2
    assert out.read_text() == 'KEYDATA'
    assert 'try 1 of 5: HTTP 503' in r.stderr


def test_four_bad_answers_still_succeed_on_the_fifth(tmp_path):
    r, calls, out = _run(tmp_path, fail_first=4)
    assert r.returncode == 0, r.stderr
    assert calls == 5
    assert out.read_text() == 'KEYDATA'


def test_five_bad_answers_fail_and_name_the_http_status(tmp_path):
    r, calls, out = _run(tmp_path, fail_first=99, fail_code='429')
    assert r.returncode != 0
    assert calls == 5
    assert not out.exists()
    for n in range(1, 6):
        assert f'try {n} of 5: HTTP 429 from {KEY_URL}' in r.stderr
    assert 'gave up after 5 tries' in r.stderr


def test_no_connection_is_retried_and_reported(tmp_path):
    r, calls, _ = _run(tmp_path, fail_first=2, fail_code='000')
    assert r.returncode == 0, r.stderr
    assert calls == 3
    assert 'HTTP 000' in r.stderr


def test_a_file_the_sink_rejects_is_tried_again(tmp_path):
    # First sink run fails (a cut-off body), the second works.
    flag = tmp_path / 'flag'
    script = tmp_path / 'sink.sh'
    script.write_text(f'#!/bin/sh\nif [ -e {flag} ]; then cat > "$OUT_FILE"; else touch {flag}; exit 1; fi\n')
    script.chmod(0o755)
    sink = str(script)
    r, calls, out = _run(tmp_path, fail_first=0, sink=sink)
    assert r.returncode == 0, r.stderr
    assert calls == 2
    assert out.read_text() == 'KEYDATA'
    assert 'got HTTP 200 but could not use the file' in r.stderr


def test_both_caddy_repo_setups_use_the_retry_helper():
    """The deploy (Step 1) and the update path (_caddy_ensure_apt_repo) both fetch the key and
    sources list; neither may go back to a one-shot `curl -f | gpg`."""
    for fn in ('run_caddy_deploy', '_caddy_ensure_apt_repo'):
        body = _segment(fn)
        assert 'curl -1sLf' not in body, f'{fn} still fetches Caddy files with a one-shot curl -f'
        assert body.count('_caddy_fetch_shell(') == 2, fn
        assert 'gpg.key' in body and 'debian.deb.txt' in body
        assert 'CADDY_FETCH_TIMEOUT' in body, f'{fn} must give the retries a longer limit than 120 s'
