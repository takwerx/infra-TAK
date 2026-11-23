# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1152: the pytest job must not freeze a runner for 35 minutes with no log.

The guard in tests/ci_guard.py ends a pytest process that runs the machine out of memory, and says which
test was running. These tests run a real pytest in a child process with a test that holds too much memory,
and check the child stops fast and names the test.
"""
import os
import subprocess
import sys
import textwrap
import time

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
import ci_guard  # noqa: E402

HOG = textwrap.dedent('''
    import time

    def test_quick():
        assert True

    def test_hog():
        block = bytearray(400 * 1024 * 1024)
        for i in range(0, len(block), 4096):   # touch every page so it counts as used
            block[i] = 1
        time.sleep(60)   # the guard must end the process long before this
''')


def _run(tmp_path, extra_args=(), env_extra=None):
    (tmp_path / 'test_hog.py').write_text(HOG)
    env = dict(os.environ, PYTHONPATH=TESTS_DIR, INFRATAK_GUARD_MAX_RSS_MB='250', INFRATAK_GUARD_MIN_AVAIL_MB='0')
    env.pop('INFRATAK_GUARD_OFF', None)
    env.update(env_extra or {})
    t0 = time.time()
    r = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'ci_guard', '-p', 'no:cacheprovider',
                        '--rootdir', str(tmp_path), *extra_args, str(tmp_path / 'test_hog.py')],
                       capture_output=True, text=True, env=env, cwd=str(tmp_path), timeout=50)
    return r, time.time() - t0


def test_check_names_each_reason():
    assert ci_guard.check(8000, 500, 1200, 6000) is None
    assert 'machine memory nearly gone' in ci_guard.check(900, 500, 1200, 6000)
    assert 'this process holds 7000 MB' in ci_guard.check(8000, 7000, 1200, 6000)
    assert ci_guard.check(None, 500, 1200, 6000) is None   # no /proc/meminfo: only the per-process cap
    assert 'this process holds' in ci_guard.check(None, 7000, 1200, 6000)


def test_a_test_that_holds_too_much_memory_stops_the_run_and_is_named(tmp_path):
    r, took = _run(tmp_path)
    out = r.stdout + r.stderr
    assert r.returncode == ci_guard.EXIT_CODE, out
    assert 'MEMORY GUARD' in out, out
    assert 'test_hog.py::test_hog' in out, out
    assert took < 40, 'the guard should end the run in seconds, took %.0f s' % took


def test_the_guard_can_be_switched_off_so_the_hog_test_alone_would_run_on(tmp_path):
    # Control: without the guard the same test is not stopped (it only ends on the child's own timeout).
    (tmp_path / 'test_hog.py').write_text(HOG.replace('time.sleep(60)', 'time.sleep(1)'))
    env = dict(os.environ, PYTHONPATH=TESTS_DIR, INFRATAK_GUARD_OFF='1', INFRATAK_GUARD_MAX_RSS_MB='250')
    r = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'ci_guard', '-p', 'no:cacheprovider',
                        '--rootdir', str(tmp_path), str(tmp_path / 'test_hog.py')],
                       capture_output=True, text=True, env=env, cwd=str(tmp_path), timeout=50)
    assert r.returncode == 0 and 'MEMORY GUARD' not in r.stdout + r.stderr, r.stdout + r.stderr


def test_under_xdist_the_crashed_worker_names_the_test(tmp_path):
    pytest.importorskip('xdist')
    r, took = _run(tmp_path, extra_args=('-n', '1'))
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert 'MEMORY GUARD' in out, out
    assert 'test_hog.py::test_hog' in out, out
    assert took < 40, took


def test_conftest_loads_the_guard_for_the_real_suite():
    with open(os.path.join(TESTS_DIR, 'conftest.py'), encoding='utf-8') as f:
        text = f.read()
    for hook in ('pytest_configure', 'pytest_collectstart', 'pytest_runtest_logstart', 'pytest_runtest_logfinish'):
        assert hook in text.split('from ci_guard import', 1)[1], hook


# --- one copy of app.py for the whole suite --------------------------------------------------------------
# app.py has characters above U+FFFF, so each copy is 4 bytes a character (27 MB); 320 modules each read
# their own and one pytest process held 8.6 GB just collecting. conftest.py now hands every reader of an
# unchanged big file the same string.

def _load(name):
    import importlib.util
    spec = importlib.util.spec_from_file_location('ops1152_probe_' + name, os.path.join(TESTS_DIR, name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_two_real_test_modules_share_one_copy_of_app_py():
    a = _load('test_authentik_pgbouncer_image')
    b = _load('test_webodm_image_pins')
    assert a.APP is b.APP, 'each module holds its own 27 MB copy of app.py again'


def test_a_big_file_that_changes_is_read_again(tmp_path):
    import pathlib
    big = tmp_path / 'big.txt'
    big.write_text('a' * 1_100_000, encoding='utf-8')
    first = pathlib.Path(big).read_text(encoding='utf-8')
    assert pathlib.Path(big).read_text(encoding='utf-8') is first
    big.write_text('b' * 1_200_000, encoding='utf-8')
    assert pathlib.Path(big).read_text(encoding='utf-8') == 'b' * 1_200_000


def test_small_files_are_never_shared(tmp_path):
    import pathlib
    small = tmp_path / 'small.txt'
    small.write_text('x', encoding='utf-8')
    assert pathlib.Path(small).read_text(encoding='utf-8') == 'x'
    small.write_text('y', encoding='utf-8')
    assert pathlib.Path(small).read_text(encoding='utf-8') == 'y'
