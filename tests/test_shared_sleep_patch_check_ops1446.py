# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1446: a test that patches time.sleep on the shared time module fails the PR checks.

Twice (ops #1172, ops #1444) dev went red on test_ldap_outpost_token_missing_provider_ops663: its fixture
patched time.sleep on the one shared `time` module, a thread left over from an earlier test slept while the
patch was on, and the thread's sleep landed in the test's list. .github/ci/shared_sleep_check.py reads every
test file and refuses a new patch of that kind. This file has two parts:

* the real tests/ folder must pass the check (this is what turns a PR red), and
* proofs that the check sees every form of the patch, lets the safe forms through, and fails a new offender
  when it runs as the CI step does (a child process, `python -I`).
"""
import os
import subprocess
import sys
import textwrap

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECK = os.path.join(REPO, '.github', 'ci', 'shared_sleep_check.py')
BASELINE = os.path.join(REPO, '.github', 'ci', 'shared-sleep-baseline.txt')

sys.path.insert(0, os.path.join(REPO, '.github', 'ci'))
import shared_sleep_check as chk  # noqa: E402


def _hits(src):
    return chk.scan_source(textwrap.dedent(src))


def _run_check(root, baseline=BASELINE):
    return subprocess.run([sys.executable, '-I', CHECK, '--root', str(root), '--baseline', baseline],
                          capture_output=True, text=True, timeout=60)


# --- the PR check: the real tests/ folder -------------------------------------------------------------

def test_tests_folder_has_no_new_shared_sleep_patch():
    r = _run_check(os.path.join(REPO, 'tests'))
    assert r.returncode == 0, r.stdout + r.stderr


def test_baseline_lists_only_files_that_exist():
    # A renamed or deleted file must not leave a line that could let a new file with that name in.
    for name in chk.load_baseline(BASELINE):
        assert os.path.exists(os.path.join(REPO, 'tests', name)), name + ' is in the baseline but not in tests/'


# --- every form of the patch is seen ------------------------------------------------------------------

OFFENDERS = {
    'patch string': '''
        from unittest import mock
        def test_a():
            with mock.patch("time.sleep") as s:
                pass
    ''',
    'patch string through a module': '''
        from unittest.mock import patch
        @patch("app.time.sleep")
        def test_a(s):
            pass
    ''',
    'patch.object on time': '''
        import time
        from unittest import mock
        def test_a():
            with mock.patch.object(time, "sleep", side_effect=[None]):
                pass
    ''',
    'patch.multiple': '''
        import time
        from unittest import mock
        def test_a():
            with mock.patch.multiple(time, sleep=lambda s: None):
                pass
    ''',
    'monkeypatch on time': '''
        import time
        def test_a(monkeypatch):
            monkeypatch.setattr(time, "sleep", lambda s: None)
    ''',
    'monkeypatch with a string target': '''
        def test_a(monkeypatch):
            monkeypatch.setattr("time.sleep", lambda s: None)
    ''',
    'monkeypatch on a module alias of time (the ops #1444 form)': '''
        import time as _real_time
        def test_a(monkeypatch):
            sleeps = []
            monkeypatch.setattr(_real_time, 'sleep', lambda n: sleeps.append(n))
    ''',
    'import inside the test': '''
        def test_a(monkeypatch):
            import time
            monkeypatch.setattr(time, 'sleep', lambda s: None)
    ''',
    "monkeypatch on a module's own reference to time": '''
        def test_a(monkeypatch, atlas):
            monkeypatch.setattr(atlas.time, 'sleep', lambda s: None)
    ''',
    'plain setattr': '''
        import time
        def test_a():
            setattr(time, 'sleep', lambda s: None)
    ''',
    'assignment': '''
        import time
        def test_a():
            time.sleep = lambda s: None
    ''',
    'call spread over lines': '''
        import time
        def test_a(monkeypatch):
            monkeypatch.setattr(
                time,
                'sleep',
                lambda s: None)
    ''',
}


@pytest.mark.parametrize('name', sorted(OFFENDERS))
def test_every_form_of_the_shared_patch_is_seen(name):
    assert len(_hits(OFFENDERS[name])) == 1, name


# --- safe forms pass ----------------------------------------------------------------------------------

SAFE = {
    "the code under test gets its own time stand-in (the ops #1444 fix)": '''
        import types
        def test_a(monkeypatch, atlas):
            fake = types.SimpleNamespace(sleep=lambda s: None)
            monkeypatch.setattr(atlas, 'time', fake)
    ''',
    'a namespace given to exec': '''
        import types
        def test_a():
            ns = {'time': types.SimpleNamespace(sleep=lambda s: None)}
    ''',
    'sleep on something that is not the time module': '''
        def test_a(monkeypatch, backoff):
            monkeypatch.setattr(backoff, 'sleep', lambda s: None)
    ''',
    'a different function on time': '''
        import time
        def test_a(monkeypatch):
            monkeypatch.setattr(time, 'time', lambda: 0.0)
    ''',
    'the words in a string or comment': '''
        """patch("time.sleep") is what broke ops #1444"""
        def test_a():
            msg = "monkeypatch.setattr(time, 'sleep', f)"  # time.sleep = x
            assert msg
    ''',
    'a marker with a reason on the line above': '''
        import time
        def test_a(monkeypatch):
            # shared-sleep-ok: records nothing, every sleep is a no-op
            monkeypatch.setattr(time, 'sleep', lambda s: None)
    ''',
    'a marker with a reason on the same line': '''
        import time
        def test_a(monkeypatch):
            monkeypatch.setattr(time, 'sleep', lambda s: None)  # shared-sleep-ok: no-op, nothing is recorded
    ''',
}


@pytest.mark.parametrize('name', sorted(SAFE))
def test_safe_forms_pass(name):
    assert _hits(SAFE[name]) == [], name


def test_a_marker_with_no_reason_does_not_count():
    assert len(_hits('''
        import time
        def test_a(monkeypatch):
            # shared-sleep-ok:
            monkeypatch.setattr(time, 'sleep', lambda s: None)
    ''')) == 1


def test_a_marker_far_away_does_not_count():
    assert len(_hits('''
        import time
        # shared-sleep-ok: this belongs to another test

        def test_a(monkeypatch):
            x = 1
            monkeypatch.setattr(time, 'sleep', lambda s: None)
    ''')) == 1


# --- the baseline: keep, never add --------------------------------------------------------------------

def _write(tmp_path, name, body):
    (tmp_path / name).write_text(textwrap.dedent(body))


OFFENDER = '''
    import time
    def test_a(monkeypatch):
        monkeypatch.setattr(time, 'sleep', lambda s: None)
'''


def test_red_on_purpose_a_new_file_with_the_patch_fails_the_check(tmp_path):
    """The proof the check catches what it claims: the same step CI runs, on a tree with one new offender."""
    _write(tmp_path, 'test_new_thing.py', OFFENDER)
    (tmp_path / 'baseline.txt').write_text('')
    r = _run_check(tmp_path, str(tmp_path / 'baseline.txt'))
    assert r.returncode == 1, r.stdout + r.stderr
    assert 'test_new_thing.py:4' in r.stdout
    assert 'time stand-in' in r.stdout  # the message says what to do instead


def test_green_a_clean_tree_passes_the_check(tmp_path):
    _write(tmp_path, 'test_clean.py', '''
        import types
        def test_a(monkeypatch, atlas):
            monkeypatch.setattr(atlas, 'time', types.SimpleNamespace(sleep=lambda s: None))
    ''')
    (tmp_path / 'baseline.txt').write_text('')
    r = _run_check(tmp_path, str(tmp_path / 'baseline.txt'))
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_file_in_the_baseline_may_keep_what_it_has(tmp_path):
    _write(tmp_path, 'test_old.py', OFFENDER)
    (tmp_path / 'baseline.txt').write_text('test_old.py 1   # kept\n')
    assert _run_check(tmp_path, str(tmp_path / 'baseline.txt')).returncode == 0


def test_a_file_in_the_baseline_may_not_add_another(tmp_path):
    _write(tmp_path, 'test_old.py', OFFENDER + '''
    def test_b(monkeypatch):
        monkeypatch.setattr(time, 'sleep', lambda s: None)
''')
    (tmp_path / 'baseline.txt').write_text('test_old.py 1\n')
    r = _run_check(tmp_path, str(tmp_path / 'baseline.txt'))
    assert r.returncode == 1 and 'test_old.py' in r.stdout


def test_a_fixed_file_does_not_fail_other_prs(tmp_path):
    # Two PRs never wait for each other: a baseline line the file no longer needs is a note, not a failure.
    _write(tmp_path, 'test_fixed.py', 'def test_a():\n    assert True\n')
    (tmp_path / 'baseline.txt').write_text('test_fixed.py 1\n')
    r = _run_check(tmp_path, str(tmp_path / 'baseline.txt'))
    assert r.returncode == 0 and 'lower its line' in r.stdout


def test_a_file_that_does_not_compile_is_left_to_compile_check(tmp_path):
    _write(tmp_path, 'test_broken.py', 'def (:\n')
    (tmp_path / 'baseline.txt').write_text('')
    assert _run_check(tmp_path, str(tmp_path / 'baseline.txt')).returncode == 0
