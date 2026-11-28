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
"""A second Update Now on the same version keeps the way back to the earlier one (ops #1427).

Found in the 10.4.10 T&E: test12 took Update Now from 10.4.9 to 10.4.10 (record: 10.4.9), then a
second click while dev moved to another commit with the same VERSION string. The second click
made a new record from HEAD and the way back to 10.4.9 was gone. Two more clicks lost it the
same way, on the main channel too: the same release clicked twice, and a click that fails at the
fetch or the pre-check (the record used to be saved at the start of every click).

Same harness as the ops #1329 tests: the real `update_apply` runs against a real git
repository (an upstream with a dev branch and release tags, and the box's own clone). Only the
outside world is faked (GitHub tag lookup, systemd restart, pip, the settings file).
Every test fails on dev 69405b0 and passes with the fix, except the ones named as "still".
"""

import subprocess

import pytest

from test_update_now_preflight_ops1329 import (  # noqa: E402
    APP_PY, NEW, OLD, Box, _git, _installed)

REQ = f'pytest=={_installed("pytest")}\n'


@pytest.fixture
def box(tmp_path):
    b = Box(tmp_path)
    b.write_release(NEW, app=APP_PY.format(v='1.0.1-alpha'), req=REQ)
    return b


def _dev_commit(box, version, note):
    """An untagged commit on upstream's dev branch, as the dev channel ships them."""
    _git(box.up, 'checkout', '-q', '-B', 'dev', OLD if not _has_dev(box) else 'dev')
    (box.up / 'app.py').write_text(APP_PY.format(v=version) + f'# {note}\n')
    (box.up / 'requirements.txt').write_text(REQ)
    _git(box.up, 'add', '-A')
    _git(box.up, 'commit', '-q', '-m', f'dev {note}')
    sha = _git(box.up, 'rev-parse', 'HEAD')
    _git(box.up, 'checkout', '-q', 'main')
    return sha


def _has_dev(box):
    r = subprocess.run(['git', 'rev-parse', '-q', '--verify', 'refs/heads/dev'], cwd=box.up,
                       capture_output=True, text=True)
    return r.returncode == 0


def _finish_restart(box):
    """What the real restart does to the lock when the new console starts."""
    if box.update_lock.exists():
        box.update_lock.unlink()


def test_dev_two_clicks_on_one_version_keep_the_first_record(box):
    """The T&E case: 10.4.9 to 10.4.10, then dev moves with the same VERSION."""
    box.settings['update_channel'] = 'dev'
    _dev_commit(box, '1.0.1-alpha', 'first')
    out1, _, _ = box.click()                                   # running 1.0.0-alpha
    assert out1['success'] is True, out1
    first = dict(box.settings['console_rollback'])
    assert first['version'] == '1.0.0-alpha' and first['tag'] == OLD and first['available'] is True
    _finish_restart(box)
    sha_b = _dev_commit(box, '1.0.1-alpha', 'second')          # dev moved, same VERSION string
    out2, _, _ = box.click(VERSION='1.0.1-alpha')              # now running 1.0.1-alpha
    assert out2['success'] is True, out2
    assert _git(box.console, 'rev-parse', 'HEAD') == sha_b, 'the click must still move the box'
    assert box.settings['console_rollback'] == first, (
        'the second click on one version replaced the way back to 1.0.0-alpha')


def test_main_the_same_release_clicked_twice_keeps_the_first_record(box):
    out1, _, _ = box.click()
    assert out1['success'] is True and box.head_tag() == NEW
    first = dict(box.settings['console_rollback'])
    assert first['version'] == '1.0.0-alpha' and first['tag'] == OLD
    _finish_restart(box)
    out2, _, _ = box.click(VERSION='1.0.1-alpha')              # no newer release exists
    assert out2['success'] is True
    assert box.settings['console_rollback'] == first, (
        'a click that changes nothing replaced the rollback record with the running version')


def test_a_click_that_fails_at_the_fetch_leaves_the_record_alone(box):
    box.click()
    first = dict(box.settings['console_rollback'])
    _finish_restart(box)
    failed = lambda _git_fn, args, *a, **k: subprocess.CompletedProcess(      # noqa: E731
        args, 128, '', 'fatal: unable to access https://github.com/: Could not resolve host')
    out, _, _ = box.click(VERSION='1.0.1-alpha', _git_fetch_retry=failed)
    assert out['success'] is False
    assert box.settings['console_rollback'] == first, 'a failed click changed the rollback record'


def test_a_click_stopped_by_the_pre_check_leaves_the_record_alone(box):
    box.click()
    first = dict(box.settings['console_rollback'])
    _finish_restart(box)
    box.write_release('v1.0.2-alpha', app=APP_PY.format(v='1.0.2-alpha') + 'def broken(:\n', req=REQ)
    out, _, _ = box.click(VERSION='1.0.1-alpha', _fetch_latest_tag_name=lambda: 'v1.0.2-alpha')
    assert out['success'] is False and 'anything was changed' in out['error'], out
    assert box.head_tag() == NEW
    assert box.settings['console_rollback'] == first


def test_still_a_real_new_version_gets_a_new_record(box):
    box.click()
    _finish_restart(box)
    box.write_release('v1.0.2-alpha', app=APP_PY.format(v='1.0.2-alpha'), req=REQ)
    out, _, _ = box.click(VERSION='1.0.1-alpha', _fetch_latest_tag_name=lambda: 'v1.0.2-alpha')
    assert out['success'] is True and box.head_tag() == 'v1.0.2-alpha'
    rec = box.settings['console_rollback']
    assert rec['version'] == '1.0.1-alpha' and rec['tag'] == NEW and rec['available'] is True


def test_still_an_interrupted_click_then_a_second_click_keeps_the_first_tag(box):
    box.restart_argv = ['sh', '-c', 'echo "Unit takwerx-console.service is masked." >&2; exit 1']
    out1, _, _ = box.click()
    assert out1.get('restart_failed') is True and box.head_tag() == NEW
    box.click()                                                # old code still running: VERSION same
    assert box.settings['console_rollback']['tag'] == OLD
    assert box.settings['console_rollback']['version'] == '1.0.0-alpha'


def test_a_record_from_an_older_console_without_commit_or_label_is_kept_as_it_is(box):
    """10.4.8 and older wrote only version, tag and snapshot_at. Keep it byte for byte."""
    old_shape = {'available': True, 'version': '0.9.0-alpha', 'tag': 'v0.9.0-alpha',
                 'snapshot_at': '2026-10-01T00:00:00Z'}
    box.settings['console_rollback'] = dict(old_shape)
    _git(box.console, 'fetch', '-q', 'origin', '--tags')
    _git(box.console, 'checkout', '-q', '--detach', NEW)
    out, _, _ = box.click(VERSION='1.0.1-alpha')               # the release it runs is the newest
    assert out['success'] is True
    assert box.settings['console_rollback'] == old_shape


def test_still_a_box_on_a_release_tag_moving_to_a_dev_commit_of_the_same_version_gets_that_tag(box):
    """HEAD exactly on v1.0.1-alpha is itself the best way back, so it is not skipped."""
    box.settings['console_rollback'] = {'available': True, 'version': '0.9.0-alpha',
                                        'tag': 'v0.9.0-alpha', 'snapshot_at': 'x'}
    box.settings['update_channel'] = 'dev'
    _git(box.console, 'fetch', '-q', 'origin', '--tags')
    _git(box.console, 'checkout', '-q', '--detach', NEW)
    _dev_commit(box, '1.0.1-alpha', 'after the release')       # dev tip, same VERSION as the tag
    out, _, _ = box.click(VERSION='1.0.1-alpha')
    assert out['success'] is True
    rec = box.settings['console_rollback']
    assert rec['tag'] == NEW and rec['version'] == '1.0.1-alpha'


def test_the_target_version_cannot_be_read_so_the_record_is_made_as_before(tmp_path):
    """No git here: nothing can be read, and the click must not fail because of it."""
    import datetime
    import json
    import os
    import re
    import test_update_now_preflight_ops1329 as t
    src, missing_f, _ = t._lift(['_update_rollback_snapshot', '_console_rollback_snapshot'],
                                ['_ROLLBACK_SHA_RE'])
    assert not missing_f
    g = dict(re=re, os=os, json=json, subprocess=subprocess, datetime=datetime.datetime)
    exec(src, g)
    prev = {'available': True, 'version': '1.0.0-alpha', 'tag': OLD, 'snapshot_at': 'x'}
    rec = g['_console_rollback_snapshot'](str(tmp_path), '1.0.1-alpha', prev,
                                          target_ref='refs/remotes/origin/dev')
    assert rec['available'] is True and rec['version'] == '1.0.1-alpha' and rec['tag'] != OLD


def test_update_now_saves_the_record_after_the_fetch_and_before_the_checkout():
    """Order in the source: the save sits between the pre-check and the checkout."""
    import test_update_now_preflight_ops1329 as t
    src = t._lift(['update_apply'], [])[0]
    save = src.index("_s['console_rollback'] = _console_rollback_snapshot(")
    pre = src.index('_update_preflight_tree(console_dir, target_ref')
    co = src.index("checkout = _git(['checkout', '--force', target_ref]")
    assert pre < save < co, 'the record must be saved after the pre-check and before HEAD moves'
    assert 'target_ref=target_ref' in src
