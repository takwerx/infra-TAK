# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""Deploy on a built ATLAS deployment must not move it to an older release (ops #982).

Seen on test6: agency `signedtest` ran ATLAS 2.3.0 (database migrated by 2.3.0),
the ATLAS channel was set to `main` (offering 2.2.2) and Deploy was pressed. It
logged "main channel offers v2.2.2 ... fetching v2.2.2 ... Source in place",
rebuilt the containers on 2.2.2, the api stopped answering and ATLAS behind
Authentik returned 502. Update already refused this ("Refusing to downgrade");
Deploy did not. ATLAS 2.x is forward-only against its database.

⚠️ **Driven, not grepped.** `deploy` runs for real up to the version check, with
git, compose and the build replaced by recorders. A refusal is proved by git
never being reached; a pass-through is proved by git being reached.
"""

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402

MAIN_TIP = 'e580fa6618fc9dbfe2b782f7ca9ff980fd813f2b'


@pytest.fixture
def rig(monkeypatch, tmp_path):
    """`deploy` on a built deployment, with a stated installed version and offers."""
    d = tmp_path / 'atlas-signedtest'
    d.mkdir()
    (d / '.git').mkdir()
    log = []
    git_calls = []

    class _R:
        returncode = 0
        stdout = ''
        stderr = ''

    def git(*args, **kwargs):
        git_calls.append(args)
        return _R()

    def subprocess_run(argv, *args, **kwargs):
        git_calls.append(tuple(argv))
        return _R()

    monkeypatch.setattr(atlas, '_plog', log.append)
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [])
    monkeypatch.setattr(atlas, 'instance_is_stranded', lambda c, i: False)
    monkeypatch.setattr(atlas, 'deployment_identity',
                        lambda c, i, s: {'name': 'signedtest',
                                         'dir': str(d).replace(chr(92), '/'),
                                         'settings_prefix': 'atlas_',
                                         'app_port': 8761})
    monkeypatch.setattr(atlas.subprocess, 'run', subprocess_run)
    monkeypatch.setattr(atlas, '_verify_release', lambda *a, **k: None)

    def _run(installed, offers, channel='main', ls_remote=True):
        monkeypatch.setattr(atlas, '_installed_version',
                            lambda c, i=None: installed)
        monkeypatch.setattr(atlas, '_latest_version',
                            lambda use_cache=True, channel=None: offers.get(channel))
        if ls_remote:
            tag = 'v' + offers[channel]
            monkeypatch.setattr(
                atlas, '_ls_remote',
                lambda refs: {r: MAIN_TIP for r in refs
                              if r in ('refs/heads/' + channel, 'refs/tags/' + tag)})
        else:
            def down(refs):
                raise RuntimeError('git ls-remote failed')
            monkeypatch.setattr(atlas, '_ls_remote', down)
        ctx = {
            'load_settings': lambda: {atlas.CHANNEL_KEY: channel},
            'save_settings': lambda s: None,
            '_docker_probe': lambda: (0, 'Docker version 27'),
            '_module_git': git,
        }
        job = {}
        atlas.deploy(ctx, job, {'slug': None})
        return job, chr(10).join(log), git_calls

    return _run


def test_deploy_refuses_to_downgrade_a_built_deployment(rig):
    """The ops #982 case: 2.3.0 built, `main` offers 2.2.2, Deploy pressed."""
    job, log, git_calls = rig('2.3.0', {'main': '2.2.2', 'dev': '2.3.0'})

    assert 'Refusing to downgrade' in log, log
    assert '2.2.2' in log and '2.3.0' in log
    assert job['error'] is True, 'Deploy reports a refusal as a failed job'
    assert git_calls == [], 'git touched the checkout of a deployment it refused'
    assert 'Source in place' not in log


def test_deploy_says_how_to_get_out_of_the_refusal(rig):
    job, log, _ = rig('2.3.0', {'main': '2.2.2'})

    assert 'migrated' in log, log
    assert 'Nothing was changed' in log, log
    assert 'Update' in log


def test_a_refused_deploy_leaves_no_trace_of_fetching(rig):
    _job, log, _git = rig('2.3.0', {'main': '2.2.2'})

    assert 'fetching' not in log
    assert 'Already cloned' not in log


def test_deploy_repairing_a_deployment_level_with_its_channel_still_runs(rig):
    """Deploy on a built deployment is a repair; same version is not a downgrade."""
    _job, log, git_calls = rig('2.3.0', {'main': '2.3.0'})

    assert 'Refusing' not in log, log
    assert git_calls, 'the repair never reached git'


def test_deploy_moving_a_deployment_forward_still_runs(rig):
    _job, log, git_calls = rig('2.2.2', {'main': '2.3.0'})

    assert 'Refusing' not in log, log
    assert git_calls, 'an upgrade never reached git'


def test_a_deployment_with_no_version_on_disk_is_not_refused(rig):
    """A first deploy, or a checkout that never finished: nothing to compare."""
    _job, log, git_calls = rig(None, {'main': '2.2.2'})

    assert 'Refusing' not in log, log
    assert git_calls


def test_the_offline_pin_is_checked_too(rig, monkeypatch):
    """GitHub unreachable falls back to the pin; an old pin is a downgrade."""
    monkeypatch.setattr(atlas, 'ATLAS_TAG', 'v2.2.0')
    job, log, git_calls = rig('2.3.0', {}, ls_remote=False)

    assert 'Refusing to downgrade' in log, log
    assert job['error'] is True
    assert git_calls == []


def test_update_and_deploy_give_the_same_refusal():
    """One helper, so the two buttons cannot drift apart again."""
    lines = atlas._downgrade_lines('2.3.0', '2.2.2', 'main')

    assert lines and 'Refusing to downgrade: 2.2.2' in lines[1]
    assert atlas._downgrade_lines('2.2.2', '2.3.0', 'main') is None
    assert atlas._downgrade_lines('2.3.0', '2.3.0', 'main') is None
    assert atlas._downgrade_lines(None, '2.2.2', 'main') is None
    assert atlas._downgrade_lines('2.3.0', 'garbage', 'main') is None
    # 2.10.0 is newer than 2.9.0: a string compare would get this wrong.
    assert atlas._downgrade_lines('2.10.0', '2.9.0', 'main')
    assert atlas._downgrade_lines('2.9.0', '2.10.0', 'main') is None
