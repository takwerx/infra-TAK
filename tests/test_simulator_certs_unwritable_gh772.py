# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""GH #772: TAK Simulator "Rebuild Now" stops at step 1 with
`[Errno 13] Permission denied: '/home/takwerx/tak-simulator/certs/lanes.json.tmp'`.

The `certs` folder (lane certificates + lanes.json) can be a folder the console user cannot
write into. The console owns `~/tak-simulator` itself but the broker has no rule for it, so
the console cannot chown the folder; it can rename it. The rebuild now sets an unwritable
`certs` folder aside, makes a new one, issues the lanes their certificates again, and puts the
old folder back if that fails.

The tests run the shipped functions against a real folder. A folder the console cannot write
is a folder with mode 500 (no write bit), which gives the same EACCES as a folder owned by
another user.
"""
import os
import pathlib
import time

import pytest

import modules.simulator as sim

pytestmark = pytest.mark.skipif(os.getuid() == 0, reason='root can write any folder')


class Env:
    def __init__(self, tmp_path, monkeypatch):
        self.install = tmp_path / 'tak-simulator'
        (self.install / 'certs').mkdir(parents=True)
        os.chmod(self.install, 0o755)
        monkeypatch.setattr(sim, 'SIM_INSTALL_DIR', str(self.install))
        monkeypatch.setattr(sim, 'SIM_SOURCE_DIR', str(tmp_path / 'src'))
        src = tmp_path / 'src'
        (src / 'engine').mkdir(parents=True)
        (src / 'scenarios').mkdir()
        (src / 'Dockerfile').write_text('FROM scratch\n')
        self.settings = {'simulator_lanes': [
            {'id': '1', 'channel': 'tak_simulation', 'user': 'sim-lane-1', 'ak_pk': 7},
            {'id': '2', 'channel': 'tak_demo', 'user': 'sim-lane-2', 'ak_pk': 8}],
            'simulator_control_token': 'tok'}
        self.log = []
        self.compose = []
        self.enroll_fail = False
        self.ctx = {
            'load_settings': lambda: self.settings,
            'save_settings': lambda s: self.settings.update(s),
            'VERSION': '10.4.9-alpha',
            '_broker_compose': self._compose,
        }

        def fake_ensure_lane(ctx, lane_id, channel, plog):
            if self.enroll_fail:
                raise RuntimeError('Authentik unreachable')
            d = pathlib.Path(sim._certs_dir())
            (d / f'lane-{lane_id}.pem').write_text('NEW-CERT')
            (d / 'ca.pem').write_text('NEW-CA')
            return {'id': lane_id}

        monkeypatch.setattr(sim, '_ensure_lane', fake_ensure_lane)
        monkeypatch.setattr(sim, '_ctl', lambda *a, **k: (200, {}))
        monkeypatch.setattr(sim, '_wait_healthy', lambda *a, **k: {'ok': True})
        monkeypatch.setattr(sim, '_link_cloudtak', lambda *a, **k: (False, 'no CloudTAK'))
        monkeypatch.setattr(sim, '_video_base', lambda *a, **k: '')

    def _compose(self, d, action, timeout=0):
        self.compose.append(action)
        return type('R', (), {'returncode': 0, 'stdout': 'ok', 'stderr': ''})()

    def make_unwritable(self):
        certs = self.install / 'certs'
        (certs / 'lane-1.pem').write_text('OLD-CERT')
        (certs / 'lanes.json').write_text('{"1": "tak_simulation"}')
        os.chmod(certs, 0o500)

    def restore_perms(self):
        for p in self.install.glob('certs*'):
            os.chmod(p, 0o700)


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = Env(tmp_path, monkeypatch)
    yield e
    e.restore_perms()


def _run_rebuild(env):
    sim._rebuild_status.update({'running': True, 'complete': False, 'error': False, 'log': []})
    sim._run_rebuild(env.ctx)
    return sim._rebuild_status


def test_rebuild_fails_without_the_fix_conditions_is_the_reported_error(env):
    """The reported failure, produced by the shipped write: lanes.json.tmp in a folder the
    console cannot write gives EACCES (here wrapped with the fix hint)."""
    env.make_unwritable()
    with pytest.raises(RuntimeError) as e:
        sim._write_lanes_json(env.settings)
    assert 'cannot write' in str(e.value) and 'chown' in str(e.value)


def test_rebuild_heals_an_unwritable_certs_folder(env):
    env.make_unwritable()
    st = _run_rebuild(env)
    assert st['complete'] is True and st['error'] is False, st['log']
    certs = env.install / 'certs'
    # a new folder the console owns, holding fresh certs for BOTH lanes and lanes.json
    assert os.access(certs, os.W_OK)
    assert oct(certs.stat().st_mode & 0o777) == '0o700'
    assert (certs / 'lane-1.pem').read_text() == 'NEW-CERT'
    assert (certs / 'lane-2.pem').read_text() == 'NEW-CERT'
    assert (certs / 'lanes.json').exists()
    assert oct((certs / 'lanes.json').stat().st_mode & 0o777) == '0o600'
    # the old folder is set aside, not deleted
    aside = [p for p in env.install.iterdir() if p.name.startswith('certs.unwritable-')]
    assert len(aside) == 1
    # the container is recreated so it mounts the NEW folder
    assert env.compose == ['up -d --build --force-recreate']


def test_healthy_certs_folder_is_left_alone(env):
    certs = env.install / 'certs'
    (certs / 'lane-1.pem').write_text('KEEP')
    st = _run_rebuild(env)
    assert st['complete'] is True, st['log']
    assert (certs / 'lane-1.pem').read_text() == 'KEEP'          # no re-enrollment
    assert not [p for p in env.install.iterdir() if 'unwritable' in p.name]
    assert env.compose == ['up -d --build']                      # no forced recreate


def test_failed_reenrollment_puts_the_old_folder_back(env):
    env.make_unwritable()
    env.enroll_fail = True
    st = _run_rebuild(env)
    assert st['complete'] is False and st['error']
    assert 'could not issue the lane certificates again' in st['error']
    certs = env.install / 'certs'
    assert (certs / 'lane-1.pem').read_text() == 'OLD-CERT'       # original certs back in place
    assert not [p for p in env.install.iterdir() if 'unwritable' in p.name]
    assert env.compose == []                                      # nothing was rebuilt


def test_unreplaceable_install_folder_gives_the_manual_fix(env):
    env.make_unwritable()
    os.chmod(env.install, 0o555)                                  # the console cannot rename inside it
    try:
        st = _run_rebuild(env)
    finally:
        os.chmod(env.install, 0o755)
    assert st['error'] and 'chown -R' in st['error'] and str(env.install) in st['error']
    assert (env.install / 'certs').is_dir()                       # never left with no certs folder


def test_leftover_tmp_file_the_console_cannot_open_is_removed(env):
    """A lanes.json.tmp that exists and is read-only to us blocks `open(tmp, 'w')` even in a
    writable folder; unlink needs only the folder, so it is cleared first."""
    certs = env.install / 'certs'
    tmp = certs / 'lanes.json.tmp'
    tmp.write_text('stale')
    os.chmod(tmp, 0o400)
    sim._write_lanes_json(env.settings)
    assert (certs / 'lanes.json').exists() and not tmp.exists()


def test_deploy_runs_the_heal_before_it_enrolls_lane_one():
    """Static guard: deploy step 3 heals the certs folder before _ensure_lane('1')."""
    src = pathlib.Path(sim.__file__).read_text(encoding='utf-8')
    deploy = src[src.index('Step 3/7: Lane identity'):src.index('Step 4/7')]
    assert deploy.index('_heal_and_reenroll(ctx, plog)') < deploy.index("_ensure_lane(ctx, '1'")
