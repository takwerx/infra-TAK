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
"""CloudTAK hardening recreate survives a kill partway (ops #175).

The startup migration wrote the override first and recreated after, so a console killed in
between came back to files that were already "converged" and never finished the recreate.
On a non-root box the orphaned `docker compose up` kept running in the broker and replaced
cloudtak-media after the new console had healed it (aws-arm, ops #165). These tests run the
real `_startup_harden_cloudtak_ports` against a temp ~/CloudTAK with docker stubbed.
"""

import ast
import json
import os
import pathlib
import re
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)

OVERRIDE = 'services:\n  api:\n    environment: {}\n'
BOUND = json.dumps({'5000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '5000'}]})
COMPOSE_UP = '/usr/libexec/docker/cli-plugins/docker-compose compose up -d --force-recreate'


class Killed(BaseException):
    """Stands in for SIGTERM/SIGKILL: not an Exception, so the migration's handler can't eat it."""


def _src(name):
    return ast.get_source_segment(APP, next(
        n for n in _TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def _const(name):
    return ast.get_source_segment(APP, next(
        n for n in _TREE.body if isinstance(n, ast.Assign)
        and any(getattr(t, 'id', None) == name for t in n.targets)))


class Box:
    """One console process: a fake docker/ps and the log it printed."""

    def __init__(self, tmp_path, *, kill_on_up=False, heal_ok=True, busy_polls=0, patched=False):
        self.home = tmp_path
        self.calls, self.logs = [], []
        self.kill_on_up, self.heal_ok, self.busy_polls = kill_on_up, heal_ok, busy_polls
        self.patched = patched
        self.heals = 0

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        if argv[:2] == ['ps', '-eo']:
            if self.busy_polls:
                self.busy_polls -= 1
                return types.SimpleNamespace(stdout=f'/usr/bin/python3 broker\n{COMPOSE_UP}\n', returncode=0)
            return types.SimpleNamespace(stdout='/usr/bin/python3 broker\nsleep 30\n', returncode=0)
        if 'inspect' in argv:
            return types.SimpleNamespace(stdout=BOUND, stderr='', returncode=0)
        if argv[:4] == ['docker', 'compose', 'up', '-d']:
            if self.kill_on_up:
                raise Killed()
            return types.SimpleNamespace(stdout='', stderr='', returncode=0)
        return types.SimpleNamespace(stdout='', stderr='', returncode=0)

    def heal(self, **kw):
        self.heals += 1
        self.calls.append(['HEAL'])
        return self.heal_ok

    def start(self):
        clock = [1000.0]
        fake_time = types.SimpleNamespace(time=lambda: clock[0],
                                          sleep=lambda s: clock.__setitem__(0, clock[0] + s))
        ns = {
            'os': os, 'json': json, 're': re, 'time': fake_time,
            'subprocess': types.SimpleNamespace(run=self.run, PIPE=-1, STDOUT=-2),
            'print': lambda *a, **k: self.logs.append(' '.join(str(x) for x in a)),
            'load_settings': lambda: {},
            '_cloudtak_build_override_yml': lambda s: OVERRIDE,
            '_patch_cloudtak_minio_registry': lambda d: False,
            '_patch_cloudtak_compose_ports': lambda d: self.patched,
            '_sudo_wrap': lambda a: list(a),
            '_docker_compose_pull': lambda *a, **k: self.calls.append(['PULL']),
            '_cloudtak_media_hls_heal': self.heal,
            '_cloudtak_open_stream_ports': lambda *a, **k: None,
            'CONFIG_DIR': str(self.home / '.config'),
        }
        for c in ('_CLOUDTAK_RECREATE_PENDING', '_CLOUDTAK_RECREATE_MAX_TRIES', '_CLOUDTAK_COMPOSE_UP_RE'):
            exec(_const(c), ns)
        for f in ('_ct_recreate_pending', '_ct_recreate_arm', '_ct_recreate_clear',
                  '_ct_wait_compose_idle', '_startup_harden_cloudtak_ports'):
            exec(compile(_src(f), 'app.py', 'exec'), ns)
        old = os.environ.get('HOME')
        os.environ['HOME'] = str(self.home)
        try:
            ns['_startup_harden_cloudtak_ports']()
        finally:
            os.environ['HOME'] = old
        return self

    def ups(self):
        return [c for c in self.calls if c[:4] == ['docker', 'compose', 'up', '-d']]

    def pending(self):
        p = self.home / '.config' / 'cloudtak-recreate-pending.json'
        return json.loads(p.read_text()) if p.exists() else None


@pytest.fixture
def home(tmp_path):
    (tmp_path / 'CloudTAK').mkdir()
    (tmp_path / '.config').mkdir()
    return tmp_path


def _write_override(home, text):
    (home / 'CloudTAK' / 'docker-compose.override.yml').write_text(text)


def test_converged_box_does_nothing_and_leaves_no_marker(home):
    _write_override(home, OVERRIDE)
    b = Box(home).start()
    assert b.ups() == [] and b.heals == 0
    assert b.pending() is None


def test_changed_override_recreates_heals_and_clears(home):
    _write_override(home, 'old\n')
    b = Box(home).start()
    assert len(b.ups()) == 1 and b.heals == 1
    assert b.pending() is None


def test_killed_mid_recreate_resumes_on_next_start(home):
    # The field case: the override is written, then the console dies during `up`.
    _write_override(home, 'old\n')
    with pytest.raises(Killed):
        Box(home, kill_on_up=True).start()
    assert (home / 'CloudTAK' / 'docker-compose.override.yml').read_text() == OVERRIDE
    assert json.loads((home / '.config' / 'cloudtak-recreate-pending.json').read_text())['tries'] == 1
    # Next start: files already converged and the api is bound to loopback, yet it must
    # still finish the recreate and heal the media container.
    b = Box(home).start()
    assert len(b.ups()) == 1, b.logs
    assert b.heals == 1
    assert any('recreate was cut off' in l for l in b.logs)
    assert b.pending() is None


def test_killed_after_files_before_recreate_resumes(home):
    # Killed even earlier — between the base-compose patch and the recreate.
    _write_override(home, OVERRIDE)
    with pytest.raises(Killed):
        Box(home, kill_on_up=True, patched=True).start()
    b = Box(home).start()
    assert len(b.ups()) == 1 and b.heals == 1 and b.pending() is None


def test_resume_waits_for_the_orphaned_compose_before_recreate_and_heal(home):
    # aws-arm: the broker's `compose up` outlived the killed console. Healing before it
    # finishes is what lost the HLS profile, so nothing may run until it is gone.
    _write_override(home, 'old\n')
    with pytest.raises(Killed):
        Box(home, kill_on_up=True).start()
    b = Box(home, busy_polls=4).start()
    ps = [i for i, c in enumerate(b.calls) if c[:2] == ['ps', '-eo']]
    up = next(i for i, c in enumerate(b.calls) if c[:4] == ['docker', 'compose', 'up', '-d'])
    heal = b.calls.index(['HEAL'])
    assert len(ps) == 5 and ps[-1] < up < heal
    assert any('waiting for a compose run left by the previous console' in l for l in b.logs)
    assert b.pending() is None


def test_wait_for_orphan_is_bounded(home):
    _write_override(home, 'old\n')
    with pytest.raises(Killed):
        Box(home, kill_on_up=True).start()
    b = Box(home, busy_polls=10_000).start()
    assert any('still going after 300s' in l for l in b.logs)
    assert len(b.ups()) == 1          # carries on rather than hanging startup


def test_failed_heal_keeps_it_pending_then_gives_up_after_three_tries(home):
    _write_override(home, 'old\n')
    for n in (1, 2, 3):
        b = Box(home, heal_ok=False).start()
        assert len(b.ups()) == 1
        assert b.pending()['tries'] == n
    b = Box(home, heal_ok=False).start()
    assert b.ups() == []
    assert any('giving up' in l for l in b.logs)
    assert b.pending() is None


def test_compromised_stack_is_never_brought_back(home):
    _write_override(home, 'old\n')
    with pytest.raises(Killed):
        Box(home, kill_on_up=True).start()
    (home / 'CloudTAK' / 'COMPROMISE-DETECTED.txt').write_text('x')
    b = Box(home).start()
    assert b.ups() == [] and b.pending() is None
    assert any('compromise banner present' in l for l in b.logs)


def test_compose_up_matcher():
    rx = re.compile(eval(re.search(r"re\.compile\((r'.*?')\)", _const('_CLOUDTAK_COMPOSE_UP_RE')).group(1)))
    for hit in (COMPOSE_UP, 'docker compose up -d --force-recreate',
                'docker-compose up -d', 'docker compose -f a.yml up'):
        assert rx.search(hit), hit
    for miss in ('docker compose pull postgis', 'docker compose ps', 'docker compose restart',
                 'python3 app.py --setup', 'sleep 30'):
        assert not rx.search(miss), miss


def test_post_update_hardening_journals_the_same_recreate():
    start = APP.index('# 4. Write hardened override (always, idempotent)')
    body = APP[start:APP.index('Post-update: CloudTAK security hardening complete', start)]
    assert body.index('_ct_recreate_arm()') < body.index("open(_override_path, 'w')")
    assert body.index('_ct_recreate_arm()') < body.index('_patch_cloudtak_compose_ports(')
    up = body.index("'up', '-d', '--force-recreate'")
    assert 'if _cloudtak_media_hls_heal(wait=True):\n' in body[up:]
    assert body[up:].index('_ct_recreate_clear()') > body[up:].index('_cloudtak_media_hls_heal(wait=True)')
