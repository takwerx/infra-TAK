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
"""ops #1379 — Authentik .env backups must not pile up (one long-running box held 586).

Every `.env.bak.<tag>.<time>` copy holds PG_PASS and AUTHENTIK_SECRET_KEY and the MAX_REQUESTS
autotune writes one per change. These pin: the newest 20 copies per tag stay and the rest go
(the proof test: 30 old copies of one tag, 20 left), the newest copy that is still sane is never
deleted (the Deploy guard from ops #1332 restores from it), nothing but those exact names is
touched, and a problem while pruning never stops the writer. The helpers are cut out of app.py
and run here, so the code under test is the shipped text.
"""

import ast
import os
import pathlib
import re
import stat
import subprocess
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

GOOD_ENV = (
    'PG_DB=authentik\nPG_USER=authentik\nPG_PASS=origPgPass123\n'
    'AUTHENTIK_SECRET_KEY=origSecretKey456\nCOMPOSE_PORT_HTTP=9090\n'
)
BAD_ENV = 'AUTHENTIK_WEB__MAX_REQUESTS=1000\n'      # no secrets: not a usable backup


def _src(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and getattr(n.targets[0], 'id', '') == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(name)


def _ns():
    ns = {'os': os, 'subprocess': subprocess, 'time': time, 're': re}
    for n in ('AUTHENTIK_ENV_BACKUPS_KEEP', '_AK_ENV_BACKUP_RE', '_authentik_env_sane',
              '_authentik_env_newest_good_backup', '_authentik_prune_env_backups',
              '_authentik_prune_env_backups_quiet'):
        exec(compile(_src(n), f'app.py:{n}', 'exec'), ns)
    return ns


def _make(folder, tag, stamps, text=GOOD_ENV, prefix='.env.bak'):
    out = []
    for ts in stamps:
        f = folder / (f'{prefix}.{tag}.{ts}' if tag else f'.env.damaged.{ts}')
        f.write_text(text)
        os.utime(f, (ts, ts))
        out.append(f)
    return out


@pytest.fixture
def ak(tmp_path):
    d = tmp_path / 'authentik'
    d.mkdir()
    (d / '.env').write_text(GOOD_ENV)
    return d


def _left(folder, glob):
    return sorted(p.name for p in folder.glob(glob))


# ── the proof: 30 old copies of one tag, 20 left, the newest good one among them ───────

def test_thirty_autotune_backups_become_twenty_and_the_newest_good_one_stays(ak):
    _make(ak, 'autotune', range(1000, 1030))
    ns = _ns()
    deleted = ns['_authentik_prune_env_backups'](str(ak / '.env'))
    assert deleted == 10
    left = _left(ak, '.env.bak.autotune.*')
    assert len(left) == 20
    assert left == sorted(f'.env.bak.autotune.{ts}' for ts in range(1010, 1030))   # the newest 20
    assert '.env.bak.autotune.1029' in left                                       # newest good copy kept
    assert (ak / '.env').read_text() == GOOD_ENV


def test_the_default_is_twenty_per_tag():
    assert _ns()['AUTHENTIK_ENV_BACKUPS_KEEP'] == 20


def test_586_copies_like_the_real_box_end_at_twenty(ak):
    _make(ak, 'autotune', range(5000, 5586))
    _make(ak, 'tunings', range(100, 105))
    _make(ak, 'gunicorn-timeout', [200])
    n = _ns()['_authentik_prune_env_backups'](str(ak / '.env'))
    assert n == 566
    assert len(_left(ak, '.env.bak.autotune.*')) == 20
    assert len(_left(ak, '.env.bak.tunings.*')) == 5            # other tags are counted on their own
    assert len(_left(ak, '.env.bak.gunicorn-timeout.*')) == 1


def test_tags_are_kept_separately(ak):
    _make(ak, 'autotune', range(1000, 1030))
    _make(ak, 'before-pgbouncer', range(900, 925))
    _ns()['_authentik_prune_env_backups'](str(ak / '.env'))
    assert len(_left(ak, '.env.bak.autotune.*')) == 20
    assert len(_left(ak, '.env.bak.before-pgbouncer.*')) == 20


def test_exactly_twenty_or_fewer_deletes_nothing(ak):
    _make(ak, 'autotune', range(1000, 1020))
    assert _ns()['_authentik_prune_env_backups'](str(ak / '.env')) == 0
    assert len(_left(ak, '.env.bak.autotune.*')) == 20


def test_order_follows_the_time_in_the_name_not_the_file_time(ak):
    files = _make(ak, 'autotune', range(1000, 1025))
    for f in files:                       # a restore from a tarball gave every file the same mtime
        os.utime(f, (5000, 5000))
    _ns()['_authentik_prune_env_backups'](str(ak / '.env'))
    assert _left(ak, '.env.bak.autotune.*') == sorted(f'.env.bak.autotune.{ts}' for ts in range(1005, 1025))


# ── the guard: the newest sane backup is never deleted ─────────────────────────────

def test_newest_good_backup_survives_even_when_twenty_newer_ones_are_damaged(ak):
    _make(ak, 'autotune', [1000], text=GOOD_ENV)                        # the only good copy, oldest
    _make(ak, 'autotune', range(2000, 2025), text=BAD_ENV)              # 25 newer ones with no secrets
    n = _ns()['_authentik_prune_env_backups'](str(ak / '.env'))
    left = _left(ak, '.env.bak.autotune.*')
    assert '.env.bak.autotune.1000' in left                              # kept although it is the 26th
    assert n == 5 and len(left) == 21
    bak, text = _ns()['_authentik_env_newest_good_backup'](str(ak / '.env'))
    assert bak and 'PG_PASS=origPgPass123' in text                       # Deploy guard can still restore


def test_damaged_copies_are_pruned_too_and_the_good_backup_stays(ak):
    _make(ak, 'autotune', [1000])
    _make(ak, None, range(3000, 3030), text=BAD_ENV)
    _ns()['_authentik_prune_env_backups'](str(ak / '.env'))
    assert len(_left(ak, '.env.damaged.*')) == 20
    assert _left(ak, '.env.bak.autotune.*') == ['.env.bak.autotune.1000']


# ── nothing but those exact names is touched ───────────────────────────────────────

def test_only_matching_names_are_deleted(ak, tmp_path):
    _make(ak, 'autotune', range(1000, 1030))
    keep = [
        '.env', 'docker-compose.yml',
        'docker-compose.yml.bak.routing-repair.1', 'docker-compose.yml.bak.autotune.2',
        '.env.bak', '.env.bak.1', '.env.bak.autotune', '.env.bak.autotune.abc',
        '.env.bak.autotune.12.keep', '.env.bakold.5', '.env.old.7', '.env.damaged', 'notes.txt',
    ]
    for k in keep:
        (ak / k).write_text(GOOD_ENV)
    outside = tmp_path / 'outside.txt'
    outside.write_text('x')
    (ak / '.env.bak.autotune.7000').symlink_to(outside)                 # a symlink is never followed or removed
    (ak / '.env.bak.autotune.7001').mkdir()                              # a folder is left alone
    _ns()['_authentik_prune_env_backups'](str(ak / '.env'))
    for k in keep:
        assert (ak / k).exists(), k
    assert (ak / '.env.bak.autotune.7000').is_symlink() and outside.exists()
    assert (ak / '.env.bak.autotune.7001').is_dir()
    assert len(_left(ak, '.env.bak.autotune.10*')) == 20


def test_tag_with_dots_and_dashes_is_one_tag(ak):
    _make(ak, 'pre-v10.4.8', range(1000, 1022))
    _ns()['_authentik_prune_env_backups'](str(ak / '.env'))
    assert len(_left(ak, '.env.bak.pre-v10.4.8.*')) == 20


def test_other_folders_are_not_touched(tmp_path, ak):
    other = tmp_path / 'other'
    other.mkdir()
    _make(other, 'autotune', range(1000, 1030))
    _ns()['_authentik_prune_env_backups'](str(ak / '.env'))
    assert len(list(other.iterdir())) == 30


# ── a problem while pruning never stops the writer ─────────────────────────────────

def test_missing_folder_is_not_an_error(tmp_path):
    assert _ns()['_authentik_prune_env_backups'](str(tmp_path / 'nope' / '.env')) == 0


def test_a_file_that_cannot_be_deleted_is_skipped_not_raised(ak, monkeypatch):
    _make(ak, 'autotune', range(1000, 1030))
    ns = _ns()

    def boom(path):
        raise PermissionError(13, 'denied', path)
    monkeypatch.setattr(os, 'unlink', boom)
    assert ns['_authentik_prune_env_backups'](str(ak / '.env')) == 0
    assert len(_left(ak, '.env.bak.autotune.*')) == 30


def test_one_undeletable_file_does_not_stop_the_rest(ak, monkeypatch):
    _make(ak, 'autotune', range(1000, 1030))
    ns = _ns()
    real = os.unlink

    def picky(path):
        if str(path).endswith('.1003'):
            raise PermissionError(13, 'denied', path)
        real(path)
    monkeypatch.setattr(os, 'unlink', picky)
    assert ns['_authentik_prune_env_backups'](str(ak / '.env')) == 9
    assert '.env.bak.autotune.1003' in _left(ak, '.env.bak.autotune.*')


def test_a_broken_helper_never_raises_out_of_the_quiet_wrapper(ak):
    ns = _ns()

    def broken(*a, **k):
        raise RuntimeError('boom')
    ns['_authentik_env_newest_good_backup'] = broken
    _make(ak, 'autotune', range(1000, 1030))
    assert ns['_authentik_prune_env_backups_quiet'](str(ak / '.env')) >= 0     # no exception


def test_the_quiet_wrapper_says_so_once(ak):
    _make(ak, 'autotune', range(1000, 1030))
    lines = []
    n = _ns()['_authentik_prune_env_backups_quiet'](str(ak / '.env'), lines.append)
    assert n == 10 and len(lines) == 1 and 'removed 10 old backup copies' in lines[0]
    lines.clear()
    assert _ns()['_authentik_prune_env_backups_quiet'](str(ak / '.env'), lines.append) == 0
    assert lines == []                                                         # a second run is silent


def test_modes_are_left_as_they_were(ak):
    files = _make(ak, 'autotune', range(1000, 1025))
    for f in files:
        os.chmod(f, 0o600)
    _ns()['_authentik_prune_env_backups'](str(ak / '.env'))
    for p in ak.glob('.env.bak.autotune.*'):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


# ── wiring: every repeating writer prunes after its backup, and the console start does it ──

@pytest.mark.parametrize('tag', [
    'gunicorn-timeout', 'pg-persistent-conn', 'conn-max-age-60to10',
    'max-requests-1000', 'snap-to-baseline', 'autotune', 'tunings',
])
def test_each_repeating_writer_prunes_right_after_its_backup(tag):
    i = APP.index(f'.bak.{tag}.')
    window = APP[i:i + 520]
    assert '_authentik_prune_env_backups_quiet(' in window, window


def test_console_start_prunes_the_pile_a_long_running_box_already_has():
    src = _src('_authentik_apply_official_tunings')
    assert src.index('_authentik_tighten_env_backups(') < src.index('_authentik_prune_env_backups_quiet(')
    # and it runs before the early returns that depend on the .env content
    assert src.index('_authentik_prune_env_backups_quiet(') < src.index('_authentik_env_sane(content)')


def test_restore_from_backup_prunes_the_damaged_copies_it_adds():
    assert '_authentik_prune_env_backups_quiet(' in _src('_authentik_env_restore_from_backup')


def test_tunings_pass_end_to_end_prunes_a_long_running_box(tmp_path, monkeypatch):
    """The real tunings function on a folder with 586 old copies: it ends with 20 and a good .env."""
    import test_authentik_env_atomic_write_ops1332 as old
    home = tmp_path / 'home'
    ak = home / 'authentik'
    ak.mkdir(parents=True)
    (ak / '.env').write_text(GOOD_ENV)
    _make(ak, 'autotune', range(5000, 5586))
    for f in ak.glob('.env.bak.autotune.*'):
        os.chmod(f, 0o644)
    monkeypatch.setenv('HOME', str(home))
    log = old._Log()
    ns = old._tunings_ns(log, old._load('_open_secret_w')['_open_secret_w'])
    ns['_authentik_apply_official_tunings'](log)
    assert len(_left(ak, '.env.bak.autotune.*')) == 20
    assert 'removed 566 old backup copies' in log.text()
    assert 'PG_PASS=origPgPass123' in (ak / '.env').read_text()
    assert len(_left(ak, '.env.bak.tunings.*')) == 1                 # the tunings pass made its own, kept
