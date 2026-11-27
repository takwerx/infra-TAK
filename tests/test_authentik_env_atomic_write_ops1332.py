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
"""ops #1332 — the Authentik .env must never be left empty or cut short.

`_open_secret_w` used to open with O_TRUNC, so a full disk or a dead process mid-write
left ~/authentik/.env truncated. It holds PG_PASS and AUTHENTIK_SECRET_KEY, and a Deploy
over the old database volume then made new ones and locked Authentik out of its own
database. These pin: an all-or-nothing write (the proof test: a write that fails halfway
leaves the old file intact), a plain full-disk error, 0600 backups, no tuning on a
damaged file, and Deploy refusing to make new secrets over an existing database volume.
The helpers are cut out of app.py and run here, so the code under test is the shipped text.
"""

import ast
import errno
import os
import pathlib
import re
import stat
import subprocess
import sys
import textwrap
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

GOOD_ENV = (
    'PG_DB=authentik\nPG_USER=authentik\nPG_PASS=origPgPass123\n'
    'AUTHENTIK_SECRET_KEY=origSecretKey456\nCOMPOSE_PORT_HTTP=9090\n'
)


def _fn(name):
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(APP, node)


def _load(*names, **extra):
    ns = {'os': os, 'subprocess': subprocess, 'time': time, 're': re}
    for node in TREE.body:      # ops #1379: module-level constants the prune helper reads
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], 'id', '') in ('AUTHENTIK_ENV_BACKUPS_KEEP', '_AK_ENV_BACKUP_RE')):
            exec(compile(ast.get_source_segment(APP, node), 'app.py:const', 'exec'), ns)
    ns.update(extra)
    for n in names:
        exec(compile(_fn(n), f'app.py:{n}', 'exec'), ns)
    return ns


class _Log:
    def __init__(self):
        self.lines = []

    def __call__(self, msg):
        self.lines.append(msg)

    def text(self):
        return '\n'.join(self.lines)


def _leftovers(folder):
    return sorted(n for n in os.listdir(folder) if n.endswith('.tmp'))


# ── the proof: a write that fails halfway leaves the old file intact ────────────

def test_failed_write_leaves_the_old_env_intact(tmp_path):
    ns = _load('_open_secret_w')
    p = tmp_path / '.env'
    p.write_text(GOOD_ENV)
    with pytest.raises(RuntimeError):
        with ns['_open_secret_w'](str(p)) as f:
            f.write('PG_PASS=newnewnew\n')
            raise RuntimeError('died halfway')
    assert p.read_text() == GOOD_ENV
    assert _leftovers(tmp_path) == []


def test_process_killed_mid_write_leaves_the_old_env_intact(tmp_path):
    p = tmp_path / '.env'
    p.write_text(GOOD_ENV)
    helper = textwrap.dedent(_fn('_open_secret_w'))
    script = (
        'import os\n' + helper + '\n'
        f'with _open_secret_w({str(p)!r}) as f:\n'
        '    f.write("PG_PASS=half")\n'
        '    os._exit(9)\n'        # the process dies inside the with-body
    )
    r = subprocess.run([sys.executable, '-I', '-c', script], capture_output=True)
    assert r.returncode == 9
    assert p.read_text() == GOOD_ENV
    assert _leftovers(tmp_path) == []


def test_clean_write_replaces_the_file_and_is_0600(tmp_path):
    ns = _load('_open_secret_w')
    p = tmp_path / '.env'
    p.write_text(GOOD_ENV)
    os.chmod(p, 0o644)
    with ns['_open_secret_w'](str(p)) as f:
        f.write('A=1\n')
        f.write('B=2\n')
    assert p.read_text() == 'A=1\nB=2\n'
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert _leftovers(tmp_path) == []


def test_new_file_is_0600_even_with_a_loose_umask(tmp_path):
    ns = _load('_open_secret_w')
    p = tmp_path / '.env'
    old = os.umask(0o022)
    try:
        with ns['_open_secret_w'](str(p)) as f:
            f.write('X=1\n')
    finally:
        os.umask(old)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_temp_file_is_made_in_the_same_folder_and_renamed(tmp_path):
    seen = []
    real_replace = os.replace

    class _Os:
        def __getattr__(self, name):
            return getattr(os, name)

        def replace(self, a, b):
            seen.append((a, b))
            return real_replace(a, b)

    ns = _load('_open_secret_w', os=_Os())
    p = tmp_path / '.env'
    with ns['_open_secret_w'](str(p)) as f:
        f.write('A=1\n')
    assert len(seen) == 1
    assert os.path.dirname(seen[0][0]) == str(tmp_path)      # same filesystem: the rename is atomic
    assert seen[0][1] == str(p)


def test_a_symlinked_env_stays_a_symlink(tmp_path):
    ns = _load('_open_secret_w')
    real = tmp_path / 'real.env'
    real.write_text('OLD=1\n')
    link = tmp_path / '.env'
    link.symlink_to(real)
    with ns['_open_secret_w'](str(link)) as f:
        f.write('NEW=2\n')
    assert link.is_symlink()
    assert real.read_text() == 'NEW=2\n'


# ── a full disk: plain message, old file untouched ─────────────────────────────

def test_full_disk_raises_a_plain_error_and_keeps_the_old_file(tmp_path):
    real_write = os.write

    class _Os:
        def __getattr__(self, name):
            return getattr(os, name)

        def write(self, fd, data):
            raise OSError(errno.ENOSPC, 'No space left on device')

    ns = _load('_open_secret_w', os=_Os())
    p = tmp_path / '.env'
    p.write_text(GOOD_ENV)
    with pytest.raises(OSError) as ei:
        with ns['_open_secret_w'](str(p)) as f:
            f.write('PG_PASS=whatever\n')
    assert ei.value.errno == errno.ENOSPC
    assert 'Disk is full' in str(ei.value) and 'old file was left unchanged' in str(ei.value)
    assert p.read_text() == GOOD_ENV
    assert _leftovers(tmp_path) == []
    assert real_write is os.write


def test_tunings_on_a_full_disk_say_no_changes_and_keep_the_file(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    env = home / 'authentik' / '.env'
    env.write_text(GOOD_ENV)
    monkeypatch.setenv('HOME', str(home))

    class _Os:
        def __getattr__(self, name):
            return getattr(os, name)

        def write(self, fd, data):
            raise OSError(errno.ENOSPC, 'No space left on device')

    helper_ns = _load('_open_secret_w', os=_Os())
    log = _Log()
    ns = _tunings_ns(log, helper_ns['_open_secret_w'])
    assert ns['_authentik_apply_official_tunings'](log) is False
    assert 'write error (no changes applied)' in log.text()
    assert 'Disk is full' in log.text()
    assert env.read_text() == GOOD_ENV


# ── fallback when the folder will not allow a rename ──────────────────────────

def test_folder_that_refuses_the_rename_falls_back_to_writing_in_place(tmp_path):
    class _Os:
        def __getattr__(self, name):
            return getattr(os, name)

        def replace(self, a, b):
            raise PermissionError(errno.EACCES, 'denied')

    ns = _load('_open_secret_w', os=_Os())
    p = tmp_path / '.env'
    p.write_text(GOOD_ENV + 'PADDING=' + 'x' * 200 + '\n')
    with ns['_open_secret_w'](str(p)) as f:
        f.write('SHORT=1\n')
    assert p.read_text() == 'SHORT=1\n'                       # shorter text: no stale tail
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert _leftovers(tmp_path) == []


# ── backups hold the secrets: 0600, never a plain open() ─────────────────────

@pytest.mark.parametrize('tag', [
    'gunicorn-timeout', 'pg-persistent-conn', 'conn-max-age-60to10',
    'max-requests-1000', 'snap-to-baseline', 'autotune',
])
def test_env_backups_are_written_through_the_0600_helper(tag):
    i = APP.index(f'.bak.{tag}.')
    window = APP[i:i + 220]
    assert re.search(r"with _open_secret_w\((backup_path|_backup)\)", window), window
    assert not re.search(r"with open\((backup_path|_backup), 'w'\)", window), window


def test_tunings_and_cidr_writers_now_keep_a_0600_backup(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    env = home / 'authentik' / '.env'
    env.write_text(GOOD_ENV)
    monkeypatch.setenv('HOME', str(home))
    log = _Log()
    ns = _tunings_ns(log, _load('_open_secret_w')['_open_secret_w'])
    assert ns['_authentik_apply_official_tunings'](log) is True
    baks = sorted((home / 'authentik').glob('.env.bak.tunings.*'))
    assert len(baks) == 1
    assert baks[0].read_text() == GOOD_ENV
    assert stat.S_IMODE(baks[0].stat().st_mode) == 0o600
    assert 'AUTHENTIK_WEB__WORKERS=4' in env.read_text()
    assert 'PG_PASS=origPgPass123' in env.read_text()          # secrets carried over unchanged

    assert ns['_authentik_fix_trusted_proxy_cidrs'](log) is True or 'already set' in log.text()
    cidr_baks = sorted((home / 'authentik').glob('.env.bak.trusted-proxy.*'))
    for b in cidr_baks:
        assert stat.S_IMODE(b.stat().st_mode) == 0o600


def test_old_world_readable_env_backups_are_made_private(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    ak = home / 'authentik'
    ak.mkdir(parents=True)
    (ak / '.env').write_text(GOOD_ENV)
    old = [ak / '.env.bak.autotune.1', ak / '.env.bak.before-pgbouncer.2', ak / '.env.damaged.3']
    for f in old:
        f.write_text(GOOD_ENV)
        os.chmod(f, 0o644)
    other = ak / 'docker-compose.yml.bak.routing-repair.4'      # not an .env backup: left alone
    other.write_text('services: {}\n')
    os.chmod(other, 0o644)
    monkeypatch.setenv('HOME', str(home))
    log = _Log()
    ns = _tunings_ns(log, _load('_open_secret_w')['_open_secret_w'])
    ns['_authentik_apply_official_tunings'](log)
    for f in old:
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, f
    assert stat.S_IMODE(other.stat().st_mode) == 0o644
    assert 'made 3 old .env backup file(s) private' in log.text()
    # idempotent: a second run has nothing left to change
    log2 = _Log()
    ns['_authentik_apply_official_tunings'](log2)
    assert 'private (mode 600)' not in log2.text()


# ── a damaged .env: no tuning on top of it, restore from a good backup ────────

@pytest.mark.parametrize('bad', ['', 'AUTHENTIK_ERROR_REPORTING__ENABLED=false\n', 'PG_PASS=abc'])
def test_tunings_refuse_a_damaged_env_with_no_backup(tmp_path, monkeypatch, bad):
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    env = home / 'authentik' / '.env'
    env.write_text(bad)
    monkeypatch.setenv('HOME', str(home))
    log = _Log()
    ns = _tunings_ns(log, _load('_open_secret_w')['_open_secret_w'])
    assert ns['_authentik_apply_official_tunings'](log) is False
    assert env.read_text() == bad                              # not tuned, not "no changes applied"
    assert 'changed nothing' in log.text()
    assert 'no changes needed' not in log.text()


def test_tunings_restore_a_damaged_env_from_the_newest_good_backup(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    ak = home / 'authentik'
    ak.mkdir(parents=True)
    (ak / '.env').write_text('PG_PASS=cut')                  # cut short: no secret key
    old = ak / '.env.bak.before-pgbouncer.1'
    old.write_text(GOOD_ENV)
    os.utime(old, (1000, 1000))
    newer_but_bad = ak / '.env.bak.tunings.2'
    newer_but_bad.write_text('')                              # an empty backup is skipped
    monkeypatch.setenv('HOME', str(home))
    log = _Log()
    ns = _tunings_ns(log, _load('_open_secret_w')['_open_secret_w'])
    assert ns['_authentik_apply_official_tunings'](log) is True
    text = (ak / '.env').read_text()
    assert 'PG_PASS=origPgPass123' in text and 'AUTHENTIK_SECRET_KEY=origSecretKey456' in text
    assert 'restored from' in log.text()
    kept = list(ak.glob('.env.damaged.*'))
    assert len(kept) == 1 and kept[0].read_text() == 'PG_PASS=cut'
    assert stat.S_IMODE(kept[0].stat().st_mode) == 0o600


# ── Deploy: never make new secrets over an existing database volume ───────────

def _guard_ns(volume, calls=None):
    ns = _load('_open_secret_w', '_authentik_env_sane', '_authentik_env_newest_good_backup',
               '_authentik_env_restore_from_backup', '_authentik_env_guard_before_mint')

    def vol():
        if calls is not None:
            calls.append('volume-check')
        return volume
    ns['_authentik_db_volume_exists'] = vol
    return ns


def test_deploy_refuses_to_mint_secrets_when_the_database_volume_exists(tmp_path):
    env = tmp_path / '.env'                                    # missing
    log = _Log()
    ns = _guard_ns(True)
    assert ns['_authentik_env_guard_before_mint'](str(env), log) == 'refuse'
    assert not env.exists()
    assert 'authentik_database' in log.text() and 'new passwords' in log.text()


def test_deploy_restores_from_a_backup_instead_of_minting(tmp_path):
    env = tmp_path / '.env'
    (tmp_path / '.env.bak.autotune.5').write_text(GOOD_ENV)
    log = _Log()
    ns = _guard_ns(True)
    assert ns['_authentik_env_guard_before_mint'](str(env), log) == 'restored'
    assert env.read_text() == GOOD_ENV
    assert stat.S_IMODE(env.stat().st_mode) == 0o600


def test_deploy_mints_as_before_on_a_fresh_box(tmp_path):
    env = tmp_path / '.env'
    ns = _guard_ns(False)
    assert ns['_authentik_env_guard_before_mint'](str(env), _Log()) == 'ok'


def test_deploy_carries_on_when_docker_cannot_say(tmp_path):
    ns = _guard_ns(None)
    assert ns['_authentik_env_guard_before_mint'](str(tmp_path / '.env'), _Log()) == 'ok'


def test_a_good_env_never_asks_docker(tmp_path):
    env = tmp_path / '.env'
    env.write_text(GOOD_ENV)
    calls = []
    ns = _guard_ns(True, calls)
    assert ns['_authentik_env_guard_before_mint'](str(env), _Log()) == 'ok'
    assert calls == []


def test_deploy_calls_the_guard_before_the_secrets_are_minted():
    i = APP.index("_authentik_env_guard_before_mint(env_path, plog) == 'refuse'")
    j = APP.index("pg_pass = subprocess.run('openssl rand -base64 36", i)
    assert 0 < j - i < 600          # the guard sits right above the minting block


def test_volume_probe_reads_docker_volume_ls():
    ns = _load('_authentik_db_volume_exists', _sudo_wrap=lambda c: c)
    ran = []

    class R:
        def __init__(self, out, rc=0):
            self.stdout, self.returncode = out, rc

    def fake_run(cmd, **kw):
        ran.append(cmd)
        return fake_run.result
    ns['subprocess'] = type('S', (), {'run': staticmethod(fake_run)})
    fake_run.result = R('other\nauthentik_database\n')
    assert ns['_authentik_db_volume_exists']() is True
    fake_run.result = R('other\nauthentik_database_old\n')
    assert ns['_authentik_db_volume_exists']() is False
    fake_run.result = R('', 1)
    assert ns['_authentik_db_volume_exists']() is None
    assert ran[0][:3] == ['docker', 'volume', 'ls']


# ── helpers ────────────────────────────────────────────────────────────────

def _tunings_ns(log, open_secret_w):
    ns = _load('_authentik_env_sane', '_authentik_env_newest_good_backup',
               '_authentik_env_restore_from_backup', '_authentik_tighten_env_backups',
               '_authentik_prune_env_backups', '_authentik_prune_env_backups_quiet',   # ops #1379
               '_authentik_apply_official_tunings', '_authentik_fix_trusted_proxy_cidrs')
    from datetime import datetime
    ns.update({
        '_open_secret_w': open_secret_w,
        'datetime': datetime,
        'load_settings': lambda: {},
        'save_settings': lambda s: None,
        'AK_TASK_EXPIRATION': '3 days',
        'AK_TRUSTED_PROXY_CIDRS': '172.16.0.0/12,127.0.0.1/32,::1/128',
    })
    return ns
