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
"""ops #1334: the CloudTAK MinIO -> Garage move and Deploy must never leave a box worse off.

Six findings from the stack audit (ops #1311), one proof test group each:
  1. a failed move left api, events, tiles and retention stopped (only Update rolled back)
  2. the Update free-space message told the customer to run `docker image prune -af`, which
     deletes the only MinIO program that can read .docker-store (MinIO is not downloadable)
  3. the 16 GB floor ignored how big .docker-store is, which is copied in full
  4. the remote Garage step ran upstream's `cloudtak.sh migrate-store` (`rclone sync`, line 485
     of 13.127.0), the very command our local code replaced with `copy --update`
  5. a Deploy re-clone ran `rm -rf` over a tree holding .docker-garage / .docker-store
  6. Deploy had no "newer than the pin" guard, so the 13.127.0 fallback could go over a 14 box

app.py cannot be imported in a test, so the functions are cut out of it and run as shipped.
"""

import ast
import os
import pathlib
import re
import secrets
import shlex
import subprocess
import time

import pytest

import test_cloudtak_deploy_keeps_secrets_ops198 as D

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
GB = 1024 ** 3
IMG = 'quay.io/minio/minio:RELEASE.2024-08-17T01-24-54Z'
GARAGE_COMPOSE = """services:
    store:
        image: dxflrs/garage:v2.4.1
        environment:
            - GARAGE_RPC_SECRET=${GARAGE_RPC_SECRET}
"""
ENV = """ASSET_BUCKET=cloudtak
AWS_S3_Endpoint=http://store:9000
AWS_S3_AccessKeyId=cloudtak
AWS_S3_SecretAccessKey=abc123
MINIO_ROOT_USER=cloudtak
MINIO_ROOT_PASSWORD=abc123
"""
FUNCS = {
    '_cloudtak_store_endpoint', '_cloudtak_compose_is_garage', '_cloudtak_env_read', '_cloudtak_env_set',
    '_cloudtak_env_parse_text', '_cloudtak_compose_at', '_cloudtak_rclone_bytes',
    '_cloudtak_migrate_space_short', '_cloudtak_keep_legacy_image', '_cloudtak_load_legacy_image',
    '_cloudtak_migrate_minio_to_garage', '_cloudtak_garage_converge', '_cloudtak_remote_garage_sh',
    '_cloudtak_remote_garage_converge', '_cloudtak_update_space_lines', '_cloudtak_version_is_newer',
    '_cloudtak_has_data', '_open_secret_w',
}


def _load(**over):
    parts = []
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in FUNCS:
            parts.append(ast.get_source_segment(APP, node))
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and (t.id.startswith('_CT_') or t.id == '_FREE_SPACE_BACKUPS_HINT')
                for t in node.targets):
            parts.append(ast.get_source_segment(APP, node))
    ns = {'os': os, 're': re, 'shlex': shlex, 'secrets': secrets,
          'time': type('T', (), {'sleep': staticmethod(lambda s: None),
                                 'strftime': staticmethod(lambda f: '20261127_030000')}),
          'subprocess': subprocess, '_sudo_wrap': lambda a: a, '_FREE_SPACE_BACKUPS_HINT': 'HINT'}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    ns.update(over)
    return ns


class Compose:
    """Records every `docker compose` call (local or remote); one call can be made to fail or raise."""
    def __init__(self, fail_on=None, raise_on=None, minio_bytes=2048, garage_bytes=0, events=None):
        self.calls, self.fail_on, self.raise_on = [], fail_on, raise_on
        self.minio_bytes, self.garage_bytes = minio_bytes, garage_bytes
        self.events = events if events is not None else []

    def run(self, cloudtak_dir, args, timeout=600):
        self.calls.append(list(args))
        self.events.append('compose ' + ' '.join(args))
        if self.raise_on and self.raise_on in args:
            raise RuntimeError('boom')
        if self.fail_on and self.fail_on in args and 'start' not in args:
            return 1, 'boom: ' + self.fail_on
        if 'copy' in args:
            return 0, 'INFO  : a.png: Copied (new)\n'
        if 'size' in args:
            n = self.minio_bytes if 'minio:cloudtak' in args else self.garage_bytes
            return 0, '{"count":1,"bytes":%d,"sizeless":0}\n' % n
        return 0, ''

    def at(self, cloudtak_dir, args, remote_cfg=None, timeout=600):
        return self.run(cloudtak_dir, args, timeout=timeout)


@pytest.fixture
def ct(tmp_path):
    (tmp_path / 'docker-compose.yml').write_text(GARAGE_COMPOSE)
    (tmp_path / '.env').write_text(ENV)
    (tmp_path / '.docker-store' / 'cloudtak').mkdir(parents=True)
    return tmp_path


def _ns(c, free=500 * GB, keep=None, **over):
    base = dict(_cloudtak_compose_run=c.run, _cloudtak_legacy_minio_image=lambda d: IMG,
                _cloudtak_keep_legacy_image=keep or (lambda *a, **k: True),
                _cloudtak_fs_free_local=lambda p: (1, free))
    base.update(over)
    return _load(**base)


START = ['start', 'api', 'events', 'tiles', 'retention']


# ── 1. a failed move starts the stopped services again ───────────────────────────────

@pytest.mark.parametrize('fail_on', ['up', 'copy', 'check', 'stop'])
def test_1_failed_move_starts_the_services_again(ct, fail_on):
    c, log = Compose(fail_on=fail_on), []
    ok, err = _ns(c)['_cloudtak_garage_converge'](str(ct), log.append, start=False, restart_on_fail=True)
    assert not ok and err
    assert c.calls[-1] == START                                     # last thing done: start them again
    assert (ct / '.docker-store' / 'cloudtak').is_dir()           # the files never moved
    assert any('started again' in l for l in log)


def test_1_unexpected_error_in_the_middle_also_starts_them_again(ct):
    c = Compose(raise_on='copy')
    ok, err = _ns(c)['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False, restart_on_fail=True)
    assert not ok and 'boom' in err
    assert c.calls[-1] == START


def test_1_update_keeps_its_own_rollback_and_does_not_start_them_here(ct):
    # the Update path puts the old tree and store back first (_cloudtak_garage_rollback)
    c = Compose(fail_on='copy')
    ok, _ = _ns(c)['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    assert not ok and START not in c.calls


def test_1_a_failed_start_is_reported_not_raised(ct):
    class C(Compose):
        def run(self, d, args, timeout=600):
            if args[:1] == ['start']:
                self.calls.append(list(args))
                return 1, 'no such container'
            return super().run(d, args, timeout)
    c, log = C(fail_on='copy'), []
    ok, _ = _ns(c)['_cloudtak_garage_converge'](str(ct), log.append, start=False, restart_on_fail=True)
    assert not ok and any('could not be started again' in l for l in log)


def _body(name):
    return re.search(rf'^def {name}\(.*?(?=^def )', APP, re.S | re.M).group(0)


def test_1_every_caller_without_a_rollback_asks_for_the_restart():
    deploy = re.sub(r'#.*', '', _body('run_cloudtak_deploy'))
    redeploy = re.sub(r'#.*', '', _body('run_cloudtak_redeploy'))
    update = re.sub(r'#.*', '', _body('run_cloudtak_update'))
    assert 'start=False, restart_on_fail=True)' in deploy and 'start=False, restart_on_fail=True)' in redeploy
    assert 'restart_on_fail=True' in deploy and 'restart_on_fail=True' in redeploy
    assert '_cloudtak_remote_garage_converge(' in deploy and 'restart_on_fail=True' in deploy
    assert 'restart_on_fail' not in update          # Update rolls the whole stack back instead
    boot = APP[APP.index('def _startup_cloudtak_garage'):]
    assert '_cloudtak_garage_converge(_ct, _gl, start=True, restart_on_fail=True)' in boot[:3000]


# ── 2. the MinIO program is kept, and the prune advice is not given ──────────────────

def test_2_space_message_drops_the_image_prune_while_minio_data_exists():
    n = _load()
    problem = {'what': 'the CloudTAK images and build cache', 'where': '/var/lib/docker',
               'free': 15 * GB, 'need': 17 * GB}
    text = '\n'.join(n['_cloudtak_update_space_lines'](problem, minio_store=True))
    assert '`docker image prune -af`' not in text                  # the advice is gone ...
    assert 'Do NOT run `docker image prune -a`' in text and '`docker builder prune -af`' in text
    assert 'Do not delete Docker volumes' in text
    plain = '\n'.join(n['_cloudtak_update_space_lines'](problem))
    assert '`docker image prune -af`' in plain         # a box with no .docker-store keeps the old advice


def test_2_update_passes_whether_the_minio_folder_is_there():
    update = re.sub(r'#.*', '', _body('run_cloudtak_update'))
    assert '_cloudtak_update_space_lines(_space, minio_store=bool(_store_now), cache_pruned=_cache_pruned)' in update


def test_2_the_minio_image_is_saved_before_the_first_service_is_stopped(ct):
    events = []
    c = Compose(events=events)
    ns = _ns(c, keep=lambda *a, **k: events.append('save image') or True)
    ok, err = ns['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    assert ok, err
    assert events[0] == 'save image' and events[1].startswith('compose stop')


def test_2_keep_saves_once_through_docker_save(tmp_path):
    seen = []

    def _docker(argv, remote_cfg=None, timeout=60):
        seen.append(argv)
        (tmp_path / '.minio-legacy-image.tar').write_bytes(b'x')
        return 0, '', ''
    n = _load(_cloudtak_docker=_docker)
    log = []
    assert n['_cloudtak_keep_legacy_image'](str(tmp_path), IMG, log.append) is True
    assert seen == [['docker', 'save', '-o', str(tmp_path / '.minio-legacy-image.tar'), IMG]]
    assert n['_cloudtak_keep_legacy_image'](str(tmp_path), IMG, log.append) is True
    assert len(seen) == 1                                           # a copy is there: not saved twice


def test_2_a_save_that_fails_never_stops_the_move(tmp_path):
    n = _load(_cloudtak_docker=lambda argv, remote_cfg=None, timeout=60: (1, '', 'permission denied'))
    log = []
    assert n['_cloudtak_keep_legacy_image'](str(tmp_path), IMG, log.append) is False
    assert any('Could not save' in l for l in log)


def test_2_the_saved_image_reads_the_files_when_docker_lost_the_cached_one(ct):
    (ct / '.minio-legacy-image.tar').write_bytes(b'tar')
    loaded = lambda argv, remote_cfg=None, timeout=60: (0, f'Loaded image: {IMG}\n', '')
    assert _load(_cloudtak_docker=loaded)['_cloudtak_load_legacy_image'](str(ct), lambda m: None) == IMG
    c = Compose()
    ns = _ns(c, _cloudtak_legacy_minio_image=lambda d: '', _cloudtak_docker=loaded)   # pruned: nothing cached
    ok, err = ns['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    assert ok, err                                                # not the "no MinIO image" refusal
    assert not (ct / '.minio-legacy-image.tar').exists()          # and the copy is dropped once the files moved


def test_2_no_saved_image_and_no_cached_image_is_still_a_clear_refusal(ct):
    c = Compose()
    ns = _ns(c, _cloudtak_legacy_minio_image=lambda d: '')       # no tar in the folder either
    ok, err = ns['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False, restart_on_fail=True)
    assert not ok and 'no MinIO image is cached' in err and c.calls == []     # nothing was stopped


# ── 3. disk space for the copy ───────────────────────────────────────────────────────

def test_3_a_copy_that_does_not_fit_stops_before_copying_and_starts_the_services(ct):
    c, log = Compose(minio_bytes=10 * GB), []
    ok, err = _ns(c, free=5 * GB)['_cloudtak_garage_converge'](str(ct), log.append, start=False,
                                                              restart_on_fail=True)
    assert not ok and 'not enough free disk space' in err
    assert not any('copy' in a for a in c.calls)
    assert c.calls[-1] == START and (ct / '.docker-store' / 'cloudtak').is_dir()
    text = '\n'.join(log)
    assert '10.0 GB' in text and '5.0 GB is free' in text and 'image prune' in text   # the warning names it


def test_3_files_already_in_garage_are_not_counted_again(ct):
    c = Compose(minio_bytes=10 * GB, garage_bytes=9 * GB)            # a retry after a partial copy
    ok, err = _ns(c, free=3 * GB)['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    assert ok, err


def test_3_the_margin_is_kept(ct):
    c = Compose(minio_bytes=4 * GB)
    ok, _ = _ns(c, free=4 * GB + GB // 2)['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    assert not ok                                                    # 4 GB + the 1 GB to spare does not fit
    c = Compose(minio_bytes=4 * GB)
    ok, _ = _ns(c, free=5 * GB + 1)['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    assert ok


def test_3_a_size_that_cannot_be_read_never_blocks(ct):
    class C(Compose):
        def run(self, d, args, timeout=600):
            if 'size' in args:
                self.calls.append(list(args))
                return 0, 'garbage'
            return super().run(d, args, timeout)
    ok, err = _ns(C(), free=1)['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    assert ok, err
    n = _load()
    assert n['_cloudtak_migrate_space_short'](None, 5) is None and n['_cloudtak_migrate_space_short'](5, None) is None
    assert n['_cloudtak_rclone_bytes']('x {"count":3,"bytes":123,"sizeless":0} y') == 123


# ── 4. the remote host runs our steps, not upstream's script ─────────────────────────

class _Ssh:
    def __init__(self, store=True, env=ENV):
        self.cmds, self.store, self.env = [], store, env

    def __call__(self, cfg, cmd, timeout=15):
        self.cmds.append(cmd)
        if cmd.startswith('test -d ~/CloudTAK/.docker-store'):
            return (self.store, '')
        if cmd == 'cat ~/CloudTAK/.env':
            return True, self.env
        return True, ''


def _remote(c, ssh, **over):
    ns = _load(_ssh_probe=ssh, _cloudtak_compose_at=c.at, _cloudtak_keep_legacy_image=lambda *a, **k: True,
               _cloudtak_fs_free_remote=lambda cfg, path: (1, 500 * GB), **over)
    return ns


def test_4_remote_move_copies_with_update_never_sync_and_archives_over_ssh():
    c, ssh, log = Compose(), _Ssh(), []
    ok, err = _remote(c, ssh)['_cloudtak_remote_garage_converge']({'host': 'h'}, log.append, legacy_image=IMG)
    assert ok, err
    flat = [' '.join(a) for a in c.calls]
    assert any('copy --update -v minio:cloudtak garage:cloudtak' in f for f in flat)
    assert any('check --one-way --size-only' in f for f in flat)
    assert not any('sync' in f for f in flat)
    assert not any('migrate-store' in cmd for cmd in ssh.cmds)
    assert any('mv .docker-store .docker-store-migrated-20261127_030000' in cmd for cmd in ssh.cmds)
    assert any("MINIO_LEGACY_IMAGE=" in cmd and IMG in cmd for cmd in ssh.cmds)


def test_4_remote_failure_starts_the_services_again_when_asked():
    c = Compose(fail_on='copy')
    ok, err = _remote(c, _Ssh())['_cloudtak_remote_garage_converge'](
        {'host': 'h'}, lambda m: None, legacy_image=IMG, restart_on_fail=True)
    assert not ok and c.calls[-1] == START
    c = Compose(fail_on='copy')
    ok, _ = _remote(c, _Ssh())['_cloudtak_remote_garage_converge']({'host': 'h'}, lambda m: None, legacy_image=IMG)
    assert not ok and START not in c.calls


def test_4_remote_without_minio_data_only_writes_secret_and_endpoint():
    c, ssh = Compose(), _Ssh(store=False)
    ok, _ = _remote(c, ssh)['_cloudtak_remote_garage_converge']({'host': 'h'}, lambda m: None)
    assert ok and c.calls == [] and 'GARAGE_RPC_SECRET' in ssh.cmds[0]


def test_4_nothing_in_the_remote_path_runs_upstreams_migrate_store():
    for fn in ('_cloudtak_remote_garage_sh', '_cloudtak_remote_garage_converge', 'run_cloudtak_deploy',
               'run_cloudtak_update', 'run_cloudtak_redeploy'):
        code = re.sub(r'#.*', '', _body(fn))
        code = re.sub(r'""".*?"""', '', code, flags=re.S)
        assert 'cloudtak.sh migrate-store' not in code, fn


# ── 5. a re-clone never deletes the store's data ─────────────────────────────────────

FAKE_GIT = """#!/bin/sh
for last; do :; done
echo "git $*" >> "$HOME/git.log"
case "$1" in
  clone) mkdir -p "$last" && echo 'services: {}' > "$last/docker-compose.yml" ;;
  init) mkdir -p .git ;;
  checkout) echo 'services: {}' > docker-compose.yml ;;
  -C) [ "$3" = rev-parse ] && [ ! -d "$2/.git" ] && exit 128 ;;
esac
exit 0
"""


def _run_prep(home, tag):
    # the shell builder is not in FUNCS (it needs shlex and CLOUDTAK_CUSTOM_COMPOSE)
    src = '\n\n'.join(ast.get_source_segment(APP, n) for n in TREE.body
                      if (isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_remote_reclone_sh')
                      or (isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in
                                                            ('CLOUDTAK_CUSTOM_COMPOSE', '_CT_REMOTE_HAS_DATA_SH')
                                                            for t in n.targets)))
    ns = {'shlex': shlex}
    exec(compile(src, 'app.py', 'exec'), ns)
    bin_ = home / 'bin'
    bin_.mkdir(exist_ok=True)
    (bin_ / 'git').write_text(FAKE_GIT)
    (bin_ / 'docker').write_text('#!/bin/sh\nexit 0\n')
    os.chmod(bin_ / 'git', 0o755)
    os.chmod(bin_ / 'docker', 0o755)
    return subprocess.run(['sh', '-c', ns['_cloudtak_remote_reclone_sh'](tag)], capture_output=True, text=True,
                          timeout=30, env={'HOME': str(home), 'PATH': f"{bin_}:{os.environ['PATH']}"})


@pytest.mark.parametrize('folder', ['.docker-garage', '.docker-store'])
@pytest.mark.parametrize('tag', ['v13.127.0', None])
def test_5_remote_broken_checkout_with_data_is_repaired_in_place(tmp_path, folder, tag):
    (tmp_path / 'CloudTAK' / folder).mkdir(parents=True)
    (tmp_path / 'CloudTAK' / folder / 'block').write_text('your files')
    (tmp_path / 'CloudTAK' / '.env').write_text('KEEP=1\n')
    r = _run_prep(tmp_path, tag)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / 'CloudTAK' / folder / 'block').read_text() == 'your files'      # never deleted
    assert (tmp_path / 'CloudTAK' / '.env').read_text() == 'KEEP=1\n'
    assert (tmp_path / 'CloudTAK' / 'docker-compose.yml').exists()
    log = (tmp_path / 'git.log').read_text()
    assert 'git clone' not in log and 'git init' in log


def test_5_remote_tree_without_data_is_still_re_cloned(tmp_path):
    (tmp_path / 'CloudTAK').mkdir()
    (tmp_path / 'CloudTAK' / 'junk').write_text('x')
    r = _run_prep(tmp_path, 'v13.127.0')
    assert r.returncode == 0, r.stderr
    assert 'git clone' in (tmp_path / 'git.log').read_text()
    assert not (tmp_path / 'CloudTAK' / 'junk').exists()


class _Sub:
    """A subprocess stand-in that records every command and answers `git rev-parse` with true."""
    TimeoutExpired = TimeoutError

    def __init__(self):
        self.cmds = []

    def run(self, cmd, *a, **k):
        self.cmds.append(cmd if isinstance(cmd, str) else ' '.join(cmd))
        return type('R', (), {'returncode': 0, 'stdout': 'true\n', 'stderr': ''})()


def test_5_local_deploy_with_no_compose_file_never_deletes_a_tree_holding_data(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    ct_dir = tmp_path / 'CloudTAK'
    (ct_dir / '.docker-garage').mkdir(parents=True)                      # data, and no docker-compose.yml
    sub = _Sub()
    ns, status = D._ns(dict(D.LOCAL), subprocess=sub,
                       _cloudtak_has_data=_load()['_cloudtak_has_data'],
                       _docker_probe=lambda: (0, 'Docker version 27'),
                       _ensure_docker_log_limits=lambda plog: None,
                       _cloudtak_git_prep=lambda d, plog: None,
                       _cloudtak_keep_aside=lambda d: None, _cloudtak_put_back=lambda *a: None)
    ns['run_cloudtak_deploy']()
    assert not any('rm -rf' in c for c in sub.cmds), sub.cmds
    assert (ct_dir / '.docker-garage').is_dir()
    text = '\n'.join(ns['cloudtak_deploy_log'])
    assert 'holds your data' in text and 'Nothing was deleted' in text
    assert status['error'] is True and status['running'] is False


def test_5_the_build_failure_advice_does_not_tell_the_customer_to_delete_the_data():
    src = _body('run_cloudtak_deploy')
    i = src.index('RECOVERY STEPS')
    block = src[i:i + 2500]
    assert '_held = _cloudtak_has_data(cloudtak_dir)' in block
    assert 'if not _held:' in block and 'Do NOT run `docker system prune -a --volumes`' in block


# ── 6. Deploy never puts the pin over a newer CloudTAK ───────────────────────────────

@pytest.mark.parametrize('have,tag,newer', [
    ('14.0.0', 'v13.127.0', True), ('13.130.1', 'v13.127.0', True), ('13.127.0', 'v13.127.0', False),
    ('13.100.0', 'v13.127.0', False), ('', 'v13.127.0', False), ('14.0.0', None, False),
    ('14.0.0-rc1', 'v13.127.0', True), ('x', 'y', False)])
def test_6_version_compare(have, tag, newer):
    assert _load()['_cloudtak_version_is_newer'](have, tag) is newer


def test_6_local_deploy_over_a_newer_box_ends_without_error_and_changes_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    (tmp_path / 'CloudTAK').mkdir()
    sub = _Sub()
    ns, status = D._ns(dict(D.LOCAL), subprocess=sub,
                       _get_cloudtak_target_release_tag=lambda use_cache=True: 'v13.127.0',
                       _cloudtak_running_version=lambda *a, **k: '14.0.0',
                       _cloudtak_version_is_newer=_load()['_cloudtak_version_is_newer'],
                       _docker_probe=lambda: (0, 'Docker version 27'),
                       _ensure_docker_log_limits=lambda plog: None)
    ns['run_cloudtak_deploy']()
    text = '\n'.join(ns['cloudtak_deploy_log'])
    assert 'CloudTAK 14.0.0 is newer than the version we test (v13.127.0). Nothing to do.' in text
    assert status['running'] is False and status['error'] is False
    assert not any('git' in c and ('checkout' in c or 'clone' in c) for c in sub.cmds)


def test_6_the_guard_runs_before_anything_is_checked_out():
    src = _body('run_cloudtak_deploy')
    local = src.index('_cloudtak_version_is_newer(_dv_now, release_tag)')
    assert local < src.index('if os.path.exists(cloudtak_dir):')
    remote = src.index('_cloudtak_version_is_newer(_rv_now, remote_release_tag)')
    assert remote < src.index('prep_cmd = _cloudtak_remote_reclone_sh(remote_release_tag)')
