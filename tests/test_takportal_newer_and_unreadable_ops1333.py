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
"""TAK Portal: Update never moves a newer box back, and an unreadable settings.json is never
rebuilt from our seeds (ops #1333, found by the stack audit, ops #1311).

Two data-safety holes, each red on dev before this change and green with it:

1. Update checked out the tested release even when the box ran a NEWER one (an admin's not-vetted
   install, or a box that ran main with Beta Mode on). TAK Portal 2.x keeps its data in Postgres, and
   the checkout does not revert it ("Portal data is not reverted"). Deploy already kept a newer
   release (_takportal_checkout_existing); Update did not.
2. _takportal_get_existing_settings() answered {} for a settings.json it could not read. The merge
   then built the file from our seeds alone and wrote it, the backup helper skips an empty read (so
   no copy existed), and the startup guardrail read {} as "everything missing" and pushed on every
   start. The reader now says WHAT it saw (ok / absent / unreadable / error); only positive evidence
   (a file whose content is not a JSON object, or Docker not answering) blocks a write.
"""
import ast
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tarfile
import threading
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

from test_takportal_release_version_gh214 import (  # noqa: E402,F401  (real-git fixtures are shared)
    _GIT_ENV, _git, _git_ns as _git_ns_base, portal, upstream)

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TPL = (ROOT / 'templates' / 'takportal.html').read_text(encoding='utf-8')
_FUNCS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}


def _src(name):
    return ast.get_source_segment(APP, _FUNCS[name])


def _consts(*names):
    out = []
    for n in TREE.body:
        if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', None) in names:
            out.append(ast.get_source_segment(APP, n))
        if isinstance(n, ast.ClassDef) and n.name in names:
            out.append(ast.get_source_segment(APP, n))
    return '\n'.join(out)


def _load(funcs, ns=None, consts=()):
    ns = {} if ns is None else ns
    for k, v in {'os': os, 'json': json, 'datetime': __import__('datetime').datetime,
                 'print': lambda *a, **k: None}.items():
        ns.setdefault(k, v)
    exec(compile(_consts(*consts), 'app.py', 'exec'), ns)
    exec(compile('\n\n'.join(_src(f) for f in funcs), 'app.py', 'exec'), ns)
    return ns


# ====================================================================== 1. Update never goes back

def _git_ns(tag):
    n = _git_ns_base(tag=tag)
    n['threading'] = threading
    n['_takportal_update_ctx'] = threading.local()
    n['_tpv'] = types.SimpleNamespace(TAG_RE=__import__('re').compile(r'\d+\.\d+\.\d+'))
    return n


def test_update_on_a_release_newer_than_the_tested_one_changes_nothing(portal):
    """Box on 2.0.15 (an admin installed it before it was vetted), tested release 2.0.14."""
    _git(portal, 'checkout', '-q', '--force', '2.0.15')
    (portal / '.env').write_text('WEB_UI_PORT=3000\nOPERATOR=1\n')
    head = _git(portal, 'rev-parse', 'HEAD')
    r = _git_ns('2.0.14')['_takportal_update_git'](str(portal), plog=lambda m: None)
    assert r['ok'] is False and r['kept_newer'] is True and r['rolled_back'] is False, r
    assert r['from_version'] == '2.0.15' and r['to_version'] == '2.0.15', r
    assert 'newer than 2.0.14' in r['error'] and 'Nothing was changed' in r['error']
    assert 'does not move TAK Portal back' in r['error']
    assert _git(portal, 'rev-parse', 'HEAD') == head, 'the checkout must not move'
    assert (portal / '.env').read_text() == 'WEB_UI_PORT=3000\nOPERATOR=1\n', 'the operator .env is kept'


def test_update_on_main_with_a_newer_package_version_changes_nothing(portal):
    """Beta Mode was on, then off: the box sits on an untagged main commit that says 2.0.16."""
    _git(portal, 'checkout', '-q', '--force', 'origin/main')
    (portal / 'package.json').write_text(json.dumps({'name': 'tak-portal', 'version': '2.0.16'}) + '\n')
    _git(portal, 'add', '-A')
    _git(portal, 'commit', '-q', '-m', 'main moves on')
    head = _git(portal, 'rev-parse', 'HEAD')
    r = _git_ns('2.0.14')['_takportal_update_git'](str(portal), plog=lambda m: None)
    assert r['ok'] is False and r['kept_newer'] is True and r['from_version'] == '2.0.16', r
    assert _git(portal, 'rev-parse', 'HEAD') == head


def test_update_still_moves_forward_and_a_same_version_box_still_checks_out_the_tag(portal):
    n = _git_ns('2.0.15')
    r = n['_takportal_update_git'](str(portal), plog=lambda m: None)           # 2.0.14 -> 2.0.15
    assert r['ok'] is True and r['to_version'] == '2.0.15' and not r.get('kept_newer'), r
    assert _git(portal, 'rev-parse', 'HEAD') == _git(portal, 'rev-parse', '2.0.15^{commit}')
    r = n['_takportal_update_git'](str(portal), plog=lambda m: None)           # already on it
    assert r['ok'] is True and not r.get('kept_newer'), r


def test_a_kept_newer_box_is_a_success_that_changed_nothing_not_a_failure():
    """_takportal_run_update must put the loopback port patch back, then answer unchanged: no build, no
    restart, no settings write, and not a 500 (a red 'failed' record would alarm for a box that is fine)."""
    calls = []
    out = {'ok': False, 'kept_newer': True, 'channel': 'stable', 'ref': '2.0.14', 'from_version': '2.0.15',
           'to_version': '2.0.15', 'rolled_back': False, 'message': 'kept', 'error': 'kept'}
    ns = _load(['_takportal_run_update'], {
        '_takportal_docker_stuck': lambda: '',
        '_mod_result_step': lambda *a, **k: None,
        '_mod_result_versions': lambda *a, **k: None,
        '_takportal_update_git': lambda d: dict(out),
        '_patch_takportal_compose_ports': lambda d: calls.append('patch'),
        '_takportal_web_running': lambda: True,
        'subprocess': types.SimpleNamespace(run=lambda *a, **k: calls.append('subprocess')),
        '_write_takportal_override': lambda: calls.append('override'),
        '_takportal_merged_settings_json': lambda s: calls.append('merge'),
    })
    body, code = ns['_takportal_run_update']('/home/x/TAK-Portal')
    assert code == 200 and body['success'] is True and body['unchanged'] is True, body
    assert body['version'] == '2.0.15' and body['rolled_back'] is False and 'kept' in body['pull']
    assert calls == ['patch'], calls


def test_the_page_shows_not_changed_and_never_offers_a_move_back():
    fn = TPL[TPL.index('function _portalUpdateShow(d){'):TPL.index('// ops #72: the update runs on the box')]
    assert 'd.unchanged' in fn and 'Not changed' in fn and '_portalUpdateDone()' in fn
    assert 'Back to' not in TPL and 'BACK to' not in TPL


# ====================================================================== 2. unreadable settings.json

PATH = '/usr/src/app/data/settings.json'
READ_CONSTS = ('_TAKPORTAL_SETTINGS_PATH', '_TAKPORTAL_SETTINGS_ABSENT_MARKERS',
               '_TAKPORTAL_SETTINGS_DOCKER_DOWN_MARKERS')


def _tar(text):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tf:
        data = text.encode()
        ti = tarfile.TarInfo('settings.json')
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class Docker:
    """`docker exec ... cat` and `docker cp ... -` answers for one settings.json situation."""

    def __init__(self, exec_out=None, cp_out=None, exec_rc=0, cp_rc=0, cp_err=b'', exec_raises=None,
                 cp_raises=None):
        self.exec_out, self.cp_out, self.exec_rc, self.cp_rc = exec_out, cp_out, exec_rc, cp_rc
        self.cp_err, self.exec_raises, self.cp_raises = cp_err, exec_raises, cp_raises
        self.calls = []

    def run(self, argv, **kw):
        self.calls.append(argv)
        if argv[1] == 'exec':
            if self.exec_raises:
                raise self.exec_raises
            return types.SimpleNamespace(returncode=self.exec_rc, stdout=self.exec_out or '', stderr='')
        if self.cp_raises:
            raise self.cp_raises
        return types.SimpleNamespace(returncode=self.cp_rc, stdout=self.cp_out or b'', stderr=self.cp_err)


def _reader(docker):
    return _load(['_takportal_read_settings_state', '_takportal_get_existing_settings'], {
        'subprocess': types.SimpleNamespace(run=docker.run), '_sudo_wrap': lambda a: a,
        '_takportal_ref': lambda: 'tak-portal', 'time': types.SimpleNamespace(sleep=lambda s: None),
    }, consts=READ_CONSTS)


GOOD = json.dumps({'TAK_URL': 'https://tak.example.com:8443/Marti', 'BETA_MODE': 'false'})


def test_a_readable_file_is_ok():
    n = _reader(Docker(exec_out=GOOD))
    state, data, raw = n['_takportal_read_settings_state']()
    assert state == 'ok' and data['TAK_URL'].startswith('https://tak.example.com')
    assert n['_takportal_get_existing_settings']() == data


@pytest.mark.parametrize('bad', ['{"TAK_URL": "https://tak.exa', '[1, 2, 3]', '"text"', 'null', '   \n', ''])
def test_a_file_that_is_not_a_json_object_is_unreadable_not_empty(bad):
    """Red on dev: there was no 'unreadable' answer, only {} (which the merge rebuilt from seeds)."""
    d = Docker(exec_out=bad, cp_out=_tar(bad))
    n = _reader(d)
    state, data, raw = n['_takportal_read_settings_state']()
    assert state == 'unreadable' and data == {} and raw == bad
    assert n['_takportal_get_existing_settings']() == {}, 'read-only callers still get {}'


def test_a_torn_read_is_retried_before_it_counts():
    """TAK Portal rewrites the file in place (GH #158): a half file, then the whole one, is fine."""
    reads = iter(['{"TAK_URL": "https://tak.example', GOOD])
    d = Docker()
    d.run = lambda argv, **kw: types.SimpleNamespace(returncode=0, stdout=next(reads), stderr='')
    state, data, _ = _reader(d)['_takportal_read_settings_state']()
    assert state == 'ok' and data['BETA_MODE'] == 'false'


def test_exec_fails_but_cp_reads_a_stopped_container():
    n = _reader(Docker(exec_rc=1, cp_out=_tar(GOOD)))
    assert n['_takportal_read_settings_state']()[0] == 'ok'


@pytest.mark.parametrize('err', [
    b'Could not find the file /usr/src/app/data/settings.json in container tak-portal',
    b'Error response from daemon: No such container: tak-portal',
    b'Error: No such object: tak-portal',
    b'Error response from daemon: lstat /var/lib/docker/x: no such file or directory',
])
def test_no_file_and_no_container_are_absent_so_a_fresh_install_still_seeds(err):
    n = _reader(Docker(exec_rc=1, cp_rc=1, cp_err=err))
    assert n['_takportal_read_settings_state']() == ('absent', {}, '')


def test_an_unknown_docker_failure_keeps_the_old_answer_absent():
    """Only positive evidence blocks a write, so an error text nobody foresaw never holds up a deploy."""
    n = _reader(Docker(exec_rc=1, cp_rc=1, cp_err=b'something new docker prints'))
    assert n['_takportal_read_settings_state']()[0] == 'absent'


@pytest.mark.parametrize('kw', [
    dict(exec_raises=subprocess.TimeoutExpired('docker', 10), cp_raises=subprocess.TimeoutExpired('docker', 15)),
    dict(exec_rc=1, cp_rc=1, cp_err=b'Cannot connect to the Docker daemon at unix:///var/run/docker.sock'),
    dict(exec_rc=1, cp_rc=1, cp_err=b'permission denied while trying to connect to the Docker daemon socket'),
])
def test_docker_not_answering_is_an_error_not_an_empty_file(kw):
    state, data, raw = _reader(Docker(**kw))['_takportal_read_settings_state']()
    assert state == 'error' and data == {} and raw == ''


# ---- the merge refuses to build from seeds ------------------------------------------------

MERGE_FUNCS = ['_takportal_template_placeholder_keys', '_takportal_with_required_prefixes',
               '_takportal_merged_settings_json', '_takportal_settings_unreadable_error',
               '_takportal_keep_unreadable_settings']
MERGE_CONSTS = ('TakPortalSettingsUnreadable', 'TAKPORTAL_DOMAIN_KEYS', 'TAKPORTAL_AUTH_ADOPT_KEYS',
                'TAKPORTAL_AUTHORITATIVE_KEYS', 'EMAIL_TRANSPORT_KEYS', 'TAKPORTAL_TEMPLATE_PLACEHOLDERS',
                'TAKPORTAL_TEMPLATE_TAK_CONNECTION', 'TAKPORTAL_REQUIRED_PREFIXES', 'TAKPORTAL_UNREADABLE_KEEP')


def _merge_ns(tmp_path, state, data=None, raw=''):
    return _load(MERGE_FUNCS, {
        '_takportal_read_settings_state': lambda: (state, dict(data or {}), raw),
        '_takportal_build_settings_dict': lambda s: {'AUTHENTIK_URL': 'http://ak:9000', 'AUTHENTIK_TOKEN': 'tok',
                                                     'USERS_HIDDEN_PREFIXES': 'akadmin,webadmin'},
        '_takportal_settings_value_is_blank': lambda v: v is None or (isinstance(v, str) and not v.strip()),
        'CONFIG_DIR': str(tmp_path),
    }, consts=MERGE_CONSTS)


@pytest.mark.parametrize('state', ['unreadable', 'error'])
def test_the_merge_writes_nothing_when_the_file_cannot_be_read(tmp_path, state):
    n = _merge_ns(tmp_path, state, raw='{"TAK_URL": "https://tak.exa')
    with pytest.raises(n['TakPortalSettingsUnreadable']) as e:
        n['_takportal_merged_settings_json']({})
    assert 'wrote nothing' in str(e.value)


def test_the_merge_keeps_a_private_copy_of_the_unreadable_file(tmp_path):
    raw = '{"TAK_URL": "https://tak.example.com", "P12_PASS": "operator-set", '        # cut off
    n = _merge_ns(tmp_path, 'unreadable', raw=raw)
    with pytest.raises(n['TakPortalSettingsUnreadable']) as e:
        n['_takportal_merged_settings_json']({})
    bdir = tmp_path / 'takportal-settings-backups'
    kept = sorted(os.listdir(bdir))
    assert len(kept) == 1 and kept[0].startswith('unreadable-') and str(bdir / kept[0]) in str(e.value)
    assert (bdir / kept[0]).read_text() == raw
    assert stat.S_IMODE(os.stat(bdir / kept[0]).st_mode) == 0o600 and stat.S_IMODE(os.stat(bdir).st_mode) == 0o700
    with pytest.raises(n['TakPortalSettingsUnreadable']):                                # again: no second copy
        n['_takportal_merged_settings_json']({})
    assert len(os.listdir(bdir)) == 1


def test_unreadable_copies_are_rotated(tmp_path):
    n = _merge_ns(tmp_path, 'unreadable')
    for i in range(9):
        assert n['_takportal_keep_unreadable_settings'](f'{{"x": {i}, ')
    kept = os.listdir(tmp_path / 'takportal-settings-backups')
    assert len(kept) == n['TAKPORTAL_UNREADABLE_KEEP'] == 5
    assert n['_takportal_keep_unreadable_settings']('   ') == '', 'nothing worth keeping, nothing written'


def test_the_merge_still_seeds_an_absent_file_and_keeps_operator_values_in_a_readable_one(tmp_path):
    fresh = json.loads(_merge_ns(tmp_path, 'absent')['_takportal_merged_settings_json']({}))
    assert fresh['AUTHENTIK_TOKEN'] == 'tok' and fresh['AUTHENTIK_URL'] == 'http://ak:9000'
    kept = json.loads(_merge_ns(tmp_path, 'ok', {'TAK_URL': 'https://mine', 'AUTHENTIK_TOKEN': 'old'})
                      ['_takportal_merged_settings_json']({}))
    assert kept['TAK_URL'] == 'https://mine' and kept['AUTHENTIK_TOKEN'] == 'tok'   # authoritative key
    assert not os.path.exists(tmp_path / 'takportal-settings-backups')


# ---- the callers ---------------------------------------------------------------------------

def test_a_settings_push_skips_an_unreadable_file_and_never_writes(tmp_path):
    writes, logs = [], []
    n = _merge_ns(tmp_path, 'unreadable', raw='{ not json')
    n.update({'_takportal_web_running': lambda: True, 'load_settings': lambda: {},
              '_takportal_write_settings_json': lambda j, plog=None: writes.append(j) or (True, ''),
              '_takportal_restart': lambda: writes.append('restart') or True})
    exec(compile(_src('_takportal_push_settings'), 'app.py', 'exec'), n)
    assert n['_takportal_push_settings'](plog=logs.append) is False
    assert writes == [] and any('skipped' in m and 'wrote nothing' in m for m in logs), (writes, logs)


def test_the_startup_guardrail_does_not_push_for_an_unreadable_file(tmp_path):
    pushes, logs = [], []
    n = _merge_ns(tmp_path, 'unreadable', raw='{ not json')
    n.update({'_takportal_web_running': lambda: True,
              '_takportal_get_existing_settings': lambda: {},
              '_takportal_push_settings': lambda plog=None: pushes.append(1) or True,
              'os': types.SimpleNamespace(path=types.SimpleNamespace(expanduser=lambda p: p, isdir=lambda p: True,
                                                                     join=os.path.join),
                                          makedirs=os.makedirs, listdir=os.listdir, open=os.open, fdopen=os.fdopen,
                                          remove=os.remove, O_WRONLY=os.O_WRONLY, O_CREAT=os.O_CREAT,
                                          O_EXCL=os.O_EXCL)})
    exec(compile(_src('_takportal_admin_guardrail'), 'app.py', 'exec'), n)
    n['_takportal_admin_guardrail'](plog_fn=logs.append)
    assert pushes == [] and any('guardrail skipped' in m for m in logs), (pushes, logs)


def test_ssh_set_user_does_not_write_a_one_key_file_over_an_unreadable_one(tmp_path):
    writes = []
    n = _merge_ns(tmp_path, 'unreadable', raw='{ not json')
    n.update({'jsonify': lambda d: d, 'request': None,
              '_takportal_write_settings_json': lambda j, plog=None: writes.append(j) or (True, ''),
              '_takportal_restart': lambda: True})
    exec(compile(_src('takportal_ssh_set_user'), 'app.py', 'exec'), n)
    body, code = n['takportal_ssh_set_user']()
    assert code == 500 and body['success'] is False and 'wrote nothing' in body['error'] and writes == []


def test_every_function_that_builds_the_settings_file_handles_an_unreadable_one():
    """A new caller of the merge that forgets this would turn an unreadable file into a 500 or a
    half-finished deploy. Same mechanical pin the other single-writer rules use."""
    def _calls_merge(f):
        return any(isinstance(c, ast.Call) and getattr(c.func, 'id', '') == '_takportal_merged_settings_json'
                   for c in ast.walk(f))
    callers = [n for n, f in _FUNCS.items() if n != '_takportal_merged_settings_json' and _calls_merge(f)]
    assert {'_takportal_push_settings', 'takportal_enable_auth_api', 'takportal_use_domain_api',
            'takportal_control', '_takportal_run_update', 'run_takportal_deploy'} <= set(callers), callers
    missing = [n for n in callers if 'TakPortalSettingsUnreadable' not in _src(n)]
    assert not missing, f'{missing} call the settings merge but do not handle TakPortalSettingsUnreadable'


def test_the_update_job_keeps_the_unreadable_message_whole():
    src = _src('_takportal_run_update')
    assert 'except TakPortalSettingsUnreadable as e:' in src
    assert src.index('except TakPortalSettingsUnreadable') < src.index('_pull_base_images(')


def test_only_the_reader_and_the_merge_read_the_state_for_a_write():
    """The sibling single-writer rule (CLAUDE.md: one writer per file): no second path builds a settings
    file from `_takportal_get_existing_settings()` alone, which cannot tell absent from unreadable."""
    for name in ('_takportal_merged_settings_json', '_takportal_admin_guardrail', 'takportal_ssh_set_user'):
        assert '_takportal_read_settings_state()' in _src(name), name
