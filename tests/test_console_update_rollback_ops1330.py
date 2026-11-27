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
"""Post-update stamp, Console Rollback, and "newer than the main channel" (ops #1330).

Five defects, each with a test that fails on dev 1ca8365 and passes with the fix:

1. The post-update run was stamped as done in a `finally`, so a run that raised was never run
   again (only a killed process re-ran it).
2. The Rollback ran three module steps (MediaMTX editor passwords, ATLAS identity headers, the
   remote HLS port) BEFORE the checkout, and threw the `git fetch` answer away: a checkout that
   failed left the console on the new version with those changes applied.
3. The Rollback said nothing about the pinned versions the older release puts back.
4. A dev box (untagged HEAD) recorded `v{VERSION}` as its rollback tag: a tag that does not exist
   or sits on another commit.
5. A dev box switched to main said "Up to date" while running code newer than main.

The route runs for real: the functions are lifted out of app.py by AST and run under a Flask test
client against a real git repository (a bare "origin", and the box's own checkout) so the order
of checkout and module steps, the fetch and the restore are what git really does.
"""

import ast
import copy
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys
import textwrap

import pytest

flask = pytest.importorskip('flask')
werkzeug_security = pytest.importorskip('werkzeug.security')

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], 'id', None) == name):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py (ops #1330 not applied)')


def _have(name):
    """Is `name` defined at module level in app.py? Lets the behaviour tests run on the code before
    ops #1330 too, so they fail there on what the code DOES, not on a missing name."""
    try:
        _src(name)
        return True
    except AssertionError:
        return False


def _ns(*names, **extra):
    g = {'re': re, 'os': os, 'json': json, 'subprocess': subprocess, 'time': __import__('time'),
         'datetime': datetime.datetime}
    g.update(extra)
    exec('\n\n'.join(_src(n) for n in names), g)
    return g


# --------------------------------------------------------------------------- #
# 1. The post-update stamp
# --------------------------------------------------------------------------- #

SHA_A = 'a' * 40
SHA_B = 'b' * 40


def _finish(s, ok, version='10.4.9-alpha', sha=SHA_A, error='boom'):
    g = _ns('_POST_UPDATE_MAX_FAILED_STARTS', '_post_update_finish_settings')
    return g['_post_update_finish_settings'](s, ok, version, sha, error)


def test_a_finished_run_is_stamped_and_clears_an_old_failure_note():
    s = {'last_console_version': '10.4.8-alpha',
         'post_update_failed': {'key': f'10.4.9-alpha@{SHA_A}', 'count': 2, 'error': 'x'}}
    stamped, msg = _finish(s, True)
    assert stamped is True
    assert s['last_console_version'] == '10.4.9-alpha' and s['last_console_sha'] == SHA_A
    assert 'post_update_failed' not in s
    assert msg.startswith('last_console_version saved as 10.4.9-alpha')


def test_a_run_that_raised_is_not_stamped_and_runs_again_at_the_next_start():
    s = {'last_console_version': '10.4.8-alpha', 'last_console_sha': SHA_B}
    stamped, msg = _finish(s, False, error='docker not up')
    assert stamped is False
    assert s['last_console_version'] == '10.4.8-alpha' and s['last_console_sha'] == SHA_B
    assert s['post_update_failed']['count'] == 1 and 'docker not up' in s['post_update_failed']['error']
    assert 'did NOT finish' in msg and 'again at the next console start' in msg


def test_three_failed_starts_in_a_row_give_up_and_stamp_so_boot_is_not_a_loop():
    s = {'last_console_version': '10.4.8-alpha'}
    results = [_finish(s, False)[0] for _ in range(3)]
    assert results == [False, False, True]
    assert s['last_console_version'] == '10.4.9-alpha' and s['post_update_failed']['count'] == 3
    stamped, msg = _finish(s, False)          # a fourth start, same commit
    assert stamped is True and 'Giving up' in msg and 'failed 4 starts in a row' in msg


def test_the_count_starts_again_for_another_commit():
    s = {}
    _finish(s, False, sha=SHA_A)
    _finish(s, False, sha=SHA_A)
    stamped, _ = _finish(s, False, sha=SHA_B)
    assert stamped is False and s['post_update_failed']['count'] == 1


def test_a_damaged_failure_note_does_not_break_the_stamp():
    for junk in ('x', 5, None, {'key': 'k', 'count': 'many'}):
        s = {'post_update_failed': junk}
        assert _finish(s, False)[0] is False
        assert s['post_update_failed']['count'] == 1


def _guarded(run_post_update, store, sha=SHA_A):
    """The real nested `_run_post_update_guarded`, with the post-update run itself replaced."""
    node = next(n for n in ast.walk(TREE)
                if isinstance(n, ast.FunctionDef) and n.name == '_run_post_update_guarded')
    src = textwrap.dedent(ast.get_source_segment(APP, node, padded=True))
    saved = {}

    def _save(s):
        store.clear()
        store.update(copy.deepcopy(s))
        saved['n'] = saved.get('n', 0) + 1

    g = _ns(*[n for n in ('_POST_UPDATE_MAX_FAILED_STARTS', '_post_update_finish_settings') if _have(n)])
    g.update({'_stack_job_running': lambda: False, '_POST_UPDATE_ACTIVE': {'on': True},
              '_run_post_update': run_post_update, 'VERSION': '10.4.9-alpha', 'cur_sha': sha,
              'lock_path': '/nonexistent/lock', 'load_settings': lambda: copy.deepcopy(store),
              'save_settings': _save})
    exec(src, g)
    g['_run_post_update_guarded']()
    return g


def test_real_guarded_runner_does_not_stamp_when_the_run_raises():
    store = {'last_console_version': '10.4.8-alpha'}

    def boom():
        raise RuntimeError('broker not ready')

    g = _guarded(boom, store)
    assert store['last_console_version'] == '10.4.8-alpha', 'a post-update that raised was stamped as done'
    assert store['post_update_failed']['count'] == 1
    assert g['_POST_UPDATE_ACTIVE']['on'] is False


def test_real_guarded_runner_stamps_when_the_run_returns():
    store = {'last_console_version': '10.4.8-alpha', 'post_update_failed': {'key': 'k', 'count': 2}}
    _guarded(lambda: None, store)
    assert store['last_console_version'] == '10.4.9-alpha' and store['last_console_sha'] == SHA_A
    assert 'post_update_failed' not in store


def test_real_guarded_runner_third_failure_in_a_row_stamps():
    store = {'last_console_version': '10.4.8-alpha'}

    def boom():
        raise RuntimeError('still broken')

    for _ in range(2):
        _guarded(boom, store)
        assert store['last_console_version'] == '10.4.8-alpha'
    _guarded(boom, store)
    assert store['last_console_version'] == '10.4.9-alpha'


# --------------------------------------------------------------------------- #
# A real git repository for the rollback
# --------------------------------------------------------------------------- #

OLD_APP = ('NODERED_IMAGE = "nodered/node-red:4.1.0"\n'
           'NETBIRD_SERVER_IMAGE = "netbirdio/netbird-server:0.82.1"\n'
           'NETBIRD_SERVER_DEV_IMAGE = "netbirdio/netbird-server:0.83.2"\n'
           'WEBODM_VERSION = \'4.0.1\'   # same in both\n'
           'MEDIAMTX_EDITOR_REF = "v2.1.14"\n')
NEW_APP = ('NODERED_IMAGE = "nodered/node-red:5.0.1"\n'
           'NETBIRD_SERVER_IMAGE = "netbirdio/netbird-server:0.83.2"\n'
           'NETBIRD_SERVER_DEV_IMAGE = "netbirdio/netbird-server:0.84.0"\n'
           'WEBODM_VERSION = \'4.0.1\'   # same in both\n'
           'MEDIAMTX_EDITOR_REF = "v2.1.17"\n')


def _git(cwd, *args, check=True):
    return subprocess.run(['git', '-c', 'user.email=t@example.invalid', '-c', 'user.name=t',
                           '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=dev'] + list(args),
                          cwd=cwd, check=check, capture_output=True, text=True)


def _head(cwd):
    return _git(cwd, 'rev-parse', 'HEAD').stdout.strip()


@pytest.fixture
def boxrepo(tmp_path):
    """origin.git (a bare repo that holds the tag), and box/ (the console's own checkout, on dev)."""
    src = tmp_path / 'src'
    src.mkdir()
    _git(src, 'init', '-q')
    (src / 'app.py').write_text(OLD_APP)
    _git(src, 'add', 'app.py')
    _git(src, 'commit', '-q', '-m', 'old release')
    _git(src, 'tag', '-a', 'v10.4.8-alpha', '-m', 'old')
    old = _head(src)
    (src / 'app.py').write_text(NEW_APP)
    _git(src, 'commit', '-q', '-a', '-m', 'new release')
    new = _head(src)
    origin = tmp_path / 'origin.git'
    _git(tmp_path, 'clone', '-q', '--bare', str(src), str(origin))
    box = tmp_path / 'box'
    _git(tmp_path, 'clone', '-q', str(origin), str(box))
    _git(box, 'checkout', '-q', 'dev')
    # The code before ops #1330 fetches from the public URL it has inline: send that to the local
    # origin, so no test ever touches the network.
    _git(box, 'config', f'url.{origin}.insteadOf', 'https://github.com/takwerx/infra-TAK.git')
    return {'box': box, 'origin': origin, 'old': old, 'new': new, 'tmp': tmp_path}


PASSWORD = 'right-pw'
PWHASH = werkzeug_security.generate_password_hash(PASSWORD, method='pbkdf2:sha256')

_ROUTE_FUNCS = ['verify_password', 'hash_password', '_hash_method_error', 'stored_hash_unusable',
                '_require_admin_password', '_rollback_git', '_rollback_resolve_target',
                '_rollback_current_ref', '_console_release_const', '_console_release_editor_ref',
                '_console_release_has_file', '_rollback_pin_short', '_rollback_pin_changes',
                '_rollback_pin_message', '_rollback_redis_hazard', '_rollback_redis_hazard_here',
                '_console_release_app_has', 'console_rollback_api', 'console_rollback_preview_api']
_ROUTE_ASSIGNS = ['PASSWORD_HASH_METHOD', '_HASH_METHOD_ERRORS', 'check_password_hash',
                  'generate_password_hash', '_ROLLBACK_REPO_URL', '_ROLLBACK_REF_RE',
                  '_ROLLBACK_SHA_RE', '_ROLLBACK_PIN_WATCH']


def _route(repo, record, editor='ok', channel='main', lacks_hashing=True, atlas_raises=False):
    """The Rollback routes against the real repo. `editor`: what the password step answers
    ('ok' reset, 'fail'). Returns the state dict (client, log, settings, restarts)."""
    log = []
    state = {'settings': {'console_rollback': record, 'update_channel': channel},
             'log': log, 'restarts': [], 'repo': repo}

    def _unhash(settings):
        log.append('editor-passwords')
        return {'state': 'fail', 'count': 0} if editor == 'fail' else {'state': 'reset', 'count': 2}

    def _atlas(ctx, say, reads_token):
        log.append('atlas')
        if atlas_raises:
            raise RuntimeError('atlas down')
        return {}

    def _hls(settings, console_dir, tag):
        log.append('hls-port')
        return 'none'

    g = {
        'jsonify': flask.jsonify, 'request': flask.request, 'os': os, 're': re,
        'subprocess': subprocess, '__file__': str(repo['box'] / 'app.py'),
        'hashlib': __import__('hashlib'),
        '_werkzeug_check_password_hash': werkzeug_security.check_password_hash,
        '_werkzeug_generate_password_hash': werkzeug_security.generate_password_hash,
        'load_auth': lambda: {'password_hash': PWHASH},
        'load_settings': lambda: state['settings'],
        'save_settings': lambda s: state.__setitem__('settings', s),
        '_detached_console_restart': lambda: state['restarts'].append(1),
        '_mediamtx_editor_ref_lacks_hashing': lambda r: lacks_hashing,
        '_mediamtx_editor_unhash_for_rollback': _unhash,
        '_mediamtx_remote_hls_port_before_rollback': _hls,
        'mod_registry': type('R', (), {
            'MODULES': {'atlas': {'before_console_rollback': _atlas}},
            'get_ctx': staticmethod(lambda: {})}),
        # what this console pins
        'NODERED_IMAGE': 'nodered/node-red:5.0.1',
        'NETBIRD_SERVER_IMAGE': 'netbirdio/netbird-server:0.83.2',
        'NETBIRD_SERVER_DEV_IMAGE': 'netbirdio/netbird-server:0.84.0',
        'WEBODM_VERSION': '4.0.1',
        'MEDIAMTX_EDITOR_REF': 'v2.1.17',
        'AUTHENTIK_REDIS_IMAGE': 'docker.io/library/redis:8.10.3-alpine',
        # what Docker says the redis ran (REDIS_VERSION); '' = not on this box
        '_authentik_redis_seen_version': lambda image: state.get('redis_seen', ''),
    }
    parts = [_src(n) for n in _ROUTE_FUNCS + _ROUTE_ASSIGNS if n not in g and _have(n)]
    exec('\n\n'.join(parts), g)
    g['_ROLLBACK_REPO_URL'] = str(repo['origin'])      # the code before ops #1330 has its own URL inline
    app = flask.Flask(__name__)
    app.add_url_rule('/api/console/rollback', view_func=g['console_rollback_api'], methods=['POST'])
    if 'console_rollback_preview_api' in g:
        app.add_url_rule('/api/console/rollback/preview', view_func=g['console_rollback_preview_api'])
    state['client'] = app.test_client()
    state['g'] = g
    return state


def _post(state):
    return state['client'].post('/api/console/rollback', json={'password': PASSWORD})


def _on_new_release(repo):
    """The box has just been updated: its checkout is on the new release."""
    _git(repo['box'], 'checkout', '-q', 'dev')
    assert _head(repo['box']) == repo['new']


# --------------------------------------------------------------------------- #
# 2. The rollback: checkout first, steps after, nothing changed when it cannot go
# --------------------------------------------------------------------------- #


def test_checkout_comes_before_the_module_steps(boxrepo):
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'})
    r = _post(st)
    assert r.status_code == 200, r.get_json()
    assert _head(boxrepo['box']) == boxrepo['old']                 # the older release is checked out
    assert st['log'] == ['editor-passwords', 'atlas', 'hls-port']   # all three ran, after it
    assert st['restarts'] == [1]
    assert st['settings']['console_rollback'] == {'available': False}


def test_a_failed_checkout_leaves_the_three_module_steps_alone(boxrepo):
    # git cannot take its lock: the checkout fails. Before the fix the editor passwords, ATLAS and
    # the HLS port had already been changed, and the console stayed on the new version.
    (boxrepo['box'] / '.git' / 'index.lock').write_text('')
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'})
    r = _post(st)
    assert r.status_code == 500 and r.get_json()['ok'] is False
    assert st['log'] == [], f"module steps ran although the checkout failed: {st['log']}"
    assert st['restarts'] == []
    assert st['settings']['console_rollback']['available'] is True      # can be tried again
    assert _head(boxrepo['box']) == boxrepo['new']


def test_a_tag_that_is_nowhere_stops_with_nothing_changed(boxrepo):
    st = _route(boxrepo, {'available': True, 'tag': 'v99.0.0-alpha'})
    r = _post(st)
    d = r.get_json()
    assert r.status_code == 500 and d['ok'] is False
    assert 'v99.0.0-alpha' in d['error'] and 'Nothing was changed' in d['error']
    assert st['log'] == [] and st['restarts'] == []
    assert _head(boxrepo['box']) == boxrepo['new']
    assert st['settings']['console_rollback']['available'] is True


def test_no_network_but_the_tag_is_already_here_still_rolls_back(boxrepo):
    # The fetch fails (origin gone) and the tag is on the box: that is enough.
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'})
    st['g']['_ROLLBACK_REPO_URL'] = str(boxrepo['tmp'] / 'no-such-origin.git')
    r = _post(st)
    assert r.status_code == 200, r.get_json()
    assert _head(boxrepo['box']) == boxrepo['old']


def test_tag_only_on_origin_is_fetched(boxrepo):
    _git(boxrepo['box'], 'tag', '-d', 'v10.4.8-alpha')
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'})
    r = _post(st)
    assert r.status_code == 200, r.get_json()
    assert _head(boxrepo['box']) == boxrepo['old']


def test_a_failed_editor_reset_puts_the_checkout_back(boxrepo):
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'}, editor='fail')
    r = _post(st)
    d = r.get_json()
    assert r.status_code == 500 and d['ok'] is False and 'Nothing was changed' in d['error']
    assert st['log'] == ['editor-passwords']               # ATLAS and the HLS port were not touched
    assert _head(boxrepo['box']) == boxrepo['new']          # back where it was
    assert _git(boxrepo['box'], 'symbolic-ref', '--short', 'HEAD').stdout.strip() == 'dev'
    assert st['restarts'] == []
    assert st['settings']['console_rollback']['available'] is True


def test_a_release_whose_editor_reads_hashes_never_touches_the_passwords(boxrepo):
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'}, lacks_hashing=False)
    assert _post(st).status_code == 200
    assert 'editor-passwords' not in st['log']


def test_a_module_step_that_raises_does_not_stop_the_rollback(boxrepo):
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'}, atlas_raises=True)
    r = _post(st)
    assert r.status_code == 200 and _head(boxrepo['box']) == boxrepo['old']
    assert st['log'] == ['editor-passwords', 'atlas', 'hls-port']


def test_the_password_gate_still_comes_first(boxrepo):
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'})
    r = st['client'].post('/api/console/rollback', json={'password': 'wrong'})
    assert r.status_code == 403 and st['log'] == [] and _head(boxrepo['box']) == boxrepo['new']


# --------------------------------------------------------------------------- #
# 4. The rollback record: the commit, and a tag only when there is one
# --------------------------------------------------------------------------- #


def test_untagged_dev_commit_rolls_back_by_commit_not_by_a_guessed_tag(boxrepo):
    # A dev box: the previous HEAD is an untagged commit and no `v10.4.9-alpha` exists.
    box = boxrepo['box']
    (box / 'app.py').write_text(NEW_APP + '# dev iteration\n')
    _git(box, 'commit', '-q', '-a', '-m', 'dev iteration')
    ran = _head(box)
    _git(box, 'checkout', '-q', '--detach', boxrepo['new'])      # the box moved on
    st = _route(boxrepo, {'available': True, 'tag': '', 'sha': ran, 'label': '10.4.9-alpha (x)'})
    r = _post(st)
    assert r.status_code == 200, r.get_json()
    assert _head(box) == ran
    assert '10.4.9-alpha (x)' in r.get_json()['message']


def test_an_old_record_with_a_guessed_tag_that_does_not_exist_is_refused_cleanly(boxrepo):
    # What dev wrote for an untagged HEAD: tag `v10.4.9-alpha`, no commit, no such tag anywhere.
    st = _route(boxrepo, {'available': True, 'version': '10.4.9-alpha', 'tag': 'v10.4.9-alpha'})
    r = _post(st)
    assert r.status_code == 500 and 'Nothing was changed' in r.get_json()['error']
    assert st['log'] == [] and _head(boxrepo['box']) == boxrepo['new']


def test_when_the_tag_moved_the_commit_that_ran_wins(boxrepo):
    box = boxrepo['box']
    _git(box, 'checkout', '-q', '--detach', boxrepo['old'])
    # The tag points to `old`, but the record says `new` is what ran: go to what ran.
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha', 'sha': boxrepo['new']})
    r = _post(st)
    assert r.status_code == 200
    assert _head(box) == boxrepo['new']


def test_a_stored_value_that_looks_like_a_git_option_never_reaches_git(boxrepo):
    for bad_tag, bad_sha in (('--force', ''), ('-d', 'zz'), ('a b', 'not-a-sha'), ('', '')):
        st = _route(boxrepo, {'available': True, 'tag': bad_tag, 'sha': bad_sha})
        r = _post(st)
        assert r.status_code == 400 and st['log'] == []
        assert _head(boxrepo['box']) == boxrepo['new']


def test_snapshot_records_the_commit_and_a_tag_only_when_head_is_on_one(boxrepo):
    g = _ns('_ROLLBACK_SHA_RE', '_update_rollback_snapshot', '_console_rollback_snapshot')
    snap = g['_console_rollback_snapshot']
    box = boxrepo['box']
    _git(box, 'checkout', '-q', '--detach', 'v10.4.8-alpha')
    rec = snap(str(box), '10.4.8-alpha')
    assert rec['available'] is True and rec['tag'] == 'v10.4.8-alpha' and rec['sha'] == boxrepo['old']
    assert rec['label'] == 'v10.4.8-alpha'
    _git(box, 'checkout', '-q', 'dev')                           # an untagged commit
    rec = snap(str(box), '10.4.9-alpha')
    assert rec['tag'] == '', 'an untagged HEAD must not record a guessed tag'
    assert rec['sha'] == boxrepo['new'] and rec['label'] == f"10.4.9-alpha ({boxrepo['new'][:7]})"


def test_snapshot_without_git_keeps_the_old_guess_rather_than_no_rollback(tmp_path):
    g = _ns('_ROLLBACK_SHA_RE', '_update_rollback_snapshot', '_console_rollback_snapshot')
    rec = g['_console_rollback_snapshot'](str(tmp_path), '10.4.9-alpha')
    assert rec['tag'] == 'v10.4.9-alpha' and rec['sha'] == ''


def test_update_now_uses_the_snapshot_helper():
    src = _src('update_apply')
    assert "_console_rollback_snapshot(" in src and "console_dir, VERSION, _s.get('console_rollback')" in src
    assert "f'v{VERSION}'" not in src            # the guessed tag is gone from Update Now


# --------------------------------------------------------------------------- #
# 3. Which pinned versions the older release puts back, in plain words
# --------------------------------------------------------------------------- #


def test_preview_lists_the_pins_the_older_release_sets_back(boxrepo):
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'}, channel='main')
    d = st['client'].get('/api/console/rollback/preview').get_json()
    names = {c['name']: c for c in d['changes']}
    assert names['Node-RED'] == {'name': 'Node-RED', 'now': '5.0.1', 'then': '4.1.0'}
    assert names['NetBird server'] == {'name': 'NetBird server', 'now': '0.83.2', 'then': '0.82.1'}
    assert 'WebODM' not in names                                  # same in both: not listed
    assert 'MediaMTX web editor' in names
    assert 'Node-RED 4.1.0 (this version 5.0.1)' in d['message']
    assert d['message'].startswith('v10.4.8-alpha runs its own start-up checks')


def test_preview_lists_only_the_netbird_pin_of_the_box_channel(boxrepo):
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'}, channel='dev')
    d = st['client'].get('/api/console/rollback/preview').get_json()
    nb = [c for c in d['changes'] if c['name'] == 'NetBird server']
    assert nb == [{'name': 'NetBird server', 'now': '0.84.0', 'then': '0.83.2'}]


def test_preview_with_no_rollback_is_empty_and_never_fails(boxrepo):
    st = _route(boxrepo, {'available': False})
    d = st['client'].get('/api/console/rollback/preview').get_json()
    assert d == {'ok': True, 'available': False, 'changes': [], 'message': ''}
    st = _route(boxrepo, {'available': True, 'tag': 'v1-nothing-here'})
    d = st['client'].get('/api/console/rollback/preview').get_json()
    assert d['ok'] is True and d['changes'] == [] and d['message'] == ''


def test_the_rollback_answer_says_the_pins_in_plain_words(boxrepo):
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'})
    d = _post(st).get_json()
    assert 'Node-RED 4.1.0 (this version 5.0.1)' in d['message']
    assert 'NetBird server 0.82.1 (this version 0.83.2)' in d['message']
    assert '<' not in d['message']                                # the console page shows it as HTML


def test_the_pin_reader_reads_git_not_the_checkout(boxrepo):
    g = _ns('_ROLLBACK_REF_RE', '_rollback_git', '_console_release_const')
    box = str(boxrepo['box'])
    assert g['_console_release_const'](box, boxrepo['old'], 'NODERED_IMAGE') == 'nodered/node-red:4.1.0'
    assert g['_console_release_const'](box, boxrepo['new'], 'NODERED_IMAGE') == 'nodered/node-red:5.0.1'
    assert g['_console_release_const'](box, boxrepo['old'], 'WEBODM_VERSION') == '4.0.1'   # trailing comment
    assert g['_console_release_const'](box, boxrepo['old'], 'NO_SUCH_THING') == ''
    for bad in ('--help', '', None, 'a b', 'x;y'):
        assert g['_console_release_const'](box, bad, 'NODERED_IMAGE') == ''
    assert g['_console_release_const'](box, boxrepo['old'], 'nodered_image') == ''          # not a constant name


# --------------------------------------------------------------------------- #
# 5. A box that runs newer code than the main channel says so
# --------------------------------------------------------------------------- #


def _ahead(latest, running='10.4.9-alpha'):
    g = _ns('_release_version_tuple', '_console_ahead_of_main_message', VERSION=running)
    return g['_console_ahead_of_main_message'](latest)


def test_a_dev_box_newer_than_main_is_told_so_in_plain_words():
    msg = _ahead('10.4.8-alpha')
    assert '10.4.9-alpha' in msg and '10.4.8-alpha' in msg and 'newer than the newest main release' in msg
    assert 'NetBird' in msg and 'dev channel' in msg


@pytest.mark.parametrize('latest', ['10.4.9-alpha', '10.4.10-alpha', '10.5.0-alpha', '11.0.0', None, '',
                                    'dev@abc1234', 'garbage'])
def test_no_message_when_main_is_the_same_or_newer_or_unknown(latest):
    assert _ahead(latest) == ''


def test_v_prefix_and_beta_suffix_are_handled():
    assert _ahead('v10.4.8-alpha') != '' and _ahead('v10.4.8-beta') != ''


def _update_response(data, running='10.4.9-alpha'):
    g = _ns('_release_version_tuple', '_console_ahead_of_main_message', '_update_check_response',
            VERSION=running, jsonify=flask.jsonify)
    app = flask.Flask(__name__)
    with app.test_request_context():
        return g['_update_check_response'](data).get_json()


def test_the_update_answer_on_main_carries_the_message():
    d = _update_response({'current': '10.4.9-alpha', 'latest': '10.4.8-alpha', 'channel': 'main',
                          'update_available': False})
    assert d['ahead_of_channel'] is True and 'newer than the newest main release' in d['ahead_message']
    assert d['update_available'] is False and d['latest'] == '10.4.8-alpha'      # nothing else changed


def test_the_update_answer_stays_as_it_was_when_it_does_not_apply():
    plain = {'current': '10.4.9-alpha', 'latest': '10.5.0-alpha', 'channel': 'main', 'update_available': True}
    assert _update_response(plain) == plain
    dev = {'current': '10.4.9-alpha', 'latest': 'dev@abc1234', 'channel': 'dev', 'update_available': False}
    assert _update_response(dev) == dev
    failed = {'current': '10.4.9-alpha', 'latest': None, 'channel': 'main', 'check_failed': True,
              'update_available': False}
    assert _update_response(failed) == failed


def test_the_console_page_shows_the_note_and_the_rollback_notice():
    html = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')
    assert 'id="ahead-note"' in html and 'd.ahead_message' in html
    assert "/api/console/rollback/preview" in html
    gd = (REPO / 'templates' / 'guarddog.html').read_text(encoding='utf-8')
    assert "console_rollback', {}).get('label')" in gd


# --------------------------------------------------------------------------- #
# 3b. A rollback to a release that pins a floating redis back (the ops #1306 loop)
# --------------------------------------------------------------------------- #

PIN = 'docker.io/library/redis:8.10.3-alpine'


def _hazard(ref_has_guard, image, seen, label='Version v10.4.8-alpha'):
    g = _ns('_rollback_redis_hazard', AUTHENTIK_REDIS_IMAGE=PIN,
            _console_release_app_has=lambda d, r, needle: ref_has_guard)
    return g['_rollback_redis_hazard']('/x', 'ref', label, image, seen)


@pytest.mark.parametrize('image', ['redis:alpine', 'docker.io/library/redis:alpine', 'redis', 'redis:latest',
                                   'redis:8', 'redis:8.10', 'redis:8-alpine'])
def test_floating_redis_that_ran_newer_warns_when_the_older_release_has_no_guard(image):
    msg = _hazard(False, image, '8.12.0')
    assert 'runs 8.12.0' in msg and 'Version v10.4.8-alpha sets a floating redis back to 8.10.3-alpine' in msg
    assert 'Update Now' in msg and '<' not in msg


@pytest.mark.parametrize('case', [
    (True, 'redis:alpine', '8.12.0'),            # that release looks at the version first
    (None, 'redis:alpine', '8.12.0'),            # git cannot say: no guess
    (False, 'redis:8.12.0-alpine', '8.12.0'),    # an exact version: the older release leaves it alone
    (False, 'valkey/valkey:8', '8.12.0'),        # another image
    (False, 'redis:alpine', '8.10.3'),           # no newer than the pin
    (False, 'redis:alpine', '8.9.0'),
    (False, 'redis:alpine', ''),                 # Docker could not say
    (False, '', '8.12.0'),                       # no redis service
])
def test_no_redis_warning_when_there_is_nothing_to_break(case):
    assert _hazard(*case) == ''


def test_preview_and_answer_carry_the_redis_warning(boxrepo, tmp_path, monkeypatch):
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    (home / 'authentik' / 'docker-compose.yml').write_text(
        'services:\n  redis:\n    image: redis:alpine\n    restart: unless-stopped\n')
    monkeypatch.setenv('HOME', str(home))
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'})
    st['redis_seen'] = '8.12.0'
    d = st['client'].get('/api/console/rollback/preview').get_json()
    assert len(d['hazards']) == 1 and 'floating redis back to 8.10.3-alpine' in d['message']
    r = _post(st)
    assert r.status_code == 200
    assert 'floating redis back to 8.10.3-alpine' in r.get_json()['message']
    # No Authentik compose on the box: nothing to warn about, and the rollback is unchanged.
    monkeypatch.setenv('HOME', str(tmp_path / 'nohome'))
    _on_new_release(boxrepo)
    st = _route(boxrepo, {'available': True, 'tag': 'v10.4.8-alpha'})
    st['redis_seen'] = '8.12.0'
    assert st['client'].get('/api/console/rollback/preview').get_json()['hazards'] == []
