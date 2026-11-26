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
"""An image pin never moves a box DOWN (ops #1307, same trap as ops #1306 / infra-TAK #759).

Update moved Authentik's redis from a floating tag that had pulled 8.12.0 onto the 8.10.3 pin, and
redis then could not read the newer data file. Two more places move a box onto a pin with no
direction check:

  * Node-RED (`_auto_nodered`, and the remote copy `_auto_nodered_image_remote`): every box
    "converges on NODERED_IMAGE", `:latest` included. Upstream `latest` is Node-RED 5.0.x on
    Node 24 today; the pin is 4.1.18-22.
  * WebODM (`_webodm_pin_images`, called by Update): every service goes to its pin, so a webapp
    newer than the pin is set back against a database the newer WebODM already migrated.

NetBird's pin-restore heal (`_heal_netbird_pinned_image`) goes down on purpose: it exists to pull a
box off a bad newer image (the 10.0.9 `:latest` incident), and the 0.83.2 -> 0.82.1 rollback on a
0.83-migrated store was drilled on Ubuntu, Rocky and ARM (ops #1088). A test below keeps it that way.

app.py cannot be imported in a test, so the code under test is cut out of it and run: it is the
shipped text. A helper that only the fix adds is looked up by name, so on the base branch the old
code runs and the test fails on what it returns, not on a NameError.
"""

import ast
import os
import pathlib
import re
import shutil
import subprocess
import textwrap
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_WANT = {
    '_IMAGE_EXACT_TAG_RE', '_image_ref_parts', '_image_exact_version', '_image_ahead_of_pin',
    '_docker_env_version', '_webodm_pin_images', '_webodm_strip_olefile', 'WEBODM_OLEFILE_STRIP',
    'WEBODM_VERSION', 'WEBODM_IMAGES', 'NODERED_IMAGE', '_NODERED_IMAGE_LINE_RE',
    '_nodered_remote_image_cmd',
}


def _ns(**extra):
    ns = {'re': re, 'subprocess': subprocess, 'os': os, '_sudo_wrap': lambda c: c}
    for node in TREE.body:
        names = ({t.id for t in node.targets if isinstance(t, ast.Name)} if isinstance(node, ast.Assign)
                 else {node.name} if isinstance(node, ast.FunctionDef) else set())
        if names & _WANT:
            exec(compile(ast.Module([node], []), 'app.py', 'exec'), ns)
    ns.update(extra)
    return ns


NS = _ns()


def _need(name):
    assert name in NS, f'{name} is missing from app.py'
    return NS[name]


PIN = NS['NODERED_IMAGE']
assert PIN == 'nodered/node-red:4.1.18-22', PIN


# ---------------------------------------------------------------------------------------------
# the direction rule itself
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize('current, pin, ran, expect', [
    # an exact tag newer than the pin: never moved back
    ('nodered/node-red:4.1.19-22', PIN, None, True),
    ('nodered/node-red:5.0.10-24', PIN, None, True),
    ('nodered/node-red:4.1.18-24', PIN, None, True),            # same Node-RED, newer Node build
    ('nodered/node-red:4.2.0-22-minimal', PIN, None, True),
    # equal or older: moved to the pin as before
    ('nodered/node-red:4.1.18-22', PIN, None, False),
    ('nodered/node-red:4.1.17-22', PIN, None, False),
    ('nodered/node-red:4.0.9', PIN, None, False),
    ('nodered/node-red:3.1.9', PIN, None, False),
    ('nodered/node-red:4.1.18-20', PIN, None, False),
    # floating tags: the compose cannot say, so the version Docker really ran decides
    ('nodered/node-red:latest', PIN, (5, 0, 10), True),
    ('nodered/node-red', PIN, (5, 0, 10), True),                 # no tag means latest
    ('nodered/node-red:4', PIN, (4, 1, 19), True),
    ('nodered/node-red:latest', PIN, (4, 1, 18), False),         # ran the pin's own version
    ('nodered/node-red:latest', PIN, (4, 0, 9), False),
    ('nodered/node-red:latest', PIN, None, False),               # unknown: the old behaviour
    ('nodered/node-red:4.1', PIN, None, False),
    # another image is the operator's, whatever its tag
    ('ghcr.io/x/node-red:9.0.0', PIN, (9, 0, 0), False),
    ('nodered/node-red-docker:9.0.0', PIN, None, False),
    # the redis broker, written the three ways compose files carry it
    ('redis:8.12.0-alpine', 'redis:8.10.3-alpine', None, True),
    ('docker.io/library/redis:8.12.0-alpine', 'redis:8.10.3-alpine', None, True),
    ('redis:8.10.3-alpine', 'redis:8.10.3-alpine', None, False),
    ('redis:7.0.10', 'redis:8.10.3-alpine', None, False),
    # WebODM
    ('webodm/webodm_webapp:4.1.0', 'webodm/webodm_webapp:4.0.1', None, True),
    ('webodm/webodm_webapp:4.0.1', 'webodm/webodm_webapp:4.0.1', None, False),
    ('webodm/webodm_webapp:3.5.4', 'webodm/webodm_webapp:4.0.1', None, False),
    ('webodm/webodm_webapp', 'webodm/webodm_webapp:4.0.1', (4, 1, 0), True),
    ('webodm/webodm_webapp', 'webodm/webodm_webapp:4.0.1', (4, 0, 1), False),
    # NetBird tags carry a leading v
    ('netbirdio/dashboard:v2.98.0', 'netbirdio/dashboard:v2.96.0', None, True),
    ('netbirdio/dashboard:v2.95.0', 'netbirdio/dashboard:v2.96.0', None, False),
])
def test_direction_rule(current, pin, ran, expect):
    ahead = _need('_image_ahead_of_pin')
    assert ahead(current, pin, (lambda: ran) if ran is not None else None) is expect


def test_running_version_is_asked_only_for_a_floating_tag_and_a_failure_is_not_a_veto():
    ahead = _need('_image_ahead_of_pin')
    calls = []

    def lookup():
        calls.append(1)
        return (9, 9, 9)
    assert ahead('nodered/node-red:4.1.17-22', PIN, lookup) is False   # exact tag: no lookup at all
    assert calls == []
    assert ahead('nodered/node-red:latest', PIN, lookup) is True
    assert calls == [1]

    def broken():
        raise RuntimeError('docker is down')
    assert ahead('nodered/node-red:latest', PIN, broken) is False      # unknown: old behaviour


def test_the_docker_template_prints_only_the_one_variable_asked_for():
    """A container's environment holds secrets (Node-RED's .env), so the template filters in
    Docker and nothing else reaches this process. Checked on the real Docker CLI (box test)."""
    formats = []

    def run(cmd, **kw):
        formats.append(cmd[cmd.index('--format') + 1])
        return types.SimpleNamespace(returncode=1, stdout='', stderr='')
    ns = _ns(subprocess=types.SimpleNamespace(run=run))
    ns['_docker_env_version']('nodered', env_name='NODE_RED_VERSION')
    assert formats and all('NODE_RED_VERSION' in f and 'split' in f for f in formats)
    assert not any(re.search(r'range \.Config\.Env\}\}\{\{println \.\}\}', f) for f in formats)
    # a name that is not a plain variable name is refused before any command runs
    formats.clear()
    assert ns['_docker_env_version']('nodered', env_name='X"}}{{.Config') is None and formats == []
    cmd = NS['_nodered_remote_image_cmd']() if '_nodered_remote_image_cmd' in NS else _remote_cmd()
    assert 'NODE_RED_VERSION' in cmd and 'split' in cmd
    assert not re.search(r'range \.Config\.Env\}\}\{\{println \.\}\}', cmd)


def test_docker_env_version_reads_the_container_then_the_image():
    seen = []

    def run(cmd, **kw):
        seen.append(cmd[-1])
        out = {'nodered': (0, 'PATH=/x\nNODE_RED_VERSION=5.0.10\nNODE_VERSION=24.1.0\n'),
               'nodered/node-red:latest': (0, 'NODE_RED_VERSION=4.1.1\n')}.get(cmd[-1], (1, ''))
        return types.SimpleNamespace(returncode=out[0], stdout=out[1], stderr='')
    ns = _ns(subprocess=types.SimpleNamespace(run=run))
    f = ns['_docker_env_version']
    assert f('nodered', 'nodered/node-red:latest', env_name='NODE_RED_VERSION') == (5, 0, 10)
    assert seen == ['nodered']                       # the container answered, the image is not asked
    seen.clear()
    assert f('gone', 'nodered/node-red:latest', env_name='NODE_RED_VERSION') == (4, 1, 1)
    assert seen == ['gone', 'nodered/node-red:latest']
    assert f('gone', 'nothing', env_name='NODE_RED_VERSION') is None
    assert f('nodered', env_name='REDIS_VERSION') is None   # the variable is not there


# ---------------------------------------------------------------------------------------------
# Node-RED, local: the image block of _auto_nodered, run as shipped
# ---------------------------------------------------------------------------------------------

def _nodered_image_block():
    i = APP.index('_nr_img_m = _NODERED_IMAGE_LINE_RE.search(content)')
    i = APP.rindex('\n', 0, i) + 1
    j = APP.index("if 'restart:' not in content and 'container_name: nodered' in content:", i)
    j = APP.rindex('\n', 0, j) + 1
    return textwrap.dedent(APP[i:j])


def _run_nodered_block(image, ran=None):
    content = f'services:\n  node-red:\n    image: {image}\n    container_name: nodered\n'
    out, asked = [], []

    def env_version(*targets, env_name):
        asked.append((targets, env_name))
        return ran
    ns = _ns(content=content, print=lambda *a, **k: out.append(' '.join(str(x) for x in a)),
             _docker_env_version=env_version)
    exec(compile(_nodered_image_block(), 'app.py', 'exec'), ns)
    return ns, out, asked


@pytest.mark.parametrize('image', ['nodered/node-red:4.1.19-22', 'nodered/node-red:5.0.10-24',
                                   'nodered/node-red:4.1.18-24'])
def test_update_keeps_a_node_red_that_is_newer_than_the_pin(image):
    ns, out, asked = _run_nodered_block(image)
    assert f'image: {image}\n' in ns['content']
    assert ns['_nr_img_changed'] is False            # no pull, no recreate for the image
    assert any('newer than the pin' in line for line in out), out
    assert asked == []                               # an exact tag needs no docker call


def test_update_keeps_a_floating_node_red_that_ran_5x():
    ns, out, asked = _run_nodered_block('nodered/node-red:latest', ran=(5, 0, 10))
    assert 'image: nodered/node-red:latest\n' in ns['content']
    assert ns['_nr_img_changed'] is False
    assert asked and asked[0][1] == 'NODE_RED_VERSION' and asked[0][0][0] == 'nodered'


@pytest.mark.parametrize('image, ran', [
    ('nodered/node-red:latest', (4, 1, 18)),
    ('nodered/node-red:latest', None),
    ('nodered/node-red:4.0', None),
    ('nodered/node-red:4.0.9', None),
    ('nodered/node-red:3.1.9', None),
    ('nodered/node-red:4.1.17-22', None),
])
def test_update_still_moves_an_older_or_unknown_node_red_onto_the_pin(image, ran):
    ns, out, _ = _run_nodered_block(image, ran=ran)
    assert f'image: {PIN}\n' in ns['content']
    assert ns['_nr_img_changed'] is True


# ---------------------------------------------------------------------------------------------
# Node-RED, remote: the shell command the post-update step sends, run in bash
# ---------------------------------------------------------------------------------------------

def _remote_cmd():
    i = APP.index('def _auto_nodered_image_remote():')
    i = APP.rindex('\n', 0, i) + 1
    j = APP.index('\n            _auto_authentik_ports()\n', i)
    block = textwrap.dedent(APP[i:j + 1])
    sent = []
    ns = _ns(print=lambda *a, **k: None, load_settings=lambda: {},
             _get_module_deployment_config=lambda s, k: {'target_mode': 'remote', 'remote': {'host': 'h'}},
             _module_run=lambda cfg, cmd, timeout=0: sent.append(cmd) or (True, ''))
    exec(compile(block, 'app.py', 'exec'), ns)
    ns['_auto_nodered_image_remote']()
    assert len(sent) == 1
    return sent[0]


def _gnu_sed():
    sed = shutil.which('sed')
    return bool(sed) and subprocess.run([sed, '--version'], capture_output=True).returncode == 0


def _run_remote(tmp_path, image, ran_version=None):
    """Run the remote command in bash with a throwaway HOME and a stub docker."""
    (tmp_path / 'node-red').mkdir()
    compose = tmp_path / 'node-red' / 'docker-compose.yml'
    compose.write_text(f'services:\n  node-red:\n    image: {image}\n    container_name: nodered\n')
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    env_lines = f'NODE_RED_VERSION={ran_version}' if ran_version else 'PATH=/usr/bin'
    (bindir / 'docker').write_text(
        '#!/bin/sh\n'
        f'echo "docker $*" >> {tmp_path}/docker.log\n'
        'if [ "$1" = inspect ]; then\n'
        f'  [ "{ran_version or ""}" = "" ] && [ "{1 if ran_version is None else 0}" = 1 ] && exit 1\n'
        f'  printf "%s\\n" "{env_lines}"\n'
        'fi\nexit 0\n')
    (bindir / 'docker').chmod(0o755)
    if not _gnu_sed():
        # the remote hosts run GNU sed (`sed -i -E ...`); give a Mac the same spelling
        (bindir / 'sed').write_text('#!/bin/sh\nif [ "$1" = -i ]; then shift; exec /usr/bin/sed -i "" "$@"; fi\n'
                                    'exec /usr/bin/sed "$@"\n')
        (bindir / 'sed').chmod(0o755)
    env = {'HOME': str(tmp_path), 'PATH': f'{bindir}:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin'}
    r = subprocess.run(['bash', '-c', _remote_cmd()], capture_output=True, text=True, env=env, timeout=60)
    log = (tmp_path / 'docker.log').read_text() if (tmp_path / 'docker.log').exists() else ''
    return r, compose.read_text(), log


@pytest.mark.parametrize('image', ['nodered/node-red:4.1.19-22', 'nodered/node-red:5.0.10-24',
                                   'nodered/node-red:4.1.18-24'])
def test_remote_update_keeps_an_exact_tag_newer_than_the_pin(tmp_path, image):
    r, compose, log = _run_remote(tmp_path, image)
    assert r.returncode == 0, r.stderr
    assert f'image: {image}\n' in compose
    assert 'compose' not in log                           # no pull, no recreate
    assert 'left alone' in r.stdout, r.stdout


def test_remote_update_keeps_a_floating_tag_whose_container_ran_5x(tmp_path):
    r, compose, log = _run_remote(tmp_path, 'nodered/node-red:latest', ran_version='5.0.10')
    assert r.returncode == 0, r.stderr
    assert 'image: nodered/node-red:latest\n' in compose
    assert 'compose' not in log
    assert 'left alone' in r.stdout, r.stdout


@pytest.mark.parametrize('image, ran', [
    ('nodered/node-red:4.0.9', None),
    ('nodered/node-red:4.1.17-22', None),
    ('nodered/node-red:latest', '4.1.18'),
    ('nodered/node-red:latest', None),
])
def test_remote_update_still_moves_an_older_or_unknown_node_red_onto_the_pin(tmp_path, image, ran):
    r, compose, log = _run_remote(tmp_path, image, ran_version=ran)
    assert r.returncode == 0, r.stderr
    assert f'image: {PIN}\n' in compose
    assert 'compose pull' in log and 'compose up -d' in log
    assert 'left alone' not in r.stdout


def test_remote_update_on_the_pin_is_a_no_op(tmp_path):
    r, compose, log = _run_remote(tmp_path, PIN)
    assert 'already on' in r.stdout and 'compose' not in log


# ---------------------------------------------------------------------------------------------
# WebODM
# ---------------------------------------------------------------------------------------------

def _compose(webapp='webodm/webodm_webapp', worker=None, db='webodm/webodm_db', broker='redis:7.0.10',
             nodeodm='webodm/nodeodx'):
    return (f'services:\n  wo_db:\n    image: {db}\n    container_name: wo_db\n'
            f'  wo_broker:\n    image: {broker}\n    container_name: wo_broker\n'
            f'  wo_webapp:\n    image: {webapp}\n    container_name: webapp\n'
            f'  wo_worker:\n    image: {worker or webapp}\n    container_name: wo_worker\n'
            f'  wo_nodeodm:\n    image: {nodeodm}\n    container_name: wo_nodeodm\n')


def _images(compose):
    return dict(re.findall(r'^  (\w+):\n(?:    [^\n]*\n)*?    image: ([^\n]*)$', compose, re.M))


def test_webodm_update_keeps_a_webapp_and_worker_newer_than_the_pin():
    pin = NS['_webodm_pin_images']
    out = _images(pin(_compose(webapp='webodm/webodm_webapp:4.1.0')))
    assert out['wo_webapp'] == out['wo_worker'] == 'webodm/webodm_webapp:4.1.0'
    # what is not tied to the migrated database still moves to its pin
    assert out['wo_broker'] == NS['WEBODM_IMAGES']['wo_broker']
    assert out['wo_nodeodm'] == NS['WEBODM_IMAGES']['wo_nodeodm']
    assert out['wo_db'] == NS['WEBODM_IMAGES']['wo_db']


def test_webodm_update_keeps_the_pair_together_when_only_one_of_them_is_ahead():
    pin = NS['_webodm_pin_images']
    out = _images(pin(_compose(webapp='webodm/webodm_webapp', worker='webodm/webodm_webapp:4.2.0')))
    assert out['wo_webapp'] == 'webodm/webodm_webapp'          # untouched, not half-moved
    assert out['wo_worker'] == 'webodm/webodm_webapp:4.2.0'


def test_webodm_update_keeps_a_newer_postgres_major():
    pin = NS['_webodm_pin_images']
    out = _images(pin(_compose(db='webodm/webodm_db:19')))
    assert out['wo_db'] == 'webodm/webodm_db:19'
    out = _images(pin(_compose(db='webodm/webodm_db:19@sha256:' + 'a' * 64)))
    assert out['wo_db'].startswith('webodm/webodm_db:19@')
    # the same major (the pin itself, or a floating tag) and an older one still go to the pin
    for same in ('webodm/webodm_db', 'webodm/webodm_db:18', 'webodm/webodm_db:latest'):
        assert _images(pin(_compose(db=same)))['wo_db'] == NS['WEBODM_IMAGES']['wo_db']


def test_webodm_update_reports_what_it_kept():
    pin = NS['_webodm_pin_images']
    kept = []
    pin(_compose(webapp='webodm/webodm_webapp:4.1.0', db='webodm/webodm_db:19'), kept=kept)
    assert kept == [('wo_db', 'webodm/webodm_db:19'), ('wo_webapp', 'webodm/webodm_webapp:4.1.0'),
                    ('wo_worker', 'webodm/webodm_webapp:4.1.0')]


def test_webodm_old_installs_still_converge_on_the_pins_and_it_is_idempotent():
    pin = NS['_webodm_pin_images']
    for old in ('webodm/webodm_webapp', 'webodm/webodm_webapp:latest', 'webodm/webodm_webapp:3.5.4',
                'webodm/webodm_webapp:4.0.0'):
        out = pin(_compose(webapp=old))
        assert _images(out) == NS['WEBODM_IMAGES'], old
        assert pin(out) == out


def test_webodm_startup_migration_still_moves_only_the_broker():
    pin = NS['_webodm_pin_images']
    got = _images(pin(_compose(webapp='webodm/webodm_webapp:4.1.0'), services=('wo_broker',)))
    assert got['wo_broker'] == NS['WEBODM_IMAGES']['wo_broker']
    assert got['wo_webapp'] == 'webodm/webodm_webapp:4.1.0' and got['wo_db'] == 'webodm/webodm_db'


def test_the_real_webodm_update_does_not_write_an_older_webapp_over_a_newer_one():
    """Run _run_webodm_update itself, with the box stubbed out, on a compose that runs WebODM 4.1.0."""
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_run_webodm_update')
    written, log = [], []
    compose = _compose(webapp='webodm/webodm_webapp:4.1.0', db='webodm/webodm_db:18',
                       broker='redis:8.10.3-alpine', nodeodm='webodm/nodeodx:2.4.0')
    status = {}
    ns = _ns(
        _webodm_update_status=status, _webodm_dir=lambda: '/home/takwerx/webodm',
        _read_priv=lambda p: compose, _write_priv=lambda p, c: written.append(c),
        _webodm_db_needs_upgrade=lambda d: False, _webodm_db_room_check=lambda plog: None,
        _webodm_compose=lambda d, a, timeout=0: types.SimpleNamespace(returncode=0, stdout='', stderr=''),
        WEBODM_PULL_TIMEOUT_S=1, WEBODM_UPGRADE_WAIT_S=1, time=types.SimpleNamespace(sleep=lambda s: None))
    exec(compile(ast.Module([node], []), 'app.py', 'exec'), ns)
    ns['_webodm_update_status'] = status
    ns['_run_webodm_update']()
    final = written[-1] if written else compose
    assert _images(final)['wo_webapp'] == 'webodm/webodm_webapp:4.1.0', status
    assert _images(final)['wo_worker'] == 'webodm/webodm_webapp:4.1.0'
    assert status.get('complete') is True, status


# ---------------------------------------------------------------------------------------------
# NetBird: the pin-restore heal goes down on purpose
# ---------------------------------------------------------------------------------------------

def test_netbird_heal_still_moves_a_newer_image_down_to_the_pin(tmp_path):
    """Rollback of 0.83.2 -> 0.82.1 on a 0.83-migrated store passed on Ubuntu, Rocky and ARM
    (ops #1088, rollback A = this heal). It also pulls a box off a bad newer image (10.0.9)."""
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_netbird_sync_compose_image_tags')
    compose = tmp_path / 'docker-compose.yml'
    compose.write_text('services:\n  netbird-server:\n    image: netbirdio/netbird-server:0.83.2\n'
                       '  dashboard:\n    image: netbirdio/dashboard:v2.98.0\n')
    ns = _ns(_get_netbird_target_images=lambda: ('netbirdio/netbird-server:0.82.1', 'netbirdio/dashboard:v2.96.0'),
             _write_priv=lambda p, c: pytest.fail('plain write expected'))
    exec(compile(ast.Module([node], []), 'app.py', 'exec'), ns)
    assert ns['_netbird_sync_compose_image_tags'](str(tmp_path)) is True
    txt = compose.read_text()
    assert 'netbird-server:0.82.1' in txt and 'dashboard:v2.96.0' in txt
