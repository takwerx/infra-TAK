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
"""TAK Portal down ~2 h after an auto-update: docker-stagger hung (GH #756).

Field report (10.4.7 -> 10.4.8, Ubuntu 22.04, root console): Docker restarted during the
post-update steps. docker-stagger.service had `Requires=docker.service`, so systemd ran it
again with Docker; it stopped Authentik and the TAK Portal worker, then hung on a
`docker stop tak-portal` dockerd never answered (Type=oneshot has no start timeout). Every
TAK Portal start, recreate and update waited behind it, and the TAK Portal Update ended with
a generic "Build timed out after 900s".

Now: the sequencer is boot-only (`Wants=`), bounded (`timeout` on the stop, TimeoutStartSec),
converged on every console update, and TAK Portal Update says Docker is stuck before it
changes anything.
"""

import ast
import base64
import importlib.util
import os
import pathlib
import re
import shlex
import subprocess
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_gh756', REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()


def _cut(*names):
    """The named top-level functions and assignments of app.py, as one module source."""
    body = [n for n in TREE.body
            if (isinstance(n, ast.FunctionDef) and n.name in names)
            or (isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets))]
    found = {n.name if isinstance(n, ast.FunctionDef) else n.targets[0].id for n in body}
    assert found == set(names), f'missing in app.py: {set(names) - found}'
    return compile(ast.Module(body=body, type_ignores=[]), 'app.py', 'exec')


UNIT_NAMES = ('_BOOT_STAGGER_STOP_TIMEOUT', '_BOOT_STAGGER_START_TIMEOUT', '_boot_stagger_unit_text')
CONTAINERS = ['authentik-postgresql-1', 'authentik-server-1', 'authentik-worker-1',
              'tak-portal-worker', 'tak-portal', 'tak-portal-postgres', 'cloudtak-api-1']
STEPS = ['echo "Starting Authentik DB..." && docker start authentik-postgresql-1', 'sleep 5',
         'echo "Starting TAK Portal..." && ((cd /root/TAK-Portal && docker compose up -d) '
         '|| docker start tak-portal-worker tak-portal tak-portal-postgres)',
         'echo "Starting CloudTAK..." && docker start cloudtak-api-1',
         'echo "All containers started"']


def _unit(**kw):
    ns = {}
    exec(_cut(*UNIT_NAMES), ns)
    return ns['_boot_stagger_unit_text'](CONTAINERS, STEPS, **kw)


def _keys(text):
    return [(s, k, v) for s, k, v in B._unit_lines(text)]


def _broker_write(text):
    return B._evaluate({'op': 'write', 'path': f'{B.UNIT_DIR}/docker-stagger.service', 'mode': 'w',
                        'content_b64': base64.b64encode(text.encode()).decode()})


# --- the unit ------------------------------------------------------------------------------

def test_a_docker_restart_does_not_rerun_the_sequencer():
    """Requires=/BindsTo=/PartOf= all carry a restart of docker.service over to this unit."""
    unit = _keys(_unit())
    deps = {(k, v) for s, k, v in unit if s == 'Unit'}
    assert ('Wants', 'docker.service') in deps and ('After', 'docker.service') in deps
    for k in ('Requires', 'BindsTo', 'PartOf'):
        assert not any(key == k and 'docker' in v for key, v in deps), (k, deps)


def test_the_sequencer_cannot_hang_for_ever():
    unit = _keys(_unit())
    svc = {k: v for s, k, v in unit if s == 'Service'}
    assert svc['Type'] == 'oneshot'
    assert svc['TimeoutStartSec'].isdigit() and 0 < int(svc['TimeoutStartSec']) <= 1800, svc
    toks = shlex.split(svc['ExecStart'])
    assert toks[:2] == ['/bin/bash', '-c']
    first = toks[2].split('&&')[0].strip()
    m = re.fullmatch(r'timeout ([0-9]+) docker stop ([^;]+) 2>/dev/null; true', ' '.join(first.split()))
    assert m, first
    assert m.group(2).split() == CONTAINERS
    assert int(m.group(1)) < int(svc['TimeoutStartSec']), 'the stop limit must end before systemd kills the unit'


def test_the_bounded_stop_is_still_ignored_when_it_fails():
    """`timeout` exits 124; the `; true` keeps the && chain going so the starts still run."""
    out = subprocess.run(['bash', '-c', 'timeout 1 sleep 5 2>/dev/null; true && echo started'],
                         capture_output=True, text=True, timeout=30)
    assert out.stdout.strip() == 'started'


def test_the_new_broker_allows_both_shapes_and_the_old_broker_allows_the_fallback():
    assert _broker_write(_unit())[0] == 'ALLOW', _broker_write(_unit())
    fallback = _unit(stop_timeout=0)
    assert _broker_write(fallback)[0] == 'ALLOW'
    assert 'timeout' not in fallback.split('docker stop')[0].split('ExecStart')[-1]
    # The stop-step rule of every broker before GH #756: the fallback must pass it, so the
    # Wants= and TimeoutStartSec part of the fix lands even before the broker is updated.
    old = re.compile(rf'docker stop( {B._CONTAINER_RE})+ 2>/dev/null; true')
    stop = ' '.join(shlex.split(dict((k, v) for s, k, v in _keys(fallback))['ExecStart'])[2]
                    .split('&&')[0].split())
    assert old.fullmatch(stop), stop
    assert all(k in B._UNIT_KEYS['Unit'] | B._UNIT_KEYS['Service'] | B._UNIT_KEYS['Install']
               for s, k, v in _keys(fallback))


def test_the_broker_still_refuses_extra_commands_around_timeout():
    for bad in ('timeout 99999 docker stop a 2>/dev/null; true',
                'timeout 5 docker stop a; id 2>/dev/null; true',
                'timeout -s KILL 5 docker stop a 2>/dev/null; true',
                'timeout 5 bash -c id 2>/dev/null; true'):
        text = _unit().replace(f'timeout 120 docker stop {" ".join(CONTAINERS)} 2>/dev/null; true', bad)
        assert bad in text
        assert _broker_write(text)[0] == 'DENY', bad


def _run_writer(write_priv, BrokerError=Exception):
    chains = []
    ns = {'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True, join=os.path.join)),
          'subprocess': types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(
              returncode=0, stdout='\n'.join(CONTAINERS))),
          '_sudo_wrap': lambda a: a, '_takportal_dir': lambda: '/root/TAK-Portal',
          '_takportal_project_containers': lambda all_states=True: [{'name': n} for n in CONTAINERS if 'portal' in n],
          '_write_priv': write_priv, 'BrokerError': BrokerError,
          '_run_priv_chain': lambda *a, **k: chains.append(a)}
    names = [n for n in UNIT_NAMES if re.search(rf'^(def )?{n}\b', APP, re.M)]
    exec(_cut(*names, '_update_boot_stagger_service'), ns)
    ns['_update_boot_stagger_service']()
    return chains


def test_the_unit_the_console_writes_is_boot_only_and_bounded():
    """Runs the real writer (red on the code before GH #756: Requires=, no timeout)."""
    writes = []
    chains = _run_writer(lambda path, text: writes.append((path, text)))
    assert chains and len(writes) == 1 and writes[0][0] == '/etc/systemd/system/docker-stagger.service'
    text = writes[0][1]
    assert 'Requires=docker.service' not in text and 'Wants=docker.service' in text
    assert re.search(r'^TimeoutStartSec=[0-9]+$', text, re.M)
    assert re.search(r"-c '\\\n  timeout [0-9]+ docker stop ", text), text
    assert _broker_write(text)[0] == 'ALLOW'


def test_update_boot_stagger_service_falls_back_when_the_broker_refuses():
    writes = []

    class BrokerError(Exception):
        pass

    def write_priv(path, text):
        writes.append(text)
        if len(writes) == 1:
            raise BrokerError('broker write denied: unit: docker-stagger step not allowed')

    chains = _run_writer(write_priv, BrokerError)
    assert len(writes) == 2 and chains, (writes, chains)
    assert 'timeout 120 docker stop' in writes[0]
    assert 'timeout 120' not in writes[1] and 'Wants=docker.service' in writes[1]
    assert 'TimeoutStartSec=' in writes[1] and 'Requires=' not in writes[1]


def test_every_console_update_converges_the_unit():
    i = APP.index('Post-update: boot sequencer (docker-stagger) converged')
    block = APP[i - 600:i]
    assert "os.path.exists('/etc/systemd/system/docker-stagger.service')" in block
    assert '_update_boot_stagger_service()' in block
    assert APP.index('Post-update: boot sequencer') < APP.index('Post-update: auto-deploying Guard Dog')


# --- TAK Portal Update says Docker is stuck --------------------------------------------------

def _stuck_ns(hang=()):
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        if argv[:2] == ['docker', 'inspect'] and argv[-1] in hang:
            raise subprocess.TimeoutExpired(argv, kw.get('timeout'))
        return types.SimpleNamespace(returncode=0, stdout='running', stderr='')

    ns = {'subprocess': types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired),
          '_sudo_wrap': lambda a: a,
          '_takportal_project_containers': lambda all_states=True: [
              {'id': 'c1', 'name': 'tak-portal-worker'}, {'id': 'c2', 'name': 'tak-portal'}]}
    exec(_cut('_TAKPORTAL_INSPECT_TIMEOUT', '_takportal_docker_stuck'), ns)
    return ns, calls


def test_a_container_dockerd_does_not_answer_for_is_named():
    ns, calls = _stuck_ns(hang=('c2',))
    assert ns['_takportal_docker_stuck']() == 'tak-portal'
    assert all(a[:2] == ['docker', 'inspect'] for a in calls)


def test_a_healthy_or_unreadable_docker_is_not_called_stuck():
    ns, _ = _stuck_ns()
    assert ns['_takportal_docker_stuck']() == ''
    ns['_takportal_project_containers'] = lambda all_states=True: (_ for _ in ()).throw(OSError('no docker'))
    assert ns['_takportal_docker_stuck']() == ''


def test_the_update_stops_before_it_changes_anything():
    job = APP[APP.index('# ops #72: TAK Portal Update as a background job'):APP.index("@app.route('/api/takportal/deploy'")]
    body = job[job.index('def _takportal_run_update(portal_dir):'):]
    i_stuck = body.index('_takportal_docker_stuck()')
    for later in ('_takportal_update_git(', '_write_takportal_override()', "'up', '-d', '--build'",
                  '_takportal_write_settings_json('):
        assert i_stuck < body.index(later), later
    ns = {'_records_module_update': lambda *a, **k: (lambda f: f), '_get_takportal_version_info': lambda: {},
          'os': os}
    src = job[job.index('_TAKPORTAL_BUILD_TIMEOUT = 900'):]
    src = src[:src.index("@app.route('/api/takportal/update/status')")] if "@app.route('/api/takportal/update/status')" in src else src
    tree = ast.parse(src)
    keep = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in (
        '_takportal_docker_stuck', '_takportal_run_update')) or (isinstance(n, ast.Assign) and getattr(
        n.targets[0], 'id', '') in ('_TAKPORTAL_INSPECT_TIMEOUT', '_TAKPORTAL_DOCKER_STUCK_MSG', '_TAKPORTAL_BUILD_TIMEOUT'))]
    exec(compile(ast.Module(body=keep, type_ignores=[]), 'app.py', 'exec'), ns)
    stuck, _ = _stuck_ns(hang=('c2',))
    git_calls = []
    ns.update({'subprocess': stuck['subprocess'], '_sudo_wrap': lambda a: a,
               '_takportal_project_containers': stuck['_takportal_project_containers'],
               '_takportal_update_git': lambda pd: git_calls.append(pd),
               '_mod_result_step': lambda *a: None})
    res, code = ns['_takportal_run_update']('/root/TAK-Portal')
    assert code == 500 and git_calls == []
    assert res['error'].startswith('Docker is stuck on the TAK Portal container tak-portal'), res
    assert 'restart docker' in res['error'].lower() and 'Nothing was changed' in res['error']
