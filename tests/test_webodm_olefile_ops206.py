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
"""Security update for WebODM (ops #206): webapp/worker drop the unused olefile package.

The webapp image is pulled from upstream, so the removal lives in the compose entrypoints and
runs on every container start. Fresh deploys write it; existing installs get it on a console
restart (startup migration) and on Update.
"""

import ast
import pathlib
import re
import shlex
import subprocess
import textwrap
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

# The webapp/worker blocks as every install before ops #206 was deployed (test6/test8/test12).
LEGACY = '''services:
  wo_db:
    image: webodm/webodm_db
    container_name: wo_db
  wo_broker:
    image: redis:8.10.2-alpine
    container_name: wo_broker
  wo_webapp:
    image: webodm/webodm_webapp:3.3.1
    container_name: webapp
    entrypoint: /bin/bash -c "service cron start && chmod +x /webodm/*.sh && /bin/bash -c \\"/webodm/wait-for-postgres.sh wo_db /webodm/wait-for-it.sh -t 0 wo_broker:6379 -- /webodm/start.sh\\""
    environment:
      - WO_BROKER=redis://wo_broker
  wo_worker:
    image: webodm/webodm_webapp:3.3.1
    container_name: wo_worker
    entrypoint: /bin/bash -c "/webodm/wait-for-postgres.sh wo_db /webodm/wait-for-it.sh -t 0 wo_broker:6379 -- /webodm/worker.sh start"
  wo_nodeodm:
    image: webodm/nodeodx:2.4.0
    container_name: wo_nodeodm
'''


def _ns():
    want = {'WEBODM_VERSION', 'WEBODM_IMAGES', 'WEBODM_DOCKER_COMPOSE', '_webodm_pin_images',
            'WEBODM_OLEFILE_STRIP', '_webodm_strip_olefile'}
    ns = {'re': re}
    for node in TREE.body:
        names = ({t.id for t in node.targets if isinstance(t, ast.Name)} if isinstance(node, ast.Assign)
                 else {node.name} if isinstance(node, ast.FunctionDef) else set())
        if names & want:
            exec(compile(ast.Module([node], []), 'app.py', 'exec'), ns)
    return ns


def _render(ns):
    return ns['WEBODM_DOCKER_COMPOSE'].format(
        wo_dir='/home/takwerx/webodm', wo_port=8765, wo_secret='x', wo_odm_cpus=2, wo_odm_mem=4,
        images=ns['WEBODM_IMAGES'])


def _entrypoints(compose):
    return dict(re.findall(r'^  (\w+):\n(?:    [^\n]*\n)*?    entrypoint: ([^\n]*)$', compose, re.M))


def test_fresh_deploy_strips_olefile_first_in_webapp_and_worker_only():
    ns = _ns()
    eps = _entrypoints(_render(ns))
    assert set(eps) == {'wo_webapp', 'wo_worker'}
    for svc, ep in eps.items():
        argv = shlex.split(ep)          # how compose splits a string entrypoint
        assert argv[:2] == ['/bin/bash', '-c'] and len(argv) == 3, svc
        assert argv[2].startswith(ns['WEBODM_OLEFILE_STRIP']), svc
    assert _render(ns).count('olefile') == 2


def test_entrypoint_shell_is_valid_and_still_runs_the_upstream_start():
    ns = _ns()
    eps = _entrypoints(_render(ns))
    for svc, tail in (('wo_webapp', '/webodm/start.sh'), ('wo_worker', '/webodm/worker.sh start')):
        inner = shlex.split(eps[svc])[2]
        assert subprocess.run(['bash', '-n', '-c', inner]).returncode == 0, svc
        assert tail in inner
        # `;` not `&&`: a pip hiccup must never keep WebODM from starting
        assert inner.startswith('pip uninstall -y -q olefile >/dev/null 2>&1; ')


def test_rewrite_brings_a_legacy_compose_to_the_template_and_is_idempotent():
    ns = _ns()
    out = ns['_webodm_strip_olefile'](LEGACY)
    assert _entrypoints(out) == _entrypoints(_render(ns))
    assert ns['_webodm_strip_olefile'](out) == out
    # the template itself is already patched
    assert ns['_webodm_strip_olefile'](_render(ns)) == _render(ns)
    # nothing but the two entrypoint lines changed
    strip = lambda t: re.sub(r'^    entrypoint: [^\n]*\n', '', t, flags=re.M)
    assert strip(out) == strip(LEGACY)


def test_rewrite_leaves_an_unrecognised_entrypoint_alone():
    ns = _ns()
    odd = LEGACY.replace('entrypoint: /bin/bash -c "/webodm/wait', 'entrypoint: ["/webodm/wait')
    out = ns['_webodm_strip_olefile'](odd)
    assert _entrypoints(out)['wo_worker'] == _entrypoints(odd)['wo_worker']
    assert _entrypoints(out)['wo_webapp'].startswith('/bin/bash -c "' + ns['WEBODM_OLEFILE_STRIP'])


def _run_startup_block(wo_dir, home, files):
    import os
    i = APP.index('        # Harden existing WebODM installs')
    block = textwrap.dedent(APP[i:APP.index('        # UFW deny belt-and-braces for WebODM ports', i)])
    ns, calls = _ns(), []
    fake_os = types.SimpleNamespace(
        path=types.SimpleNamespace(join=os.path.join, exists=lambda p: p in files,
                                   expanduser=lambda p: p.replace('~', home, 1)),
        cpu_count=lambda: 4)
    ns.update({
        'os': fake_os, 's': {}, 'print': lambda *a, **k: calls.append(('print', a[0] if a else '')),
        '_webodm_dir': lambda: wo_dir,
        '_read_priv': lambda p: calls.append(('read', p)) or LEGACY,
        '_write_priv': lambda p, c: calls.append(('write', p, c)),
        '_webodm_compose': lambda d, a, timeout=300: calls.append(('compose', d, a)),
        '_get_module_deployment_config': lambda s, k: {},
        '_webodm_odm_limits': lambda cpus, cfg: (2, 4),
    })
    exec(compile(block, 'app.py', 'exec'), ns)
    return calls, ns


def test_console_restart_patches_an_existing_install_and_recreates_it():
    calls, ns = _run_startup_block('/root/webodm', '/home/takwerx', files=set())
    writes = [c for c in calls if c[0] == 'write']
    assert len(writes) == 1
    eps = _entrypoints(writes[0][2])
    assert all(ns['WEBODM_OLEFILE_STRIP'] in eps[s] for s in ('wo_webapp', 'wo_worker'))
    assert ('compose', '/root/webodm', 'up -d') in calls
    assert any(c[0] == 'print' and 'ops #206' in c[1] for c in calls)


def test_update_applies_it_before_pulling():
    body = ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_run_webodm_update'))
    assert body.index('_webodm_strip_olefile(') < body.index("_webodm_compose(wo_dir, 'pull')")
    assert '_write_priv(compose_path, stripped)' in body
