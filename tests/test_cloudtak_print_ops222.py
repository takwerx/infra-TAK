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
"""ops #222: TAK Portal's Print plugin works through infra-TAK's Caddy.

TAK Portal's marketplace runs Print (cloudtak-print) from its own docker-compose.plugin-print.yml
with `expose: 5010` only and internal URLs that don't resolve on a stock CloudTAK project, and
infra-TAK's Caddy runs on the host, so /print-api had nowhere to go. Now:
  1. infra-TAK's overlay (docker-compose.infratak-print.yml) publishes it on 127.0.0.1:5010 with
     api / tiles URLs; Print is started from base + TAK Portal's file + the overlay. Neither file
     goes in COMPOSE_FILE. A file TAK Portal 2.0.18 left unstartable is never used.
  2. Guard Dog (console and tak-cloudtak-watch.sh) spots a Print TAK Portal restarted without the
     overlay and the repair restarts that one container.
  3. The CloudTAK map site imports a `(cloudtak_print)` snippet pointing at 127.0.0.1:5010, which
     TAK Portal's "Deploy To Caddy" then reports as applied and leaves alone.
  4. Nothing changes while Print isn't installed.

app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import json
import os
import pathlib
import re
import shutil
import subprocess
import types

import pytest

from test_cloudtak_autorepair_ops197 import _alerts, _repair_calls, gd  # noqa: F401
from test_cloudtak_marketplace_plugins_ops216 import PluginBox, _override

yaml = pytest.importorskip('yaml')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP_PATH = REPO / 'app.py'
APP = APP_PATH.read_text(encoding='utf-8')
TREE = ast.parse(APP)
_NODES = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}
_ASSIGNS = {t.id: n for n in TREE.body if isinstance(n, ast.Assign)
            for t in n.targets if isinstance(t, ast.Name)}

PLUGIN = 'docker-compose.plugin-print.yml'
OVERLAY = 'docker-compose.infratak-print.yml'
CONSTS = ('CLOUDTAK_CUSTOM_COMPOSE', '_CLOUDTAK_PRINT_PLUGIN_COMPOSE', 'CLOUDTAK_PRINT_OVERLAY',
          'CLOUDTAK_PRINT_SERVICE', 'CLOUDTAK_PRINT_PORT', '_CLOUDTAK_PRINT_OVERLAY_YML',
          '_CT_ENV_LINE_RE', '_CLOUDTAK_COMPOSE_VAR_RE')
FUNCS = ('_cloudtak_env_read', '_cloudtak_compose_interpolate', '_cloudtak_print_problem',
         '_cloudtak_print_containers', '_cloudtak_print_set_up', '_cloudtak_print_drift', '_cloudtak_print_converge')

# CloudTAK v13.113.0's docker-compose.yml, trimmed to what matters here.
BASE = ('services:\n  api:\n    image: cloudtak-api\n  tiles:\n    image: cloudtak-tiles\n'
        '  store:\n    image: garage\n  events:\n    image: cloudtak-events\n')
# What TAK Portal 2.0.19+ writes: Print's compose.service.yml with depends_on and the internal
# URLs rewritten to CloudTAK's service names.
PLUGIN_OK = """\
# Managed by TAK Portal CloudTAK marketplace. Do not edit by hand.
services:
    cloudtak-print:
      container_name: cloudtak-print
      build:
        context: ./cloudtak-marketplace-plugins/print/service
        dockerfile: Dockerfile
      restart: unless-stopped
      depends_on:
        - api
        - tiles
        - store
      expose:
        - "5010"
      shm_size: '1gb'
      env_file: .env
      environment:
        - API_INTERNAL_URL=http://api:5000
        - TILES_INTERNAL_URL=http://tiles:5002
        - PRINT_CONCURRENCY=${PRINT_CONCURRENCY:-1}
"""
# TAK Portal 2.0.18: the depends_on rewrite never ran (TAK-Portal#69).
PLUGIN_2018 = PLUGIN_OK.replace('- api\n', '- cloudtak-api\n').replace('- store\n', '- cloudtak-store\n')
# A file from before TAK Portal 2.0.19: the depends_on rewrite ran but the URLs were left alone.
PLUGIN_OLD_URLS = PLUGIN_OK.replace('http://api:5000', 'http://cloudtak-api:5000')


def _src(name):
    node = _NODES.get(name) or _ASSIGNS[name]
    return ast.get_source_segment(APP, node)


def _load(funcs, consts=(), **ns):
    ns = {'os': os, 're': re, 'json': json, 'subprocess': subprocess, **ns}
    for c in consts:
        exec(compile(_src(c), str(APP_PATH), 'exec'), ns)
    for f in funcs:
        node = _NODES[f]
        exec(compile('\n' * (node.lineno - 1) + _src(f), str(APP_PATH), 'exec'), ns)
    return ns


class Stack:
    """~/CloudTAK on disk, docker faked: `rows` is the running cloudtak-print containers as
    (name, [config files]); None means CloudTAK isn't running."""

    def __init__(self, tmp_path, plugin=PLUGIN_OK, rows=(), compose_rc=0, custom=True):
        self.ct = tmp_path / 'CloudTAK'
        self.ct.mkdir()
        (self.ct / 'docker-compose.yml').write_text(BASE)
        if custom:
            (self.ct / 'docker-compose.custom.yml').write_text('services: {}\n')
        if plugin is not None:
            (self.ct / PLUGIN).write_text(plugin)
        self.rows = None if rows is None else list(rows)
        self.compose_rc = compose_rc
        self.compose, self.caddy, self.logs = [], [], []

    def docker_out(self, args, timeout=20, stdin=None):
        if args[0] == 'inspect':
            return '' if self.rows is None else 'cloudtak\n'
        if args[0] == 'ps':
            assert 'label=com.docker.compose.service=cloudtak-print' in args
            return ''.join(f'{n}|{",".join(f)}|cloudtak-print|{(r[2:] or [""])[0]}\n'
                           for r in self.rows or [] for n, f in [r[:2]])
        raise AssertionError(args)

    def compose_run(self, ct_dir, args, timeout=600):
        self.compose.append(list(args))
        if self.compose_rc == 0:
            files = [args[i + 1] for i, a in enumerate(args) if a == '-f']
            self.rows = [('cloudtak-print', [f'{self.ct}/{f}' for f in files])]
            return 0, ''
        return self.compose_rc, 'Error response from daemon: Bind for 127.0.0.1:5010 failed: port is already allocated'

    def ns(self):
        return _load(FUNCS, CONSTS, _ct_docker_out=self.docker_out, _cloudtak_compose_run=self.compose_run,
                     _cloudtak_print_caddy_converge=lambda log=None: self.caddy.append(True),
                     print=lambda *a, **k: self.logs.append(' '.join(map(str, a))))

    def converge(self):
        return self.ns()['_cloudtak_print_converge'](str(self.ct), self.logs.append)

    def takportal_started(self, ports=''):
        """What TAK Portal's `-f docker-compose.yml -f docker-compose.plugin-print.yml up` leaves.
        `ports` is docker's published-ports text (the Print file of ops #279 publishes the loopback
        port itself, which is why Compose never adds the overlay to the labels)."""
        self.rows = [('cloudtak-print', [f'{self.ct}/docker-compose.yml', f'{self.ct}/{PLUGIN}'], ports)]


# ── 1. Compose: the overlay, and only a startable file ───────────────────────

def test_overlay_publishes_on_loopback_only_and_nothing_else():
    # ops #235: the plugin's own defaults are the stock api / tiles URLs now (clptak/cloudtak-
    # plugin-print PRs #3/#4), so the overlay no longer sets API_INTERNAL_URL / TILES_INTERNAL_URL.
    ns = _load((), CONSTS)
    svc = yaml.safe_load(ns['_CLOUDTAK_PRINT_OVERLAY_YML'])['services']['cloudtak-print']
    assert svc['ports'] == ['127.0.0.1:5010:5010']
    assert set(svc) == {'ports'}                     # adds to TAK Portal's service, replaces nothing else


# What the plugin's compose.service.yml carries since clptak/cloudtak-plugin-print#4 (TAK Portal
# leaves the ${...} lines alone): Compose fills them in from CloudTAK's .env.
PLUGIN_VARS = PLUGIN_OK.replace(
    '- api\n        - tiles\n        - store\n',
    '- ${PRINT_API_SERVICE:-api}\n        - ${PRINT_TILES_SERVICE:-tiles}\n        - ${PRINT_STORE_SERVICE:-store}\n'
).replace('http://api:5000', '${PRINT_API_INTERNAL_URL:-http://api:5000}'
          ).replace('http://tiles:5002', '${PRINT_TILES_INTERNAL_URL:-http://tiles:5002}')


def test_plugin_vars_fixture_has_the_upstream_lines():
    assert '${PRINT_API_SERVICE:-api}' in PLUGIN_VARS and '- api\n' not in PLUGIN_VARS


@pytest.mark.parametrize('env, want', [
    ('', ''),                                                    # defaults: stock names
    ('PRINT_API_SERVICE=\n', ''),                                # empty counts as unset for :-
    ('PRINT_API_SERVICE=api\nPRINT_STORE_SERVICE="store"\n', ''),
    ('# PRINT_API_SERVICE=cloudtak-api\n', ''),                  # a comment sets nothing
])
def test_stock_stack_without_print_vars_in_env_is_startable(tmp_path, env, want):
    st = Stack(tmp_path, plugin=PLUGIN_VARS)
    (st.ct / '.env').write_text(env)
    assert st.ns()['_cloudtak_print_problem'](str(st.ct)) == want


def test_stock_stack_with_no_env_file_is_startable(tmp_path):
    st = Stack(tmp_path, plugin=PLUGIN_VARS)
    assert not (st.ct / '.env').exists()
    assert st.ns()['_cloudtak_print_problem'](str(st.ct)) == ''


def test_env_override_naming_a_service_the_stack_lacks_is_unstartable(tmp_path):
    st = Stack(tmp_path, plugin=PLUGIN_VARS)
    (st.ct / '.env').write_text('PRINT_API_SERVICE=cloudtak-api\n')
    got = st.ns()['_cloudtak_print_problem'](str(st.ct))
    assert 'cloudtak-api' in got and 'depends_on' in got, got
    assert 'PRINT_API_SERVICE' in got and 'reinstall' not in got, got   # the .env is what to fix


def test_renamed_stack_that_sets_the_print_vars_is_startable(tmp_path):
    # The stack names its services cloudtak-api / -tiles / -store and says so in .env (what
    # clptak/cloudtak-plugin-print#4 is for); before ops #235 the overlay forced api / tiles.
    st = Stack(tmp_path, plugin=PLUGIN_VARS)
    st.ct.joinpath('docker-compose.yml').write_text(
        BASE.replace('  api:', '  cloudtak-api:').replace('  tiles:', '  cloudtak-tiles:').replace('  store:', '  cloudtak-store:'))
    assert "has no api service" in st.ns()['_cloudtak_print_problem'](str(st.ct))     # defaults don't fit
    (st.ct / '.env').write_text('PRINT_API_SERVICE=cloudtak-api\nPRINT_TILES_SERVICE=cloudtak-tiles\n'
                                'PRINT_STORE_SERVICE=cloudtak-store\n'
                                'PRINT_API_INTERNAL_URL=http://cloudtak-api:5000\n'
                                'PRINT_TILES_INTERNAL_URL=http://cloudtak-tiles:5002\n')
    assert st.ns()['_cloudtak_print_problem'](str(st.ct)) == ''


def test_url_that_names_no_cloudtak_service_is_unstartable(tmp_path):
    st = Stack(tmp_path, plugin=PLUGIN_VARS)
    (st.ct / '.env').write_text('PRINT_TILES_INTERNAL_URL=http://cloudtak-tiles:5002\n')
    got = st.ns()['_cloudtak_print_problem'](str(st.ct))
    assert got.startswith("CloudTAK's docker-compose.yml has no cloudtak-tiles service (TILES_INTERNAL_URL)"), got


def test_file_without_url_settings_needs_the_stock_services(tmp_path):
    plugin = '\n'.join(l for l in PLUGIN_OK.splitlines() if 'INTERNAL_URL' not in l) + '\n'
    st = Stack(tmp_path, plugin=plugin)
    assert st.ns()['_cloudtak_print_problem'](str(st.ct)) == ''
    st.ct.joinpath('docker-compose.yml').write_text(BASE.replace('  tiles:', '  other:'))
    assert "has no tiles service" in st.ns()['_cloudtak_print_problem'](str(st.ct))


def test_required_var_that_is_missing_is_unstartable(tmp_path):
    st = Stack(tmp_path, plugin=PLUGIN_VARS.replace('${PRINT_API_SERVICE:-api}', '${PRINT_API_SERVICE:?set it}'))
    got = st.ns()['_cloudtak_print_problem'](str(st.ct))
    assert "doesn't set" in got and 'PRINT_API_SERVICE' in got, got


@pytest.mark.parametrize('text, env, want', [
    ('${A:-x}', {}, 'x'), ('${A:-x}', {'A': ''}, 'x'), ('${A-x}', {'A': ''}, ''),
    ('${A-x}', {}, 'x'), ('${A:-x}', {'A': 'y'}, 'y'), ('${A}', {'A': "'y'"}, 'y'),
    ('$A', {'A': 'y'}, 'y'), ('$$A', {'A': 'y'}, '$A'), ('${A:+r}', {'A': 'y'}, 'r'),
    ('${A:+r}', {}, ''), ('plain', {}, 'plain'), ('${A:?no}', {}, None), ('${A:?no}', {'A': 'y'}, 'y'),
])
def test_compose_interpolation_matches_composes_rules(text, env, want):
    assert _load(FUNCS, CONSTS)['_cloudtak_compose_interpolate'](text, env) == want


def test_print_with_vars_is_converged_without_touching_the_stack_env(tmp_path):
    st = Stack(tmp_path, plugin=PLUGIN_VARS)
    (st.ct / '.env').write_text('FOO=bar\n')
    st.takportal_started()
    assert st.converge() == 'ok'
    assert (st.ct / '.env').read_text() == 'FOO=bar\n'            # we never write PRINT_*_SERVICE
    assert len(st.compose) == 1


def test_print_api_route_is_generated_once_converge_succeeds_with_the_var_file(tmp_path):
    # GH #295: with the plugin's ${PRINT_API_SERVICE:-api} lines the check used to call Print
    # unstartable, so no overlay was written and /print-api was never routed (200 text/html).
    st = Stack(tmp_path, plugin=PLUGIN_VARS)
    st.takportal_started()
    assert st.converge() == 'ok'
    assert (st.ct / OVERLAY).is_file() and st.caddy == [True]
    ns = _load(('_caddy_operator_owns_print', '_cloudtak_print_caddy'), CONSTS + CADDY_CONSTS,
               CADDYFILE_PATH=str(tmp_path / 'Caddyfile'),
               _caddy_operator_include_files=lambda: [],
               _get_cloudtak_deployment_config=lambda s: {'target_mode': 'local'})
    snippet, site = ns['_cloudtak_print_caddy']({}, str(st.ct))
    assert '    @cloudtak_print path /print-api /print-api/*' in snippet
    assert '        reverse_proxy 127.0.0.1:5010' in snippet
    assert site == ['    import cloudtak_print']


@pytest.mark.parametrize('plugin, want', [
    (None, None),
    (PLUGIN_OK, ''),
    (PLUGIN_OK.replace('- api\n        - tiles\n        - store\n', '{api: {condition: service_started}}\n'), ''),
])
def test_problem_none_without_the_file_and_empty_for_a_startable_one(tmp_path, plugin, want):
    st = Stack(tmp_path, plugin=plugin)
    assert st.ns()['_cloudtak_print_problem'](str(st.ct)) == want


@pytest.mark.parametrize('plugin, words', [
    (PLUGIN_2018, ['cloudtak-api', 'cloudtak-store', 'TAK Portal']),
    ('services: [\n', ['could not be read']),
    ('services:\n  something-else:\n    image: x\n', ['no cloudtak-print service']),
])
def test_problem_names_what_compose_would_refuse(tmp_path, plugin, words):
    st = Stack(tmp_path, plugin=plugin)
    got = st.ns()['_cloudtak_print_problem'](str(st.ct))
    assert got and all(w in got for w in words), got


def test_takportal_started_print_is_restarted_with_the_overlay(tmp_path):
    st = Stack(tmp_path)
    st.takportal_started()
    assert st.converge() == 'ok'
    assert (st.ct / OVERLAY).read_text() == st.ns()['_CLOUDTAK_PRINT_OVERLAY_YML']
    assert st.compose == [['-f', 'docker-compose.yml', '-f', PLUGIN, '-f', OVERLAY,
                           '-f', 'docker-compose.custom.yml',
                           'up', '-d', '--no-deps', '--no-build', 'cloudtak-print']]
    assert st.caddy == [True]
    assert any('127.0.0.1:5010' in l for l in st.logs)


def test_converged_print_is_left_alone(tmp_path):
    st = Stack(tmp_path)
    st.takportal_started()
    st.converge()
    st.compose.clear()
    assert st.converge() == 'ok'
    assert st.compose == []                                     # no restart loop


LOOPBACK = '127.0.0.1:5010->5010/tcp'


def test_print_that_already_publishes_the_loopback_port_is_left_alone(tmp_path):
    # ops #279: the Print file TAK Portal installs now publishes 127.0.0.1:5010 itself, so an
    # `up` with the overlay changes nothing and the labels never list it: not drift, no restart.
    st = Stack(tmp_path)
    st.takportal_started(LOOPBACK)
    assert st.ns()['_cloudtak_print_drift'](str(st.ct)) == []
    assert st.converge() == 'ok'
    assert st.compose == []
    assert (st.ct / OVERLAY).exists() and st.caddy == [True]    # the route still follows the overlay


@pytest.mark.parametrize('ports', ['', '5010/tcp', '0.0.0.0:5010->5010/tcp, [::]:5010->5010/tcp',
                                   '127.0.0.1:5011->5010/tcp'])
def test_print_without_the_loopback_port_is_still_drift(tmp_path, ports):
    st = Stack(tmp_path)
    st.takportal_started(ports)
    assert st.ns()['_cloudtak_print_drift'](str(st.ct)) == ['cloudtak-print']
    assert st.converge() == 'ok'
    assert len(st.compose) == 1


def test_custom_file_only_when_it_exists(tmp_path):
    st = Stack(tmp_path, custom=False)
    st.takportal_started()
    st.converge()
    assert 'docker-compose.custom.yml' not in st.compose[0]


def test_print_that_is_not_running_is_started_while_cloudtak_is_up(tmp_path):
    st = Stack(tmp_path, rows=[])
    assert st.converge() == 'ok'
    assert len(st.compose) == 1


def test_nothing_is_started_while_cloudtak_is_down(tmp_path):
    st = Stack(tmp_path, rows=None)
    assert st.converge() == 'ok'
    assert st.compose == [] and (st.ct / OVERLAY).exists()


def test_a_failed_start_is_reported(tmp_path):
    st = Stack(tmp_path, compose_rc=1)
    st.takportal_started()
    assert st.converge() == 'failed'
    assert any('port is already allocated' in l for l in st.logs)


def test_file_with_urls_to_services_cloudtak_lacks_is_never_started(tmp_path):
    # Print would start and then fail every export, so say so instead; the overlay no longer
    # sets these URLs for it (ops #235).
    st = Stack(tmp_path, plugin=PLUGIN_OLD_URLS, rows=[])
    assert st.converge() == 'unusable'
    assert st.compose == [] and not (st.ct / OVERLAY).exists()
    assert any('cloudtak-api' in l and 'API_INTERNAL_URL' in l and 'reinstall' in l for l in st.logs), st.logs


def test_takportal_2018_file_is_never_started(tmp_path):
    st = Stack(tmp_path, plugin=PLUGIN_2018, rows=[])
    assert st.converge() == 'unusable'
    assert st.compose == [] and not (st.ct / OVERLAY).exists()
    assert any("can't be started" in l and 'cloudtak-store' in l for l in st.logs)


def test_without_print_nothing_changes(tmp_path):
    st = Stack(tmp_path, plugin=None, rows=[])
    assert st.converge() == 'absent'
    assert st.compose == [] and sorted(p.name for p in st.ct.iterdir()) == [
        'docker-compose.custom.yml', 'docker-compose.yml']
    assert st.logs == []


def test_uninstall_removes_the_overlay(tmp_path):
    st = Stack(tmp_path)
    st.takportal_started()
    st.converge()
    (st.ct / PLUGIN).unlink()                                   # TAK Portal's uninstall
    st.rows = []
    assert st.converge() == 'absent'
    assert not (st.ct / OVERLAY).exists()
    assert len(st.caddy) == 2                                   # the route follows


def test_print_never_goes_in_compose_file():
    # CloudTAK Update builds everything in COMPOSE_FILE with --no-cache, and TAK Portal's
    # uninstall deletes its file: neither may be listed there.
    for f in ('_cloudtak_compose_file_value', '_cloudtak_ensure_custom_compose', '_cloudtak_remote_custom_compose_sh'):
        assert 'PRINT' not in _src(f) and 'plugin-print' not in _src(f)


def test_drift_is_print_running_without_the_overlay_while_installed(tmp_path):
    st = Stack(tmp_path)
    st.takportal_started()
    assert st.ns()['_cloudtak_print_drift'](str(st.ct)) == ['cloudtak-print']
    st.converge()
    assert st.ns()['_cloudtak_print_drift'](str(st.ct)) == []
    (st.ct / PLUGIN).unlink()
    st.takportal_started()
    assert st.ns()['_cloudtak_print_drift'](str(st.ct)) == []    # not installed: not ours


# ── 2. Guard Dog: console repair ─────────────────────────────────────────────

class PrintBox(PluginBox):
    """ops #216's box (real override, TAK Portal's Print + uDash containers) with Print's file
    installed and the Print functions loaded."""

    def __init__(self, home):
        super().__init__(home)
        (self.ct / 'docker-compose.yml').write_text(BASE)
        (self.ct / PLUGIN).write_text(PLUGIN_OK)
        self.compose, self.caddy = [], []

    def compose_run(self, ct_dir, args, timeout=600):
        self.compose.append(list(args))
        files = [args[i + 1] for i, a in enumerate(args) if a == '-f']
        self.labels['cloudtak-print'] = ','.join(f'{self.ct}/{f}' for f in files)
        return 0, ''

    def ns(self):
        ns = super().ns()
        ns.update({'_cloudtak_compose_run': self.compose_run,
                   '_cloudtak_print_caddy_converge': lambda log=None: self.caddy.append(True)})
        for c in CONSTS[1:]:
            exec(compile(_src(c), str(APP_PATH), 'exec'), ns)
        for f in FUNCS:
            exec(compile(_src(f), str(APP_PATH), 'exec'), ns)
        return ns


@pytest.fixture
def prbox(tmp_path):
    return PrintBox(tmp_path)


def _drift(box):
    old = os.environ['HOME']
    os.environ['HOME'] = str(box.home)
    try:
        return box.ns()['_cloudtak_drift'](str(box.ct))
    finally:
        os.environ['HOME'] = old


def test_print_only_drift_restarts_print_not_the_stack(prbox):
    prbox.clean()
    d = _drift(prbox)
    assert d['kind'] == 'print' and d['print'] == ['cloudtak-print'] and d['no_override'] == []
    assert prbox.request()['state'] == 'repairing'
    prbox.finish()
    assert prbox.record()['last']['result'] == 'repaired'
    assert prbox.ups() == []                                    # no force-recreate of CloudTAK
    assert len(prbox.compose) == 1 and prbox.compose[0][-1] == 'cloudtak-print'
    assert OVERLAY in prbox.labels['cloudtak-print']
    assert prbox.request()['state'] == 'ok'
    assert len(prbox.compose) == 1                              # no repair loop
    assert prbox.mails == []                                    # logged, not emailed (ops #230)
    assert '(cloudtak-print) on 127.0.0.1:5010' in prbox.guard_log[0][1]


def test_takportal_install_recreate_also_gets_print_set_up(prbox):
    d = _drift(prbox)
    assert d['kind'] == 'recreate' and d['print'] == ['cloudtak-print']
    prbox.request()
    prbox.finish()
    assert prbox.record()['last']['result'] == 'repaired'
    assert len(prbox.ups()) == 1 and len(prbox.compose) == 1
    assert prbox.request()['state'] == 'ok'


def test_print_drift_summary_names_it(prbox):
    prbox.clean()
    ns = prbox.ns()
    assert "Print started without infra-TAK's /print-api settings: cloudtak-print" in \
        ns['_cloudtak_drift_summary'](_drift(prbox))


def test_every_repair_and_every_cloudtak_path_ends_with_print():
    assert '_cloudtak_print_converge(ct_dir, _log)' in _src('_cloudtak_autorepair_run')
    assert '_cloudtak_print_converge(_ct_dir' in _src('_startup_harden_cloudtak_ports')
    for f in ('run_cloudtak_deploy', 'run_cloudtak_redeploy', 'run_cloudtak_update'):
        assert '_cloudtak_print_converge(cloudtak_dir, plog)' in _src(f), f
    upd = _src('run_cloudtak_update')
    assert 'if not is_remote:\n            _cloudtak_print_converge' in upd


# ── 2b. Guard Dog: tak-cloudtak-watch.sh ─────────────────────────────────────

def _gd_rows(gd, tmp_path, print_files):
    ct = tmp_path / 'CloudTAK'
    (ct / 'docker-compose.override.yml').write_text(_override())   # api, events, media, postgis
    return {'cloudtak-api-1': gd.clean + '|api', 'cloudtak-media-1': gd.clean + '|media',
            'cloudtak-print': ','.join(f'{ct}/{f}' for f in print_files) + '|cloudtak-print'}


PROFILE = 'hlsVariant: mpegts\nhlsSegmentCount: 3\nhlsSegmentDuration: 500ms\nhlsPartDuration: 200ms\n'


def test_gd_print_without_the_overlay_is_drift_and_asks_for_the_repair(gd, tmp_path):
    (tmp_path / 'CloudTAK' / PLUGIN).write_text(PLUGIN_OK)
    rows = _gd_rows(gd, tmp_path, ['docker-compose.yml', PLUGIN])
    calls = gd(yml=PROFILE, labels=rows)
    assert _repair_calls(calls) == [] and "Print started without infra-TAK's /print-api settings" in gd.log()
    calls = gd(yml=PROFILE, labels=rows, console={'state': 'repairing'})
    assert len(_repair_calls(calls)) == 1 and _alerts(calls) == []


def test_gd_print_publishing_the_loopback_port_is_clean(gd, tmp_path):
    # ops #279: started from TAK Portal's file alone, but that file publishes 127.0.0.1:5010 itself
    (tmp_path / 'CloudTAK' / PLUGIN).write_text(PLUGIN_OK)
    rows = _gd_rows(gd, tmp_path, ['docker-compose.yml', PLUGIN])
    rows['cloudtak-print'] += '|127.0.0.1:5010->5010/tcp'
    gd(yml=PROFILE, labels=rows)
    calls = gd(yml=PROFILE, labels=rows)
    assert _repair_calls(calls) == [] and _alerts(calls) == [] and 'drift' not in gd.log()
    rows['cloudtak-print'] = rows['cloudtak-print'].replace('127.0.0.1', '0.0.0.0')
    gd(yml=PROFILE, labels=rows)
    assert "Print started without infra-TAK's /print-api settings" in gd.log()


def test_gd_print_with_the_overlay_is_clean(gd, tmp_path):
    (tmp_path / 'CloudTAK' / PLUGIN).write_text(PLUGIN_OK)
    rows = _gd_rows(gd, tmp_path, ['docker-compose.yml', PLUGIN, OVERLAY, 'docker-compose.custom.yml'])
    gd(yml=PROFILE, labels=rows)
    calls = gd(yml=PROFILE, labels=rows)
    assert _repair_calls(calls) == [] and _alerts(calls) == [] and 'drift' not in gd.log()


def test_gd_print_is_not_drift_while_takportal_print_is_not_installed(gd, tmp_path):
    rows = _gd_rows(gd, tmp_path, ['docker-compose.yml', PLUGIN])
    gd(yml=PROFILE, labels=rows)
    calls = gd(yml=PROFILE, labels=rows)
    assert _repair_calls(calls) == [] and 'drift' not in gd.log()


# ── 3. Caddy ─────────────────────────────────────────────────────────────────

CADDY_CONSTS = ('CADDYFILE_USER_BLOCKS_MARKER', '_CADDY_PRINT_SNIPPET', '_CADDY_PRINT_IMPORT')


def _caddy_ns(tmp_path, overlay=True, remote=False, includes=(), live=''):
    ct = tmp_path / 'CloudTAK'
    ct.mkdir(exist_ok=True)
    if overlay:
        (ct / OVERLAY).write_text('x')
    cf = tmp_path / 'Caddyfile'
    cf.write_text(live)
    ns = _load(('_caddy_operator_owns_print', '_cloudtak_print_caddy'), CONSTS + CADDY_CONSTS,
               CADDYFILE_PATH=str(cf),
               _caddy_operator_include_files=lambda: [str(p) for p in includes],
               _get_cloudtak_deployment_config=lambda s: {'target_mode': 'remote' if remote else 'local'})
    return ns, str(ct)


def test_caddy_lines_while_print_is_set_up(tmp_path):
    ns, ct = _caddy_ns(tmp_path)
    snippet, site = ns['_cloudtak_print_caddy']({}, ct)
    assert '(cloudtak_print) {' in snippet and '        reverse_proxy 127.0.0.1:5010' in snippet
    assert site == ['    import cloudtak_print']


@pytest.mark.parametrize('kw', [{'overlay': False}, {'remote': True}])
def test_no_caddy_lines_without_print_or_on_a_remote_cloudtak(tmp_path, kw):
    ns, ct = _caddy_ns(tmp_path, **kw)
    assert ns['_cloudtak_print_caddy']({}, ct) == ([], [])


def test_operator_print_route_wins(tmp_path):
    # GH #176's README example is this very snippet: two definitions and Caddy refuses the file.
    inc = tmp_path / 'print.caddy'
    inc.write_text('(cloudtak_print) {\n    reverse_proxy 127.0.0.1:5010\n}\n')
    ns, ct = _caddy_ns(tmp_path, includes=[inc])
    assert ns['_cloudtak_print_caddy']({}, ct) == ([], [])
    ns, ct = _caddy_ns(tmp_path, live='a {\n}\n# --- User-added blocks (do not remove) ---\n'
                                      '(cloudtak_print) {\n}\n')
    assert ns['_cloudtak_print_caddy']({}, ct) == ([], [])
    # ...but our own snippet ABOVE the marker is not the operator's.
    ns, ct = _caddy_ns(tmp_path, live='(cloudtak_print) {\n}\n# --- User-added blocks (do not remove) ---\n')
    assert ns['_cloudtak_print_caddy']({}, ct)[1] == ['    import cloudtak_print']


def test_generate_caddyfile_defines_the_snippet_first_and_imports_it_in_the_map_site():
    src = _src('generate_caddyfile')
    snip, glob = src.index('lines += _ct_print_caddy[0]'), src.index('_caddy_global_options_lines(')
    site = src.index('lines += _ct_print_caddy[1]')
    assert glob < snip < src.index('ct_map = sd[') < site < src.index('# CloudTAK Tile Server')


def _render(tmp_path, with_print=True, takportal=False):
    """The CloudTAK part of a generated Caddyfile, in the generator's own shapes."""
    ns, ct = _caddy_ns(tmp_path, overlay=with_print)
    snippet, site = ns['_cloudtak_print_caddy']({}, ct)
    out = ['# infra-TAK - Auto-generated Caddyfile', '', '{', '    admin off', '    auto_https off', '}', '']
    out += snippet
    if takportal:   # what TAK Portal's Deploy To Caddy writes into a file without ours
        out += ['(cloudtak_print) {', '\t@cloudtak_print path /print-api /print-api/*',
                '\thandle @cloudtak_print {', '\t\treverse_proxy cloudtak-print:5010', '\t}', '}']
    out += ['# CloudTAK Web UI (flush for SSE channels / WebSocket; longer timeouts for channel sync)',
            'http://map.example.com {']
    if takportal:
        out += ['    import cloudtak_print']
    out += ['    reverse_proxy 127.0.0.1:5000 {', '        flush_interval -1', '    }',
            '    @ct_pwa_entry path /sw.js /registerSW.js /manifest.webmanifest / /index.html',
            '    header @ct_pwa_entry Cache-Control "no-cache, no-store, must-revalidate"']
    out += site
    out += ['}', '', '# CloudTAK Tile Server', 'http://tiles.map.example.com {',
            '    reverse_proxy 127.0.0.1:5002', '}', '',
            '# --- User-added blocks (do not remove) ---',
            '# Anything below this line survives every infra-TAK regeneration.', '']
    return '\n'.join(out)


def _caddy_bin():
    return os.environ.get('CADDY_BIN') or shutil.which('caddy')


def _print_upstreams(path):
    """Dial addresses Caddy uses for /print-api on map.example.com, in the order it tries them."""
    r = subprocess.run([_caddy_bin(), 'adapt', '--config', str(path), '--adapter', 'caddyfile'],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    found = []

    def walk(routes):
        for rt in routes:
            paths = [p for m in (rt.get('match') or []) for p in m.get('path', [])]
            for h in rt.get('handle', []):
                if h.get('handler') == 'reverse_proxy' and any(p.startswith('/print-api') for p in paths):
                    found.extend(u['dial'] for u in h['upstreams'])
                walk(h.get('routes', []))
                if h.get('handler') == 'subroute' and any(p.startswith('/print-api') for p in paths):
                    for sr in h.get('routes', []):
                        for hh in sr.get('handle', []):
                            found.extend(u['dial'] for u in hh.get('upstreams', []))
    for srv in json.loads(r.stdout)['apps']['http']['servers'].values():
        walk(srv['routes'])
    return found


@pytest.mark.skipif(not _caddy_bin(), reason='caddy binary not on PATH (set CADDY_BIN)')
def test_caddy_routes_print_api_to_loopback(tmp_path):
    cf = tmp_path / 'out.caddy'
    cf.write_text(_render(tmp_path))
    assert _print_upstreams(cf) == ['127.0.0.1:5010']
    (tmp_path / 'none').mkdir()
    cf.write_text(_render(tmp_path / 'none', with_print=False))
    assert _print_upstreams(cf) == []


@pytest.mark.skipif(not _caddy_bin(), reason='caddy binary not on PATH (set CADDY_BIN)')
def test_caddy_takportal_copy_is_what_we_replace(tmp_path):
    # Without ours, TAK Portal's Deploy To Caddy copy is a container name host Caddy can't resolve
    # (and parses fine, so a reload does not fail on it: the symptom is a 502).
    (tmp_path / 'tp').mkdir()
    cf = tmp_path / 'tp.caddy'
    cf.write_text(_render(tmp_path / 'tp', with_print=False, takportal=True))
    assert _print_upstreams(cf) == ['cloudtak-print:5010']


TAKPORTAL_SRC = os.environ.get('TAKPORTAL_SRC', '')
_needs_takportal = pytest.mark.skipif(
    not (TAKPORTAL_SRC and shutil.which('node')),
    reason="set TAKPORTAL_SRC to a TAK Portal checkout to run its own Caddy code")


def _takportal_deploy_to_caddy(path):
    """TAK Portal's real "Deploy To Caddy" step for Print (applyCaddySnippets with the catalog's
    snippet) on the Caddyfile at path: {ok, changed, applied (before), text (after)}."""
    js = (
        "const c=require(process.argv[1]+'/services/cloudtakMarketplace.caddy.js');"
        "const fs=require('fs');"
        "const cat=JSON.parse(fs.readFileSync(process.argv[1]+'/catalog/cloudtak-plugins.json'));"
        "const p=cat.plugins.find(x=>x.id==='print');"
        "const s=p.additionalActions.filter(c.isCaddyAction).map(a=>a.snippet);"
        "const src=fs.readFileSync(process.argv[2],'utf8');"
        "const r=c.applyCaddySnippets(src,s,{host:'map.example.com'});"
        "console.log(JSON.stringify({ok:r.ok,changed:r.changed,text:r.text,"
        "applied:c.appliedKeys([p],src,{host:'map.example.com'}).length}));")
    r = subprocess.run(['node', '-e', js, TAKPORTAL_SRC, str(path)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@_needs_takportal
@pytest.mark.parametrize('with_print', [True, False])
def test_takportal_deploy_to_caddy_leaves_ours_alone(tmp_path, with_print):
    """TAK Portal's real applyCaddySnippets on our file: with ours, nothing to do and the step
    shows as applied; without (Print not set up) it would add its own copy."""
    cf = tmp_path / 'Caddyfile.gen'
    cf.write_text(_render(tmp_path, with_print=with_print))
    got = _takportal_deploy_to_caddy(cf)
    got.pop('text')
    assert got == ({'ok': True, 'changed': False, 'applied': 1} if with_print
                   else {'ok': True, 'changed': True, 'applied': 0})


class CaddyBox:
    def __init__(self, tmp_path, live, overlay=True, ready=True):
        self.calls, self.logs = [], []
        ct = tmp_path / 'CloudTAK'
        ct.mkdir()
        if overlay:
            (ct / OVERLAY).write_text('x')
        cf = tmp_path / 'Caddyfile'
        cf.write_text(live)
        self.ns = _load(
            ('_caddy_operator_owns_print', '_cloudtak_print_caddy', '_cloudtak_print_caddy_converge'),
            CONSTS + CADDY_CONSTS + ('CLOUDTAK_PRINT_SERVICE',),
            CADDYFILE_PATH=str(cf),
            _caddy_operator_include_files=lambda: [],
            _get_cloudtak_deployment_config=lambda s: {'target_mode': 'local'},
            load_settings=lambda: {'fqdn': 'example.com'},
            _read_priv=lambda p: pathlib.Path(p).read_text(),
            generate_caddyfile=lambda s: self.calls.append('generate') or 'x',
            _CADDY_REGISTRY_READY=types.SimpleNamespace(is_set=lambda: ready),
            _caddy_reload_if_changed=lambda: self.calls.append('reload') or (True, ''))
        os.environ['HOME'] = str(tmp_path)

    def run(self):
        return self.ns['_cloudtak_print_caddy_converge'](self.logs.append)


OURS = ('(cloudtak_print) {\n    handle @cloudtak_print {\n        reverse_proxy 127.0.0.1:5010\n'
        '    }\n}\nmap.example.com {\n    import cloudtak_print\n}\n')
MARK = '# --- User-added blocks (do not remove) ---\n'


@pytest.fixture
def home_back():
    old = os.environ['HOME']
    yield
    os.environ['HOME'] = old


@pytest.mark.parametrize('live, overlay, want', [
    ('map.example.com {\n}\n' + MARK, True, ['generate', 'reload']),            # missing
    (OURS + MARK, True, []),                                                    # in place
    (OURS + MARK, False, ['generate', 'reload']),                               # left over
    ('map.example.com {\n}\n' + MARK, False, []),                               # nothing to do
    ('map.example.com {\n}\n' + MARK + OURS, True, []),     # the operator's own, below the marker
    (OURS.replace('127.0.0.1:5010', 'cloudtak-print:5010') + MARK, False,
     ['generate', 'reload']),                                                   # TAK Portal's copy
])
def test_caddy_converge(tmp_path, home_back, live, overlay, want):
    box = CaddyBox(tmp_path, live, overlay=overlay)
    assert box.run() == bool(want)
    assert box.calls == want


def test_caddy_converge_before_the_registry_loads_leaves_the_reload_to_it(tmp_path, home_back):
    box = CaddyBox(tmp_path, 'map.example.com {\n}\n' + MARK, ready=False)
    assert box.run() is True and box.calls == ['generate']


# ── 4. A box that already has TAK Portal's /print-api route (GH #286) ─────────

def _field_box(tmp_path):
    """A v10.2.29 Caddyfile after TAK Portal's Deploy To Caddy: its snippet above the CloudTAK
    site and the import inside it, upstream cloudtak-print:5010 (the 502 in GH #286). Made by
    TAK Portal's own code when TAKPORTAL_SRC is set, else in the shape that code writes."""
    d = tmp_path / 'field'
    d.mkdir()
    if not (TAKPORTAL_SRC and shutil.which('node')):
        return _render(d, with_print=False, takportal=True)
    cf = d / 'Caddyfile.old'
    cf.write_text(_render(d, with_print=False))
    got = _takportal_deploy_to_caddy(cf)
    assert got['ok'] and got['changed']
    return got['text']


def test_field_box_with_takportal_route_gets_ours_after_the_update(tmp_path, home_back):
    field = _field_box(tmp_path)
    generated = field.split(MARK)[0]
    assert 'reverse_proxy cloudtak-print:5010' in generated and 'import cloudtak_print' in generated
    cf = tmp_path / 'check.caddy'
    if _caddy_bin():
        cf.write_text(field)
        assert _print_upstreams(cf) == ['cloudtak-print:5010']        # the reporter's 502
    # First console start on the fixed version, Print installed (so the overlay is written):
    # TAK Portal's copy in the generated part means regenerate.
    (tmp_path / 'new').mkdir()
    box = CaddyBox(tmp_path / 'new', field)
    assert box.run() is True and box.calls == ['generate', 'reload']
    # What that writes: exactly one cloudtak_print, ours, nothing of TAK Portal's left.
    fixed = _render(tmp_path / 'new')
    assert fixed.count('(cloudtak_print)') == 1 and fixed.count('import cloudtak_print') == 1
    assert 'cloudtak-print:5010' not in fixed
    if _caddy_bin():
        cf.write_text(fixed)
        assert _print_upstreams(cf) == ['127.0.0.1:5010']
    # Stable: no second regen, and pressing Deploy To Caddy again changes nothing.
    (tmp_path / 'again').mkdir()
    assert CaddyBox(tmp_path / 'again', fixed).run() is False
    if TAKPORTAL_SRC and shutil.which('node'):
        cf.write_text(fixed)
        got = _takportal_deploy_to_caddy(cf)
        assert (got['changed'], got['applied']) == (False, 1)


def test_field_box_without_a_startable_print_loses_the_dead_route(tmp_path, home_back):
    # TAK Portal 2.0.18 left Print's file unstartable (TAK-Portal#69): no overlay, so no route of
    # ours, but TAK Portal's cloudtak-print:5010 copy still goes (no dangling upstream).
    field = _field_box(tmp_path)
    (tmp_path / 'new').mkdir()
    box = CaddyBox(tmp_path / 'new', field, overlay=False)
    assert box.run() is True and box.calls == ['generate', 'reload']
    fixed = _render(tmp_path / 'new', with_print=False)
    assert 'cloudtak_print' not in fixed and 'print-api' not in fixed
