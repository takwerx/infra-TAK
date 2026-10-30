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
"""ops #216: CloudTAK plugins installed from TAK Portal's marketplace survive every infra-TAK path.

The end-to-end pass after #252 / #261 / #271 found five gaps, one section each below:
  1. Print and the uDash sidecar run from TAK Portal's own docker-compose.plugin-<id>.yml in the
     CloudTAK project, so they never carry infra-TAK's override. Console start and Guard Dog
     counted them as drift: a recreate on every console start, three repairs an hour that could
     never clear it, then the alarm.
  2. Deploy's build retry ran `compose down --remove-orphans`, which removed those containers.
  3. A CloudTAK on another host: Deploy and Update reset TAK Portal's build edits and the shield
     only ran locally, so the remote build failed like #252 / #271.
  4. Crossing CloudTAK's api/web -> app/ move, only infra-TAK's own plugins were moved.
  5. Deploy's re-clone (no compose file) deleted every plugin file with the tree.

app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import json
import os
import pathlib
import re
import subprocess
import tempfile
import types

import pytest

from test_cloudtak_autorepair_ops197 import Box, PROFILE, _alerts, _repair_calls, gd  # noqa: F401
from test_cloudtak_marketplace_shield_gh252 import (APP_LINT, APP_PKG, OVERLAY, _git, _scripts,
                                                    _tree)
from test_cloudtak_plugin_npm_deps_gh271 import _deps, _rubber_sheet

REPO = pathlib.Path(__file__).resolve().parent.parent
APP_PATH = REPO / 'app.py'
APP = APP_PATH.read_text(encoding='utf-8')
TREE = ast.parse(APP)
_NODES = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}
_ASSIGNS = {t.id: n for n in TREE.body if isinstance(n, ast.Assign)
            for t in n.targets if isinstance(t, ast.Name)}


def _fn(name):
    return ast.get_source_segment(APP, _NODES[name])


def _assign(name):
    return ast.get_source_segment(APP, _ASSIGNS[name])


def _load(funcs, consts=(), **ns):
    """Compile the named app.py functions at their real line numbers under app.py's own file
    name, so inspect.getsource() (which the remote shield uses) reads them back as shipped."""
    ns = {'os': os, 're': re, 'json': json, 'subprocess': subprocess, 'tempfile': tempfile, **ns}
    for c in consts:
        exec(compile(_assign(c), str(APP_PATH), 'exec'), ns)
    for f in funcs:
        node = _NODES[f]
        src = '\n' * (node.lineno - 1) + ast.get_source_segment(APP, node)
        exec(compile(src, str(APP_PATH), 'exec'), ns)
    return ns


# ── 1. Print / uDash are not drift ───────────────────────────────────────────

def _override(**kw):
    """infra-TAK's real override, rendered by _cloudtak_build_override_yml()."""
    settings = {'simulator_enabled': kw.get('sim', False), 'simulator_control_token': 'tok',
                'console_cert_docker_san': True}
    ns = _load(['_cloudtak_build_override_yml'],
               CONFIG_DIR='/nonexistent', MEDIA_INFRA_IMAGE='ghcr.io/dfpc-coe/media-infra:v9.12.1',
               POSTGIS_IMAGE='postgis/postgis:17-3.5-alpine', POSTGIS_IMAGE_ARM64='x:arm',
               INFRATAK_DOCKER_NETWORK='infratak',
               _get_takserver_host=lambda s: '',
               _get_cloudtak_deployment_config=lambda s: {'target_mode': 'remote' if kw.get('remote') else 'local'},
               _ensure_infratak_docker_network=lambda: None,
               _host_arch=lambda: 'amd64',
               _container_ca_trust=lambda node=False: (
                   ('      NODE_EXTRA_CA_CERTS: "/etc/ssl/certs/ca-certificates.crt"\n',
                    '      - "/etc/ssl/certs:/etc/ssl/certs:ro"\n') if kw.get('ca') else ('', '')))
    return ns['_cloudtak_build_override_yml'](settings)


@pytest.mark.parametrize('kw', [{}, {'sim': True}, {'ca': True}, {'remote': True}, {'sim': True, 'ca': True}])
def test_override_services_are_read_from_the_real_override(tmp_path, kw):
    (tmp_path / 'docker-compose.override.yml').write_text(_override(**kw))
    ns = _load(['_cloudtak_override_services'])
    assert ns['_cloudtak_override_services'](str(tmp_path)) == {'api', 'events', 'media', 'postgis'}


def test_override_services_unreadable_is_empty(tmp_path):
    ns = _load(['_cloudtak_override_services'])
    assert ns['_cloudtak_override_services'](str(tmp_path)) == set()
    (tmp_path / 'docker-compose.override.yml').write_text('# TAKWERX override\n')
    assert ns['_cloudtak_override_services'](str(tmp_path)) == set()


class PluginBox(Box):
    """Box with infra-TAK's real override and TAK Portal's Print + uDash containers, which come
    from their own docker-compose.plugin-<id>.yml — so our recreate never touches them."""
    PLUGINS = {'cloudtak-print': 'cloudtak-print', 'cloudtak-plugin-udash-sidecar': 'cloudtak-plugin-udash-sidecar'}

    def __init__(self, home):
        super().__init__(home)
        self.override = _override()
        (self.ct / 'docker-compose.override.yml').write_text(self.override)
        self.services = {'cloudtak-api-1': 'api', 'cloudtak-media-1': 'media',
                         'cloudtak-postgis-1': 'postgis', 'cloudtak-events-1': 'events', **self.PLUGINS}
        for n in self.PLUGINS:
            self.labels[n] = f'{self.ct}/docker-compose.yml,{self.ct}/docker-compose.plugin-{n.split("-")[-1]}.yml'

    def clean(self):
        files = f'{self.ct}/docker-compose.yml,{self.ct}/docker-compose.override.yml'
        for n in ('cloudtak-api-1', 'cloudtak-media-1', 'cloudtak-postgis-1', 'cloudtak-events-1'):
            self.labels[n] = files
        self.media_image, self.api_ca, self.hls = 'ghcr.io/dfpc-coe/media-infra:v9.12.1', True, True

    def run(self, argv, **kw):
        if list(argv[:2]) == ['docker', 'ps'] and 'label=com.docker.compose.project=cloudtak' in argv:
            self.calls.append((list(argv), kw.get('cwd')))
            out = ''.join(f'{n}|{f}|{self.services.get(n, "")}\n' for n, f in self.labels.items())
            return types.SimpleNamespace(stdout=out, stderr='', returncode=0)
        keep = {n: self.labels[n] for n in self.PLUGINS if n in self.labels}
        r = super().run(argv, **kw)
        self.labels.update(keep)
        return r

    def ns(self):
        ns = super().ns()
        ns['_cloudtak_build_override_yml'] = lambda s: self.override
        return ns


@pytest.fixture
def pbox(tmp_path):
    return PluginBox(tmp_path)


def _drift(box):
    old = os.environ['HOME']
    os.environ['HOME'] = str(box.home)
    try:
        return box.ns()['_cloudtak_drift'](str(box.ct))
    finally:
        os.environ['HOME'] = old


def test_print_and_udash_alone_are_not_drift(pbox):
    pbox.clean()
    d = _drift(pbox)
    assert d['kind'] == '' and d['no_override'] == []
    assert pbox.request()['state'] == 'ok'
    assert pbox.ups() == []


def test_takportal_recreate_is_still_found_but_not_the_plugin_containers(pbox):
    d = _drift(pbox)
    assert d['kind'] == 'recreate'
    assert d['no_override'] == ['cloudtak-api-1', 'cloudtak-media-1', 'cloudtak-postgis-1']


def test_repair_clears_even_though_print_and_udash_keep_their_own_files(pbox):
    assert pbox.request()['state'] == 'repairing'
    pbox.finish()
    assert pbox.record()['last']['result'] == 'repaired'
    assert 'docker-compose.plugin-print.yml' in pbox.labels['cloudtak-print']   # untouched by us
    assert pbox.request()['state'] == 'ok'
    assert len(pbox.ups()) == 1                                                # no repair loop


def test_console_start_check_uses_the_same_rule():
    src = _fn('_startup_harden_cloudtak_ports')
    assert '_cloudtak_containers_without_override(_ct_dir)' in src
    assert "ours and service.strip() not in ours" in _fn('_cloudtak_containers_without_override')


def test_gd_print_and_udash_are_not_drift(gd, tmp_path):
    (tmp_path / 'CloudTAK' / 'docker-compose.override.yml').write_text(_override())
    plug = f'{tmp_path}/CloudTAK/docker-compose.yml,{tmp_path}/CloudTAK/docker-compose.plugin-print.yml'
    labels = {'cloudtak-api-1': gd.clean + '|api', 'cloudtak-media-1': gd.clean + '|media',
              'cloudtak-print': plug + '|cloudtak-print',
              'cloudtak-plugin-udash-sidecar': plug.replace('print', 'udash') + '|cloudtak-plugin-udash-sidecar'}
    gd(yml=PROFILE, labels=labels)
    calls = gd(yml=PROFILE, labels=labels)
    assert _alerts(calls) == [] and _repair_calls(calls) == []
    assert 'drift' not in gd.log()


def test_gd_api_without_override_is_still_drift_next_to_print(gd, tmp_path):
    (tmp_path / 'CloudTAK' / 'docker-compose.override.yml').write_text(_override())
    plug = f'{tmp_path}/CloudTAK/docker-compose.yml,{tmp_path}/CloudTAK/docker-compose.plugin-print.yml'
    labels = {'cloudtak-api-1': gd.takportal + '|api', 'cloudtak-media-1': gd.clean + '|media',
              'cloudtak-print': plug + '|cloudtak-print'}
    gd(yml=PROFILE, labels=labels)
    calls = gd(yml=PROFILE, labels=labels, console={'state': 'repairing'})
    assert len(_repair_calls(calls)) == 1
    assert 'cloudtak-api-1' in gd.log() and 'cloudtak-print' not in gd.log()


# ── 2. Deploy's build retry keeps them ───────────────────────────────────────

def test_deploy_build_retry_does_not_remove_orphans():
    src = _fn('run_cloudtak_deploy')
    seg = src[src.find('Cleaning up from previous build attempt'):]
    seg = seg[:seg.find('Cleaned up containers')]
    # ops #348: `stop`, not `down` — down orphans postgis' anonymous data volume
    assert "_sudo_wrap(['docker', 'compose', 'stop'])" in seg
    assert '--remove-orphans' not in seg


# ── 3. The shield on a remote CloudTAK host ──────────────────────────────────

_SHIELD = ['_cloudtak_web_dir', '_cloudtak_plugins_dir', '_cloudtak_foreign_plugins',
           '_cloudtak_has_ts_nocheck', '_cloudtak_rewrite_in_place', '_cloudtak_plugin_missing_deps',
           '_cloudtak_keep_plugins_in_build', '_cloudtak_shield_foreign_plugins']
_SHIELD_CONSTS = ['_CT_MARKETPLACE_TSCONFIG', '_CT_MARKETPLACE_ROUTES_RE', '_CT_IMPORT_RE',
                  '_CT_NPM_NAME_RE', '_CT_NPM_SPEC_RE', '_CT_DOCKERIGNORE_MARK', '_CT_PLUGIN_DIR_RE',
                  '_CT_SHIELD_CONSTS', '_CT_SHIELD_FUNCS']
OURS = [{'install_dir': d, 'key': d} for d in ('taksim',)]


def _remote_ns():
    import base64
    ns = _load(_SHIELD + ['_cloudtak_shield_py', '_cloudtak_remote_shield_sh'], _SHIELD_CONSTS,
               CLOUDTAK_PLUGINS=OURS, _b64=base64)
    ns['_CT_SHIELD_PY'] = ns['_cloudtak_shield_py']()
    return ns


def _remote_run(sh, home, path=None):
    env = {'HOME': str(home), 'PATH': path or os.environ['PATH']}
    return subprocess.run(['/bin/bash', '-c', sh], capture_output=True, text=True, env=env, timeout=120)


def test_shield_script_is_the_shipped_code():
    py = _remote_ns()['_CT_SHIELD_PY']
    for f in _SHIELD:
        assert _fn(f) in py
    assert "_cloudtak_shield_foreign_plugins(sys.argv[1]" in py
    compile(py, 'shield.py', 'exec')


def test_remote_shield_does_what_the_local_one_does(tmp_path):
    local, remote = tmp_path / 'local', tmp_path / 'remote'
    local.mkdir()
    remote.mkdir()
    for home in (local, remote):
        ct = _tree(home, ('livewx-radar', 'sidebar-configurator', 'taksim'))
        _rubber_sheet(ct)
        (ct / 'api' / 'stateless' / 'routes' / 'plugin-sidebar-config.ts').write_text('// @ts-nocheck\nx\n')
    log = []
    _load(_SHIELD, _SHIELD_CONSTS[:5], CLOUDTAK_PLUGINS=OURS)['_cloudtak_shield_foreign_plugins'](
        str(local / 'CloudTAK'), log.append)
    r = _remote_run(_remote_ns()['_cloudtak_remote_shield_sh'](), remote)
    assert r.returncode == 0, r.stderr
    for p in ('app/package.json', 'app/tsconfig.marketplace.json', 'api/eslint.config.js'):
        assert (remote / 'CloudTAK' / p).read_text() == (local / 'CloudTAK' / p).read_text(), p
    rct = remote / 'CloudTAK'
    assert _scripts(rct)['check'] == 'vue-tsc --project tsconfig.marketplace.json'
    assert _scripts(rct)['lint'] != APP_LINT
    assert (rct / 'app' / 'tsconfig.marketplace.json').read_text() == OVERLAY
    assert _deps(rct) == {'pdfjs-dist': '4.10.38'}
    assert r.stdout.splitlines() == log


def test_remote_shield_only_our_plugins_changes_nothing(tmp_path):
    ct = _tree(tmp_path, ('taksim',))
    r = _remote_run(_remote_ns()['_cloudtak_remote_shield_sh'](), tmp_path)
    assert r.returncode == 0 and r.stdout.strip() == ''
    assert (ct / 'app' / 'package.json').read_text() == APP_PKG


def test_remote_host_without_python3_says_so_and_goes_on(tmp_path):
    _tree(tmp_path, ('livewx-radar',))
    empty = tmp_path / 'nopython'
    empty.mkdir()
    r = _remote_run(_remote_ns()['_cloudtak_remote_shield_sh'](), tmp_path, path=str(empty))
    assert r.returncode == 0
    assert 'python3 not found' in r.stdout
    assert (tmp_path / 'CloudTAK' / 'app' / 'package.json').read_text() == APP_PKG


def test_remote_shield_logs_and_never_raises():
    log = []
    ns = _load(['_cloudtak_remote_shield'], _CT_SHIELD_PY='x',
               _cloudtak_remote_shield_sh=lambda: 'sh',
               _ssh_probe=lambda cfg, cmd, timeout=0: (True, '  Put back npm package(s)...\nPlugins not installed'))
    ns['_cloudtak_remote_shield']({'host': 'h'}, log.append)
    assert log == ['  Put back npm package(s)...', '  Plugins not installed']
    ns['_ssh_probe'] = lambda *a, **k: (_ for _ in ()).throw(OSError('boom'))
    ns['_cloudtak_remote_shield']({'host': 'h'}, log.append)
    assert 'non-fatal' in log[-1]
    ns['_ssh_probe'] = lambda *a, **k: (False, 'Permission denied')
    ns['_cloudtak_remote_shield']({'host': 'h'}, log.append)
    assert 'non-fatal' in log[-1]


def test_remote_update_shields_after_the_checkout_and_before_the_build():
    src = _fn('run_cloudtak_update')
    co = src.index('ok, out = _ssh_probe(remote_cfg, checkout_cmd, timeout=120)')
    sh = src.index('_cloudtak_remote_shield(remote_cfg, plog)')
    build = src.index('build_cmd = f"cd ~/CloudTAK && {dcc} build --no-cache"')
    assert co < sh < build


def test_remote_deploy_shields_after_the_repo_prep_and_before_the_build():
    src = _fn('run_cloudtak_deploy')
    prep = src.index('prep_cmd = _cloudtak_remote_reclone_sh(remote_release_tag)')
    sh = src.index('_cloudtak_remote_shield(remote_cfg, plog)')
    build = src.index('"docker compose build --no-cache && "')
    assert prep < sh < build


# ── 4. Every plugin across the api/web -> app/ move ──────────────────────────

def _carry_ns():
    return _load(['_cloudtak_web_dir', '_cloudtak_plugins_dir', '_cloudtak_carry_plugins'])


def _layout(tmp_path, new_tree):
    """A committed checkout in the new (app/) or old (api/web/) layout."""
    ct = tmp_path / 'CloudTAK'
    web = ct / 'app' if new_tree else ct / 'api' / 'web'
    (web / 'src').mkdir(parents=True)
    (web / 'plugins').mkdir()
    (web / 'plugins' / 'example').mkdir()
    (web / 'plugins' / 'example' / 'index.ts').write_text('upstream\n')
    _git(ct, 'init', '-q')
    _git(ct, 'add', '-A')
    _git(ct, 'commit', '-qm', 'stock')
    return ct


def test_marketplace_plugins_follow_the_app_move(tmp_path):
    ct = _layout(tmp_path, new_tree=True)
    old = ct / 'api' / 'web' / 'plugins'
    for n in ('rubber-sheet', 'quick-point-dropper', 'tak-dispatcher'):
        (old / n).mkdir(parents=True)
        (old / n / 'index.ts').write_text(n)
    log = []
    moves = _carry_ns()['_cloudtak_carry_plugins'](str(ct), log.append)
    for n in ('rubber-sheet', 'quick-point-dropper', 'tak-dispatcher'):
        assert (ct / 'app' / 'plugins' / n / 'index.ts').read_text() == n
        assert not (old / n).exists()
    assert sorted(os.path.basename(d) for _s, d in moves) == ['quick-point-dropper', 'rubber-sheet', 'tak-dispatcher']
    assert any('rubber-sheet' in ln and 'app/plugins/' in ln for ln in log)


def test_rollback_to_the_old_layout_moves_them_back(tmp_path):
    ct = _layout(tmp_path, new_tree=False)
    (ct / 'app' / 'plugins' / 'livewx-radar').mkdir(parents=True)
    moves = _carry_ns()['_cloudtak_carry_plugins'](str(ct), lambda m: None)
    assert (ct / 'api' / 'web' / 'plugins' / 'livewx-radar').is_dir()
    assert moves == [(str(ct / 'app' / 'plugins' / 'livewx-radar'),
                      str(ct / 'api' / 'web' / 'plugins' / 'livewx-radar'))]


def test_carry_never_overwrites_and_leaves_tracked_and_hidden_alone(tmp_path):
    ct = _layout(tmp_path, new_tree=False)
    other = ct / 'app' / 'plugins'
    (other / 'example').mkdir(parents=True)            # same name as upstream's tracked one
    (other / 'example' / 'index.ts').write_text('mine\n')
    (other / '.cache').mkdir()
    assert _carry_ns()['_cloudtak_carry_plugins'](str(ct), lambda m: None) == []
    assert (ct / 'api' / 'web' / 'plugins' / 'example' / 'index.ts').read_text() == 'upstream\n'
    assert (other / 'example' / 'index.ts').read_text() == 'mine\n'


def test_nothing_to_carry_is_a_noop(tmp_path):
    ct = _layout(tmp_path, new_tree=True)
    assert _carry_ns()['_cloudtak_carry_plugins'](str(ct), lambda m: None) == []


def test_update_carries_before_restoring_catalog_plugins_and_can_undo():
    src = _fn('run_cloudtak_update')
    carry = src.index('_plugin_moves.extend(_cloudtak_carry_plugins(cloudtak_dir, plog))')
    assert src.index("checkout -f {release_tag}") < carry < src.index('# Restore any catalog plugins')


def test_deploy_carries_after_the_checkout():
    src = _fn('run_cloudtak_deploy')
    assert src.index('plog("✓ Repository ready")') < src.index('_cloudtak_carry_plugins(cloudtak_dir, plog)') \
        < src.index('━━━ Step 3/7: Configuring .env ━━━')


# ── 5. Deploy's re-clone keeps the plugin files ──────────────────────────────

def _keep_ns():
    return _load(['_cloudtak_keep_aside', '_cloudtak_put_back'],
                 ['CLOUDTAK_CUSTOM_COMPOSE', '_CLOUDTAK_TAKPORTAL_CSP_COMPOSE', '_CLOUDTAK_KEEP_FILES', '_CLOUDTAK_KEEP_DIRS'])


def _installed(ct):
    files = {
        'docker-compose.yml': 'services: {}\n',
        'docker-compose.custom.yml': 'services:\n  mine: {}\n',
        'docker-compose.marketplace.yml': '# Managed by TAK Portal\n',
        'docker-compose.plugin-print.yml': 'services:\n  cloudtak-print: {}\n',
        'cloudtak-marketplace-plugins/print/service/Dockerfile': 'FROM node\n',
        'cloudtak-marketplace-plugins/csp.tsv': 'livewx\tconnect-src\n',
        'app/plugins/README.md': 'upstream old\n',
        'app/plugins/rubber-sheet/index.ts': 'rs\n',
        'app/plugins/sidebar-configurator/lib/apply.ts': 'sc\n',
        'api/stateless/routes/basemap.ts': 'upstream old\n',
        'api/stateless/routes/plugin-sidebar-config.ts': '// @ts-nocheck\n',
        '.plugin-src/tak-dispatcher/README.md': 'ours\n',
    }
    for rel, text in files.items():
        p = ct / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return files


def _clone(ct):
    for rel, text in {'docker-compose.yml': 'services: {api: {}}\n', 'app/plugins/README.md': 'upstream new\n',
                      'api/stateless/routes/basemap.ts': 'upstream new\n', 'app/src/main.ts': 'x\n'}.items():
        p = ct / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def test_reclone_keeps_every_marketplace_file(tmp_path):
    import shutil
    ct = tmp_path / 'CloudTAK'
    files = _installed(ct)
    ns = _keep_ns()
    keep = ns['_cloudtak_keep_aside'](str(ct))
    assert keep and os.path.dirname(keep) == str(tmp_path)
    shutil.rmtree(ct)                                   # the rm -rf
    _clone(ct)
    log = []
    ns['_cloudtak_put_back'](keep, str(ct), log.append)
    for rel, text in files.items():
        if rel in ('docker-compose.yml', 'app/plugins/README.md', 'api/stateless/routes/basemap.ts'):
            continue
        assert (ct / rel).read_text() == text, rel
    # what the clone brought wins
    assert (ct / 'docker-compose.yml').read_text() == 'services: {api: {}}\n'
    assert (ct / 'app' / 'plugins' / 'README.md').read_text() == 'upstream new\n'
    assert (ct / 'api' / 'stateless' / 'routes' / 'basemap.ts').read_text() == 'upstream new\n'
    assert not os.path.exists(keep)
    assert len(log) == 1 and 'rubber-sheet' in log[0] and 'docker-compose.plugin-print.yml' in log[0]


def test_nothing_to_keep_returns_none(tmp_path):
    ct = tmp_path / 'CloudTAK'
    (ct / 'app').mkdir(parents=True)
    ns = _keep_ns()
    assert ns['_cloudtak_keep_aside'](str(ct)) is None
    assert [p for p in os.listdir(tmp_path) if p.startswith('.cloudtak-keep-')] == []
    ns['_cloudtak_put_back'](None, str(ct), lambda m: None)        # no-op


def test_failed_reclone_keeps_the_files_and_says_where():
    src = _fn('run_cloudtak_deploy')
    seg = src[src.find('docker-compose.yml missing — re-cloning'):]
    seg = seg[:seg.find('compose_yml = os.path.join(cloudtak_dir, ')]
    assert seg.index('_keep = _cloudtak_keep_aside(cloudtak_dir)') < seg.index("rm -rf {cloudtak_dir}")
    assert seg.index('git clone --depth 1') < seg.index('_cloudtak_put_back(_keep, cloudtak_dir, plog)')
    assert 'kept in {_keep}' in seg
