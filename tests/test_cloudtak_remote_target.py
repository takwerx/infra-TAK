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
"""A remote CloudTAK stays remote and installed (ops #33).

Field report: a CloudTAK deployed to a remote host "went away" after an infra-TAK update,
a reinstall said it worked but https://map.<fqdn> would not connect, and then the page said
CloudTAK was not installed. For a remote target "installed" is one saved flag
(cloudtak_deployment.deployed), and three paths broke it:
  * the page has no target form once CloudTAK is installed, and collectDeployConfig() then
    sent target_mode "local", so Update config / Remove saved the remote install as local;
  * Save target settings replaced the whole saved config, dropping `deployed`;
  * the remote deploy generated the Caddyfile before saving deployed=True, so Caddy had no
    map. site (no certificate) after a fresh remote install.
"""

import ast
import copy
import json
import pathlib
import re
import shutil
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

_FUNCS = ('_deep_merge_dict', '_cloudtak_deployment_defaults', '_normalize_cloudtak_deployment_config',
          '_get_cloudtak_deployment_config', '_cloudtak_cfg_for_installed_action',
          'cloudtak_save_deployment_config', 'cloudtak_redeploy_api', 'cloudtak_uninstall')

REMOTE_DEPLOYED = {
    'target_mode': 'remote', 'deployed': True,
    'remote': {'host': '10.0.0.15', 'ssh_user': 'root', 'ssh_port': 22,
               'ssh_key_path': '/home/takwerx/.ssh/infra-tak-cloudtak'},
}


class _Thread:
    started = []

    def __init__(self, target=None, args=(), **k):
        self.target, self.args = target, args

    def start(self):
        _Thread.started.append((self.target, self.args))


class _Lock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _ns(settings, body):
    """The CloudTAK config helpers + routes, exec'd from app.py with Flask/IO faked out."""
    tree = ast.parse(APP)
    src = '\n\n'.join(ast.get_source_segment(APP, n) for n in tree.body
                      if isinstance(n, ast.FunctionDef) and n.name in _FUNCS)
    store = {'settings': copy.deepcopy(settings), 'saves': 0}

    def save_settings(s):
        store['settings'] = copy.deepcopy(s)
        store['saves'] += 1

    _Thread.started = []
    ns = {
        'copy': copy,
        'request': types.SimpleNamespace(get_json=lambda *a, **k: body, json=body),
        'jsonify': lambda *a, **k: (a[0] if a else k),
        'load_settings': lambda: copy.deepcopy(store['settings']),
        'save_settings': save_settings,
        'load_auth': lambda: {'password_hash': 'h'},
        'check_password_hash': lambda h, p: True,
        'threading': types.SimpleNamespace(Thread=_Thread),
        '_cloudtak_deploy_lock': _Lock(),
        'cloudtak_deploy_status': {'running': False},
        'cloudtak_deploy_log': [],
        'cloudtak_uninstall_status': {'running': False},
        'run_cloudtak_redeploy': lambda cfg=None: None,
        'datetime': __import__('datetime').datetime,
    }
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns, store


def _saved(store):
    return store['settings']['cloudtak_deployment']


def test_update_config_from_installed_page_keeps_remote_target():
    """The pre-fix page JS sends {target_mode: 'local'} — a cached page still will."""
    ns, store = _ns({'cloudtak_deployment': REMOTE_DEPLOYED}, {'config': {'target_mode': 'local'}})
    ns['cloudtak_redeploy_api']()
    assert _saved(store)['target_mode'] == 'remote'
    assert _saved(store)['deployed'] is True
    assert _saved(store)['remote']['host'] == '10.0.0.15'
    (target, args), = _Thread.started
    assert args[0]['target_mode'] == 'remote'
    assert store['saves'] == 0


def test_update_config_with_fixed_js_empty_config_changes_nothing():
    ns, store = _ns({'cloudtak_deployment': REMOTE_DEPLOYED}, {'config': {}})
    ns['cloudtak_redeploy_api']()
    assert store['saves'] == 0
    assert _Thread.started[0][1][0]['target_mode'] == 'remote'


def test_remove_on_installed_remote_targets_the_remote_host():
    ns, store = _ns({'cloudtak_deployment': REMOTE_DEPLOYED},
                    {'password': 'x', 'config': {'target_mode': 'local'}})
    ns['cloudtak_uninstall']()
    assert _saved(store)['target_mode'] == 'remote'
    assert _saved(store)['remote']['host'] == '10.0.0.15'


def test_remove_with_empty_config_does_not_reset_to_defaults():
    """The old code normalized the request on its own: {} became local with no host."""
    ns, store = _ns({'cloudtak_deployment': REMOTE_DEPLOYED}, {'password': 'x', 'config': {}})
    ns['cloudtak_uninstall']()
    assert _saved(store)['target_mode'] == 'remote'
    assert _saved(store)['remote']['host'] == '10.0.0.15'


def test_remove_failed_first_install_still_uses_the_form_target():
    """Not deployed = the target form is on the page, so what it says counts."""
    saved = {'target_mode': 'local', 'deployed': False}
    ns, store = _ns({'cloudtak_deployment': saved},
                    {'password': 'x', 'config': {'target_mode': 'remote', 'remote': {'host': '10.0.0.20'}}})
    ns['cloudtak_uninstall']()
    assert _saved(store)['target_mode'] == 'remote'
    assert _saved(store)['remote']['host'] == '10.0.0.20'


def test_save_target_settings_keeps_the_deployed_flag():
    ns, store = _ns({'cloudtak_deployment': REMOTE_DEPLOYED},
                    {'config': {'target_mode': 'remote', 'remote': {'host': '10.0.0.15', 'ssh_port': 2222}}})
    ns['cloudtak_save_deployment_config']()
    assert _saved(store)['deployed'] is True
    assert _saved(store)['remote']['ssh_port'] == 2222
    assert _saved(store)['remote']['ssh_key_path'] == '/home/takwerx/.ssh/infra-tak-cloudtak'


def test_remote_deploy_saves_deployed_before_generating_caddyfile():
    body = re.search(r'^def run_cloudtak_deploy\(.*?(?=^def )', APP, re.S | re.M).group(0)
    remote = body[:body.index('# Step 1: Check Docker')]
    assert "if target_mode == 'remote':" in remote
    flag = remote.index("cfg['deployed'] = True")
    caddy = remote.index('generate_caddyfile(settings)')
    assert flag < caddy
    assert 'save_settings(settings)' in remote[flag:caddy]


def _page_js():
    tree = ast.parse(APP)
    for n in tree.body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'CLOUDTAK_PAGE_JS'
                                             for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError('CLOUDTAK_PAGE_JS not found')


@pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')
@pytest.mark.parametrize('elements,expected', [
    ({}, {}),   # installed page: no target form
    ({'cloudtak-target-mode': 'local'}, {'target_mode': 'local'}),
    ({'cloudtak-target-mode': 'remote', 'cloudtak-remote-host': ' 10.0.0.15 ',
      'cloudtak-remote-port': '22', 'cloudtak-remote-user': 'root', 'cloudtak-remote-key': ''},
     {'target_mode': 'remote', 'remote': {'host': '10.0.0.15', 'ssh_user': 'root',
                                          'ssh_port': 22, 'ssh_key_path': ''}}),
])
def test_collect_deploy_config_in_the_browser(elements, expected):
    js = _page_js()
    fn = js[js.index('window.collectDeployConfig = function'):js.index('window.toggleCloudtakTargetFields')]
    script = (
        'var els = ' + json.dumps(elements) + ';\n'
        'var window = {};\n'
        'var document = {getElementById: function(id) {'
        ' return Object.prototype.hasOwnProperty.call(els, id) ? {value: els[id]} : null; }};\n'
        + fn + '\nconsole.log(JSON.stringify(window.collectDeployConfig()));\n')
    out = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == expected


# --- Update config on a remote CloudTAK keeps the secrets the remote .env already has ---------
# Found on the box test for this fix: once Update config really ran on the remote (above), it
# wrote a fresh AWS_S3_SecretAccessKey and SigningSecret every time. The Garage store keeps the
# key it first started with, so it crash-looped ("Access key cloudtakminioadmin is associated
# with a secret key different than the one given in GARAGE_DEFAULT_SECRET_KEY").

REMOTE_ENV = """CLOUDTAK_Mode=docker-compose
SigningSecret=sig-original
AWS_S3_Endpoint=http://store:3900
AWS_S3_AccessKeyId=cloudtakminioadmin
AWS_S3_SecretAccessKey=store-original
MINIO_ROOT_USER=cloudtakminioadmin
MINIO_ROOT_PASSWORD=store-original
POSTGRES_PASSWORD=pg-original
GARAGE_RPC_SECRET=%s
""" % ('ab' * 32)


def _redeploy_ns(remote_env, env_read_ok=True):
    tree = ast.parse(APP)
    names = ('run_cloudtak_redeploy', '_cloudtak_build_env_content', '_cloudtak_env_secrets',
             '_cloudtak_env_preserve_unknown', '_cloudtak_remote_media_bufs')
    src = '\n\n'.join(ast.get_source_segment(APP, n) for n in tree.body
                      if isinstance(n, ast.FunctionDef) and n.name in names)
    sent = {'cmds': []}

    def _ssh_probe(cfg, cmd, timeout=15):
        sent['cmds'].append(cmd)
        if cmd.startswith('cat ~/CloudTAK/.env'):
            return (True, remote_env) if env_read_ok else (False, 'ssh: connect timed out')
        return True, ''

    def _scp_to_host(cfg, local, remote):
        sent[remote] = pathlib.Path(local).read_text()
        return True, ''

    status = {'running': True}
    ns = {
        'os': __import__('os'), 'shutil': shutil, 'tempfile': __import__('tempfile'),
        'datetime': __import__('datetime').datetime, 'subprocess': subprocess,
        'load_settings': lambda: {'fqdn': 'example.com',
                                  'cloudtak_deployment': copy.deepcopy(REMOTE_DEPLOYED)},
        '_get_cloudtak_deployment_config': lambda s: copy.deepcopy(REMOTE_DEPLOYED),
        '_get_service_domain': lambda s, k: '',
        '_cloudtak_remote_store_endpoint': lambda cfg: 'http://store:3900',
        '_cloudtak_build_override_yml': lambda s: 'services: {}\n',
        '_cloudtak_remote_compose_is_garage': lambda cfg: False,
        '_ssh_probe': _ssh_probe, '_scp_to_host': _scp_to_host,
        'generate_caddyfile': lambda s=None: None, '_caddy_reload': lambda: None,
        '_cloudtak_media_hls_heal': lambda **k: None,
        'cloudtak_deploy_log': [], 'cloudtak_deploy_status': status,
    }
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns, sent, status


def _env(text):
    return dict(l.split('=', 1) for l in text.splitlines() if '=' in l and not l.startswith('#'))


def test_env_secrets_reads_the_three_secrets():
    secrets_of = _redeploy_ns('')[0]['_cloudtak_env_secrets']
    assert secrets_of(REMOTE_ENV) == ('sig-original', 'store-original', 'pg-original')
    # the Garage key alone (MINIO_ROOT_PASSWORD gone) still counts as the store secret
    assert secrets_of('AWS_S3_SecretAccessKey=k\n')[1] == 'k'
    assert secrets_of('') == ('', '', '')


def test_remote_update_config_keeps_store_and_signing_secrets():
    ns, sent, status = _redeploy_ns(REMOTE_ENV)
    ns['run_cloudtak_redeploy']()
    assert status.get('complete') is True, ns['cloudtak_deploy_log']
    env = _env(sent['/tmp/.env'])
    assert env['SigningSecret'] == 'sig-original'
    assert env['AWS_S3_SecretAccessKey'] == 'store-original'
    assert env['MINIO_ROOT_PASSWORD'] == 'store-original'
    assert env['POSTGRES_PASSWORD'] == 'pg-original'
    assert env['GARAGE_RPC_SECRET'] == 'ab' * 32


def test_remote_update_config_stops_when_the_remote_env_cannot_be_read():
    ns, sent, status = _redeploy_ns(REMOTE_ENV, env_read_ok=False)
    ns['run_cloudtak_redeploy']()
    assert status.get('error') is True
    assert '/tmp/.env' not in sent       # never write new secrets over a working install


def test_remote_update_config_without_env_generates_secrets():
    ns, sent, status = _redeploy_ns('')
    ns['run_cloudtak_redeploy']()
    env = _env(sent['/tmp/.env'])
    assert len(env['SigningSecret']) == 64 and len(env['AWS_S3_SecretAccessKey']) == 32
    assert env['POSTGRES_PASSWORD'] == 'docker'


def test_remote_update_config_sets_media_kernel_buffers():
    """cloudtak-media crash-looped on a fresh remote: the 4MB UDP buffer was only set on the console box."""
    ns, sent, status = _redeploy_ns(REMOTE_ENV)
    ns['run_cloudtak_redeploy']()
    bufs = [c for c in sent['cmds'] if 'net.core.rmem_max=4194304' in c]
    assert bufs and '/etc/sysctl.d/99-takwerx-media-bufs.conf' in bufs[0]
    up = next(i for i, c in enumerate(sent['cmds']) if 'docker compose up -d' in c)
    assert sent['cmds'].index(bufs[0]) < up


def test_remote_deploy_sets_media_kernel_buffers_before_starting_containers():
    body = re.search(r'^def run_cloudtak_deploy\(.*?(?=^def )', APP, re.S | re.M).group(0)
    remote = body[:body.index('# Step 1: Check Docker')]
    assert remote.index('_cloudtak_remote_media_bufs(remote_cfg, plog)') < remote.index('docker compose up -d')


def test_remote_deploy_stops_the_old_stack_before_deleting_its_tree():
    """A running Garage store (restart: always) re-created ~/CloudTAK/.docker-garage during the
    rm -rf and initialized it with the old key, so the new stack crash-looped on a key mismatch."""
    body = re.search(r'^def run_cloudtak_deploy\(.*?(?=^def )', APP, re.S | re.M).group(0)
    remote = re.sub(r'#.*', '', body[:body.index('# Step 1: Check Docker')])
    tagged = remote[remote.index('if remote_release_tag:'):remote.index('else:', remote.index('if remote_release_tag:'))]
    assert tagged.index('docker compose down --remove-orphans') < tagged.index('rm -rf ~/CloudTAK')
    assert 'down -v' not in tagged          # the postgis volume (and its password) survives a redeploy
