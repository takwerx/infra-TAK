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
"""ops #691: the "plugins" tier. A change to anything TAK Portal Marketplace installs depend on
asks for a real Marketplace install on a box before merge.

10.3.12 changed the TAK Portal SSH key line (ops #644), nothing asked for a plugin install, and
every Marketplace install broke (ops #687). The first test feeds pick-tests that exact change.
"""
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location('pick_tests_691', os.path.join(ROOT, 'tools', 'pick-tests.py'))
pick_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pick_tests)
TIER_MAP = pick_tests.load_map(os.path.join(ROOT, 'tools', 'test-tiers.json'))


def diff(path, added=(), removed=(), ctx=''):
    out = ['diff --git a/%s b/%s' % (path, path), '--- a/%s' % path, '+++ b/%s' % path,
           '@@ -10,1 +10,1 @@ %s' % ctx]
    out += ['-' + r for r in removed] + ['+' + a for a in added]
    return '\n'.join(out) + '\n'


def result_for(text):
    return pick_tests.build_result(pick_tests.parse_diff(text), TIER_MAP)


def ids(text):
    return [it['id'] for it in result_for(text)['required']]


def test_the_10_3_12_key_change_asks_for_a_marketplace_install():
    """The ops #644 hunk that shipped in 10.3.12 and broke every Marketplace install."""
    text = diff('app.py',
                removed=["    return 'restrict'"],
                added=["    return 'restrict,from=\"' + ','.join(['127.0.0.1', '::1'] + list(sources)) + '\"'"],
                ctx='def _takportal_ssh_key_options(sources):')
    result = result_for(text)
    assert 'plugins' in [it['id'] for it in result['required']]
    box = [it for it in result['required'] if it['id'] == 'box'][0]
    assert any('test6' in b for b in box['boxes'])
    md = pick_tests.render_markdown(result)
    assert 'Marketplace' in md and 'CloudTAK' in md


def test_authorized_keys_anywhere_is_plugins():
    assert 'plugins' in ids(diff('app.py', added=["    ak = os.path.expanduser('~/.ssh/authorized_keys')"],
                                 ctx='def _something_else():'))


def test_broker_grants_are_plugins():
    """The grant lines in the broker fire; the rest of the broker (Guard Dog ops etc.) does not."""
    assert 'plugins' in ids(diff('broker/takwerx_broker.py', added=['    x = 1'],
                                 ctx='def _takportal_sudoers_text(user, variant=None):'))
    assert 'plugins' in ids(diff('broker/takwerx_broker.py', added=["    path = '/etc/sudoers.d/infratak-x'"],
                                 ctx='def _write():'))
    assert 'plugins' not in ids(diff('broker/takwerx_broker.py', added=['    x = 1'], ctx='def _gd_render(name):'))
    assert 'plugins' in ids(diff('app.py', added=['    line = "takwerx ALL=(tak) NOPASSWD: /bin/true"'],
                                 ctx='def _other():'))


def test_docker_networks_are_plugins():
    assert 'plugins' in ids(diff('app.py', added=["    _run('docker network connect ' + net + ' ' + c)"],
                                 ctx='def _cloudtak_join():'))
    assert 'plugins' in ids(diff('app.py', added=['    net = INFRATAK_DOCKER_NETWORK'], ctx='def _x():'))
    assert 'plugins' in ids(diff('app.py', added=['      - "host.docker.internal:host-gateway"'],
                                 ctx='def _compose_text():'))


def test_caddy_for_portal_or_cloudtak_is_plugins():
    assert 'plugins' in ids(diff('app.py', added=["    block = f'reverse_proxy cloudtak-api:5000'  # caddy"],
                                 ctx='def _render():'))


def test_marketplace_and_plugin_catalog_are_plugins():
    assert 'plugins' in ids(diff('app.py', added=["    'print': {'repo': 'x'},"], ctx='CLOUDTAK_PLUGINS = {'))
    assert 'plugins' in ids(diff('app.py', added=['    pass'], ctx='def cloudtak_marketplace_jobs():'))
    assert 'plugins' in ids(diff('scripts/takportal-caddy-validate-shim.sh', added=['echo hi']))


def test_unrelated_changes_do_not_ask_for_plugins():
    assert 'plugins' not in ids(diff('app.py', added=['    label = "Hello"'], ctx='def home():'))
    assert 'plugins' not in ids(diff('app.py', added=['    x = 1'], ctx='def run_caddy_deploy(domain):'))
    assert 'plugins' not in ids(diff('tests/test_x.py', added=["AK = 'authorized_keys _takportal_x'"]))
    assert 'plugins' not in ids(diff('README.md', added=['TAK Portal sudoers and authorized_keys notes']))
