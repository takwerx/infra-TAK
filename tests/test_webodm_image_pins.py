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
"""WebODM stack pinned to tested images (ops #92).

The compose copied upstream's redis:7.0.10 (Redis 7.0 is end of life: CVE-2025-49844 Lua
use-after-free, CVE-2025-21605, CVE-2025-32023, ...) and ran webapp / nodeodx / db on a floating
:latest, so whatever upstream published that day landed on the next pull. Fresh deploys now
write pins; existing installs get the broker moved on a console restart and the rest on Update.
"""

import ast
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

# The compose every install before ops #92 was deployed with.
LEGACY = '''services:
  wo_db:
    image: webodm/webodm_db
    container_name: wo_db
  wo_broker:
    image: redis:7.0.10
    container_name: wo_broker
  wo_webapp:
    image: webodm/webodm_webapp
    container_name: webapp
    environment:
      - WO_BROKER=redis://wo_broker
  wo_worker:
    image: webodm/webodm_webapp
    container_name: wo_worker
  wo_nodeodm:
    image: webodm/nodeodx
    container_name: wo_nodeodm
'''


def _ns():
    """Exec the pins, the rewrite helper and the compose template out of app.py."""
    want = {'WEBODM_VERSION', 'WEBODM_IMAGES', 'WEBODM_DOCKER_COMPOSE', '_webodm_pin_images'}
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


def _images(compose):
    return dict(re.findall(r'^  (\w+):\n(?:    [^\n]*\n)*?    image: ([^\n]*)$', compose, re.M))


def _pinned(ref):
    return '@sha256:' in ref or re.search(r':\d+\.\d+\.\d+(-alpine)?$', ref)


def test_every_image_is_pinned_and_redis_is_off_70():
    ns = _ns()
    imgs = ns['WEBODM_IMAGES']
    assert set(imgs) == {'wo_db', 'wo_broker', 'wo_webapp', 'wo_worker', 'wo_nodeodm'}
    for svc, ref in imgs.items():
        assert ':latest' not in ref and _pinned(ref), (svc, ref)
    major_minor = tuple(int(x) for x in re.search(r'redis:(\d+)\.(\d+)', imgs['wo_broker']).groups())
    assert major_minor >= (7, 4)
    assert imgs['wo_webapp'] == imgs['wo_worker'] == 'webodm/webodm_webapp:' + ns['WEBODM_VERSION']


def test_fresh_deploy_compose_uses_the_pins():
    ns = _ns()
    assert _images(_render(ns)) == ns['WEBODM_IMAGES']
    # both deploy paths (local + remote) pass the pins into the template
    assert len(re.findall(r'WEBODM_DOCKER_COMPOSE\.format\(', APP)) == 2
    assert len(re.findall(r'images=WEBODM_IMAGES', APP)) == 2


def test_rewrite_moves_a_legacy_compose_to_the_pins_and_is_idempotent():
    ns = _ns()
    out = ns['_webodm_pin_images'](LEGACY)
    assert _images(out) == ns['WEBODM_IMAGES']
    assert ns['_webodm_pin_images'](out) == out
    # nothing but the image lines changed
    strip = lambda t: re.sub(r'^    image: [^\n]*\n', '', t, flags=re.M)
    assert strip(out) == strip(LEGACY)


def test_startup_rewrite_touches_only_the_broker():
    ns = _ns()
    out = ns['_webodm_pin_images'](LEGACY, services=('wo_broker',))
    got = _images(out)
    assert got['wo_broker'] == ns['WEBODM_IMAGES']['wo_broker']
    assert got['wo_webapp'] == got['wo_worker'] == 'webodm/webodm_webapp'
    assert got['wo_nodeodm'] == 'webodm/nodeodx'
    assert got['wo_db'] == 'webodm/webodm_db'


def test_startup_migration_pins_redis_and_keeps_the_nodeodx_image():
    i = APP.index('# Harden existing WebODM installs')
    block = APP[i:APP.index('# UFW deny belt-and-braces for WebODM ports', i)]
    assert "_webodm_pin_images(_wo_patched, services=('wo_broker',))" in block
    # the ODM-cap rewrite used to hard-code the floating image, undoing any pin
    assert 'image: webodm/nodeodx' not in block


def test_update_writes_the_pins_before_pulling():
    body = ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_run_webodm_update'))
    assert body.index('_webodm_pin_images(') < body.index("_webodm_compose(wo_dir, 'pull')")
    assert '_write_priv(compose_path' in body


def test_update_offered_against_the_pin_not_upstream_latest():
    body = ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_get_webodm_version_info'))
    assert 'api.github.com' not in body
    assert "'latest': WEBODM_VERSION" in body
