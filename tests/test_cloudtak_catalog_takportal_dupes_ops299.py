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
"""ops #299: infra-TAK no longer hosts the plugins TAK Portal's marketplace already lists.

Cell Ping / RTT, Search Containment and CloudTAK Dispatcher left CLOUDTAK_PLUGINS. The TAK
Simulator panel stays (TAK Portal does not list it yet). A box that already has one of the three
keeps it: the folder is treated like any other marketplace plugin.
"""

import ast
import pathlib

from test_cloudtak_marketplace_shield_gh252 import _tree, _run, _scripts, _load

APP_PY = pathlib.Path(__file__).resolve().parent.parent / 'app.py'
MOVED = ('ping', 'search-containment', 'tak-dispatcher')


def _catalog():
    tree = ast.parse(APP_PY.read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.Assign)
                and any(getattr(t, 'id', None) == 'CLOUDTAK_PLUGINS' for t in n.targets))
    return [{k.value: v for k, v in zip(d.keys, d.values)} for d in node.value.elts]


def test_catalog_keeps_only_the_simulator_panel():
    entries = _catalog()
    assert [ast.literal_eval(e['key']) for e in entries] == ['taksim']
    assert ast.literal_eval(entries[0]['install_dir']) == 'taksim'


def test_moved_plugins_are_not_hosted_here_any_more():
    src = APP_PY.read_text(encoding='utf-8')
    for repo in ('clptak/cloudtak-plugin-cellphone', 'clptak/cloudtak-plugin-search-containment',
                 'takwerx/cloudtak-dispatcher-plugin'):
        assert 'https://github.com/' + repo not in src


def test_already_installed_copies_are_handled_like_marketplace_plugins(tmp_path):
    ct = _tree(tmp_path, MOVED + ('taksim',))
    ns = _load()
    assert ns['_cloudtak_foreign_plugins'](str(ct)) == sorted(MOVED)
    log = _run(ns, ct)
    # the build skips lint/typecheck for them, so a box that has one still builds
    assert len(log) == 1 and all(n in log[0] for n in MOVED) and 'taksim' not in log[0]
    assert _scripts(ct)['check'] == 'vue-tsc --project tsconfig.marketplace.json'
    # and the folders themselves are never touched
    for n in MOVED + ('taksim',):
        assert (ct / 'app' / 'plugins' / n / 'index.ts').read_text() == 'export default {};\n'


def test_installed_copies_stay_in_the_image_build(tmp_path):
    ct = _tree(tmp_path, MOVED)
    (ct / '.dockerignore').write_text('app/plugins/*\n!app/plugins/*.ts\n')
    _run(_load(), ct)
    out = (ct / 'Dockerfile.dockerignore').read_text()
    for n in MOVED:
        assert f'\n!app/plugins/{n}\n' in out
