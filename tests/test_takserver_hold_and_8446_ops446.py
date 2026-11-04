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
"""TAK Server update false FAILED on a held package, and the false 8446 warning (ops #446).

* `_verify_takserver_dpkg_ok` accepted only the exact string `install ok installed`. A package
  under `apt-mark hold` reports `hold ok installed` (fully installed and configured), so the
  update ended "FAILED" for it. It now judges the error flag and status (words 2 and 3).
* The LE install's 8446 regex `[^/]*/>` could not match the connector it writes itself
  (`keystoreFile="certs/files/takserver-le.jks"` holds slashes), so every run after the first
  warned "8446 connector pattern not matched". The regex now skips quoted values, and an
  already-wired connector logs "already set".

app.py cannot be imported in a test, so the pieces are cut out of the shipped text.
"""

import ast
import pathlib
import re
import subprocess
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _node_src(name):
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', None) == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _verify(state, rc=0):
    ns = {'subprocess': subprocess}
    exec(_node_src('_verify_takserver_dpkg_ok'), ns)
    out = types.SimpleNamespace(stdout=state, returncode=rc)
    ns['subprocess'] = types.SimpleNamespace(run=lambda *a, **k: out)
    lines = []
    return ns['_verify_takserver_dpkg_ok'](lines.append), lines


def test_held_but_fully_installed_passes():
    ok, lines = _verify('hold ok installed')
    assert ok is True
    assert not any('NOT fully configured' in l for l in lines)


def test_plain_install_still_passes():
    assert _verify('install ok installed')[0] is True


def test_half_configured_still_fails():
    for state in ('install ok half-configured', 'hold ok half-configured',
                  'install ok unpacked', 'install reinstreq half-installed',
                  'hold reinstreq installed'):
        ok, lines = _verify(state)
        assert ok is False, state
        assert any('NOT fully configured' in l for l in lines)


# --- 8446 connector -------------------------------------------------------------------

LE_CONNECTOR = ('<connector port="8446" clientAuth="false" _name="LetsEncrypt" '
                'keystore="JKS" keystoreFile="certs/files/takserver-le.jks" '
                'keystorePass="atakatak" enableAdminUI="true" enableWebtak="true" '
                'enableNonAdminUI="false"/>')
STOCK_CONNECTOR = ('<connector port="8446" clientAuth="false" _name="cert_https" '
                   'enableAdminUI="true"/>')


def _ns():
    ns = {'re': re}
    exec(_node_src('_TAK_8446_CONNECTOR_RE') + '\n' + _node_src('_tak_8446_connector_has_le'), ns)
    return ns


def _cfg(connector):
    return ('<Configuration xmlns="http://bbn.com/marti/xml/config">'
            '<network><connector port="8443" _name="https"/>' + connector +
            '<connector port="8089" _name="s"/></network></Configuration>')


def test_regex_matches_the_connector_it_writes_itself():
    ns = _ns()
    m = ns['_TAK_8446_CONNECTOR_RE'].search(_cfg(LE_CONNECTOR))
    assert m and m.group(0) == LE_CONNECTOR


def test_regex_still_matches_stock_and_namespaced_connectors():
    ns = _ns()
    rx = ns['_TAK_8446_CONNECTOR_RE']
    assert rx.search(_cfg(STOCK_CONNECTOR)).group(0) == STOCK_CONNECTOR
    ns0 = STOCK_CONNECTOR.replace('<connector', '<ns0:connector')
    assert rx.search(_cfg(ns0)).group(0) == ns0
    assert rx.search(_cfg(STOCK_CONNECTOR[:-2] + '/ >')) is not None


def test_regex_does_not_run_into_the_next_connector():
    rx = _ns()['_TAK_8446_CONNECTOR_RE']
    assert rx.search(_cfg(LE_CONNECTOR)).group(0).count('<connector') == 1


def test_replacing_a_stock_connector_gives_an_already_set_second_run():
    ns = _ns()
    rx, has_le = ns['_TAK_8446_CONNECTOR_RE'], ns['_tak_8446_connector_has_le']
    content = _cfg(STOCK_CONNECTOR)
    assert not has_le(content)
    first = rx.sub(lambda _m: LE_CONNECTOR, content, count=1)
    assert first != content and has_le(first)
    second = rx.sub(lambda _m: LE_CONNECTOR, first, count=1)
    assert second == first          # nothing to patch, and has_le says "already set"
    assert has_le(second)


def test_has_le_ignores_le_text_outside_the_8446_connector():
    has_le = _ns()['_tak_8446_connector_has_le']
    other = '<connector port="8443" _name="LetsEncrypt" keystoreFile="certs/files/takserver-le.jks"/>'
    assert not has_le(_cfg(STOCK_CONNECTOR).replace('<connector port="8443" _name="https"/>', other))
    assert not has_le('')
    assert not has_le(None)


def test_both_installers_log_already_set_instead_of_the_false_warning():
    host = _node_src('install_le_cert_on_8446')
    assert '_tak_8446_connector_has_le(content)' in host
    assert 'already set to the LE cert' in host
    assert '[^/]*/' not in host
    assert '[^/]*/' not in _node_src('_install_le_cert_on_8446_container')


def test_the_old_pattern_really_could_not_match_the_connector_we_write():
    old = re.compile(r'<(?:[A-Za-z][\w-]*:)?connector\s+port="8446"[^/]*/\s*>')
    assert old.search(_cfg(LE_CONNECTOR)) is None
