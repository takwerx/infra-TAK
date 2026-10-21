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
"""Rotate Intermediate CA re-issues client certs only, never CA or signing material.

Every `makeCert.sh ca` run leaves NAME.crl, truststore-NAME.jks and NAME-signing.p12 in
/opt/tak/certs/files. The client-cert loop used to skip only the old and new CA names, so on a
box rotated many times it re-issued INT-CA-01..0N-signing as client certs — including the live
enrollment signing keystore, which then held a second, non-CA private key.
"""

import ast
import os
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _names(cert_dir, skip=()):
    ns = {'os': os}
    exec(compile(_func('_rotate_client_cert_names'), 'app.py', 'exec'), ns)
    return ns['_rotate_client_cert_names'](str(cert_dir), skip=skip)


def _ca(d, name, signing_p12=True):
    """The files `makeCert.sh ca NAME` writes."""
    for ext in ('.crl', '.csr', '.key', '.pem', '-trusted.pem', '-signing.jks', '-signing.pem'):
        (d / f'{name}{ext}').write_text('x')
    if signing_p12:
        (d / f'{name}-signing.p12').write_text('x')
    (d / f'truststore-{name}.jks').write_text('x')
    (d / f'truststore-{name}.p12').write_text('x')


def _client(d, name):
    for ext in ('.csr', '.jks', '.key', '.p12', '.pem', '-trusted.pem'):
        (d / f'{name}{ext}').write_text('x')


CLIENTS = ['ADSB_PS', 'admin', 'cloudtak-svc-bootstrap', 'nodered-global-tisb', 'user']


@pytest.fixture
def rotated_many_times(tmp_path):
    """test8's layout on Oct 19: nine intermediates, the current one INT-CA-09."""
    for f in ('root-ca.pem', 'root-ca-do-not-share.key', 'truststore-root.jks', 'truststore-root.p12',
              'ca.pem', 'ca.crl', 'ca-do-not-share.key', 'fed-truststore.jks'):
        (tmp_path / f).write_text('x')
    for i in range(1, 10):
        _ca(tmp_path, f'INT-CA-0{i}')
    _client(tmp_path, 'takserver')
    for c in CLIENTS:
        _client(tmp_path, c)
    return tmp_path


def test_old_intermediates_and_signing_keystores_are_not_reissued(rotated_many_times):
    got = _names(rotated_many_times, skip=('INT-CA-09', 'INT-CA-10'))
    assert got == sorted(CLIENTS)


def test_the_live_signing_keystore_is_skipped_even_without_the_skip_list(rotated_many_times):
    got = _names(rotated_many_times)
    assert not any('INT-CA' in n for n in got), got
    assert 'takserver' not in got


def test_the_new_ca_made_in_step_2_is_skipped(rotated_many_times):
    _ca(rotated_many_times, 'INT-CA-10')
    assert _names(rotated_many_times, skip=('INT-CA-09', 'INT-CA-10')) == sorted(CLIENTS)


def test_a_ca_found_only_by_its_truststore_or_crl_is_still_skipped(tmp_path):
    _ca(tmp_path, 'OLD-A')
    (tmp_path / 'OLD-A.crl').unlink()
    _ca(tmp_path, 'OLD-B')
    (tmp_path / 'truststore-OLD-B.jks').unlink()
    _client(tmp_path, 'admin')
    assert _names(tmp_path) == ['admin']


def test_case_differences_do_not_let_a_ca_through(tmp_path):
    _ca(tmp_path, 'int-ca-01')
    _client(tmp_path, 'admin')
    assert _names(tmp_path, skip=('INT-CA-01',)) == ['admin']


def test_a_client_that_merely_ends_in_signing_is_still_reissued(tmp_path):
    _client(tmp_path, 'doc-signing')
    _client(tmp_path, 'admin')
    assert _names(tmp_path) == ['admin', 'doc-signing']


def test_rotate_uses_the_helper():
    body = _func('takserver_rotate_intca')
    assert '_rotate_client_cert_names(cert_dir, skip=(old_ca_name, new_ca_name))' in body
    assert "f.endswith('.p12')" not in body, 'rotate grew its own .p12 loop again'
