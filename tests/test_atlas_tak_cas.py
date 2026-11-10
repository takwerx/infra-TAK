# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""ATLAS W460: the TAK Server's CA certificates, handed to ATLAS."""

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import atlas_tak_cas as tc  # noqa: E402

NL = '\n'


def _block(tag):
    """A PEM-shaped block; `tag` makes it unique and tells the fake is_ca."""
    body = (tag * 20)[:64]
    return '-----BEGIN CERTIFICATE-----' + NL + body + NL + '-----END CERTIFICATE-----'


ROOT_CA, CA1, CA2, LEAF = _block('Uk9PVA'), _block('Q0Ex'), _block('Q0Ey'), _block('TEVBRg')
KEY_FILE_CA = _block('S0VZ')
#: Every block the fake calls a CA, the one in the .key file too: that one is
#: left out only because a .key file is never read.
CAS = {ROOT_CA, CA1, CA2, KEY_FILE_CA}
KEY = '-----BEGIN PRIVATE KEY-----' + NL + 'U0VDUkVU' + NL + '-----END PRIVATE KEY-----'


def fake_is_ca(pem):
    return pem.strip() in CAS


@pytest.fixture
def certs(tmp_path):
    d = tmp_path / 'files'
    d.mkdir()
    (d / 'root-ca.pem').write_text(ROOT_CA + NL)
    (d / 'INTERMEDIATE-CA-01.pem').write_text(CA1 + NL)
    # A -trusted file: a chain, repeating the root.
    (d / 'INTERMEDIATE-CA-02-trusted.pem').write_text(CA2 + NL + ROOT_CA + NL)
    # A user's certificate and key in one .pem.
    (d / 'admin.pem').write_text(KEY + NL + LEAF + NL)
    # Not a .pem: never read, whatever it holds.
    (d / 'takserver.key').write_text(KEY_FILE_CA + NL)
    return d


def test_the_bundle_is_the_root_then_each_ca_once(certs):
    bundle = tc.collect(str(certs), fake_is_ca)
    assert bundle.startswith(ROOT_CA)
    assert bundle.count('BEGIN CERTIFICATE') == 3
    assert CA1 in bundle and CA2 in bundle


def test_no_key_and_no_leaf_is_ever_written(certs):
    bundle = tc.collect(str(certs), fake_is_ca)
    assert 'PRIVATE KEY' not in bundle and 'U0VDUkVU' not in bundle
    assert LEAF not in bundle
    assert 'S0VZ' not in bundle  # from the .key file


def test_no_root_means_no_tak_server_here(certs):
    (certs / 'root-ca.pem').unlink()
    assert tc.collect(str(certs), fake_is_ca) is None
    assert tc.collect(str(certs / 'missing'), fake_is_ca) is None


def test_written_once_readable_by_the_container_and_unchanged_after(tmp_path, certs):
    bundle = tc.collect(str(certs), fake_is_ca)
    first = tc.write(str(tmp_path), bundle)
    path = tmp_path / tc.DIR / tc.FILE
    assert first == {'changed': True, 'recreated': False}
    assert path.read_text() == bundle
    if os.name == 'posix':
        assert oct(path.stat().st_mode & 0o777) == '0o644'
    assert tc.write(str(tmp_path), bundle) == {'changed': False, 'recreated': False}


def test_an_empty_folder_docker_made_as_root_is_made_again(tmp_path, monkeypatch):
    folder = tmp_path / tc.DIR
    folder.mkdir()
    real, removed = os.access, []
    real_rmdir = os.rmdir
    monkeypatch.setattr(tc.os, 'access',
                        lambda p, mode: False if str(p) == str(folder) else real(p, mode))
    monkeypatch.setattr(tc.os, 'rmdir', lambda p: (removed.append(str(p)), real_rmdir(p)))
    result = tc.write(str(tmp_path), ROOT_CA + NL)
    assert result == {'changed': True, 'recreated': True}
    assert removed == [str(folder)]
    assert (folder / tc.FILE).read_text() == ROOT_CA + NL


def test_a_folder_that_is_not_ours_and_not_empty_is_left_alone(tmp_path, monkeypatch, certs):
    folder = tmp_path / tc.DIR
    folder.mkdir()
    (folder / 'something').write_text('x')
    monkeypatch.setattr(tc.os, 'access', lambda p, mode: False)
    logs = []
    result = tc.refresh(str(tmp_path), logs.append, str(certs), fake_is_ca)
    assert result == {'changed': False, 'recreated': False}
    assert (folder / 'something').exists()
    assert any('Could not give ATLAS' in m for m in logs)


def test_refresh_says_how_many_and_never_raises(tmp_path, certs):
    logs = []
    assert tc.refresh(str(tmp_path), logs.append, str(certs), fake_is_ca)['changed']
    assert any('3 certificate(s), updated' in m for m in logs)
    logs.clear()
    tc.refresh(str(tmp_path), logs.append, str(tmp_path / 'none'), fake_is_ca)
    assert any('ATLAS lists every TAK Server CA' in m for m in logs)


@pytest.mark.skipif(shutil.which('openssl') is None, reason='needs openssl')
def test_openssl_tells_a_ca_from_a_leaf(tmp_path):
    def make(name, ca):
        ext = 'basicConstraints=critical,CA:TRUE' if ca else 'basicConstraints=critical,CA:FALSE'
        out = tmp_path / (name + '.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:prime256v1', '-nodes', '-keyout',
                        str(tmp_path / (name + '.key')), '-out', str(out), '-days', '1',
                        '-subj', '/CN=' + name, '-addext', ext],
                       check=True, capture_output=True)
        return out.read_text()
    assert tc.openssl_is_ca(make('ca', True))
    assert not tc.openssl_is_ca(make('leaf', False))
    assert not tc.openssl_is_ca('not a certificate')


def test_deploy_both_updates_and_a_rotation_refresh_it():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    # deploy, update, update with nothing to install, and every deployment
    # after a TAK CA rotation
    assert src.count('atlas_tak_cas.refresh(') == 4
    assert "'tak_ca_changed': tak_ca_changed," in src
    # Before the containers start or are rebuilt, so `api` mounts our folder.
    for marker in ('# ── 4/7 Start', "plog('━━━ Step 2/3: Rebuilding ━━━')"):
        at = src.index(marker)
        assert 'atlas_tak_cas.refresh(dirpath, plog)' in src[at - 600:at]
    app = (ROOT / 'app.py').read_text(encoding='utf-8')
    start = app.index('def _rotate_refresh_integrations(')
    end = app.index('\ndef ', start + 10)
    assert "get('tak_ca_changed')" in app[start:end]
    assert '_atlas_hook(mod_registry.get_ctx(), log)' in app[start:end]


def test_after_a_rotation_every_built_deployment_gets_the_list(tmp_path, monkeypatch, certs):
    import modules.atlas as atlas
    from modules import atlas_instances as ai

    plain, corona = ai.make(None, ai.MODE_FIXED, 100, 8760), ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    unbuilt = ai.make('unbuilt', ai.MODE_DYNAMIC, 50, 8762)
    dirs = {id(plain): tmp_path / 'atlas', id(corona): tmp_path / 'corona',
            id(unbuilt): tmp_path / 'unbuilt'}
    for d in dirs.values():
        d.mkdir()
    monkeypatch.setattr(atlas, 'load_instances', lambda ctx: [plain, corona, unbuilt])
    monkeypatch.setattr(atlas, 'compose_projects_present', lambda ctx: set())
    monkeypatch.setattr(atlas, 'instance_is_built', lambda ctx, inst, projects=None: inst is not unbuilt)
    monkeypatch.setattr(atlas, 'instance_paths', lambda ctx, inst: {'dir': str(dirs[id(inst)])})
    composed = []
    monkeypatch.setattr(atlas, '_compose', lambda ctx, action, timeout=180, inst=None: composed.append(action))
    real_refresh = tc.refresh
    monkeypatch.setattr(atlas.atlas_tak_cas, 'refresh',
                        lambda dirpath, plog: real_refresh(dirpath, plog, str(certs), fake_is_ca))
    logs = []

    atlas.tak_ca_changed({}, logs.append)

    for d in ('atlas', 'corona'):
        assert (tmp_path / d / tc.DIR / tc.FILE).read_text().count('BEGIN CERTIFICATE') == 3
    assert not (tmp_path / 'unbuilt' / tc.DIR).exists()
    assert composed == []  # nothing restarts: ATLAS reads the file at each page load


def test_a_folder_made_again_restarts_api_so_its_mount_follows():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    assert src.count("if _cas['recreated']:") == 2
    assert "if result['recreated']:" in src
