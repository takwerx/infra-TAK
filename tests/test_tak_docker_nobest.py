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
"""TAK's hardened (UBI 10) Docker image builds again: `microdnf update --nobest`.

Field 2026-10-14: every new Docker TAK install failed at the takserver image build — TAK's
Dockerfile excludes openssl* during `microdnf update`, and Red Hat's newer curl requires an
OpenSSL >= 3.5.8. Measured fix: `--nobest` (the update completes, OpenSSL stays pinned, curl is
simply not upgraded). These tests pin the patch to exactly that line and to both build paths.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

SHIPPED = '''FROM ${BASE_REGISTRY}/${BASE_DEPLOY_IMAGE}:${BASE_DEPLOY_TAG} AS deploy_container
RUN echo -e "\\nexclude=openssl* openssl-fips-provider*" >> /etc/dnf/dnf.conf

RUN microdnf update -y --disableplugin=subscription-manager --nodocs && \\
    microdnf install -y --disableplugin=subscription-manager --nodocs \\
        net-tools \\
        netcat \\
    && microdnf clean all

RUN sed -i '/exclude=openssl\\*/d' /etc/dnf/dnf.conf
'''


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, name
    return m.group(0)


def _patcher():
    import os
    ns = {'os': os, 're': re, 'print': lambda *a, **k: None}
    exec(compile(_fn('_patch_tak_hardened_dockerfile'), 'app.py', 'exec'), ns)
    return ns['_patch_tak_hardened_dockerfile']


def _ctx(tmp_path, app=SHIPPED, db=None):
    d = tmp_path / 'docker'
    d.mkdir()
    (d / 'Dockerfile.hardened-takserver').write_text(app)
    if db is not None:
        (d / 'Dockerfile.hardened-takserver-db').write_text(db)
    return str(tmp_path), ('docker/Dockerfile.hardened-takserver', 'docker/Dockerfile.hardened-takserver-db')


def test_adds_nobest_to_the_update_line_only(tmp_path):
    ctx, dfs = _ctx(tmp_path)
    logs = []
    assert _patcher()(ctx, dfs, logs.append) is True
    out = (tmp_path / 'docker/Dockerfile.hardened-takserver').read_text()
    assert 'RUN microdnf update -y --nobest --disableplugin=subscription-manager --nodocs && \\' in out
    assert out.count('--nobest') == 1
    # nothing else moves: the OpenSSL pin, the install list and its removal are as shipped
    assert out.replace(' --nobest', '', 1) == SHIPPED
    assert logs and 'microdnf update --nobest' in logs[0]


def test_idempotent(tmp_path):
    ctx, dfs = _ctx(tmp_path)
    f = _patcher()
    f(ctx, dfs, lambda m: None)
    once = (tmp_path / 'docker/Dockerfile.hardened-takserver').read_text()
    assert f(ctx, dfs, lambda m: None) is False
    assert (tmp_path / 'docker/Dockerfile.hardened-takserver').read_text() == once


def test_a_dockerfile_without_the_line_is_left_as_shipped(tmp_path):
    other = 'FROM postgres:15.1\nRUN apt-get update && apt install -y postgresql-15-postgis-3\n'
    ctx, dfs = _ctx(tmp_path, app=other, db=other)
    assert _patcher()(ctx, dfs, lambda m: None) is False
    assert (tmp_path / 'docker/Dockerfile.hardened-takserver').read_text() == other


def test_missing_files_and_none_entries_are_fine(tmp_path):
    (tmp_path / 'docker').mkdir()
    assert _patcher()(str(tmp_path), ('docker/nope', None, ''), lambda m: None) is False


def test_both_build_paths_patch_before_building():
    deploy = APP[APP.index('━━━ Step 3/9: Building TAK Server images ━━━'):]
    deploy = deploy[:deploy.index('✓ Images built')]
    assert deploy.index('_patch_tak_hardened_dockerfile(build_ctx, (_app_df, _db_df), log_step)') \
        < deploy.index('docker build -t takserver_db')
    upgrade = APP[APP.index('Step 4/6: Building new TAK Server images'):]
    upgrade = upgrade[:upgrade.index('✓ Images built')]
    assert upgrade.index('_patch_tak_hardened_dockerfile(new_ctx, (_app_df, _db_df), ulog)') \
        < upgrade.index('docker build -t takserver_db')
