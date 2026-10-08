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
"""Container TAK: the takserver_db image builds again after PostgreSQL archived bullseye (v10.2.7, GH #84).

Field (GH #84, 2026-10-06, reported from Armbian/ARM64 — not arch- or OS-specific):
    Err:5 http://apt.postgresql.org/pub/repos/apt bullseye-pgdg Release  404  Not Found
    ✗ takserver_db image build failed.
postgres:15.1's own pgdg.list points at apt.postgresql.org; bullseye now lives on
apt-archive.postgresql.org, which is https-only, and the base image has no CA bundle.
"""

import ast
import os
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

BBN = """FROM postgres:15.1

# this is slow - updates all packages
RUN apt-get update && apt install -y postgresql-15-postgis-3 openjdk-17-jdk

ENTRYPOINT ["/opt/tak/db-utils/configureInDocker.sh"]
"""
GH69_ONLY = BBN.replace(
    "RUN apt-get update && apt install -y postgresql-15-postgis-3 openjdk-17-jdk",
    "RUN sed -i -e '/debian-security/d' -e 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g'"
    " /etc/apt/sources.list && apt-get -o Acquire::Check-Valid-Until=false update"
    " && apt-get -o Acquire::Check-Valid-Until=false install -y postgresql-15-postgis-3 openjdk-17-jdk")


def _patch():
    fn = [n for n in ast.parse(APP).body
          if isinstance(n, ast.FunctionDef) and n.name == '_patch_tak_db_dockerfile'][0]
    ns = {'os': os, 're': re}
    exec(ast.get_source_segment(APP, fn), ns)
    return ns['_patch_tak_db_dockerfile']


def _ctx(tmp_path, body):
    (tmp_path / 'docker').mkdir()
    (tmp_path / 'docker' / 'Dockerfile.takserver-db').write_text(body)
    return tmp_path / 'docker' / 'Dockerfile.takserver-db'


def _run_line(df):
    return [l for l in df.read_text().splitlines() if l.startswith('RUN ')][0]


def test_bbn_line_gets_debian_archive_ca_bundle_then_pgdg_archive(tmp_path):
    df = _ctx(tmp_path, BBN)
    assert _patch()(str(tmp_path), lambda m: None) is True
    run = _run_line(df)
    order = [run.index(x) for x in (
        "'/debian-security/d'",
        'http://archive.debian.org/debian',
        'mv /etc/apt/sources.list.d/pgdg.list /tmp/pgdg.list',
        'install -y --no-install-recommends ca-certificates',
        "sed 's|http://apt.postgresql.org/|https://apt-archive.postgresql.org/|'",
        'install -y postgresql-15-postgis-3 openjdk-17-jdk')]
    assert order == sorted(order)
    # TLS verification is never switched off to get there
    assert 'Verify-Peer' not in run and 'Verify-Host' not in run and 'AllowInsecure' not in run
    assert 'ENTRYPOINT ["/opt/tak/db-utils/configureInDocker.sh"]' in df.read_text()


def test_idempotent_and_repatches_a_gh69_only_tree(tmp_path):
    df = _ctx(tmp_path, GH69_ONLY)
    p = _patch()
    assert p(str(tmp_path), lambda m: None) is True        # GH #69-only line is upgraded
    once = df.read_text()
    assert 'apt-archive.postgresql.org' in once and once.count('RUN ') == 1
    assert p(str(tmp_path), lambda m: None) is False       # second pass: no-op
    assert df.read_text() == once


def test_unrecognised_install_line_is_left_as_shipped(tmp_path):
    body = BBN.replace('RUN apt-get update && apt install -y', 'RUN something-else')
    df = _ctx(tmp_path, body)
    assert _patch()(str(tmp_path), lambda m: None) is False
    assert df.read_text() == body
