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
"""TAK's hardened DB image builds again after a new RHEL minor (ops #686).

Field 2026-11-12: the DB image's own `dnf update` takes UBI 10.2 to RHEL 10.3, PGDG has no
rhel-10.3 folder yet, and `docker build` of takserver_db 404s on pgdg-common. The fix puts
the PGDG repo files on PGDG's rhel-<major> folder right after the repo rpm is installed.
These tests pin the patch to TAK's real Dockerfile lines (5.8-RELEASE-75), run the generated
sed over the real PGDG repo text, and check both build paths call it before `docker build`.
"""

import ast
import os
import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

# The lines around the failure in Dockerfile.hardened-takserver-db, 5.8-RELEASE-75, as shipped.
SHIPPED_DB = '''FROM registry.access.redhat.com/ubi10/ubi:10.2
RUN dnf update -y && \\
    dnf install -y cracklib-dicts nss

# Install dependencies
RUN curl -fsSL -o /tmp/pgdg-repo.rpm "https://download.postgresql.org/pub/repos/yum/reporpms/EL-10-$(cat /tmp/buildarch)/pgdg-redhat-repo-latest.noarch.rpm" && \\
    rpm -Uvh --nodeps /tmp/pgdg-repo.rpm && \\
    rm -f /tmp/pgdg-repo.rpm

RUN dnf install -y "https://download.postgresql.org/pub/repos/yum/reporpms/EL-10-$(cat /tmp/buildarch)/pgdg-redhat-repo-latest.noarch.rpm"

RUN dnf -v -y updateinfo list cves && \\
    dnf -v -y update --security && \\
    dnf -v -y upgrade --nodocs --exclude='openssl*' --exclude='openssl-fips-provider*' --exclude='pgdg-redhat-repo*'

RUN dnf -v -y install --nodocs \\
        postgresql18-server postgresql18 glibc-locale-source \\
        postgis36_18
'''

# Two sections of pgdg-redhat-all.repo from pgdg-redhat-repo-42.0-69 (EL-10), as shipped,
# plus the older single-variable form.
PGDG_REPO = '''# $releasever_major and $releasever_minor come from the installed OS release
[pgdg-common]
name=PostgreSQL common RPMs for RHEL / Rocky Linux / AlmaLinux $releasever_major.$releasever_minor - $basearch
baseurl=https://download.postgresql.org/pub/repos/yum/common/redhat/rhel-$releasever_major.$releasever_minor-$basearch
enabled=1

[pgdg18]
name=PostgreSQL 18 for RHEL / Rocky Linux / AlmaLinux $releasever_major.$releasever_minor - $basearch
baseurl=https://download.postgresql.org/pub/repos/yum/18/redhat/rhel-$releasever_major.$releasever_minor-$basearch
enabled=1

[pgdg-old]
baseurl=https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-$releasever-$basearch
'''


def _ns():
    want = {'_PGDG_MAJOR_MARK', '_PGDG_MAJOR_STEP', '_patch_tak_db_pgdg_releasever'}
    nodes = [n for n in ast.parse(APP).body
             if (isinstance(n, ast.FunctionDef) and n.name in want)
             or (isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in want for t in n.targets))]
    assert len(nodes) == len(want)
    ns = {'os': os, 're': re, 'print': lambda *a, **k: None}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'app.py', 'exec'), ns)
    return ns


def _ctx(tmp_path, db=SHIPPED_DB):
    d = tmp_path / 'docker'
    d.mkdir()
    (d / 'Dockerfile.hardened-takserver-db').write_text(db)
    return str(tmp_path), 'docker/Dockerfile.hardened-takserver-db'


def test_step_lands_after_the_repo_rpm_and_before_the_first_dnf_that_reads_pgdg(tmp_path):
    ctx, df = _ctx(tmp_path)
    ns, logs = _ns(), []
    assert ns['_patch_tak_db_pgdg_releasever'](ctx, df, logs.append) is True
    out = (tmp_path / df).read_text()
    step = ns['_PGDG_MAJOR_STEP']
    first = out.index(step)
    # after the curl + rpm -Uvh block ends (its last continuation line) …
    assert out.index('rm -f /tmp/pgdg-repo.rpm\n') < first
    # … and before the `dnf install` of the repo rpm, which is what 404'd in the field
    assert first < out.index('RUN dnf install -y "https://download.postgresql.org')
    # once more after that dnf install (it could replace the repo file), and nowhere else
    assert out.count(step) == 2
    assert out.index(step, first + 1) < out.index('RUN dnf -v -y updateinfo')
    # nothing of TAK's own text moves
    assert out.replace(step, '') == SHIPPED_DB
    assert logs and 'RHEL major version' in logs[0]


def test_idempotent(tmp_path):
    ctx, df = _ctx(tmp_path)
    f = _ns()['_patch_tak_db_pgdg_releasever']
    f(ctx, df, lambda m: None)
    once = (tmp_path / df).read_text()
    assert f(ctx, df, lambda m: None) is False
    assert (tmp_path / df).read_text() == once


def test_a_dockerfile_without_the_pgdg_rpm_is_left_as_shipped(tmp_path):
    # the pre-5.8 Debian DB image, and the exclude= line alone, are not a repo install
    other = ('FROM postgres:15.1\nRUN apt-get update && apt install -y postgresql-15-postgis-3\n'
             "RUN dnf -y upgrade --exclude='pgdg-redhat-repo*'\n")
    ctx, df = _ctx(tmp_path, db=other)
    assert _ns()['_patch_tak_db_pgdg_releasever'](ctx, df, lambda m: None) is False
    assert (tmp_path / df).read_text() == other


def test_missing_file_and_none_are_fine(tmp_path):
    f = _ns()['_patch_tak_db_pgdg_releasever']
    assert f(str(tmp_path), None, lambda m: None) is False
    assert f(str(tmp_path), 'docker/nope', lambda m: None) is False


@pytest.mark.skipif(not shutil.which('bash') or not shutil.which('sed'), reason='needs bash and sed')
def test_the_step_rewrites_every_pgdg_baseurl_to_the_major_folder(tmp_path):
    """Run the RUN line itself over the real repo text: every baseurl goes to rhel-10-$basearch,
    both variable forms, and nothing but baseurl changes. Without the patch the URL dnf builds is
    rhel-10.3-aarch64, which 404'd on 2026-11-12."""
    step = _ns()['_PGDG_MAJOR_STEP']
    run = [ln for ln in step.splitlines() if ln.startswith('RUN ')][0][len('RUN '):]
    repos = tmp_path / 'etc/yum.repos.d'
    repos.mkdir(parents=True)
    (repos / 'pgdg-redhat-all.repo').write_text(PGDG_REPO)
    (repos / 'ubi.repo').write_text('baseurl=https://cdn-ubi.redhat.com/rhel-$releasever-$basearch\n')
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    (bindir / 'rpm').write_text('#!/bin/sh\n[ "$1 $2" = "-E %rhel" ] && echo 10\n')
    (bindir / 'rpm').chmod(0o755)
    # GNU sed -i and BSD sed -i differ; give the test a GNU-style sed on macOS runs too
    if subprocess.run(['sed', '--version'], capture_output=True).returncode != 0:
        (bindir / 'sed').write_text('#!/bin/sh\n[ "$1" = "-i" ] && exec /usr/bin/sed -i "" "$2" "$3"\n'
                                    'exec /usr/bin/sed "$@"\n')
        (bindir / 'sed').chmod(0o755)
    script = run.replace('/etc/yum.repos.d/', str(repos) + '/')
    r = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                       env={**os.environ, 'PATH': f'{bindir}:{os.environ["PATH"]}'})
    assert r.returncode == 0, r.stderr
    out = (repos / 'pgdg-redhat-all.repo').read_text()
    urls = [ln for ln in out.splitlines() if ln.startswith('baseurl=')]
    assert urls == [
        'baseurl=https://download.postgresql.org/pub/repos/yum/common/redhat/rhel-10-$basearch',
        'baseurl=https://download.postgresql.org/pub/repos/yum/18/redhat/rhel-10-$basearch',
        'baseurl=https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-10-$basearch',
    ]
    keep = lambda t: [ln for ln in t.splitlines() if not ln.startswith('baseurl=')]
    assert keep(out) == keep(PGDG_REPO)
    # only PGDG's files: UBI's own repo keeps $releasever
    assert '$releasever' in (repos / 'ubi.repo').read_text()


def test_both_build_paths_patch_the_db_dockerfile_before_building():
    deploy = APP[APP.index('━━━ Step 3/9: Building TAK Server images ━━━'):]
    deploy = deploy[:deploy.index('✓ Images built')]
    assert deploy.index('_patch_tak_db_pgdg_releasever(build_ctx, _db_df, log_step)') \
        < deploy.index('docker build -t takserver_db')
    upgrade = APP[APP.index('Step 4/6: Building new TAK Server images'):]
    upgrade = upgrade[:upgrade.index('✓ Images built')]
    assert upgrade.index('_patch_tak_db_pgdg_releasever(new_ctx, _db_df, ulog)') \
        < upgrade.index('docker build -t takserver_db')
