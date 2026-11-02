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
"""GH #352 — TAK Server would not install on Ubuntu Pro boxes.

PGDG's PostGIS needs PGDG's own GDAL/GEOS/PROJ. Ubuntu Pro pins its ESM copies at 510,
so apt chose ESM's gdal-data 3.8.4 next to PGDG's libgdal39 and refused the install:
  libgdal39 : Depends: gdal-data (>= 3.13.3+dfsg-2.pgdg24.04+1) but 3.8.4+dfsg-3ubuntu3+esm1 is to be installed
infra-TAK now writes /etc/apt/preferences.d/infratak-pgdg-gis (PGDG GIS stack at 600) on
every Debian-family path that installs PostGIS: the single-box deploy, the TAK upgrade, the
two-server Server One over SSH and the printed Server One runbook.
"""

import fnmatch
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _pgdg_block():
    """The PGDG constants through _PGDG_REMOTE_SETUP_SH, executed on their own."""
    import shlex
    ns = {'shlex': shlex}
    m = re.search(r"^_APT_CODENAME_SH = .*?\n(?=\n)", APP, re.S | re.M)
    exec(m.group(0), ns)
    s = APP[APP.index('_PGDG_APT_HOST = '):]
    s = s[:s.index('\n)\n', s.index('_PGDG_REMOTE_SETUP_SH = (')) + 3]
    exec(s, ns)
    return ns


NS = _pgdg_block()
BODY = NS['_PGDG_GIS_PIN_BODY']


def _stanzas():
    out = []
    for block in BODY.split('\n\n'):
        fields = {}
        for ln in block.splitlines():
            if ln.startswith('#') or not ln.strip():
                continue
            k, _, v = ln.partition(':')
            fields[k.strip()] = v.strip()
        out.append(fields)
    return out


def test_pin_targets_pgdg_above_ubuntu_pro_without_downgrades():
    assert len(_stanzas()) == 2
    for f in _stanzas():
        assert set(f) == {'Package', 'Pin', 'Pin-Priority'}
        # the Origin field of apt.postgresql.org's Release file (checked on test6, noble-pgdg)
        assert f['Pin'] == 'release o=apt.postgresql.org'
        # above ubuntu-pro-esm-{apps,infra} (510); below 1000 so an installed version is never downgraded
        assert 510 < int(f['Pin-Priority']) < 1000


def test_pin_covers_the_postgis_stack_and_postgresql_shared_packages_only():
    globs = [g for f in _stanzas() for g in f['Package'].split()]
    hit = lambda p: any(fnmatch.fnmatchcase(p, g) for g in globs)
    # the packages in the field error, plus what PGDG's postgresql-15-postgis-3 3.7 / libgdal39 pull
    for p in ('gdal-data', 'gdal-plugins', 'libgdal39', 'libgeos-c1t64', 'libproj25', 'proj-data',
              'libsfcgal2', 'python3-gdal'):
        assert hit(p), p
    # shared packages PGDG's postgresql-<major> needs PGDG versions of (postgresql-common >= 241)
    for p in ('postgresql-common', 'postgresql-client-common', 'libpq5'):
        assert hit(p), p
    # the server packages themselves exist only in PGDG (or are versioned apart) — not pinned
    for p in ('postgresql-15', 'postgresql-15-postgis-3', 'postgresql-client-15', 'openjdk-17-jdk'):
        assert not hit(p), p


def test_body_is_printf_safe_and_remote_fragment_writes_it_verbatim():
    assert "'" not in BODY and '%' not in BODY and '\\' not in BODY
    frag = NS['_PGDG_REMOTE_SETUP_SH']
    assert frag.endswith('&& ')
    m = re.search(r"printf '(.*?)' \| sudo tee /etc/apt/preferences\.d/infratak-pgdg-gis >/dev/null && $", frag, re.S)
    assert m, frag[-300:]
    out = subprocess.run(['bash', '-c', "printf '" + m.group(1) + "'"], capture_output=True, text=True).stdout
    assert out == BODY
    # written after the PGDG source, before the caller's apt-get update + install
    assert frag.index('pgdg main') < frag.index('infratak-pgdg-gis')


def _ensure_ns(family='debian', existing=None, write_raises=False):
    writes, logs = [], []

    class _F:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self.body

    def fake_open(path, mode='r', *a, **k):
        if path == NS['_PGDG_GIS_PIN'] and existing is not None:
            return _F(existing)
        raise FileNotFoundError(path)

    def fake_write(path, content, *a, **k):
        if write_raises:
            raise RuntimeError('broker write denied')
        writes.append((path, content))

    ns = dict(NS, _distro_family=lambda: family, _write_priv=fake_write, open=fake_open)
    exec(_fn('_pgdg_gis_pin_ensure'), ns)
    return ns['_pgdg_gis_pin_ensure'], writes, logs


def test_ensure_writes_once_and_is_idempotent():
    ensure, writes, logs = _ensure_ns()
    assert ensure(logs.append) is True
    assert writes == [('/etc/apt/preferences.d/infratak-pgdg-gis', BODY)]
    assert any('infratak-pgdg-gis' in l for l in logs)

    ensure, writes, logs = _ensure_ns(existing=BODY)
    assert ensure(logs.append) is True and writes == [] and logs == []

    ensure, writes, _ = _ensure_ns(existing='Package: gdal-*\nPin: release o=apt.postgresql.org\nPin-Priority: 500\n')
    assert ensure() is True and writes == [('/etc/apt/preferences.d/infratak-pgdg-gis', BODY)]


def test_ensure_skips_rhel_and_never_raises():
    ensure, writes, _ = _ensure_ns(family='rhel')
    assert ensure() is False and writes == []
    ensure, writes, logs = _ensure_ns(write_raises=True)
    assert ensure(logs.append) is False
    assert any('could not write' in l for l in logs)


def test_every_debian_postgis_path_writes_the_pin():
    # single-box deploy: before the apt-get update that precedes Step 4's install
    body = _fn('_setup_pgdg_apt_source')
    assert body.index('_pgdg_gis_pin_ensure(log_step)') < body.index('_apt_update_capture()')
    # TAK upgrade: before apt-get install of the new .deb
    body = _fn('_tak_upgrade_apt_install')
    assert body.index('_pgdg_gis_pin_ensure(') < body.index("apt-get install -y ./")
    # 5.7 -> 5.8 upgrade: right before its apt-get install command is built
    i = APP.index("'--allow-change-held-packages ' + shlex.quote(pkg_path)")
    assert '_pgdg_gis_pin_ensure(_say)' in APP[i - 300:i]
    # two-server Server One: both remote install chains use the fragment
    assert APP.count('+ _PGDG_REMOTE_SETUP_SH +') >= 2
    # printed Server One runbook: pin line sits before `sudo apt update`
    i = APP.index("'# Server One: Database Server',")
    block = APP[i:APP.index('sudo apt install -y ./', i)]
    assert block.index('_PGDG_GIS_PIN_BODY') < block.index("'sudo apt update'")
