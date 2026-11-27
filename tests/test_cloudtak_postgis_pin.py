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
"""CloudTAK postgis pin (ops #110).

Upstream CloudTAK pins postgis/postgis:17-3.4-alpine, which Docker Hub stopped rebuilding on
2024-10-14 (PostgreSQL 17.0). The override pins a newer tag — same PG major, so no dump or
pg_upgrade — and the PostGIS extensions are updated once the new container is up.
arm64 runs the imresamu/postgis mirror (amd64 + arm64, Docker Hub 2026-10-20).

ops #1013 (2026-11-20): postgis/postgis stopped rebuilding 17-3.6 on 2026-10-26 (PostGIS 3.7 shipped),
so amd64 17-3.6-alpine stayed at PostgreSQL 17.11 (Alpine krb5-libs 1.22.2) after the Nov 12 minor
(17.12, about 60 fixes). amd64 is pinned to 17-3.7-alpine (PostgreSQL 17.12, krb5 1.22.3). imresamu has
no 17-3.7 tag, so arm64 stays on its 17-3.6 build, which it rebuilt on 2026-11-16 (PostgreSQL 17.12).
"""

import ast
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _func(name):
    return re.search(rf'^def {name}\(.*?(?=^def |^[A-Z_]+ = )', APP, re.S | re.M).group(0)


def _load(name, ns):
    src = ast.get_source_segment(APP, next(
        n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef) and n.name == name))
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns[name]


def test_pins():
    assert "POSTGIS_IMAGE = 'postgis/postgis:17-3.7-alpine'" in APP
    assert "POSTGIS_IMAGE_ARM64 = 'imresamu/postgis:17-3.6-alpine'" in APP
    assert APP.index('POSTGIS_IMAGE = ') < APP.index('def _cloudtak_build_override_yml(')


def _pin(name):
    m = re.search(rf"^{name} = '([^']+)'", APP, re.M)
    assert m, f'{name} is gone: re-point this test'
    return m.group(1)


def _tag(image):
    m = re.fullmatch(r'(postgis/postgis|imresamu/postgis):(\d+)-(\d+)\.(\d+)-alpine', image)
    assert m, f'{image!r} is not a PG-PostGIS-alpine floating tag the converge can follow'
    return m.group(1), int(m.group(2)), (int(m.group(3)), int(m.group(4)))


# Tags a publisher no longer rebuilds, so the image never gets a PostgreSQL minor again. Each is
# frozen at the PostgreSQL minor named, read from the image itself on Docker Hub.
FROZEN_AMD64_TAGS = {
    'postgis/postgis:17-3.4-alpine': '17.0 (stopped 2024-10-14)',
    'postgis/postgis:17-3.5-alpine': 'below 17.11',
    'postgis/postgis:17-3.6-alpine': '17.11 (stopped 2026-10-26, ops #1013)',
}


def test_amd64_pin_is_a_tag_the_publisher_still_rebuilds():
    # ops #1013: 17-3.6-alpine on amd64 held PostgreSQL 17.11 after 17.12 (Nov 12) shipped.
    image = _pin('POSTGIS_IMAGE')
    assert image not in FROZEN_AMD64_TAGS, f'{image} is frozen at PostgreSQL {FROZEN_AMD64_TAGS[image]}'
    repo, major, postgis = _tag(image)
    assert repo == 'postgis/postgis' and major == 17
    assert postgis >= (3, 7)


def test_arm64_pin_is_the_mirror_on_the_same_postgresql_major():
    # the data volume is shared by both arches' images, so the PG major must match; imresamu has
    # no 17-3.7 tag yet (Docker Hub 2026-11-20), so PostGIS may trail amd64 by one minor
    a_repo, a_major, a_gis = _tag(_pin('POSTGIS_IMAGE'))
    b_repo, b_major, b_gis = _tag(_pin('POSTGIS_IMAGE_ARM64'))
    assert b_repo == 'imresamu/postgis' and b_major == a_major
    assert b_gis >= (3, 6) and b_gis <= a_gis


def test_pinned_postgresql_major_is_one_the_security_table_checks():
    # the converge and the update email judge the running database against POSTGRES_SECURITY_RELEASES;
    # a major the table does not list claims nothing, so the pin must stay on a listed one
    _, major, _ = _tag(_pin('POSTGIS_IMAGE'))
    ns = {}
    exec(compile(re.search(r'^POSTGRES_SECURITY_RELEASES = \(.*?^\)', APP, re.S | re.M).group(0),
                 'app.py', 'exec'), ns)
    assert all(major in rel['fixed'] for rel in ns['POSTGRES_SECURITY_RELEASES'])


def test_override_pins_postgis_image():
    body = _func('_cloudtak_build_override_yml')
    post = body.split('  postgis:\n', 1)[1]
    # ops #1335: the image line is '' when the data is on a newer PostgreSQL than the pin
    assert '{postgis_image_line}' in post.split('environment:')[0]
    assert "postgis_image_line = f'    image: {postgis_image}\\n' if postgis_image else ''" in body
    # arm64 only for a CloudTAK on this box — the console can't see a remote host's arch
    assert ("postgis_image = POSTGIS_IMAGE_ARM64 if (not _ct_is_remote and _host_arch() == 'arm64') "
            "else POSTGIS_IMAGE") in body


def _upgrade_fn(ps_out, exec_out, calls):
    def run(argv, **kw):
        calls.append(argv)
        out = ps_out if 'ps' in argv else exec_out
        return types.SimpleNamespace(stdout=out, stderr='', returncode=0)
    ns = {'subprocess': types.SimpleNamespace(run=run), '_sudo_wrap': lambda a: a,
          '_CT_POSTGIS_EXT_UPGRADE_SH': 'SCRIPT', '_b64': None, '_ssh_probe': None}
    return _load('_cloudtak_postgis_extensions_upgrade', ns)


def test_upgrade_reports_each_database():
    calls, logs = [], []
    fn = _upgrade_fn('abc123\n', 'UPGRADED gis: postgis 3.4.3 -> 3.6.0\nUPGRADED template_postgis: '
                     'postgis 3.4.3 -> 3.6.0\nDONE\n', calls)
    assert fn(plog=logs.append) is True
    assert calls[1] == ['docker', 'exec', 'abc123', 'sh', '-c', 'SCRIPT']
    assert sum('✓ PostGIS extensions updated' in l for l in logs) == 2


def test_upgrade_is_quiet_when_converged():
    logs = []
    assert _upgrade_fn('abc123\n', 'DONE\n', [])(plog=logs.append) is True
    assert logs == []


def test_upgrade_failure_and_not_ready_are_surfaced():
    logs = []
    assert _upgrade_fn('abc\n', 'FAILED gis: postgis 3.4.3 -> 3.6.0\nDONE\n', [])(plog=logs.append) is False
    assert any('⚠ PostGIS extension update failed in gis' in l for l in logs)
    logs = []
    assert _upgrade_fn('abc\n', 'NOTREADY\n', [])(plog=logs.append) is False
    assert any('inconclusive (NOTREADY)' in l for l in logs)


def test_no_container_is_not_an_error():
    calls = []
    assert _upgrade_fn('', '', calls)() is False
    assert len(calls) == 1


def test_script_checks_before_it_upgrades():
    sh = re.search(r"^_CT_POSTGIS_EXT_UPGRADE_SH = r'''(.*?)'''", APP, re.S | re.M).group(1)
    assert 'pg_isready' in sh
    assert sh.index('[ -n "$V" ] || continue') < sh.index('postgis_extensions_upgrade()')
    assert 'datallowconn' in sh and 'echo DONE' in sh


def test_upgrade_runs_after_every_path_that_can_swap_the_image():
    # console Update (boot thread after the startup override refresh), CloudTAK Update/rebuild,
    # and the remote post-update override refresh
    assert len(re.findall(r'^\s+_cloudtak_postgis_extensions_upgrade\(', APP, re.M)) == 3
    boot = APP[APP.index('def _startup_postgis_sync'):][:900]
    assert boot.index('_cloudtak_sync_postgis_password(') < boot.index('_cloudtak_postgis_extensions_upgrade(')


def test_startup_refresh_prepulls_postgis_before_recreate():
    # ops #197: the startup recreate goes through the shared helper, asking it to pull first
    assert 'pull=_override_changed or _pending is not None' in _func('_startup_harden_cloudtak_ports')
    body = _func('_cloudtak_recreate_and_heal')
    assert "services=['postgis']" in body
    assert body.index("services=['postgis']") < body.index("'up', '-d', '--force-recreate'")
