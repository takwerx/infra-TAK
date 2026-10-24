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
2024-10-14 (PostgreSQL 17.0). The override pins 17-3.6-alpine — same PG major, so no dump or
pg_upgrade — and the PostGIS extensions are updated 3.4 → 3.6 once the new container is up.
arm64 runs the imresamu/postgis mirror of the same tag (amd64 + arm64, Docker Hub 2026-10-20).
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
    assert "POSTGIS_IMAGE = 'postgis/postgis:17-3.6-alpine'" in APP
    assert "POSTGIS_IMAGE_ARM64 = 'imresamu/postgis:17-3.6-alpine'" in APP
    assert APP.index('POSTGIS_IMAGE = ') < APP.index('def _cloudtak_build_override_yml(')


def test_override_pins_postgis_image():
    body = _func('_cloudtak_build_override_yml')
    post = body.split('  postgis:\n', 1)[1]
    assert 'image: {postgis_image}' in post.split('environment:')[0]
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
