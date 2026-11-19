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
"""ops #969 / infra-TAK #589 — saving the schedule or login of an ETL layer fails in CloudTAK.

Every ETL layer infra-TAK makes is server-wide (connection 0). CloudTAK's UI saves it with
PATCH /api/connection/0/layer/ID/incoming (and /outgoing). Those two routes declare
`connectionid: Type.Integer({ minimum: 1 })` and have no connection-0 branch, so the save is
refused with "Validation Error" (400; once the limit is relaxed, 404). Reported upstream as
dfpc-coe/CloudTAK#2042. _cloudtak_etl_layer_heal gives the two routes the branch their sibling
routes already have (admin only, the layer must have no connection) in the running api container.

The first half runs the SHIPPED script (_CT_ETL_LAYER_SH, text taken from app.py) against
tests/fixtures/cloudtak-13.124.0-connection-layer-routes.mjs, a trimmed copy of the real compiled
route file from CloudTAK 13.124.0, then calls the patched handlers with node (the harness fakes
only the framework). The second half runs the shipped Python heal with docker faked.
app.py cannot be imported in a test, so this reads the shipped text.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_cloudtak_autorepair_ops197 import Box, PINNED_MEDIA, _converged  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
FIXTURES = REPO / 'tests' / 'fixtures'
ROUTES = FIXTURES / 'cloudtak-13.124.0-connection-layer-routes.mjs'
HARNESS = FIXTURES / 'etl-layer-routes-harness.mjs'


def _sh():
    m = re.search(r"^_CT_ETL_LAYER_SH = r'''(.*?)'''\n", APP, re.M | re.S)
    assert m, 'the ETL layer script is gone'
    return m.group(1)


def _api_dir(tmp_path, text=None):
    """A stand-in for /home/etl/api in the container: package.json says ESM, like the real one."""
    api = tmp_path / 'etl' / 'api'
    route_dir = api / 'dist' / 'stateless' / 'routes'
    route_dir.mkdir(parents=True)
    (api / 'package.json').write_text('{"type": "module"}')
    route = route_dir / 'connection-layer.js'
    route.write_text(ROUTES.read_text() if text is None else text)
    return api, route


def _run(api, mode):
    script = _sh().replace('__MODE__', mode).replace('/home/etl/api', str(api))
    r = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _calls(route):
    r = subprocess.run(['node', str(HARNESS), str(route)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# ── the bug, as CloudTAK 13.124.0 ships it ───────────────────────────────────

def test_cloudtak_13_124_0_refuses_a_server_wide_layer_save(tmp_path):
    _, route = _api_dir(tmp_path)
    got = _calls(route)
    for kind in ('incoming', 'outgoing'):
        assert got[kind]['minimum'] == 1
        assert got[kind]['admin_server_wide']['code'] == 400      # "Validation Error" in the UI


# ── the fix ──────────────────────────────────────────────────────────────────

def test_heal_lets_an_admin_save_a_server_wide_layer_on_both_routes(tmp_path):
    api, route = _api_dir(tmp_path)
    assert _run(api, 'apply') == 'HEALED'
    got = _calls(route)
    for kind in ('incoming', 'outgoing'):
        assert got[kind]['minimum'] == 0
        assert got[kind]['admin_server_wide']['code'] == 200


def test_heal_keeps_a_non_admin_out_of_a_server_wide_layer(tmp_path):
    api, route = _api_dir(tmp_path)
    _run(api, 'apply')
    got = _calls(route)
    for kind in ('incoming', 'outgoing'):
        assert got[kind]['user_server_wide']['code'] == 403            # signed in, not an admin
        assert got[kind]['anonymous_server_wide']['code'] == 401       # not signed in
        # the admin URL for a layer that belongs to a connection is refused, never a way around the owner
        assert got[kind]['admin_other_layer_on_0']['code'] == 400


def test_heal_leaves_saves_on_a_connections_own_layers_as_they_were(tmp_path):
    api, route = _api_dir(tmp_path)
    before = _calls(_api_dir(tmp_path / 'base')[1])
    _run(api, 'apply')
    after = _calls(route)
    for kind in ('incoming', 'outgoing'):
        for case in ('owner_own_layer', 'other_user_own_layer'):
            assert after[kind][case] == before[kind][case]
    assert after['incoming']['owner_own_layer']['code'] == 200
    assert after['incoming']['other_user_own_layer']['code'] == 403
    # the route's own check that the layer belongs to the connection still runs
    assert after['incoming']['owner_wrong_layer']['code'] == 400


# ── convergence: check before apply ──────────────────────────────────────────

def test_check_reports_missing_and_never_edits(tmp_path):
    api, route = _api_dir(tmp_path)
    before = route.read_text()
    assert _run(api, 'check') == 'MISSING'
    assert route.read_text() == before
    assert not list(route.parent.glob('*.ops969.*'))


def test_second_run_is_a_no_op(tmp_path):
    api, route = _api_dir(tmp_path)
    assert _run(api, 'apply') == 'HEALED'
    done = route.read_text()
    again = _run(api, 'apply')
    assert re.fullmatch(r'OK \d+', again)                  # OK and when the file was edited
    assert int(again.split()[1]) == int(route.stat().st_mtime)
    assert re.fullmatch(r'OK \d+', _run(api, 'check'))
    assert route.read_text() == done


def test_heal_does_nothing_when_cloudtak_already_allows_connection_0(tmp_path):
    # a CloudTAK that carries the upstream fix: no minimum-1 on the two routes
    fixed = ROUTES.read_text().replace('connectionid: Type.Integer({ minimum: 1 })',
                                       'connectionid: Type.Integer({ minimum: 0 })')
    assert fixed != ROUTES.read_text()
    api, route = _api_dir(tmp_path, fixed)
    assert _run(api, 'check') == 'UPSTREAM'
    assert _run(api, 'apply') == 'UPSTREAM'
    assert route.read_text() == fixed
    assert not list(route.parent.glob('*.ops969.*'))


def test_heal_leaves_a_file_it_does_not_recognise_alone(tmp_path):
    # the minimum is there but the auth lines are not what the patch expects
    changed = ROUTES.read_text().replace('const layer = await layerControl.from(connection, req.params.layerid);',
                                         'const layer = await layerControl.byId(connection, req.params.layerid);')
    api, route = _api_dir(tmp_path, changed)
    assert _run(api, 'check') == 'SHAPE'
    assert _run(api, 'apply') == 'SHAPE'
    assert route.read_text() == changed


def test_heal_does_not_mistake_moved_params_for_an_upstream_fix(tmp_path):
    # the minimum is neither 1 nor 0 near the description (params reordered or reshaped): not "fixed"
    moved = ROUTES.read_text().replace(
        "        params: Type.Object({\n            connectionid: Type.Integer({ minimum: 1 }),\n            layerid: Type.Integer({ minimum: 1 }),\n        }),\n        body: Type.Object({\n            environment",
        "        params: Type.Object({\n            layerid: Type.Integer({ minimum: 1 }),\n            // " + 'x' * 260 + "\n            connectionid: Type.Integer({ minimum: 1 }),\n        }),\n        body: Type.Object({\n            environment")
    assert moved != ROUTES.read_text()
    api, route = _api_dir(tmp_path, moved)
    assert _run(api, 'check') == 'SHAPE'
    assert route.read_text() == moved


def test_the_belongs_to_connection_check_is_only_edited_inside_the_incoming_route(tmp_path):
    # an identical comparison earlier in the file must not be the one that gets edited
    cmp_line = 'if (layer.connection !== connection.id) {'
    text = ROUTES.read_text()
    early = text.replace("export default async function router(schema, config) {",
                         "export default async function router(schema, config) {\n    " + cmp_line.replace('{', '{ /* unrelated */ }'), 1)
    api, route = _api_dir(tmp_path, early)
    assert _run(api, 'apply') == 'HEALED'
    out = route.read_text()
    assert out.count(cmp_line + ' /* unrelated */ }') == 1                 # the early one is untouched
    assert 'if (connection && layer.connection !== connection.id) {' in out   # the route's own one is edited


def test_heal_keeps_the_first_backup_and_leaves_no_temp_file(tmp_path):
    api, route = _api_dir(tmp_path)
    original = route.read_text()
    assert _run(api, 'apply') == 'HEALED'
    bak = route.parent / 'connection-layer.js.ops969.bak'
    assert bak.read_text() == original
    assert not list(route.parent.glob('*.tmp.js'))


def test_heal_reports_noconf_when_the_route_file_is_not_there(tmp_path):
    api = tmp_path / 'empty'
    api.mkdir()
    assert _run(api, 'apply') == 'NOCONF'


def test_a_patch_that_does_not_parse_is_never_installed(tmp_path):
    # node --check runs on the new text first; make the replacement text invalid by breaking the
    # brace the patch relies on and see that the original stays
    api, route = _api_dir(tmp_path)
    script = _sh().replace('__MODE__', 'apply').replace('/home/etl/api', str(api))
    script = script.replace("'            }',\n  ''].join('\\n');\nconst OLDCMP", "'            ',\n  ''].join('\\n');\nconst OLDCMP")
    assert "'            ',\n  ''].join" in script
    before = route.read_text()
    r = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=60)
    assert r.stdout.strip() == 'FAIL'
    assert route.read_text() == before
    assert not list(route.parent.glob('*.tmp.js'))


# ── the shipped Python heal, with docker faked ───────────────────────────────

def _func(name):
    m = re.search(rf"^def {name}\(.*?(?=^def |^[A-Za-z_]+ = |^@)", APP, re.M | re.S)
    assert m, f'{name} is gone'
    return m.group(0)


class _Docker:
    """Fakes subprocess.run for the heal: docker ps / exec sh / inspect / restart / exec curl."""
    def __init__(self, script_answer, curl_codes=('200',), started='', restart_rc=0):
        self.answer = script_answer
        self.curl_codes = list(curl_codes)
        self.started = started
        self.restart_rc = restart_rc
        self.calls = []
        self.scripts = []

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        out, rc = '', 0
        if argv[:2] == ['docker', 'ps']:
            out = 'cloudtak-api-1\n'
        elif argv[:2] == ['docker', 'exec'] and argv[-1] == 'sh':
            self.scripts.append(kw.get('input'))
            out = self.answer + '\n'
        elif argv[:2] == ['docker', 'inspect']:
            out = self.started + '\n'
        elif argv[:2] == ['docker', 'restart']:
            rc = self.restart_rc
        elif argv[:2] == ['docker', 'exec'] and 'curl' in argv:
            out = self.curl_codes.pop(0) if self.curl_codes else '000'
        return subprocess.CompletedProcess(argv, rc, out, '')


def _heal(answer, curl_codes=('200', '200'), started='', restart_rc=0):
    docker = _Docker(answer, curl_codes, started, restart_rc)
    order = []

    class _Time:
        sleep = staticmethod(lambda _s: None)
        strptime = staticmethod(time.strptime)

    ns = {
        'subprocess': type('S', (), {'run': staticmethod(docker.run), 'CompletedProcess': subprocess.CompletedProcess}),
        'time': _Time,
        '_sudo_wrap': lambda a: a,
        '_b64': __import__('base64'),
        '_ssh_probe': lambda *a, **k: (True, ''),
        '_CT_ETL_LAYER_SH': _sh(),
        '_cloudtak_etl_heal_lock': threading.Lock(),
        '_cloudtak_upload_limit_heal': lambda **k: order.append(('upload', k)) or True,
    }
    exec(_func('_ct_etl_stale'), ns)
    exec(_func('_cloudtak_etl_layer_heal'), ns)
    logs = []
    ok = ns['_cloudtak_etl_layer_heal'](plog=logs.append, wait=True)
    return ok, docker, order, logs


def _restarts(docker):
    return [c for c in docker.calls if c[:2] == ['docker', 'restart']]


def test_heal_restarts_the_api_once_then_reapplies_the_upload_limit():
    ok, docker, order, logs = _heal('HEALED')
    assert ok is True
    assert _restarts(docker) == [['docker', 'restart', 'cloudtak-api-1']]
    # the restart rewrites nginx.conf: the upload limit goes back on straight after
    assert [o[0] for o in order] == ['upload']
    assert any('MODE=apply' in (s or '') for s in docker.scripts)
    assert any('an admin can now save' in m for m in logs)


def test_heal_waits_for_the_api_before_the_restart_and_again_after_it():
    # first curl: the api answers (so it is safe to restart); second: it answers again after the restart
    _, docker, _, _ = _heal('HEALED')
    seq = ['restart' if c[:2] == ['docker', 'restart'] else 'curl' for c in docker.calls
           if c[:2] == ['docker', 'restart'] or 'curl' in c]
    assert seq == ['curl', 'restart', 'curl']


def test_heal_never_restarts_an_api_that_is_not_answering_yet():
    # first-boot migrations can take 25 minutes: the file is edited, the restart is left for the drift check
    ok, docker, order, logs = _heal('HEALED', curl_codes=())
    assert ok is False
    assert _restarts(docker) == [] and order == []
    assert any('not applied (NOAPI)' in m for m in logs)


def test_heal_does_not_restart_when_nothing_changed():
    for answer in ('OK 1700000000', 'UPSTREAM', 'SHAPE'):
        ok, docker, order, _ = _heal(answer, started='2026-11-19T10:00:00.123456789Z')
        assert ok is True, answer
        assert _restarts(docker) == [], answer
        assert order == [], answer


def test_heal_restarts_when_the_file_was_edited_after_the_api_started():
    # a failed restart, or a console stopped between the edit and the restart, left the old routes running
    edited = 1795000000                       # epoch of the edit
    started_before = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(edited - 600)) + '.123456789Z'
    ok, docker, order, logs = _heal(f'OK {edited}', started=started_before)
    assert ok is True
    assert len(_restarts(docker)) == 1 and [o[0] for o in order] == ['upload']
    assert any('started before it' in m for m in logs)
    started_after = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(edited + 600)) + '.123456789Z'
    ok, docker, order, _ = _heal(f'OK {edited}', started=started_after)
    assert ok is True and _restarts(docker) == [] and order == []


def test_heal_reports_failure_when_the_restart_fails_or_the_api_does_not_come_back():
    ok, docker, order, logs = _heal('HEALED', restart_rc=1)
    assert ok is False and order == []
    ok, docker, order, logs = _heal('HEALED', curl_codes=('200',))      # answers before, never after
    assert ok is False and order == []
    assert any('not applied (NOAPI)' in m for m in logs)


def test_heal_reports_failure_when_the_edit_failed():
    ok, docker, _, logs = _heal('FAIL')
    assert ok is False
    assert _restarts(docker) == []


def test_two_overlapping_heals_cannot_run_at_once():
    assert re.search(r'^_cloudtak_etl_heal_lock = threading\.Lock\(\)', APP, re.M)
    body = _func('_cloudtak_etl_layer_heal')
    assert '_cloudtak_etl_heal_lock.acquire(' in body and '_cloudtak_etl_heal_lock.release()' in body


# ── wired in wherever the upload limit is, and into the drift check ──────────

def test_heal_runs_wherever_cloudtak_is_recreated_and_before_the_upload_limit():
    lines = APP.splitlines()
    sites = [i for i, l in enumerate(lines) if re.match(r'\s+_cloudtak_upload_limit_heal\(plog=', l)]
    # deploy (local + remote), update, restart, recreate-and-heal, remote or local, autorepair
    assert len(sites) >= 7
    paired = [i for i in sites if '_cloudtak_etl_layer_heal(' in lines[i - 1]]
    assert len(paired) >= 6, 'every recreate path runs the ETL layer fix just before the upload limit'
    recreate = APP[APP.index('def _cloudtak_recreate_and_heal'):]
    assert '_cloudtak_etl_layer_heal(' in recreate[:recreate.index('def _startup_harden_cloudtak_ports')]


def test_heal_runs_after_every_console_start_off_the_start_path():
    start = APP[APP.index('def _startup_heal_cloudtak_etl_layer'):]
    start = start[:start.index('_startup_heal_cloudtak_etl_layer()\n')]
    assert 'threading.Thread(' in start and '_cloudtak_etl_layer_heal()' in start
    assert '_cloudtak_stack_busy_procs()' in start            # never while a compose or build run goes
    assert '\n_startup_heal_cloudtak_etl_layer()\n' in APP


def test_drift_check_and_repair_know_the_etl_fix():
    drift = APP[APP.index('def _cloudtak_drift(ct_dir):'):]
    drift = drift[:drift.index('def _cloudtak_drift_summary')]
    assert "_CT_ETL_LAYER_SH.replace('__MODE__', 'check')" in drift
    assert "'MISSING'" in drift and '_ct_etl_stale(' in drift     # UPSTREAM and OK are converged, SHAPE is not drift
    assert "out['kind'] = 'etl'" in drift
    repair = APP[APP.index('def _cloudtak_autorepair_run'):]
    repair = repair[:repair.index('def _cloudtak_autorepair_notify')]
    assert "drift.get('etl') is False" in repair and '_cloudtak_etl_layer_heal(' in repair
    assert "'etl':" in APP[APP.index('def _cloudtak_autorepair_notify'):]


def test_the_script_checks_before_it_applies():
    sh = _sh()
    assert "process.env.MODE" in sh and "MODE !== 'apply'" in sh
    assert 'UPSTREAM' in sh and 'SHAPE' in sh and "'--check'" in sh
    assert 'Auth.as_user(config, req, { admin: true })' in sh     # admin only, like Create Incoming


def test_node_is_available_for_these_tests():
    assert shutil.which('node'), 'these tests run the shipped script with node'


# ── Guard Dog / console drift repair of the ETL fix (the console's own check, docker faked) ──

@pytest.fixture
def box(tmp_path):
    return Box(tmp_path)


def test_a_recreate_that_took_the_fix_away_is_drift_and_gets_only_the_etl_heal(box):
    # a TAK Portal plugin install recreated the api: its routes are CloudTAK's own again
    _converged(box)
    box.etl = False
    assert box.request()['state'] == 'repairing'
    box.finish()
    assert box.ups() == [] and box.etls() == [['ETL']]       # no compose recreate for this
    assert box.etl is True and box.upload is True
    assert box.record()['last']['result'] == 'repaired'
    assert 'ETL layer save fix missing' in box.guard_log[0][1]
    assert 'save the schedule and login of a server-wide ETL layer' in box.guard_log[0][1]
    assert box.request()['state'] == 'ok'


def test_a_cloudtak_that_carries_the_fix_or_an_unknown_file_is_not_drift(box):
    _converged(box)
    box.etl = 'UPSTREAM'        # the check answers UPSTREAM, SHAPE or NOCONF: none of them is drift
    assert box.request()['state'] == 'ok'
    assert box.threads == [] and box.etls() == [] and box.record() == {}


def test_an_etl_heal_that_does_not_confirm_is_a_failure(box):
    _converged(box)
    box.etl = False
    box.etl_heal_ok = False
    box.request()
    box.finish()
    last = box.record()['last']
    assert last['result'] == 'failed' and 'ETL layer save fix did not re-apply' in last['detail']
    assert box.guard_log == []


def test_the_recreate_path_puts_the_fix_back_too(box):
    # label drift forces the full console recreate; it must end with the fix in place
    box.etl = True
    box.request()
    box.finish()
    assert box.ups() == [['docker', 'compose', 'up', '-d', '--force-recreate']]
    assert box.etls() and box.etl is True
    assert box.record()['last']['result'] == 'repaired'


def test_a_route_file_edited_after_the_api_started_is_drift_and_gets_the_etl_heal(box):
    _converged(box)
    box.etl = True
    box.etl_mtime = time.time()
    box.etl_started = time.time() - 3600          # the api never reloaded the edited file
    assert box.request()['state'] == 'repairing'
    box.finish()
    assert box.etls() == [['ETL']] and box.record()['last']['result'] == 'repaired'
    assert box.request()['state'] == 'ok'           # the api now started after the edit


def test_an_edited_file_the_api_has_reloaded_is_not_drift(box):
    _converged(box)
    box.etl = True
    box.etl_mtime = time.time() - 600
    box.etl_started = time.time() - 300           # started after the edit
    assert box.request()['state'] == 'ok'
    assert box.etls() == []
