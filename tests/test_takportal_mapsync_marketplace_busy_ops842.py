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
"""Adding a TAK group must not restart TAK Portal under a running Marketplace job (ops #842).

The map sync adds every new TAK channel to the portal's `admin` bridge entry and then restarts
TAK Portal. A restart ends every queued or running Marketplace job with "Interrupted by restart."
and leaves CloudTAK half rebuilt (seen on test6, TAK Portal 2.0.36, 5 jobs lost). The sync now
waits while a job is queued or running, then writes the channels and restarts once.
"""

import ast
import json
import pathlib
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
UAF_NS = 'http://bbn.com/marti/xml/bindings'
UAF_OLD = (f'<UserAuthenticationFile xmlns="{UAF_NS}">'
           '<User identifier="admin" fingerprint="abc" role="ROLE_ADMIN">'
           '<groupList>__ANON__</groupList><groupList>OPS</groupList></User>'
           '</UserAuthenticationFile>')
JOBS = '/usr/src/app/data/cloudtak-marketplace/jobs.json'


def _source(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    return None  # not in app.py (the base branch has no busy check): the test then fails on behaviour


def _const(name, default=None):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', None) == name:
            return eval(compile(ast.Expression(n.value), 'app.py', 'eval'))  # literals and 3 * 3600
    return default


class Box:
    """A console box: a UAF, a Marti channel list, the portal's jobs file and a clock."""

    def __init__(self, jobs=None, jobs_unreadable=False):
        self.jobs, self.jobs_unreadable = jobs or [], jobs_unreadable
        self.uaf, self.restarts, self.docker_calls, self.log, self.now = UAF_OLD, 0, [], [], 1000.0
        ns = {
            'json': json, 'subprocess': types.SimpleNamespace(run=self._run),
            'time': types.SimpleNamespace(time=lambda: self.now),
            'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True)),
            '_sudo_wrap': lambda argv: argv, '_takportal_ref': lambda: 'portal-ctr',
            '_get_tak_deployment_config': lambda s: {}, 'load_settings': lambda: {},
            '_takportal_web_container': lambda all_states=False: {'id': 'portal-ctr'},
            '_tak_admin_marti_get': lambda url: ({'data': [{'name': 'OPS'}, {'name': 'NEWGROUP'}]}, None),
            '_read_priv': lambda p: self.uaf, '_write_priv': self._write,
            '_takportal_restart': self._restart, 'CLOUDTAK_BOOTSTRAP_CERT_CN': 'cloudtak-svc-bootstrap',
            '_TAK_UAF_NS': UAF_NS, '_mapsync_splitbox_logged': False,
            '_TAKPORTAL_MARKETPLACE_JOBS': _const('_TAKPORTAL_MARKETPLACE_JOBS', JOBS),
            '_TAKPORTAL_MARKETPLACE_BUSY_STATES': _const('_TAKPORTAL_MARKETPLACE_BUSY_STATES', ('queued', 'running')),
            '_MAPSYNC_MARKETPLACE_WAIT_MAX': _const('_MAPSYNC_MARKETPLACE_WAIT_MAX', 3 * 3600),
            '_MAPSYNC_MARKETPLACE_WAIT': {'since': None}, 'print': lambda *a, **k: None,
        }
        for fn in ('_takportal_marketplace_busy', '_takportal_mapsync_wait_for_marketplace',
                   '_takportal_sync_map_channels'):
            if _source(fn):
                exec(compile(_source(fn), 'app.py', 'exec'), ns)
        self.ns = ns

    def _run(self, argv, **kw):
        self.docker_calls.append(list(argv))
        if self.jobs_unreadable:
            return types.SimpleNamespace(returncode=1, stdout='', stderr='No such file')
        return types.SimpleNamespace(returncode=0, stdout=json.dumps({'jobs': self.jobs}), stderr='')

    def _write(self, path, text):
        self.uaf = text

    def _restart(self, timeout=120):
        self.restarts += 1
        return True

    def sync(self):
        self.ns['_takportal_sync_map_channels'](plog=self.log.append)


def _job(status, kind='update', pid='print'):
    return {'id': f'{kind}-{pid}', 'kind': kind, 'pluginId': pid, 'status': status}


def test_running_marketplace_job_holds_back_the_restart_and_the_uaf_write():
    box = Box(jobs=[_job('running'), _job('queued', pid='replay'), _job('complete', pid='old')])
    box.sync()
    assert box.restarts == 0, 'tak-portal was restarted under a running Marketplace job'
    assert box.uaf == UAF_OLD, 'the UAF was rewritten while the sync is waiting (the next tick must still see a change)'
    assert any('Marketplace job is running' in m for m in box.log)
    assert box.docker_calls and box.docker_calls[0][:3] == ['docker', 'exec', 'portal-ctr']
    assert JOBS in box.docker_calls[0]


def test_queued_job_alone_also_holds_it_back():
    box = Box(jobs=[_job('queued', kind='install')])
    box.sync()
    assert box.restarts == 0


def test_idle_marketplace_still_writes_the_channel_and_restarts_once():
    box = Box(jobs=[_job('complete'), _job('failed', pid='replay'), _job('staged', pid='x')])
    box.sync()
    assert box.restarts == 1
    assert 'NEWGROUP' in box.uaf
    box.sync()  # converged: no second restart
    assert box.restarts == 1


def test_waits_while_busy_then_restarts_exactly_once_when_the_batch_ends():
    box = Box(jobs=[_job('running')])
    box.sync()
    box.now += 600
    box.sync()
    assert box.restarts == 0
    box.jobs = [_job('complete')]
    box.now += 600
    box.sync()
    assert box.restarts == 1 and 'NEWGROUP' in box.uaf
    box.now += 600
    box.sync()
    assert box.restarts == 1, 'a converged sync must not restart again'


def test_a_job_stuck_on_running_does_not_block_the_sync_for_ever():
    box = Box(jobs=[_job('running')])
    box.sync()
    assert box.restarts == 0
    box.now += box.ns['_MAPSYNC_MARKETPLACE_WAIT_MAX'] - 60
    box.sync()
    assert box.restarts == 0
    box.now += 120
    box.sync()
    assert box.restarts == 1 and 'NEWGROUP' in box.uaf


def test_an_unreadable_jobs_file_means_not_busy_as_before():
    box = Box(jobs_unreadable=True)
    box.sync()
    assert box.restarts == 1 and 'NEWGROUP' in box.uaf


def test_no_docker_call_when_the_channels_already_match():
    """The common 10-minute tick (nothing changed) must stay free of the extra docker exec."""
    box = Box(jobs=[_job('running')])
    box.uaf = (f'<UserAuthenticationFile xmlns="{UAF_NS}"><User identifier="admin" role="ROLE_ADMIN">'
               '<groupList>NEWGROUP</groupList><groupList>OPS</groupList><groupList>__ANON__</groupList>'
               '</User></UserAuthenticationFile>')
    box.sync()
    assert box.restarts == 0 and box.docker_calls == []


def test_busy_check_reads_the_portals_own_status_words():
    for status, busy in (('queued', True), ('running', True), ('staged', False),
                         ('complete', False), ('failed', False)):
        assert Box(jobs=[_job(status)]).ns['_takportal_marketplace_busy']() is busy, status
