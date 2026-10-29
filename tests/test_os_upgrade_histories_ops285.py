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
"""The box-history matrix for one-way upgrades (ops #285): tools/os-upgrade-histories/.

Offline only: the matrix file, the judge, the Azure box script run against a fake `az`, the
console driver against a local stub, and the test picker rule. No cloud, no box."""
import copy
import importlib.util
import json
import os
import stat
import subprocess
import sys
import threading
import http.server

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, 'tools', 'os-upgrade-histories')


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, os.path.join(TOOLS, fname))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hist = _load('histories', 'histories.py')
drive = _load('drive', 'drive.py')
DATA = hist.load()


# ---- the matrix itself ---------------------------------------------------------------------------

def test_every_history_ops285_asked_for_is_a_cell():
    ids = {c.split(':')[0] for c in hist.cells(DATA)}
    assert ids == {'h1-fresh-single', 'h2-57-to-58-then-os', 'h3-old-pg-left-online',
                   'h4-stuck-reassert', 'h5-two-server', 'h6-58-r92-then-os'}


def test_every_cell_resolves_and_uses_known_steps():
    for c in hist.cells(DATA):
        cell = hist.resolve(DATA, c)
        assert cell['labels'][0] == 'image', c
        for s in cell['history']:
            assert s['step'] in DATA['steps'], (c, s)
            arg = hist.STEP_ARG.get(s['step'])
            assert arg is None or s.get(arg), (c, s)


def test_h2_is_the_real_released_path_not_a_hand_built_end_state():
    labels = hist.resolve(DATA, 'h2-57-to-58-then-os')['labels']
    assert labels.index('takserver-deploy:5.7') < labels.index('takserver-58-migrate:5.8')
    assert any(l.startswith('infratak-install:v10.1.') for l in labels)
    assert hist.resolve(DATA, 'h2-57-to-58-then-os')['start']['clusters'] == [
        ['15', 'main', '5433', 'down'], ['18', 'main', '5432', 'online']]


def test_h3_and_h4_are_built_on_h2_and_h3_is_the_unsafe_one():
    h2 = hist.resolve(DATA, 'h2-57-to-58-then-os')
    h3 = hist.resolve(DATA, 'h3-old-pg-left-online')
    h4 = hist.resolve(DATA, 'h4-stuck-reassert')
    assert h3['labels'][:len(h2['labels'])] == h2['labels'] and h3['labels'][-1] == 'start-old-cluster:15/main'
    assert h4['labels'][:len(h2['labels'])] == h2['labels'] and h4['labels'][-1] == 'os-upgrade-released:v10.3.0-alpha'
    assert h3['expect']['result'] == 'refused' and h3['expect']['unchanged'] is True
    assert h4['start']['status'] == 'failed:reassert' and h4['expect']['no_automatic_reboot'] is True


def test_variants_cover_authentik_docker_and_broker():
    names = set(DATA['scenarios'][0]['variants'])
    assert {'a-bare', 'b-authentik', 'c-docker-tak', 'd-full'} <= names
    full = hist.resolve(DATA, 'h1-fresh-single:d-full')['labels']
    assert {'module-deploy:authentik', 'module-deploy:broker', 'module-deploy:docker-modules'} <= set(full)
    dock = hist.resolve(DATA, 'h1-fresh-single:c-docker-tak')
    assert 'module-deploy:docker-tak' in dock['labels'] and 'takserver-deploy:5.8' not in dock['labels']
    assert dock['expect']['clusters'] == []   # a container TAK has no PostgreSQL cluster on the host


def test_two_server_cell_has_a_database_box_and_both_snapshots_named():
    cell = hist.resolve(DATA, 'h5-two-server')
    assert cell['boxes'] == ['core', 'db'] and cell['expect']['also_upgrade_db_box'] is True
    assert hist.expected_labels(cell, 'db') == ['image', 'two-server-deploy:5.8']


def test_asking_for_a_variant_scenario_without_the_variant_is_an_error():
    with pytest.raises(hist.Bad):
        hist.resolve(DATA, 'h1-fresh-single')
    with pytest.raises(hist.Bad):
        hist.resolve(DATA, 'nope')


def test_readme_names_every_cell():
    text = open(os.path.join(TOOLS, 'README.md'), encoding='utf-8').read()
    for c in hist.cells(DATA):
        assert '`%s`' % c in text, c


def test_azure_defaults_follow_the_cloud_vm_rules():
    az = DATA['defaults']['azure']
    assert az['auto_shutdown_hours'] == 3                      # job length plus an hour, never past 4 (OPS-WORKER.md)
    assert az['owner'] == 'claude-lane' and az['resource_group'].startswith('rg-')
    assert 'subscription' not in az          # the id stays out of the public repo: HIST_AZURE_SUBSCRIPTION


# ---- judge: facts builders ----------------------------------------------------------------------

def facts(cell, **kw):
    f = {'os_release': '24.04', 'boot_id': 'boot-2', 'status': 'done',
         'clusters': copy.deepcopy(cell['expect'].get('clusters', [])),
         'services': {'takserver': 'active', 'takwerx-console': 'active', 'takwerx-broker': 'active', 'docker': 'active'},
         'containers': {'running': ['authentik-server-1'], 'unhealthy': []},
         'baseline_services': {'takwerx-console': 'active'}, 'baseline_containers': ['authentik-server-1'],
         'apt_conf_left': False, 'pkg_hash': 'p1',
         'log': '[2026-10-27T10:00:00Z] reassert complete\n[x] kept as it is: stopped PostgreSQL 15/main on 5433 (the copy)\n',
         'infratak_sha': 'abcdef0123456789'}
    f.update(kw)
    return f


def done_input(cell_id, after=None, before=None, **kw):
    cell = hist.resolve(DATA, cell_id)
    b = before or facts(cell, os_release='22.04', status='', boot_id='boot-1')
    a = after or facts(cell)
    inp = {'boxes': {cell['boxes'][0]: {'before': b, 'after': a}}, 'final_status': 'done',
           'client_check': {'passed': True, 'anon_named': 0}}
    if len(cell['boxes']) > 1:
        inp['boxes']['db'] = {'after': {'status': 'done', 'os_release': '24.04',
                                        'clusters': cell['expect']['clusters_db']}}
    inp.update(kw)
    return cell, inp


def verdict(cell_id, inp, stage='end'):
    cell = hist.resolve(DATA, cell_id)
    rep = hist.judge(cell, inp, stage, DATA)
    return rep.passed, {c['name']: c for c in rep.checks}


def failed_names(cell_id, inp, stage='end'):
    _, checks = verdict(cell_id, inp, stage)
    return {n for n, c in checks.items() if not c['ok']}


def test_good_h2_upgrade_passes():
    _, inp = done_input('h2-57-to-58-then-os')
    ok, checks = verdict('h2-57-to-58-then-os', inp)
    assert ok, [c for c in checks.values() if not c['ok']]


def test_h2_fails_when_the_stopped_pg15_was_lost():
    cell, inp = done_input('h2-57-to-58-then-os')
    inp['boxes']['core']['after']['clusters'] = [['18', 'main', '5432', 'online']]
    assert 'PostgreSQL clusters as expected' in failed_names('h2-57-to-58-then-os', inp)


def test_h2_fails_when_pg15_came_up_online():
    cell, inp = done_input('h2-57-to-58-then-os')
    inp['boxes']['core']['after']['clusters'] = [['15', 'main', '5433', 'online'], ['18', 'main', '5432', 'online']]
    assert 'PostgreSQL clusters as expected' in failed_names('h2-57-to-58-then-os', inp)


def test_down_recovery_counts_as_down():
    cell, inp = done_input('h2-57-to-58-then-os')
    inp['boxes']['core']['after']['clusters'] = [['15', 'main', '5433', 'down,recovery'], ['18', 'main', '5432', 'online']]
    assert verdict('h2-57-to-58-then-os', inp)[0]


@pytest.mark.parametrize('mutate, expect_failed', [
    (lambda i: i.update(final_status='failed:reassert'), 'upgrade status is done'),
    (lambda i: i['boxes']['core']['after'].update(os_release='22.04'), 'Ubuntu 24.04'),
    (lambda i: i['boxes']['core']['after'].update(log='ok\nFATAL: step reassert failed — x\n'), 'the log has no "failed"'),
    (lambda i: i['boxes']['core']['after'].update(log=''), 'the log is there'),
    (lambda i: i['boxes']['core']['after'].update(log='all fine\n'), 'the log says: kept as it is: stopped PostgreSQL 15/main on 5433'),
    (lambda i: i['boxes']['core']['after']['services'].update({'takwerx-console': 'inactive'}), 'core: console running'),
    (lambda i: i['boxes']['core']['after']['services'].update({'takserver': 'inactive'}), 'core: TAK Server running'),
    (lambda i: i['boxes']['core']['after']['containers'].update(running=['nodered']), 'core: a authentik container is running'),
    (lambda i: i['boxes']['core']['after']['containers'].update(unhealthy=['nodered']), 'core: no unhealthy or restarting container'),
    (lambda i: i['boxes']['core']['after'].update(baseline_services={'takwerx-console': 'active', 'mediamtx': 'active'}),
     'core: every service from before the upgrade is back'),
    (lambda i: i.update(client_check={'passed': False}), 'client check passes'),
    (lambda i: i.update(client_check={'passed': True, 'anon_named': 2}), 'client check passes'),
    (lambda i: i.pop('client_check'), 'client check passes'),
    (lambda i: i.update(candidate_sha='1234567890'), 'the box runs the candidate 12345678'),
])
def test_h2_each_broken_thing_is_named(mutate, expect_failed):
    _, inp = done_input('h2-57-to-58-then-os')
    mutate(inp)
    ok, checks = verdict('h2-57-to-58-then-os', inp)
    assert not ok
    assert expect_failed in {n for n, c in checks.items() if not c['ok']}


def test_an_explicit_client_check_skip_passes_but_is_named_as_skipped():
    _, inp = done_input('h2-57-to-58-then-os', client_check={'skipped': True, 'reason': 'needs device'})
    cell = hist.resolve(DATA, 'h2-57-to-58-then-os')
    rep = hist.judge(cell, inp, 'end', DATA)
    assert rep.passed
    assert rep.as_dict('end')['skipped'] == ['client check passes']
    line = hist.release_line([rep.as_dict('end')])
    assert 'passed (client check skipped: needs device)' in line


def test_a_skip_never_covers_a_missing_or_failed_client_check():
    for cc in ({}, {'passed': False}, {'skipped': False}, {'skipped': 'yes'}):
        _, inp = done_input('h2-57-to-58-then-os', client_check=cc)
        assert 'client check passes' in failed_names('h2-57-to-58-then-os', inp)


def test_a_skipped_client_check_does_not_hide_another_failure():
    _, inp = done_input('h2-57-to-58-then-os', client_check={'skipped': True, 'reason': 'needs device'})
    inp['boxes']['core']['after']['os_release'] = '22.04'
    ok, _ = verdict('h2-57-to-58-then-os', inp)
    assert not ok


def test_candidate_sha_match_passes_even_when_abbreviated():
    _, inp = done_input('h2-57-to-58-then-os', candidate_sha='abcdef0')
    assert verdict('h2-57-to-58-then-os', inp)[0]


def test_log_allow_list_lets_a_known_harmless_line_through():
    data = copy.deepcopy(DATA)
    data['defaults']['log_allow'] = ['dpkg: warning: failed to remove']
    cell, inp = done_input('h2-57-to-58-then-os')
    inp['boxes']['core']['after']['log'] += 'dpkg: warning: failed to remove obsolete file\n'
    assert not hist.judge(cell, inp, 'end', DATA).passed
    assert hist.judge(cell, inp, 'end', data).passed


def test_h1_bare_and_docker_variants_expect_their_own_shape():
    c = hist.resolve(DATA, 'h1-fresh-single:a-bare')
    inp = done_input('h1-fresh-single:a-bare', after=facts(c, containers={'running': [], 'unhealthy': []},
                                                            baseline_containers=[], log='ok\n'))[1]
    assert verdict('h1-fresh-single:a-bare', inp)[0]
    # a container called takserver does not stand in for the native unit
    inp['boxes']['core']['after']['services']['takserver'] = 'inactive'
    inp['boxes']['core']['after']['containers'] = {'running': ['takserver'], 'unhealthy': []}
    assert 'core: TAK Server running' in failed_names('h1-fresh-single:a-bare', inp)
    inp = done_input('h1-fresh-single:a-bare', after=facts(c, containers={'running': [], 'unhealthy': []},
                                                            baseline_containers=[], log='ok\n'))[1]
    assert verdict('h1-fresh-single:a-bare', inp)[0]
    d = hist.resolve(DATA, 'h1-fresh-single:c-docker-tak')
    after = facts(d, clusters=[], services={'takwerx-console': 'active', 'docker': 'active'},
                  containers={'running': ['takserver', 'takserver-db'], 'unhealthy': []}, baseline_containers=['takserver'], log='ok\n')
    assert verdict('h1-fresh-single:c-docker-tak', done_input('h1-fresh-single:c-docker-tak', after=after)[1])[0]
    after['clusters'] = [['18', 'main', '5432', 'online']]
    assert not verdict('h1-fresh-single:c-docker-tak', done_input('h1-fresh-single:c-docker-tak', after=after)[1])[0]


def test_h4_must_not_reboot_by_itself_and_must_say_reassert_complete():
    cell = hist.resolve(DATA, 'h4-stuck-reassert')
    before = facts(cell, status='failed:reassert', boot_id='boot-1')
    after = facts(cell, boot_id='boot-1', log='finishing the OS upgrade that stopped at reassert\nreassert complete\nkept as it is: stopped PostgreSQL 15/main on 5433\n')
    inp = done_input('h4-stuck-reassert', after=after, before=before)[1]
    assert verdict('h4-stuck-reassert', inp)[0]
    after['boot_id'] = 'boot-2'
    assert 'the box did not reboot by itself' in failed_names('h4-stuck-reassert', done_input('h4-stuck-reassert', after=after, before=before)[1])


def test_h5_needs_the_database_server_upgraded_too():
    cell, inp = done_input('h5-two-server')
    inp['boxes']['core']['after'].update(containers={'running': ['takserver'], 'unhealthy': []}, baseline_containers=[], log='ok\n')
    ok, checks = verdict('h5-two-server', inp)
    assert ok, [c for c in checks.values() if not c['ok']]
    inp['boxes']['db']['after']['os_release'] = '22.04'
    assert 'db: Ubuntu 24.04' in failed_names('h5-two-server', inp)
    inp['boxes']['db']['after'].update(os_release='24.04', status='running:release-upgrade')
    assert 'db: status is done' in failed_names('h5-two-server', inp)


# ---- judge: the unsafe cell ---------------------------------------------------------------------

REFUSED_DETAIL = ("TAK Server 5.8; TAK Server's database must be the only running PostgreSQL cluster (18 on 5432); "
                  "running: 15/main:5433 online, 18/main:5432 online — stop 15/main (sudo pg_ctlcluster 15 main stop, "
                  "and set /etc/postgresql/15/main/start.conf to manual)")


def refused_input(**kw):
    cell = hist.resolve(DATA, 'h3-old-pg-left-online')
    clusters = [['15', 'main', '5433', 'online'], ['18', 'main', '5432', 'online']]
    before = facts(cell, os_release='22.04', status='', boot_id='boot-1', clusters=clusters, pkg_hash='p1', containers={'running': ['takserver', 'authentik-server-1'], 'unhealthy': []})
    after = copy.deepcopy(before)
    inp = {'boxes': {'core': {'before': before, 'after': after}},
           'preflight': {'ok': False, 'checks': [{'name': 'os_type', 'pass': True, 'detail': 'Ubuntu 22.04'},
                                                 {'name': 'takserver_58', 'pass': False, 'detail': REFUSED_DETAIL}]},
           'start_response': {'http_status': 409, 'ok': False},
           'client_check': {'passed': True, 'anon_named': 0}}
    inp.update(kw)
    return inp


def test_h3_refused_with_nothing_changed_passes():
    ok, checks = verdict('h3-old-pg-left-online', refused_input())
    assert ok, [c for c in checks.values() if not c['ok']]


@pytest.mark.parametrize('mutate, expect_failed', [
    (lambda i: i['preflight'].update(ok=True), 'preflight is red'),
    (lambda i: i['preflight']['checks'][1].update(**{'pass': True}), 'the right check refused: takserver_58'),
    (lambda i: i['preflight']['checks'][1].update(detail='something is wrong'), 'it names the next step: pg_ctlcluster 15 main stop'),
    (lambda i: i['start_response'].update(http_status=200, ok=True), 'Start was refused by the console'),
    (lambda i: i['boxes']['core']['after'].update(status='running:pre-snapshot'), 'no upgrade job was started'),
    (lambda i: i['boxes']['core']['after'].update(os_release='24.04'), 'still Ubuntu 22.04'),
    (lambda i: i['boxes']['core']['after'].update(clusters=[['18', 'main', '5432', 'online']]), 'PostgreSQL clusters exactly as before'),
    (lambda i: i['boxes']['core']['after'].update(boot_id='boot-9'), 'no reboot'),
    (lambda i: i['boxes']['core']['after'].update(apt_conf_left=True), 'no upgrade settings left behind'),
    (lambda i: i['boxes']['core']['after'].update(pkg_hash='p2'), 'no package was moved'),
    (lambda i: i['boxes']['core']['after']['services'].update({'takserver': 'inactive'}), 'core: TAK Server running'),
    (lambda i: i.update(client_check={'passed': False}), 'client check passes'),
])
def test_h3_each_unsafe_outcome_is_named(mutate, expect_failed):
    inp = refused_input()
    mutate(inp)
    ok, checks = verdict('h3-old-pg-left-online', inp)
    assert not ok
    assert expect_failed in {n for n, c in checks.items() if not c['ok']}


def test_h3_a_started_upgrade_is_a_failure_even_if_it_finished_done():
    inp = refused_input()
    inp['preflight']['ok'] = True
    inp['start_response'] = {'http_status': 200, 'ok': True}
    inp['boxes']['core']['after'].update(status='done', os_release='24.04')
    assert not verdict('h3-old-pg-left-online', inp)[0]


# ---- judge: start stage (is the snapshot a real history?) ---------------------------------------

def start_input(cell_id, **kw):
    cell = hist.resolve(DATA, cell_id)
    f = {'provenance': list(cell['labels']), 'os_release': cell['start'].get('os_release', '22.04'),
         'status': cell['start'].get('status', ''), 'clusters': copy.deepcopy(cell['start']['clusters']),
         'services': {'takwerx-console': 'active'}}
    f.update(kw)
    inp = {'boxes': {cell['boxes'][0]: f}}
    if len(cell['boxes']) > 1:
        inp['boxes']['db'] = {'provenance': hist.expected_labels(cell, 'db'), 'clusters': cell['start']['clusters_db']}
    return inp


@pytest.mark.parametrize('cell_id', ['h2-57-to-58-then-os', 'h3-old-pg-left-online', 'h4-stuck-reassert', 'h5-two-server',
                                     'h6-58-r92-then-os', 'h1-fresh-single:b-authentik'])
def test_a_snapshot_with_the_recorded_history_is_accepted(cell_id):
    assert verdict(cell_id, start_input(cell_id), 'start')[0]


def test_a_hand_built_end_state_has_no_history_and_is_refused():
    inp = start_input('h2-57-to-58-then-os', provenance=[])
    assert 'core: replayed the real steps, in order' in failed_names('h2-57-to-58-then-os', inp, 'start')


def test_steps_out_of_order_or_missing_are_refused():
    cell = hist.resolve(DATA, 'h2-57-to-58-then-os')
    swapped = list(cell['labels'])
    swapped[2], swapped[3] = swapped[3], swapped[2]
    assert 'core: replayed the real steps, in order' in failed_names('h2-57-to-58-then-os', start_input('h2-57-to-58-then-os', provenance=swapped), 'start')
    short = [l for l in cell['labels'] if l != 'takserver-58-migrate:5.8']
    assert 'core: replayed the real steps, in order' in failed_names('h2-57-to-58-then-os', start_input('h2-57-to-58-then-os', provenance=short), 'start')


def test_right_history_but_wrong_clusters_is_refused():
    inp = start_input('h2-57-to-58-then-os', clusters=[['18', 'main', '5432', 'online']])
    assert 'core: starting clusters' in failed_names('h2-57-to-58-then-os', inp, 'start')


def test_h4_snapshot_must_be_stuck_on_24_04_at_failed_reassert():
    inp = start_input('h4-stuck-reassert', status='done')
    assert 'core: starting upgrade status' in failed_names('h4-stuck-reassert', inp, 'start')
    inp = start_input('h4-stuck-reassert', os_release='22.04')
    assert 'core: starting Ubuntu' in failed_names('h4-stuck-reassert', inp, 'start')


# ---- command line, release line, assemble --------------------------------------------------------

def run_cli(*args):
    return subprocess.run([sys.executable, '-I', os.path.join(TOOLS, 'histories.py')] + list(args),
                          capture_output=True, text=True)


def test_cli_list_plan_and_judge_exit_codes(tmp_path):
    out = run_cli('list')
    assert out.returncode == 0 and 'h4-stuck-reassert' in out.stdout
    plan = run_cli('plan', 'h2-57-to-58-then-os')
    assert plan.returncode == 0 and 'takserver-58-migrate:5.8' in plan.stdout and 'auto-shutdown 3 hours after creation' in plan.stdout
    _, inp = done_input('h2-57-to-58-then-os')
    good = tmp_path / 'good.json'
    good.write_text(json.dumps(inp))
    assert run_cli('judge', 'h2-57-to-58-then-os', str(good)).returncode == 0
    inp['final_status'] = 'failed:reassert'
    bad = tmp_path / 'bad.json'
    bad.write_text(json.dumps(inp))
    r = run_cli('judge', 'h2-57-to-58-then-os', str(bad))
    assert r.returncode == 1 and 'FAIL upgrade status is done' in r.stderr
    assert run_cli('judge', 'nope', str(good)).returncode == 2
    assert run_cli('judge', 'h2-57-to-58-then-os', str(tmp_path / 'missing.json')).returncode == 2


def test_missing_input_fails_closed_not_open(tmp_path):
    p = tmp_path / 'empty.json'
    p.write_text('{"boxes": {"core": {"after": {}}}}')
    assert run_cli('judge', 'h2-57-to-58-then-os', str(p)).returncode == 1


def test_release_line_names_failed_and_not_run_cells(tmp_path):
    results = [{'cell': 'h2-57-to-58-then-os', 'passed': True}, {'cell': 'h3-old-pg-left-online', 'passed': False}]
    line = hist.release_line_all(results, DATA)
    assert 'h2-57-to-58-then-os passed' in line and 'h3-old-pg-left-online FAILED' in line
    assert 'h5-two-server NOT RUN' in line and line.startswith('Tested on box histories:')


def test_assemble_reads_what_run_scenario_wrote_and_missing_files_are_empty(tmp_path):
    pre = str(tmp_path / 'x')
    for suffix, body in (('-preflight.json', {'ok': False}), ('-start.json', {'http_status': 409, 'ok': False}),
                         ('-client.json', {'passed': True}), ('-core-before.json', {'boot_id': 'a'})):
        (tmp_path / ('x' + suffix)).write_text(json.dumps(body))
    got = hist.assemble(pre, ['core'], final='', candidate='abc')
    assert got['start_response'] == {'http_status': 409, 'ok': False}
    assert got['boxes']['core']['before'] == {'boot_id': 'a'} and got['boxes']['core']['after'] == {}
    assert got['candidate_sha'] == 'abc'


# ---- box.sh against a fake az -------------------------------------------------------------------

FAKE_AZ = r'''#!/usr/bin/env bash
echo "az $*" >> "$FAKE_AZ_LOG"
case "$*" in
  "account show --query id -o tsv") echo "${FAKE_AZ_SUB:-lane-sub}" ;;
  "group exists"*) echo true ;;
  "network vnet show"*) exit 0 ;;
  "vm auto-shutdown"*) [ -n "${FAKE_AZ_NO_SHUTDOWN:-}" ] && exit 1 ;;
  "vm list-ip-addresses"*) echo 198.51.100.7 ;;
  "vm show"*) echo /subscriptions/s/disks/d1 ;;
  "disk list"*) ;;
esac
exit 0
'''


@pytest.fixture
def fake_az(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    az = bin_dir / 'az'
    az.write_text(FAKE_AZ)
    az.chmod(az.stat().st_mode | stat.S_IEXEC)
    ssh = bin_dir / 'ssh'     # box.sh waits for ssh after create/restore
    ssh.write_text('#!/usr/bin/env bash\necho "ssh $*" >> "$FAKE_AZ_LOG"\nexit 0\n')
    ssh.chmod(ssh.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / 'az.log'
    log.write_text('')
    env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ['PATH'], FAKE_AZ_LOG=str(log),
               HIST_SOURCE_CIDR='203.0.113.9/32', HIST_AZURE_SUBSCRIPTION='lane-sub', HIST_SSH_KEY=str(tmp_path / 'k'), HOME=str(tmp_path))
    (tmp_path / 'k.pub').write_text('ssh-ed25519 AAAA test')
    return env, log


def box(env, *args, **extra):
    return subprocess.run(['bash', os.path.join(TOOLS, 'box.sh')] + list(args), capture_output=True, text=True,
                          env=dict(env, **extra))


def lines(log):
    return [l for l in log.read_text().splitlines() if not l.startswith('az account show')]


def test_create_sets_auto_shutdown_before_anything_else_touches_the_box(fake_az):
    env, log = fake_az
    r = box(env, 'create', 'run1', '--cell', 'h2-57-to-58-then-os')
    assert r.returncode == 0, r.stderr
    ls = lines(log)
    create = next(i for i, l in enumerate(ls) if l.startswith('az vm create'))
    shutdown = next(i for i, l in enumerate(ls) if l.startswith('az vm auto-shutdown'))
    first_ssh = next(i for i, l in enumerate(ls) if l.startswith('ssh '))
    assert create < shutdown < first_ssh
    # three hours from now (UTC clock time), never the old fixed 06:00
    import datetime
    want = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=3)).replace(second=0, microsecond=0)
    got = int(ls[shutdown].split('--time ')[1].split()[0])
    mins = lambda hhmm: (hhmm // 100) * 60 + hhmm % 100
    assert abs(mins(got) - (want.hour * 60 + want.minute)) % 1440 <= 2 or abs(mins(got) - (want.hour * 60 + want.minute)) % 1440 >= 1438
    vm_create = ls[create]
    assert 'owner=claude-lane' in vm_create and 'expires=' in vm_create and 'history=h2-57-to-58-then-os' in vm_create
    assert '-g rg-tak-hist' in vm_create and '--nsg-rule NONE' in vm_create
    rule = next(l for l in ls if l.startswith('az network nsg rule create'))
    assert '--source-address-prefixes 203.0.113.9/32' in rule and '0.0.0.0' not in rule and '*' not in rule


def test_a_box_whose_auto_shutdown_fails_is_deleted_again(fake_az):
    env, log = fake_az
    r = box(env, 'create', 'run2', FAKE_AZ_NO_SHUTDOWN='1')
    assert r.returncode != 0
    ls = lines(log)
    assert any(l.startswith('az vm delete') and '-n run2' in l for l in ls)
    assert not any(l.startswith('ssh ') for l in ls)


def test_the_wrong_subscription_is_refused_before_anything_is_created(fake_az):
    env, log = fake_az
    r = box(env, 'create', 'run3', FAKE_AZ_SUB='00000000-0000-0000-0000-000000000000')
    assert r.returncode != 0 and 'not the lane one' in r.stderr
    assert not any('vm create' in l or 'group create' in l for l in lines(log))
    for cmd in (['snapshot', 'run3', 'snap-x'], ['restore', 'snap-x', 'run3'], ['delete', 'run3'], ['sweep']):
        r = box(env, *cmd, FAKE_AZ_SUB='00000000-0000-0000-0000-000000000000')
        assert r.returncode != 0, cmd


def test_snapshot_is_incremental_tagged_and_stops_the_box_first(fake_az):
    env, log = fake_az
    assert box(env, 'snapshot', 'run4', 'snap-h2', '--cell', 'h2-57-to-58-then-os').returncode == 0
    ls = lines(log)
    stop = next(i for i, l in enumerate(ls) if l.startswith('az vm deallocate'))
    snap = next(i for i, l in enumerate(ls) if l.startswith('az snapshot create'))
    assert stop < snap
    assert '--incremental true' in ls[snap] and 'owner=claude-lane' in ls[snap] and 'expires=' in ls[snap]


def test_restore_makes_a_new_box_from_the_snapshot_and_never_changes_it(fake_az):
    env, log = fake_az
    assert box(env, 'restore', 'snap-h2', 'run5').returncode == 0
    ls = lines(log)
    assert any(l.startswith('az disk create') and '--source snap-h2' in l and 'expires=' in l for l in ls)
    assert any(l.startswith('az vm create') and '--attach-os-disk run5-osdisk' in l and 'owner=claude-lane' in l for l in ls)
    assert any(l.startswith('az vm auto-shutdown') and '-n run5' in l for l in ls)
    assert not any(l.startswith('az snapshot delete') or l.startswith('az snapshot update') for l in ls)


def test_delete_also_removes_the_auto_shutdown_schedule_and_never_the_shared_network(fake_az):
    env, log = fake_az
    assert box(env, 'delete', 'run6').returncode == 0
    ls = lines(log)
    assert any('shutdown-computevm-run6' in l for l in ls)
    assert not any('vnet delete' in l for l in ls)
    assert all('-g rg-tak-hist' in l for l in ls if l.startswith(('az vm delete', 'az disk delete', 'az network')))


def test_note_step_refuses_a_label_that_could_carry_a_shell_command(fake_az):
    env, log = fake_az
    r = box(env, 'note-step', 'run7', "x'; rm -rf /; echo '")
    assert r.returncode != 0
    assert not any(l.startswith('ssh ') for l in lines(log))
    assert box(env, 'note-step', 'run7', 'module-deploy:authentik').returncode == 0


def test_without_a_named_subscription_nothing_runs(fake_az):
    env, log = fake_az
    env = {k: v for k, v in env.items() if k != 'HIST_AZURE_SUBSCRIPTION'}
    r = box(env, 'create', 'run9')
    assert r.returncode != 0 and 'HIST_AZURE_SUBSCRIPTION' in r.stderr
    assert log.read_text() == ''
    assert box(env, 'help').returncode == 0


def test_the_public_repo_files_carry_no_subscription_id_or_customer_name():
    import re
    for fname in (f for f in os.listdir(TOOLS) if os.path.isfile(os.path.join(TOOLS, f))):
        text = open(os.path.join(TOOLS, fname), encoding='utf-8', errors='replace').read()
        assert not re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', text), fname
        assert 'CoC_Atak' not in text, fname


def test_dry_run_runs_nothing(fake_az):
    env, log = fake_az
    r = box(env, 'create', 'run8', DRY_RUN='1')
    assert r.returncode == 0 and '+ az vm create' in r.stdout and '+ az vm auto-shutdown' in r.stdout
    assert log.read_text() == ''


def test_a_two_server_box_is_restored_on_its_private_address_and_only_inside_the_lane_network(fake_az):
    env, log = fake_az
    r = box(env, 'restore', 'snap-h5-db', 'run4', '--role', 'db', '--private-ip', '10.50.0.11')
    assert r.returncode == 0, r.stderr
    vm_create = [l for l in log.read_text().splitlines() if l.startswith('az vm create')]
    assert vm_create and '--private-ip-address 10.50.0.11' in vm_create[0]
    for bad in ('192.168.1.5', '10.50.1.5', '10.50.0.11; id', '8.8.8.8'):
        r = box(env, 'create', 'run6', '--private-ip', bad)
        assert r.returncode != 0 and 'lane network' in r.stderr, bad


def test_the_two_server_cell_names_the_private_addresses_and_a_core_with_no_local_database():
    cell = hist.resolve(DATA, 'h5-two-server')
    assert cell['private_ips'] == {'core': '10.50.0.10', 'db': '10.50.0.11'}
    assert cell['start']['clusters'] == []                       # the core of a split box has no local PostgreSQL
    assert hist.resolve(DATA, 'h1-fresh-single:c-docker-tak')['start']['clusters'] == []   # PostgreSQL is in the container
    assert hist.resolve(DATA, 'h1-fresh-single:a-bare')['start']['clusters'] != []


def test_a_restored_database_server_gets_a_new_host_key_so_the_core_forgets_the_old_one_and_the_db_follows_only_a_finished_core():
    cell = hist.resolve(DATA, 'h5-two-server')
    assert any('ssh-keygen -R 10.50.0.11' in c for c in cell['post_prepare'])
    script = open(os.path.join(TOOLS, 'run-scenario.sh'), encoding='utf-8').read()
    assert '[ "$FINAL" = done ] && [ "$(J expect.also_upgrade_db_box' in script


# ---- collect-facts.sh ---------------------------------------------------------------------------

def test_collect_facts_prints_one_json_object_with_every_key_the_judge_reads():
    r = subprocess.run(['bash', os.path.join(TOOLS, 'collect-facts.sh')], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    got = json.loads(r.stdout)
    for key in ('os_release', 'boot_id', 'status', 'clusters', 'services', 'containers', 'baseline_services',
                'baseline_containers', 'apt_conf_left', 'pkg_hash', 'provenance', 'infratak_sha', 'log'):
        assert key in got, key


# ---- the console driver -------------------------------------------------------------------------

class _Stub(http.server.BaseHTTPRequestHandler):
    seen = []
    status_answers = []

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json', cookie=False):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        if cookie:
            self.send_header('Set-Cookie', 'session=abc; Path=/')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n).decode()
        _Stub.seen.append(('POST', self.path, body))
        if self.path == '/login':
            if 'password=right' in body:
                return self._send(200, b'ok', 'text/html', cookie=True)
            return self._send(200, b'<input name="password"> Invalid password', 'text/html')
        if self.path == '/api/console/os-upgrade/start':
            return self._send(409, {'ok': False, 'error': 'preflight failed: takserver_58'})
        self._send(200, {'ok': True})

    def do_GET(self):
        _Stub.seen.append(('GET', self.path, ''))
        if self.path == '/api/console/os-upgrade/status':
            raw = _Stub.status_answers.pop(0) if len(_Stub.status_answers) > 1 else (_Stub.status_answers[0] if _Stub.status_answers else '')
            return self._send(200, {'ok': True, 'raw': raw})
        self._send(200, {'ok': False, 'checks': [{'name': 'takserver_58', 'pass': False, 'detail': 'x'}]})


@pytest.fixture
def stub():
    _Stub.seen = []
    _Stub.status_answers = []
    srv = http.server.HTTPServer(('127.0.0.1', 0), _Stub)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield 'http://127.0.0.1:%d' % srv.server_address[1]
    srv.shutdown()


def test_driver_logs_in_and_sends_the_password_and_typed_acknowledgment_on_start(stub, tmp_path, monkeypatch, capsys):
    pw = tmp_path / 'pw'
    pw.write_text('right\n')
    pw.chmod(0o600)
    monkeypatch.setenv('INFRATAK_CONSOLE_PASSWORD_FILE', str(pw))
    assert drive.main([stub, 'start']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['http_status'] == 409 and out['ok'] is False
    post = next(s for s in _Stub.seen if s[1] == '/api/console/os-upgrade/start')
    body = json.loads(post[2])
    assert body['acknowledge'] == 'I have a snapshot' and body['admin_password'] == 'right' and body['stack_backup'] is True


def test_driver_never_prints_the_password(stub, tmp_path, monkeypatch, capsys):
    pw = tmp_path / 'pw'
    pw.write_text('right\n')
    pw.chmod(0o600)
    monkeypatch.setenv('INFRATAK_CONSOLE_PASSWORD_FILE', str(pw))
    drive.main([stub, 'preflight'])
    drive.main([stub, 'start'])
    cap = capsys.readouterr()
    assert 'right' not in cap.out and 'right' not in cap.err


def test_driver_refuses_a_world_readable_password_file_and_a_wrong_password(stub, tmp_path, monkeypatch, capsys):
    pw = tmp_path / 'pw'
    pw.write_text('right\n')
    pw.chmod(0o644)
    monkeypatch.setenv('INFRATAK_CONSOLE_PASSWORD_FILE', str(pw))
    assert drive.main([stub, 'preflight']) == 2 and 'mode 600' in capsys.readouterr().err
    pw.write_text('wrong\n')
    pw.chmod(0o600)
    assert drive.main([stub, 'preflight']) == 2 and 'refused the password' in capsys.readouterr().err


def test_insecure_tls_is_only_for_an_ip_literal_and_must_be_asked_for():
    drive.Console('https://203.0.113.5:5001', 'x', insecure=True)
    drive.Console('https://[2001:db8::1]:5001', 'x', insecure=True)
    with pytest.raises(drive.DriveError):
        drive.Console('https://console.example.org:5001', 'x', insecure=True)
    con = drive.Console('https://203.0.113.5:5001', 'x')   # default: the certificate is checked
    ctx = [h for h in con.opener.handlers if h.__class__.__name__ == 'HTTPSHandler'][0]._context
    assert ctx.verify_mode.name == 'CERT_REQUIRED' and ctx.check_hostname is True


def test_driver_without_a_password_file_stops(monkeypatch, capsys):
    monkeypatch.delenv('INFRATAK_CONSOLE_PASSWORD_FILE', raising=False)
    assert drive.main(['http://127.0.0.1:9', 'preflight']) == 2


def test_wait_status_rides_out_a_console_that_is_not_answering(monkeypatch):
    calls = {'n': 0}

    class Con:
        password = 'x'

        def login(self):
            pass

        def call(self, method, path, payload=None, timeout=60):
            calls['n'] += 1
            if calls['n'] < 3:
                raise drive.DriveError('cannot reach')
            return 200, {'raw': 'done'}

    monkeypatch.setattr(drive.time, 'sleep', lambda s: None)
    ok, last = drive.wait_status(Con(), 600)
    assert ok and last['raw'] == 'done' and calls['n'] == 3


def test_wait_status_ignores_a_starting_failed_state_only_for_the_grace_period(monkeypatch):
    clock = {'t': 0.0}
    monkeypatch.setattr(drive.time, 'time', lambda: clock['t'])
    monkeypatch.setattr(drive.time, 'sleep', lambda s: clock.update(t=clock['t'] + s))
    answers = iter(['failed:reassert'] * 3 + ['running:reassert', 'verifying', 'done'])

    class Con:
        def login(self):
            pass

        def call(self, method, path, payload=None, timeout=60):
            return 200, {'raw': next(answers)}

    ok, last = drive.wait_status(Con(), 3600, ignore_failed_for=120)
    assert ok and last['raw'] == 'done'

    answers2 = iter(['failed:reassert'] * 50)
    clock['t'] = 0.0

    class Stuck(Con):
        def call(self, method, path, payload=None, timeout=60):
            return 200, {'raw': next(answers2)}

    ok, last = drive.wait_status(Stuck(), 3600, ignore_failed_for=60)
    assert not ok and last['raw'] == 'failed:reassert' and clock['t'] >= 60

    # the finish ran and failed again: that ends the wait at once, however long the grace period is
    answers3 = iter(['failed:reassert', 'running:reassert', 'failed:reassert'] + ['failed:reassert'] * 50)
    clock['t'] = 0.0

    class Retried(Con):
        def call(self, method, path, payload=None, timeout=60):
            return 200, {'raw': next(answers3)}

    ok, last = drive.wait_status(Retried(), 3600, ignore_failed_for=1200)
    assert not ok and last['raw'] == 'failed:reassert' and clock['t'] < 100


def test_dbserver_status_uses_the_core_record_shape():
    assert drive.status_state('dbserver', {'job': 'os-upgrade', 'state': 'done'})[0] == 'done'
    assert drive.status_state('dbserver', {'job': 'os-upgrade', 'state': 'failed'})[0] == 'failed'
    assert drive.status_state('dbserver', {'job': 'updates', 'state': 'done'})[0] == 'other'
    assert drive.status_state('core', {'raw': 'failed:reassert'})[0] == 'failed'


# ---- the test picker (tools/pick-tests.py) ------------------------------------------------------

spec = importlib.util.spec_from_file_location('pick_tests', os.path.join(ROOT, 'tools', 'pick-tests.py'))
pick_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pick_tests)
TIER_MAP = pick_tests.load_map(os.path.join(ROOT, 'tools', 'test-tiers.json'))


def _diff(path, added=(), ctx=''):
    return '\n'.join(['diff --git a/%s b/%s' % (path, path), '--- a/%s' % path, '+++ b/%s' % path,
                      '@@ -1,1 +1,1 @@ %s' % ctx] + ['+' + a for a in added]) + '\n'


def _ids(text):
    result = pick_tests.build_result(pick_tests.parse_diff(text), TIER_MAP)
    return [it['id'] for it in result['required']]


def test_picker_asks_for_the_history_matrix_when_os_upgrade_code_changes():
    assert 'osupgrade' in _ids(_diff('app.py', ['    x = 1'], ctx='def _os_upgrade_pg_layout(clusters, expect="18"):'))
    assert 'osupgrade' in _ids(_diff('app.py', ["_OS_UPGRADE_ACK = 'I have a snapshot'"], ctx='def y():'))
    assert 'osupgrade' in _ids(_diff('app.py', ["    'do-release-upgrade -f DistUpgradeViewNonInteractive'"], ctx='def z():'))
    assert 'osupgrade' in _ids(_diff('app.py', ['    pg_upgradecluster -m upgrade 15 main'], ctx='def run_takserver_58_migration(pkg):'))
    assert 'osupgrade' in _ids(_diff('app.py', ['    y = 2'], ctx='def _startup_os_upgrade_verify():'))


def test_picker_leaves_ordinary_changes_and_the_harness_itself_alone():
    assert 'osupgrade' not in _ids(_diff('app.py', ['    label = "Hello"'], ctx='def home():'))
    assert 'osupgrade' not in _ids(_diff('start.sh', ['echo hi']))
    assert 'osupgrade' not in _ids(_diff('tools/os-upgrade-histories/histories.py', ['_os_upgrade_x = 1']))
    assert 'osupgrade' not in _ids(_diff('tests/test_x.py', ['_os_upgrade_y = 1']))


def test_the_r92_cell_checks_the_tak_server_version_after_the_upgrade():
    cell, inp = done_input('h6-58-r92-then-os')
    inp['boxes']['core']['after']['tak_version'] = '5.8-RELEASE92'
    assert verdict('h6-58-r92-then-os', inp)[0]
    inp['boxes']['core']['after']['tak_version'] = '5.8-RELEASE84'
    assert 'core: TAK Server is 5.8-RELEASE92' in failed_names('h6-58-r92-then-os', inp)
