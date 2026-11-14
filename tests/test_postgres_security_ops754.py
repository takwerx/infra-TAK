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
"""PostgreSQL security release of 2026-11-12 (ops #754).

Three promises, each tested with the real functions cut out of app.py:

  1. A box on an old PostgreSQL is told (Guard Dog email item + Updates panel note) and a box
     on the fixed build is not. The claim needs positive evidence from the package manager.
  2. A Docker database on an old build (Authentik, CloudTAK) is pulled and recreated, its own
     service only, and only when the pull brought a different image. A fixed box is left alone.
  3. The wiring: the email sweep collects the item and the console update runs the converge.
"""

import contextlib
import pathlib
import re
import subprocess as _real_subprocess
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?\n(?=\n)', APP, re.S | re.M).group(0)


VERSION_FUNCS = ('_pg_version_tuple', '_pg_fixed_tuple', '_pg_releases_missing',
                 '_pg_releases_fixed_between')
HOST_FUNCS = VERSION_FUNCS + ('_postgres_host_security_items', '_postgres_security_items',
                              '_upstream_version', '_pkg_restart_impact', '_classify_os_updates',
                              '_is_major_jump')
CONVERGE_FUNCS = VERSION_FUNCS + ('_pg_run', '_pg_stack_container', '_pg_container_version',
                                  '_pg_container_image_state', '_pg_wait_healthy',
                                  '_postgres_compose_converge')

OS_INSTALL_HOW = 'Console page → "Operating system updates available" → Install updates.'


def _impact_table():
    ns = {'re': re}
    exec(compile(_const('_MANAGED_PKG_IMPACT'), 'app.py', 'exec'), ns)   # both assignments
    return ns['_MANAGED_PKG_IMPACT']


def _ns_versions():
    n = {'re': re}
    src = '\n'.join([_const('POSTGRES_SECURITY_RELEASES'), _const('_PG_SERVER_PKG_RE')]
                    + [_cut(f) for f in VERSION_FUNCS])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


def _ns_host(pending=None, pending_error=None):
    n = {'re': re, 'print': lambda *a, **k: None, '_OS_INSTALL_HOW': OS_INSTALL_HOW,
         '_MANAGED_PKG_IMPACT': _impact_table()}

    def fake_pending(*a, **k):
        if pending_error:
            raise pending_error
        return list(pending or [])
    n['_pending_os_updates'] = fake_pending
    src = '\n'.join([_const('POSTGRES_SECURITY_RELEASES'), _const('_PG_SERVER_PKG_RE')]
                    + [_cut(f) for f in HOST_FUNCS])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


def apt(name, old, new):
    return {'name': name, 'old': old + '-1.pgdg22.04+1', 'new': new + '-1.pgdg22.04+1'}


def rpm(name, old, new):
    return {'name': name, 'old': '0:' + old + '-1PGDG.rhel9', 'new': '0:' + new + '-1PGDG.rhel9'}


# ── 1a. the version table ─────────────────────────────────────────────────────

def test_table_has_the_fixed_minors_of_the_nov_12_release():
    (rel,) = _ns_versions()['POSTGRES_SECURITY_RELEASES']
    assert rel['released'] == '2026-11-12'
    assert rel['fixed'] == {14: '14.25', 15: '15.20', 16: '16.16', 17: '17.12', 18: '18.7'}


@pytest.mark.parametrize('v', ['15.19', '18.6', '16.15', '17.11', '14.24',
                               '18.6-1.pgdg22.04+1', '0:15.19-1PGDG.rhel9',
                               'postgres (PostgreSQL) 16.15'])
def test_builds_below_the_fix_are_flagged(v):
    assert [r['id'] for r in _ns_versions()['_pg_releases_missing'](v)] == ['PostgreSQL 2026-11-12']


@pytest.mark.parametrize('v', ['15.20', '18.7', '16.16', '17.12', '14.25', '18.10', '16.20',
                               '18.7-1.pgdg24.04+1', '0:15.20-2PGDG.rhel9',
                               'postgres (PostgreSQL) 16.16'])
def test_fixed_builds_are_not_flagged(v):
    assert _ns_versions()['_pg_releases_missing'](v) == []


@pytest.mark.parametrize('v', ['13.20', '19.0', '', None, 'postgres: not found', '16'])
def test_unknown_major_or_unparseable_version_claims_nothing(v):
    assert _ns_versions()['_pg_releases_missing'](v) == []


def test_a_major_is_never_crossed():
    n = _ns_versions()
    # 15.19 -> 16.16 is a major move: it is not "the fix" for 15
    assert n['_pg_releases_fixed_between']('15.19', '16.16') == []
    assert n['_pg_releases_fixed_between']('15.19', '15.20')
    assert n['_pg_releases_fixed_between']('15.19', '15.19') == []
    assert n['_pg_releases_fixed_between']('15.20', '15.21') == []


# ── 1b. the email item: old build flagged, new build not ──────────────────────

def test_old_build_with_the_fix_on_offer_makes_a_security_item_for_apt_and_dnf():
    for pend in ([apt('postgresql-18', '18.6', '18.7')], [rpm('postgresql18-server', '18.6', '18.7')]):
        (item,) = _ns_host(pend)['_postgres_host_security_items'](pend)
        assert item['key'] == 'pg-host'
        assert item['how'] == OS_INSTALL_HOW
        text = ' '.join(item['security'])
        assert 'PostgreSQL 2026-11-12' in text
        assert 'restarts PostgreSQL' in text          # what the update costs the operator
        assert '18.6' in item['installed'] and '18.7' in item['target']
        assert item['identity'].startswith('pg-PostgreSQL 2026-11-12=')


def test_the_new_build_is_not_flagged():
    n = _ns_host()
    # installed at the fix: a rebuild of the same minor is not a security update
    assert n['_postgres_host_security_items']([apt('postgresql-18', '18.7', '18.7')]) == []
    assert n['_postgres_host_security_items']([rpm('postgresql15-server', '15.20', '15.21')]) == []
    # no update pending at all
    assert n['_postgres_host_security_items']([]) == []


def test_a_pending_update_that_does_not_reach_the_fix_is_not_flagged():
    # PGDG mirror still on 18.6 rebuilds, or a RHEL minor lagging: no evidence the fix is offered
    n = _ns_host()
    assert n['_postgres_host_security_items']([apt('postgresql-18', '18.5', '18.6')]) == []
    assert n['_postgres_host_security_items']([apt('postgresql-18', '18.6', '18.6')]) == []


def test_only_server_packages_count_not_clients_or_extensions():
    n = _ns_host()
    pend = [apt('postgresql-client-18', '18.6', '18.7'), apt('postgresql-18-postgis-3', '3.5.1', '3.5.2'),
            apt('libpq5', '18.6', '18.7'), rpm('postgresql18-contrib', '18.6', '18.7'),
            apt('postgresql-common', '261', '262')]
    assert n['_postgres_host_security_items'](pend) == []


def test_two_majors_on_one_box_make_one_item():
    pend = [apt('postgresql-15', '15.19', '15.20'), apt('postgresql-18', '18.6', '18.7')]
    items = _ns_host(pend)['_postgres_host_security_items'](pend)
    assert len(items) == 1
    assert 'postgresql-15 15.19' in items[0]['installed'] and 'postgresql-18 18.6' in items[0]['installed']


def test_package_manager_that_cannot_answer_goes_to_unknown_not_to_not_security():
    unknown = set()
    n = _ns_host(pending_error=RuntimeError('apt-get simulation failed'))
    assert n['_postgres_security_items'](unknown) == []
    assert unknown == {'pg-host'}


def test_security_items_reads_the_pending_list():
    pend = [apt('postgresql-18', '18.6', '18.7')]
    unknown = set()
    (item,) = _ns_host(pend)['_postgres_security_items'](unknown)
    assert item['key'] == 'pg-host' and unknown == set()


# ── 1c. the Updates panel row says it too ─────────────────────────────────────

def test_updates_panel_row_for_the_database_names_the_security_fix():
    n = _ns_host()
    managed, routine = n['_classify_os_updates'](
        [apt('postgresql-18', '18.6', '18.7'), apt('postgresql-client-18', '18.6', '18.7')])
    (row,) = managed
    assert row['service'] == 'TAK database'
    assert row['impact'].startswith('SECURITY UPDATE (PostgreSQL 2026-11-12)')
    assert 'restarts PostgreSQL' in row['impact']
    assert [p['name'] for p in routine] == ['postgresql-client-18']


def test_updates_panel_row_without_a_fix_has_no_security_note():
    managed, _ = _ns_host()['_classify_os_updates']([apt('postgresql-18', '18.5', '18.6')])
    assert 'SECURITY' not in managed[0]['impact']


# ── 2. the Docker database converge ───────────────────────────────────────────

class FakeDocker:
    """One compose service. State: the running container (id, image, PostgreSQL version) and what
    the image tag points at. `pull_brings` is the (image id, PostgreSQL version) a pull fetches."""

    def __init__(self, running=('sha256:old', '16.15'), tag=('sha256:old', '16.15'), pull_brings=None,
                 up_rc=0, ready=True, running_container=True):
        self.img, self.ver = running
        self.tag_img, self.tag_ver = tag
        self.pull_brings = pull_brings
        self.up_rc, self.ready = up_rc, ready
        self.cid = 'cid1' if running_container else ''
        self.calls, self.pulls = [], []

    def pull(self, compose_yml, cwd, plog, timeout=0, label='', services=None, **kw):
        self.pulls.append((cwd, services))
        if self.pull_brings == 'FAIL':
            return False
        if self.pull_brings:
            self.tag_img, self.tag_ver = self.pull_brings
        return True

    def run(self, argv, *a, **k):
        argv = list(argv)[1:]   # drop the _sudo_wrap marker
        self.calls.append((argv, k.get('cwd')))
        out = lambda rc=0, o='', e='': _real_subprocess.CompletedProcess(argv, rc, o, e)
        if argv[:4] == ['docker', 'compose', 'ps', '-q']:
            return out(0, self.cid + '\n' if self.cid else '')
        if argv[:2] == ['docker', 'exec'] and argv[3:] == ['postgres', '--version']:
            return out(0, 'postgres (PostgreSQL) %s\n' % self.ver) if self.ver else out(126, '', 'nope')
        if argv[:2] == ['docker', 'exec'] and argv[3:] == ['pg_isready', '-q']:
            return out(0 if self.ready else 2)
        if argv[:2] == ['docker', 'inspect']:
            return out(0, '%s postgres:16-alpine\n' % self.img)
        if argv[:3] == ['docker', 'image', 'inspect']:
            return out(0, self.tag_img + '\n')
        if argv[:5] == ['docker', 'compose', 'up', '-d', '--no-deps']:
            if self.up_rc == 0:
                self.cid, self.img, self.ver = 'cid2', self.tag_img, self.tag_ver
            return out(self.up_rc, '', 'boom' if self.up_rc else '')
        raise AssertionError('unexpected docker call: %r' % (argv,))

    @property
    def recreates(self):
        return [a for a, _ in self.calls if a[:5] == ['docker', 'compose', 'up', '-d', '--no-deps']]


def _run_converge(fake, stacks=None, dirs=('~/authentik',)):
    logs, locks = [], []

    @contextlib.contextmanager
    def fake_lock(holder, plog=None, timeout=0):
        locks.append(holder)
        yield True

    n = {'re': re, 'time': time, 'os': types.SimpleNamespace(
        path=types.SimpleNamespace(expanduser=lambda p: p.replace('~', '/home/t'),
                                   isdir=lambda p: p.replace('/home/t', '~') in dirs)),
         'subprocess': types.SimpleNamespace(run=fake.run),
         '_sudo_wrap': lambda argv: ['BROKER'] + list(argv),
         '_docker_compose_pull': fake.pull, '_authentik_compose_lock': fake_lock}
    src = '\n'.join([_const('POSTGRES_SECURITY_RELEASES'), _const('POSTGRES_COMPOSE_STACKS')]
                    + [_cut(f) for f in CONVERGE_FUNCS])
    exec(compile(src, 'app.py', 'exec'), n)
    res = n['_postgres_compose_converge'](logs.append, **({'stacks': stacks} if stacks else {}))
    return res, logs, locks


def test_old_database_container_is_pulled_and_recreated_when_the_pull_brings_a_newer_image():
    fake = FakeDocker(pull_brings=('sha256:new', '16.16'))
    res, logs, locks = _run_converge(fake)
    assert res == {'authentik': 'fixed'}
    assert fake.pulls == [('/home/t/authentik', ['postgresql'])]
    assert fake.recreates == [['docker', 'compose', 'up', '-d', '--no-deps', 'postgresql']]
    assert locks == ['postgres-security-update']      # Authentik: under its compose lock
    assert any('now runs PostgreSQL 16.16' in l for l in logs)


def test_pull_that_finds_nothing_newer_recreates_nothing():
    # the image maker has not rebuilt the tag yet (postgis 17-3.6 on Nov 14): must not restart the DB
    fake = FakeDocker(running=('sha256:old', '17.9'), tag=('sha256:old', '17.9'), pull_brings=('sha256:old', '17.9'))
    res, logs, _ = _run_converge(fake, dirs=('~/CloudTAK',))
    assert res == {'cloudtak': 'waiting'}
    assert fake.recreates == []
    assert any('no newer database image is published yet' in l for l in logs)


def test_fixed_database_is_left_completely_alone():
    fake = FakeDocker(running=('sha256:new', '16.16'), tag=('sha256:new', '16.16'))
    res, _, _ = _run_converge(fake)
    assert res == {'authentik': 'ok'}
    assert fake.pulls == [] and fake.recreates == []


def test_database_that_is_not_running_or_unreadable_is_skipped_without_a_pull():
    for fake in (FakeDocker(running_container=False), FakeDocker(running=('sha256:old', ''))):
        res, _, _ = _run_converge(fake)
        assert res == {'authentik': 'skipped'}
        assert fake.pulls == [] and fake.recreates == []


def test_stack_that_is_not_installed_is_not_touched():
    fake = FakeDocker()
    res, _, _ = _run_converge(fake, dirs=())
    assert res == {} and fake.calls == [] and fake.pulls == []


def test_failed_pull_leaves_the_running_database_alone():
    fake = FakeDocker(pull_brings='FAIL')
    res, _, _ = _run_converge(fake)
    assert res == {'authentik': 'failed'} and fake.recreates == []


def test_failed_recreate_is_reported_failed():
    fake = FakeDocker(pull_brings=('sha256:new', '16.16'), up_rc=1)
    res, logs, _ = _run_converge(fake)
    assert res == {'authentik': 'failed'}
    assert any('recreating the database failed' in l for l in logs)


def test_recreate_that_does_not_come_back_healthy_is_reported_failed(monkeypatch):
    fake = FakeDocker(pull_brings=('sha256:new', '16.16'), ready=False)
    monkeypatch.setattr(time, 'sleep', lambda s: None)
    t = iter(range(0, 10_000, 40))
    monkeypatch.setattr(time, 'time', lambda: next(t))
    res, logs, _ = _run_converge(fake)
    assert res == {'authentik': 'failed'}
    assert any('reports PostgreSQL nothing' in l for l in logs)


def test_only_the_database_service_is_ever_recreated_and_never_its_dependents():
    fake = FakeDocker(pull_brings=('sha256:new', '16.16'))
    _run_converge(fake)
    for argv, cwd in fake.calls:
        if argv[:3] == ['docker', 'compose', 'up']:
            assert '--no-deps' in argv and argv[-1] == 'postgresql'
            assert 'down' not in argv and '--force-recreate' not in argv
        assert argv[:3] != ['docker', 'compose', 'down']


def test_the_stacks_are_the_local_floating_tag_databases():
    ns = {}
    exec(compile(_const('POSTGRES_COMPOSE_STACKS'), 'app.py', 'exec'), ns)
    assert [(k, d, s) for k, _, d, s in ns['POSTGRES_COMPOSE_STACKS']] == [
        ('authentik', '~/authentik', 'postgresql'), ('cloudtak', '~/CloudTAK', 'postgis'),
        ('takportal', '~/TAK-Portal', 'postgres'), ('remote_assist', '~/eud-remote-assist', 'postgres')]


# ── 3. wiring ─────────────────────────────────────────────────────────────────

def _func_src(name):
    return _cut(name)


def test_the_email_sweep_collects_the_database_item():
    assert '_postgres_security_items(unknown)' in _func_src('_collect_pending_updates')


def test_the_console_update_runs_the_converge_after_the_container_steps():
    i_conv = APP.index('_postgres_compose_converge(lambda m: print(f"Post-update: {m}"')
    i_harden = APP.index('            _auto_harden_mediamtx()\n')
    i_orphans = APP.index('# Final orphan postgres kill')
    i_done = APP.index('print("Post-update: auto-deploy complete")')
    assert i_harden < i_conv < i_orphans < i_done
