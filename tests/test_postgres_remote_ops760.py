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
"""PostgreSQL security release of 2026-11-12 for a database on ANOTHER machine (ops #760).

ops #754 told hosts with PostgreSQL packages and refreshed local Docker databases. A split box
(database on Server One) and a managed database (Amazon RDS, Azure) have neither, so nobody was
told. Promises, each tested with the real functions cut out of app.py:

  1. A remote database below the fix gives one email item and one panel answer; at or above the
     fix gives none; a version that cannot be read says so and is never counted as fixed.
  2. The version is read with one fixed read-only query, the password only in the environment, and
     nothing is installed or written on the page-load path.
  3. A Docker app whose database is not a local container is left alone and never reported fixed.
  4. The wiring: the email sweep, the route and the console banner.
"""

import pathlib
import re
import subprocess as _real_subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CONSOLE = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?\n(?=\n)', APP, re.S | re.M).group(0)


VERSION_FUNCS = ('_pg_version_tuple', '_pg_fixed_tuple', '_pg_releases_missing')
REMOTE_FUNCS = VERSION_FUNCS + ('_pg_remote_kind', '_pg_remote_where', '_pg_remote_read_error',
                                '_pg_remote_server_version', '_postgres_remote_status',
                                '_postgres_remote_items', '_postgres_remote_security_items',
                                '_postgres_remote_panel')


def _ns(**over):
    n = {'re': re, 'print': lambda *a, **k: None, 'os': types.SimpleNamespace(environ={'PATH': '/bin'}),
         'subprocess': _real_subprocess, 'time': __import__('time'),
         '_pg_dbserver_manageable': lambda host: False}      # ops #766: no SSH link to a database server
    n.update(over)
    src = '\n'.join([_const('POSTGRES_SECURITY_RELEASES'), _const('_PG_RDS_HOST_RE'),
                     _const('_PG_AZURE_HOST_RE'), _const('_PG_REMOTE_CACHE'), _const('_PG_REMOTE_TTL')]
                    + [_cut(f) for f in REMOTE_FUNCS])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


RDS = 'tak-db.abc123xyz.us-east-1.rds.amazonaws.com'
AURORA = 'tak.cluster-abc123xyz.us-west-2.rds.amazonaws.com'
AZURE = 'tak-db.postgres.database.azure.com'
SPLIT = '10.20.30.40'


def _status(host, version, reason=''):
    n = _ns()
    return n['_postgres_remote_status'](('remote', host, 5432), reader=lambda: (version, reason))


# ── 1. below the fix is flagged, at the fix is not, unreadable says so ────────

@pytest.mark.parametrize('host,kind', [(RDS, 'rds'), (AURORA, 'rds'), (AZURE, 'azure'),
                                       (SPLIT, 'split'), ('db.example.org', 'split'),
                                       ('evil-rds.amazonaws.com.attacker.net', 'split')])
def test_who_runs_the_database_is_read_from_the_host_name(host, kind):
    assert _ns()['_pg_remote_kind'](host) == kind


@pytest.mark.parametrize('host', [RDS, AZURE, SPLIT])
@pytest.mark.parametrize('ver', ['18.6', '17.11', '16.15', '15.19', '14.24'])
def test_remote_database_below_the_fix_gives_one_security_item(host, ver):
    n = _ns()
    st = _status(host, ver)
    assert st['state'] == 'update' and st['version'] == ver
    (item,) = n['_postgres_remote_items'](st)
    text = ' '.join(item['security'])
    assert item['key'] == 'pg-remote'
    assert 'PostgreSQL 2026-11-12' in text
    assert host in item['summary'] and ver in item['installed']
    assert 'changes nothing on that database' in text
    assert 'restarts the database' in text


def test_the_email_says_what_to_do_where_the_database_runs():
    n = _ns()
    rds = ' '.join(n['_postgres_remote_items'](_status(RDS, '16.15'))[0]['security'])
    assert ('Your TAK database runs on Amazon RDS. Apply the PostgreSQL minor update in the AWS console, '
            'or turn on auto minor version upgrade.') in rds
    az = ' '.join(n['_postgres_remote_items'](_status(AZURE, '16.15'))[0]['security'])
    assert 'Azure Database for PostgreSQL' in az and 'Azure portal' in az
    split = ' '.join(n['_postgres_remote_items'](_status(SPLIT, '16.15'))[0]['security'])
    assert f'Your TAK database runs on {SPLIT}. Update PostgreSQL on that machine.' in split
    assert 'AWS' not in split and 'RDS' not in split


@pytest.mark.parametrize('ver', ['18.7', '17.12', '16.16', '15.20', '14.25', '18.10', '16.20'])
def test_remote_database_at_or_above_the_fix_gives_no_item(ver):
    n = _ns()
    st = _status(RDS, ver)
    assert st['state'] == 'ok'
    assert n['_postgres_remote_items'](st) == []


def test_a_major_the_table_does_not_list_claims_nothing():
    n = _ns()
    for ver in ('13.20', '19.0'):
        st = _status(SPLIT, ver)
        assert st['state'] == 'ok' and n['_postgres_remote_items'](st) == []


@pytest.mark.parametrize('version,reason', [
    ('', 'could not connect to the database'), ('', 'the saved login was refused or is missing'),
    ('', 'the database did not answer in time'), ('weird', ''), ('', '')])
def test_unreadable_version_is_unknown_and_never_fixed(version, reason):
    n = _ns()
    st = _status(RDS, version, reason)
    assert st['state'] == 'unknown' and st['version'] == ''
    (item,) = n['_postgres_remote_items'](st)
    text = ' '.join(item['security'])
    assert 'could not read the PostgreSQL version' in text
    assert 'Amazon RDS' in text                      # still says where to look
    assert '16.16' in text and '18.7' in text        # and what "fixed" is
    assert 'fixed' not in item['summary'].lower().replace('could not be checked', '')
    assert item['identity'].startswith('pg-remote-unknown-')


def test_the_unknown_reason_never_carries_raw_error_text():
    n = _ns()
    st = _status(SPLIT, '', n['_pg_remote_read_error'](2, 'FATAL: password authentication failed for user "martiuser" at 10.20.30.40'))
    text = ' '.join(n['_postgres_remote_items'](st)[0]['security'])
    assert 'martiuser' not in text and 'FATAL' not in text


def test_a_database_on_this_box_is_not_remote():
    n = _ns()
    for topo in (('local', '127.0.0.1', 5432), ('container', 'takserver-db', 5432)):
        assert n['_postgres_remote_status'](topo, reader=lambda: pytest.fail('must not connect')) is None
    assert n['_postgres_remote_items'](None) == []


def test_the_identity_is_per_host_and_per_release_so_it_mails_once():
    n = _ns()
    a = n['_postgres_remote_items'](_status(RDS, '16.15'))[0]['identity']
    assert a == n['_postgres_remote_items'](_status(RDS, '16.14'))[0]['identity']   # same release, same mail
    assert a != n['_postgres_remote_items'](_status(AZURE, '16.15'))[0]['identity']  # another database
    assert a.startswith('pg-remote-PostgreSQL 2026-11-12=')


def test_a_failed_check_goes_to_unknown_not_to_not_security():
    unknown = set()

    def boom(*a, **k):
        raise RuntimeError('coreconfig unreadable')
    n = _ns(_tak_db_topology=boom)
    assert n['_postgres_remote_security_items'](unknown) == []
    assert unknown == {'pg-remote'}


def test_the_sweep_path_may_install_a_client_and_the_page_path_may_not():
    seen = []

    def status(topology=None, reader=None, allow_install=False):
        seen.append(allow_install)
        return None
    n = _ns()
    n['_postgres_remote_status'] = status
    n['_postgres_remote_security_items'](set())
    n['_postgres_remote_panel'](force=True)
    assert seen == [True, False]


# ── 2. how the version is read ────────────────────────────────────────────────

class FakePsql:
    def __init__(self, rc=0, out='16.15\n', err='', raises=None):
        self.rc, self.out, self.err, self.raises, self.calls = rc, out, err, raises, []

    def run(self, argv, **kw):
        self.calls.append((list(argv), kw))
        if self.raises:
            raise self.raises
        return _real_subprocess.CompletedProcess(argv, self.rc, self.out, self.err)


def _reader_ns(fake, params=(RDS, 5432, 'cot', 'martiuser', 's3cret!'), client='/usr/lib/postgresql/18/bin/psql',
               ensure=None):
    return _ns(subprocess=types.SimpleNamespace(run=fake.run, TimeoutExpired=_real_subprocess.TimeoutExpired),
               _cot_conn_params=lambda: params, _psql_client_bin=lambda: client,
               _ensure_psql_client=ensure or (lambda: '/installed/psql'))


def test_the_version_is_read_with_one_fixed_read_only_query_and_the_password_stays_out_of_argv():
    fake = FakePsql()
    n = _reader_ns(fake)
    assert n['_pg_remote_server_version']() == ('16.15', '')
    (argv, kw), = fake.calls
    assert argv[argv.index('-c') + 1] == 'SHOW server_version;'
    assert argv.count('-c') == 1
    assert '-w' in argv                                    # never prompts
    assert argv[argv.index('-h') + 1] == RDS and argv[argv.index('-U') + 1] == 'martiuser'
    assert 's3cret!' not in ' '.join(argv)
    assert kw['env']['PGPASSWORD'] == 's3cret!'


def test_a_managed_service_version_string_is_parsed():
    # RDS and Azure answer SHOW server_version with the bare version; Debian builds add a suffix
    for out in ('16.15\n', '16.15 (Debian 16.15-1.pgdg120+1)\n'):
        n = _reader_ns(FakePsql(out=out))
        st = n['_postgres_remote_status'](('remote', RDS, 5432))
        assert st['state'] == 'update' and st['version'] == '16.15'


def test_a_login_that_cannot_be_used_is_unknown_without_connecting():
    fake = FakePsql()
    for params in ((RDS, 5432, 'cot', 'martiuser', ''), ('', 5432, 'cot', 'martiuser', 'pw')):
        n = _reader_ns(fake, params=params)
        assert n['_pg_remote_server_version']() == ('', 'the saved login was refused or is missing')
    assert fake.calls == []


def test_no_psql_client_is_installed_on_the_page_path():
    called = []
    fake = FakePsql()
    n = _reader_ns(fake, client='', ensure=lambda: called.append(1) or '/installed/psql')
    assert n['_pg_remote_server_version'](allow_install=False) == ('', 'this machine has no PostgreSQL client')
    assert called == [] and fake.calls == []
    assert n['_pg_remote_server_version'](allow_install=True) == ('16.15', '')
    assert called == [1]


@pytest.mark.parametrize('kw,reason', [
    (dict(rc=2, err='psql: error: connection to server at "x" failed: Connection refused'),
     'could not connect to the database'),
    (dict(rc=2, err='FATAL:  password authentication failed for user "martiuser"'),
     'the saved login was refused or is missing'),
    (dict(rc=2, err='FATAL: no pg_hba.conf entry for host'), 'the saved login was refused or is missing'),
    (dict(raises=_real_subprocess.TimeoutExpired('psql', 15)), 'the database did not answer in time'),
    (dict(raises=OSError('no such file')), 'this machine has no PostgreSQL client'),
    (dict(rc=0, out='\n'), 'the database gave no readable version'),
])
def test_a_failed_read_gives_a_plain_reason_and_no_version(kw, reason):
    assert _reader_ns(FakePsql(**kw))['_pg_remote_server_version']() == ('', reason)


# ── the console page answer ───────────────────────────────────────────────────

def test_the_panel_answer_for_each_state_and_it_is_cached():
    calls = []

    def status(topology=None, reader=None, allow_install=False):
        calls.append(1)
        return _status(RDS, '16.15')
    n = _ns()
    n['_postgres_remote_status'] = status
    d = n['_postgres_remote_panel'](force=True)
    assert d['remote'] and d['state'] == 'update' and d['missing'] == ['PostgreSQL 2026-11-12']
    assert '16.15' in d['headline'] and RDS in d['headline'] and 'Amazon RDS' in d['where']
    assert n['_postgres_remote_panel']() is d and len(calls) == 1          # cached
    n['_postgres_remote_status'] = lambda **k: None
    assert n['_postgres_remote_panel'](force=True) == {'remote': False}
    n['_postgres_remote_status'] = lambda **k: _status(SPLIT, '', 'could not connect to the database')
    d = n['_postgres_remote_panel'](force=True)
    assert d['state'] == 'unknown' and 'Could not check' in d['headline'] and d['version'] == ''
    n['_postgres_remote_status'] = lambda **k: _status(SPLIT, '16.16')
    assert 'headline' not in n['_postgres_remote_panel'](force=True)


def test_a_check_that_raises_is_unknown_on_the_panel_not_fixed():
    def boom(**k):
        raise RuntimeError('x')
    n = _ns()
    n['_postgres_remote_status'] = boom
    d = n['_postgres_remote_panel'](force=True)
    assert d['remote'] and d['state'] == 'unknown'


# ── 3. Docker apps whose database is not a local container ────────────────────

def test_a_docker_app_on_an_external_database_is_skipped_and_never_reported_fixed():
    """Authentik, CloudTAK, TAK Portal on a database that is not a local compose service: the
    converge must neither fail, pull, recreate, nor claim the database is fixed."""
    ns = {'re': re, 'time': __import__('time')}
    src = '\n'.join([_const('POSTGRES_SECURITY_RELEASES'), _const('POSTGRES_COMPOSE_STACKS')]
                    + [_cut(f) for f in VERSION_FUNCS + ('_pg_run', '_pg_stack_container',
                                                         '_pg_container_version', '_pg_container_image_state',
                                                         '_pg_image_version', '_pg_wait_healthy',
                                                         '_postgres_compose_converge')])
    calls, pulls, logs = [], [], []

    def run(argv, **kw):
        calls.append(list(argv)[1:])
        # `docker compose ps -q postgresql` on a stack with no such service: exit 1, nothing printed
        return _real_subprocess.CompletedProcess(argv, 1, '', 'no such service: postgresql')
    ns.update({'os': types.SimpleNamespace(path=types.SimpleNamespace(
        expanduser=lambda p: p.replace('~', '/home/t'), isdir=lambda p: True)),
        'subprocess': types.SimpleNamespace(run=run), '_sudo_wrap': lambda a: ['BROKER'] + list(a),
        '_docker_compose_pull': lambda *a, **k: pulls.append(a) or True})
    exec(compile(src, 'app.py', 'exec'), ns)
    res = ns['_postgres_compose_converge'](logs.append)
    assert res == {k: 'skipped' for k in ('authentik', 'cloudtak', 'takportal', 'remote_assist')}
    assert 'fixed' not in res.values() and pulls == []
    assert all(c[:4] == ['docker', 'compose', 'ps', '-q'] for c in calls)    # only ever read
    assert logs == []


# ── 4. wiring ─────────────────────────────────────────────────────────────────

def test_the_email_sweep_collects_the_remote_database_item():
    body = _cut('_collect_pending_updates')
    assert '_postgres_remote_security_items(unknown)' in body
    assert body.index('_postgres_security_items(unknown)') < body.index('_postgres_remote_security_items(unknown)')


def test_the_route_needs_a_login():
    m = re.search(r"@app\.route\('/api/postgres-remote'\)\n@login_required\ndef postgres_remote_api\(", APP)
    assert m


def test_the_console_page_has_the_banner_and_asks_the_route():
    assert 'id="pg-remote-banner"' in CONSOLE
    assert "fetch('/api/postgres-remote'" in CONSOLE
    assert re.search(r'^checkPgRemote\(\);$', CONSOLE, re.M)
    assert 'changes nothing on it' in CONSOLE                    # the banner says it is read-only
