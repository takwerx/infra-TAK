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
"""The Authentik server's channel-layer LISTEN goes to Postgres directly (ops #177).

Behind PgBouncer's transaction pooling the server never heard NOTIFY, so no outpost got a
config push (the LDAP outpost waited for its 5-min refresh). Authentik 2026.8 moves that
LISTEN to a direct alias when `postgresql.direct.*` is set.
_ensure_authentik_server_direct_listen() is cut out of app.py and run against a temp
~/authentik with docker stubbed: `compose up` makes the fake server load .env, and
`ak dump_config` reports what it loaded.
"""

import contextlib
import datetime
import json
import os
import pathlib
import re
import stat
import subprocess
import types

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
LINE = 'AUTHENTIK_POSTGRESQL__DIRECT__HOST=postgresql'
PG_PASS = 'pg-secret-do-not-log'
ENV = ('PG_PASS=%s\nAUTHENTIK_POSTGRESQL__HOST=pgbouncer\nAUTHENTIK_POSTGRESQL__PORT=5432\n'
       'AUTHENTIK_POSTGRESQL__DISABLE_SERVER_SIDE_CURSORS=true\n' % PG_PASS)
UP = ['docker', 'compose', 'up', '-d', '--force-recreate', '--no-deps', 'server']


def _src(name):
    return re.search(r'^def %s\(.*?(?=^def |^# ops #177: fleet constant|\Z)' % name, APP, re.S | re.M).group(0)


def _compose(server_host='pgbouncer', pgbouncer=True, server_env=None):
    svcs = {'postgresql': {'image': 'docker.io/library/postgres:16-alpine'},
            'server': {'environment': server_env or {'AUTHENTIK_POSTGRESQL__HOST': server_host}},
            'worker': {'environment': {'AUTHENTIK_POSTGRESQL__HOST': 'postgresql'}}}
    if pgbouncer:
        svcs['pgbouncer'] = {'image': 'edoburu/pgbouncer:v1.26.1-p0'}
    return {'services': svcs}


def _direct_in(env_text):
    hosts = [ln.split('=', 1)[1].strip() for ln in env_text.splitlines()
             if re.match(r'^\s*AUTHENTIK_POSTGRESQL__DIRECT__HOST\s*=', ln)]
    return hosts[-1] if hosts else ''


def _run(tmp_path, env=ENV, compose=None, live=None, up_rc=0, loads=True, healthy=True, locked=True,
         dump_rc=0):
    """`live` = postgresql.direct.host the running server has now (None = can't read it).
    `loads=False` = a recreated server comes up WITHOUT the new key (verify must catch it)."""
    ak = tmp_path / 'authentik'
    ak.mkdir()
    (ak / '.env').write_text(env)
    os.chmod(ak / '.env', 0o600)
    (ak / 'docker-compose.yml').write_text(yaml.safe_dump(compose or _compose(), sort_keys=False))
    calls, settings, log, recycle = [], {}, [], []
    st = {'direct': live or '', 'readable': live is not None}

    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[:3] == ['docker', 'compose', 'up']:
            if up_rc == 0:
                st['direct'] = _direct_in((ak / '.env').read_text()) if loads else ''
                st['readable'] = True
            return subprocess.CompletedProcess(cmd, up_rc, stdout='', stderr='up boom' if up_rc else '')
        if cmd[:2] == ['docker', 'exec'] and cmd[-2:] == ['ak', 'dump_config']:
            if not st['readable'] or dump_rc:
                return subprocess.CompletedProcess(cmd, dump_rc or 1, stdout='', stderr='No such container')
            pg = {'host': 'pgbouncer', 'password': PG_PASS}
            if st['direct']:
                pg['direct'] = {'host': st['direct']}
            return subprocess.CompletedProcess(
                cmd, 0, stdout='{"level": "info", "event": "Loaded config"}\n' + json.dumps({'postgresql': pg}))
        raise AssertionError(cmd)

    @contextlib.contextmanager
    def lock(holder, plog=None):
        yield locked

    ns = {
        'os': types.SimpleNamespace(path=types.SimpleNamespace(
            expanduser=lambda p: str(ak) if p == '~/authentik' else p,
            join=os.path.join, exists=os.path.exists), chmod=os.chmod),
        'subprocess': types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired),
        'datetime': datetime.datetime,
        'json': json,
        're': re,
        'VERSION': 'test',
        '_sudo_wrap': lambda c: c,
        '_authentik_compose_lock': lock,
        'load_settings': lambda: settings,
        'save_settings': lambda s: settings.update(s),
        '_wait_for_authentik_stack_healthy': lambda plog, timeout=0: calls.append(['wait-healthy']) or healthy,
        '_tak_ldap_recycle_request': lambda reason, need_groups=True, restart=False: recycle.append(reason),
    }
    ns['_ak_compose_subprocess'] = lambda cmd, holder, plog=None, wait=None, **kw: ns['subprocess'].run(cmd, **kw)
    exec(compile(re.search(r'^_AK_DIRECT_HOST_LINE = .*?\n_AK_DIRECT_HOST_RE = .*?\n', APP, re.S | re.M).group(0),
                 'app.py:consts', 'exec'), ns)
    for name in ('_ak_compose_service_env', '_authentik_server_direct_host_live',
                 '_ensure_authentik_server_direct_listen'):
        exec(compile(_src(name), f'app.py:{name}', 'exec'), ns)
    out = ns['_ensure_authentik_server_direct_listen'](log.append)
    return types.SimpleNamespace(out=out, env=(ak / '.env').read_text(), calls=calls, settings=settings,
                                 log='\n'.join(log), recycle=recycle, ak=ak, live=st['direct'])


def _ups(r):
    return [c for c in r.calls if c[:3] == ['docker', 'compose', 'up']]


def test_stock_box_gets_the_line_and_only_the_server_is_recreated(tmp_path):
    r = _run(tmp_path, live='')
    assert r.out is True
    assert r.env.startswith(ENV)                                  # every existing line kept
    assert [ln for ln in r.env.splitlines() if 'DIRECT' in ln and not ln.startswith('#')] == [LINE]
    assert _ups(r) == [UP]                                         # server only: no worker, no ldap
    assert r.live == 'postgresql'
    assert r.settings['authentik_server_direct_listen']['last_outcome'] == 'applied'
    assert len(r.recycle) == 1                                     # the recreate was an LDAP blip under TAK
    bak = [p for p in r.ak.iterdir() if '.bak.before-server-direct-listen.' in p.name]
    assert len(bak) == 1 and bak[0].read_text() == ENV
    assert stat.S_IMODE(bak[0].stat().st_mode) == 0o600            # holds PG_PASS


def test_done_box_is_a_noop(tmp_path):
    r = _run(tmp_path, env=ENV + LINE + '\n', live='postgresql')
    assert r.out is False
    assert _ups(r) == [] and r.recycle == []
    assert r.env == ENV + LINE + '\n'


def test_second_run_after_applying_is_a_noop(tmp_path):
    (tmp_path / 'a').mkdir()
    (tmp_path / 'b').mkdir()
    first = _run(tmp_path / 'a', live='')
    r = _run(tmp_path / 'b', env=first.env, live='postgresql')
    assert r.out is False and _ups(r) == []
    assert r.env == first.env                                      # no second comment block


def test_line_in_env_but_server_never_loaded_it_is_recreated(tmp_path):
    r = _run(tmp_path, env=ENV + LINE + '\n', live='')
    assert r.out is True
    assert _ups(r) == [UP]
    assert r.env == ENV + LINE + '\n'


def test_unreadable_live_config_with_line_set_does_not_recreate(tmp_path):
    r = _run(tmp_path, env=ENV + LINE + '\n', live=None)
    assert r.out is False and _ups(r) == []


def test_other_value_is_replaced_in_place(tmp_path):
    env = ENV + 'AUTHENTIK_POSTGRESQL__DIRECT__HOST=pgbouncer\nAUTHENTIK_POSTGRESQL__DIRECT__HOST = x\nTAIL=1\n'
    r = _run(tmp_path, env=env, live='x')
    assert r.out is True
    assert r.env == ENV + LINE + '\nTAIL=1\n'                      # fleet constant, one line, same spot


def test_not_bundled_topology_is_left_alone(tmp_path):
    for i, compose in enumerate((_compose(pgbouncer=False), _compose(server_host='postgresql'),
                                 _compose(server_host='db.example.org'))):
        sub = tmp_path / str(i)
        sub.mkdir()
        r = _run(sub, compose=compose, live='')
        assert r.out is False, compose
        assert r.calls == [] and r.env == ENV


def test_direct_key_in_compose_environment_is_left_alone(tmp_path):
    # compose `environment:` beats env_file — a .env line would never load and would loop.
    for i, env in enumerate(({'AUTHENTIK_POSTGRESQL__HOST': 'pgbouncer', 'AUTHENTIK_POSTGRESQL__DIRECT__HOST': 'pg2'},
                             ['AUTHENTIK_POSTGRESQL__HOST=pgbouncer', 'AUTHENTIK_POSTGRESQL__DIRECT__PORT=6432'])):
        sub = tmp_path / str(i)
        sub.mkdir()
        r = _run(sub, compose=_compose(server_env=env), live='')
        assert r.out is False and r.calls == [] and r.env == ENV


def test_server_up_without_the_key_is_rolled_back(tmp_path):
    r = _run(tmp_path, live='', loads=False)
    assert r.out is None
    assert r.env == ENV                                            # byte-for-byte
    assert _ups(r) == [UP, UP]
    assert r.settings['authentik_server_direct_listen']['last_outcome'] == 'rolled-back'
    assert len(r.recycle) == 1


def test_unhealthy_server_is_rolled_back(tmp_path):
    r = _run(tmp_path, live='', healthy=False)
    assert r.out is None and r.env == ENV and _ups(r) == [UP, UP]
    assert r.settings['authentik_server_direct_listen']['last_outcome'] == 'rolled-back'


def test_failed_recreate_restores_env(tmp_path):
    r = _run(tmp_path, live='', up_rc=1)
    assert r.out is None and r.env == ENV
    assert r.settings['authentik_server_direct_listen']['last_outcome'] == 'recreate-failed'


def test_busy_lock_changes_nothing(tmp_path):
    r = _run(tmp_path, live='', locked=False)
    assert r.out is None and r.env == ENV and r.calls == [] and r.recycle == []


def test_dump_config_secrets_never_logged(tmp_path):
    for i, kw in enumerate(({'live': ''}, {'live': '', 'loads': False})):
        sub = tmp_path / str(i)
        sub.mkdir()
        assert PG_PASS not in _run(sub, **kw).log


def test_fresh_install_env_has_the_line():
    tpl = APP[APP.index('env_content = f"""PG_DB=authentik\nPG_USER=authentik\nPG_PASS={pg_pass}\n'
                        'AUTHENTIK_SECRET_KEY={secret_key}\nCOMPOSE_PORT_HTTP=9090\nCOMPOSE_PORT_HTTPS=9443\n'
                        'AUTHENTIK_ERROR_REPORTING__ENABLED=false\n# v10.1.17'):]
    tpl = tpl[:tpl.index('with open(env_path')]
    assert '_AK_DIRECT_HOST_LINE + "\\n"' in tpl
    assert re.search(r"^_AK_DIRECT_HOST_LINE = 'AUTHENTIK_POSTGRESQL__DIRECT__HOST=postgresql'$", APP, re.M)


def test_boot_and_deploy_run_it_after_the_worker_move():
    boot = APP[APP.index('_ensure_authentik_worker_direct_pg(lambda m:'):]
    assert '_ensure_authentik_server_direct_listen(lambda m:' in boot[:1500]
    deploy = APP[APP.index('            _ensure_authentik_worker_direct_pg(plog)\n'):]
    assert deploy.index('_ensure_authentik_server_direct_listen(plog)') < deploy.index('redis + pgbouncer up inline')
