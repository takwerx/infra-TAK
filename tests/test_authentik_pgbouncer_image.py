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
"""Existing PgBouncer sidecars are moved onto the pinned image (ops #91, ops #123).

_ensure_authentik_pgbouncer() writes `_AUTHENTIK_PGBOUNCER_IMAGE` only when it first adds
the service, so bumping the pin never reached a box that already had PgBouncer.
_ensure_authentik_pgbouncer_image() is cut out of app.py and run against a temp compose
with docker, ldapsearch and the clock stubbed.

ops #123: after the v10.2.22 swap to v1.26.1-p0, TAK users reconnected with no groups.
The pin went back to v1.25.1-p0, and a swap is only accepted once a live adm_ldapservice
bind plus users' memberOf hold through the outpost.

ops #151: the pin returns to v1.26.1-p0, so the fleet swaps 1.25.1 → 1.26.1 again.
"""

import contextlib
import datetime
import os
import pathlib
import re
import subprocess
import threading
import types

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
PIN = re.search(r"^_AUTHENTIK_PGBOUNCER_IMAGE = '([^']+)'", APP, re.M).group(1)
OTHER = 'edoburu/pgbouncer:v1.25.1-p0'     # what v10.2.23 put boxes back on
SA_PASS = 'sa-secret-do-not-log'


def _src(name):
    return re.search(r'^def %s\(.*?(?=^def |\Z)' % name, APP, re.S | re.M).group(0)


def _compose(image):
    return {'services': {
        'postgresql': {'image': 'docker.io/library/postgres:16-alpine'},
        'pgbouncer': {'image': image, 'environment': {'DB_HOST': 'postgresql'}},
        'server': {'environment': {'AUTHENTIK_POSTGRESQL__HOST': 'pgbouncer'}},
    }}


def _ldif(users, groups):
    out = []
    for i in range(users):
        out.append(f'dn: cn=user{i},ou=users,dc=takldap')
        if i < groups:
            out.append('memberOf: cn=tak_OPS,ou=groups,dc=takldap')
        out.append('memberOf: cn=authentik Admins,ou=groups,dc=takldap')
        out.append('')
    return '\n'.join(out) + '\nresult: 0 Success\n'


def healthy(live):
    return 0, 3


def _run(tmp_path, image, pull_rc=0, up_rc=0, inspect=None, ldap=healthy, sa_pass=SA_PASS, raw=None,
         cred_changed=False):
    """`ldap(live) -> (rc, tak_groups)` scripts the outpost; `live` carries the running
    pgbouncer image, how many server/worker/ldap restarts happened, and the fake clock."""
    ak = tmp_path / 'authentik'
    ak.mkdir()
    (ak / 'docker-compose.yml').write_text(raw or yaml.safe_dump(_compose(image), sort_keys=False))
    calls, settings, log = [], {}, []
    live = {'image': image, 'restarts': 0, 't': 0.0, 'probes': 0}

    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ['docker', 'pull']:
            return subprocess.CompletedProcess(cmd, pull_rc, stdout='', stderr='pull boom' if pull_rc else '')
        if cmd[:3] == ['docker', 'compose', 'up']:
            live['image'] = yaml.safe_load((ak / 'docker-compose.yml').read_text())['services']['pgbouncer']['image']
            return subprocess.CompletedProcess(cmd, up_rc, stdout='', stderr='up boom' if up_rc else '')
        if cmd[:3] == ['docker', 'compose', 'restart']:
            if 'ldap' in cmd:
                live['restarts'] += 1
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
        if cmd[:2] == ['docker', 'inspect']:
            return subprocess.CompletedProcess(cmd, 0, stdout=inspect or f"{live['image']} running healthy\n")
        if cmd[0] == 'ldapsearch':
            live['probes'] += 1
            rc, groups = ldap(live)
            if rc == 49:
                return subprocess.CompletedProcess(cmd, 49, stdout='', stderr='ldap_bind: Invalid credentials (49)\n')
            return subprocess.CompletedProcess(cmd, rc, stdout=_ldif(5, groups), stderr='')
        raise AssertionError(cmd)

    @contextlib.contextmanager
    def lock(holder, plog=None):
        yield True

    def sleep(s):
        live['t'] += s

    ns = {
        'os': types.SimpleNamespace(path=types.SimpleNamespace(
            expanduser=lambda p: str(ak) if p == '~/authentik' else p,
            join=os.path.join, exists=os.path.exists)),
        'subprocess': types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired),
        'time': types.SimpleNamespace(sleep=sleep, time=lambda: live['t']),
        'datetime': datetime.datetime,
        '_sudo_wrap': lambda c: c,
        '_authentik_compose_lock': lock,
        '_AUTHENTIK_PGBOUNCER_IMAGE': PIN,
        'load_settings': lambda: settings,
        'save_settings': lambda s: settings.update(s),
        '_get_authentik_env_value': lambda s, k: sa_pass if k == 'AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD' else None,
        '_ensure_ldapsearch': lambda: True,
        '_wait_for_authentik_stack_healthy': lambda plog, timeout=0: calls.append(['wait-healthy']) or True,
        're': re,
        'threading': threading,      # the ops #126 block after the settle helper makes a Lock
        '_resync_ldap_credential_to_coreconfig': lambda: (calls.append(['tak-resync']) or
                                                          ((True, 'credential') if cred_changed else (False, 'in_sync'))),
        '_tak_ldap_recycle_request': lambda reason, need_groups=True, restart=False: calls.append(
            ['tak-recycle-request', reason, need_groups, restart]),
    }
    for name in ('_ensure_authentik_pgbouncer_image', '_authentik_ldap_sa_group_probe',
                 '_authentik_ldap_sa_groups_settle', '_compose_set_service_image'):
        exec(compile(_src(name), f'app.py:{name}', 'exec'), ns)
    out = ns['_ensure_authentik_pgbouncer_image'](log.append)
    on_disk = yaml.safe_load((ak / 'docker-compose.yml').read_text())
    return out, on_disk, calls, settings, log, live


def _restarts(calls):
    """One entry per Authentik restart (server+worker, healthy wait, then ldap)."""
    return [c for c in calls if c[:3] == ['docker', 'compose', 'restart'] and 'server' in c]


RESTART_SEQ = [['docker', 'compose', 'restart', 'server', 'worker'], ['wait-healthy'],
               ['docker', 'compose', 'restart', 'ldap']]


def test_pin_is_1_26_1_after_ops_151():
    assert re.fullmatch(r'edoburu/pgbouncer:v\d+\.\d+\.\d+-p\d+', PIN), PIN
    assert PIN == 'edoburu/pgbouncer:v1.26.1-p0'


def test_box_on_1_25_1_is_moved_to_the_pin(tmp_path):
    out, compose, calls, settings, _, _ = _run(tmp_path, OTHER)
    assert out is True
    assert compose['services']['pgbouncer']['image'] == PIN
    assert [c for c in calls if c[:2] == ['docker', 'pull']] == [['docker', 'pull', PIN]]
    assert calls.index(['docker', 'pull', PIN]) < next(
        i for i, c in enumerate(calls) if c[:2] == ['docker', 'compose'])     # pulled before compose is touched
    up = [c for c in calls if c[:3] == ['docker', 'compose', 'up']]
    assert up == [['docker', 'compose', 'up', '-d', '--force-recreate', '--no-deps', 'pgbouncer']]
    assert settings['authentik_pgbouncer']['image'] == PIN
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'applied'
    assert compose['services']['server']['environment']['AUTHENTIK_POSTGRESQL__HOST'] == 'pgbouncer'
    assert _restarts(calls) == []                     # LDAP held — nothing else restarted
    assert calls.count(['tak-resync']) == 1           # LDAP → TAK credential resync, logged


def test_already_on_pin_is_a_noop(tmp_path):
    out, compose, calls, _, _, _ = _run(tmp_path, PIN)
    assert out is False
    assert calls == []


def test_non_edoburu_image_is_left_alone(tmp_path):
    # AJ's stopgap pin (docker.io/ prefix) is left alone too.
    for img in ('bitnami/pgbouncer:1.26.1', 'docker.io/edoburu/pgbouncer:v1.25.1-p0'):
        sub = tmp_path / img.replace('/', '_').replace(':', '_')
        sub.mkdir()
        out, compose, calls, _, _, _ = _run(sub, img)
        assert out is False
        assert calls == []
        assert compose['services']['pgbouncer']['image'] == img


def test_failed_pull_changes_nothing(tmp_path):
    out, compose, calls, settings, _, _ = _run(tmp_path, OTHER, pull_rc=1)
    assert out is None
    assert compose['services']['pgbouncer']['image'] == OTHER
    assert not [c for c in calls if c[:2] == ['docker', 'compose']]
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'pull-failed'


def test_unhealthy_container_rolls_back(tmp_path):
    out, compose, calls, settings, log, _ = _run(tmp_path, OTHER, inspect=f'{PIN} running unhealthy\n')
    assert out is None
    assert compose['services']['pgbouncer']['image'] == OTHER
    assert len([c for c in calls if c[:3] == ['docker', 'compose', 'up']]) == 2   # new, then back
    assert _restarts(calls) == []                     # LDAP held after the rollback → no restart
    assert any('LDAP after rollback' in l and 'held' in l for l in log)
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'rolled-back'
    assert 'image' not in settings['authentik_pgbouncer']


def test_failed_recreate_rolls_back(tmp_path):
    out, compose, _, settings, _, _ = _run(tmp_path, OTHER, up_rc=1)
    assert out is None
    assert compose['services']['pgbouncer']['image'] == OTHER
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'recreate-failed'


# ── ops #123: healthy container ≠ TAK can read groups ──────────────────────────────

def test_healthy_container_alone_is_not_enough_ldap_must_hold(tmp_path):
    out, _, calls, _, log, live = _run(tmp_path, OTHER)
    assert out is True
    probes = [c for c in calls if c[0] == 'ldapsearch']
    # baseline + enough probes to cover the hold (45 s at 5 s steps)
    assert len(probes) >= 1 + 45 // 5
    assert any('LDAP before the swap: SA bind ok' in l for l in log)
    assert any('LDAP after swap' in l and 'held 45s' in l for l in log)


def test_memberof_zero_window_is_seen_and_logged(tmp_path):
    # test12, 01:03Z: SA bind kept working, every user at memberOf=0 for ~10 s, then back.
    def blip(live):
        if live['image'] == PIN and 20 <= live['t'] < 30:
            return 0, 0
        return 0, 3
    out, compose, calls, settings, log, _ = _run(tmp_path, OTHER, ldap=blip)
    assert out is True
    assert compose['services']['pgbouncer']['image'] == PIN
    assert any('SA bind ok but NO tak_ groups' in l for l in log)
    assert any('failed probe(s) before it settled' in l for l in log)


def test_persistent_failure_restarts_server_worker_ldap_then_passes(tmp_path):
    def broken_until_restart(live):
        if live['image'] == PIN and live['restarts'] == 0:
            return 0, 0
        return 0, 3
    out, compose, calls, settings, log, _ = _run(tmp_path, OTHER, ldap=broken_until_restart)
    assert out is True
    assert compose['services']['pgbouncer']['image'] == PIN
    i = calls.index(RESTART_SEQ[0])
    assert calls[i:i + 3] == RESTART_SEQ             # ldap only after the server is healthy (ops #30)
    assert len(_restarts(calls)) == 1
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'applied'
    assert any('verified after restart' in l for l in log)


def test_still_failing_after_restart_rolls_back_and_restarts_again(tmp_path):
    def bind_dies_on_new_image(live):
        return (49, 0) if live['image'] == PIN else (0, 3)
    out, compose, calls, settings, log, live = _run(tmp_path, OTHER, ldap=bind_dies_on_new_image)
    assert out is None
    assert compose['services']['pgbouncer']['image'] == OTHER
    assert live['image'] == OTHER
    assert len(_restarts(calls)) == 1                 # never more than one LDAP outage per run
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'rolled-back-ldap'
    assert any('SA bind FAILED' in l for l in log)
    assert any('LDAP after rollback' in l and 'held' in l for l in log)


def test_box_already_failing_before_the_swap_keeps_the_pin(tmp_path):
    # A field box already broken on the old image must not be rolled back INTO it.
    out, compose, calls, settings, log, _ = _run(tmp_path, OTHER, ldap=lambda live: (49, 0))
    assert out is True
    assert compose['services']['pgbouncer']['image'] == PIN
    assert len(_restarts(calls)) == 1
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'applied-ldap-failing'
    assert any('LDAP before the swap: SA bind FAILING' in l for l in log)
    assert any('STILL failing' in l for l in log)


def test_box_with_no_tak_groups_only_needs_the_bind(tmp_path):
    out, _, calls, settings, _, _ = _run(tmp_path, OTHER, ldap=lambda live: (0, 0))
    assert out is True
    assert _restarts(calls) == []
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'applied'


def test_size_limit_still_counts_as_a_working_bind(tmp_path):
    out, _, calls, _, _, _ = _run(tmp_path, OTHER, ldap=lambda live: (4, 3))
    assert out is True
    assert _restarts(calls) == []


def test_no_sa_password_falls_back_to_container_health(tmp_path):
    out, _, calls, settings, log, _ = _run(tmp_path, OTHER, sa_pass=None)
    assert out is True
    assert not [c for c in calls if c[0] == 'ldapsearch']
    assert any('LDAP not checked' in l for l in log)


def test_sa_password_is_never_logged(tmp_path):
    _, _, calls, _, log, _ = _run(tmp_path, OTHER, ldap=lambda live: (49, 0))
    assert [c for c in calls if c[0] == 'ldapsearch']
    assert not [l for l in log if SA_PASS in l]


def test_probe_reads_memberof_the_way_tak_server_does():
    src = _src('_authentik_ldap_sa_group_probe')
    assert "'cn=adm_ldapservice,ou=users,dc=takldap'" in src
    assert "'ldap://127.0.0.1:389'" in src
    assert "'memberOf'" in src


def test_rollback_that_still_fails_does_not_restart_twice(tmp_path):
    out, _, calls, settings, log, _ = _run(tmp_path, OTHER, ldap=lambda live: (0, 0) if live['t'] > 0 else (0, 3))
    assert out is None
    assert len(_restarts(calls)) == 1
    assert any('already restarted once this run' in l for l in log)


# ── ops #123: only the image line changes; nothing is re-dumped ─────────────────────

LONG = 'x' * 150
RAW = f"""---
services:
  postgresql:
    image: docker.io/library/postgres:16-alpine
    command: ["postgres", "-c", "max_connections=200", "-c", "shared_buffers=256MB", "-c", "{LONG}"]
    restart: unless-stopped
  pgbouncer:
    # pinned by infra-TAK
    image: "{OTHER}"
    environment:
      DB_HOST: postgresql
      AUTH_TYPE: scram-sha-256
    restart: unless-stopped
  server:
    image: ghcr.io/goauthentik/server:2026.8.3
    depends_on:
      pgbouncer:
        condition: service_healthy
    environment:
      AUTHENTIK_POSTGRESQL__HOST: pgbouncer
"""


def test_only_the_image_line_changes(tmp_path):
    out, compose, _, _, _, _ = _run(tmp_path, OTHER, raw=RAW)
    assert out is True
    text = (tmp_path / 'authentik' / 'docker-compose.yml').read_text()
    assert text == RAW.replace(f'image: "{OTHER}"', f'image: "{PIN}"')    # byte-identical otherwise
    assert compose['services']['pgbouncer']['image'] == PIN


def test_set_service_image_ignores_other_pgbouncer_keys():
    ns = {'re': re}
    exec(compile(_src('_compose_set_service_image'), 'x', 'exec'), ns)
    f = ns['_compose_set_service_image']
    out = f(RAW, 'pgbouncer', PIN)
    assert out.count(PIN) == 1 and OTHER not in out
    assert 'ghcr.io/goauthentik/server:2026.8.3' in out
    assert f(RAW, 'missing', PIN) is None
    two = RAW.replace('    environment:\n      DB_HOST', '    image: other:1\n    environment:\n      DB_HOST', 1)
    assert f(two, 'pgbouncer', PIN) is None                                # ambiguous → no edit


def test_line_edit_failure_changes_nothing_and_never_redumps(tmp_path):
    raw = RAW.replace(f'    image: "{OTHER}"\n', f'    image:\n      "{OTHER}"\n')
    out, _, calls, settings, _, _ = _run(tmp_path, OTHER, raw=raw)
    assert out is None
    assert (tmp_path / 'authentik' / 'docker-compose.yml').read_text() == raw
    assert not [c for c in calls if c[:2] == ['docker', 'compose']]
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'write-failed'
    src = _src('_ensure_authentik_pgbouncer_image')
    assert '.safe_dump(' not in src


def test_harden_step_does_not_recreate_on_a_formatting_only_diff():
    # The post-update harden step re-dumps compose at the default width; v10.2.22's
    # width=200 file differed only in line wrapping and still recreated server/ldap.
    i = APP.index('print("Post-update: Authentik compose hardened — recreating worker/server, then ldap")')
    block = APP[i - 1500:i]
    assert '_ak_recreate = _ak != _ak_orig' in block
    assert 'safe_load(_ak) == _yaml_cmp.safe_load(_ak_orig)' in block
    assert block.rstrip().endswith('if _ak_recreate:')


# ── ops #126 (GH #189): TAK's clients are healed once LDAP is back ─────────────────

def _recycle_requests(calls):
    return [c for c in calls if c[0] == 'tak-recycle-request']


def test_good_swap_requests_a_tak_client_heal_even_with_the_credential_in_sync(tmp_path):
    out, _, calls, _, log, _ = _run(tmp_path, OTHER)
    assert out is True
    assert calls.count(['tak-resync']) == 1                         # resync said 'in_sync'
    reqs = _recycle_requests(calls)
    assert len(reqs) == 1 and PIN in reqs[0][1] and reqs[0][2] is True
    assert reqs[0][3] is False                                      # heal first, no forced restart
    assert calls.index(['tak-resync']) < calls.index(reqs[0])      # after the settle passed
    assert not any('restart needed to load it' in l for l in log)  # no more "someone should restart"
    assert any('TAK client check requested' in l for l in log)


def test_changed_credential_requests_a_real_tak_restart(tmp_path):
    # Java reads CoreConfig at start: a new credential only takes effect after a restart.
    out, _, calls, _, log, _ = _run(tmp_path, OTHER, cred_changed=True)
    assert out is True
    reqs = _recycle_requests(calls)
    assert len(reqs) == 1 and reqs[0][3] is True
    assert any('TAK Server restart requested' in l for l in log)


def test_swap_that_needed_the_authentik_restart_requests_it_too(tmp_path):
    def broken_until_restart(live):
        return (0, 0) if live['image'] == PIN and live['restarts'] == 0 else (0, 3)
    out, _, calls, _, _, _ = _run(tmp_path, OTHER, ldap=broken_until_restart)
    assert out is True
    reqs = _recycle_requests(calls)
    assert len(reqs) == 1
    assert calls.index(reqs[0]) > calls.index(RESTART_SEQ[-1])     # after the 'after restart' settle


def test_no_request_when_nothing_was_swapped(tmp_path):
    for i, kw in enumerate(({'image': PIN}, {'image': OTHER, 'pull_rc': 1}, {'image': OTHER, 'up_rc': 1})):
        sub = tmp_path / str(i)
        sub.mkdir()
        _, _, calls, _, _, _ = _run(sub, **kw)
        assert _recycle_requests(calls) == [], kw


def test_rollback_without_an_ldap_outage_requests_nothing(tmp_path):
    # Container unhealthy → rolled back; LDAP held throughout, so TAK never lost it.
    _, _, calls, _, _, _ = _run(tmp_path, OTHER, inspect=f'{PIN} running unhealthy\n')
    assert _restarts(calls) == []
    assert _recycle_requests(calls) == []


def test_rollback_after_an_ldap_outage_requests_a_heal(tmp_path):
    out, _, calls, settings, _, _ = _run(tmp_path, OTHER, ldap=lambda live: (49, 0) if live['image'] == PIN else (0, 3))
    assert out is None and settings['authentik_pgbouncer']['image_last_outcome'] == 'rolled-back-ldap'
    reqs = _recycle_requests(calls)
    assert len(reqs) == 1 and 'rolled back' in reqs[0][1]


def test_rollback_that_never_recovers_requests_nothing(tmp_path):
    # Healing (or restarting) TAK into a broken LDAP fixes nothing.
    _, _, calls, _, _, _ = _run(tmp_path, OTHER, ldap=lambda live: (0, 0) if live['t'] > 0 else (0, 3))
    assert _recycle_requests(calls) == []


def test_startup_migration_calls_it():
    boot = APP[APP.index('_ensure_authentik_worker_direct_pg(lambda m:'):]
    assert '_ensure_authentik_pgbouncer_image(lambda m:' in boot[:2000]
