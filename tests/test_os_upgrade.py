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
"""v10.3.0 W4 — the console-driven in-place Ubuntu 22.04 -> 24.04 upgrade.

Code-only proof (PLAN-v10.3.0 §4 W4): the preflight checks, the job script's step
order and landmine handlers (L1-L6), the broker's third fixed systemd-run shape
(exact shape accepted, every one-token variant refused), the status-file state
machine, the post-reboot verify, the route gating, and the /redteam-selfaudit
regression guard. Nothing here touches a box: refusal paths are proved by return
value ([[never-execute-destructive-negative-tests]]).
"""

import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER_PY = REPO / 'broker' / 'takwerx_broker.py'
SCAN_PY = REPO / '.claude' / 'skills' / 'redteam-selfaudit' / 'scan.py'
CODE = '\n'.join(l for l in APP.splitlines() if not l.lstrip().startswith('#'))


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


CONSTS = APP[APP.index('_OS_UPGRADE_UNIT = '):APP.index('\n\n\ndef _os_upgrade_unit_state')]
STEPS = ('pre-snapshot', 'pin-pg16', 'release-upgrade', 'repos-noble',
         'venv-rebuild', 'reassert', 'restart-console', 'reboot')


def _ns(**extra):
    """Namespace with the W4 constants + pure helpers; callers add stubs."""
    import shlex, hashlib, time, os as _os
    ns = {'re': re, 'json': json, 'shlex': shlex, 'hashlib': hashlib, 'shutil': shutil,
          'time': time, 'os': _os, 'subprocess': subprocess, 'types': types}
    ns.update(extra)
    exec(compile(CONSTS, 'app.py:W4-consts', 'exec'), ns)
    for name in ('_os_upgrade_tak_version_tuple', '_os_upgrade_script', '_os_upgrade_job_state'):
        exec(compile(_fn(name), f'app.py:{name}', 'exec'), ns)
    return ns


# ---------------------------------------------------------------------------
# constants / pure helpers
# ---------------------------------------------------------------------------
def test_step_list_is_the_plan():
    ns = _ns()
    assert tuple(ns['_OS_UPGRADE_STEPS']) == STEPS
    assert ns['_OS_UPGRADE_FROM'] == 'ubuntu-22.04' and ns['_OS_UPGRADE_TO'] == 'ubuntu-24.04'
    assert ns['_OS_UPGRADE_ACK'] == 'I have a snapshot'
    assert ns['_OS_UPGRADE_SCRIPT'] == '/var/lib/infratak-os-upgrade.sh'
    assert ns['_OS_UPGRADE_UNIT'] == 'infratak-os-upgrade.service'
    assert len(ns['_OS_UPGRADE_IRREVERSIBLE']) >= 3
    assert any('no rollback' in t for t in ns['_OS_UPGRADE_IRREVERSIBLE'])


@pytest.mark.parametrize('ver,want', [
    ('5.8-RELEASE84', (5, 8)), ('5.7-RELEASE43', (5, 7)), ('5.10-RELEASE1', (5, 10)),
    ('4.10.0.68', (4, 10)), ('', None), ('garbage', None), (None, None),
    ('hardened-5.8-RELEASE75', (5, 8)),          # Docker TAK, read off the bundle folder name
    ('hardened-5.7-RELEASE43', (5, 7))])
def test_tak_version_tuple(ver, want):
    assert _ns()['_os_upgrade_tak_version_tuple'](ver) == want


# ---------------------------------------------------------------------------
# the job script
# ---------------------------------------------------------------------------
@pytest.fixture(scope='module')
def script():
    return _ns()['_os_upgrade_script']('/opt/infratak', 'takwerx', 5001, pg_expect='18')


def test_script_parses_in_bash(script):
    r = subprocess.run(['bash', '-n'], input=script, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_script_steps_in_plan_order(script):
    steps = re.findall(r'^step (\S+)$', script, re.M)
    assert tuple(steps) == STEPS


def test_script_names_the_step_before_doing_anything(script):
    # step() writes running:<name> to the status file; fail() writes failed:<name>
    assert 'step() { echo "running:$1" > "$STATUS";' in script
    assert 'fail() {\n  echo "failed:$1" > "$STATUS"; echo "[$(TS)] FATAL: step $1 failed — $2"' in script
    # every fail call names the step it belongs to
    for m in re.finditer(r'\bfail (\S+) ', script):
        assert m.group(1) in STEPS, m.group(0)
    # `rebooting` is written BEFORE the reboot and nothing else after it
    i_reb = script.index('echo "rebooting" > "$STATUS"')
    assert i_reb < script.index('systemctl reboot')
    assert script.index('step reboot') < i_reb


def _between(script, a, b):
    return script[script.index(f'step {a}'):script.index(f'step {b}')]


def test_step1_snapshot_captures_what_later_steps_restore(script):
    s = _between(script, 'pre-snapshot', 'pin-pg16')
    assert '/etc/apt/sources.list.d/*.list "$PRE/sources.list.d/"' in s
    assert 'cp -a /etc/ssl/openssl.cnf "$PRE/openssl.cnf"' in s
    assert '/etc/update-manager/release-upgrades "$PRE/release-upgrades"' in s
    assert 'baseline.json' in s
    assert 'cp -a "$INSTALL_DIR/.venv" "$PRE/venv" || fail pre-snapshot' in s
    # Prompt=lts corrected by the JOB (operator-started), never by preflight
    assert 'Prompt=lts' in s
    assert 'Prompt=lts' not in _fn('_os_upgrade_preflight').replace('Prompt=lts first', '')
    # refuses to run on anything but 22.04 and never twice
    assert '[ "$VERSION_ID" = "22.04" ] || fail pre-snapshot' in script


def test_step2_landmines_L2_L4_L6(script):
    s = _between(script, 'pin-pg16', 'release-upgrade')
    assert 'Package: postgresql-16*' in s and 'Pin-Priority: -1' in s           # L2
    assert '/etc/update-manager/release-upgrades.d/infratak.cfg' in s           # L6
    assert '[Distro]\nRemoveObsoletes=no' in s
    assert '"--force-confdef"; "--force-confold"' in s                          # L4


def test_step3_release_upgrade_noninteractive_and_verified(script):
    s = _between(script, 'release-upgrade', 'repos-noble')
    assert 'do-release-upgrade -f DistUpgradeViewNonInteractive' in s
    assert 'wait_for_apt || fail release-upgrade' in s
    assert 'fail release-upgrade "do-release-upgrade exited $rc' in s
    # exit 0 is not believed on its own — os-release must say 24.04
    assert '[ "$VERSION_ID" = "24.04" ] || fail release-upgrade' in s
    # the upgrader must not re-exec into screen inside a unit (DistUpgradeMain.py)
    assert 'RELEASE_UPGRADER_NO_SCREEN=1' in script.split('step pre-snapshot')[0]


def test_step4_repos_rewritten_from_pre_flip_copy(script):
    s = _between(script, 'repos-noble', 'venv-rebuild')
    assert 'for f in "$PRE/sources.list.d/"*.list' in s                          # L3
    assert 'sed -e "s/jammy/noble/g" "$f" > "/etc/apt/sources.list.d/$b"' in s
    assert 'apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=300 update' in s
    assert 'fail repos-noble' in s


def test_step5_venv_rebuilt_as_console_user_before_console_restart(script):
    s = _between(script, 'venv-rebuild', 'reassert')
    assert 'runuser -u "$CONSOLE_USER" --' in s                                  # L1
    assert 'python3 -m venv .venv' in s and 'pip install -r requirements.txt' in s
    assert 'cp -a "$PRE/venv" "$INSTALL_DIR/.venv"' in s     # honest fallback, status still failed
    assert 'fail venv-rebuild' in s
    assert script.index('step venv-rebuild') < script.index('step restart-console')


def test_step6_reassert(script):
    s = _between(script, 'reassert', 'restart-console')
    assert 'string_mask = nombstr' in s                                          # L4
    assert 'pg_lsclusters --no-header' in s and '5432[[:space:]]+online' in s   # L2
    assert 'postgresql-16 was installed despite the pin' in s
    assert 'systemctl enable docker' in s
    # the temporary knobs are removed again
    assert 'rm -f /etc/apt/apt.conf.d/99infratak-os-upgrade /etc/update-manager/release-upgrades.d/infratak.cfg' in s


def test_step7_console_restart_waits_for_port(script):
    s = _between(script, 'restart-console', 'reboot')
    assert 'systemctl restart takwerx-console || fail restart-console' in s
    assert 'takwerx-broker' in s
    assert 'https://127.0.0.1:${CONSOLE_PORT}/login' in s


def test_script_quotes_its_inputs():
    sc = _ns()['_os_upgrade_script']('/opt/my dir', 'tak werx', 5001)
    assert "INSTALL_DIR='/opt/my dir'" in sc and "CONSOLE_USER='tak werx'" in sc
    assert subprocess.run(['bash', '-n'], input=sc, capture_output=True, text=True).returncode == 0
    sc2 = _ns()['_os_upgrade_script']('/opt/infratak', 'takwerx', 5001, pg_expect='')
    assert "PG_EXPECT=''" in sc2


def test_tak_packages_held_for_the_run(script):
    assert 'apt-mark hold "$p"' in script and 'trap release_holds EXIT' in script
    assert script.index('release_holds; HELD=""') < script.index('systemctl reboot')


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
class Box:
    def __init__(self, os_release=('ubuntu-22.04', 'Ubuntu 22.04.5 LTS'), tak_ver='5.8-RELEASE84',
                 tak_installed=True, container=False, db_host='127.0.0.1', clusters=(('18', 'main', '5432', 'online'),),
                 root_free_gb=40, boot_free_mb=400, busy=(), systemd_run=True, broker=(True, 'root console'),
                 upgrader_ver='1:22.04.20', prompt='lts', containers=('authentik-server', 'tak-portal'),
                 problems=(), docker_err='', pending=(), pending_err='', reboot_pkgs=()):
        calls = self.calls = []
        exists = {'/opt/tak/CoreConfig.xml': tak_installed, '/usr/bin/systemd-run': systemd_run,
                  '/bin/systemd-run': False, '/usr/bin/do-release-upgrade': bool(upgrader_ver),
                  '/usr/bin/docker': True}
        fake_os = types.SimpleNamespace(path=types.SimpleNamespace(
            exists=lambda p: exists.get(p, False), isdir=lambda p: p == '/boot'))

        def disk_usage(p):
            free = (boot_free_mb * 1024 ** 2) if p == '/boot' else (root_free_gb * 1024 ** 3)
            return types.SimpleNamespace(free=free, total=free * 2, used=free)

        def run(argv, **kw):
            calls.append(argv)
            if argv[:2] == ['dpkg-query', '-W']:
                return types.SimpleNamespace(returncode=0 if upgrader_ver else 1, stdout=upgrader_ver or '')
            if argv[:2] == ['systemctl', 'is-active']:
                return types.SimpleNamespace(returncode=0, stdout='active\n' if argv[2] in ('takserver', 'docker') else 'inactive\n')
            raise AssertionError(f'unexpected subprocess: {argv}')

        def fake_open(path, *a, **kw):
            import io
            if path == '/etc/update-manager/release-upgrades':
                return io.StringIO(f'[DEFAULT]\nPrompt={prompt}\n')
            raise FileNotFoundError(path)

        self.ns = _ns(
            os=fake_os, shutil=types.SimpleNamespace(disk_usage=disk_usage, which=lambda n: '/usr/bin/docker'),
            subprocess=types.SimpleNamespace(run=run), open=fake_open,
            datetime=__import__('datetime').datetime,
            _read_os_release=lambda: os_release,
            _get_takserver_version_info=lambda: {'version': tak_ver},
            _tak_is_container=lambda: container,
            _tak_db_host_from_coreconfig=lambda: db_host,
            _tak_db_is_remote=lambda h=None: (h or db_host) not in ('127.0.0.1', 'localhost', ''),
            _os_upgrade_pg_clusters=lambda: list(clusters),
            _os_upgrade_running_jobs=lambda: list(busy),
            _os_upgrade_broker_current=lambda: broker,
            _os_upgrade_containers=lambda: (None if docker_err else list(containers), list(problems), docker_err),
            _os_upgrade_pending_updates=lambda: ((None, pending_err) if pending_err else (list(pending), '')),
            _os_upgrade_reboot_blockers=lambda: list(reboot_pkgs),
            _os_upgrade_service_baseline=lambda: {'takserver': 'active', 'docker': 'active'},
        )
        exec(compile(_fn('_os_upgrade_preflight'), 'app.py:_os_upgrade_preflight', 'exec'), self.ns)

    def run(self, **kw):
        return self.ns['_os_upgrade_preflight'](**kw)


def _check(pf, name):
    return next(c for c in pf['checks'] if c['name'] == name)


def test_preflight_all_green_on_a_ready_box():
    pf = Box().run()
    assert pf['ok'] is True
    assert [c['name'] for c in pf['checks']] == ['os_type', 'takserver_58', 'tak_db_local', 'disk',
                                                 'no_job_running', 'systemd_run', 'release_upgrader',
                                                 'os_up_to_date', 'no_reboot_pending', 'containers']
    assert all(c['pass'] for c in pf['checks'])
    assert pf['baseline']['containers'] == ['authentik-server', 'tak-portal']
    assert pf['baseline']['services'] == {'takserver': 'active', 'docker': 'active'}
    assert pf['baseline']['pg_expect'] == '18' and pf['baseline']['db_remote'] is False
    assert pf['from'] == 'ubuntu-22.04' and pf['to'] == 'ubuntu-24.04'
    assert len(pf['irreversible']) >= 3


def test_preflight_refuses_anything_but_2204():
    for rel in (('ubuntu-24.04', 'Ubuntu 24.04.1 LTS'), ('rocky-9', 'Rocky Linux 9.4'), ('debian-12', 'Debian 12'), ('', '')):
        pf = Box(os_release=rel).run()
        assert pf['ok'] is False and _check(pf, 'os_type')['pass'] is False


def test_preflight_tak_gate_L5():
    pf = Box(tak_ver='5.7-RELEASE43').run()
    c = _check(pf, 'takserver_58')
    assert c['pass'] is False and '5.8 migration' in c['detail'] and pf['ok'] is False
    assert _check(Box(tak_ver='4.10.0.68').run(), 'takserver_58')['pass'] is False
    # unreadable version is refused, not guessed
    assert _check(Box(tak_ver='').run(), 'takserver_58')['pass'] is False
    # not installed passes the gate
    pf = Box(tak_installed=False).run()
    assert _check(pf, 'takserver_58')['pass'] is True and pf['baseline']['pg_expect'] == ''
    # 5.8 but the cluster is still 15 -> the migration did not finish
    c = _check(Box(clusters=(('15', 'main', '5432', 'online'),)).run(), 'takserver_58')
    assert c['pass'] is False and 'not 18' in c['detail']
    assert _check(Box(clusters=()).run(), 'takserver_58')['pass'] is False
    # container TAK: no host cluster to check
    pf = Box(container=True, clusters=()).run()
    assert _check(pf, 'takserver_58')['pass'] is True and pf['baseline']['pg_expect'] == ''


def test_docker_tak_database_is_local_not_a_separate_box():
    # W4.d: a Docker TAK's CoreConfig names the takserver-db container — not "a separate box"
    pf = Box(container=True, clusters=(), db_host='takserver-db').run()
    c = _check(pf, 'tak_db_local')
    assert c['pass'] is True and c['notice'] is False and 'takserver-db container on this box' in c['detail']
    assert pf['baseline']['db_remote'] is False


def test_preflight_remote_db_is_a_notice_not_a_refusal():
    pf = Box(db_host='10.0.0.5', clusters=()).run()
    c = _check(pf, 'tak_db_local')
    assert c['pass'] is True and c['notice'] is True and '10.0.0.5' in c['detail']
    assert _check(pf, 'takserver_58')['pass'] is True      # no local cluster expected
    assert pf['baseline']['db_remote'] is True and pf['baseline']['pg_expect'] == ''
    assert pf['ok'] is True


def test_preflight_disk_floor():
    assert _check(Box(root_free_gb=9.5).run(), 'disk')['pass'] is False
    assert _check(Box(boot_free_mb=150).run(), 'disk')['pass'] is False
    assert _check(Box(root_free_gb=10, boot_free_mb=200).run(), 'disk')['pass'] is True


def test_preflight_refuses_while_another_job_runs():
    pf = Box(busy=['takportal_deploy_status', 'kernel-patch']).run()
    c = _check(pf, 'no_job_running')
    assert c['pass'] is False and 'takportal_deploy_status' in c['detail'] and 'kernel-patch' in c['detail']


def test_preflight_systemd_run_and_broker():
    assert _check(Box(systemd_run=False).run(), 'systemd_run')['pass'] is False
    c = _check(Box(broker=(False, 'the running broker (abc) is not on the repo source')).run(), 'systemd_run')
    assert c['pass'] is False and 'repo source' in c['detail']


def test_preflight_release_upgrader():
    assert _check(Box(upgrader_ver='').run(), 'release_upgrader')['pass'] is False
    c = _check(Box(prompt='never').run(), 'release_upgrader')
    assert c['pass'] is True and c['notice'] is True and 'Prompt=lts' in c['detail']
    c = _check(Box(prompt='lts').run(), 'release_upgrader')
    assert c['pass'] is True and c['notice'] is False


def test_preflight_containers_baseline():
    c = _check(Box(problems=['cloudtak-api']).run(), 'containers')
    assert c['pass'] is False and 'cloudtak-api' in c['detail']
    c = _check(Box(docker_err='Cannot connect to the Docker daemon').run(), 'containers')
    assert c['pass'] is False
    pf = Box(containers=()).run()
    assert _check(pf, 'containers')['pass'] is True and pf['baseline']['containers'] == []


def test_preflight_acknowledgment_only_at_start():
    pf = Box().run()
    assert 'acknowledge' not in [c['name'] for c in pf['checks']]
    pf = Box().run(for_start=True, data={})
    assert pf['ok'] is False and _check(pf, 'acknowledge')['pass'] is False
    pf = Box().run(for_start=True, data={'acknowledge': 'i have a snapshot'})
    assert _check(pf, 'acknowledge')['pass'] is False          # exact text, nothing looser
    pf = Box().run(for_start=True, data={'acknowledge': '  I have a snapshot '})
    assert pf['ok'] is True and _check(pf, 'acknowledge')['pass'] is True


def test_preflight_never_mutates_the_box():
    """Read-only by construction: no _write_priv / _makedirs_priv / sed / tee in the preflight."""
    body = _fn('_os_upgrade_preflight')
    for bad in ('_write_priv', '_makedirs_priv', "'tee'", "'sed'", 'reset-failed', "'systemd-run'"):
        assert bad not in body, bad
    assert "_sudo_wrap" not in body     # every shell-out is an unprivileged read probe


# ---------------------------------------------------------------------------
# status-file state machine
# ---------------------------------------------------------------------------
ACTIVE = ('loaded', 'active', 'running', '', 4242)
INACTIVE = ('loaded', 'inactive', 'dead', 'success', 0)
FAILED = ('loaded', 'failed', 'failed', 'exit-code', 0)
GONE = ('not-found', 'inactive', 'dead', 'success', 0)   # post-reboot: transient unit is gone


@pytest.mark.parametrize('raw,unit,state,step', [
    ('', GONE, 'idle', ''),
    ('running:start', ACTIVE, 'running', 'start'),
    ('running:release-upgrade', ACTIVE, 'running', 'release-upgrade'),
    ('running:restart-console', ACTIVE, 'running', 'restart-console'),
    ('running:reboot', ACTIVE, 'rebooting', ''),
    ('running:reboot', GONE, 'rebooting', ''),
    ('rebooting', GONE, 'rebooting', ''),
    ('verifying', GONE, 'verifying', ''),
    ('done', GONE, 'done', ''),
    ('failed:release-upgrade', FAILED, 'failed', 'release-upgrade'),
    ('failed:venv-rebuild', INACTIVE, 'failed', 'venv-rebuild'),
    ('failed:verify:containers=cloudtak-api', GONE, 'failed', 'verify'),
    # the unit died mid-step without writing anything: honest failure, not an endless spinner
    ('running:repos-noble', FAILED, 'failed', 'repos-noble'),
    ('running:repos-noble', INACTIVE, 'failed', 'repos-noble'),
    ('running:repos-noble', GONE, 'failed', 'repos-noble'),
    # systemctl itself unreadable: do not invent a failure
    ('running:repos-noble', ('', '', '', '', 0), 'running', 'repos-noble'),
])
def test_job_state_transitions(raw, unit, state, step):
    st = _ns()['_os_upgrade_job_state'](raw=raw, unit=unit)
    assert st['state'] == state and st['step'] == step, st
    assert st['running'] == (state in ('running', 'rebooting', 'verifying'))
    assert st['steps'] == list(STEPS)
    if raw.startswith('failed:verify:'):
        assert st['detail'] == 'containers=cloudtak-api'
    if state == 'running' and unit is ACTIVE:
        assert st['pid'] == 4242
    if unit is GONE:
        assert st['unit_state'].startswith('not-loaded/')


# ---------------------------------------------------------------------------
# post-reboot verify (step 8, console side)
# ---------------------------------------------------------------------------
class Boot:
    def __init__(self, status='rebooting', os_release=('ubuntu-24.04', 'Ubuntu 24.04.1 LTS'),
                 baseline=None, running=('authentik-server', 'tak-portal'), active=('takserver', 'docker'),
                 clusters=(('18', 'main', '5432', 'online'),), poststart=None):
        self.writes = []
        self.poststart = list(poststart or [('not-found', 'inactive', 'dead', '', 0)])
        baseline = baseline if baseline is not None else {
            'containers': ['authentik-server', 'tak-portal'], 'services': {'takserver': 'active', 'docker': 'active'},
            'pg_expect': '18'}
        self.audits = []

        def run(argv, **kw):
            assert argv[:2] == ['systemctl', 'is-active']
            return types.SimpleNamespace(returncode=0, stdout=('active\n' if argv[2] in active else 'inactive\n'))

        class _T:
            def __init__(s, target=None, daemon=None, name=None):
                s.target = target

            def start(s):
                s.target()

        self.ns = _ns(
            threading=types.SimpleNamespace(Thread=_T),
            time=types.SimpleNamespace(time=__import__('time').time, sleep=lambda n: None),
            subprocess=types.SimpleNamespace(run=run),
            _os_upgrade_read_status=lambda: status,
            _os_upgrade_write_status=self.writes.append,
            _read_os_release=lambda: os_release,
            _read_priv=lambda p: json.dumps(baseline),
            _os_upgrade_containers=lambda: (list(running), [], ''),
            _os_upgrade_pg_clusters=lambda: list(clusters),
            audit=lambda *a: self.audits.append(a),
            print=lambda *a, **k: None,
            _kernel_patch_unit_state=lambda unit: (self.poststart.pop(0) if len(self.poststart) > 1 else self.poststart[0]),
        )
        self.ns['_OS_UPGRADE_VERIFY_WAIT_S'] = 0
        self.ns['_OS_UPGRADE_POSTSTART_WAIT_S'] = 3600
        exec(compile(_fn('_startup_os_upgrade_verify'), 'app.py:_startup_os_upgrade_verify', 'exec'), self.ns)

    def go(self):
        return self.ns['_startup_os_upgrade_verify']()


def test_verify_noop_unless_rebooting():
    for st in ('', 'running:release-upgrade', 'done', 'failed:release-upgrade'):
        b = Boot(status=st)
        assert b.go() is False and b.writes == []


def test_verify_done_when_everything_is_back():
    for st in ('rebooting', 'running:reboot', 'verifying'):
        b = Boot(status=st)
        assert b.go() is True
        assert b.writes == ['verifying', 'done']
        assert b.audits[-1] == ('os-upgrade:verify', 'done')


def test_verify_names_what_is_missing():
    b = Boot(running=('authentik-server',))
    b.go()
    assert b.writes == ['verifying', 'failed:verify:containers=tak-portal']
    b = Boot(active=('docker',))
    b.go()
    assert b.writes[-1] == 'failed:verify:services=takserver'
    b = Boot(clusters=(('16', 'main', '5432', 'online'), ('18', 'main', '5433', 'online')))
    b.go()
    assert b.writes[-1].startswith('failed:verify:postgresql=')
    b = Boot(os_release=('ubuntu-22.04', 'Ubuntu 22.04.5 LTS'))
    b.go()
    assert b.writes[-1].startswith('failed:verify:os-release=ubuntu-22.04')


def test_verify_tolerates_an_empty_baseline():
    b = Boot(baseline={})
    b.go()
    assert b.writes == ['verifying', 'done']


# ---------------------------------------------------------------------------
# routes + wiring (source-level)
# ---------------------------------------------------------------------------
def test_four_routes_all_login_required_and_os_gated():
    for path, methods in (('preflight', ''), ('start', ", methods=['POST']"), ('status', ''), ('log', '')):
        decl = f"@app.route('/api/console/os-upgrade/{path}'{methods})\n@login_required\n"
        assert decl in APP, path
        body = APP[APP.index(decl):]
        body = body[:body.index('\n\n\n')]
        assert '_os_upgrade_routes_available()' in body and '404' in body, path


def test_start_route_is_password_gated_and_reruns_preflight():
    body = _fn('console_os_upgrade_start_api')
    assert '_require_admin_password(' in body
    assert "data.get('admin_password')" in body
    assert body.index('_require_admin_password(') < body.index('_os_upgrade_start_job(')
    start = _fn('_os_upgrade_start_job')
    # server-side re-run, never the client's copy; refused with 409 + the checks
    assert '_os_upgrade_preflight(for_start=True, data=data)' in start
    assert "return 409, {'ok': False, 'error': 'preflight failed: '" in start
    assert start.index('_os_upgrade_preflight(for_start=True') < start.index('systemd-run')
    assert "_write_priv(_OS_UPGRADE_SCRIPT, script, perm=0o755)" in start


def test_start_builds_exactly_the_broker_shape():
    start = _fn('_os_upgrade_start_job')
    i = start.index('cmd = [')
    cmd = start[i:start.index(']', i)]
    for tok in ("'systemd-run'", "'--unit=' + _OS_UPGRADE_UNIT.replace('.service', '')",
                "'--property=StandardOutput=append:' + _OS_UPGRADE_LOGFILE",
                "'--property=StandardError=append:' + _OS_UPGRADE_LOGFILE",
                "'--setenv=DEBIAN_FRONTEND=noninteractive'", "'--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin'",
                "'--setenv=RELEASE_UPGRADER_NO_SCREEN=1'", "'--no-block'", "'/bin/bash', _OS_UPGRADE_SCRIPT"):
        assert tok in cmd, tok
    assert cmd.count('--setenv=') == 3
    assert '_sudo_wrap(cmd)' in start


def test_startup_migrations_calls_the_verify():
    body = _fn('_startup_migrations')
    assert '_startup_os_upgrade_verify()' in body


def test_unit_state_helper_is_shared_not_copied():
    assert 'def _kernel_patch_unit_state(unit=_KERNEL_PATCH_UNIT):' in APP
    assert 'return _kernel_patch_unit_state(_OS_UPGRADE_UNIT)' in _fn('_os_upgrade_unit_state')


def test_console_card_only_offers_the_button_on_2204():
    html = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')
    assert "{% if settings.get('os_type') in ('ubuntu-22.04', 'ubuntu-24.04') %}" in html
    assert 'id="os-upgrade-card"' in html and 'id="osup-modal"' in html
    # W4.e parameterized the modal by target; the core's phrase is unchanged
    assert "var _OSUP_ACK={core:'I have a snapshot'," in html
    assert "ack.trim()!==_OSUP_ACK[_osupTarget]" in html
    assert "admin_password:pw,acknowledge:ack.trim()" in html
    # the button is rendered only when the server says the box can start (22.04, idle)
    assert "_osupShow(d.can_start?'osup-idle':null)" in html
    # the reboot gap is ridden through, not treated as an error
    assert 'rebooting into Ubuntu 24.04 — waiting for it to come back' in html


# ---------------------------------------------------------------------------
# broker: the third fixed systemd-run shape
# ---------------------------------------------------------------------------
@pytest.fixture(scope='module')
def broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_osup_test', BROKER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


OSUP = ['systemd-run', '--unit=infratak-os-upgrade',
        '--description=infra-TAK OS upgrade Ubuntu 22.04 -> 24.04 (detached)',
        '--property=StandardOutput=append:/var/log/infratak-os-upgrade.log',
        '--property=StandardError=append:/var/log/infratak-os-upgrade.log',
        '--setenv=DEBIAN_FRONTEND=noninteractive', '--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin',
        '--setenv=RELEASE_UPGRADER_NO_SCREEN=1', '--no-block',
        '/bin/bash', '/var/lib/infratak-os-upgrade.sh']
KPATCH = ['systemd-run', '--unit=infratak-kernel-patch', '--description=infra-TAK Kernel Patch Job (detached)',
          '--property=StandardOutput=append:/var/log/takguard/kernel-patch.log',
          '--property=StandardError=append:/var/log/takguard/kernel-patch.log',
          '--setenv=DEBIAN_FRONTEND=noninteractive', '--setenv=NEEDRESTART_MODE=a',
          '--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin', '--no-block',
          '/bin/bash', '/var/lib/infratak-kernel-patch.sh']


def test_broker_accepts_exactly_the_shape_the_console_sends(broker):
    broker._check_systemd_run(OSUP)                                   # the W4 shape
    broker._check_systemd_run(KPATCH)                                 # kernel-patch unchanged
    broker._check_systemd_run(['systemd-run', '--unit=infratak-nonroot-migrate', '--no-block',
                               '--property=StandardOutput=append:/var/log/takwerx-console-nonroot-migrate.log',
                               '/bin/bash', '/opt/infratak/scripts/migrate-console-nonroot.sh',
                               '--apply', '--auto-rollback'])
    # the shape app.py builds IS this shape (same tokens, same order)
    start = _fn('_os_upgrade_start_job')
    for tok in OSUP[2:9]:
        assert repr(tok) in start or tok.split('=', 1)[0] in start, tok


def _variants():
    yield 'fourth unit', [a.replace('infratak-os-upgrade', 'infratak-os-upgrade2') if a.startswith('--unit=') else a for a in OSUP]
    yield 'other script', [a.replace('/var/lib/infratak-os-upgrade.sh', '/var/lib/infratak-os-upgrade.sh.bak') if a.startswith('/var/lib') else a for a in OSUP]
    yield 'home script', OSUP[:-1] + ['/home/takwerx/x.sh']
    yield 'extra positional', OSUP + ['--really']
    yield 'extra arg after script', OSUP + ['/etc/shadow']
    yield 'BASH_ENV', OSUP[:8] + ['--setenv=BASH_ENV=/tmp/x'] + OSUP[8:]
    yield 'LD_PRELOAD', OSUP[:8] + ['--setenv=LD_PRELOAD=/tmp/x.so'] + OSUP[8:]
    yield 'PATH hijack', [a.replace('--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin', '--setenv=PATH=/tmp:/usr/bin') for a in OSUP]
    yield 'NO_SCREEN other value', [a.replace('NO_SCREEN=1', 'NO_SCREEN=0') for a in OSUP]
    yield 'key-only setenv', [a.replace('--setenv=RELEASE_UPGRADER_NO_SCREEN=1', '--setenv=RELEASE_UPGRADER_NO_SCREEN') for a in OSUP]
    yield 'unknown flag', OSUP[:1] + ['--pty'] + OSUP[1:]
    yield 'User property', OSUP[:5] + ['--property=User=root'] + OSUP[5:]
    yield 'ExecStartPre', OSUP[:5] + ['--property=ExecStartPre=/bin/sh -c id'] + OSUP[5:]
    yield 'other log', [a.replace('/var/log/infratak-os-upgrade.log', '/var/log/other.log') for a in OSUP]
    yield 'no unit', [a for a in OSUP if not a.startswith('--unit=')]
    yield 'sh not bash', [('/bin/sh' if a == '/bin/bash' else a) for a in OSUP]
    yield 'kpatch unit, osup script', [('--unit=infratak-kernel-patch' if a.startswith('--unit=') else a) for a in OSUP]
    yield 'osup unit, kpatch script', [('/var/lib/infratak-kernel-patch.sh' if a.endswith('.sh') else a) for a in OSUP]
    # the ONE extra setenv is for THIS unit only — the kernel-patch job does not get it
    yield 'kpatch with NO_SCREEN', KPATCH[:8] + ['--setenv=RELEASE_UPGRADER_NO_SCREEN=1'] + KPATCH[8:]


@pytest.mark.parametrize('label,argv', list(_variants()), ids=[v[0] for v in _variants()])
def test_broker_refuses_every_one_token_variant(broker, label, argv):
    with pytest.raises(broker.Denied):
        broker._check_systemd_run(argv)


def test_broker_allowlist_literals_are_pinned(broker):
    assert broker._OSUP_UNIT_NAME == 'infratak-os-upgrade'
    assert broker._OSUP_SCRIPT == '/var/lib/infratak-os-upgrade.sh'
    assert broker._OSUP_ALLOWED_SETENV == broker._SYSTEMD_RUN_ALLOWED_SETENV | {'RELEASE_UPGRADER_NO_SCREEN=1'}
    for v in broker._OSUP_ALLOWED_SETENV | broker._SYSTEMD_RUN_ALLOWED_SETENV:
        assert re.fullmatch(r'[A-Z_]+=.+', v), v
    assert broker._OSUP_ALLOWED_PROPERTIES == {
        'StandardOutput=append:/var/log/infratak-os-upgrade.log',
        'StandardError=append:/var/log/infratak-os-upgrade.log'}


def test_broker_paths_for_the_job_state(broker):
    assert broker._path_allowed('/var/lib/infratak-os-upgrade.sh')
    assert broker._path_allowed('/var/lib/infratak-os-upgrade/status')
    assert broker._path_allowed('/var/lib/infratak-os-upgrade/baseline.json')
    assert broker._path_allowed('/var/lib/infratak-os-upgrade')
    assert broker._path_allowed('/var/log/infratak-os-upgrade.log')
    for bad in ('/var/lib/infratak-os-upgrade.sh.bak', '/var/lib/infratak-os-upgradeX/status', '/var/lib/x.sh'):
        with pytest.raises(broker.Denied):
            broker._path_allowed(bad)


# ---------------------------------------------------------------------------
# /redteam-selfaudit regression guard
# ---------------------------------------------------------------------------
@pytest.fixture(scope='module')
def scan():
    if not SCAN_PY.exists():
        pytest.skip('redteam-selfaudit scanner not present (gitignored skills dir)')
    spec = importlib.util.spec_from_file_location('redteam_scan_osup_test', SCAN_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _guard(scan, src):
    out = []
    scan._regressions_broker_systemd_run(src, out)
    return [f.key for f in out]


def test_guard_is_green_on_the_shipped_broker(scan):
    assert _guard(scan, BROKER_PY.read_text()) == []


def test_guard_fails_on_a_fourth_unit(scan):
    src = BROKER_PY.read_text()
    src = src.replace("_OSUP_UNIT_NAME = 'infratak-os-upgrade'",
                      "_OSUP_UNIT_NAME = 'infratak-os-upgrade'\n_FOURTH_UNIT_NAME = 'infratak-anything'")
    src = src.replace("(_KPATCH_UNIT_NAME, _MIGRATE_UNIT_NAME, _OSUP_UNIT_NAME)",
                      "(_KPATCH_UNIT_NAME, _MIGRATE_UNIT_NAME, _OSUP_UNIT_NAME, _FOURTH_UNIT_NAME)")
    assert _guard(scan, src)
    # a unit smuggled into the membership tuple as a bare literal is caught too
    src2 = BROKER_PY.read_text().replace("(_KPATCH_UNIT_NAME, _MIGRATE_UNIT_NAME, _OSUP_UNIT_NAME)",
                                         "(_KPATCH_UNIT_NAME, _MIGRATE_UNIT_NAME, _OSUP_UNIT_NAME, 'infratak-x')")
    assert _guard(scan, src2)
    # and so is dropping one (the membership test must name exactly the three constants)
    src3 = BROKER_PY.read_text().replace("(_KPATCH_UNIT_NAME, _MIGRATE_UNIT_NAME, _OSUP_UNIT_NAME)",
                                         "(_KPATCH_UNIT_NAME, _MIGRATE_UNIT_NAME)")
    assert _guard(scan, src3)


def test_guard_fails_on_an_unpinned_setenv(scan):
    src = BROKER_PY.read_text().replace("'RELEASE_UPGRADER_NO_SCREEN=1',", "'RELEASE_UPGRADER_NO_SCREEN',")
    assert _guard(scan, src)
    src = BROKER_PY.read_text().replace("setenvs.append(a.split('=', 1)[1])", "setenvs.append(a.split('=', 2)[1])")
    assert _guard(scan, src)
    src = BROKER_PY.read_text().replace("setenvs.append(a.split('=', 1)[1])   # the FULL KEY=VALUE, checked per unit below",
                                        "pass")
    assert _guard(scan, src)


def test_guard_fails_when_positionals_are_unpinned(scan):
    src = BROKER_PY.read_text().replace("if positionals != ['/bin/bash', _OSUP_SCRIPT]:", "if positionals[:1] != ['/bin/bash']:")
    assert _guard(scan, src)


def test_scan_wires_the_guard_for_the_broker_file(scan):
    src = SCAN_PY.read_text()
    i = src.index("if rel.endswith('takwerx_broker.py'):")
    assert '_regressions_broker_systemd_run(src, out)' in src[i:i + 300]


# ---------------------------------------------------------------------------
# W5 run 1 (aws-jammy, 2026-10-13): Ubuntu's own gates, asked the way it asks them
# ---------------------------------------------------------------------------
JAMMY_PENDING = ['libarchive13', 'libfreetype6', 'libpng16-16', 'libsgutils2-2', 'libx11-data', 'libxml2',
                 'linux-tools-common', 'sg3-utils', 'sg3-utils-udev', 'snapd', 'sosreport', 'sudo']


def test_preflight_refuses_pending_updates_like_do_release_upgrade():
    pf = Box(pending=JAMMY_PENDING).run()
    c = _check(pf, 'os_up_to_date')
    assert pf['ok'] is False and c['pass'] is False
    assert '12 update(s) pending' in c['detail'] and 'libarchive13' in c['detail'] and 'Install updates' in c['detail']
    c = _check(Box(pending_err='E: could not open lock file').run(), 'os_up_to_date')
    assert c['pass'] is False and 'could not ask apt' in c['detail']        # unknown is a refusal, never a pass
    assert _check(Box(pending=()).run(), 'os_up_to_date')['pass'] is True


def test_preflight_refuses_a_pending_reboot():
    c = _check(Box(reboot_pkgs=['linux-image-6.8.0-1070-aws']).run(), 'no_reboot_pending')
    assert c['pass'] is False and 'linux-image-6.8.0-1070-aws' in c['detail'] and 'Reboot' in c['detail']
    assert _check(Box().run(), 'no_reboot_pending')['pass'] is True


def test_pending_updates_uses_upstreams_rule_through_system_python():
    consts = APP[APP.index('_OS_UPGRADE_PENDING_PY = ('):APP.index('\n\n\ndef _os_upgrade_pending_updates')]
    ns = {}
    exec(consts, ns)
    py = ns['_OS_UPGRADE_PENDING_PY']
    assert 'apt.Cache()' in py and 'p.is_upgradable' in py
    assert "'Phased-Update-Percentage' not in p.candidate.record" in py      # upstream's phasing exemption
    body = _fn('_os_upgrade_pending_updates')
    assert "['/usr/bin/python3', '-I', '-c', _OS_UPGRADE_PENDING_PY]" in body  # system apt bindings, isolated
    assert "env['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'" in body
    assert '_sudo_wrap' not in body                                          # read-only, unprivileged
    compile(py, 'pending.py', 'exec')


@pytest.mark.parametrize('content,want', [
    (b'', []),
    (b'libc6\n', ['libc6']),
    (b'linux-base\nopenssh-server\n', ['linux-base']),
    (b'linux-image-6.8.0-1070-aws\ndbus\nlinux-image-6.8.0-1070-aws\n', ['linux-image-6.8.0-1070-aws']),
    (b'dbus\nopenssh-server\n', []),
    (b'libc6-dev\nlinux-headers-6.8\n', []),            # exact name for libc6/linux-base, prefix only for linux-image-
])
def test_reboot_blockers_match_upstream(content, want):
    import io
    ns = {'open': lambda p, m='r': io.BytesIO(content) if p == '/var/run/reboot-required.pkgs' else open(p, m)}
    exec(compile(_fn('_os_upgrade_reboot_blockers'), 'app.py', 'exec'), ns)
    assert ns['_os_upgrade_reboot_blockers']() == want


def test_reboot_blockers_absent_file_is_no_reboot():
    def nope(p, m='r'):
        raise FileNotFoundError(p)
    ns = {'open': nope}
    exec(compile(_fn('_os_upgrade_reboot_blockers'), 'app.py', 'exec'), ns)
    assert ns['_os_upgrade_reboot_blockers']() == []


def test_versions_recorded_first_thing_in_pre_snapshot(script):
    s = _between(script, 'pre-snapshot', 'pin-pg16')
    rec = s.index('dpkg-query -W -f=\'${Package} ${Version}\\n\' | sort > "$PRE/dpkg-versions.txt"')
    assert s.index('rm -f "$PRE/dpkg-versions.txt"') < rec          # never compare against a previous run's list
    assert rec < s.index('cp -a /etc/apt/sources.list.d/')           # before anything else in the step


def _run_fail(tmp_path, *, changed, os_version='22.04'):
    """Execute the script's real fail() in a sandbox: every absolute path it touches is
    rewritten under tmp_path, dpkg-query is a stub on PATH."""
    sc = _ns()['_os_upgrade_script']('/opt/infratak', 'takwerx', 5001)
    i = sc.index('fail() {')
    fn = sc[i:sc.index('exit 1\n}', i) + 8]
    root = str(tmp_path)
    assert '/var/' not in fn.replace('$PRE', '')   # fail() touches /etc only; nothing else to sandbox
    fn = fn.replace('/etc/', root + '/etc/')
    (tmp_path / 'bin').mkdir()
    (tmp_path / 'pre').mkdir()
    (tmp_path / 'pre' / 'dpkg-versions.txt').write_text('base-files 12ubuntu4.7\nsudo 1.9.9-1ubuntu2.6\n')
    now = 'base-files 12ubuntu4.7\nsudo 1.9.9-1ubuntu2.7\n' if changed else 'sudo 1.9.9-1ubuntu2.6\nbase-files 12ubuntu4.7\n'
    stub = tmp_path / 'bin' / 'dpkg-query'
    stub.write_text('#!/bin/bash\nprintf "%s" "' + now + '"\n')
    stub.chmod(0o755)
    for f in ('etc/apt/preferences.d/infratak-no-pg16', 'etc/apt/apt.conf.d/99infratak-os-upgrade',
              'etc/update-manager/release-upgrades.d/infratak.cfg', 'etc/update-manager/release-upgrades'):
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text('Prompt=lts\n' if f.endswith('release-upgrades') else 'x\n')
    (tmp_path / 'pre' / 'release-upgrades').write_text('Prompt=never\n')
    (tmp_path / 'etc' / 'os-release').write_text(f'ID=ubuntu\nVERSION_ID="{os_version}"\n')
    prog = (f'STATUS={root}/status\nPRE={root}/pre\nTS() {{ echo T; }}\n' + fn + '\nfail release-upgrade "exited 1"\n')
    r = subprocess.run(['bash', '-c', prog], capture_output=True, text=True,
                       env={'PATH': f'{root}/bin:/usr/bin:/bin'})
    return r, (tmp_path / 'status').read_text().strip()


def test_fail_on_an_unchanged_box_undoes_the_jobs_settings(tmp_path):
    r, status = _run_fail(tmp_path, changed=False)
    assert r.returncode == 1 and status == 'failed:release-upgrade'
    assert 'UNCHANGED' in r.stdout and 'run the upgrade again' in r.stdout
    for f in ('etc/apt/preferences.d/infratak-no-pg16', 'etc/apt/apt.conf.d/99infratak-os-upgrade',
              'etc/update-manager/release-upgrades.d/infratak.cfg'):
        assert not (tmp_path / f).exists(), f
    assert (tmp_path / 'etc/update-manager/release-upgrades').read_text() == 'Prompt=never\n'   # restored


def test_fail_on_a_partly_upgraded_box_keeps_the_pins_and_says_restore(tmp_path):
    r, status = _run_fail(tmp_path, changed=True)
    assert r.returncode == 1 and status == 'failed:release-upgrade'
    assert 'PARTLY UPGRADED' in r.stdout and 'Restore your snapshot' in r.stdout and 'UNCHANGED' not in r.stdout
    assert (tmp_path / 'etc/apt/preferences.d/infratak-no-pg16').exists()        # pins protect a manual recovery
    assert (tmp_path / 'etc/apt/apt.conf.d/99infratak-os-upgrade').exists()


def test_fail_after_the_flip_adds_nothing(tmp_path):
    r, _ = _run_fail(tmp_path, changed=True, os_version='24.04')
    assert 'PARTLY UPGRADED' not in r.stdout and 'UNCHANGED' not in r.stdout   # the step's own message stands


def test_diagnostics_bundle_carries_the_upgrade_run():
    i = APP.index('# v10.3.0 W4: the console-driven 22.04 -> 24.04 upgrade. Its status file names the step')
    blk = APP[i:i + 2200]
    assert '_os_upgrade_read_status()' in blk and '_diag_log_lines(_OS_UPGRADE_LOGFILE' in blk
    assert "'/var/log/dist-upgrade/main.log'" in blk
    for marker in ('FATAL', 'UNCHANGED', 'PARTLY UPGRADED', 'Please '):
        assert marker in blk


def test_console_labels_the_new_checks():
    html = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')
    assert "os_up_to_date:'All Ubuntu updates installed'" in html
    assert "no_reboot_pending:'No reboot pending'" in html
    assert 'UNCHANGED means nothing was touched' in html



# ---------------------------------------------------------------------------
# W4.b — verify waits for Guard Dog's post-start; baseline = every long-running service
# ---------------------------------------------------------------------------
def test_verify_waits_for_guard_dog_post_start_before_judging():
    seq = [('loaded', 'activating', 'start', '', 0)] * 3 + [('loaded', 'active', 'exited', 'success', 0)]
    b = Boot(poststart=seq)
    b.go()
    assert b.writes == ['verifying', 'done'] and b.poststart == [('loaded', 'active', 'exited', 'success', 0)]


def test_verify_does_not_wait_when_post_start_failed_or_is_absent():
    for st in (('loaded', 'failed', 'failed', 'timeout', 0), ('not-found', 'inactive', 'dead', '', 0)):
        b = Boot(poststart=[st])
        b.go()
        assert b.writes == ['verifying', 'done']


def test_verify_post_start_wait_is_capped():
    assert 'ps_deadline = time.time() + _OS_UPGRADE_POSTSTART_WAIT_S' in _fn('_startup_os_upgrade_verify')
    assert '_OS_UPGRADE_POSTSTART_WAIT_S = 1800' in APP


def _baseline(show_out, files, links=()):
    ns = {'os': __import__('os'), 'subprocess': subprocess}
    exec(compile(APP[APP.index('_OS_UPGRADE_CORE_SERVICES = ('):APP.index('def _os_upgrade_service_baseline(')]
                 + _fn('_os_upgrade_service_baseline'), 'app.py', 'exec'), ns)
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        return types.SimpleNamespace(stdout=show_out, returncode=0)
    return ns['_os_upgrade_service_baseline'](listdir=lambda d: files, run=run,
                                              islink=lambda p: p.rsplit('/', 1)[-1] in links), calls


def test_baseline_covers_every_long_running_infratak_service():
    show = "\n\n".join([
        "Id=takserver.service\nType=forking\nActiveState=active\nSubState=running",
        "Id=mediamtx-webeditor.service\nType=simple\nActiveState=active\nSubState=running",
        "Id=tak-health.service\nType=simple\nActiveState=active\nSubState=running",
        "Id=tak-post-start.service\nType=oneshot\nActiveState=active\nSubState=exited",     # oneshot: excluded
        "Id=docker-stagger.service\nType=oneshot\nActiveState=active\nSubState=exited",
        "Id=caddy.service\nType=notify\nActiveState=failed\nSubState=failed",              # not up now: excluded
        "Id=fail2ban.service\nType=simple\nActiveState=inactive\nSubState=dead",
    ])
    files = ['mediamtx-webeditor.service', 'tak-health.service', 'tak-post-start.service', 'docker-stagger.service',
             'infratak-os-upgrade.service', 'getty@tty1.service', 'something.timer']
    out, calls = _baseline(show, files)
    assert out == {'takserver': 'active', 'mediamtx-webeditor': 'active', 'tak-health': 'active'}
    asked = set(calls[0][calls[0].index('--') + 1:])
    assert 'infratak-os-upgrade.service' not in asked          # the job itself is never baseline
    assert 'getty@tty1.service' not in asked and 'something.timer.service' not in asked
    assert {'takserver.service', 'docker.service', 'mediamtx-webeditor.service'} <= asked


# ---------------------------------------------------------------------------
# W4.b — the MediaMTX web editor's Python packages after the flip
# ---------------------------------------------------------------------------
class EditorBox:
    def __init__(self, installed=True, ok_seq=(False, True), install_ok=True):
        self.ok_seq = list(ok_seq)
        self.restarts, self.installs, self.logs = [], [], []
        paths = {'/etc/systemd/system/mediamtx-webeditor.service', '/opt/mediamtx-webeditor/mediamtx_config_editor.py'}

        class _T:
            def __init__(s, target=None, daemon=None, name=None):
                s.target = target

            def start(s):
                s.target()
        ns = {
            'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: installed and p in paths)),
            'subprocess': types.SimpleNamespace(run=lambda argv, **kw: (self.restarts.append(argv) if 'restart' in argv else None)
                                                or types.SimpleNamespace(stdout='3.12\n', returncode=0)),
            'threading': types.SimpleNamespace(Thread=_T),
            '_sudo_wrap': lambda c: c,
            '_mediamtx_editor_python_ok': lambda: self.ok_seq.pop(0) if self.ok_seq else True,
            '_mediamtx_editor_install_py_deps': lambda: (self.installs.append(1) or (install_ok, 'ok' if install_ok else 'E: no network')),
            'print': lambda *a, **k: self.logs.append(' '.join(map(str, a))),
            '_MEDIAMTX_EDITOR_PY_PKGS': ('Flask', 'ruamel.yaml', 'requests', 'psutil'),
            '_MEDIAMTX_EDITOR_UNIT': '/etc/systemd/system/mediamtx-webeditor.service',
            '_MEDIAMTX_EDITOR_SRC': '/opt/mediamtx-webeditor/mediamtx_config_editor.py',
        }
        exec(compile(_fn('_startup_heal_mediamtx_editor_python'), 'app.py', 'exec'), ns)
        self.fn = ns['_startup_heal_mediamtx_editor_python']


def test_editor_heal_reinstalls_and_restarts_when_imports_fail():
    e = EditorBox(ok_seq=(False, True))
    assert e.fn() is True
    assert e.installs == [1] and e.restarts == [['systemctl', 'restart', 'mediamtx-webeditor']]
    assert any('Python 3.12' in l for l in e.logs) and any('✓' in l for l in e.logs)


def test_editor_heal_is_a_no_op_when_fine_or_absent():
    e = EditorBox(ok_seq=(True,))
    assert e.fn() is False and e.installs == [] and e.restarts == []
    e = EditorBox(installed=False)
    assert e.fn() is False and e.installs == [] and e.restarts == []


def test_editor_heal_never_restarts_on_a_failed_install():
    e = EditorBox(ok_seq=(False, False), install_ok=False)
    e.fn()
    assert e.restarts == [] and any('could not be reinstalled' in l for l in e.logs)


def test_one_package_list_everywhere():
    """deploy, Patch and the remote deploy all install the same list through the constant."""
    assert "pip3 install Flask" not in APP
    assert APP.count('_mediamtx_editor_install_py_deps()') >= 3        # deploy, patch, heal
    assert "f'pip3 install {_pkgs} --break-system-packages 2>&1'" in APP  # remote deploy
    assert '_startup_heal_mediamtx_editor_python()' in _fn('_startup_migrations')


def test_editor_installer_uses_an_argv_not_a_shell_string():
    body = _fn('_mediamtx_editor_install_py_deps')
    assert 'shell=True' not in body
    assert "['pip3', 'install'] + list(_MEDIAMTX_EDITOR_PY_PKGS)" in body and "['--break-system-packages']" in body


def test_baseline_skips_os_alias_links_and_snap_units():
    """aws-jammy2: /etc/systemd/system holds alias LINKS for OS services (sshd -> ssh, syslog ->
    rsyslog …) and snap units. They are not infra-TAK's, and 24.04 starts ssh on demand — counting
    them would fail a healthy upgrade."""
    files = ['sshd.service', 'syslog.service', 'chronyd.service', 'snap.amazon-ssm-agent.amazon-ssm-agent.service',
             'mediamtx.service', 'tak-health.service']
    _out, calls = _baseline('', files, links=('sshd.service', 'syslog.service', 'chronyd.service'))
    asked = set(calls[0][calls[0].index('--') + 1:])
    assert 'mediamtx.service' in asked and 'tak-health.service' in asked
    for os_unit in ('sshd.service', 'syslog.service', 'chronyd.service', 'snap.amazon-ssm-agent.amazon-ssm-agent.service'):
        assert os_unit not in asked, os_unit


def test_card_states_the_58_requirement_before_the_click():
    """Operator, 2026-10-14: a 5.7 box must be told up front, not only inside the check window."""
    html = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')
    i = html.index('id="osup-idle"')
    card = html[i:html.index('id="osup-progress"', i)]
    assert 'Requires TAK Server 5.8 or newer' in card and 'TAK Server page first' in card
