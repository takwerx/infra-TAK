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
"""Guard Dog repairs CloudTAK by itself after a TAK Portal marketplace install (ops #197).

TAK Portal rebuilds CloudTAK with `docker compose -f docker-compose.yml -f
docker-compose.marketplace.yml up -d --force-recreate api`. Explicit -f flags ignore
COMPOSE_FILE, so infra-TAK's override is skipped and the containers come back stock (media
v9.10.0, upstream postgis, no console CA, no HLS profile). Guard Dog used to email and leave
it; now its second check asks the console, which repairs through the console-restart path.

Console half: the shipped functions are cut out of app.py (it cannot be imported in a test)
and run against a temp ~/CloudTAK with docker faked. Guard Dog half: the real
tak-cloudtak-watch.sh runs with docker and curl stubbed.
"""

import ast
import json
import os
import pathlib
import re
import shlex
import socket
import subprocess
import threading
import time
import types
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-cloudtak-watch.sh').read_text()

STOCK_MEDIA = 'ghcr.io/dfpc-coe/media-infra:v9.10.0'
PINNED_MEDIA = 'ghcr.io/dfpc-coe/media-infra:v9.12.1'
TAKPORTAL_BUILD = ('docker compose --progress=plain -f docker-compose.yml '
                   '-f docker-compose.marketplace.yml build --no-cache api')
OPERATOR = 'services:\n  print:\n    image: example/print\n'
TAKPORTAL_CSP = 'services:\n  api:\n    environment:\n      CSP: "x"\n'


def _fn(name):
    return ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def _assign(name):
    return ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)))


def _iso(ts):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts)) + '.123456789Z'


class Box:
    """A CloudTAK stack on disk plus a fake docker that tracks what compose did to it."""

    def __init__(self, home):
        self.home = home
        self.ct = home / 'CloudTAK'
        self.ct.mkdir()
        (home / '.config').mkdir()
        (self.ct / '.env').write_text('CLOUDTAK_Mode=docker-compose\nPOSTGRES_PASSWORD=pw\n')
        (self.ct / 'docker-compose.yml').write_text('services:\n  api:\n    image: cloudtak-api\n')
        (self.ct / 'docker-compose.override.yml').write_text('# TAKWERX override\n')
        (self.ct / 'docker-compose.marketplace.yml').write_text(TAKPORTAL_CSP)
        (self.ct / 'docker-compose.custom.yml').write_text(OPERATOR)
        self.calls, self.logs, self.mails, self.threads = [], [], [], []
        self.procs = ['/usr/bin/python3 broker', 'sleep 30']
        self.api_started = time.time() - 600
        self.up_rc = 0
        self.heal_ok = True
        self.busy = None
        self.settings = {'guarddog_alert_email': 'ops@example.com'}
        self.takportal_recreate()

    def takportal_recreate(self):
        """What TAK Portal's `-f ... up --force-recreate api` leaves behind."""
        base = f'{self.ct}/docker-compose.yml,{self.ct}/docker-compose.marketplace.yml'
        self.labels = {'cloudtak-api-1': base, 'cloudtak-media-1': base,
                       'cloudtak-postgis-1': base,
                       'cloudtak-events-1': base.replace('marketplace', 'override')}
        self.media_image, self.api_ca, self.hls = STOCK_MEDIA, False, False

    def run(self, argv, **kw):
        argv = list(argv)
        self.calls.append((argv, kw.get('cwd')))
        out, rc = '', 0
        if argv[:2] == ['ps', '-eo']:
            out = '\n'.join(self.procs) + '\n'
        elif argv[:3] == ['docker', 'inspect', 'cloudtak-api-1']:
            fmt = argv[-1]
            if 'com.docker.compose.project' in fmt:
                out = 'cloudtak\n'
            elif '.Config.Env' in fmt:
                env = ['PATH=/usr/bin'] + (['NODE_EXTRA_CA_CERTS=/etc/ssl/certs/takwerx-console.crt'] if self.api_ca else [])
                out = json.dumps(env)
            elif '.State.Status' in fmt:
                out = f'running {_iso(self.api_started)}\n'
        elif argv[:3] == ['docker', 'inspect', 'cloudtak-media-1']:
            out = self.media_image + '\n'
        elif argv[:2] == ['docker', 'ps'] and 'label=com.docker.compose.project=cloudtak' in argv:
            out = ''.join(f'{n}|{f}\n' for n, f in self.labels.items())
        elif argv[:2] == ['docker', 'ps'] and 'name=cloudtak-media' in argv:
            out = 'cloudtak-media-1\n'
        elif argv[:2] == ['docker', 'exec']:
            out = ('ok' if self.hls else 'drift') + ' ok na\n'
        elif argv[:5] == ['docker', 'compose', 'up', '-d', '--force-recreate']:
            rc = self.up_rc
            if rc == 0:
                # The real recreate: compose loads COMPOSE_FILE from .env.
                env = dict(l.split('=', 1) for l in (self.ct / '.env').read_text().splitlines() if '=' in l)
                files = ','.join(os.path.normpath(os.path.join(str(self.ct), f))
                                 for f in env['COMPOSE_FILE'].split(':'))
                self.labels = {n: files for n in self.labels}
                self.media_image, self.api_ca, self.hls = PINNED_MEDIA, True, False
                self.api_started = time.time()
        return types.SimpleNamespace(stdout=out, stderr='', returncode=rc)

    def heal(self, plog=None, remote_cfg=None, wait=False):
        self.calls.append((['HEAL'], None))
        if self.heal_ok:
            self.hls = True
        return self.heal_ok

    def ns(self):
        fake_threading = types.SimpleNamespace(
            Lock=threading.Lock,
            Thread=lambda target, args=(), **k: types.SimpleNamespace(
                start=lambda: self.threads.append((target, args))))
        ns = {
            'os': os, 'json': json, 're': re, 'time': time, 'shlex': shlex, 'socket': socket,
            'datetime': datetime, 'threading': fake_threading,
            'subprocess': types.SimpleNamespace(run=self.run, PIPE=-1, STDOUT=-2),
            'print': lambda *a, **k: self.logs.append(' '.join(str(x) for x in a)),
            'CONFIG_DIR': str(self.home / '.config'),
            'load_settings': lambda: dict(self.settings),
            '_sudo_wrap': lambda a: list(a),
            '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'local'},
            '_console_busy_reason': lambda: self.busy,
            '_cloudtak_build_override_yml': lambda s: '# TAKWERX override\n',
            '_patch_cloudtak_minio_registry': lambda d: False,
            '_patch_cloudtak_compose_ports': lambda d: self.calls.append((['PORTS'], d)) or False,
            '_docker_compose_pull': lambda *a, **k: self.calls.append((['PULL'], k.get('services'))) or True,
            '_cloudtak_media_hls_heal': self.heal,
            '_guarddog_server_identifier': lambda s: 'test-box (10.0.0.1)',
            '_guarddog_send_alert_email_via_relay': lambda to, subj, body: self.mails.append((to, subj, body)) or True,
        }
        src = '\n\n'.join(
            [_assign(n) for n in (
                '_CT_ENV_LINE_RE', 'CLOUDTAK_CUSTOM_COMPOSE', '_CLOUDTAK_CUSTOM_COMPOSE_SEED',
                '_CLOUDTAK_TAKPORTAL_CSP_COMPOSE', '_CT_MEDIA_CHECK_SH',
                '_CLOUDTAK_RECREATE_PENDING', 'CLOUDTAK_AUTOREPAIR_MAX_PER_HOUR',
                'CLOUDTAK_AUTOREPAIR_SETTLE_S', 'CLOUDTAK_AUTOREPAIR_FAIL_HOLD_S',
                '_CLOUDTAK_AUTOREPAIR_RECORD', '_CLOUDTAK_COMPOSE_BUSY_RE',
                'cloudtak_autorepair_status', '_cloudtak_autorepair_lock')]
            + [_fn(n) for n in (
                '_cloudtak_env_read', '_cloudtak_env_set', '_cloudtak_compose_file_value',
                '_cloudtak_ensure_custom_compose', '_ct_media_converged',
                '_ct_recreate_pending', '_ct_recreate_arm', '_ct_recreate_clear',
                '_ct_docker_out', '_cloudtak_containers_without_override',
                '_cloudtak_write_override_file', '_cloudtak_recreate_and_heal',
                '_cloudtak_drift', '_cloudtak_drift_summary', '_cloudtak_autorepair_wait_reason',
                '_cloudtak_autorepair_record', '_cloudtak_autorepair_record_save',
                '_cloudtak_autorepair_request', '_cloudtak_autorepair_run',
                '_cloudtak_autorepair_notify')])
        exec(compile(src, 'app.py', 'exec'), ns)
        return ns

    def request(self):
        old = os.environ.get('HOME')
        os.environ['HOME'] = str(self.home)
        try:
            if not hasattr(self, '_ns'):
                self._ns = self.ns()
            return self._ns['_cloudtak_autorepair_request']()
        finally:
            os.environ['HOME'] = old

    def finish(self):
        """Run the repair thread the request started."""
        while self.threads:
            target, args = self.threads.pop(0)
            target(*args)

    def ups(self):
        return [c for c, cwd in self.calls if c[:3] == ['docker', 'compose', 'up']]

    def record(self):
        p = self.home / '.config' / 'cloudtak-autorepair.json'
        return json.loads(p.read_text()) if p.exists() else {}

    def pending(self):
        return (self.home / '.config' / 'cloudtak-recreate-pending.json').exists()


@pytest.fixture
def box(tmp_path):
    return Box(tmp_path)


# ── console: drift found and repaired ────────────────────────────────────────

def test_drift_after_a_takportal_install_is_found(box):
    d = box.ns()
    old = os.environ['HOME']
    os.environ['HOME'] = str(box.home)
    try:
        drift = d['_cloudtak_drift'](str(box.ct))
    finally:
        os.environ['HOME'] = old
    assert drift['kind'] == 'recreate'
    assert drift['no_override'] == ['cloudtak-api-1', 'cloudtak-media-1', 'cloudtak-postgis-1']
    assert drift['hls'] is False and drift['api_ca'] is False and drift['media_image'] == STOCK_MEDIA


def test_drift_is_repaired_through_the_console_restart_path(box):
    r = box.request()
    assert r['state'] == 'repairing'
    assert box.request()['state'] == 'repairing'         # the next check: still on it
    assert box.ups() == []                               # nothing ran in the request itself
    box.finish()
    ups = box.ups()
    assert ups == [['docker', 'compose', 'up', '-d', '--force-recreate']]   # bare: COMPOSE_FILE decides
    up_cwd = next(cwd for c, cwd in box.calls if c[:3] == ['docker', 'compose', 'up'])
    assert up_cwd == str(box.ct)
    order = [c[0] for c, _ in box.calls if c[0] in ('PORTS', 'PULL', 'docker', 'HEAL')
             and (c[0] != 'docker' or c[:3] == ['docker', 'compose', 'up'])]
    assert order == ['PORTS', 'PULL', 'docker', 'HEAL']  # ports re-asserted before the recreate
    assert box.media_image == PINNED_MEDIA and box.api_ca is True and box.hls is True
    assert box.record()['last']['result'] == 'repaired'
    assert not box.pending()                             # journaled recreate finished
    assert box.request()['state'] == 'ok'


def test_repair_sends_one_short_repaired_note_not_the_alarm(box):
    box.request()
    box.finish()
    assert len(box.mails) == 1
    to, subj, body = box.mails[0]
    assert to == 'ops@example.com'
    assert subj == 'Guard Dog: CloudTAK repaired automatically on test-box (10.0.0.1)'
    assert 'Nothing to do' in body and STOCK_MEDIA in body and PINNED_MEDIA in body
    assert 'console CA missing in the api' in body and 'console CA trusted by the api' in body
    assert 'drift' not in subj.lower()


def test_takportal_file_and_operator_file_are_both_kept(box):
    box.request()
    box.finish()
    env = dict(l.split('=', 1) for l in (box.ct / '.env').read_text().splitlines() if '=' in l)
    files = env['COMPOSE_FILE'].split(':')
    assert files[0] == f'{box.ct}/docker-compose.yml'
    assert files[1] == f'{box.ct}/docker-compose.override.yml'
    assert 'docker-compose.marketplace.yml' in files
    assert files[-1] == f'{box.ct}/docker-compose.custom.yml'          # operator's file wins
    assert (box.ct / 'docker-compose.marketplace.yml').read_text() == TAKPORTAL_CSP
    assert (box.ct / 'docker-compose.custom.yml').read_text() == OPERATOR
    assert all('docker-compose.marketplace.yml' in f and 'docker-compose.custom.yml' in f
               for f in box.labels.values())


def test_hls_only_drift_gets_the_media_heal_not_a_recreate(box):
    box.labels = {n: f'{box.ct}/docker-compose.yml,{box.ct}/docker-compose.override.yml'
                  for n in box.labels}
    box.media_image, box.api_ca = PINNED_MEDIA, True
    assert box.request()['state'] == 'repairing'
    box.finish()
    assert box.ups() == [] and box.hls is True
    assert box.record()['last']['result'] == 'repaired'
    assert 're-applied the HLS profile to cloudtak-media' in box.mails[0][2]


def test_clean_box_is_ok_and_does_nothing(box):
    box.labels = {n: f'{box.ct}/docker-compose.yml,{box.ct}/docker-compose.override.yml'
                  for n in box.labels}
    box.hls = True
    assert box.request()['state'] == 'ok'
    assert box.threads == [] and box.ups() == [] and box.record() == {}


# ── console: a TAK Portal install still running → wait ───────────────────────

def test_waits_while_takportal_is_still_building(box):
    box.procs.append(TAKPORTAL_BUILD)
    r = box.request()
    assert r['state'] == 'waiting' and 'compose/build run is still going' in r['detail']
    assert box.threads == [] and box.record() == {}          # not counted against the limit


def test_waits_for_the_api_to_settle_after_takportal_recreates_it(box):
    box.api_started = time.time() - 20
    r = box.request()
    assert r['state'] == 'waiting' and 'started' in r['detail']
    box.api_started = time.time() - 600
    assert box.request()['state'] == 'repairing'


def test_waits_while_the_console_itself_is_busy(box):
    box.busy = 'cloudtak_update_status running'
    assert box.request()['state'] == 'waiting'


def test_busy_matcher():
    ns = {'re': re}
    exec(_assign('_CLOUDTAK_COMPOSE_BUSY_RE'), ns)
    rx = ns['_CLOUDTAK_COMPOSE_BUSY_RE']
    for hit in (TAKPORTAL_BUILD,
                'docker compose --progress=plain -f docker-compose.yml -f docker-compose.marketplace.yml up -d --force-recreate api',
                'sudo -n docker compose up -d', 'docker-compose pull', 'docker build -t x .',
                'docker buildx build .', '/usr/libexec/docker/cli-plugins/docker-compose compose up -d'):
        assert rx.search(hit), hit
    for miss in ("docker compose -f docker-compose.yml ps api --format '{{.State}}'",
                 'docker image prune -f', 'docker compose logs --tail 50', 'sleep 30',
                 '/usr/bin/python3 broker'):
        assert not rx.search(miss), miss


# ── console: rate limit → fall back ──────────────────────────────────────────

def test_rate_limit_falls_back_to_the_alarm(box):
    for _ in range(3):
        assert box.request()['state'] == 'repairing'
        box.finish()
        box.takportal_recreate()                          # TAK Portal does it again
        box.api_started = time.time() - 600
    r = box.request()
    assert r['state'] == 'rate_limited' and '3 automatic repairs in the last hour' in r['detail']
    assert len(box.ups()) == 3 and box.threads == []


def test_old_attempts_age_out_of_the_limit(box):
    (box.home / '.config' / 'cloudtak-autorepair.json').write_text(json.dumps(
        {'attempts': [time.time() - 3700] * 3}))
    assert box.request()['state'] == 'repairing'
    assert len(box.record()['attempts']) == 1


# ── console: repair failed → fall back ───────────────────────────────────────

def test_failed_recreate_falls_back_and_stays_pending_for_a_console_restart(box):
    box.up_rc = 1
    assert box.request()['state'] == 'repairing'
    box.finish()
    rec = box.record()['last']
    assert rec['result'] == 'failed' and 'force-recreate failed' in rec['detail']
    assert box.mails == []                                 # no "repaired" note
    assert box.pending()                                   # the next console start redoes it
    r = box.request()
    assert r['state'] == 'failed' and 'automatic repair failed' in r['detail']
    assert len(box.ups()) == 1                             # not retried straight away


def test_heal_that_does_not_confirm_is_a_failure(box):
    box.heal_ok = False
    box.request()
    box.finish()
    assert box.record()['last']['result'] == 'failed'
    assert box.request()['state'] == 'failed' and box.mails == []


def test_compromised_stack_is_never_brought_back(box):
    (box.ct / 'COMPROMISE-DETECTED.txt').write_text('x')
    r = box.request()
    assert r['state'] == 'failed' and 'compromise' in r['detail']
    assert box.threads == [] and box.ups() == []


# ── the endpoint ─────────────────────────────────────────────────────────────

def _route(remote_addr, headers=None):
    ns = {'request': types.SimpleNamespace(remote_addr=remote_addr, headers=headers or {}),
          'jsonify': lambda d: d, '_cloudtak_autorepair_request': lambda: {'state': 'ok'}}
    src = _fn('guarddog_cloudtak_repair')
    src = src[src.index('def '):]
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns['guarddog_cloudtak_repair']()


def test_endpoint_is_loopback_only_and_refuses_caddy_proxied_requests():
    assert _route('127.0.0.1') == {'state': 'ok'}
    assert _route('::1') == {'state': 'ok'}
    assert _route('10.0.0.5')[1] == 403
    assert _route('127.0.0.1', {'X-Forwarded-For': '203.0.113.9'})[1] == 403
    assert "@app.route('/api/guarddog/cloudtak-repair', methods=['POST'])" in APP


# ── Guard Dog: tak-cloudtak-watch.sh ─────────────────────────────────────────

PROFILE = 'hlsVariant: mpegts\nhlsSegmentCount: 3\nhlsSegmentDuration: 500ms\nhlsPartDuration: 200ms\n'
STOCK = 'hlsVariant: fmp4\nhlsSegmentCount: 7\nhlsSegmentDuration: 1s\n'


@pytest.fixture
def gd(tmp_path):
    calls = tmp_path / 'calls.log'
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    ct = tmp_path / 'CloudTAK'
    ct.mkdir()
    (ct / 'docker-compose.override.yml').write_text('# override\n')
    g = tmp_path / 'gd'
    g.mkdir()
    state, logs, proc = tmp_path / 'state', tmp_path / 'logs', tmp_path / 'proc'
    proc.mkdir()
    (proc / 'uptime').write_text('99999.00 1.00\n')
    (g / '_gd-tak-lib.sh').write_text('gd_find_stack_dir() { echo "%s"; }\n' % ct)
    alert = g / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\necho "alert $1" >> %s\ncat >> %s\n' % (calls, tmp_path / 'body.txt'))
    alert.chmod(0o755)
    (stubs / 'docker').write_text(
        '#!/bin/sh\necho "docker $*" >> %(calls)s\n'
        'case "$1" in\n'
        '  inspect) case "$*" in *com.docker.compose.project*) echo cloudtak ;; esac; exit 0 ;;\n'
        '  exec) cat %(yml)s; exit 0 ;;\n'
        '  ps) case "$*" in *label=*) cat %(labels)s ;; *) echo "Up 3 hours" ;; esac ;;\n'
        'esac\nexit 0\n' % {'calls': calls, 'yml': tmp_path / 'media.yml', 'labels': tmp_path / 'labels'})
    (stubs / 'docker').chmod(0o755)
    # curl: answer from $tmp/console (empty file = no answer, like a console that is down)
    (stubs / 'curl').write_text(
        '#!/bin/sh\necho "curl $*" >> %(calls)s\n'
        '[ -s %(resp)s ] || exit 7\ncat %(resp)s\n' % {'calls': calls, 'resp': tmp_path / 'console'})
    (stubs / 'curl').chmod(0o755)
    script = (WATCH.replace('/opt/tak-guarddog/', str(g) + '/')
                   .replace('/var/lib/takguard', str(state))
                   .replace('/var/log/takguard', str(logs))
                   .replace('/proc/', str(proc) + '/')
                   .replace('/tmp/', str(tmp_path) + '/'))
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)
    clean = f'{ct}/docker-compose.yml,{ct}/docker-compose.override.yml'
    takportal = f'{ct}/docker-compose.yml,{ct}/docker-compose.marketplace.yml'

    def tick(yml=STOCK, labels=None, console=None):
        (tmp_path / 'media.yml').write_text(yml)
        rows = labels if labels is not None else {'cloudtak-api-1': takportal, 'cloudtak-media-1': takportal}
        (tmp_path / 'labels').write_text(''.join(f'{n}|{f}\n' for n, f in rows.items()))
        (tmp_path / 'console').write_text(json.dumps(console) if console else '')
        if calls.exists():
            calls.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        return calls.read_text() if calls.exists() else ''

    tick.log = lambda: (logs / 'restarts.log').read_text() if (logs / 'restarts.log').exists() else ''
    tick.body = lambda: (tmp_path / 'body.txt').read_text() if (tmp_path / 'body.txt').exists() else ''
    tick.state, tick.clean, tick.takportal = state, clean, takportal
    return tick


def _alerts(calls):
    return [l for l in calls.splitlines() if l.startswith('alert ')]


def _repair_calls(calls):
    return [l for l in calls.splitlines() if l.startswith('curl ') and 'cloudtak-repair' in l]


def test_gd_first_check_waits_and_never_calls_the_console(gd):
    calls = gd(console={'state': 'repairing'})
    assert _alerts(calls) == [] and _repair_calls(calls) == []
    assert 'created without' in gd.log()


def test_gd_second_check_asks_the_console_and_holds_the_alarm_while_it_repairs(gd):
    gd()
    calls = gd(console={'state': 'repairing', 'detail': 'created without ...'})
    assert len(_repair_calls(calls)) == 1 and _alerts(calls) == []
    assert 'auto-repair: repairing' in gd.log()
    calls = gd(console={'state': 'waiting', 'detail': 'a compose/build run is still going'})
    assert _alerts(calls) == []


def test_gd_repaired_stack_clears_without_any_alarm(gd):
    gd()
    gd(console={'state': 'repairing'})
    calls = gd(yml=PROFILE, labels={'cloudtak-api-1': gd.clean, 'cloudtak-media-1': gd.clean})
    assert _alerts(calls) == [] and _repair_calls(calls) == []
    assert not (gd.state / 'cloudtak_media_drift_pending').exists()


def test_gd_override_drift_alone_is_drift(gd):
    # HLS fine, but the api was recreated by TAK Portal without our override (no console CA).
    gd(yml=PROFILE, labels={'cloudtak-api-1': gd.takportal, 'cloudtak-media-1': gd.clean})
    calls = gd(yml=PROFILE, labels={'cloudtak-api-1': gd.takportal, 'cloudtak-media-1': gd.clean},
               console={'state': 'repairing'})
    assert len(_repair_calls(calls)) == 1
    assert 'created without' in gd.log() and 'cloudtak-api-1' in gd.log() and 'MISSING' not in gd.log()


@pytest.mark.parametrize('state', ['failed', 'rate_limited'])
def test_gd_falls_back_to_the_alarm_when_the_repair_cannot_fix_it(gd, state):
    gd()
    calls = gd(console={'state': state, 'detail': f'{state} detail'})
    alerts = _alerts(calls)
    assert len(alerts) == 1 and alerts[0].startswith('alert Guard Dog: CloudTAK video config drift on ')
    assert f'Automatic repair: {state} — {state} detail' in gd.body()
    assert 'created without' in gd.body()
    assert _alerts(gd(console={'state': state})) == []      # once per episode


def test_gd_console_down_still_alarms_like_before(gd):
    gd()
    alerts = _alerts(gd())                                  # no console answer
    assert len(alerts) == 1 and 'Automatic repair: unreachable' in gd.body()


def test_gd_waiting_too_long_alarms(gd):
    gd()
    (gd.state / 'cloudtak_media_drift_pending').write_text(str(int(time.time()) - 1900))
    alerts = _alerts(gd(console={'state': 'waiting', 'detail': 'cloudtak-api-1 started 5s ago'}))
    assert len(alerts) == 1 and 'not fixed after 31 min' in gd.body()


def test_gd_settings_drift_subject_when_hls_is_fine(gd):
    labels = {'cloudtak-api-1': gd.takportal, 'cloudtak-media-1': gd.clean}
    gd(yml=PROFILE, labels=labels)
    alerts = _alerts(gd(yml=PROFILE, labels=labels, console={'state': 'failed'}))
    assert len(alerts) == 1 and alerts[0].startswith('alert Guard Dog: CloudTAK settings drift on ')


def test_gd_without_an_override_file_nothing_is_flagged(gd, tmp_path):
    (tmp_path / 'CloudTAK' / 'docker-compose.override.yml').unlink()
    gd(yml=PROFILE)
    calls = gd(yml=PROFILE)
    assert _alerts(calls) == [] and _repair_calls(calls) == [] and 'drift' not in gd.log()
