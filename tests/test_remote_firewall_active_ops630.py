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
"""Remote deploys must not trust a firewall that is off (ops #630).

Stock Ubuntu cloud images ship ufw installed but INACTIVE. The remote MediaMTX deploy
only checked that the ufw binary existed, added `ufw deny 5080`, and printed "closed"
while the web editor (meant for the console only) still listened on
0.0.0.0:5080. Its console allow went in AFTER the deny, so with ufw on the console's own
Caddy was blocked. The RHEL remote DB set listen_addresses='*' and printed FW_DONE over a
firewalld that might not exist.

The shell snippets here run for real under `sh` against fake ufw / firewalld / sudo
binaries that keep their state in files, so the tests check what the box would end up
with, not just which strings were sent.
"""

import ast
import json
import os
import pathlib
import re
import shlex
import stat
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

CONSOLE = '203.0.113.5'      # TEST-NET-3: the console as the remote sees it over SSH
SERVER_IP = '198.51.100.7'   # TEST-NET-2: Settings → Server IP
OTHER = '192.0.2.99'         # TEST-NET-1: anyone else on the internet


def _src(*names):
    """Top-level defs/assignments from app.py, in file order. A name app.py does not have
    is skipped, so on unfixed code the old function runs and fails on what it does."""
    parts = []
    for n in TREE.body:
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names:
            parts.append(ast.get_source_segment(APP, n))
        elif isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in names for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
    return '\n\n'.join(parts)


def _ns(names, **extra):
    ns = {'re': re, 'os': os, 'json': json, 'shlex': shlex, 'time': __import__('time'),
          'socket': __import__('socket')}
    ns.update(extra)
    exec(compile(_src(*names), 'app.py', 'exec'), ns)
    return ns


# ── fake box ──────────────────────────────────────────────────────────────────────

_UFW = r'''#!/bin/sh
D="$FAKE"; echo "ufw $*" >> "$D/calls"
[ "$1" = "--force" ] && shift
case "$1" in
  status) if [ -f "$D/ufw_active" ]; then echo "Status: active"; else echo "Status: inactive"; fi ;;
  enable) [ -f "$D/ufw_enable_fails" ] && exit 1; touch "$D/ufw_active" ;;
  delete) shift; grep -vxF "$*" "$D/ufw_rules" > "$D/r.tmp"; mv "$D/r.tmp" "$D/ufw_rules" ;;
  allow|deny) grep -qxF "$*" "$D/ufw_rules" || echo "$*" >> "$D/ufw_rules" ;;  # ufw: "Skipping adding existing rule"
esac
exit 0
'''
_FWCMD = r'''#!/bin/sh
D="$FAKE"; echo "firewall-cmd $*" >> "$D/calls"
if [ "$1" = "--state" ]; then
  if [ -f "$D/fwd_running" ]; then echo running; exit 0; fi
  echo "not running"; exit 252
fi
[ -f "$D/fwd_running" ] || exit 252
exit 0
'''
_FWOFF = '#!/bin/sh\necho "firewall-offline-cmd $*" >> "$FAKE/calls"\nexit 0\n'
_SYSTEMCTL = r'''#!/bin/sh
D="$FAKE"; echo "systemctl $*" >> "$D/calls"
case "$*" in *"enable --now firewalld"*) [ -f "$D/fwd_start_fails" ] || touch "$D/fwd_running" ;; esac
exit 0
'''
_INSTALLER = r'''#!/bin/sh
D="$FAKE"; echo "PKG $*" >> "$D/calls"
[ -f "$D/pkg_fails" ] && exit 1
case "$*" in
  *firewalld*) cp "$D/tpl/firewall-cmd" "$D/bin/"; cp "$D/tpl/firewall-offline-cmd" "$D/bin/" ;;
  *ufw*) cp "$D/tpl/ufw" "$D/bin/" ;;
esac
exit 0
'''
_SUDO = '#!/bin/sh\n[ -f "$FAKE/sudo_fails" ] && exit 1\n[ "$1" = "-n" ] && shift\nexec "$@"\n'


def _write(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class Box:
    """A fake remote box: a bin dir of fake tools and their state files."""

    def __init__(self, tmp, have=('ufw',), rhel=False, root=False, ssh_port=22,
                 ufw_active=False, fwd_running=False):
        self.d = tmp
        (tmp / 'bin').mkdir()
        (tmp / 'tpl').mkdir()
        for name, text in (('ufw', _UFW), ('firewall-cmd', _FWCMD),
                           ('firewall-offline-cmd', _FWOFF)):
            _write(tmp / 'tpl' / name, text)
        for name in have:
            _write(tmp / 'bin' / name, (tmp / 'tpl' / name).read_text())
            if name == 'firewall-cmd':
                _write(tmp / 'bin' / 'firewall-offline-cmd', _FWOFF)
        _write(tmp / 'bin' / 'systemctl', _SYSTEMCTL)
        _write(tmp / 'bin' / 'dnf', _INSTALLER)
        _write(tmp / 'bin' / 'apt-get', _INSTALLER)
        _write(tmp / 'bin' / 'sudo', _SUDO)
        _write(tmp / 'bin' / 'id', f'#!/bin/sh\necho {0 if root else 1000}\n')
        (tmp / 'ufw_rules').write_text('')
        (tmp / 'calls').write_text('')
        self.rhel_marker = tmp / 'redhat-release'
        if rhel:
            self.rhel_marker.write_text('Rocky Linux release 9.4\n')
        if ufw_active:
            (tmp / 'ufw_active').write_text('')
        if fwd_running:
            (tmp / 'fwd_running').write_text('')
        self.ssh_port = ssh_port

    def flag(self, name):
        (self.d / name).write_text('')

    def run(self, cmd):
        cmd = cmd.replace('/etc/redhat-release', str(self.rhel_marker))
        env = {
            'PATH': f'{self.d / "bin"}:/usr/bin:/bin',
            'FAKE': str(self.d),
            'SSH_CONNECTION': f'{CONSOLE} 50000 10.0.0.4 {self.ssh_port}',
            'SSH_CLIENT': f'{CONSOLE} 50000 {self.ssh_port}',
        }
        r = subprocess.run(['sh', '-c', cmd], env=env, capture_output=True, text=True, timeout=30)
        return r.returncode == 0, (r.stdout or '') + (r.stderr or '')

    def calls(self):
        return (self.d / 'calls').read_text().splitlines()

    def ufw_active(self):
        return (self.d / 'ufw_active').exists()

    def ufw_rules(self):
        return (self.d / 'ufw_rules').read_text().splitlines()

    def ufw_verdict(self, src, port):
        """What an active ufw does with a TCP packet from src to port: first match wins."""
        if not self.ufw_active():
            return 'open'
        for rule in self.ufw_rules():
            if rule in (f'allow {port}/tcp', f'deny {port}/tcp'):
                return rule.split()[0]
            if rule == f'allow from {src} to any port {port} proto tcp':
                return 'allow'
        return 'deny'   # ufw default incoming policy


def _module_fw_ns(box):
    """_module_fw and its helpers, with _module_run going to the fake box."""
    return _ns(('_MODULE_FW_BACKEND_KEY', '_module_fw_backend', '_module_fw',
                '_REMOTE_SUDO_SH', '_MODULE_FW_ACTIVE_KEY', '_remote_fw_ensure_sh',
                '_module_fw_ensure_active'),
               _module_run=lambda cfg, cmd, timeout=120, log_fn=None: box.run(cmd),
               _fw_backend=lambda: 'ufw', _fw_allow=None, _fw_deny=None, _fw_remove=None)


def _remote_cfg(port=22):
    return {'target_mode': 'remote', 'remote': {'host': 'mtx.example', 'ssh_port': port}}


# ── 1. _module_fw: never a rule in a firewall that is off ──────────────────────────

def test_deny_into_an_off_firewall_that_cannot_be_turned_on_fails(tmp_path):
    """The bug: ufw installed but off, the SSH user cannot turn it on. dev said ok."""
    box = Box(tmp_path, have=('ufw',))
    box.flag('sudo_fails')
    ns = _module_fw_ns(box)
    ok, msg = ns['_module_fw'](_remote_cfg(), 'deny', 5080, 'tcp')
    assert ok is False
    assert 'not active' in msg
    assert not box.ufw_active()


def test_off_ufw_is_turned_on_with_ssh_allowed_first(tmp_path):
    box = Box(tmp_path, have=('ufw',), ssh_port=22)
    ns = _module_fw_ns(box)
    logs = []
    ok, _ = ns['_module_fw'](_remote_cfg(port=2222), 'deny', 9898, 'tcp', log_fn=logs.append)
    assert ok is True
    assert box.ufw_active()
    calls = box.calls()
    enable = calls.index('ufw --force enable')
    # Configured port AND the port this session really came in on (NAT forward 2222→22).
    assert calls.index('ufw allow 2222/tcp') < enable
    assert calls.index('ufw allow 22/tcp') < enable
    assert box.ufw_verdict(OTHER, 22) == 'allow'
    assert 'deny 9898/tcp' in box.ufw_rules()
    assert any('was OFF' in m for m in logs)


def test_active_firewall_is_left_alone(tmp_path):
    box = Box(tmp_path, have=('ufw',), ufw_active=True)
    ns = _module_fw_ns(box)
    ok, _ = ns['_module_fw'](_remote_cfg(), 'allow', 8554, 'tcp')
    assert ok is True
    calls = box.calls()
    assert 'ufw --force enable' not in calls
    assert not any(c.startswith('ufw allow 22/') for c in calls)


def test_no_firewall_at_all_installs_ufw_on_debian(tmp_path):
    box = Box(tmp_path, have=())
    ns = _module_fw_ns(box)
    ok, _ = ns['_module_fw'](_remote_cfg(), 'deny', 9898, 'tcp')
    assert ok is True
    assert any(c.startswith('PKG ') and 'ufw' in c for c in box.calls())
    assert box.ufw_active()


def test_no_firewall_and_install_fails_is_not_ok(tmp_path):
    """dev returned (True, 'no firewall present on target') for a deny."""
    box = Box(tmp_path, have=())
    box.flag('pkg_fails')
    ns = _module_fw_ns(box)
    ok, msg = ns['_module_fw'](_remote_cfg(), 'deny', 5080, 'tcp')
    assert ok is False
    assert 'could not be installed' in msg


def test_rhel_firewalld_off_is_started_with_ssh_kept(tmp_path):
    box = Box(tmp_path, have=('firewall-cmd',), rhel=True)
    ns = _module_fw_ns(box)
    cfg = _remote_cfg(port=2222)
    ok, be, _ = ns['_module_fw_ensure_active'](cfg)
    assert (ok, be) == (True, 'firewalld')
    calls = box.calls()
    start = calls.index('systemctl enable --now firewalld')
    assert calls.index('firewall-offline-cmd --add-port=2222/tcp') < start
    assert calls.index('firewall-offline-cmd --add-port=22/tcp') < start
    assert calls.index('firewall-offline-cmd --add-service=ssh') < start


def test_rhel_firewalld_that_will_not_start_is_not_ok(tmp_path):
    box = Box(tmp_path, have=('firewall-cmd',), rhel=True)
    box.flag('fwd_start_fails')
    ns = _module_fw_ns(box)
    ok, msg = ns['_module_fw'](_remote_cfg(), 'deny', 9898, 'tcp')
    assert ok is False and 'firewalld' in msg


def test_remove_does_not_turn_a_firewall_on(tmp_path):
    """Uninstall closes ports; it must not change whether the firewall is on."""
    box = Box(tmp_path, have=('ufw',))
    ns = _module_fw_ns(box)
    ns['_module_fw'](_remote_cfg(), 'remove', 5000, 'tcp')
    assert not box.ufw_active()
    assert 'ufw --force enable' not in box.calls()


def test_saved_config_drops_the_per_deploy_firewall_cache():
    ns = _ns(('_MODULE_FW_BACKEND_KEY', '_MODULE_FW_ACTIVE_KEY', '_module_deployment_defaults',
              '_normalize_module_deployment_config', '_deep_merge_dict'),
             copy=__import__('copy'))
    c = ns['_normalize_module_deployment_config'](
        {'target_mode': 'remote', '_infratak_fw_backend': '', '_infratak_fw_active': 'ufw',
         'remote': {'host': 'h'}})
    assert '_infratak_fw_backend' not in c and '_infratak_fw_active' not in c


# ── 2. MediaMTX: console allowed BEFORE the deny, everyone else blocked ────────────

def _mtx_ns(box):
    names = ('_MODULE_FW_BACKEND_KEY', '_module_fw_backend', '_module_fw', '_REMOTE_SUDO_SH',
             '_MODULE_FW_ACTIVE_KEY', '_remote_fw_ensure_sh', '_module_fw_ensure_active',
             '_MEDIAMTX_REMOTE_FW_RULES', '_MEDIAMTX_REMOTE_CONSOLE_PORTS',
             '_mediamtx_remote_console_scope_sh', '_mediamtx_remote_firewall',
             '_fedhub_caddy_source_ip')
    return _ns(names,
               _module_run=lambda cfg, cmd, timeout=120, log_fn=None: box.run(cmd),
               _fw_backend=lambda: 'ufw', _fw_allow=None, _fw_deny=None, _fw_remove=None)


def test_remote_mediamtx_firewall_on_a_stock_ubuntu_box(tmp_path):
    """ufw installed but off, as on a stock Ubuntu cloud image."""
    box = Box(tmp_path, have=('ufw',))
    ns = _mtx_ns(box)
    logs = []
    state, failed = ns['_mediamtx_remote_firewall']({'server_ip': SERVER_IP}, _remote_cfg(), logs.append)
    assert (state, failed) == ('on', [])
    assert box.ufw_active()
    for port in (5080, 8888):
        assert box.ufw_verdict(CONSOLE, port) == 'allow'      # SSH source (Caddy egress)
        assert box.ufw_verdict(SERVER_IP, port) == 'allow'    # Settings → Server IP
        assert box.ufw_verdict(OTHER, port) == 'deny'
    assert box.ufw_verdict(OTHER, 9898) == 'deny'
    for port in (8554, 8322):
        assert box.ufw_verdict(OTHER, port) == 'allow'
    assert box.ufw_verdict(OTHER, 22) == 'allow'
    assert any('open to the console only' in m for m in logs)


def test_old_deny_rules_from_an_earlier_deploy_do_not_block_the_console(tmp_path):
    """A pre-#630 box: `deny 5080/tcp` sits ABOVE the console allow. First match wins."""
    box = Box(tmp_path, have=('ufw',), ufw_active=True)
    (box.d / 'ufw_rules').write_text(
        'deny 8888/tcp\ndeny 5080/tcp\ndeny 9898/tcp\n'
        f'allow from {SERVER_IP} to any port 5080 proto tcp\n'
        f'allow from {SERVER_IP} to any port 8888 proto tcp\n')
    assert box.ufw_verdict(SERVER_IP, 5080) == 'deny'          # the bug, as found
    ns = _mtx_ns(box)
    state, failed = ns['_mediamtx_remote_firewall']({'server_ip': SERVER_IP}, _remote_cfg(), print)
    assert (state, failed) == ('on', [])
    for port in (5080, 8888):
        assert box.ufw_verdict(SERVER_IP, port) == 'allow'
        assert box.ufw_verdict(OTHER, port) == 'deny'


def test_rerun_does_not_pile_up_rules(tmp_path):
    box = Box(tmp_path, have=('ufw',))
    ns = _mtx_ns(box)
    for _ in range(3):
        ns['_mediamtx_remote_firewall']({'server_ip': SERVER_IP}, _remote_cfg(), print)
    rules = box.ufw_rules()
    assert rules.count('deny 5080/tcp') == 1
    assert rules.count(f'allow from {CONSOLE} to any port 5080 proto tcp') == 1


def test_remote_mediamtx_firewall_reports_off_when_it_cannot_turn_it_on(tmp_path):
    box = Box(tmp_path, have=('ufw',))
    box.flag('sudo_fails')
    ns = _mtx_ns(box)
    logs = []
    state, _ = ns['_mediamtx_remote_firewall']({'server_ip': SERVER_IP}, _remote_cfg(), logs.append)
    assert state == 'off'
    assert not any(m.startswith('✓') for m in logs)
    assert any('reachable from any address' in m for m in logs)


def test_unreachable_box_is_unknown_not_off():
    ns = _ns(('_MODULE_FW_BACKEND_KEY', '_module_fw_backend', '_module_fw', '_REMOTE_SUDO_SH',
              '_MODULE_FW_ACTIVE_KEY', '_remote_fw_ensure_sh', '_module_fw_ensure_active',
              '_MEDIAMTX_REMOTE_FW_RULES', '_MEDIAMTX_REMOTE_CONSOLE_PORTS',
              '_mediamtx_remote_console_scope_sh', '_mediamtx_remote_firewall',
              '_fedhub_caddy_source_ip'),
             _module_run=lambda *a, **k: (False, 'ssh: connect to host timed out'),
             _fw_backend=lambda: 'ufw', _fw_allow=None, _fw_deny=None, _fw_remove=None)
    state, _ = ns['_mediamtx_remote_firewall']({}, _remote_cfg(), print)
    assert state == 'unknown'


def test_remote_mediamtx_firewall_on_rhel(tmp_path):
    box = Box(tmp_path, have=('firewall-cmd',), rhel=True)
    ns = _mtx_ns(box)
    state, failed = ns['_mediamtx_remote_firewall']({'server_ip': SERVER_IP}, _remote_cfg(), print)
    assert (state, failed) == ('on', [])
    calls = box.calls()
    for port in (5080, 8888):
        for src in (CONSOLE, SERVER_IP):
            assert any(f"source address='{src}' port port='{port}'" in c for c in calls)
        assert f'firewall-cmd --permanent --remove-port={port}/tcp' in calls


def _deploy_body():
    fn = next(n for n in TREE.body
              if isinstance(n, ast.FunctionDef) and n.name == '_run_mediamtx_deploy_remote')
    return ast.get_source_segment(APP, fn)


def test_deploy_firewalls_before_the_editor_starts_and_stops_if_it_cannot():
    body = _deploy_body()
    fw = body.index('_mediamtx_remote_firewall(')
    start = body.index('systemctl start mediamtx-webeditor')
    assert fw < start
    between = body[fw:start]
    assert "!= 'on'" in between and 'return' in between
    assert 'disable --now mediamtx-webeditor' in between


def test_deploy_has_no_bare_ufw_lines_left():
    """The old late block put `ufw deny 5080` before the console allow."""
    body = _deploy_body()
    assert 'ufw deny 5080' not in body and 'ufw allow from' not in body


# ── 3. RHEL remote DB: firewalld installed, running, or the deploy stops ───────────

def _rhel_db(box, port=22):
    calls = []

    def ssh_probe(s1, cmd, timeout=15):
        calls.append(cmd)
        if 'firewall-cmd' in cmd:
            return box.run(cmd)
        if 'information_schema.tables' in cmd:
            return True, '1\n60'
        if 'pg_roles' in cmd or 'pg_database' in cmd:
            return True, '1\n1'
        return True, 'ACTIVE=active PG_OK REPO_DONE EPEL_OK'
    ns = _ns(('_setup_server_one_rhel',),
             _ssh_probe=ssh_probe, _valid_core_ip=lambda ip: True,
             _PG_REMOTE_PGDATA_SH='PGDATA=/var/lib/pgsql/18/data',
             _PG_REMOTE_PGSVC_SH='PGSVC=postgresql-18', _pg_keepalive_sh=lambda p: 'true',
             TAK_PG_MAJOR=18, _scp_to_host=lambda *a, **k: (True, ''),
             _fetch_db_password_from_server_one=lambda s1: ('pw', ''),
             _verify_server_one_db_password=lambda *a, **k: (True, ''),
             _server_one_tls_step=lambda *a, **k: 'PEM')
    res = ns['_setup_server_one_rhel']({'host': 'db', 'ssh_port': port}, '198.51.100.20', 5432)
    return res, calls


def test_rhel_db_without_firewalld_stops_the_deploy(tmp_path):
    """dev: `enable --now firewalld || true` on a box with no firewalld, then FW_DONE."""
    box = Box(tmp_path, have=(), rhel=True)
    box.flag('pkg_fails')
    res, calls = _rhel_db(box)
    assert res[0] is False
    assert any('firewalld is NOT running' in ln for ln in res[1])
    # Nothing after the firewall step ran.
    fw_i = max(i for i, c in enumerate(calls) if 'firewall-cmd' in c)
    assert fw_i == len(calls) - 1


def test_rhel_db_installs_and_starts_firewalld_keeping_ssh(tmp_path):
    box = Box(tmp_path, have=(), rhel=True, ssh_port=22)
    res, _ = _rhel_db(box, port=2222)
    assert res[0] is True
    calls = box.calls()
    assert any(c.startswith('PKG ') and 'firewalld' in c for c in calls)
    start = calls.index('systemctl enable --now firewalld')
    assert calls.index('firewall-offline-cmd --add-port=2222/tcp') < start
    assert calls.index('firewall-offline-cmd --add-port=22/tcp') < start
    assert any("source address='198.51.100.20'" in c and "port='5432'" in c for c in calls)
    assert any('firewalld: running' in ln for ln in res[1])


# ── 4. Existing remote boxes: checked on console start ─────────────────────────────

def _startup_ns(tmp_path, state, failed=(), email='ops@example.com'):
    runs, mails = [], []
    ns = _ns(('_REMOTE_SUDO_SH', '_MEDIAMTX_REMOTE_FW_ALERT_EVERY_S',
              '_startup_converge_mediamtx_remote_firewall', '_mediamtx_remote_fw_alert'),
             CONFIG_DIR=str(tmp_path),
             load_settings=lambda: {'guarddog_alert_email': email},
             _get_module_deployment_config=lambda s, k: {
                 'target_mode': 'remote', 'deployed': True, 'remote': {'host': 'mtx.example'}},
             _mediamtx_remote_firewall=lambda s, c, log: (state, list(failed)),
             _module_run=lambda cfg, cmd, timeout=120, log_fn=None: runs.append(cmd) or (True, ''),
             _guarddog_server_identifier=lambda s: 'console1',
             _guarddog_send_alert_email_via_relay=lambda to, subj, body: mails.append((to, subj, body)) or True)
    return ns, runs, mails


def test_startup_off_stops_the_editor_and_mails_once_a_day(tmp_path):
    ns, runs, mails = _startup_ns(tmp_path, 'off')
    ns['_startup_converge_mediamtx_remote_firewall']()
    assert any('disable --now mediamtx-webeditor' in r for r in runs)
    assert len(mails) == 1 and 'firewall is off' in mails[0][1]
    ns['_startup_converge_mediamtx_remote_firewall']()     # daily console restart
    assert len(mails) == 1


def test_startup_on_again_restarts_only_an_editor_it_stopped(tmp_path):
    ns, runs, _ = _startup_ns(tmp_path, 'off')
    ns['_startup_converge_mediamtx_remote_firewall']()
    ns2, runs2, mails2 = _startup_ns(tmp_path, 'on')
    ns2['_startup_converge_mediamtx_remote_firewall']()
    assert any('enable --now mediamtx-webeditor' in r for r in runs2)
    assert mails2 == []
    ns3, runs3, _ = _startup_ns(tmp_path, 'on')
    ns3['_startup_converge_mediamtx_remote_firewall']()
    assert runs3 == []


def test_startup_unreachable_box_is_only_logged(tmp_path):
    ns, runs, mails = _startup_ns(tmp_path, 'unknown')
    ns['_startup_converge_mediamtx_remote_firewall']()
    assert runs == [] and mails == []


def test_startup_rules_failed_mails(tmp_path):
    ns, runs, mails = _startup_ns(tmp_path, 'on', failed=['console-only 5080/8888: x'])
    ns['_startup_converge_mediamtx_remote_firewall']()
    assert runs == [] and len(mails) == 1 and 'did not apply' in mails[0][1]


def test_startup_runs_the_check_in_the_background():
    fn = next(n for n in TREE.body
              if isinstance(n, ast.FunctionDef) and n.name == '_startup_migrations')
    body = ast.get_source_segment(APP, fn)
    assert re.search(r'threading\.Thread\(target=_startup_converge_mediamtx_remote_firewall,'
                     r'\s*daemon=True', body)
