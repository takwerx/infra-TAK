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
"""ops #737: video from a remote CloudTAK needs TCP 9997 open on the CONSOLE box.

A remote CloudTAK's api container calls https://video.<name>:9997 (CloudTAK's video-service.ts
forces that port). That name is the console box, where Caddy listens on :9997. The console
opened 9997 for a local CloudTAK only, so with CloudTAK on a remote host and ufw active on the
console, every video lease timed out ("CloudTAK has no working media server") until the
operator ran `ufw allow 9997/tcp` by hand (found in the 10.3.13 T&E, AWS boxes in one VPC).

Deploy, Update config, Update, console start and Remove now open and close the port for the
remote host's address only. The helpers run for real here (fake ufw / firewall-cmd binaries,
a fake settings store); the wiring into the five paths is checked on the source.
"""

import ast
import ipaddress
import os
import pathlib
import socket
import stat
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _assign(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _ns(**extra):
    """The new helpers plus the firewall helpers they sit on, exec'd from app.py."""
    parts = [_assign('CLOUDTAK_FW_WEB'), _assign('CLOUDTAK_VIDEO_FW_KEY'),
             _src('_fw_allow_from'), _src('_fw_remove_from'),
             _src('_cloudtak_remote_video_sources'), _src('_cloudtak_console_video_fw')]
    ns = {'subprocess': subprocess, 'ipaddress': ipaddress, 'socket': socket,
          '_sudo_wrap': lambda cmd: list(cmd),
          '_list_local_ipv4s': lambda: ['10.0.0.5'],
          '_fw_backend': lambda: 'ufw'}
    ns.update(extra)
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    ns.update(extra)   # a test's stand-ins win over the real helpers
    return ns


class _Store:
    """load_settings / save_settings stand-ins."""
    def __init__(self, data=None):
        self.data = dict(data or {})
        self.saves = 0

    def load(self):
        return dict(self.data)

    def save(self, s):
        self.data = dict(s)
        self.saves += 1


def _fake_fw(tmp_path, monkeypatch):
    """Fake `ufw` and `firewall-cmd` on PATH; every call is appended to calls.log."""
    log = tmp_path / 'calls.log'
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for name in ('ufw', 'firewall-cmd'):
        p = bindir / name
        p.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\nexit 0\n')
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv('PATH', f'{bindir}{os.pathsep}{os.environ["PATH"]}')
    return log


def _calls(log):
    return log.read_text().splitlines() if log.exists() else []


REMOTE = {'target_mode': 'remote', 'remote': {'host': '10.0.0.77'}}


# ── the firewall helpers: the exact commands ────────────────────────────────────────────────

def test_ufw_remove_from_deletes_the_source_scoped_rule(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    ns = _ns()
    assert ns['_fw_allow_from']('10.0.0.77', 9997, 'tcp')[0]
    assert ns['_fw_remove_from']('10.0.0.77', 9997, 'tcp')[0]
    assert _calls(log) == [
        'ufw allow from 10.0.0.77 to any port 9997 proto tcp',
        'ufw --force delete allow from 10.0.0.77 to any port 9997 proto tcp',
    ]


def test_firewalld_remove_from_removes_the_same_rich_rule_it_added(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    ns = _ns(_fw_backend=lambda: 'firewalld')
    ns['_fw_allow_from']('10.0.0.77', 9997, 'tcp')
    ns['_fw_remove_from']('10.0.0.77', 9997, 'tcp')
    calls = _calls(log)
    rule = 'rule family="ipv4" source address="10.0.0.77" port port="9997" protocol="tcp" accept'
    assert f'firewall-cmd --zone=public --permanent --add-rich-rule={rule}' in calls
    assert f'firewall-cmd --zone=public --permanent --remove-rich-rule={rule}' in calls
    assert calls[-1] == 'firewall-cmd --reload'


def test_remove_from_without_a_firewall_is_a_noop():
    ns = _ns(_fw_backend=lambda: None)
    assert ns['_fw_remove_from']('10.0.0.77', 9997)[0] is True


# ── the sources: the remote host's own address ──────────────────────────────────────────────

def test_sources_is_the_configured_address():
    assert _ns()['_cloudtak_remote_video_sources'](REMOTE) == ['10.0.0.77']


def test_sources_resolves_a_host_name_on_the_console(monkeypatch):
    fake = types.SimpleNamespace(
        getaddrinfo=lambda h, p, fam: [(2, 1, 6, '', ('203.0.113.9', 0))],
        AF_INET=2)
    ns = _ns(socket=fake)
    cfg = {'target_mode': 'remote', 'remote': {'host': 'ct.example.com'}}
    assert ns['_cloudtak_remote_video_sources'](cfg) == ['203.0.113.9']


def test_sources_leave_out_this_box_and_loopback_and_unresolvable():
    ns = _ns()
    assert ns['_cloudtak_remote_video_sources']({'remote': {'host': '10.0.0.5'}}) == []
    assert ns['_cloudtak_remote_video_sources']({'remote': {'host': '127.0.0.1'}}) == []
    assert ns['_cloudtak_remote_video_sources']({'remote': {'host': ''}}) == []

    def boom(*a, **k):
        raise OSError('nxdomain')
    ns2 = _ns(socket=types.SimpleNamespace(getaddrinfo=boom, AF_INET=2))
    assert ns2['_cloudtak_remote_video_sources']({'remote': {'host': 'nope.invalid'}}) == []


# ── the behaviour: open for the remote host only, close on Remove ───────────────────────────

def test_allow_opens_9997_for_the_remote_host_only(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    store = _Store()
    ns = _ns(load_settings=store.load, save_settings=store.save)
    logs = []
    ok, failed = ns['_cloudtak_console_video_fw'](None, REMOTE, 'allow', log_fn=logs.append)
    assert ok == ['10.0.0.77'] and failed == []
    assert _calls(log) == ['ufw allow from 10.0.0.77 to any port 9997 proto tcp']
    assert not any(c.startswith('ufw allow 9997') for c in _calls(log))   # never open to everyone
    assert store.data[ns['CLOUDTAK_VIDEO_FW_KEY']] == ['10.0.0.77']
    text = '\n'.join(logs)
    assert '10.0.0.77' in text
    # the operator is told which CLOUD firewall rules the console box still needs
    assert 'TCP 443 and 9997' in text and 'security group' in text


def test_allow_twice_is_idempotent_and_saves_once(tmp_path, monkeypatch):
    _fake_fw(tmp_path, monkeypatch)
    store = _Store()
    ns = _ns(load_settings=store.load, save_settings=store.save)
    ns['_cloudtak_console_video_fw'](None, REMOTE, 'allow', log_fn=lambda m: None)
    ns['_cloudtak_console_video_fw'](None, REMOTE, 'allow', log_fn=lambda m: None)
    assert store.saves == 1
    assert store.data[ns['CLOUDTAK_VIDEO_FW_KEY']] == ['10.0.0.77']


def test_a_new_remote_host_closes_the_old_hosts_rule(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    store = _Store()
    ns = _ns(load_settings=store.load, save_settings=store.save)
    ns['_cloudtak_console_video_fw'](None, REMOTE, 'allow', log_fn=lambda m: None)
    new = {'target_mode': 'remote', 'remote': {'host': '10.0.0.88'}}
    ns['_cloudtak_console_video_fw'](None, new, 'allow', log_fn=lambda m: None)
    assert 'ufw --force delete allow from 10.0.0.77 to any port 9997 proto tcp' in _calls(log)
    assert 'ufw allow from 10.0.0.88 to any port 9997 proto tcp' in _calls(log)
    assert store.data[ns['CLOUDTAK_VIDEO_FW_KEY']] == ['10.0.0.88']


def test_remove_closes_the_recorded_and_the_current_host(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    store = _Store({'cloudtak_video_fw_sources': ['10.0.0.66']})
    ns = _ns(load_settings=store.load, save_settings=store.save)
    ns['_cloudtak_console_video_fw'](None, REMOTE, 'remove', log_fn=lambda m: None)
    closed = [c for c in _calls(log) if 'delete allow from' in c]
    assert sorted(closed) == [
        'ufw --force delete allow from 10.0.0.66 to any port 9997 proto tcp',
        'ufw --force delete allow from 10.0.0.77 to any port 9997 proto tcp']
    assert store.data['cloudtak_video_fw_sources'] == []
    assert not any(c.startswith('ufw allow') for c in _calls(log))


def test_a_local_target_opens_nothing_here(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    store = _Store()
    ns = _ns(load_settings=store.load, save_settings=store.save)
    assert ns['_cloudtak_console_video_fw'](None, {'target_mode': 'local'}, 'allow',
                                            log_fn=lambda m: None) == ([], [])
    assert _calls(log) == [] and store.saves == 0


def test_an_unresolvable_host_warns_and_opens_nothing(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    store = _Store()
    ns = _ns(load_settings=store.load, save_settings=store.save)
    logs = []
    cfg = {'target_mode': 'remote', 'remote': {'host': ''}}
    ok, failed = ns['_cloudtak_console_video_fw'](None, cfg, 'allow', log_fn=logs.append)
    assert ok == [] and _calls(log) == []
    assert any('stays closed' in l for l in logs)


def test_a_failed_close_is_kept_and_tried_again(tmp_path, monkeypatch):
    _fake_fw(tmp_path, monkeypatch)
    store = _Store({'cloudtak_video_fw_sources': ['10.0.0.66']})
    state = {'fail': True}

    def remove_from(ip, port, proto='tcp'):
        return (not state['fail']), 'busy'
    ns = _ns(load_settings=store.load, save_settings=store.save, _fw_remove_from=remove_from)
    ns['_fw_remove_from'] = remove_from
    cfg = {'target_mode': 'remote', 'remote': {'host': '10.0.0.77'}}
    ns['_cloudtak_console_video_fw'](None, cfg, 'allow', log_fn=lambda m: None)
    assert '10.0.0.66' in store.data['cloudtak_video_fw_sources']
    state['fail'] = False
    ns['_cloudtak_console_video_fw'](None, cfg, 'allow', log_fn=lambda m: None)
    assert store.data['cloudtak_video_fw_sources'] == ['10.0.0.77']


def test_a_firewall_error_never_raises():
    def boom(*a, **k):
        raise RuntimeError('ufw exploded')
    ns = _ns(load_settings=lambda: {}, save_settings=lambda s: None, _fw_allow_from=boom)
    logs = []
    assert ns['_cloudtak_console_video_fw'](None, REMOTE, 'allow', log_fn=logs.append) == ([], [])
    assert any('skipped' in l for l in logs)


# ── the wiring: every path that sets up, changes or removes a remote CloudTAK ───────────────

def _after(src, first, second):
    """True when `second` appears in src after `first`."""
    i = src.index(first)
    return second in src[i:]


def test_remote_deploy_opens_the_port_after_the_port_lock_and_before_the_containers_start():
    src = _src('run_cloudtak_deploy')
    guard = src.index('_remote_cloudtak_port_guard(cfg, settings, log_fn=plog)')
    call = src.index("_cloudtak_console_video_fw(settings, cfg, 'allow'")
    step5 = src.index('Step 5/6: Building/Starting remote containers')
    assert guard < call < step5


def test_update_config_reapplies_the_console_rule_after_the_port_lock():
    src = _src('run_cloudtak_redeploy')
    guard = src.index('_remote_cloudtak_port_guard(cfg, settings, log_fn=plog)')
    call = src.index("_cloudtak_console_video_fw(settings, cfg, 'allow'")
    assert guard < call
    assert src.count("_cloudtak_console_video_fw(settings, cfg, 'allow'") == 1


def test_update_reapplies_the_console_rule_in_its_remote_branch():
    src = _src('run_cloudtak_update')
    guard = src.index('_remote_cloudtak_port_guard(cfg, settings, log_fn=plog)')
    call = src.index("_cloudtak_console_video_fw(settings, cfg, 'allow'")
    assert guard < call
    assert src.count("_cloudtak_console_video_fw(settings, cfg, 'allow'") == 1
    # inside the `if is_remote:` block, not the local else
    assert src.rindex('if is_remote:', 0, call) > src.rindex('else:', 0, guard) - 4000


def test_remove_closes_the_console_rule_for_a_remote_target():
    src = _src('_cloudtak_close_firewall')
    assert "cfg.get('target_mode') == 'remote'" in src
    assert "_cloudtak_console_video_fw(None, cfg, 'remove'" in src


def test_console_start_opens_it_for_an_already_deployed_remote_cloudtak():
    src = _src('_startup_cloudtak_remote_video_fw')
    assert "cfg.get('target_mode') != 'remote' or not cfg.get('deployed')" in src
    assert "'allow'" in src
    assert '\n_startup_cloudtak_remote_video_fw()\n' in APP


def test_the_port_is_the_one_cloudtak_always_calls():
    ns = _ns()
    assert ns['CLOUDTAK_FW_WEB'] == ((9997, 'tcp'),)
