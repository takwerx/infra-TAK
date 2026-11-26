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
"""fail2ban bans reach Docker-published ports too (infra-TAK #736).

ufw, iptables-allports and iptables-multiport ban in INPUT. A port Docker publishes
(Docker TAK Server, CloudTAK media, any container) is DNATed and goes through FORWARD,
so a banned address could still reach it. Every jail now carries an infratak-docker
action beside its own ban action, on the same ports, that drops the address in
DOCKER-USER. These tests run the shipped app.py text against fakes; the real firewall
check is the box test in the PR.
"""

import ast
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

NAMES = ('_F2B_DOCKER_ACTION_PATH', '_F2B_DOCKER_MATCH', '_F2B_DOCKER_ENSURE',
         '_F2B_DOCKER_ACTION_CONF', '_F2B_ALLPORTS_ACTIONS', '_F2B_ACTION_ITEM_RE',
         '_F2B_ACTION_OPT_RE', '_f2b_ensure_docker_action', '_f2b_docker_twin_item',
         '_f2b_docker_twin', '_f2b_add_docker_twins')


def _seg(node):
    return ast.get_source_segment(APP, node)


def _load(tmp_path, have_dir=True):
    """The helpers from app.py, with the action file written under tmp_path."""
    src = []
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in NAMES:
            src.append(_seg(n))
        elif isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in NAMES for t in n.targets):
            src.append(_seg(n))
    assert len(src) == len(NAMES), 'a #736 helper was renamed or removed'
    import os
    written = {}
    ns = {'os': os, 're': re}

    def _write_priv(path, text, **kw):
        written[path] = text
        with open(path, 'w') as f:
            f.write(text)
    ns['_write_priv'] = _write_priv
    exec('\n\n'.join(src), ns)
    act_dir = tmp_path / 'action.d'
    if have_dir:
        act_dir.mkdir(exist_ok=True)
    path = str(act_dir / 'infratak-docker.conf')
    ns['_F2B_DOCKER_ACTION_PATH'] = path
    real_isdir = os.path.isdir
    ns['os'] = type('o', (), {'path': type('p', (), {
        'isdir': staticmethod(lambda p: real_isdir(str(act_dir)) if p == '/etc/fail2ban/action.d' else real_isdir(p)),
    })})
    ns['_written'] = written
    return ns


# The shapes the jail writers produce today (from a live box, Nov 25, 2026).
AUTHENTIK = ("[authentik]\nenabled  = true\nfilter   = authentik\n"
             "logpath  = /var/log/authentik/auth.log\nbackend  = auto\nmaxretry = 5\n"
             "findtime = 600\nbantime  = 3600\nignoreip = 127.0.0.1/8 ::1\n"
             "action   = infratak-ufw\n         infratak-guarddog\n")
MEDIA = ("[mediamtx-rtsp]\nenabled  = true\nmaxretry = 5\n"
         "action   = iptables-multiport[name=mediamtx-tcp, port=\"1935,8322,8554,8555,8888,8889,8892\", protocol=tcp]\n"
         "         iptables-multiport[name=mediamtx-udp, port=\"8000,8001,8189,8890\", protocol=udp]\n"
         "         infratak-guarddog\n")
TAK = ("[takserver]\nenabled  = true\n"
       "action   = iptables-multiport[name=takserver, port=\"8089,8443,8446,9000,9001\", protocol=tcp]\n"
       "         infratak-guarddog-takserver\n")
RECIDIVE = ("[recidive]\nenabled  = true\nbantime  = 604800\n"
            "action   = iptables-allports\n")


def test_twin_matches_each_ban_action(tmp_path):
    ns = _load(tmp_path)
    t = ns['_f2b_docker_twin_item']
    for allports in ('ufw', 'infratak-ufw', 'iptables-allports', 'action   = infratak-ufw'):
        assert t(allports) == 'infratak-docker'
    assert t('iptables-multiport[name=takserver, port="8089,8443,8446,9000,9001", protocol=tcp]') == \
        'infratak-docker[name=takserver, dports="8089,8443,8446,9000,9001", dkproto=tcp]'
    assert t('         iptables-multiport[name=mediamtx-udp, port="8000,8001", protocol=udp]') == \
        'infratak-docker[name=mediamtx-udp, dports="8000,8001", dkproto=udp]'
    # not a ban action of ours: no twin
    for other in ('infratak-guarddog', 'infratak-guarddog-takserver', 'sendmail-whois',
                  'iptables-multiport[name=x, port="ssh", protocol=tcp]',
                  'iptables-multiport[name=x, port="22", protocol=icmp]',
                  'iptables-multiport[name=x;id, port="22", protocol=tcp]', ''):
        assert t(other) == '', other


def test_add_twins_puts_them_after_the_ban_actions_and_before_notify(tmp_path):
    ns = _load(tmp_path)
    add = ns['_f2b_add_docker_twins']
    out = add(AUTHENTIK)
    assert out.endswith("action   = infratak-ufw\n         infratak-docker\n         infratak-guarddog\n")
    out = add(MEDIA)
    assert ('protocol=udp]\n'
            '         infratak-docker[name=mediamtx-tcp, dports="1935,8322,8554,8555,8888,8889,8892", dkproto=tcp]\n'
            '         infratak-docker[name=mediamtx-udp, dports="8000,8001,8189,8890", dkproto=udp]\n'
            '         infratak-guarddog\n') in out
    out = add(TAK)
    assert 'protocol=tcp]\n         infratak-docker[name=takserver, dports="8089,8443,8446,9000,9001", dkproto=tcp]\n' \
           '         infratak-guarddog-takserver\n' in out
    assert add(RECIDIVE).endswith("action   = iptables-allports\n         infratak-docker\n")
    # everything else is untouched, and a second pass changes nothing
    for txt in (AUTHENTIK, MEDIA, TAK, RECIDIVE):
        once = add(txt)
        assert once.replace(''.join(l + '\n' for l in once.split('\n') if 'infratak-docker' in l), '') == txt
        assert add(once) == once


def test_writer_text_equals_migration_text(tmp_path):
    """A jail the writer makes and a jail the startup migration fixes read the same, so
    the console never sees a difference and rewrites/reloads on every start."""
    ns = _load(tmp_path)
    primary = 'iptables-multiport[name=takserver, port="8089,8443,8446,9000,9001", protocol=tcp]'
    written = f"action   = {primary}{ns['_f2b_docker_twin'](primary)}\n         infratak-guarddog-takserver\n"
    migrated = ns['_f2b_add_docker_twins'](f"action   = {primary}\n         infratak-guarddog-takserver\n")
    assert written == migrated


def test_never_names_the_action_when_its_file_cannot_be_written(tmp_path):
    """A jail naming an action with no file on disk stops the WHOLE fail2ban daemon."""
    ns = _load(tmp_path, have_dir=False)
    assert ns['_f2b_docker_twin']('infratak-ufw') == ''
    assert ns['_f2b_add_docker_twins'](AUTHENTIK) == AUTHENTIK


def test_action_file_written_once_and_kept(tmp_path):
    ns = _load(tmp_path)
    assert ns['_f2b_ensure_docker_action']() is True
    assert pathlib.Path(ns['_F2B_DOCKER_ACTION_PATH']).read_text() == ns['_F2B_DOCKER_ACTION_CONF']
    ns['_written'].clear()
    assert ns['_f2b_ensure_docker_action']() is True
    assert ns['_written'] == {}                      # same content: not rewritten


def _render(conf, **tags):
    """fail2ban-style: take [Definition] values, fill <tags> from [Init] + given."""
    sect, cur = {}, None
    for ln in conf.split('\n'):
        m = re.match(r'^\[(.+)\]$', ln)
        if m:
            cur = sect.setdefault(m.group(1), {})
            last = None
            continue
        if cur is None or ln.startswith('#') or not ln.strip():
            continue
        if ln[:1] in (' ', '\t') and last:
            cur[last] += '\n' + ln.strip()
            continue
        k, v = ln.split('=', 1)
        last = k.strip()
        cur[last] = v.strip()
    vals = dict(sect['Init'])
    vals.update(tags)

    def fill(s):
        for _ in range(5):
            s = re.sub(r'<(\w+)>', lambda m: vals.get(m.group(1), m.group(0)), s)
        return s
    return {k: fill(v) for k, v in sect['Definition'].items()}, sect


def test_action_rules(tmp_path):
    ns = _load(tmp_path)
    conf = ns['_F2B_DOCKER_ACTION_CONF']
    d, sect = _render(conf, name='takserver', ip='203.0.113.9')
    assert sect['Init?family=inet6']['ipt'] == 'ip6tables -w'
    assert d['actioncheck'] == ''
    ban = d['actionban']
    # the chain and the DOCKER-USER jump come back first, then the address is dropped
    assert ban.index('-N f2bd-takserver') < ban.index('-I f2bd-takserver 1 -s 203.0.113.9 -j DROP')
    assert 'iptables -w -I DOCKER-USER 1 -m conntrack --ctstate DNAT --ctdir ORIGINAL -j f2bd-takserver' in ban
    assert 'while iptables -w -D f2bd-takserver -s 203.0.113.9 -j DROP' in d['actionunban']
    assert '-X f2bd-takserver' in d['actionstop']
    for k in ('actionstart', 'actionstop', 'actionban', 'actionunban'):
        r = subprocess.run(['sh', '-n', '-c', d[k]], capture_output=True, text=True)
        assert r.returncode == 0, (k, r.stderr)
        assert not re.search(r'<\w+>', d[k]), (k, d[k])        # every tag is filled
    # a port-scoped jail jumps per port, on the original (published) destination port
    d2, _ = _render(conf, name='takserver', ip='203.0.113.9', dports='8089,8443', dkproto='tcp')
    assert '--ctorigdstport $p -j f2bd-takserver' in d2['actionban']
    assert 'echo "8089,8443"' in d2['actionban']
    # chain names fit iptables' 28-character limit for every jail name we allow
    assert len('f2bd-' + 'x' * 23) <= 28


def test_ban_runs_against_a_fake_iptables(tmp_path):
    """Run the rendered ban/unban/stop through sh with a fake iptables that keeps rules
    in a file, to prove the shell does what the comments say."""
    ns = _load(tmp_path)
    state = tmp_path / 'rules'
    state.write_text('-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n')
    fake = tmp_path / 'iptables'
    fake.write_text(r'''#!/bin/sh
S=%s
[ "$1" = -w ] && shift
op=$1; ch=$2; shift 2
case $op in
  -N) grep -qx -- "-N $ch" $S && exit 1; echo "-N $ch" >> $S;;
  -X) grep -vx -- "-N $ch" $S > $S.t; mv $S.t $S;;
  -F) grep -v -- "^-A $ch " $S > $S.t; mv $S.t $S;;
  -S) grep -qx -- "-N $ch" $S || exit 1; grep -- "^-A $ch " $S;;
  -C) grep -qx -- "-A $ch $*" $S;;
  -I) grep -qx -- "-N $ch" $S || exit 1; [ "$1" = 1 ] && shift; { echo "-A $ch $*"; cat $S; } > $S.t; mv $S.t $S;;
  -D) grep -qx -- "-A $ch $*" $S || exit 1; awk -v r="-A $ch $*" 'f||$0!=r{print;next}{f=1}' $S > $S.t; mv $S.t $S;;
esac
''' % state)
    fake.chmod(0o755)
    env = {'PATH': f'{tmp_path}:/usr/bin:/bin'}

    def run(cmd):
        r = subprocess.run(['sh', '-c', cmd], capture_output=True, text=True, env=env)
        return r.returncode

    conf = ns['_F2B_DOCKER_ACTION_CONF']
    d, _ = _render(conf, name='takserver', ip='203.0.113.9', dports='8089,8443', dkproto='tcp')
    assert run(d['actionban']) == 0
    rules = state.read_text()
    for p in ('8089', '8443'):
        assert (f'-A DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctdir ORIGINAL '
                f'--ctorigdstport {p} -j f2bd-takserver') in rules
    assert '-A f2bd-takserver -s 203.0.113.9 -j DROP' in rules
    assert run(d['actionban']) == 0                          # idempotent
    assert state.read_text() == rules
    d_b, _ = _render(conf, name='takserver', ip='198.51.100.7', dports='8089,8443', dkproto='tcp')
    assert run(d_b['actionban']) == 0
    assert run(d['actionunban']) == 0
    rules = state.read_text()
    assert '203.0.113.9' not in rules and '198.51.100.7' in rules
    assert run(d['actionstop']) == 0
    rules = state.read_text()
    assert 'f2bd-takserver' not in rules
    assert '-A DOCKER-USER -j RETURN' in rules                # Docker's own rule kept


# ── every jail writer and the startup migration ──────────────────────────────

def test_every_jail_writer_adds_the_docker_twin():
    """Red on the base branch: no jail action line covered Docker-published ports."""
    lines = [ln for ln in APP.splitlines() if re.search(r'f"action   = \{_f2b_banaction', ln)]
    assert len(lines) >= 11, lines
    for ln in lines:
        m = re.search(r'\{(_f2b_banaction\w*\(\))\}\{_f2b_docker_twin\((_f2b_banaction\w*\(\))\)\}', ln)
        assert m and m.group(1) == m.group(2), ln


def test_startup_migration_runs_after_the_ufw_lock_switch_and_restarts():
    calls = [n.value.func.id for n in TREE.body
             if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
             and isinstance(n.value.func, ast.Name)]
    assert '_startup_f2b_docker_twins' in calls
    assert calls.index('_startup_f2b_ufw_lock_switch') < calls.index('_startup_f2b_docker_twins')
    src = next(_seg(n) for n in TREE.body
               if isinstance(n, ast.FunctionDef) and n.name == '_startup_f2b_docker_twins')
    # waits while a jail is still on the stock unlocked ufw action (restart unbans through it)
    assert src.index('_f2b_stale_ufw_jails()') < src.index("'restart', 'fail2ban'")
    assert src.index('_f2b_ensure_docker_action()') < src.index('_write_priv(path, new)')


def _migration_ns(tmp_path, monkeypatch, files, settings, restart_rc=0, active='active'):
    """_startup_f2b_docker_twins against a fake box: jail files, settings, systemctl."""
    import types
    ns = _load(tmp_path)
    src = next(_seg(n) for n in TREE.body
               if isinstance(n, ast.FunctionDef) and n.name == '_startup_f2b_docker_twins')
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        if argv[:2] == ['systemctl', 'is-active']:
            return types.SimpleNamespace(returncode=0, stdout=active + '\n', stderr='')
        return types.SimpleNamespace(returncode=restart_rc, stdout='', stderr='')
    act_dir = ns['os'].path.isdir                      # the fake from _load
    import os as _os
    import time as _time
    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(isdir=act_dir, basename=_os.path.basename))
    glob_mod = types.ModuleType('glob')
    glob_mod.glob = lambda pat: sorted(files)
    import sys
    ns.update(os=fake_os, time=_time, subprocess=types.SimpleNamespace(run=run),
              _sudo_wrap=lambda a: a, _distro_family=lambda: 'debian',
              _f2b_stale_ufw_jails=lambda: [],
              _f2b_read_text=lambda p: files.get(p),
              load_settings=lambda: dict(settings),
              save_settings=lambda s: (settings.clear(), settings.update(s)))
    real_write = ns['_write_priv']
    ns['_write_priv'] = lambda p, t, **k: files.__setitem__(p, t) if p in files else real_write(p, t)
    exec(next(_seg(n) for n in TREE.body if isinstance(n, ast.Assign)
              and any(getattr(t, 'id', None) == '_F2B_DOCKER_FLAG' for t in n.targets)), ns)
    exec(src, ns)
    monkeypatch.setitem(sys.modules, 'glob', glob_mod)
    return ns, calls


RESTART = ['systemctl', 'restart', 'fail2ban']


def test_migration_restarts_once_even_when_a_writer_already_added_the_line(tmp_path, monkeypatch):
    """Box test, Nov 25: the ignoreip re-apply rewrote the jail (with the line) and only
    reloaded, so a migration keyed on its own diff skipped the restart and the current
    ban never reached the Docker ports."""
    j = '/etc/fail2ban/jail.d/infratak-authentik.conf'
    files = {j: AUTHENTIK.replace('infratak-ufw\n', 'infratak-ufw\n         infratak-docker\n')}
    settings = {}
    ns, calls = _migration_ns(tmp_path, monkeypatch, files, settings)
    ns['_startup_f2b_docker_twins']()
    assert calls.count(RESTART) == 1
    assert settings['f2b_docker_ports']['last_outcome'] == 'applied'
    calls.clear()
    ns['_startup_f2b_docker_twins']()                 # next console start: nothing to do
    assert RESTART not in calls


def test_migration_adds_the_line_and_retries_a_failed_restart(tmp_path, monkeypatch):
    j = '/etc/fail2ban/jail.d/infratak-authentik.conf'
    files = {j: AUTHENTIK}
    settings = {}
    ns, calls = _migration_ns(tmp_path, monkeypatch, files, settings, restart_rc=1)
    ns['_startup_f2b_docker_twins']()
    assert 'infratak-docker' in files[j] and calls.count(RESTART) == 1
    assert 'f2b_docker_ports' not in settings         # failed: the next start tries again
    ns2, calls2 = _migration_ns(tmp_path, monkeypatch, files, settings)
    ns2['_startup_f2b_docker_twins']()
    assert calls2.count(RESTART) == 1 and settings['f2b_docker_ports']['last_outcome'] == 'applied'
