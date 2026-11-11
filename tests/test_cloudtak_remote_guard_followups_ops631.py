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
"""ops #631 follow-ups for a remote CloudTAK.

1. The DOCKER-USER port guard removes its own jumps for ports that left its list, so a
   remote CloudTAK whose domain is removed gets 5000/5002 back for browsers (and a changed
   WebODM port does not stay locked). Update config re-applies the guard, so a domain change
   reaches the remote host.
2. A remote CloudTAK Update no longer moves media 9997 to 127.0.0.1 on the remote host.
   Caddy on the console proxies video to <remote>:9997; the guard limits 9997 to the console.
   A box an older Update left on 127.0.0.1 is put right on console start.
The guard script and the shell commands run for real (fake iptables / docker); the wiring is
checked on the source.
"""

import ast
import base64
import ipaddress
import os
import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

UPSTREAM_MEDIA = '      - "${MEDIA_PORT_API:-9997}:9997"\n'
LOOPBACK_MEDIA = '      - "127.0.0.1:${MEDIA_PORT_API:-9997}:9997"\n'


def _func_src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') == name:
            ns = {}
            exec(ast.get_source_segment(APP, node), ns)
            return ns[name]
    raise AssertionError(f'{name} not found in app.py')


def _guard_script(name, ports, ips):
    ns = {'re': re, 'ipaddress': ipaddress}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == '_docker_port_guard_files':
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') == '_PORT_GUARD_NAME_RE':
            exec(ast.get_source_segment(APP, node), ns)
    return ns['_docker_port_guard_files'](name, ports, ips)[0]


# A fake iptables that keeps DOCKER-USER as a list of `-A DOCKER-USER <spec>` lines, the way
# `iptables -S` prints them, and supports -C / -I / -D on it. Other chains are accepted.
_FAKE_IPTABLES = r'''#!/bin/sh
[ "$1" = "-w" ] && shift
op="$1"; chain="$2"; shift 2
touch "$STATE"
if [ "$chain" != "DOCKER-USER" ]; then exit 0; fi
spec="$*"
case "$op" in
  -S) echo "-N DOCKER-USER"; cat "$STATE";;
  -C) grep -qxF -- "-A DOCKER-USER $spec" "$STATE";;
  -I) { echo "-A DOCKER-USER $spec"; cat "$STATE"; } > "$STATE.new" && mv "$STATE.new" "$STATE";;
  -D) awk -v l="-A DOCKER-USER $spec" '!d && $0 == l { d = 1; next } { print }' "$STATE" > "$STATE.new" \
        && cmp -s "$STATE" "$STATE.new" && exit 1; mv "$STATE.new" "$STATE";;
  -N) exit 0;;
esac
'''


@pytest.fixture
def fake_iptables(tmp_path):
    fake = tmp_path / 'bin' / 'iptables'
    fake.parent.mkdir()
    fake.write_text(_FAKE_IPTABLES)
    fake.chmod(0o755)
    state = tmp_path / 'docker-user'
    env = {**os.environ, 'PATH': f'{fake.parent}:/usr/bin:/bin', 'STATE': str(state)}

    def run(name, ports):
        script = tmp_path / f'guard-{name}.sh'
        script.write_text(_guard_script(name, ports, ['203.0.113.10']))
        r = subprocess.run(['sh', str(script)], env=env, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return state.read_text().splitlines()
    return run


def _jumps(rules, chain):
    return sorted(int(re.search(r'--ctorigdstport (\d+)', r).group(1))
                  for r in rules if r.endswith(f'-j {chain}'))


def test_guard_removes_jumps_for_ports_no_longer_on_its_list(fake_iptables):
    # Domain set: 5000/5002 locked with the rest.
    assert _jumps(fake_iptables('cloudtak', [5000, 5002, 9000, 9997]), 'INFRATAK-CLOUDTAK') == [5000, 5002, 9000, 9997]
    # Domain removed: the browser goes to 5000/5002 directly, so their jumps must go.
    assert _jumps(fake_iptables('cloudtak', [9000, 9997]), 'INFRATAK-CLOUDTAK') == [9000, 9997]
    # Domain set again: locked again, once each.
    assert _jumps(fake_iptables('cloudtak', [5000, 5002, 9000, 9997]), 'INFRATAK-CLOUDTAK') == [5000, 5002, 9000, 9997]


def test_guard_never_touches_another_guards_jumps(fake_iptables):
    fake_iptables('authentik', [9090, 389, 636])
    fake_iptables('cloudtak', [5000, 9000])
    rules = fake_iptables('cloudtak', [9000])
    assert _jumps(rules, 'INFRATAK-AUTHENTIK') == [389, 636, 9090]
    assert _jumps(rules, 'INFRATAK-CLOUDTAK') == [9000]


def test_guard_rerun_with_the_same_ports_changes_nothing(fake_iptables):
    first = fake_iptables('webodm', [8000])
    assert fake_iptables('webodm', [8000]) == first == [
        '-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8000 --ctdir ORIGINAL -j INFRATAK-WEBODM']


def test_changed_webodm_port_unlocks_the_old_one(fake_iptables):
    fake_iptables('webodm', [8000])
    assert _jumps(fake_iptables('webodm', [8010]), 'INFRATAK-WEBODM') == [8010]


def test_update_config_reapplies_the_cloudtak_guard_before_compose_up():
    src = _func_src('run_cloudtak_redeploy')
    remote = src[:src.index("cloudtak_dir = os.path.expanduser('~/CloudTAK')")]
    assert '_remote_cloudtak_port_guard(cfg, settings, log_fn=plog)' in remote
    assert remote.index('_remote_cloudtak_port_guard(') < remote.index('docker compose up -d')


# ── 2. remote video port 9997 ────────────────────────────────────────────────

pytestmark_perl = pytest.mark.skipif(shutil.which('perl') is None, reason='perl not installed')


def _run_on_fake_remote(tmp_path, cmd, compose_text, docker_ok=True):
    home = tmp_path / 'home'
    (home / 'CloudTAK').mkdir(parents=True)
    compose = home / 'CloudTAK' / 'docker-compose.yml'
    compose.write_text('services:\n  media:\n    ports:\n' + compose_text)
    bin_dir = tmp_path / 'fakebin'
    bin_dir.mkdir()
    (bin_dir / 'docker').write_text(f'#!/bin/sh\necho "$*" >> "{tmp_path}/docker.log"\nexit {0 if docker_ok else 1}\n')
    (bin_dir / 'docker').chmod(0o755)
    env = {**os.environ, 'HOME': str(home), 'PATH': f'{bin_dir}:/usr/bin:/bin'}
    r = subprocess.run(['sh', '-c', cmd], env=env, capture_output=True, text=True)
    log = tmp_path / 'docker.log'
    return r, compose.read_text(), (log.read_text() if log.exists() else '')


@pytestmark_perl
@pytest.mark.parametrize('before', [UPSTREAM_MEDIA, LOOPBACK_MEDIA])
def test_remote_update_keeps_video_9997_published_for_caddy(tmp_path, before):
    r, after, _ = _run_on_fake_remote(tmp_path, _const('_CLOUDTAK_REMOTE_MEDIA_PERL'), before)
    assert r.returncode == 0, r.stderr
    assert after.endswith(UPSTREAM_MEDIA), after
    assert '127.0.0.1' not in after


def test_caddy_proxies_remote_video_to_the_remote_host():
    """The reason 9997 must stay published on the remote host."""
    src = _func_src('_get_cloudtak_upstreams')
    assert "'video_api': f'{host}:9997'" in src


def test_remote_update_reapplies_the_guard_and_no_longer_moves_9997_to_loopback():
    src = _func_src('run_cloudtak_update')
    remote = src[src.index('if is_remote:\n            # The loopback move'):]
    remote = remote[:remote.index('        else:')]
    assert '_ssh_probe(remote_cfg, _CLOUDTAK_REMOTE_MEDIA_PERL' in remote
    assert '_remote_cloudtak_port_guard(cfg, settings, log_fn=plog)' in remote
    assert 'loopback hardening' not in remote


def _heal_cmd():
    """The command _cloudtak_remote_media_publish_heal sends, captured from a fake _ssh_probe."""
    sent = []
    ns = {'_CLOUDTAK_REMOTE_MEDIA_PERL': _const('_CLOUDTAK_REMOTE_MEDIA_PERL'),
          '_ssh_probe': lambda cfg, cmd, timeout=0: sent.append(cmd) or (True, 'SAME'),
          '_cloudtak_media_hls_heal': lambda **k: True}
    exec(_func_src('_cloudtak_remote_media_publish_heal'), ns)
    assert ns['_cloudtak_remote_media_publish_heal']({'host': 'r'}) == 'same'
    return sent[0], ns


@pytestmark_perl
def test_heal_publishes_9997_again_and_recreates_only_media(tmp_path):
    cmd, _ = _heal_cmd()
    r, after, docker = _run_on_fake_remote(tmp_path, cmd, LOOPBACK_MEDIA)
    assert 'HEALED' in r.stdout, r.stdout + r.stderr
    assert after.endswith(UPSTREAM_MEDIA)
    assert docker.strip() == 'compose up -d --no-deps media'


@pytestmark_perl
def test_heal_is_a_noop_on_a_right_box(tmp_path):
    cmd, _ = _heal_cmd()
    r, after, docker = _run_on_fake_remote(tmp_path, cmd, UPSTREAM_MEDIA)
    assert 'SAME' in r.stdout and after.endswith(UPSTREAM_MEDIA) and docker == ''


def test_heal_reports_each_outcome():
    _, ns = _heal_cmd()
    heal = ns['_cloudtak_remote_media_publish_heal']
    for out, want in (('HEALED', 'healed'), ('NOCT', 'same'), ('FAILED', 'failed')):
        ns['_ssh_probe'] = lambda cfg, cmd, timeout=0, _o=out: (True, _o)
        assert heal({'host': 'r'}) == want


def test_startup_heals_9997_only_after_the_cloudtak_guard_is_in_place():
    src = _func_src('_startup_guard_remote_authentik_cloudtak_ports')
    heal = src.index('_cloudtak_remote_media_publish_heal(')
    assert src.index('ok, first = _guard(') < heal
    assert "if ok and _key == 'cloudtak_deployment':" in src[:heal]
