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
"""A failed remote Authentik Update puts back the FULL tag the host was pinned to (ops #1359).

`authentik_control` (remote branch) reads the host's compose pin before it changes anything, so a
failed pull can restore it. The read used `cut -d- -f2`, which splits on every dash: a pin of
`2026.11.0-rc2` came back as `2026.11.0` and the restore wrote that into docker-compose.yml and .env.

app.py cannot be imported in a test, so `authentik_control` is cut out of it. Every command it sends
to the host runs in a REAL bash against a real ~/authentik folder (a temp HOME) with a stub `docker`,
because the shell pipeline is exactly the part a fake would hide.
"""

import ast
import os
import pathlib
import re
import stat
import subprocess
import sys
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = {
    '_ak_ver_tuple', '_ak_upgrade_hop', '_get_authentik_target_release', '_ak_tag_is_sane',
    '_ak_tags_from_text', '_ak_env_tag', 'authentik_control',
    'AUTHENTIK_VETTED_RELEASE', 'AUTHENTIK_DEV_RELEASE', 'AUTHENTIK_UPGRADE_STEPS',
}
# Present only once the remote downgrade check (ops #1322) is in the tree. Loaded when there, so this
# file passes on a branch with and without it, and on the base commit the OLD code still runs and the
# tests fail on what it does (restores a cut tag), not on a missing helper.
_NEW = {'_ak_remote_current_version', '_AK_REMOTE_READ_CMD', '_AK_REMOTE_TAG_RE'}


def _cut():
    parts = {}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES | _NEW:
            parts[node.name] = ast.get_source_segment(APP, node)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and \
                getattr(node.targets[0], 'id', None) in _NAMES | _NEW:
            parts[node.targets[0].id] = ast.get_source_segment(APP, node)
    missing = _NAMES - set(parts)
    assert not missing, 'missing from app.py: %s' % sorted(missing)
    return parts


PARTS = _cut()
VETTED = ast.literal_eval(next(n.value for n in TREE.body if isinstance(n, ast.Assign)
                               and getattr(n.targets[0], 'id', None) == 'AUTHENTIK_VETTED_RELEASE'))

# A stub `docker`: `compose config` prints the tag compose would use (.env pin wins over the compose
# default), `compose pull` fails when PULL_FAILS is set, `compose up/down` and `network` succeed and
# are logged, `ps` shows nothing running.
_DOCKER = r'''#!/bin/bash
echo "docker $*" >> "$HOME/docker.log"
case "$1 $2" in
  "compose config")
    tag=$(grep -E '^[[:space:]]*AUTHENTIK_TAG[[:space:]]*=' .env 2>/dev/null | tail -1 | sed 's/^[^=]*=//')
    [ -n "$tag" ] || tag=$(grep -oE 'AUTHENTIK_TAG:-[^}]+' docker-compose.yml | head -1 | sed 's/^AUTHENTIK_TAG:-//')
    echo "    image: ghcr.io/goauthentik/server:$tag" ;;
  "compose pull")
    if [ -f "$HOME/PULL_FAILS" ]; then echo "Error response from daemon: manifest unknown"; exit 1; fi
    echo done ;;
  *) : ;;
esac
exit 0
'''
# The console sends GNU `sed -i 's/.../'`. macOS sed needs `-i ''`; this shim lets the same text run
# on a developer Mac. On Linux (CI, the hosts) it just runs the real sed.
_SED = r'''#!/bin/bash
if [ "$1" = "-i" ] && [ "$(uname)" = "Darwin" ]; then shift; exec /usr/bin/sed -i '' "$@"; fi
exec /usr/bin/sed "$@"
'''


class RealHost(object):
    """A remote Authentik host: a temp HOME whose ~/authentik holds a real docker-compose.yml and
    .env, with the stub docker first on PATH. `probe` runs each command the console sends."""

    def __init__(self, tmp, compose_tag, env_tag=None, pull_fails=True):
        self.home = tmp
        ak = tmp / 'authentik'
        ak.mkdir()
        (ak / 'docker-compose.yml').write_text(
            'services:\n  server:\n    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:'
            '${AUTHENTIK_TAG:-%s}\n  worker:\n    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:'
            '${AUTHENTIK_TAG:-%s}\n' % (compose_tag, compose_tag))
        (ak / '.env').write_text('PG_PASS=x\n' + ('AUTHENTIK_TAG=%s\n' % env_tag if env_tag else ''))
        bindir = tmp / 'bin'
        bindir.mkdir()
        for name, text in (('docker', _DOCKER), ('sed', _SED)):
            p = bindir / name
            p.write_text(text)
            p.chmod(p.stat().st_mode | stat.S_IXUSR)
        if pull_fails:
            (tmp / 'PULL_FAILS').write_text('1')
        self.cmds = []

    def probe(self, host_cfg, cmd='echo ok', timeout=15):
        self.cmds.append(cmd)
        env = dict(os.environ, HOME=str(self.home), PATH='%s:/usr/bin:/bin' % (self.home / 'bin'))
        r = subprocess.run(['/bin/bash', '-c', cmd], env=env, capture_output=True, text=True, timeout=30)
        return r.returncode == 0, (r.stdout + r.stderr)

    def compose_pins(self):
        text = (self.home / 'authentik' / 'docker-compose.yml').read_text()
        return set(re.findall(r'AUTHENTIK_TAG:-([^}]+)\}', text))

    def env_pin(self):
        m = re.search(r'^AUTHENTIK_TAG=(.*)$', (self.home / 'authentik' / '.env').read_text(), re.M)
        return m.group(1) if m else None

    def docker_log(self):
        p = self.home / 'docker.log'
        return p.read_text() if p.exists() else ''


def run_update(host, dev_latest='2026.12.0'):
    # dev channel with a target newer than every pin used here, so the (ops #1322) downgrade check,
    # where it exists, lets the update go on to the pull that fails
    ns = {
        're': re,
        'time': types.SimpleNamespace(sleep=lambda s: None),
        'request': types.SimpleNamespace(json={'action': 'update'}),
        'jsonify': lambda d: d,
        'load_settings': lambda: {'update_channel': 'dev'},
        '_get_module_deployment_config': lambda s, k: {
            'target_mode': 'remote', 'deployed': True,
            'remote': {'host': '10.0.0.9', 'ssh_user': 'rocky'}},
        '_ssh_probe': host.probe,
        'INFRATAK_DOCKER_NETWORK': 'infratak',
        '_get_authentik_latest_release_tag': lambda use_cache=True: dev_latest,
        '_get_authentik_version_info': lambda: {'version': ''},
        '_authentik_remote_trusted_proxy_cidrs': lambda s: None,
        '_mod_result_step': lambda m, s: None,
        '_update_error_line': lambda t, limit=600: (t or '').strip()[-300:],
    }
    exec(compile('\n\n'.join(PARTS[n] for n in sorted(PARTS)), 'app.py', 'exec'), ns)
    rv = ns['authentik_control']()
    return rv if isinstance(rv, tuple) else (rv, 200)


# ── the bug: a pin with a dash is put back whole ──────────────────────────────

@pytest.mark.parametrize('pin', ['2026.11.0-rc2', '2026.8.7-distroless', '2026.11.0-rc2-distroless'])
def test_failed_pull_restores_the_full_dash_tag_in_compose_and_env(tmp_path, pin):
    host = RealHost(tmp_path, compose_tag=pin, env_tag=pin)
    body, status = run_update(host)
    assert status == 500, body
    assert 'pull/recreate failed' in body['error']
    assert 'the tag pin was restored to v%s ' % pin in body['error'], body['error']
    assert host.compose_pins() == {pin}
    assert host.env_pin() == pin


def test_failed_pull_restores_the_dash_tag_when_only_compose_has_it(tmp_path):
    host = RealHost(tmp_path, compose_tag='2026.11.0-rc2')
    body, status = run_update(host)
    assert status == 500
    assert host.compose_pins() == {'2026.11.0-rc2'}
    assert host.env_pin() is None                 # the restore never creates an .env pin


# ── unchanged: plain pins behave as before ────────────────────────────────────

@pytest.mark.parametrize('pin', ['2026.5.6', '2026.8.7'])
def test_plain_pin_is_restored_as_before(tmp_path, pin):
    host = RealHost(tmp_path, compose_tag=pin, env_tag=pin)
    body, status = run_update(host)
    assert status == 500
    assert 'the tag pin was restored to v%s ' % pin in body['error']
    assert host.compose_pins() == {pin} and host.env_pin() == pin


@pytest.mark.parametrize('pin', ['2026.8', '2026.2.3.1'])
def test_short_or_long_pin_is_restored_as_before_unless_refused_up_front(tmp_path, pin):
    # these shapes were restorable before; with the ops #1322 check in the tree a floating `2026.8` is
    # refused before anything changes instead, which is also safe
    host = RealHost(tmp_path, compose_tag=pin, env_tag=pin)
    body, status = run_update(host)
    assert status == 500
    if 'Nothing was changed' not in body['error']:
        assert 'the tag pin was restored to v%s ' % pin in body['error']
        assert host.compose_pins() == {pin} and host.env_pin() == pin


@pytest.mark.parametrize('pin', ['latest', 'v2026.8.7', '2026'])
def test_floating_or_odd_pin_is_still_not_restored(tmp_path, pin):
    host = RealHost(tmp_path, compose_tag=pin)
    body, status = run_update(host)
    assert status == 500
    assert ('could not be read, so it was not restored' in body['error']
            or 'Nothing was changed' in body['error'])


# ── the restore value goes into a shell: only a tag shape may pass ────────────

@pytest.mark.parametrize('bad', [
    '2026.8.7; touch /tmp/x', '2026.8.7-rc2&reboot', '2026.8.7/../x', "2026.8.7-rc'2",
    '2026.8.7 -rc2', '2026.8.7-', '2026.8.7-' + 'a' * 60, '-rc2', '2026.8.7-$(id)', '2026.8.7-`id`',
    '2026.8.7|id',
])
def test_unsafe_pin_text_is_never_written_back(tmp_path, bad):
    host = RealHost(tmp_path, compose_tag=bad)
    body, status = run_update(host)
    assert status == 500
    assert ('could not be read, so it was not restored' in body['error']
            or 'Nothing was changed' in body['error'])
    sent = [c for c in host.cmds if 'sed -i' in c and bad in c]
    assert sent == []                              # the odd text never reached a command
    assert not (tmp_path / 'x').exists()


def test_the_read_does_not_cut_at_a_dash():
    ctrl = PARTS['authentik_control']
    assert '| cut -d-' not in ctrl
