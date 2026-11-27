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
"""The Authentik Update button on a REMOTE host never walks it back to an older version (ops #1322).

The local branch of `authentik_control` has refused a downgrade since v10.1.39 (409, "Refusing to
downgrade Authentik"). The remote branch had no such check: it set the tag with `sed` in
docker-compose.yml and .env, pulled, recreated, and only then looked at what ran. A remote host that
runs a newer Authentik than this channel's target (a hand update, a dev-channel box moved to main,
2026.11.0-rc2 against the vetted 2026.8.7) would be pointed at the older image. Authentik's database
migrations do not go back, so the older server may not start.

app.py cannot be imported in a test, so `authentik_control` and its helpers are cut out of it and
run against a fake remote host: the code under test is the shipped text. The read command also runs
in a real shell against a stub `docker`, because its quoting is the part a fake cannot check.
"""

import ast
import os
import pathlib
import re
import subprocess
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
# Added by the fix. Loaded only when the tree has them, so on the base commit the old
# `authentik_control` still runs and the tests fail on what it DOES (it pins and pulls a newer host
# back), not because a helper was missing and the loader stopped.
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
UPGRADE_STEP = ast.literal_eval(next(n.value for n in TREE.body if isinstance(n, ast.Assign)
                                 and getattr(n.targets[0], 'id', None) == 'AUTHENTIK_UPGRADE_STEPS'))[0]


class FakeRemote(object):
    """A remote Authentik host as Docker Compose sees it, driven only through the commands the
    console sends. `running` is the authentik-server image tag (None: stack stopped), `env` the
    active AUTHENTIK_TAG line value in .env (None: no pin), `compose` the `:-` default."""

    def __init__(self, running=None, env=None, compose=VETTED, env_state=None, ssh_down=False,
                 nodir=False, truncated=False, pull_fails=False, env_line=None):
        self.running, self.env, self.compose = running, env, compose
        self.env_state = env_state or ('ok' if env is not None else 'missing')
        self.ssh_down, self.nodir, self.truncated, self.pull_fails = ssh_down, nodir, truncated, pull_fails
        self.env_line = env_line            # replaces the whole `AUTHENTIK_TAG=...` line text
        self.cmds = []

    def effective(self):
        return self.env if self.env else self.compose

    def probe(self, host_cfg, cmd='echo ok', timeout=15):
        self.cmds.append(cmd)
        if self.ssh_down:
            return False, 'ssh: connect to host 10.0.0.9 port 22: Connection timed out'
        if 'AKREAD_' in cmd:
            if self.nodir:
                return True, 'Welcome banner\nAKREAD_NODIR'
            lines = ['Welcome banner, not ours']
            lines.append('AKREAD_RUN=' + ('ghcr.io/goauthentik/server:' + self.running if self.running else ''))
            lines.append('AKREAD_ENVSTATE=' + self.env_state)
            if self.env_state == 'ok':
                text = self.env_line if self.env_line is not None else (
                    'AUTHENTIK_TAG=' + self.env if self.env is not None else '')
                lines.append('AKREAD_ENV=' + text)
            lines.append('AKREAD_COMPOSE=AUTHENTIK_TAG:-' + self.compose)
            if not self.truncated:
                lines.append('AKREAD_DONE')
            return True, '\n'.join(lines)
        if 'docker network' in cmd:
            return True, ''
        if "grep -oE 'AUTHENTIK_TAG:-[^}]+' docker-compose.yml | head -1 | cut -d- -f2" in cmd:
            return True, ('AUTHENTIK_TAG:-' + self.compose).split('-')[1]       # what `cut -d- -f2` does
        if "sed -i 's/AUTHENTIK_TAG:-[^}]*/AUTHENTIK_TAG:-" in cmd and 'docker-compose.yml' in cmd:
            self.compose = re.search(r'AUTHENTIK_TAG:-([0-9][^/]*)/g', cmd).group(1)
            return True, ''
        # the console's f-string turns \t into a real tab, so the command carries tab characters
        if "sed -i 's/^[ \t]*AUTHENTIK_TAG[ \t]*=.*/AUTHENTIK_TAG=" in cmd and '.env' in cmd \
                and 'docker compose' not in cmd:
            if self.env is not None:
                self.env = re.search(r'/AUTHENTIK_TAG=([0-9][^/]*)/', cmd).group(1)
            return True, ''
        if 'docker compose config' in cmd:
            return True, 'image: ghcr.io/goauthentik/server:' + self.effective()
        if 'docker compose pull' in cmd:
            if self.pull_fails:
                return False, 'Error response from daemon: manifest unknown'
            self.running = self.effective()
            return True, 'done'
        if 'docker ps --filter name=authentik-server' in cmd:
            return True, ('ghcr.io/goauthentik/server:' + self.running) if self.running else ''
        return True, ''

    def mutations(self):
        """Every command that changes the host: a tag rewrite, a pull, a recreate."""
        return [c for c in self.cmds if 'sed -i' in c or 'docker compose pull' in c
                or 'docker compose up' in c or 'docker compose down' in c]


def run_update(fake, channel='main', dev_latest=None):
    steps = []
    ns = {
        're': re,
        'time': types.SimpleNamespace(sleep=lambda s: None),
        'request': types.SimpleNamespace(json={'action': 'update'}),
        'jsonify': lambda d: d,
        'load_settings': lambda: {'update_channel': channel},
        '_get_module_deployment_config': lambda s, k: {
            'target_mode': 'remote', 'deployed': True,
            'remote': {'host': '10.0.0.9', 'ssh_user': 'rocky'}},
        '_ssh_probe': fake.probe,
        'INFRATAK_DOCKER_NETWORK': 'infratak',
        '_get_authentik_latest_release_tag': lambda use_cache=True: dev_latest,
        '_get_authentik_version_info': lambda: {'version': fake.running or ''},
        '_authentik_remote_trusted_proxy_cidrs': lambda s: None,
        '_mod_result_step': lambda m, s: steps.append(s),
        '_update_error_line': lambda t, limit=600: (t or '').strip()[-300:],   # only on a failed pull
    }
    exec(compile('\n\n'.join(PARTS[n] for n in sorted(PARTS)), 'app.py', 'exec'), ns)
    rv = ns['authentik_control']()
    if isinstance(rv, tuple):
        return rv[0], rv[1], steps
    return rv, 200, steps


# ── the bug: a remote host that is NEWER than the target ──────────────────────

@pytest.mark.parametrize('running', ['2026.11.0-rc2', '2026.8.8', '2026.9.1', '2027.2.0'])
def test_newer_running_remote_is_refused_and_nothing_is_changed(running):
    fake = FakeRemote(running=running, compose=running)
    body, status, _ = run_update(fake)
    assert status == 409, body
    assert 'Refusing to downgrade Authentik' in body['error']
    assert running in body['error'] and VETTED in body['error']
    assert 'Nothing was changed' in body['error']
    assert fake.mutations() == []                # no sed, no pull, no recreate


def test_newer_running_remote_with_an_env_pin_is_refused():
    fake = FakeRemote(running='2026.11.0-rc2', env='2026.11.0-rc2', compose='2026.11.0-rc2')
    body, status, _ = run_update(fake)
    assert status == 409 and fake.mutations() == []
    assert fake.env == '2026.11.0-rc2' and fake.running == '2026.11.0-rc2'


def test_the_check_runs_before_the_first_write():
    fake = FakeRemote(running='2026.11.0-rc2', compose='2026.11.0-rc2')
    run_update(fake)
    assert any('AKREAD_' in c for c in fake.cmds)
    ctrl = PARTS['authentik_control']
    assert ctrl.index('_ak_remote_current_version(remote)') < ctrl.index(
        "sed -i 's/AUTHENTIK_TAG:-[^}}]*/AUTHENTIK_TAG:-{latest}/g'")


# ── a stopped stack: what compose would start decides ─────────────────────────

def test_stopped_stack_with_a_newer_env_pin_is_refused():
    fake = FakeRemote(running=None, env='2026.11.0-rc2', compose=VETTED)
    body, status, _ = run_update(fake)
    assert status == 409 and fake.mutations() == []
    assert '.env pin' in body['error']


def test_stopped_stack_with_a_newer_compose_default_is_refused():
    fake = FakeRemote(running=None, env=None, compose='2026.11.0-rc2')
    body, status, _ = run_update(fake)
    assert status == 409 and fake.mutations() == []
    assert 'compose file pin' in body['error']


def test_stopped_stack_env_pin_overrides_a_newer_compose_default():
    # compose resolves the .env value, so an older .env pin is what would start: update goes on
    fake = FakeRemote(running=None, env='2026.8.4', compose='2026.11.0-rc2')
    body, status, _ = run_update(fake)
    assert status == 200 and body.get('success'), body


def test_stopped_stack_whose_env_cannot_be_read_is_refused():
    fake = FakeRemote(running=None, env='2026.8.4', compose=VETTED, env_state='unreadable')
    body, status, _ = run_update(fake)
    assert status == 500 and fake.mutations() == []
    assert 'cannot be read' in body['error'] and 'Nothing was changed' in body['error']


# ── never guess ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize('fake', [
    FakeRemote(running='latest', compose='latest'),
    FakeRemote(running='2026.8', compose=VETTED),
    FakeRemote(running=None, env='latest', compose=VETTED),
    FakeRemote(running=None, env=None, compose='2026.8'),
    FakeRemote(ssh_down=True),
    FakeRemote(nodir=True),
    FakeRemote(running=VETTED, truncated=True),
], ids=['running-latest', 'running-family-tag', 'env-latest', 'compose-family-tag',
        'ssh-down', 'no-folder', 'output-cut-short'])
def test_a_host_that_cannot_be_read_is_refused_not_guessed(fake):
    body, status, _ = run_update(fake)
    assert status == 500, body
    assert body['error'].startswith('Refusing to update 10.0.0.9')
    assert 'Nothing was changed' in body['error']
    assert fake.mutations() == []


def test_an_empty_env_value_is_no_pin_and_the_compose_default_is_read():
    fake = FakeRemote(running=None, env='', compose=VETTED, env_line='AUTHENTIK_TAG=')
    body, status, _ = run_update(fake)
    assert status == 200 and body.get('success'), body


def test_floating_tag_message_says_what_to_do():
    body, status, _ = run_update(FakeRemote(running='latest', compose='latest'))
    assert status == 500
    assert 'not a version number' in body['error'] and 'really running' in body['error']


def test_errors_never_use_the_codes_the_page_reads_as_still_running():
    # authentik.html treats 502 and 504 as "update still running": a refusal must show as red text
    for fake in (FakeRemote(running='2026.11.0-rc2'), FakeRemote(ssh_down=True),
                 FakeRemote(running='latest')):
        _, status, _ = run_update(fake)
        assert status in (409, 500)


# ── a normal update still works, and old boxes still get their hop ────────────

@pytest.mark.parametrize('running,expect', [
    ('2026.8.4', VETTED),
    ('2026.8.6', VETTED),
    (VETTED, VETTED),                      # equal: nothing to refuse
    ('2026.8.7-rc1', VETTED),              # a release candidate of the same version is not newer
    ('2026.5.7', VETTED),                  # 2026.5 to 2026.8 is one family: straight to the target
    ('2026.2.2', UPGRADE_STEP),            # old box: the next safe step first, as before
])
def test_a_normal_update_still_pins_pulls_and_confirms(running, expect):
    fake = FakeRemote(running=running, env=running if running == '2026.8.4' else None, compose=running)
    body, status, steps = run_update(fake)
    assert status == 200 and body.get('success') and body.get('version') == expect, body
    assert fake.running == expect and fake.compose == expect
    assert any('docker compose pull' in c for c in fake.cmds)
    assert 'read the version on the remote host (remote)' in steps


def test_half_finished_update_can_be_retried_the_running_tag_decides():
    # an earlier update wrote the new pin, then the console restarted before the pull: the old
    # container still runs. Update must be able to put the box back on the target.
    fake = FakeRemote(running='2026.8.4', env='2026.11.0-rc2', compose='2026.11.0-rc2')
    body, status, _ = run_update(fake)
    assert status == 200 and body.get('success'), body
    assert fake.running == VETTED and fake.env == VETTED


@pytest.mark.parametrize('line,tag', [
    ('AUTHENTIK_TAG=2026.8.4 # kept for the migration', '2026.8.4'),
    ('AUTHENTIK_TAG="v2026.8.4"', '2026.8.4'),
    ("  AUTHENTIK_TAG = '2026.8.4'", '2026.8.4'),
])
def test_env_line_spellings_are_read(line, tag):
    fake = FakeRemote(running=None, env=tag, compose=VETTED, env_line=line)
    body, status, _ = run_update(fake)
    assert status == 200 and body.get('success'), body


def test_dev_channel_release_candidate_moves_to_its_final_release():
    fake = FakeRemote(running='2026.11.0-rc2', compose='2026.11.0-rc2')
    body, status, _ = run_update(fake, channel='dev', dev_latest='2026.11.0')
    assert status == 200 and body.get('success') and body['version'] == '2026.11.0', body


def test_dev_channel_box_ahead_of_upstream_latest_is_refused():
    fake = FakeRemote(running='2026.11.1', compose='2026.11.1')
    body, status, _ = run_update(fake, channel='dev', dev_latest='2026.8.7')
    assert status == 409 and fake.mutations() == [], body


# ── the read command is read-only and works in a real shell ──────────────────

def test_the_read_command_changes_nothing():
    cmd = PARTS['_AK_REMOTE_READ_CMD']
    for word in ('sed', 'rm ', 'mv ', 'tee', 'docker compose', 'restart', 'pull', 'sudo', 'chmod'):
        assert word not in cmd, word
    assert '>' not in cmd.replace('2>/dev/null', '')
    assert '[[:space:]]' in cmd and '[ \\t]' not in cmd      # \t inside a grep bracket is not a tab


def _real_shell(tmp_path, running, env_text=None, compose_tag=VETTED, env_mode=0o600):
    home = tmp_path / 'home'
    ak = home / 'authentik'
    ak.mkdir(parents=True)
    (ak / 'docker-compose.yml').write_text(
        'services:\n  server:\n    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:'
        '${AUTHENTIK_TAG:-%s}\n' % compose_tag)
    if env_text is not None:
        (ak / '.env').write_text(env_text)
        os.chmod(str(ak / '.env'), env_mode)
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    stub = bin_dir / 'docker'
    stub.write_text('#!/bin/sh\n[ "$1" = ps ] && echo "%s"\nexit 0\n' % (
        ('ghcr.io/goauthentik/server:' + running) if running else ''))
    os.chmod(str(stub), 0o755)

    def probe(host_cfg, cmd='echo ok', timeout=15):
        r = subprocess.run(['/bin/sh', '-c', cmd], capture_output=True, text=True, timeout=30,
                           env={'HOME': str(home), 'PATH': str(bin_dir) + ':/usr/bin:/bin'})
        return r.returncode == 0, (r.stdout or '').strip()
    ns = {'re': re, '_ssh_probe': probe}
    exec(compile('\n\n'.join(PARTS[n] for n in ('_AK_REMOTE_READ_CMD', '_AK_REMOTE_TAG_RE',
                                                '_ak_env_tag', '_ak_remote_current_version')),
                 'app.py', 'exec'), ns)
    return ns['_ak_remote_current_version']({'host': '10.0.0.9'})


def test_real_shell_reads_the_running_image(tmp_path):
    cur = _real_shell(tmp_path, running='2026.11.0-rc2', env_text='PG_PASS=x\nAUTHENTIK_TAG=2026.8.4\n')
    assert cur['ok'] and cur['tag'] == '2026.11.0-rc2' and cur['tuple'] == (2026, 11, 0)
    assert cur['what'] == 'the running server image'


def test_real_shell_reads_the_env_pin_of_a_stopped_stack(tmp_path):
    cur = _real_shell(tmp_path, running=None,
                      env_text='PG_PASS=x\n# AUTHENTIK_TAG=2020.1.1\n\tAUTHENTIK_TAG=2026.11.0-rc2\n')
    assert cur['ok'] and cur['tag'] == '2026.11.0-rc2' and cur['what'] == 'the .env pin'


def test_real_shell_falls_back_to_the_compose_pin(tmp_path):
    cur = _real_shell(tmp_path, running=None, env_text='PG_PASS=x\n', compose_tag='2026.5.9')
    assert cur['ok'] and cur['tag'] == '2026.5.9' and cur['what'] == 'the compose file pin'


@pytest.mark.skipif(hasattr(os, 'geteuid') and os.geteuid() == 0, reason='root reads any file')
def test_real_shell_reports_an_unreadable_env_of_a_stopped_stack(tmp_path):
    cur = _real_shell(tmp_path, running=None, env_text='AUTHENTIK_TAG=2026.11.0\n', env_mode=0o000)
    assert not cur['ok'] and 'cannot be read' in cur['error']


def test_a_missing_folder_is_an_error():
    ns = {'re': re, '_ssh_probe': lambda h, c='', timeout=15: (True, 'AKREAD_NODIR')}
    exec(compile('\n\n'.join(PARTS[n] for n in ('_AK_REMOTE_READ_CMD', '_AK_REMOTE_TAG_RE',
                                                '_ak_env_tag', '_ak_remote_current_version')),
                 'app.py', 'exec'), ns)
    cur = ns['_ak_remote_current_version']({'host': 'h'})
    assert not cur['ok'] and 'no ~/authentik folder' in cur['error']
