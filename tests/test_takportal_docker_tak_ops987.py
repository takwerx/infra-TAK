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
"""TAK Portal with a Docker TAK Server (ops #987, TAK-Portal PR 115).

Before: the broker refused every grant when /opt/tak is a symlink (Docker TAK), so a portal
that can drive the container had no sudo rule to do it with. Now a Docker TAK box gets a
grant of exactly `docker exec` into / `docker restart` of the one container `takserver`,
and only when the portal checkout ships Docker support. A portal without it, and every
native box, behave as before.
"""

import ast
import importlib.util
import os
import pathlib
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


@pytest.fixture()
def b(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('takwerx_broker_t987', REPO / 'broker' / 'takwerx_broker.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m._sudoers_safe_binaries = lambda name: {
        'cat': ['/usr/bin/cat'], 'tee': ['/usr/bin/tee'], 'setpriv': ['/usr/bin/setpriv'],
        'systemctl': ['/usr/bin/systemctl'], 'visudo': ['/usr/sbin/visudo'],
        'docker': ['/usr/bin/docker', '/bin/docker'],
    }.get(name, [])
    home = tmp_path / 'home'
    (home / 'TAK-Portal' / 'services').mkdir(parents=True)
    m._home = home
    fake_pw = types.SimpleNamespace(pw_uid=1000, pw_dir=str(home))
    monkeypatch.setattr(m.pwd, 'getpwnam', lambda n: fake_pw)
    return m


def _grant(text):
    return [l for l in text.splitlines() if l and not l.startswith('#')]


def _portal_with_docker(b):
    (b._home / 'TAK-Portal' / 'services' / 'takServerMode.service.js').write_text('module.exports = {};\n')


# ----------------------------------------------------------------------------- the grant
def test_docker_grant_is_exactly_exec_and_restart_of_one_container(b):
    t = b._takportal_sudoers_text(user='takwerx', variant='docker', helper=True)
    assert _grant(t) == [
        'Defaults:takwerx !requiretty',
        'takwerx ALL=(root) NOPASSWD: /usr/bin/docker exec -i takserver *',
        'takwerx ALL=(root) NOPASSWD: /usr/bin/docker exec -i -u tak takserver *',
        'takwerx ALL=(root) NOPASSWD: /usr/bin/docker restart takserver',
        'takwerx ALL=(root) NOPASSWD: /bin/docker exec -i takserver *',
        'takwerx ALL=(root) NOPASSWD: /bin/docker exec -i -u tak takserver *',
        'takwerx ALL=(root) NOPASSWD: /bin/docker restart takserver',
        'takwerx ALL=(root) NOPASSWD: /usr/local/libexec/tak-portal/marketplace-helper',
    ]


def test_docker_grant_gives_the_caller_nothing_before_the_container_name(b):
    # `docker exec` stops reading options at the container name. Everything a caller picks is
    # after it, so --privileged, -u root, -v and --env can never be added.
    body = '\n'.join(_grant(b._takportal_sudoers_text(user='takwerx', variant='docker')))
    for line in body.splitlines():
        if ' exec ' in line:
            assert line.endswith('takserver *'), line
    for bad in ('(ALL)', '(root) NOPASSWD: ALL', 'NOPASSWD: ALL', 'docker *', 'docker run', 'docker cp',
                'docker compose', 'systemctl', 'secure_path', '/usr/bin/cat', '/usr/bin/tee', '-u root'):
        assert bad not in body, bad
    assert 'marketplace-helper' not in body        # not granted until the helper is in place


def test_docker_grant_refused_without_a_root_owned_docker(b):
    orig = b._sudoers_safe_binaries
    b._sudoers_safe_binaries = lambda n: [] if n == 'docker' else orig(n)
    with pytest.raises(b.Denied):
        b._takportal_sudoers_text(user='takwerx', variant='docker')


def test_native_grant_is_unchanged(b):
    t = b._takportal_sudoers_text(user='takwerx', variant='hardened', helper=False)
    assert 'docker' not in t and 'ALL=(tak) NOPASSWD: ALL' in t and 'restart takserver' in t


# ------------------------------------------------------------------------- when it is offered
def test_docker_tak_with_a_portal_that_supports_it_is_supported(b, monkeypatch):
    monkeypatch.setattr(b, '_takportal_layout', lambda: 'docker')
    _portal_with_docker(b)
    assert b._takportal_sudoers_supported() == (True, '')
    assert b._takportal_decide()['variant'] == 'docker'


def test_docker_tak_with_an_older_portal_still_gets_no_grant(b, monkeypatch):
    monkeypatch.setattr(b, '_takportal_layout', lambda: 'docker')
    ok, why = b._takportal_sudoers_supported()          # no takServerMode.service.js
    assert ok is False and 'no Docker TAK Server support' in why
    with pytest.raises(b.Denied):
        b._check_takportal_sudoers({'action': 'install'})
    # status and remove stay allowed on a box that cannot receive a grant
    b._check_takportal_sudoers({'action': 'status'})
    b._check_takportal_sudoers({'action': 'remove'})


def test_docker_tak_needs_a_root_owned_docker_binary(b, monkeypatch):
    monkeypatch.setattr(b, '_takportal_layout', lambda: 'docker')
    _portal_with_docker(b)
    orig = b._sudoers_safe_binaries
    monkeypatch.setattr(b, '_sudoers_safe_binaries', lambda n: [] if n == 'docker' else orig(n))
    ok, why = b._takportal_sudoers_supported()
    assert ok is False and 'docker' in why


def test_docker_install_check_passes_and_builds_no_native_wrappers(b, monkeypatch):
    monkeypatch.setattr(b, '_takportal_layout', lambda: 'docker')
    _portal_with_docker(b)
    monkeypatch.setattr(b, '_takportal_wrapper_text',
                        lambda n: (_ for _ in ()).throw(AssertionError('wrapper built for Docker TAK')))
    b._check_takportal_sudoers({'action': 'install'})


def test_feature_file_is_not_followed_through_a_symlinked_checkout(b, tmp_path):
    real = tmp_path / 'elsewhere'
    (real / 'services').mkdir(parents=True)
    (real / 'services' / 'takServerMode.service.js').write_text('x')
    portal = b._home / 'TAK-Portal'
    for p in (portal / 'services').iterdir():
        p.unlink()
    (portal / 'services').rmdir()
    portal.rmdir()
    portal.symlink_to(real)
    assert b._takportal_portal_supports_docker() is False


def test_feature_file_must_be_a_regular_nonempty_file(b):
    f = b._home / 'TAK-Portal' / 'services' / 'takServerMode.service.js'
    assert b._takportal_portal_supports_docker() is False        # missing
    f.write_text('')
    assert b._takportal_portal_supports_docker() is False        # empty
    f.write_text('module.exports = {};\n')
    assert b._takportal_portal_supports_docker() is True
    f.unlink()
    f.symlink_to('/etc/hostname')
    assert b._takportal_portal_supports_docker() is False        # symlink


def test_native_box_still_needs_the_tak_user(b, monkeypatch):
    monkeypatch.setattr(b, '_takportal_layout', lambda: 'native')

    def _gone(name):
        if name == b.TAKPORTAL_TAK_USER:
            raise KeyError(name)
        return types.SimpleNamespace(pw_uid=1000, pw_dir=str(b._home))
    monkeypatch.setattr(b.pwd, 'getpwnam', _gone)
    ok, why = b._takportal_sudoers_supported()
    assert ok is False and 'no `tak` user' in why


def test_layout_reads_the_opt_tak_symlink(tmp_path):
    real = tmp_path / 'tak'
    real.mkdir()
    link = tmp_path / 'optlink'
    link.symlink_to(real)
    body = (REPO / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')
    fn = next(n for n in ast.parse(body).body if isinstance(n, ast.FunctionDef) and n.name == '_takportal_layout')
    code = ast.get_source_segment(body, fn)
    assert code.count("'/opt/tak'") == 2
    for path, want in ((real, 'native'), (link, 'docker'), (tmp_path / 'none', '')):
        ns = {'os': os}
        exec(compile(code.replace("'/opt/tak'", repr(str(path))), 'broker', 'exec'), ns)
        assert ns['_takportal_layout']() == want, path


# ------------------------------------------------------------------------------ console side
def _app_func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def test_probe_in_docker_mode_checks_through_the_container(monkeypatch, tmp_path):
    home = tmp_path / 'home'
    key = home / 'TAK-Portal' / 'data' / 'ssh'
    key.mkdir(parents=True)
    (key / 'tak_ssh_ed25519').write_text('k')
    monkeypatch.setenv('HOME', str(home))
    seen = {}

    def _run(args, **kw):
        seen['probe'] = args[-1]
        return types.SimpleNamespace(returncode=0, stdout='nopasswd\n', stderr='')
    for container, want_docker in ((True, True), (False, False)):
        ns = {'os': os, 'subprocess': types.SimpleNamespace(run=_run), '_tak_is_container': lambda c=container: c,
              'TAK_CONTAINER': 'takserver'}
        exec(compile(_app_func('_takportal_ssh_probe'), 'app.py', 'exec'), ns)
        assert ns['_takportal_ssh_probe']() == ('nopasswd', '')
        p = seen['probe']
        assert ('docker exec -i takserver cat /opt/tak/CoreConfig.xml' in p) is want_docker
        assert ('docker exec -i -u tak takserver id' in p) is want_docker
        if want_docker:
            assert '-r /opt/tak/CoreConfig.xml' not in p, 'a host read of the symlink proves nothing'
            assert 'echo direct' not in p
        else:
            assert 'echo direct' in p


def test_docker_keys_are_seed_only_and_only_for_container_tak():
    src = _app_func('_takportal_build_settings_dict')
    i = src.index('_built["TAK_SERVER_MODE"]')
    guard = src[:i].rsplit('\n', 2)[-2]
    assert 'tak_local and _tak_is_container()' in guard, guard
    assert '_built["TAK_DOCKER_CONTAINER"] = TAK_CONTAINER' in src
    auth = next(ast.get_source_segment(APP, n) for n in TREE.body
                if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == 'TAKPORTAL_AUTHORITATIVE_KEYS' for t in n.targets))
    for k in ('TAK_SERVER_MODE', 'TAK_DOCKER_CONTAINER', 'TAK_ENROLL_HOST'):
        assert k not in auth, f'{k} must stay seed-only (operator-owned after the first write)'
    assert '"TAK_ENROLL_HOST"' not in src, 'the external host is the operator\'s; infra-TAK does not guess it'


def test_setup_ssh_keeps_the_limitation_note_only_for_a_portal_without_docker_support():
    src = _app_func('_takportal_setup_ssh')
    i = src.index('_tak_is_container()')
    assert 'not _takportal_portal_supports_docker()' in src[i:i + 120]


def test_container_name_matches_the_fleet_constant():
    broker = (REPO / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')
    assert "TAKPORTAL_DOCKER_CONTAINER = 'takserver'" in broker
    assert "TAK_CONTAINER = 'takserver'" in APP
