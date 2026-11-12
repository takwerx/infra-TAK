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
"""ops #644: TAK Portal's SSH key is limited to its own network, and the legacy grant is gone.

The portal key's line in the console user's authorized_keys is now
`restrict,pty,from="127.0.0.1,::1,<TAK Portal's Docker networks>"`, older `tak-portal-auto`
lines are dropped, a console-start heal fixes boxes that already trust the key, and every
box gets the hardened grant.
"""

import ast
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import tempfile
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

PORTAL_PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPortalCurrentKeyBlob0000000000000000000000 tak-portal-auto'
OLD_PORTAL = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldRootEraPortalKeyBlob00000000000000000 tak-portal-auto'
OPERATOR = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOperatorKeyBlob000000000000000000000000000 ops@laptop'
OPERATOR_OPTS = 'from="10.0.0.0/8, 192.168.1.5",command="echo hi there" ' + OPERATOR.replace('ops@laptop', 'with opts')
NETS = ['172.19.0.0/16', '172.22.0.0/16']


def _func(name):
    for n in ast.walk(TREE):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} is missing from app.py')


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} is missing from app.py')


def _load(*names, consts=(), **extra):
    ns = {'os': os, 're': re, 'json': json, 'ipaddress': ipaddress, 'tempfile': tempfile}
    ns.update(extra)
    src = '\n\n'.join([_const(c) for c in consts] + [_func(n) for n in names])
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


@pytest.fixture()
def kt():
    return _load('_authorized_keys_split', '_takportal_ssh_key_options', '_takportal_authorized_keys_text',
                 consts=('TAKPORTAL_SSH_KEY_COMMENT', '_AUTHKEY_TYPE_RE'))


def _lines_for(text, blob_line):
    blob = blob_line.split()[1]
    return [l for l in text.splitlines() if blob in l]


# ------------------------------------------------------------ the deploy path writes options
def test_setup_ssh_writes_a_restricted_line_not_a_bare_key(monkeypatch, tmp_path):
    """The real _takportal_setup_ssh + the real key writer. On dev this appended the bare key."""
    home = tmp_path / 'home'
    key_dir = home / 'TAK-Portal' / 'data' / 'ssh'
    key_dir.mkdir(parents=True)
    (key_dir / 'tak_ssh_ed25519').write_text('priv')
    (key_dir / 'tak_ssh_ed25519.pub').write_text(PORTAL_PUB + '\n')
    (home / '.ssh').mkdir()
    (home / '.ssh' / 'authorized_keys').write_text(OPERATOR + '\n')
    monkeypatch.setenv('HOME', str(home))
    real_isdir = os.path.isdir
    monkeypatch.setattr(os.path, 'isdir', lambda p: p == '/opt/tak' or real_isdir(p))
    names = ['_takportal_setup_ssh']
    try:
        _func('_takportal_trust_portal_key')
        names = ['_authorized_keys_split', '_takportal_ssh_key_options', '_takportal_authorized_keys_text',
                 '_takportal_trust_portal_key'] + names
        consts = ('TAKPORTAL_SSH_KEY_COMMENT', '_AUTHKEY_TYPE_RE', 'TAKPORTAL_CONTAINER_TAK_NOTE')
    except AssertionError:
        consts = ('TAKPORTAL_CONTAINER_TAK_NOTE',)
    ns = _load(*names, consts=consts,
               subprocess=types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout='', stderr='')),
               _takportal_ssh_from_sources=lambda: list(NETS),
               _takportal_ref=lambda: 'tak-portal', _sudo_wrap=lambda c: c,
               _takportal_push_settings=lambda restart=False: None,
               _takportal_install_sudoers=lambda log_fn=None: (True, 'skipped'),
               _takportal_install_caddy_validate_shim=lambda log_fn=None: 'skipped',
               _takportal_ssh_probe=lambda: ('nopasswd', ''), _tak_is_container=lambda: False)
    log = []
    assert ns['_takportal_setup_ssh'](log_fn=log.append) is True
    ak = (home / '.ssh' / 'authorized_keys')
    text = ak.read_text()
    portal = _lines_for(text, PORTAL_PUB)
    assert portal == ['restrict,pty,from="127.0.0.1,::1,172.19.0.0/16,172.22.0.0/16" ' + PORTAL_PUB], text
    assert OPERATOR in text.splitlines()
    assert oct(ak.stat().st_mode & 0o777) == '0o600'


# ---------------------------------------------------------------------- the line rewrite
def test_bare_portal_line_is_restricted_in_place_and_others_kept(kt):
    existing = f'{OPERATOR}\n\n{PORTAL_PUB}\n# a comment\n{OPERATOR_OPTS}\n'
    text, changed, removed = kt['_takportal_authorized_keys_text'](existing, PORTAL_PUB, NETS)
    assert changed and removed == 0
    lines = text.splitlines()
    assert lines[0] == OPERATOR and lines[1] == '' and lines[3] == '# a comment' and lines[4] == OPERATOR_OPTS
    assert lines[2] == 'restrict,pty,from="127.0.0.1,::1,172.19.0.0/16,172.22.0.0/16" ' + PORTAL_PUB


def test_rewrite_is_idempotent(kt):
    once, _, _ = kt['_takportal_authorized_keys_text'](f'{PORTAL_PUB}\n', PORTAL_PUB, NETS)
    twice, changed, _ = kt['_takportal_authorized_keys_text'](once, PORTAL_PUB, NETS)
    assert twice == once and changed is False


def test_from_is_refreshed_when_docker_networks_change(kt):
    once, _, _ = kt['_takportal_authorized_keys_text'](f'{PORTAL_PUB}\n', PORTAL_PUB, NETS)
    new, changed, _ = kt['_takportal_authorized_keys_text'](once, PORTAL_PUB, ['172.30.0.0/16'])
    assert changed and _lines_for(new, PORTAL_PUB) == ['restrict,pty,from="127.0.0.1,::1,172.30.0.0/16" ' + PORTAL_PUB]


def test_older_portal_keys_and_duplicates_are_dropped(kt):
    existing = f'{OLD_PORTAL}\n{PORTAL_PUB}\n{OPERATOR}\n{PORTAL_PUB}\n'
    text, changed, removed = kt['_takportal_authorized_keys_text'](existing, PORTAL_PUB, NETS)
    assert changed and removed == 2
    assert OLD_PORTAL.split()[1] not in text
    assert len(_lines_for(text, PORTAL_PUB)) == 1 and OPERATOR in text.splitlines()


def test_missing_key_is_added_once(kt):
    text, changed, _ = kt['_takportal_authorized_keys_text'](f'{OPERATOR}\n\n\n', PORTAL_PUB, NETS)
    assert changed and text == f'{OPERATOR}\nrestrict,pty,from="127.0.0.1,::1,172.19.0.0/16,172.22.0.0/16" {PORTAL_PUB}\n'
    text, _, _ = kt['_takportal_authorized_keys_text']('', PORTAL_PUB, NETS)
    assert text.startswith('restrict,pty,from=')


def test_docker_unreadable_never_locks_the_portal_out(kt):
    """No sources: `restrict,pty` alone on a bare line, and an existing from= is kept, not narrowed to loopback."""
    text, _, _ = kt['_takportal_authorized_keys_text'](f'{PORTAL_PUB}\n', PORTAL_PUB, [])
    assert _lines_for(text, PORTAL_PUB) == ['restrict,pty ' + PORTAL_PUB]
    good, _, _ = kt['_takportal_authorized_keys_text'](f'{PORTAL_PUB}\n', PORTAL_PUB, NETS)
    kept, changed, _ = kt['_takportal_authorized_keys_text'](good, PORTAL_PUB, [])
    assert kept == good and changed is False


def test_split_handles_quoted_options(kt):
    split = kt['_authorized_keys_split']
    opts, t, blob, comment = split(OPERATOR_OPTS)
    assert opts == 'from="10.0.0.0/8, 192.168.1.5",command="echo hi there"' and t == 'ssh-ed25519'
    assert comment == 'with opts'
    assert split('# x') is None and split('') is None and split('garbage') is None
    assert split('ecdsa-sha2-nistp256 AAAAE2 c')[1] == 'ecdsa-sha2-nistp256'


def test_bad_public_key_is_refused(kt):
    with pytest.raises(ValueError):
        kt['_takportal_authorized_keys_text']('', 'not a key', NETS)


# ------------------------------------------------------------------ where from= comes from
def _sources(inspect_out, nets):
    calls = []

    def run(cmd, **k):
        calls.append(cmd)
        if cmd[:2] == ['docker', 'inspect']:
            return types.SimpleNamespace(returncode=0, stdout=inspect_out, stderr='')
        name = cmd[-1]
        if name in nets:
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(nets[name]), stderr='')
        return types.SimpleNamespace(returncode=1, stdout='', stderr='no such network')

    ns = _load('_takportal_ssh_from_sources', consts=('INFRATAK_DOCKER_NETWORK',),
               _probe_run=run, _sudo_wrap=lambda c: c,
               _takportal_project_name=lambda: 'tak-portal',
               _takportal_app_services=lambda: ['tak-portal', 'tak-portal-worker'],
               _takportal_project_containers=lambda all_states=False: [
                   {'id': 'w', 'name': 'tak-portal', 'service': 'tak-portal'},
                   {'id': 'k', 'name': 'tak-portal-worker', 'service': 'tak-portal-worker'},
                   {'id': 'p', 'name': 'tak-portal-postgres', 'service': 'tak-portal-postgres'}])
    return ns['_takportal_ssh_from_sources'](), calls


def test_sources_are_the_portal_app_containers_networks():
    inspect = (json.dumps({'infratak': {}, 'tak-portal_default': {}}) + '\n'
               + json.dumps({'extra_net': {}, 'host': {}}) + '\n')
    nets = {'infratak': [{'Subnet': '172.22.0.0/16'}],
            'tak-portal_default': [{'Subnet': '172.19.0.0/16'}, {'Subnet': 'fd00:abcd::/64'}],
            'extra_net': [{'Subnet': '192.168.240.0/20'}],
            'host': None}
    got, calls = _sources(inspect, nets)
    assert got == sorted(['172.22.0.0/16', '172.19.0.0/16', 'fd00:abcd::/64', '192.168.240.0/20'])
    inspect_call = [c for c in calls if c[:2] == ['docker', 'inspect']][0]
    assert 'p' not in inspect_call, 'Postgres is not an app container'


def test_public_or_huge_ranges_are_never_trusted():
    nets = {'infratak': [{'Subnet': '0.0.0.0/0'}, {'Subnet': '8.8.8.0/24'}, {'Subnet': '10.0.0.0/7'},
                         {'Subnet': '127.0.0.0/8'}, {'Subnet': 'junk'}, {}],
            'tak-portal_default': [{'Subnet': '172.19.0.0/16'}]}
    got, _ = _sources('', nets)
    assert got == ['172.19.0.0/16']


def test_no_docker_means_no_sources():
    got, _ = _sources('', {})
    assert got == []


# --------------------------------------------------------------------- writer and heal
def _trust_ns(sources=NETS):
    return _load('_authorized_keys_split', '_takportal_ssh_key_options', '_takportal_authorized_keys_text',
                 '_takportal_trust_portal_key', '_heal_takportal_ssh_key',
                 consts=('TAKPORTAL_SSH_KEY_COMMENT', '_AUTHKEY_TYPE_RE'),
                 _takportal_ssh_from_sources=lambda: list(sources),
                 _takportal_web_running=lambda: True)


def test_heal_restricts_an_existing_bare_line(monkeypatch, tmp_path):
    home = tmp_path / 'h'
    (home / '.ssh').mkdir(parents=True)
    (home / 'TAK-Portal' / 'data' / 'ssh').mkdir(parents=True)
    (home / 'TAK-Portal' / 'data' / 'ssh' / 'tak_ssh_ed25519.pub').write_text(PORTAL_PUB + '\n')
    ak = home / '.ssh' / 'authorized_keys'
    ak.write_text(f'{OPERATOR}\n{OLD_PORTAL}\n{PORTAL_PUB}\n')
    ak.chmod(0o644)
    monkeypatch.setenv('HOME', str(home))
    real_isdir = os.path.isdir
    monkeypatch.setattr(os.path, 'isdir', lambda p: p == '/opt/tak' or real_isdir(p))
    ns = _trust_ns()
    log = []
    assert ns['_heal_takportal_ssh_key'](log.append) is True
    assert ak.read_text() == (f'{OPERATOR}\nrestrict,pty,from="127.0.0.1,::1,172.19.0.0/16,172.22.0.0/16" '
                              f'{PORTAL_PUB}\n')
    assert oct(ak.stat().st_mode & 0o777) == '0o600'
    assert any('Removed 1 older TAK Portal key' in m for m in log)
    assert ns['_heal_takportal_ssh_key'](log.append) is False, 'second start changes nothing'
    assert not [p for p in (home / '.ssh').iterdir() if p.name != 'authorized_keys'], 'no temp file left'


def test_heal_never_adds_trust(monkeypatch, tmp_path):
    home = tmp_path / 'h'
    (home / '.ssh').mkdir(parents=True)
    (home / 'TAK-Portal' / 'data' / 'ssh').mkdir(parents=True)
    (home / 'TAK-Portal' / 'data' / 'ssh' / 'tak_ssh_ed25519.pub').write_text(PORTAL_PUB + '\n')
    ak = home / '.ssh' / 'authorized_keys'
    ak.write_text(f'{OPERATOR}\n')
    monkeypatch.setenv('HOME', str(home))
    real_isdir = os.path.isdir
    monkeypatch.setattr(os.path, 'isdir', lambda p: p == '/opt/tak' or real_isdir(p))
    assert _trust_ns()['_heal_takportal_ssh_key'](lambda m: None) is False
    assert ak.read_text() == f'{OPERATOR}\n'


def test_heal_runs_at_console_start_and_status_shows_restriction():
    startup = _func('_startup_migrations')
    assert '_heal_takportal_ssh_key(' in startup
    status = _func('takportal_ssh_status')
    assert 'not restricted' in status and "restricted to TAK Portal's Docker networks" in status


def test_probe_source_is_in_from():
    """The console's own probe connects from 127.0.0.1; from= must admit it."""
    assert "f'{user}@127.0.0.1'" in _func('_takportal_ssh_probe')
    ns = _load('_takportal_ssh_key_options')
    assert ns['_takportal_ssh_key_options'](NETS).startswith('restrict,pty,from="127.0.0.1,::1,')


# ------------------------------------------------------------- no more legacy grant
@pytest.fixture()
def b():
    spec = importlib.util.spec_from_file_location('takwerx_broker_t644', REPO / 'broker' / 'takwerx_broker.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m._sudoers_safe_binaries = lambda name: {
        'cat': ['/usr/bin/cat'], 'tee': ['/usr/bin/tee'], 'bash': ['/usr/bin/bash'],
        'systemctl': ['/usr/bin/systemctl'], 'setpriv': ['/usr/bin/setpriv'], 'visudo': ['/usr/sbin/visudo'],
    }.get(name, [])
    return m


def test_default_grant_is_the_hardened_text(b):
    t = b._takportal_sudoers_text(user='takwerx')
    rules = '\n'.join(l for l in t.splitlines() if l and not l.startswith('#'))
    assert 'tak-portal-repair-certs' not in rules and '/opt/tak/utils' not in rules
    assert 'NOPASSWD: /usr/bin/bash' not in rules and 'NOPASSWD: /usr/bin/tee' not in rules
    with pytest.raises(b.Denied):
        b._takportal_sudoers_text(user='takwerx', variant='legacy')


def test_old_portal_gets_the_hardened_grant(b, tmp_path, monkeypatch):
    home = tmp_path / 'home'
    (home / 'TAK-Portal').mkdir(parents=True)
    (home / 'TAK-Portal' / 'package.json').write_text('{"version": "2.0.12"}')
    monkeypatch.setattr(b.pwd, 'getpwnam', lambda u: type('P', (), {'pw_dir': str(home)})())
    d = b._takportal_decide()
    assert d['variant'] == 'hardened' and d.get('portal_old') is True
    assert 'update' in d['reason'].lower()
