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
"""Broker: root renders the Guard Dog scripts (ops #645 W2 part 2a).

Root runs every script in /opt/tak-guarddog. The console used to fill in the repo
template and `write` the result, so it chose the code root ran. Now root reads the
template from the verified tree it runs from, checks each value, and writes the
script; the console may no longer write, copy, move, install or tee a Guard Dog
script once the broker runs from that tree.

Nothing outside tmp_path is touched: the tree, GD_DIR and the root-layout state are
pointed at tmp_path and chown is a no-op (the tests do not run as root).
"""

import base64
import importlib.util
import os
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
COMMIT = 'a' * 40


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_gd', REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()

TEMPLATE = ('#!/bin/bash\nALERT_EMAIL="ALERT_EMAIL_PLACEHOLDER"\nCERT_PASS="CERT_PASS_PLACEHOLDER"\n'
            'DB_HOST="DB_HOST_PLACEHOLDER"\nSSH_USER="SSH_USER_PLACEHOLDER"\n'
            'echo "$ALERT_EMAIL"\n')


@pytest.fixture
def root(tmp_path, monkeypatch):
    """A broker running from the root-owned tree, with one template."""
    lib = tmp_path / 'lib'
    tdir = lib / COMMIT / 'scripts' / 'guarddog'
    tdir.mkdir(parents=True)
    (tdir / 'tak-disk-watch.sh').write_text(TEMPLATE)
    gd = tmp_path / 'opt' / 'tak-guarddog'
    monkeypatch.setattr(B, 'ROOT_CODE_DIR', str(lib))
    monkeypatch.setattr(B, 'GD_DIR', str(gd))
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    monkeypatch.setattr(B.os, 'chown', lambda *a, **k: None)
    monkeypatch.setattr(B.os, 'fchown', lambda *a, **k: None)
    return types_ns(lib=lib, tdir=tdir, gd=gd)


def types_ns(**kw):
    import types
    return types.SimpleNamespace(**kw)


def verdict(req):
    return B._evaluate(req)


def render(name, values):
    req = {'op': 'gd_render', 'name': name, 'values': values}
    v = verdict(req)
    if v[0] != 'ALLOW':
        return v
    return B._do_gd_render(req)


def write_req(path, text='x'):
    return {'op': 'write', 'path': path, 'mode': 'w',
            'content_b64': base64.b64encode(text.encode()).decode()}


# --- the console can no longer put code in a Guard Dog script ---------------------------

GDS = '/opt/tak-guarddog/tak-disk-watch.sh'


def test_write_into_a_guarddog_script_is_refused_on_the_root_tree(monkeypatch):
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    v = verdict(write_req(GDS, '#!/bin/bash\nid\n'))
    assert v[0] == 'DENY' and 'gd_render' in v[1]
    v = verdict(write_req('/opt/tak-guarddog/new-watch.py'))
    assert v[0] == 'DENY'


@pytest.mark.parametrize('argv', [
    ['cp', '/home/takwerx/x', GDS],
    ['mv', '/var/log/x', GDS],
    ['install', '-m', '0755', '/home/takwerx/x', GDS],
    ['tee', GDS],
    ['ln', '-s', '/home/takwerx/x', GDS],
    # into the folder: the file lands under the source's name (a script name)
    ['cp', '/home/takwerx/x', '/opt/tak-guarddog/'],
    ['cp', '/home/takwerx/x', '/opt/tak-guarddog'],
    ['cp', '/home/takwerx/x', '/opt/tak-guarddog/.'],
    ['install', '-D', '/home/takwerx/x', '/opt/tak-guarddog/'],
    # other spellings of the same script path
    ['cp', '/home/takwerx/x', '/opt/tak-guarddog/./tak-disk-watch.sh'],
    ['install', '-m', '0755', '/home/takwerx/x', '/opt/tak-guarddog/sub/../tak-disk-watch.sh'],
    # a folder at a script name would make every render fail
    ['mkdir', '-p', GDS],
])
def test_exec_routes_into_a_guarddog_script_are_refused(monkeypatch, argv):
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    with pytest.raises(B.Denied):
        B.check_exec(argv)


def test_old_layout_and_state_files_keep_working(monkeypatch):
    """Before the broker runs from the root tree there is no gd_render, so the old
    write stays (that broker runs console-owned code anyway). State files and the
    inline scripts W2 part 2b moves are not scripts from the repo."""
    monkeypatch.setattr(B, '_installed_commit', lambda: '')
    assert verdict(write_req(GDS))[0] == 'ALLOW'
    B.check_exec(['mkdir', '-p', '/opt/tak-guarddog'])       # the deploy makes the folder
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    B.check_exec(['mkdir', '-p', '/opt/tak-guarddog'])
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    for p in ('/opt/tak-guarddog/server_identifier', '/opt/tak-guarddog/known_hosts',
              '/opt/tak-guarddog/guarddog.conf', '/opt/tak-guarddog/sms_send.sh',
              '/opt/tak-guarddog/tak-authentik-tasklog-purge.sh'):
        assert verdict(write_req(p))[0] == 'ALLOW', p


# --- gd_render: what root accepts -------------------------------------------------------

def test_render_fills_the_template_from_the_root_tree(root):
    r = render('tak-disk-watch.sh', {'ALERT_EMAIL_PLACEHOLDER': 'a@x.com,b@y.org',
                                     'CERT_PASS_PLACEHOLDER': 'atakatak',
                                     'DB_HOST_PLACEHOLDER': '10.0.0.5',
                                     'SSH_USER_PLACEHOLDER': 'ubuntu'})
    assert r == {'ok': True, 'changed': True}
    out = root.gd / 'tak-disk-watch.sh'
    assert out.read_text() == TEMPLATE.replace('ALERT_EMAIL_PLACEHOLDER', 'a@x.com,b@y.org').replace(
        'CERT_PASS_PLACEHOLDER', 'atakatak').replace('DB_HOST_PLACEHOLDER', '10.0.0.5').replace(
        'SSH_USER_PLACEHOLDER', 'ubuntu')
    assert out.stat().st_mode & 0o777 == 0o755
    assert not [p for p in root.gd.iterdir() if p.name.startswith('.')]     # no temp left
    # same bytes again: not rewritten, still reported
    mtime = out.stat().st_mtime_ns
    r = render('tak-disk-watch.sh', {'ALERT_EMAIL_PLACEHOLDER': 'a@x.com,b@y.org',
                                     'CERT_PASS_PLACEHOLDER': 'atakatak',
                                     'DB_HOST_PLACEHOLDER': '10.0.0.5',
                                     'SSH_USER_PLACEHOLDER': 'ubuntu'})
    assert r == {'ok': True, 'changed': False} and out.stat().st_mtime_ns == mtime


def test_a_placeholder_without_a_value_stays_as_it_was(root):
    """Same as the console's own fill-in: each caller fills only what it knows."""
    render('tak-disk-watch.sh', {'ALERT_EMAIL_PLACEHOLDER': ''})
    assert 'DB_HOST="DB_HOST_PLACEHOLDER"' in (root.gd / 'tak-disk-watch.sh').read_text()


def test_fill_is_one_pass(root):
    render('tak-disk-watch.sh', {'CERT_PASS_PLACEHOLDER': 'DB_HOST_PLACEHOLDER',
                                 'DB_HOST_PLACEHOLDER': 'h1'})
    text = (root.gd / 'tak-disk-watch.sh').read_text()
    assert 'CERT_PASS="DB_HOST_PLACEHOLDER"' in text and 'DB_HOST="h1"' in text


def test_the_template_comes_from_the_root_tree_only(root, tmp_path):
    (tmp_path / 'evil.sh').write_text('#!/bin/bash\nid\n')
    (root.tdir / 'tak-oom-watch.sh').symlink_to(tmp_path / 'evil.sh')
    r = render('tak-oom-watch.sh', {})
    assert not r.get('ok') and not (root.gd / 'tak-oom-watch.sh').exists()
    r = render('tak-nope-watch.sh', {})
    assert r['ok'] is False and r['code'] == 'ENOENT'


def test_a_link_at_the_destination_is_replaced_not_followed(root, tmp_path):
    victim = tmp_path / 'victim'
    victim.write_text('keep')
    root.gd.mkdir(parents=True)
    (root.gd / 'tak-disk-watch.sh').symlink_to(victim)
    assert render('tak-disk-watch.sh', {})['ok']
    assert victim.read_text() == 'keep'
    assert not (root.gd / 'tak-disk-watch.sh').is_symlink()


def test_a_linked_guarddog_dir_is_refused(root, tmp_path):
    (tmp_path / 'elsewhere').mkdir()
    root.gd.parent.mkdir(parents=True)
    root.gd.symlink_to(tmp_path / 'elsewhere')
    r = render('tak-disk-watch.sh', {})
    assert r['ok'] is False and not list((tmp_path / 'elsewhere').iterdir())


def test_no_root_tree_no_render(monkeypatch):
    monkeypatch.setattr(B, '_installed_commit', lambda: '')
    v = verdict({'op': 'gd_render', 'name': 'tak-disk-watch.sh', 'values': {}})
    assert v[0] == 'DENY' and 'root-owned copy' in v[1]


# --- gd_render: what root refuses -------------------------------------------------------

@pytest.mark.parametrize('key,value', [
    ('ALERT_EMAIL_PLACEHOLDER', 'a@x.com" ; id ; "'),
    ('ALERT_EMAIL_PLACEHOLDER', '$(id)@x.com'),
    ('ALERT_EMAIL_PLACEHOLDER', 'a@x.com\nid'),
    ('ALERT_SMS_PLACEHOLDER', '`id`'),
    ('CERT_PASS_PLACEHOLDER', 'pa"ss'),
    ('CERT_PASS_PLACEHOLDER', 'pa$(id)'),
    ('CERT_PASS_PLACEHOLDER', 'pa`id`'),
    ('CERT_PASS_PLACEHOLDER', 'pa\\'),
    ('CERT_PASS_PLACEHOLDER', 'pa ss'),
    ('DB_HOST_PLACEHOLDER', '-oProxyCommand=id'),
    ('DB_HOST_PLACEHOLDER', 'h;id'),
    ('FEDHUB_HOST_PLACEHOLDER', '-oProxyCommand=id'),
    ('SSH_USER_PLACEHOLDER', '-oProxyCommand=id'),
    ('SSH_USER_PLACEHOLDER', 'u@h'),
    ('SSH_KEY_PLACEHOLDER', '-i/tmp/k'),
    ('SSH_KEY_PLACEHOLDER', 'relative/key'),
    ('SSH_KEY_PLACEHOLDER', '/home/x/k y'),
    ('SSH_KEY_PLACEHOLDER', '/home/takwerx/../../etc/shadow'),
    ('DB_PORT_PLACEHOLDER', '5432;id'),
    ('EXTERNAL_DB_PLACEHOLDER', 'yes'),
    ('CONSOLE_VERSION_PLACEHOLDER', '10.3; id'),
    ('UPDATE_CHANNEL_PLACEHOLDER', 'dev;id'),
    ('AK_VETTED_PLACEHOLDER', '2025.10 x'),
    ('SOMETHING_PLACEHOLDER', 'x'),
])
def test_bad_values_are_refused(root, key, value):
    v = verdict({'op': 'gd_render', 'name': 'tak-disk-watch.sh', 'values': {key: value}})
    assert v[0] == 'DENY', (key, value)


@pytest.mark.parametrize('req', [
    {'op': 'gd_render', 'name': '../../etc/cron.d/x.sh', 'values': {}},
    {'op': 'gd_render', 'name': 'x.txt', 'values': {}},
    {'op': 'gd_render', 'name': '.hidden.sh', 'values': {}},
    {'op': 'gd_render', 'name': 'sms_send.sh', 'values': {}},           # inline, 2b
    {'op': 'gd_render', 'name': 'tak-disk-watch.sh', 'values': []},
    {'op': 'gd_render', 'name': 'tak-disk-watch.sh', 'values': {}, 'path': '/etc/x'},
    {'op': 'gd_render', 'name': 'tak-disk-watch.sh', 'values': {'DB_PORT_PLACEHOLDER': 5432}},
])
def test_bad_requests_are_refused(root, req):
    assert verdict(req)[0] == 'DENY'


@pytest.mark.parametrize('key,value', [
    ('ALERT_EMAIL_PLACEHOLDER', 'ops@example.com,oncall+tak@example.org'),
    ('ALERT_EMAIL_PLACEHOLDER', ''),
    ('CERT_PASS_PLACEHOLDER', 'atakatak'),
    ('CERT_PASS_PLACEHOLDER', 'P@ss!w0rd#%^&*()'),
    ('DB_HOST_PLACEHOLDER', 'db1.example.com'),
    ('DB_HOST_PLACEHOLDER', '[fd00::5]'),
    ('DB_PORT_PLACEHOLDER', '5432'),
    ('SSH_USER_PLACEHOLDER', 'root'),
    ('SSH_KEY_PLACEHOLDER', '/home/takwerx/.ssh/id_ed25519'),
    ('SSH_KEY_PLACEHOLDER', ''),
    ('EXTERNAL_DB_PLACEHOLDER', 'true'),
    ('CONSOLE_VERSION_PLACEHOLDER', '10.3.12-alpha'),
    ('UPDATE_CHANNEL_PLACEHOLDER', 'main'),
    ('AK_VETTED_PLACEHOLDER', '2025.10.2'),
    ('FEDHUB_HOST_PLACEHOLDER', 'fedhub.example.com'),
])
def test_real_values_pass(root, key, value):
    assert verdict({'op': 'gd_render', 'name': 'tak-disk-watch.sh', 'values': {key: value}})[0] == 'ALLOW'


# --- the templates in this repo ---------------------------------------------------------

def _templates():
    return sorted((REPO / 'scripts' / 'guarddog').iterdir())


def test_every_repo_placeholder_has_a_value_rule():
    found = set()
    for p in _templates():
        found |= set(B._GD_PLACEHOLDER_RE.findall(p.read_text()))
    assert found and found <= set(B._GD_VALUE_RES), sorted(found - set(B._GD_VALUE_RES))


def test_every_placeholder_sits_inside_double_quotes():
    """The value check (no $ ` " \\) is only enough inside "...". A placeholder in
    a comment is harmless (values have no line break)."""
    bad = []
    for p in _templates():
        for n, line in enumerate(p.read_text().splitlines(), 1):
            if line.lstrip().startswith('#'):
                continue
            for m in B._GD_PLACEHOLDER_RE.finditer(line):
                if line[:m.start()].count('"') % 2 != 1:
                    bad.append(f'{p.name}:{n}: {line.strip()[:80]}')
    assert not bad, bad


def test_inline_pending_names_are_not_repo_templates():
    names = {p.name for p in _templates()}
    assert not (B._GD_INLINE_PENDING & names)
    assert all(B._GD_NAME_RE.match(n) for n in names if n.endswith(('.sh', '.py')))


def test_console_fill_matches_the_broker_fill():
    """app.py fills locally to compare and for the old-broker path; it must give the
    same bytes as root."""
    src = (REPO / 'app.py').read_text()
    m = re.search(r"^_GD_PLACEHOLDER_RE = re\.compile\((r'[^']+')\)$", src, re.M)
    assert m and eval(m.group(1)) == B._GD_PLACEHOLDER_RE.pattern


_REAL_VALUES = {
    'ALERT_EMAIL_PLACEHOLDER': 'ops@example.com,oncall@example.org',
    'ALERT_SMS_PLACEHOLDER': '',
    'CERT_PASS_PLACEHOLDER': 'Takserver#atak!',
    'CONSOLE_VERSION_PLACEHOLDER': '10.3.12-alpha',
    'UPDATE_CHANNEL_PLACEHOLDER': 'dev',
    'AK_VETTED_PLACEHOLDER': '2025.10.2',
    'EXTERNAL_DB_PLACEHOLDER': 'true',
    'DB_HOST_PLACEHOLDER': '10.0.0.5',
    'DB_PORT_PLACEHOLDER': '5432',
    'SSH_KEY_PLACEHOLDER': '/home/takwerx/.ssh/infratak_serverone',
    'SSH_USER_PLACEHOLDER': 'ubuntu',
    'FEDHUB_HOST_PLACEHOLDER': 'fedhub.example.com',
}


@pytest.mark.parametrize('subset', ['all', 'one_server'])
def test_root_render_gives_the_same_bytes_as_the_old_fill(root, subset):
    """Boxes see no change: for every repo template, root's one-pass fill writes the
    same bytes the console's old `.replace` chain wrote (so no script is rewritten or
    logged as changed on the first Update after this ships)."""
    vals = dict(_REAL_VALUES)
    if subset == 'one_server':      # run_guarddog_deploy on a one-server box
        for k in ('DB_HOST', 'DB_PORT', 'SSH_KEY', 'SSH_USER', 'FEDHUB_HOST', 'EXTERNAL_DB'):
            vals.pop(k + '_PLACEHOLDER')
    for p in _templates():
        if not p.name.endswith(('.sh', '.py')):
            continue
        (root.tdir / p.name).write_bytes(p.read_bytes())
        assert verdict({'op': 'gd_render', 'name': p.name, 'values': vals})[0] == 'ALLOW', p.name
        assert B._do_gd_render({'op': 'gd_render', 'name': p.name, 'values': vals})['ok'], p.name
        old = p.read_text()
        for k, v in vals.items():
            old = old.replace(k, v)
        assert (root.gd / p.name).read_text() == old, p.name


def test_the_audit_log_never_carries_values():
    req = {'op': 'gd_render', 'name': 'tak-cert-watch.sh',
           'values': {'CERT_PASS_PLACEHOLDER': 'sekret-pass'}}
    seen = []
    orig = B.audit
    try:
        B.audit = lambda peer, op, summary, verdict, reason='': seen.append(summary)
        B._dispatch(req, {'uid': 0, 'pid': 1})
    finally:
        B.audit = orig
    assert seen and not any('sekret' in x for x in seen), seen


def test_app_fills_guarddog_templates_only_through_the_helper():
    """Every fill-in goes through _gd_install_script (gd_render on the root layout).
    A new `.replace('X_PLACEHOLDER', …)` would write a root script from console bytes."""
    src = (REPO / 'app.py').read_text()
    assert not re.findall(r"\.replace\(f?'[A-Z_{}]*_PLACEHOLDER'", src)
    assert src.count('_gd_install_script(') >= 5          # def + the four call sites


# --- Security re-review #2: the whole Guard Dog tree is locked, not only depth-1 scripts ---
# With a fake installed commit these were all ALLOW: `mkdir -p /opt/tak-guarddog/sub`,
# `write` (cp, install, tee) to `/opt/tak-guarddog/sub/x.sh`, then a unit with
# `ExecStart=/opt/tak-guarddog/sub/x.sh` (the unit check took anything under the prefix).

_SUB = '/opt/tak-guarddog/sub/x.sh'
_UNIT_GUARD = '[Unit]\nDescription=g\n\n[Service]\nType=oneshot\nExecStart={}\n'


@pytest.mark.parametrize('argv', [
    ['mkdir', '-p', '/opt/tak-guarddog/sub'],
    ['mkdir', '/opt/tak-guarddog/sub'],
    ['mkdir', '-p', '/opt/tak-guarddog/sub/deeper'],
    ['mkdir', '-p', '/opt/tak-guarddog/server_identifier'],
    ['cp', '/home/takwerx/x', _SUB],
    ['cp', '-r', '/home/takwerx/dir', '/opt/tak-guarddog/sub'],
    ['mv', '/var/log/x', _SUB],
    ['install', '-m', '0755', '/home/takwerx/x', _SUB],
    ['install', '-D', '-m', '0644', '/tmp/x', _SUB],
    ['tee', _SUB],
    ['touch', _SUB],
    ['touch', '/opt/tak-guarddog/new-name'],
    # depth 1 names that are neither a state file nor an inline script
    ['cp', '/home/takwerx/x', '/opt/tak-guarddog/.evil.sh'],
    ['cp', '/home/takwerx/x', '/opt/tak-guarddog/evil'],
    ['tee', '/opt/tak-guarddog/x.SH'],
    # a state file copied over a script, a script moved onto a state name
    ['cp', '/opt/tak-guarddog/server_identifier', GDS],
    ['mv', GDS, '/opt/tak-guarddog/server_identifier'],
])
def test_exec_routes_into_the_guarddog_tree_are_refused(monkeypatch, argv):
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    with pytest.raises(B.Denied):
        B.check_exec(argv)


@pytest.mark.parametrize('path', [_SUB, '/opt/tak-guarddog/sub/x.py', '/opt/tak-guarddog/sub/server_identifier',
                                  '/opt/tak-guarddog/.evil.sh', '/opt/tak-guarddog/evil',
                                  '/opt/tak-guarddog/a/../sub/x.sh', '//opt/tak-guarddog/sub/x.sh'])
def test_write_into_the_guarddog_tree_is_refused(monkeypatch, path):
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    v = verdict(write_req(path, '#!/bin/bash\nid\n'))
    assert v[0] == 'DENY', (path, v)


@pytest.mark.parametrize('cmd', [
    _SUB, '/usr/bin/python3 /opt/tak-guarddog/sub/x.py', '/bin/bash /opt/tak-guarddog/sub/x.sh',
    '/opt/tak-guarddog/.evil.sh', '/opt/tak-guarddog/server_identifier', '/opt/tak-guarddog/evil',
    '/etc/debsig/policies/x', '/usr/share/debsig/keyrings/x', '/opt/tak-guarddog',
])
def test_units_run_only_depth_one_guarddog_scripts(cmd):
    v = B._evaluate({'op': 'write', 'path': '/etc/systemd/system/takdiskguard.service', 'mode': 'w',
                     'content_b64': base64.b64encode(_UNIT_GUARD.format(cmd).encode()).decode()})
    assert v[0] == 'DENY' and 'infra-TAK script' in v[1], (cmd, v)


def test_depth_one_guarddog_scripts_and_exact_assets_still_run_from_units():
    for cmd in (GDS, '/usr/bin/python3 -I /opt/tak-guarddog/tak-health-endpoint.py',
                '/opt/tak-guarddog/_gd-tak-lib.sh', '/usr/local/sbin/takserver-renew-letsencrypt.sh',
                '/opt/tak-guarddog/tak-client-gate.sh release'):
        v = B._evaluate({'op': 'write', 'path': '/etc/systemd/system/takdiskguard.service', 'mode': 'w',
                         'content_b64': base64.b64encode(_UNIT_GUARD.format(cmd).encode()).decode()})
        assert v[0] == 'ALLOW', (cmd, v)


def test_state_file_list_matches_the_console_code():
    """Every non-script name app.py uses in /opt/tak-guarddog is a state file the
    console may still write, and every listed state file is used by app.py."""
    app = (REPO / 'app.py').read_text()
    names = set(re.findall(r'/opt/tak-guarddog/([A-Za-z0-9_.-]+)', app))
    names = {n for n in names if not re.search(r'\.(sh|py)$', n)}
    assert names == set(B._GD_STATE_FILES), (sorted(names - B._GD_STATE_FILES),
                                             sorted(B._GD_STATE_FILES - names))


def test_console_state_file_shapes_still_pass(monkeypatch):
    """Shapes from the test6/test12 broker audit logs (10 days) on the locked tree."""
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    for argv in (['mkdir', '-p', '/opt/tak-guarddog'], ['touch', '/opt/tak-guarddog/known_hosts'],
                 ['chown', 'root:root', '/opt/tak-guarddog/known_hosts'],
                 ['chmod', '600', '/opt/tak-guarddog/known_hosts'],
                 ['rm', '-f', '/opt/tak-guarddog/diskio_email_off'],
                 ['touch', '/opt/tak-guarddog/diskio_email_off']):
        B.check_exec(argv)
    for n in sorted(B._GD_STATE_FILES | B._GD_INLINE_PENDING):
        assert verdict(write_req('/opt/tak-guarddog/' + n))[0] == 'ALLOW', n


def test_render_works_through_the_directory_fd(root):
    r = render('tak-disk-watch.sh', {'ALERT_EMAIL_PLACEHOLDER': 'a@b.c'})
    assert r == {'ok': True, 'changed': True}, r
    assert 'a@b.c' in (root.gd / 'tak-disk-watch.sh').read_text()
    assert not [p for p in os.listdir(root.gd) if p.startswith('.')], 'temp file left behind'
    assert render('tak-disk-watch.sh', {'ALERT_EMAIL_PLACEHOLDER': 'a@b.c'}) == {'ok': True, 'changed': False}


def test_render_never_calls_path_based_chown_or_chmod():
    src = (REPO / 'broker' / 'takwerx_broker.py').read_text()
    body = src[src.index('def _do_gd_render('):src.index('\ndef ', src.index('def _do_gd_render(') + 10)]
    assert 'os.chown(' not in body and 'os.chmod(' not in body
    assert 'dir_fd=dfd' in body and 'O_DIRECTORY' in body
