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
"""Broker: the last Guard Dog scripts the console built inline (ops #645 W2 part 2b).

`sms_send.sh`, `sms_send.py`, `tak-authentik-tasklog-purge.sh` and
`mediamtx-cert-sync.sh` were built in app.py and written by the console, and root
runs them. Now they are repo templates that root installs (gd_render) and removes
(gd_remove), so the console chooses no code root runs from /opt/tak-guarddog.

The cert sync was the worst: the console wrote the local cert and key paths into it,
so a console foothold could make root send any file to any host. Now the script
finds the cert in Caddy's store from the domain.

Nothing outside tmp_path is touched (the tree and GD_DIR point at tmp_path, chown is
a no-op). The cert-sync run uses fake scp/ssh on PATH.
"""

import ast
import base64
import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = REPO / 'scripts' / 'guarddog'
COMMIT = 'b' * 40
OPTIONAL = ('sms_send.py', 'sms_send.sh', 'tak-authentik-tasklog-purge.sh', 'mediamtx-cert-sync.sh')


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_gd2b', REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()
APP_SRC = (REPO / 'app.py').read_text()


def _app_constant(name):
    for node in ast.parse(APP_SRC).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name):
            return ast.literal_eval(node.value) if not isinstance(node.value, ast.Call) else \
                ast.literal_eval(node.value.args[0])
    raise AssertionError(f'{name} not found in app.py')


@pytest.fixture
def root(tmp_path, monkeypatch):
    """A broker on the root-owned tree, with the real repo templates in it."""
    lib = tmp_path / 'lib'
    tdir = lib / COMMIT / 'scripts' / 'guarddog'
    shutil.copytree(TEMPLATES, tdir)
    gd = tmp_path / 'opt' / 'tak-guarddog'
    monkeypatch.setattr(B, 'ROOT_CODE_DIR', str(lib))
    monkeypatch.setattr(B, 'GD_DIR', str(gd))
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    monkeypatch.setattr(B.os, 'chown', lambda *a, **k: None)
    monkeypatch.setattr(B.os, 'fchown', lambda *a, **k: None)
    return types.SimpleNamespace(tdir=tdir, gd=gd, tmp=tmp_path)


def render(name, values):
    req = {'op': 'gd_render', 'name': name, 'values': values}
    v = B._evaluate(req)
    if v[0] != 'ALLOW':
        return {'ok': False, 'verdict': v}
    return B._do_gd_render(req)


def remove(name):
    req = {'op': 'gd_remove', 'name': name}
    v = B._evaluate(req)
    if v[0] != 'ALLOW':
        return {'ok': False, 'verdict': v}
    return B._do_gd_remove(req)


MTX = {
    'MTX_DOMAIN_PLACEHOLDER': 'stream.example.com',
    'MTX_HOST_PLACEHOLDER': '10.0.0.9',
    'MTX_USER_PLACEHOLDER': 'ubuntu',
    'MTX_PORT_PLACEHOLDER': '22',
    'MTX_KEYFILE_PLACEHOLDER': '/home/takwerx/.ssh/id_ed25519',
}


# --- the four are repo templates now, installed by root ---------------------------------

@pytest.mark.parametrize('name', OPTIONAL)
def test_each_once_inline_script_is_a_repo_template_root_installs(root, name):
    vals = MTX if name == 'mediamtx-cert-sync.sh' else {}
    r = render(name, vals)
    assert r == {'ok': True, 'changed': True}, r
    out = root.gd / name
    assert out.stat().st_mode & 0o777 == 0o755
    assert '_PLACEHOLDER' not in out.read_text()


@pytest.mark.parametrize('name', OPTIONAL)
def test_console_writes_to_them_are_refused_on_the_root_tree(monkeypatch, name):
    monkeypatch.setattr(B, '_installed_commit', lambda: COMMIT)
    p = '/opt/tak-guarddog/' + name
    v = B._evaluate({'op': 'write', 'path': p, 'mode': 'w',
                     'content_b64': base64.b64encode(b'#!/bin/bash\nid\n').decode()})
    assert v[0] == 'DENY', v
    for argv in (['cp', '/home/takwerx/x', p], ['mv', '/tmp/x', p], ['tee', p],
                 ['install', '-m', '0755', '/home/takwerx/x', p], ['ln', '-s', '/home/takwerx/x', p]):
        with pytest.raises(B.Denied):
            B.check_exec(argv)


def test_purge_and_sms_render_to_the_bytes_app_py_used_to_write(root):
    """No value goes in, so root writes the template as is: same bytes as before 2b,
    so no box sees a rewrite on the first Update."""
    for name in ('sms_send.py', 'sms_send.sh', 'tak-authentik-tasklog-purge.sh'):
        text = (TEMPLATES / name).read_text()
        assert not B._GD_PLACEHOLDER_RE.search(text), name
        render(name, {})
        assert (root.gd / name).read_text() == text
    assert 'VACUUM' in (TEMPLATES / 'tak-authentik-tasklog-purge.sh').read_text()
    assert '/api/guarddog/send-sms' in (TEMPLATES / 'sms_send.py').read_text()


# --- mediamtx-cert-sync.sh: what the console may name -----------------------------------

@pytest.mark.parametrize('key,value', [
    ('MTX_DOMAIN_PLACEHOLDER', '../../etc'),
    ('MTX_DOMAIN_PLACEHOLDER', 'a/b'),
    ('MTX_DOMAIN_PLACEHOLDER', '-x.example.com'),
    ('MTX_DOMAIN_PLACEHOLDER', 'a b.com'),
    ('MTX_DOMAIN_PLACEHOLDER', '*'),
    ('MTX_DOMAIN_PLACEHOLDER', ''),
    ('MTX_HOST_PLACEHOLDER', '-oProxyCommand=id'),
    ('MTX_HOST_PLACEHOLDER', 'h;id'),
    ('MTX_HOST_PLACEHOLDER', ''),
    ('MTX_USER_PLACEHOLDER', '-oProxyCommand=id'),
    ('MTX_USER_PLACEHOLDER', 'u@h'),
    ('MTX_PORT_PLACEHOLDER', '0'),
    ('MTX_PORT_PLACEHOLDER', '22 -oX'),
    ('MTX_PORT_PLACEHOLDER', '123456'),
    ('MTX_KEYFILE_PLACEHOLDER', '/etc/ssh/ssh_host_ed25519_key'),
    ('MTX_KEYFILE_PLACEHOLDER', '/root/.ssh/id_rsa'),
    ('MTX_KEYFILE_PLACEHOLDER', '/home/takwerx/../../etc/shadow'),
    ('MTX_KEYFILE_PLACEHOLDER', '/home/takwerx/./k'),
    ('MTX_KEYFILE_PLACEHOLDER', '/var/lib/caddy/.local/share/caddy/x.key'),
    ('MTX_KEYFILE_PLACEHOLDER', 'relative/key'),
    ('MTX_KEYFILE_PLACEHOLDER', '/home/x/$(id)'),
])
def test_bad_cert_sync_values_are_refused(root, key, value):
    vals = dict(MTX, **{key: value})
    v = B._evaluate({'op': 'gd_render', 'name': 'mediamtx-cert-sync.sh', 'values': vals})
    assert v[0] == 'DENY', (key, value)


def test_real_cert_sync_values_pass(root):
    for vals in (MTX, dict(MTX, MTX_KEYFILE_PLACEHOLDER=''), dict(MTX, MTX_HOST_PLACEHOLDER='[fd00::9]'),
                 dict(MTX, MTX_USER_PLACEHOLDER='root', MTX_PORT_PLACEHOLDER='2222')):
        assert B._evaluate({'op': 'gd_render', 'name': 'mediamtx-cert-sync.sh', 'values': vals})[0] == 'ALLOW'


def test_cert_sync_template_holds_no_local_path_from_the_console():
    """The only local file a value names is the -i key. The cert and key come from
    Caddy's store, and the remote command is fixed (the same one the deploy runs)."""
    text = (TEMPLATES / 'mediamtx-cert-sync.sh').read_text()
    assert set(B._GD_PLACEHOLDER_RE.findall(text)) == set(MTX)
    assert 'STORE=/var/lib/caddy/.local/share/caddy/certificates\n' in text
    perms = _app_constant('_MEDIAMTX_REMOTE_CERT_PERMS')
    assert f'"{perms} && systemctl restart mediamtx"' in text


def _run_cert_sync(root, tmp_path, vals, store_files):
    """Render the script, point STORE at a temp store, run it with fake scp/ssh."""
    render('mediamtx-cert-sync.sh', vals)
    store = tmp_path / 'store'
    for rel, age in store_files:
        p = store / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(age, str):            # a link to that target
            p.symlink_to(age)
            continue
        p.write_text(rel)
        t = time.time() - age
        os.utime(p, (t, t))
    script = (root.gd / 'mediamtx-cert-sync.sh').read_text().replace(
        'STORE=/var/lib/caddy/.local/share/caddy/certificates', f'STORE={store}')
    run = tmp_path / 'run.sh'
    run.write_text(script)
    fake = tmp_path / 'bin'
    fake.mkdir()
    log = tmp_path / 'calls.log'
    for tool in ('scp', 'ssh'):
        f = fake / tool
        f.write_text(f'#!/bin/bash\nprintf "%s" "{tool}" >> "{log}"\n'
                     f'for a in "$@"; do printf " [%s]" "$a" >> "{log}"; done\necho >> "{log}"\n')
        f.chmod(0o755)
    env = dict(os.environ, PATH=f'{fake}:/usr/bin:/bin')
    r = subprocess.run(['bash', str(run)], env=env, capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.skipif(not shutil.which('bash'), reason='needs bash')
def test_cert_sync_sends_only_the_newest_caddy_pair(root, tmp_path):
    d = 'stream.example.com'
    # the old issuer sorts after the new one by name, so only the age can pick the new one
    calls = _run_cert_sync(root, tmp_path, dict(MTX, MTX_KEYFILE_PLACEHOLDER=''), [
        (f'acme-v02.api.letsencrypt.org-directory/{d}/{d}.crt', 10),
        (f'acme-v02.api.letsencrypt.org-directory/{d}/{d}.key', 10),
        (f'zz-old-ca-directory/{d}/{d}.crt', 9000), (f'zz-old-ca-directory/{d}/{d}.key', 9000),
    ])
    assert len(calls) == 3, calls
    assert 'zz-old-ca' not in ''.join(calls)
    assert calls[0].startswith('scp [-P] [22] [-o] [StrictHostKeyChecking=accept-new] [-o] [BatchMode=yes] [--] ')
    assert f'letsencrypt.org-directory/{d}/{d}.crt] [ubuntu@10.0.0.9:/etc/mediamtx/certs/stream.crt]' in calls[0]
    assert f'letsencrypt.org-directory/{d}/{d}.key] [ubuntu@10.0.0.9:/etc/mediamtx/certs/stream.key]' in calls[1]
    assert calls[2].startswith('ssh [-p] [22] ') and '[--] [ubuntu@10.0.0.9]' in calls[2]
    assert '[-i]' not in ''.join(calls)


@pytest.mark.skipif(not shutil.which('bash'), reason='needs bash')
def test_cert_sync_skips_links_in_the_store(root, tmp_path):
    """A link in the store (Caddy writes none) would point root at another file."""
    d = 'stream.example.com'
    (tmp_path / 'secret').write_text('root only')
    calls = _run_cert_sync(root, tmp_path, MTX, [
        (f'evil-directory/{d}/{d}.crt', str(tmp_path / 'secret')),
        (f'evil-directory/{d}/{d}.key', str(tmp_path / 'secret')),
    ])
    assert calls == []


@pytest.mark.skipif(not shutil.which('bash'), reason='needs bash')
def test_cert_sync_sends_nothing_without_a_pair(root, tmp_path):
    d = 'stream.example.com'
    assert _run_cert_sync(root, tmp_path, MTX, [(f'acme-x-directory/{d}/{d}.crt', 5)]) == []


@pytest.mark.skipif(not shutil.which('bash'), reason='needs bash')
def test_cert_sync_uses_the_key_only_when_it_is_a_plain_file(root, tmp_path):
    d = 'stream.example.com'
    key = tmp_path / 'id_ed25519'
    key.write_text('k')
    calls = _run_cert_sync(root, tmp_path, dict(MTX, MTX_KEYFILE_PLACEHOLDER=str(key)), [
        (f'acme-x-directory/{d}/{d}.crt', 5), (f'acme-x-directory/{d}/{d}.key', 5)])
    assert all(f'[-i] [{key}]' in c for c in calls), calls


def test_rendered_cert_sync_is_valid_bash(root):
    render('mediamtx-cert-sync.sh', MTX)
    r = subprocess.run(['bash', '-n', str(root.gd / 'mediamtx-cert-sync.sh')], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# --- gd_remove ----------------------------------------------------------------------------

def test_remove_an_optional_script(root):
    render('sms_send.sh', {})
    assert remove('sms_send.sh') == {'ok': True, 'changed': True}
    assert not (root.gd / 'sms_send.sh').exists()
    assert remove('sms_send.sh') == {'ok': True, 'changed': False}


@pytest.mark.parametrize('req', [
    {'op': 'gd_remove', 'name': 'tak-disk-watch.sh'},
    {'op': 'gd_remove', 'name': '../../etc/passwd'},
    {'op': 'gd_remove', 'name': 'sms_send.sh/../../x'},
    {'op': 'gd_remove', 'name': 'server_identifier'},
    {'op': 'gd_remove', 'name': ['sms_send.sh']},
    {'op': 'gd_remove', 'name': 'sms_send.sh', 'path': '/etc/x'},
])
def test_remove_refuses_anything_else(req):
    assert B._evaluate(req)[0] == 'DENY'


def test_remove_takes_the_link_not_its_target(root):
    victim = root.tmp / 'victim'
    victim.write_text('keep')
    root.gd.mkdir(parents=True)
    (root.gd / 'sms_send.py').symlink_to(victim)
    assert remove('sms_send.py')['changed'] is True
    assert victim.read_text() == 'keep' and not os.path.lexists(root.gd / 'sms_send.py')


def test_remove_through_a_linked_guarddog_dir_is_refused(root):
    other = root.tmp / 'elsewhere'
    other.mkdir()
    (other / 'sms_send.sh').write_text('x')
    root.gd.parent.mkdir(parents=True)
    root.gd.symlink_to(other)
    r = remove('sms_send.sh')
    assert r['ok'] is False and (other / 'sms_send.sh').exists()


# --- Security note 1 (W2 third look): alert lists never start an item with '-' ------------

@pytest.mark.parametrize('key', ['ALERT_EMAIL_PLACEHOLDER', 'ALERT_SMS_PLACEHOLDER'])
@pytest.mark.parametrize('value,ok', [
    ('-x', False), ('a@b.c,-x', False), ('-oX@b.c', False), ('.a@b.c', False), ('a@b.c,@x', False),
    ('', True), ('a@b.c', True), ('a@b.c,+15551234567', True), ('5551234567@txt.example.com', True),
    ('a@b.c,', True), ('ops-team@example.com,on-call@example.org', True),
])
def test_alert_list_items_start_with_a_letter_digit_or_plus(root, key, value, ok):
    v = B._evaluate({'op': 'gd_render', 'name': 'tak-disk-watch.sh', 'values': {key: value}})
    assert (v[0] == 'ALLOW') == ok, (value, v)


# --- app.py ------------------------------------------------------------------------------

def test_app_and_broker_agree_on_the_optional_set():
    m = re.search(r"^_GD_OPTIONAL_SCRIPTS = frozenset\(\{(.*?)\}\)", APP_SRC, re.M | re.S)
    assert m
    assert set(re.findall(r"'([^']+)'", m.group(1))) == set(B._GD_OPTIONAL) == set(OPTIONAL)


def test_guarddog_sync_skips_the_optional_scripts():
    """The sync installs every file in scripts/guarddog/. The four must not land on
    every box: the Guard Dog page reads 'purge installed' and SMS 'on' from the file."""
    i = APP_SRC.index("script_files = [f for f in os.listdir(scripts_dir) if f.endswith(('.sh', '.py'))]")
    loop = APP_SRC[i:i + 600]
    assert 'name in _GD_OPTIONAL_SCRIPTS' in loop and 'continue' in loop


def test_app_no_longer_builds_them_inline():
    assert 'Auto-generated: sync Caddy certs' not in APP_SRC
    assert "py_script = '''#!/usr/bin/env python3" not in APP_SRC
    assert '_AUTHENTIK_TASKLOG_PURGE_SCRIPT = (' not in APP_SRC
    for name in OPTIONAL:
        # no path write of these names any more, only the helpers
        assert not re.search(r"_write_priv\(\s*'/opt/tak-guarddog/%s'" % re.escape(name), APP_SRC), name
    assert not re.search(r'_write_priv\([^)]*_AUTHENTIK_TASKLOG_PURGE_SCRIPT', APP_SRC)
    assert 'sync_script' not in APP_SRC
    assert "_gd_install_script('mediamtx-cert-sync.sh'" in APP_SRC
    assert APP_SRC.count("_gd_install_script('tak-authentik-tasklog-purge.sh'") == 3
    assert "_gd_remove_script(name)" in APP_SRC


def test_cert_sync_deploy_sends_only_the_values_the_template_takes():
    i = APP_SRC.index("_gd_install_script('mediamtx-cert-sync.sh'")
    block = APP_SRC[i:i + 600]
    assert set(re.findall(r"'([A-Z_]+_PLACEHOLDER)'", block)) == set(MTX)


# --- console against an older root-owned broker ------------------------------------------
# A box whose root broker could not move to this commit (Update could not reach GitHub,
# or a trial of an unmerged commit) keeps the older root copy (W1/2a). That broker does
# not render the four scripts ("not a Guard Dog script name": they were inline) and has
# no gd_remove ("unknown op"). The console must then use the old routes, which that
# broker still allows for these names, not fail SMS save, SMS off or the purge.

_OLD_RENDER_REFUSAL = 'gd_render: not a Guard Dog script name: %s'   # broker at dev 85d4f8e


def _console(broker_reply, exec_rc=0):
    """_gd_install_script / _gd_remove_script from app.py, with a fake broker."""
    names = ('_gd_fill', '_gd_render_older_broker', '_gd_remove_script', '_gd_install_script')
    tree = ast.parse(APP_SRC)
    src = [ast.get_source_segment(APP_SRC, n) for n in tree.body
           if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(src) == len(names)
    calls = {'broker': [], 'exec': [], 'write': []}

    class BrokerError(RuntimeError):
        pass

    def _broker_request(req):
        calls['broker'].append(req)
        return broker_reply(req)

    def _run(argv, **kw):
        calls['exec'].append(argv)
        return types.SimpleNamespace(returncode=exec_rc, stdout='', stderr='denied' if exec_rc else '')

    ns = {
        'os': types.SimpleNamespace(path=types.SimpleNamespace(join=os.path.join, lexists=lambda p: True),
                                    remove=lambda p: calls['exec'].append(['os.remove', p])),
        'subprocess': types.SimpleNamespace(run=_run),
        're': re, 'BrokerError': BrokerError,
        '_GD_OPTIONAL_SCRIPTS': frozenset(_app_constant('_GD_OPTIONAL_SCRIPTS')),
        '_GD_PLACEHOLDER_RE': B._GD_PLACEHOLDER_RE,
        '_broker_should_route': lambda: True, '_broker_available': lambda: True,
        '_broker_request': _broker_request,
        '_sudo_wrap': lambda argv: ['brokerctl', 'exec', '--'] + list(argv),
        '_read_priv': lambda p: (_ for _ in ()).throw(OSError('absent')),
        '_chmod_priv': lambda p, m: None,
        '_write_priv': lambda p, c, perm=None: calls['write'].append((p, c, perm)),
    }
    exec('\n\n'.join(src), ns)
    return ns, calls


@pytest.mark.parametrize('name', OPTIONAL)
def test_install_falls_back_on_a_broker_that_predates_2b(name):
    ns, calls = _console(lambda req: {'ok': False, 'code': 'DENIED',
                                      'error': _OLD_RENDER_REFUSAL % req['name']})
    assert ns['_gd_install_script'](name, 'echo hi\n', {}) is True
    assert calls['write'] == [('/opt/tak-guarddog/' + name, 'echo hi\n', 0o755)]


def test_install_still_raises_for_a_normal_script_the_broker_refuses():
    ns, calls = _console(lambda req: {'ok': False, 'code': 'DENIED',
                                      'error': _OLD_RENDER_REFUSAL % req['name']})
    with pytest.raises(RuntimeError, match='not installed'):
        ns['_gd_install_script']('tak-disk-watch.sh', 'echo hi\n', {})
    assert calls['write'] == []


def test_install_still_raises_when_this_broker_refuses_a_value():
    """A refusal from the current broker (a bad value) is never sidestepped."""
    with_bad = {'op': 'gd_render', 'name': 'mediamtx-cert-sync.sh',
                'values': {'MTX_HOST_PLACEHOLDER': '-oProxyCommand=x'}}
    verdict, reason = B._evaluate(with_bad)
    assert verdict == 'DENY'
    ns, calls = _console(lambda req: {'ok': False, 'code': 'DENIED', 'error': reason})
    with pytest.raises(RuntimeError, match='not installed'):
        ns['_gd_install_script']('mediamtx-cert-sync.sh', 'x', with_bad['values'])
    assert calls['write'] == []


def test_install_falls_back_when_the_older_copy_lacks_a_template():
    ns, calls = _console(lambda req: {'ok': False, 'code': 'ENOENT',
                                      'error': 'no Guard Dog template new.sh in commit 85d4f8e62b8c'})
    assert ns['_gd_install_script']('new.sh', 'echo hi\n', {}) is True
    assert len(calls['write']) == 1


def test_remove_on_a_broker_without_gd_remove_asks_it_with_rm():
    """Before: os.remove as takwerx in root's folder, which fails on the root layout."""
    ns, calls = _console(lambda req: {'ok': False, 'code': 'DENIED', 'error': 'unknown op: gd_remove'})
    assert ns['_gd_remove_script']('sms_send.sh') is True
    assert calls['exec'] == [['brokerctl', 'exec', '--', 'rm', '-f', '/opt/tak-guarddog/sms_send.sh']]
    B.check_exec(['rm', '-f', '/opt/tak-guarddog/sms_send.sh'])   # this broker allows it too


def test_remove_on_an_older_broker_reports_a_refused_rm():
    ns, calls = _console(lambda req: {'ok': False, 'code': 'DENIED', 'error': 'unknown op: gd_remove'},
                         exec_rc=1)
    with pytest.raises(RuntimeError, match='not removed'):
        ns['_gd_remove_script']('sms_send.sh')


def test_remove_raises_when_this_broker_refuses():
    ns, calls = _console(lambda req: {'ok': False, 'code': 'DENIED', 'error': 'gd_remove: not an optional'})
    with pytest.raises(RuntimeError, match='not removed'):
        ns['_gd_remove_script']('sms_send.sh')
    assert calls['exec'] == []
