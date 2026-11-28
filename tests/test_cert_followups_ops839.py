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
"""Follow-ups to the CA key work (ops #839).

1. A restore of a Docker TAK Server reads the container's user ids while the container
   still runs, and never invents 1000:0 when it cannot ask.
2. A Federation Hub on another host gets its CA signing keystores closed after the
   certificate step (deploy and Rotate CA), the same as the TAK Server's own (ops #831).
3. The console steps that act on a file by name inside the certificate folder (download,
   listing, privileged read, ownership) do not follow a link planted there.
"""

import ast
import os
import pathlib
import re
import shlex
import stat
import subprocess

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _assign(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _load(ns, funcs, globs=(), fix=None):
    for g in globs:
        exec(compile(_assign(g), 'app.py', 'exec'), ns)
    for f in funcs:
        src = _func(f)
        if fix:
            src = fix(src)
        exec(compile(src, 'app.py', 'exec'), ns)
    return ns


class _Done(Exception):
    """Raised by a stub to end a long function where the test has seen what it needs."""


# ── 1. container ids ─────────────────────────────────────────────────────────────────────────

class _Docker:
    """A stand-in for the docker CLI: a TAK container that runs as 1001:0, running or stopped."""

    def __init__(self, running=True, user='tak', inspect_ok=True, image_ok=True):
        self.running, self.user, self.inspect_ok, self.image_ok = running, user, inspect_ok, image_ok
        self.calls = []

    def run(self, args, **kw):
        self.calls.append(list(args) if not isinstance(args, str) else args)
        out, rc = '', 0
        if isinstance(args, str):                       # `docker stop takserver` through the shell
            if args.startswith('docker stop'):
                self.running = False
            return subprocess.CompletedProcess(args, 0, '', '')
        a = list(args)
        if a[:2] == ['docker', 'exec']:
            if not self.running:
                return subprocess.CompletedProcess(args, 1, '', 'Error: container is not running')
            out = '1001' if a[-1] == '-u' else '0'
        elif a[:2] == ['docker', 'inspect']:
            if not self.inspect_ok:
                return subprocess.CompletedProcess(args, 1, '', 'No such object')
            out = f'takserver:5.8-hardened|{self.user}'
        elif a[:2] == ['docker', 'run']:
            assert '--network' in a and a[a.index('--network') + 1] == 'none'
            assert a[a.index('--entrypoint') + 1] == 'id'
            if not self.image_ok:
                return subprocess.CompletedProcess(args, 125, '', 'Unable to find image')
            if self.user:
                assert a[a.index('--user') + 1] == self.user
            out = '1001' if a[-1] == '-u' else '0'
        return subprocess.CompletedProcess(args, rc, out + '\n', '')


class _FakeSubprocess:
    TimeoutExpired = subprocess.TimeoutExpired
    CompletedProcess = subprocess.CompletedProcess
    PIPE = subprocess.PIPE

    def __init__(self, docker, other=None):
        self.docker, self.other, self.all = docker, other, []

    def run(self, args, **kw):
        self.all.append(args)
        a = args if isinstance(args, str) else list(args)
        if isinstance(a, str) or a[0] == 'docker':
            return self.docker.run(a, **kw)
        return subprocess.CompletedProcess(args, 0, '', '')


def _ids_ns(docker):
    sub = _FakeSubprocess(docker)
    ns = {'subprocess': sub, 're': re, 'os': os, 'TAK_CONTAINER': 'takserver', '_sudo_wrap': lambda c: list(c)}
    _load(ns, ['_tak_container_ids'])
    return ns, sub


def test_ids_of_a_running_container():
    ns, _ = _ids_ns(_Docker(running=True))
    assert ns['_tak_container_ids']() == ('1001', '0')


def test_ids_of_a_stopped_container_are_still_the_containers_not_1000():
    """A restore asks after `docker stop`; `docker exec` fails then."""
    ns, sub = _ids_ns(_Docker(running=False))
    assert ns['_tak_container_ids']() == ('1001', '0')


def test_ids_with_no_user_set_in_the_container_config():
    ns, _ = _ids_ns(_Docker(running=False, user=''))
    assert ns['_tak_container_ids']() == ('1001', '0')


def test_ids_that_cannot_be_read_are_none_never_a_number():
    for kw in ({'running': False, 'inspect_ok': False, 'image_ok': False}, {'running': False, 'image_ok': False}):
        ns, _ = _ids_ns(_Docker(**kw))
        assert ns['_tak_container_ids']() == (None, None), kw


def test_docker_options_from_inspect_are_not_passed_on_when_odd():
    d = _Docker(running=False, user='tak; rm -rf /')
    ns, sub = _ids_ns(d)
    ns['_tak_container_ids']()
    runs = [c for c in d.calls if c[:2] == ['docker', 'run']]
    assert all('rm -rf' not in ' '.join(c) for c in runs)


def _rollback_ns(tmp_path, docker, ids_stub=None):
    """_tak_rollback up to the end of the certificate restore (step 5): a stub ends it there."""
    snaps = tmp_path / 'snapshots'
    snap = snaps / 'snap1'
    (snap / 'certs').mkdir(parents=True)
    (snap / 'cot.pgdump').write_bytes(b'x')
    (snap / 'UserAuthenticationFile.xml').write_text('<x/>')
    sub = _FakeSubprocess(docker)
    lines = []
    cfg_calls = {'n': 0}

    def _cfg(_settings):
        # ops #1337: the first call is the early look at the deployment (before TAK stops); the
        # second one is step 6 (pg_restore), where this stub ends the run.
        cfg_calls['n'] += 1
        if cfg_calls['n'] > 1:
            raise _Done()
        return {'mode': 'single_server'}

    ns = {
        'subprocess': sub, 'os': os, 're': re, 'shlex': shlex, 'SNAPSHOT_DIR': str(snaps), 'TAK_CONTAINER': 'takserver',
        '_sudo_wrap': lambda c: list(c), '_validate_snapshot_label': lambda l: (True, l),
        '_tak_is_container': lambda: True,
        '_tak_systemctl': lambda action: f'docker {action} takserver',
        '_tak_ca_private_lockdown': lambda plog=None, **kw: ([], []),
        'load_settings': lambda: {},
        '_get_tak_deployment_config': _cfg,
        '_tak_snapshot': lambda label, plog=None: (True, {'db_dump': True}),
        '_tak_prune_snapshots': lambda source, keep: None,
        'datetime': __import__('datetime').datetime,
    }
    _load(ns, ['_tak_container_ids', '_tak_swap_certs', '_tak_rollback'])
    if ids_stub:
        ns['_tak_container_ids'] = ids_stub
    return ns, sub, lines


def _chowns(sub):
    return [a for a in sub.all if not isinstance(a, str) and a[0] == 'chown']


def test_restore_chowns_the_certificate_folder_to_the_containers_user_not_1000(tmp_path):
    ns, sub, lines = _rollback_ns(tmp_path, _Docker(running=True))
    with pytest.raises(_Done):
        ns['_tak_rollback']('snap1', lines.append)
    owners = [c for c in _chowns(sub)]
    assert owners, 'the restore did not set an owner at all'
    assert all(any(x == '1001:0' for x in c) for c in owners), owners
    assert not any('1000:0' in c for c in owners), owners
    # -h: a link in the folder is re-owned itself, never what it points at
    folder = [c for c in owners if '/opt/tak/certs/files' in c]
    assert folder and all('-h' in c for c in folder), folder


def test_restore_reads_the_ids_before_it_stops_the_container(tmp_path):
    docker = _Docker(running=True)
    seen = []

    def ids():
        seen.append(docker.running)
        return '1001', '0'

    ns, sub, lines = _rollback_ns(tmp_path, docker, ids_stub=ids)
    with pytest.raises(_Done):
        ns['_tak_rollback']('snap1', lines.append)
    assert seen and seen[0] is True, 'the ids were asked after the container stopped'


def test_restore_leaves_owners_alone_when_the_ids_are_unknown(tmp_path):
    ns, sub, lines = _rollback_ns(tmp_path, _Docker(running=True), ids_stub=lambda: (None, None))
    with pytest.raises(_Done):
        ns['_tak_rollback']('snap1', lines.append)
    assert _chowns(sub) == [], _chowns(sub)
    assert any('could not be read' in m for m in lines), lines


def _lockdown_ns(ids):
    calls = []

    def _record(args, **kw):
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, '', '')

    class Sub:
        TimeoutExpired = subprocess.TimeoutExpired
        CompletedProcess = subprocess.CompletedProcess
        PIPE = subprocess.PIPE
        run = staticmethod(_record)

    ns = {'subprocess': Sub, 'os': os, 're': re, 'shlex': shlex, '_stat': stat, 'hashlib': __import__('hashlib'),
          'threading': __import__('threading'), 'TAK_CONTAINER': 'takserver', '_tak_is_container': lambda: True,
          '_tak_container_ids': lambda: ids, '_sudo_wrap': lambda c: list(c), 'audit': lambda *a, **k: None,
          '_CERT_FILES_DIR': '/nonexistent'}
    _load(ns, ['_is_ca_private_material', '_ca_key_stem', '_ca_file_stem', '_ca_names_from_listing',
               '_ca_private_files', '_tak_ca_private_lockdown'] if '_ca_names_from_listing' in APP else
          ['_is_ca_private_material', '_ca_key_stem', '_ca_file_stem', '_ca_private_files', '_tak_ca_private_lockdown'],
          globs=['_CA_SCAN_LOCK', '_CA_SCAN_FACTS', '_CA_SCAN_DIRS', '_CA_CERT_EXTS', '_CA_KEYSTORE_EXTS',
                 '_CA_NAME_LEFTOVER_RE', '_CA_SCAN_MAX_BYTES'])
    return ns, calls


def test_ca_key_lockdown_does_not_chown_to_a_guessed_user(tmp_path):
    d = tmp_path / 'files'
    d.mkdir()
    f = d / 'INT-CA-01-signing.jks'
    f.write_bytes(b'x')
    os.chmod(f, 0o644)
    ns, calls = _lockdown_ns((None, None))
    ns['_tak_ca_private_lockdown'](lambda m: None, cert_dir=str(d))
    assert [c for c in calls if c[0] == 'chown'] == [], calls
    assert [c for c in calls if c[0] == 'docker'] == [], calls       # no blind chmod inside the image either
    assert stat.S_IMODE(f.stat().st_mode) == 0o644                   # left as it was: not shown to be safe


# ── 2. Federation Hub on another host ─────────────────────────────────────────────────────────

FEDHUB_FILES = ['FEDHUB-INT-CA-01-signing.jks', 'FEDHUB-INT-CA-01-signing.p12', 'FEDHUB-INT-CA-01.pem',
                'FEDHUB-INT-CA-01.key', 'FEDHUB-INT-CA-01.crl', 'FEDHUB-ROOT-CA-do-not-share.key',
                'ca-do-not-share.key', 'ca.pem', 'truststore-FEDHUB-INT-CA-01.jks',
                'fedhub1.jks', 'fedhub1.pem', 'webadmin-fed.p12', 'webadmin-fed.pem', 'webadmin-fed.key']
FEDHUB_CLOSED = ['FEDHUB-INT-CA-01-signing.jks', 'FEDHUB-INT-CA-01-signing.p12', 'FEDHUB-INT-CA-01.key',
                 'FEDHUB-ROOT-CA-do-not-share.key',
                 'ca-do-not-share.key']


def _fedhub_folder(tmp_path):
    d = tmp_path / 'federation-hub' / 'certs' / 'files'
    d.mkdir(parents=True)
    for n in FEDHUB_FILES:
        (d / n).write_bytes(b'x')
        os.chmod(d / n, 0o644)            # what makeCert.sh leaves
    secret = tmp_path / 'secret'
    secret.write_bytes(b's')
    os.chmod(secret, 0o644)
    os.symlink(secret, d / 'x-signing.jks')    # a link is never followed
    return d, secret


def _fedhub_ns(tmp_path):
    """_fedhub_ca_lockdown with the remote host being a local shell: `sudo` is dropped and the
    folder is the temporary one (the command a Federation Hub host gets is run as it is)."""
    ran = []
    env = dict(os.environ)
    if os.uname().sysname == 'Darwin':       # BSD stat has no -c: a shim with the one use the command makes
        shim = tmp_path / 'bin'
        shim.mkdir(exist_ok=True)
        (shim / 'stat').write_text('#!/bin/sh\nif [ "$1" = "-c" ] && [ "$2" = "%a" ]; then shift 2; '
                                   'exec /usr/bin/stat -f %Lp "$@"; fi\nexec /usr/bin/stat "$@"\n')
        os.chmod(shim / 'stat', 0o755)
        env['PATH'] = f'{shim}:{env["PATH"]}'

    def module_run(cfg, cmd, timeout=120):
        ran.append(cmd)
        sh = re.sub(r'\bsudo ', '', cmd)
        r = subprocess.run(['/bin/sh', '-c', sh], capture_output=True, text=True, timeout=30, env=env)
        return r.returncode == 0, (r.stdout or '') + (r.stderr or '')

    ns = {'re': re, 'shlex': shlex, 'os': os, '_module_run': module_run, 'audit': lambda *a, **k: None}
    _load(ns, ['_is_ca_private_material', '_ca_key_stem', '_ca_file_stem', '_ca_names_from_listing',
               '_ca_private_names_only', '_fedhub_ca_lockdown'],
          globs=['_CA_CERT_EXTS', '_CA_KEYSTORE_EXTS', '_CA_NAME_LEFTOVER_RE'])
    return ns, ran


def _mode(p):
    return stat.S_IMODE(os.lstat(p).st_mode)


def test_federation_hub_ca_keystores_are_closed_after_the_certificate_step(tmp_path):
    d, secret = _fedhub_folder(tmp_path)
    ns, ran = _fedhub_ns(tmp_path)
    fixed = ns['_fedhub_ca_lockdown']({}, str(tmp_path / 'federation-hub'), lambda m: None)
    assert sorted(f.split()[0] for f in fixed) == sorted(FEDHUB_CLOSED)
    for n in FEDHUB_CLOSED:
        assert _mode(d / n) & 0o077 == 0, n
    # client and server files and the public CA files keep their modes; the link and its target too
    for n in set(FEDHUB_FILES) - set(FEDHUB_CLOSED):
        assert _mode(d / n) == 0o644, n
    assert _mode(secret) == 0o644
    # a second run changes nothing
    assert ns['_fedhub_ca_lockdown']({}, str(tmp_path / 'federation-hub'), lambda m: None) == []


def test_federation_hub_lockdown_command_names_each_file_and_never_a_glob(tmp_path):
    ns, ran = _fedhub_ns(tmp_path)
    out_names = '\n'.join(['a-signing.jks', 'b.key; rm -rf x-signing.p12', 'ok-signing.p12'])
    cmds = []

    def module_run(cfg, cmd, timeout=120):
        cmds.append(cmd)
        return True, out_names if cmd.lstrip().startswith('sudo ls') else ''

    ns['_module_run'] = module_run
    ns['_fedhub_ca_lockdown']({}, '/opt/tak/federation-hub', lambda m: None)
    run = cmds[-1]
    assert 'a-signing.jks' in run and 'ok-signing.p12' in run
    assert 'rm -rf' not in run                         # an odd file name is reported, not run
    assert '[ ! -L ' in run                            # a link is never touched
    assert "'./a-signing.jks'" in run or './a-signing.jks' in run
    assert '-R' not in run                             # no recursive change


def test_federation_hub_deploy_and_rotate_close_the_keystores():
    for fn in ('_fedhub_run_remote_package_install', 'run_fedhub_remote_rotate_ca'):
        src = _func(fn)
        assert '_fedhub_ca_lockdown(cfg, fh_dir' in src, fn
    rot = _func('run_fedhub_remote_rotate_ca')
    assert rot.index('makeRootCa.sh') < rot.index('_fedhub_ca_lockdown(cfg, fh_dir')
    assert rot.index('_fedhub_ca_lockdown(cfg, fh_dir') < rot.index('systemctl restart federation-hub')
    dep = _func('_fedhub_run_remote_package_install')
    assert dep.index('makeRootCa.sh') < dep.index('_fedhub_ca_lockdown(cfg, fh_dir')
    assert dep.index('_fedhub_ca_lockdown(cfg, fh_dir') < dep.index('systemctl restart federation-hub')


# ── 3. links in the certificate folder ───────────────────────────────────────────────────────

def _cert_ns(tmp_path, privileged=None):
    d = tmp_path / 'files'
    d.mkdir(exist_ok=True)
    audits = []
    ns = {'os': os, 're': re, 'subprocess': subprocess, '_stat': stat, 'jsonify': flask.jsonify,
          'audit': lambda ev, detail='', **kw: audits.append((ev, detail)),
          '_sudo_wrap': lambda c: list(c), '_read_priv_bytes': privileged or (lambda p: open(p, 'rb').read()),
          '_ca_private_verdict_or_refuse_all': lambda p: {},
          '_is_ca_private_file': lambda f, p=None, v=None: False}
    fix = lambda src: src.replace("'/opt/tak/certs/files'", repr(str(d)))
    _load(ns, ['_cert_file_bytes', '_send_cert_file_priv', 'list_cert_files', 'download_ca_pem'], fix=fix)
    return ns, d, audits


def _serve(ns, d, name):
    app = flask.Flask('t')
    with app.test_request_context():
        resp = ns['_send_cert_file_priv'](str(d), name)
        if isinstance(resp, tuple):
            return resp[1], resp[0].get_json()
        resp.direct_passthrough = False
        return resp.status_code, resp.get_data()


def test_a_link_in_the_certificate_folder_is_not_served(tmp_path):
    ns, d, audits = _cert_ns(tmp_path)
    secret = tmp_path / 'secret.txt'
    secret.write_text('root only')
    os.symlink(secret, d / 'notes.pem')
    (d / 'admin.p12').write_bytes(b'client file')
    status, body = _serve(ns, d, 'notes.pem')
    assert status == 403, (status, body)
    assert b'root only' not in (body if isinstance(body, bytes) else str(body).encode())
    assert any(a[0] == 'cert_download_refused' for a in audits)
    assert _serve(ns, d, 'admin.p12') == (200, b'client file')       # a client file is served as before
    assert _serve(ns, d, 'gone.pem')[0] == 404


def test_the_privileged_read_does_not_serve_a_file_swapped_for_a_link_meanwhile(tmp_path):
    """Root reads by path: if the file was replaced while it was read, nothing is served."""
    victim = tmp_path / 'secret.txt'
    victim.write_text('root only')

    def privileged_cat(path):
        os.unlink(path)
        os.symlink(victim, path)
        return victim.read_bytes()

    ns, d, _ = _cert_ns(tmp_path)
    f = d / 'client.p12'
    f.write_bytes(b'client')
    os.chmod(f, 0)                                          # the console user cannot open it

    class Sub:
        TimeoutExpired = subprocess.TimeoutExpired

        @staticmethod
        def run(args, **kw):
            return subprocess.CompletedProcess(args, 0, privileged_cat(args[-1]), b'')

    ns['subprocess'] = Sub
    if os.geteuid() == 0:
        pytest.skip('root can open a mode 000 file')
    status, body = _serve(ns, d, 'client.p12')
    assert status == 500, (status, body)


def test_cert_file_bytes_refuses_a_link_and_reads_a_file(tmp_path):
    ns, d, _ = _cert_ns(tmp_path)
    (d / 'a.pem').write_bytes(b'abc')
    secret = tmp_path / 'secret.txt'
    secret.write_bytes(b'root only')
    os.symlink(secret, d / 'b.pem')
    assert ns['_cert_file_bytes'](str(d / 'a.pem')) == b'abc'
    with pytest.raises(OSError):
        ns['_cert_file_bytes'](str(d / 'b.pem'))
    with pytest.raises(FileNotFoundError):
        ns['_cert_file_bytes'](str(d / 'none.pem'))


def test_the_listing_leaves_out_a_link(tmp_path):
    ns, d, _ = _cert_ns(tmp_path)
    (d / 'admin.p12').write_bytes(b'x')
    secret = tmp_path / 'secret.txt'
    secret.write_bytes(b'0' * 5000)
    os.symlink(secret, d / 'notes.pem')
    app = flask.Flask('t')
    with app.test_request_context():
        names = [f['name'] for f in ns['list_cert_files']().get_json()['files']]
    assert names == ['admin.p12']


def test_ca_pem_download_does_not_follow_a_link(tmp_path):
    ns, d, _ = _cert_ns(tmp_path)
    secret = tmp_path / 'secret.txt'
    secret.write_text('root only')
    os.symlink(secret, d / 'ca.pem')
    app = flask.Flask('t')
    with app.test_request_context():
        resp = ns['download_ca_pem']()
    status = resp[1] if isinstance(resp, tuple) else resp.status_code
    assert status == 403
    os.unlink(d / 'ca.pem')
    (d / 'ca.pem').write_bytes(b'-----BEGIN CERTIFICATE-----')
    with app.test_request_context():
        resp = ns['download_ca_pem']()
    resp.direct_passthrough = False
    assert resp.status_code == 200 and resp.get_data() == b'-----BEGIN CERTIFICATE-----'


def test_node_red_heal_changes_regular_files_only():
    src = _func('_heal_nodered_cert_read_access')
    assert "'%F|%a'" in src and "startswith('regular')" in src


def test_cert_folder_ownership_commands_do_not_follow_links():
    """Every chown -R over the certificate folder has -h (a link is re-owned itself)."""
    bad = [m.group(0) for m in re.finditer(r"chown -R [^'\"\n]*?/opt/tak/certs[^'\"\n]*", APP)
           if ' -h ' not in m.group(0)]
    assert bad == [], bad
