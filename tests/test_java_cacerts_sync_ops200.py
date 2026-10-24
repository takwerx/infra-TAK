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
"""Ubuntu's Java CA keystore follows the OS trust store (ops #200).

test8, 2026-10-23: /etc/ssl/certs/java/cacerts still trusted 43 roots that the OS store had
dropped and lacked 17 it had added, because update-ca-certificates never tells
ca-certificates-java's hook about a root a package update removes. The broker op
`java_cacerts_sync` works out the difference and feeds it to that hook.
"""

import ast
import importlib.util
import os
import pathlib
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops200',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Box:
    """A fake Ubuntu: /etc/ssl/certs links into a CA source dir, a keystore file, and a
    keytool + hook that read and change an in-memory alias set."""

    def __init__(self, tmp, system, java, hook_rc=0, break_keystore=False):
        self.src = tmp / 'usr-share-ca-certificates' / 'mozilla'
        self.src.mkdir(parents=True)
        self.certs = tmp / 'etc-ssl-certs'
        self.certs.mkdir()
        for name in system:
            crt = self.src / (name[:-4] + '.crt')
            crt.write_text('cert')
            (self.certs / name).symlink_to(crt)
        # things in /etc/ssl/certs that are not roots: the bundle and a hash link
        (self.certs / 'ca-certificates.crt').write_text('bundle')
        if system:
            (self.certs / 'abcd1234.0').symlink_to(self.certs / system[0])
        self.keystore = tmp / 'cacerts'
        self.keystore.write_text('keystore-v1')
        self.backup = tmp / 'backups' / 'infratak-java-cacerts.bak'
        self.java = set(java)
        self.hook_rc = hook_rc
        self.break_keystore = break_keystore
        self.feeds = []

    def run(self, argv, **kw):
        if argv[0] == 'KEYTOOL':
            if self.keystore.read_text() == 'corrupt':
                return types.SimpleNamespace(returncode=1, stdout='', stderr='keytool error')
            out = 'Keystore type: JKS\n\nYour keystore contains %d entries\n\n' % len(self.java)
            out += ''.join(f'debian:{a}, Mar 13, 2026, trustedCertEntry, \n'
                           f'Certificate fingerprint (SHA-256): AA:BB\n' for a in sorted(self.java))
            out += 'mykey, Mar 13, 2026, trustedCertEntry, \n'   # an operator import, not ours
            return types.SimpleNamespace(returncode=0, stdout=out, stderr='')
        assert argv == ['HOOK'], argv
        self.feeds.append(kw['input'])
        for line in kw['input'].splitlines():
            name = os.path.basename(line[1:]).lower()
            if line[0] == '-':
                self.java.discard(name)
            else:
                self.java.add(name)
        if self.break_keystore:
            self.keystore.write_text('corrupt')
        return types.SimpleNamespace(returncode=self.hook_rc, stdout='done.', stderr='')

    def wire(self, m, supported=True):
        m.SYSTEM_CERTS_DIR = str(self.certs)
        m._SYSTEM_CA_SOURCES = (os.path.realpath(self.src.parent) + '/',)
        m.JAVA_CACERTS = str(self.keystore)
        m.JAVA_CACERTS_HOOK = 'HOOK'
        m.JAVA_CACERTS_BACKUP = str(self.backup)
        m._sudoers_safe_binaries = lambda name: ['KEYTOOL']
        m._java_cacerts_settings = lambda: (True, 'changeit')
        if supported:
            m._java_cacerts_supported = lambda: (True, '')
        m.subprocess = types.SimpleNamespace(run=self.run, TimeoutExpired=TimeoutError)
        m._JAVA_CACERTS_MIN_SYSTEM_ROOTS = 3


def _roots(n, prefix='root'):
    return [f'{prefix}_{i}.pem' for i in range(n)]


def test_stale_roots_removed_and_missing_roots_added(tmp_path):
    m = _broker()
    system = ['Kept_Root.pem', 'Also_Kept.pem', 'New_Root_2026.pem']
    box = _Box(tmp_path, system, java=['kept_root.pem', 'also_kept.pem', 'distrusted_root.pem'])
    box.wire(m)
    r = m._do_java_cacerts_sync({})
    assert r['ok'] is True
    assert r['removed'] == ['distrusted_root.pem']
    assert r['added'] == ['New_Root_2026.pem']
    assert r['still_stale'] == [] and r['still_missing'] == []
    # exactly one hook run, in update-ca-certificates' own line protocol
    assert box.feeds == [f'-{box.certs}/distrusted_root.pem\n+{box.certs}/New_Root_2026.pem\n']
    assert box.backup.read_text() == 'keystore-v1'
    assert box.java == {'kept_root.pem', 'also_kept.pem', 'new_root_2026.pem'}


def test_in_step_keystore_is_left_alone(tmp_path):
    m = _broker()
    box = _Box(tmp_path, ['A.pem', 'B.pem', 'C.pem'], java=['a.pem', 'b.pem', 'c.pem'])
    box.wire(m)
    assert m._do_java_cacerts_sync({}) == {'ok': True, 'removed': [], 'added': []}
    assert box.feeds == [] and not box.backup.exists()


def test_operator_aliases_are_never_touched(tmp_path):
    m = _broker()
    box = _Box(tmp_path, ['A.pem', 'B.pem', 'C.pem'], java=['a.pem', 'b.pem', 'c.pem'])
    box.wire(m)
    stale, missing, n = m._java_cacerts_drift('KEYTOOL', 'changeit')
    # `mykey` (no debian: prefix) is in the listing but is not ours to judge
    assert (stale, missing, n) == ([], [], 3)


def test_hash_links_and_bundle_are_not_roots(tmp_path):
    m = _broker()
    box = _Box(tmp_path, ['A.pem', 'B.pem', 'C.pem'], java=[])
    box.wire(m)
    _, missing, n = m._java_cacerts_drift('KEYTOOL', 'changeit')
    assert missing == ['A.pem', 'B.pem', 'C.pem'] and n == 3


def test_links_outside_the_ca_source_dirs_are_ignored(tmp_path):
    m = _broker()
    box = _Box(tmp_path, ['A.pem', 'B.pem', 'C.pem'], java=['a.pem', 'b.pem', 'c.pem'])
    stray = tmp_path / 'elsewhere.crt'
    stray.write_text('cert')
    (box.certs / 'Stray.pem').symlink_to(stray)
    box.wire(m)
    assert m._java_cacerts_drift('KEYTOOL', 'changeit')[1] == []


def test_refuses_to_sync_down_to_a_broken_system_store(tmp_path):
    m = _broker()
    box = _Box(tmp_path, ['A.pem'], java=_roots(140))
    box.wire(m)
    r = m._do_java_cacerts_sync({})
    assert r['ok'] is False and 'refusing' in r['error']
    assert box.feeds == [] and len(box.java) == 140


def test_unreadable_keystore_after_the_hook_is_restored(tmp_path):
    m = _broker()
    box = _Box(tmp_path, ['A.pem', 'B.pem', 'C.pem'], java=['a.pem', 'b.pem', 'c.pem', 'old.pem'],
               break_keystore=True)
    box.wire(m)
    r = m._do_java_cacerts_sync({})
    assert r['ok'] is False and 'restored' in r['error']
    assert box.keystore.read_text() == 'keystore-v1'


def test_hook_failure_is_reported(tmp_path):
    m = _broker()
    box = _Box(tmp_path, ['A.pem', 'B.pem', 'C.pem'], java=['a.pem', 'b.pem', 'c.pem', 'old.pem'],
               hook_rc=1)
    box.wire(m)
    r = m._do_java_cacerts_sync({})
    assert r['ok'] is False and 'hook rc 1' in r['error']


def test_unsupported_box_is_a_skip_not_a_denial(tmp_path):
    m = _broker()
    target = tmp_path / 'pki-java-cacerts'
    target.write_text('x')
    link = tmp_path / 'cacerts'
    link.symlink_to(target)
    m.JAVA_CACERTS = str(link)                       # RHEL layout
    assert m._evaluate({'op': 'java_cacerts_sync'}) == ('ALLOW', '')
    r = m._do_java_cacerts_sync({})
    assert r['ok'] is True and 'symlink' in r['skipped']
    m.JAVA_CACERTS = str(tmp_path / 'absent')        # no Java on the host
    assert 'no Java CA keystore' in m._do_java_cacerts_sync({})['skipped']


def test_hook_must_be_root_owned(tmp_path):
    m = _broker()
    ks = tmp_path / 'cacerts'
    ks.write_text('x')
    hook = tmp_path / 'jks-keystore'
    hook.write_text('#!/bin/sh\n')
    m.JAVA_CACERTS = str(ks)
    m.JAVA_CACERTS_HOOK = str(hook)
    ok, why = m._java_cacerts_supported()
    if os.getuid() != 0:
        assert not ok and 'root-owned' in why


@pytest.mark.parametrize('text, want', [
    ("cacerts_updates=yes\n#storepass=''\n", (True, 'changeit')),
    ("cacerts_updates=no\n", (False, 'changeit')),
    ("cacerts_updates=yes\nstorepass='s3cret!'\n", (True, 's3cret!')),
    ("", (False, 'changeit')),                       # the hook does nothing without =yes
])
def test_defaults_file_read_like_the_hook(tmp_path, text, want):
    m = _broker()
    f = tmp_path / 'cacerts'
    f.write_text(text)
    m.JAVA_CACERTS_DEFAULTS = str(f)
    assert m._java_cacerts_settings() == want


def test_dispatch_runs_the_op_and_audits_it(tmp_path):
    m = _broker()
    seen = []
    m.audit = lambda peer, op, summary, verdict, detail='': seen.append((op, summary, verdict))
    m._do_java_cacerts_sync = lambda req: {'ok': True, 'removed': ['x.pem'], 'added': []}
    assert m._dispatch({'op': 'java_cacerts_sync'}, None)['removed'] == ['x.pem']
    assert seen == [('java_cacerts_sync', m.JAVA_CACERTS, 'ALLOW')]


# ── console side ────────────────────────────────────────────────────────────

def _fn(name):
    for n in ast.parse(APP).body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    raise AssertionError(f'{name} was renamed or removed')


def _load(name, ns):
    exec(compile(ast.get_source_segment(APP, _fn(name)), 'app.py', 'exec'), ns)
    return ns[name]


def test_console_sends_an_argument_free_request():
    sent, logs = [], []
    ns = {
        'os': types.SimpleNamespace(getuid=lambda: 1001, path=types.SimpleNamespace(isdir=lambda p: True)),
        '_broker_should_route': lambda: True,
        '_broker_available': lambda: True,
        '_broker_request': lambda req, timeout=600: sent.append(req) or {
            'ok': True, 'removed': ['a.pem', 'b.pem'], 'added': ['c.pem'], 'backup': '/var/backups/x'},
        '_tak_is_container': lambda: False,
    }
    fn = _load('_sync_java_cacerts', ns)
    fn(log_fn=logs.append)
    assert sent == [{'op': 'java_cacerts_sync'}]
    assert len(logs) == 1 and 'removed 2' in logs[0] and 'added 1' in logs[0]
    assert 'next restart' in logs[0]


def test_console_is_quiet_on_a_skipped_box():
    logs = []
    ns = {
        'os': types.SimpleNamespace(getuid=lambda: 1001),
        '_broker_should_route': lambda: True,
        '_broker_available': lambda: True,
        '_broker_request': lambda req, timeout=600: {'ok': True, 'skipped': 'symlink'},
    }
    _load('_sync_java_cacerts', ns)(log_fn=logs.append)
    assert logs == []


def test_root_console_runs_the_broker_function_in_process():
    calls = []
    mod = types.SimpleNamespace(
        _check_java_cacerts_sync=lambda req: calls.append(('check', req)),
        _do_java_cacerts_sync=lambda req: calls.append(('do', req)) or {'ok': True, 'removed': [], 'added': []})
    ns = {
        'os': types.SimpleNamespace(getuid=lambda: 0),
        '_broker_should_route': lambda: False,
        '_broker_available': lambda: False,
        '_broker_module': lambda: mod,
    }
    _load('_sync_java_cacerts', ns)(log_fn=lambda m: None)
    assert calls == [('check', {}), ('do', {})]


def test_runs_from_startup_migrations():
    called = {n.func.id for n in ast.walk(_fn('_startup_migrations'))
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert '_sync_java_cacerts' in called


# ── container TAK: the JDK's own bundled cacerts ────────────────────────────

G3_TEMURIN = 'cn_emsign_ecc_root_ca__g3,o_emudhra_technologies_limited,ou_emsign_pki,c_in [jdk]'

HARDENED = '''ARG BASE_REGISTRY=docker.io
FROM ${BASE_REGISTRY}/${BASE_DEPLOY_IMAGE}:${BASE_DEPLOY_TAG} AS deploy_container
RUN microdnf update -y --disableplugin=subscription-manager --nodocs
USER tak:0
'''


def _consts():
    ns = {}
    for n in ast.parse(APP).body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in ('_JDK_DISTRUSTED_CA_ALIASES',
                                                                     '_JDK_DISTRUST_MARK') for t in n.targets):
            exec(compile(ast.get_source_segment(APP, n), 'app.py', 'exec'), ns)
    return ns


def test_g3_is_in_the_jdk_distrust_list():
    assert G3_TEMURIN in _consts()['_JDK_DISTRUSTED_CA_ALIASES']


def _dockerfile_patcher():
    import re
    import shlex
    ns = {'os': os, 're': re, 'shlex': shlex, **_consts()}
    return _load('_patch_tak_dockerfile_cacerts', ns)


def test_dockerfile_gets_the_drop_before_tak_steps_and_user_switch(tmp_path):
    (tmp_path / 'docker').mkdir()
    df = tmp_path / 'docker' / 'Dockerfile.hardened-takserver'
    df.write_text(HARDENED)
    logs = []
    patch = _dockerfile_patcher()
    assert patch(str(tmp_path), 'docker/Dockerfile.hardened-takserver', logs.append) is True
    out = df.read_text().splitlines()
    i = out.index('FROM ${BASE_REGISTRY}/${BASE_DEPLOY_IMAGE}:${BASE_DEPLOY_TAG} AS deploy_container')
    assert out[i + 1] == '# infra-TAK: CA trust store update'
    assert out[i + 2].startswith('RUN keytool -delete -cacerts ') and out[i + 2].endswith(' ; true')
    assert out.index('USER tak:0') > i + 2
    # everything TAK shipped is still there, in order
    assert [l for l in out if l not in out[i + 1:i + 3]] == HARDENED.splitlines()
    assert logs and 'CA trust store update' in logs[0]
    # idempotent: a rebuild of the same bundle does not stack a second step
    assert patch(str(tmp_path), 'docker/Dockerfile.hardened-takserver', logs.append) is False
    assert df.read_text().count('keytool -delete') == 1


def test_dockerfile_run_line_deletes_the_exact_alias(tmp_path):
    """Run the generated RUN through /bin/sh with a stand-in keytool: the alias (commas,
    spaces, brackets) must arrive as one argv word, and a missing alias must not fail."""
    import subprocess
    (tmp_path / 'docker').mkdir()
    df = tmp_path / 'docker' / 'Dockerfile.takserver'
    df.write_text('FROM eclipse-temurin:17-jammy\nRUN true\n')
    _dockerfile_patcher()(str(tmp_path), 'docker/Dockerfile.takserver', lambda m: None)
    run = [l for l in df.read_text().splitlines() if l.startswith('RUN keytool')][0][4:]
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    rec = tmp_path / 'argv'
    kt = bindir / 'keytool'
    kt.write_text(f'#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a" >> {rec}; done\nexit 1\n')
    kt.chmod(0o755)
    r = subprocess.run(['/bin/sh', '-c', run], env={'PATH': f'{bindir}:/usr/bin:/bin'})
    assert r.returncode == 0                          # keytool's "does not exist" is not a build failure
    assert rec.read_text().splitlines() == ['-delete', '-cacerts', '-storepass', 'changeit', '-alias', G3_TEMURIN]


def test_dockerfile_we_cannot_read_builds_as_shipped(tmp_path):
    assert _dockerfile_patcher()(str(tmp_path), 'docker/Dockerfile.missing', lambda m: None) is False


def test_both_tak_image_builds_apply_the_patch():
    # deploy and upgrade each build the takserver image; both must patch it first
    assert APP.count('_patch_tak_dockerfile_cacerts(build_ctx, _app_df') == 1
    assert APP.count('_patch_tak_dockerfile_cacerts(new_ctx, _app_df') == 1
    for ctx in ('build_ctx', 'new_ctx'):
        at = APP.index(f'_patch_tak_dockerfile_cacerts({ctx}, _app_df')
        assert at < APP.index('docker build -t {TAK_CONTAINER}', at)


class _Exec:
    def __init__(self, listing_rc, listing_out='', delete_rc=0):
        self.listing_rc, self.listing_out, self.delete_rc = listing_rc, listing_out, delete_rc
        self.calls = []

    def run(self, argv, **kw):
        self.calls.append(argv)
        if '-list' in argv:
            return types.SimpleNamespace(returncode=self.listing_rc, stdout=self.listing_out, stderr='')
        return types.SimpleNamespace(returncode=self.delete_rc, stdout='', stderr='')


def _container_dropper(fake):
    ns = {'subprocess': types.SimpleNamespace(run=fake.run), '_sudo_wrap': lambda c: list(c),
          'TAK_CONTAINER': 'takserver', **_consts()}
    return _load('_tak_container_drop_distrusted_cas', ns)


def test_running_container_has_g3_removed_as_root_without_a_shell():
    fake = _Exec(listing_rc=0, listing_out=f'{G3_TEMURIN}, Feb 18, 2018, trustedCertEntry,')
    assert _container_dropper(fake)() == [G3_TEMURIN]
    assert fake.calls[1] == ['docker', 'exec', '-u', '0', 'takserver', 'keytool', '-delete', '-cacerts',
                             '-storepass', 'changeit', '-alias', G3_TEMURIN]


def test_clean_container_is_left_alone():
    fake = _Exec(listing_rc=1, listing_out=f'keytool error: java.lang.Exception: Alias <{G3_TEMURIN}> does not exist')
    assert _container_dropper(fake)() == []
    assert len(fake.calls) == 1


def test_stopped_container_is_quiet_and_retried_later():
    logs = []
    fake = _Exec(listing_rc=1, listing_out='Error response from daemon: container abc is not running')
    assert _container_dropper(fake)(logs.append) is None
    assert logs == []


def test_startup_runs_the_container_cleanup_for_container_tak():
    called = {n.func.id for n in ast.walk(_fn('_startup_migrations'))
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert '_tak_container_drop_distrusted_cas' in called
