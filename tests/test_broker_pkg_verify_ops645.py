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
"""Broker: package installs from a file, and package-manager options (ops #645 W0 part 2).

* A local .deb/.rpm installs only as a copy the broker checked as root: a TAK Server
  package signed with the pinned TAK release key, or the Caddy .deb matching Caddy's
  published SHA-512. Anything else is refused with a plain reason, and a key change at
  TAK.gov says so.
* Options that point the package manager at config, plugins or packages of the
  caller's choosing are refused; the options the console uses still pass.

The signature tests make a throwaway GnuPG key and build small .deb files; nothing is
installed.
"""

import base64
import gzip
import hashlib
import importlib.util
import io
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
H = '/home/takwerx'


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops645_pkg',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()


# --- rulebook: options and file shapes --------------------------------------------------

ESCAPES = [
    # dnf config file / plugin path / root of the caller's choosing
    ['dnf', '--config=/home/takwerx/dnf.conf', 'install', 'x'],
    ['yum', '--config=/tmp/y.conf', 'install', 'x'],
    ['dnf', '--installroot=/tmp/r', 'install', 'x'],
    ['dnf', '--setopt=reposdir=/tmp/repos', 'install', 'x'],
    # a repo of the caller's choosing, unsigned
    ['dnf', '--repofrompath=evil,/home/takwerx/repo', '--enablerepo=evil', 'install', 'x'],
    ['dnf', '--nogpgcheck', 'install', 'x'],
    ['dnf', '--enableplugin=evil', 'install', 'x'],
    ['dnf', '--downloaddir=/etc/cron.d', '--downloadonly', 'install', 'x'],
    ['apt-get', '--allow-unauthenticated', 'install', 'x'],
    ['apt-get', '--allow-insecure-repositories', 'update'],
    ['apt-get', '--force-yes', 'install', 'x'],
    ['apt-get', '-t', 'evil', 'install', 'x'],
    ['dnf', 'config-manager', '--add-repo', 'https://evil.example/x.repo'],
    ['dnf', 'config-manager', '--add-repo', '/home/takwerx/x.repo'],
    ['dnf', 'copr', 'enable', 'evil/repo'],
    # local "packages" that are not package files
    ['apt-get', 'install', './'],
    ['apt-get', 'install', '/home/takwerx/src/'],
    ['apt-get', 'install', './x.dsc'],
    ['apt-get', 'install', '-y', './x.rpm'],
    ['dnf', 'install', '-y', './x.deb'],
    ['dnf', 'install', '/usr/bin/semanage'],
    ['dnf', 'install', '--enablerepo=/tmp/x', 'y'],
]

LEGIT = [
    ['apt-get', 'install', '-y', 'caddy'],
    ['apt-get', 'install', '-y', '--allow-downgrades', './takserver_5.8-RELEASE84_all.deb'],
    ['apt-get', 'install', '-y', '/tmp/caddy-deb-x/caddy_2.10.2_linux_amd64.deb'],
    ['apt-get', 'install', '--reinstall', '-y', 'caddy'],
    ['apt-get', 'install', '-y', '--no-install-recommends', 'ca-certificates'],
    ['apt-get', '-qq', 'update'],
    ['apt-get', '-qy', 'install', 'fail2ban'],
    ['apt-get', '-f', 'install', '-y'],
    ['apt-get', 'remove', '--purge', '-y', 'takserver'],
    ['apt', 'list', '--upgradable'],
    ['apt', 'install', '-y', './takserver_5.8-RELEASE84_all.deb'],
    ['dnf', 'install', '-y', './takserver-5.8-RELEASE84.noarch.rpm',
     '--setopt=clean_requirements_on_remove=false'],
    ['dnf', '-y', 'install', '/opt/infratak/uploads/takserver-core-5.8-RELEASE84.noarch.rpm'],
    ['dnf', 'reinstall', '-y', '/opt/infratak/uploads/takserver-5.8-RELEASE84.noarch.rpm'],
    ['dnf', 'install', '-y', 'https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm'],
    ['dnf', 'install', '-y', 'dnf-command(copr)'],
    ['dnf', 'copr', 'enable', '-y', '@caddy/caddy'],
    ['dnf', 'config-manager', '--add-repo', 'https://download.docker.com/linux/centos/docker-ce.repo'],
    ['dnf', 'config-manager', '--set-enabled', 'crb'],
    ['dnf', '-q', '--assumeno', 'check-update', 'caddy'],
    ['dnf', '-C', '-q', 'module', 'list', '--enabled'],
    ['dnf', '-C', 'updateinfo', 'list', '--security'],
    ['dnf', '-C', 'check-update', '--setopt=skip_if_unavailable=True'],
    ['dnf', 'upgrade', '-y', 'caddy'],
    ['dnf', 'remove', '-y', 'takserver', '--setopt=clean_requirements_on_remove=false'],
    ['yum', 'install', '-y', 'fail2ban'],
]


@pytest.mark.parametrize('argv', ESCAPES, ids=lambda a: ' '.join(a)[:70])
def test_pkgmgr_escape_is_denied(argv):
    with pytest.raises(B.Denied):
        B.check_exec(argv, H)


@pytest.mark.parametrize('argv', LEGIT, ids=lambda a: ' '.join(a)[:70])
def test_pkgmgr_console_shape_still_allowed(argv):
    B.check_exec(argv, H)


def test_broker_state_dir_is_not_writable():
    with pytest.raises(B.Denied):
        B._path_allowed('/var/lib/takwerx-broker/pkg-stage/pkg-x/takserver_5.8_all.deb')


@pytest.mark.parametrize('argv,cwd,want', [
    (['apt-get', 'install', '-y', './takserver_5.8-RELEASE84_all.deb'], '/opt/infratak/uploads',
     [(3, '/opt/infratak/uploads/takserver_5.8-RELEASE84_all.deb')]),
    (['dnf', '-y', 'install', '/tmp/x/takserver-5.8.noarch.rpm', 'java-17'], '/',
     [(3, '/tmp/x/takserver-5.8.noarch.rpm')]),
    (['apt', 'install', 'takserver_5.8_all.deb'], '/home/takwerx', [(2, '/home/takwerx/takserver_5.8_all.deb')]),
    (['apt-get', 'install', '-y', 'caddy'], '/', []),
    (['apt-get', 'remove', './x.deb'], '/', []),
    (['dpkg', '-l', 'x.deb'], '/', []),
])
def test_local_package_args_found(argv, cwd, want):
    assert B._pkg_local_files(argv, cwd) == want


# --- the pinned key ---------------------------------------------------------------------

def test_pinned_tak_key_is_the_tak_release_key():
    """The armored key in the broker parses, and its fingerprint is the pinned one."""
    gpg = shutil.which('gpg')
    if not gpg:
        pytest.skip('gpg not installed')
    home = tempfile.mkdtemp(prefix='g645', dir='/tmp')
    try:
        r = subprocess.run([gpg, '--batch', '--with-colons', '--show-keys'],
                           input=B._TAK_PKG_KEY_ASC.encode(), capture_output=True, timeout=60,
                           env={'GNUPGHOME': home, 'PATH': os.environ.get('PATH', '')})
    finally:
        shutil.rmtree(home, ignore_errors=True)
    fprs = [ln.split(':')[9] for ln in r.stdout.decode().splitlines() if ln.startswith('fpr:')]
    assert fprs and fprs[0] == B._TAK_PKG_KEY_FPR
    assert 'TAK Server Release' in r.stdout.decode()
    assert len(B._tak_key_packets()) > 500


# --- .deb signature check with a throwaway key -----------------------------------------

def _ar(members):
    out = io.BytesIO()
    out.write(b'!<arch>\n')
    for name, data in members:
        hdr = (name.encode().ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) + b'0'.ljust(6)
               + b'100644'.ljust(8) + str(len(data)).encode().ljust(10) + b'`\n')
        out.write(hdr + data + (b'\n' if len(data) & 1 else b''))
    return out.getvalue()


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as t:
        for n, d in files.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


class _Keys:
    def __init__(self, home):
        self.home = str(home)
        os.makedirs(self.home, mode=0o700, exist_ok=True)
        self.gpg = shutil.which('gpg')
        self.env = {'GNUPGHOME': self.home, 'PATH': os.environ.get('PATH', '')}

    def run(self, *args, data=None):
        return subprocess.run([self.gpg, '--batch', '--pinentry-mode', 'loopback',
                               '--passphrase', ''] + list(args), input=data,
                              capture_output=True, timeout=120, env=self.env, check=True)

    def make(self, uid):
        self.run('--quick-gen-key', uid, 'ed25519', 'sign', 'never')
        out = self.run('--with-colons', '--fingerprint', uid).stdout.decode()
        fpr = [ln.split(':')[9] for ln in out.splitlines() if ln.startswith('fpr:')][0]
        asc = self.run('--armor', '--export', fpr).stdout.decode()
        return fpr, asc

    def sign(self, fpr, data):
        return self.run('--local-user', fpr, '--detach-sign', data=data).stdout


@pytest.fixture(scope='module')
def keys():
    if not (shutil.which('gpg') and shutil.which('gpgv')):
        pytest.skip('gpg/gpgv not installed')
    # short path: gpg-agent's socket path must fit in sun_path (104 bytes on macOS)
    k = _Keys(tempfile.mkdtemp(prefix='g645', dir='/tmp'))
    try:
        k.tak = k.make('Test TAK Release <tak@example.invalid>')
        k.other = k.make('Someone Else <other@example.invalid>')
        yield k
    finally:
        if shutil.which('gpgconf'):
            subprocess.run(['gpgconf', '--kill', 'gpg-agent'], env=k.env, capture_output=True)
        shutil.rmtree(k.home, ignore_errors=True)


@pytest.fixture
def pinned(monkeypatch, keys):
    fpr, asc = keys.tak
    monkeypatch.setattr(B, '_TAK_PKG_KEY_FPR', fpr)
    monkeypatch.setattr(B, '_TAK_PKG_KEY_ASC', asc)
    gpgv_dir = os.path.dirname(shutil.which('gpgv'))
    monkeypatch.setattr(B, 'BROKER_TRUSTED_PATH', gpgv_dir + ':/usr/bin:/bin')
    return keys


def _deb(keys, signer=None, tamper=False, extra=None, sign=True):
    db = b'2.0\n'
    ctl = _tgz({'./control': b'Package: takserver\nVersion: 5.8\n'})
    data = _tgz({'./opt/tak/x': b'payload'})
    members = [('debian-binary', db), ('control.tar.gz', ctl), ('data.tar.gz', data)]
    if sign:
        fpr = (signer or keys.tak)[0]
        sig = keys.sign(fpr, db + ctl + data)
        members.append(('_gpgorigin', sig))
    if tamper:
        members[2] = ('data.tar.gz', _tgz({'./opt/tak/x': b'changed', './etc/cron.d/x': b'* * * * * root id'}))
    if extra:
        members.insert(3, extra)
    return _ar(members)


def _check_deb(tmp_path, blob, name='takserver_5.8-RELEASE84_all.deb'):
    p = tmp_path / name
    p.write_bytes(blob)
    w = tmp_path / 'work'
    w.mkdir()
    B._verify_tak_deb(str(p), name, str(w))


def test_deb_signed_with_pinned_key_passes(pinned, tmp_path):
    _check_deb(tmp_path, _deb(pinned))


def test_deb_without_signature_is_refused(pinned, tmp_path):
    with pytest.raises(B.Denied, match='no TAK.gov signature'):
        _check_deb(tmp_path, _deb(pinned, sign=False))


def test_deb_signed_with_another_key_names_the_key_and_the_fix(pinned, tmp_path):
    """A key change at TAK.gov must not strand an update with no hint: the error
    names the key it found, the key it wanted, and says to update infra-TAK."""
    with pytest.raises(B.Denied) as e:
        _check_deb(tmp_path, _deb(pinned, signer=pinned.other))
    msg = str(e.value)
    assert pinned.other[0][-16:] in msg.replace(' ', '')
    assert B._fpr_spaced(pinned.tak[0]) in msg
    assert 'update infra-TAK' in msg and 'Nothing was installed' in msg


def test_deb_changed_after_signing_is_refused(pinned, tmp_path):
    with pytest.raises(B.Denied, match='does not match its content'):
        _check_deb(tmp_path, _deb(pinned, tamper=True))


def test_deb_with_an_extra_member_is_refused(pinned, tmp_path):
    with pytest.raises(B.Denied, match='unexpected package layout'):
        _check_deb(tmp_path, _deb(pinned, extra=('data.tar.xz', b'x')))


def test_not_a_deb_is_refused(pinned, tmp_path):
    with pytest.raises(B.Denied, match='not a Debian package'):
        _check_deb(tmp_path, b'#!/bin/sh\nid\n')


# --- .rpm verdicts (rpmkeys -Kv output, RHEL 9 rpm 4.16 wording) -------------------------

def _kid():
    return B._TAK_PKG_KEY_FPR[-8:].lower()


def test_rpm_good_signature_passes():
    out = (f'/s/takserver.rpm:\n    Header V4 RSA/SHA256 Signature, key ID {_kid()}: OK\n'
           '    Header SHA256 digest: OK\n    Header SHA1 digest: OK\n'
           '    Payload SHA256 digest: OK\n'
           f'    V4 RSA/SHA256 Signature, key ID {_kid()}: OK\n    MD5 digest: OK\n')
    B._tak_rpm_verdict(0, out, 'takserver.rpm')


def test_rpm_unsigned_is_refused():
    out = ('/s/takserver.rpm:\n    Header SHA256 digest: OK\n    Header SHA1 digest: OK\n'
           '    Payload SHA256 digest: OK\n    MD5 digest: OK\n')
    with pytest.raises(B.Denied, match='no valid signature'):
        B._tak_rpm_verdict(0, out, 'takserver.rpm')


def test_rpm_other_key_names_the_key_and_the_fix():
    out = ('/s/takserver.rpm:\n    Header V4 RSA/SHA256 Signature, key ID 0badc0de: NOKEY\n'
           '    Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n'
           '    V4 RSA/SHA256 Signature, key ID 0badc0de: NOKEY\n')
    with pytest.raises(B.Denied) as e:
        B._tak_rpm_verdict(1, out, 'takserver.rpm')
    assert '0badc0de' in str(e.value) and 'update infra-TAK' in str(e.value)


def test_rpm_damaged_is_refused():
    out = (f'/s/takserver.rpm:\n    Header V4 RSA/SHA256 Signature, key ID {_kid()}: OK\n'
           '    Payload SHA256 digest: BAD (Expected 1 != 2)\n')
    with pytest.raises(B.Denied, match='does not match its content'):
        B._tak_rpm_verdict(1, out, 'takserver.rpm')


# --- Caddy .deb against Caddy's checksum file -----------------------------------------

class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _caddy(monkeypatch, tmp_path, body, sums=None, fail=False):
    name = 'caddy_2.10.2_linux_amd64.deb'
    p = tmp_path / name
    p.write_bytes(body)
    seen = []

    def urlopen(url, timeout=None):
        seen.append(url)
        if fail:
            raise OSError('no network')
        return _Resp((sums or '').encode())
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)
    B._verify_caddy_deb(str(p), name, B._CADDY_DEB_RE.match(name))
    return seen


def test_caddy_deb_matching_published_sha512_passes(monkeypatch, tmp_path):
    body = b'caddy deb'
    sums = f'{hashlib.sha512(body).hexdigest()}  caddy_2.10.2_linux_amd64.deb\n'
    seen = _caddy(monkeypatch, tmp_path, body, sums)
    assert seen == ['https://github.com/caddyserver/caddy/releases/download/v2.10.2/'
                    'caddy_2.10.2_checksums.txt']


def test_caddy_deb_with_other_content_is_refused(monkeypatch, tmp_path):
    sums = f'{hashlib.sha512(b"real").hexdigest()}  caddy_2.10.2_linux_amd64.deb\n'
    with pytest.raises(B.Denied, match='SHA-512 does not match'):
        _caddy(monkeypatch, tmp_path, b'planted', sums)


def test_caddy_deb_not_listed_or_no_network_is_refused(monkeypatch, tmp_path):
    with pytest.raises(B.Denied, match='not listed'):
        _caddy(monkeypatch, tmp_path, b'x', 'abc  caddy_2.10.2_linux_arm64.deb\n')
    with pytest.raises(B.Denied, match='could not fetch'):
        _caddy(monkeypatch, tmp_path, b'x', fail=True)


# --- staging: copy as the console user, check, install the checked copy ---------------

def _stage_env(monkeypatch, tmp_path, verdict=None):
    calls = []

    def run(cmd, **kw):
        calls.append((list(cmd), kw))
        if cmd[0] == 'cat':          # the console user's read: copy into the fd we got
            kw['stdout'].write(pathlib.Path(cmd[2]).read_bytes())
        if cmd[0] == 'stat':         # the console user's size check (free-space guard)
            return subprocess.CompletedProcess(
                cmd, 0, str(os.path.getsize(cmd[-1])).encode(), b'')
        return subprocess.CompletedProcess(cmd, 0, b'', b'')
    monkeypatch.setattr(B.subprocess, 'run', run)
    monkeypatch.setattr(B, '_PKG_STAGE_ROOT', str(tmp_path / 'stage'))
    monkeypatch.setattr(B.os, 'chown', lambda *a, **k: None)
    monkeypatch.setattr(B.os, 'getgrouplist', lambda n, g: [g])
    monkeypatch.setattr(B.pwd, 'getpwnam',
                        lambda n: types.SimpleNamespace(pw_uid=4242, pw_gid=4242, pw_name=n))
    checked = []

    def verify(path, name, work):
        checked.append((path, pathlib.Path(path).read_bytes()))
        if verdict:
            B._pkg_refuse(name, verdict)
    monkeypatch.setattr(B, '_verify_tak_deb', verify)
    monkeypatch.setattr(B, '_verify_tak_rpm', verify)
    return calls, checked


def test_install_runs_on_the_checked_copy(monkeypatch, tmp_path):
    up = tmp_path / 'uploads'
    up.mkdir()
    (up / 'takserver_5.8-RELEASE84_all.deb').write_bytes(b'deb bytes')
    calls, checked = _stage_env(monkeypatch, tmp_path)
    argv, stage = B._pkg_stage_verified(
        ['/usr/bin/apt-get', 'install', '-y', '--allow-downgrades', './takserver_5.8-RELEASE84_all.deb'],
        str(up), 60)
    # the console user read the file, with its own uid; root never opened the path
    (st, skw), (cat, kw) = calls
    assert st == ['stat', '-L', '-c', '%s', '--', str(up / 'takserver_5.8-RELEASE84_all.deb')]
    assert cat == ['cat', '--', str(up / 'takserver_5.8-RELEASE84_all.deb')]
    assert kw['user'] == 4242 and kw['group'] == 4242
    assert skw['user'] == 4242 and skw['group'] == 4242
    # the checked bytes are the installed file, in the root-only stage
    assert argv[:4] == ['/usr/bin/apt-get', 'install', '-y', '--allow-downgrades']
    assert argv[4] == checked[0][0] and argv[4].startswith(stage + '/')
    assert checked[0][1] == b'deb bytes'
    assert stage.startswith(str(tmp_path / 'stage') + '/pkg-')
    assert oct(os.stat(stage).st_mode & 0o777) == '0o711'
    assert oct(os.stat(argv[4]).st_mode & 0o777) == '0o644'


def test_refused_package_is_not_installed_and_leaves_nothing(monkeypatch, tmp_path):
    (tmp_path / 'evil.deb').write_bytes(b'x')
    calls, _ = _stage_env(monkeypatch, tmp_path, verdict='no valid signature')
    monkeypatch.setattr(B.shutil, 'which', lambda n, path=None: '/usr/bin/' + n)
    with pytest.raises(B.Denied, match='evil.deb was not installed: no valid signature'):
        B._do_exec({'argv': ['apt-get', 'install', '-y', str(tmp_path / 'evil.deb')]})
    assert [c[0][0] for c in calls] == ['stat', 'cat']  # apt-get never ran
    assert os.listdir(tmp_path / 'stage') == []


def test_do_exec_installs_checked_copy_and_cleans_up(monkeypatch, tmp_path):
    (tmp_path / 'takserver-5.8-RELEASE84.noarch.rpm').write_bytes(b'rpm')
    calls, _ = _stage_env(monkeypatch, tmp_path)
    monkeypatch.setattr(B.shutil, 'which', lambda n, path=None: '/usr/bin/' + n)
    B._do_exec({'argv': ['dnf', '-y', 'install', './takserver-5.8-RELEASE84.noarch.rpm'],
                'cwd': str(tmp_path)})
    inst = calls[-1][0]
    assert inst[:3] == ['/usr/bin/dnf', '-y', 'install']
    assert inst[3].startswith(str(tmp_path / 'stage') + '/pkg-')
    assert inst[3].endswith('/takserver-5.8-RELEASE84.noarch.rpm')
    assert os.listdir(tmp_path / 'stage') == []          # staged copy removed after


def test_plain_install_by_name_is_not_staged(monkeypatch, tmp_path):
    calls, checked = _stage_env(monkeypatch, tmp_path)
    monkeypatch.setattr(B.shutil, 'which', lambda n, path=None: '/usr/bin/' + n)
    B._do_exec({'argv': ['apt-get', 'install', '-y', 'caddy']})
    assert [c[0] for c in calls] == [['/usr/bin/apt-get', 'install', '-y', 'caddy']]
    assert not checked


# --- Security review conditions (ops #645): file names and free disk space -------------

@pytest.mark.parametrize('argv', [
    ['apt-get', 'install', '-y', '/opt/infratak/uploads/takserver_5.8-RELEASE84_all (1).deb'],
    ['apt-get', 'install', '-y', './takserver_5.8-RELEASE84_all[1].deb'],
    ['dnf', 'install', '-y', '/opt/infratak/uploads/-takserver-5.8-RELEASE84.noarch.rpm'],
], ids=['space-bracket', 'square-bracket', 'leading-dash'])
def test_bad_package_file_name_gets_a_plain_rename_message(argv):
    with pytest.raises(B.Denied) as e:
        B.check_exec(argv, H)
    msg = str(e.value)
    assert 'was not installed' in msg and 'Rename the' in msg and 'Nothing was installed' in msg


def test_upload_names_always_pass_the_broker_name_rule():
    """The console's TAK upload route (secure_filename, leading '-._' stripped, lower-case
    extension) never saves a name the broker's package-file rule refuses."""
    werkzeug_utils = pytest.importorskip('werkzeug.utils')
    src = (REPO / 'app.py').read_text()
    assert "fn = secure_filename(raw_name).lstrip('-._')" in src
    for raw in ['takserver_5.8-RELEASE84_all (1).deb', 'takserver_5.8-RELEASE84_all[2].deb',
                'takserver-5.8-RELEASE84.noarch (3).rpm', 'TAKSERVER_5.8-RELEASE92_ALL.DEB',
                'takserver 5.8 RELEASE84 all.deb', '-takserver_5.8_all.deb', '-._x.rpm',
                '..\\takserver.deb', 'takserver_5.8-RELEASE84_allé.deb', '  takserver.rpm',
                'takserver_5.8~beta+1_all.deb']:
        fn = werkzeug_utils.secure_filename(raw).lstrip('-._')
        stem, ext = os.path.splitext(fn)
        if ext and ext != ext.lower():
            fn = stem + ext.lower()
        assert B._PKG_FILE_NAME_RE.match(fn), (raw, fn)


def test_not_enough_disk_space_is_refused_before_the_copy(monkeypatch, tmp_path):
    (tmp_path / 'takserver_5.8-RELEASE84_all.deb').write_bytes(b'x' * 4096)
    calls, checked = _stage_env(monkeypatch, tmp_path)
    monkeypatch.setattr(B.os, 'statvfs',
                        lambda p: types.SimpleNamespace(f_bavail=10, f_frsize=4096))
    monkeypatch.setattr(B.shutil, 'which', lambda n, path=None: '/usr/bin/' + n)
    with pytest.raises(B.Denied) as e:
        B._do_exec({'argv': ['apt-get', 'install', '-y', './takserver_5.8-RELEASE84_all.deb'],
                    'cwd': str(tmp_path)})
    msg = str(e.value)
    assert 'not enough free disk space' in msg and 'Free up disk space' in msg
    assert 'It needs about 257 MB there, and 1 MB is free.' in msg
    assert [c[0][0] for c in calls] == ['stat']          # no copy, no install
    assert not checked and os.listdir(tmp_path / 'stage') == []


def test_disk_full_during_the_copy_gets_the_plain_message(monkeypatch, tmp_path):
    (tmp_path / 'takserver-5.8-RELEASE84.noarch.rpm').write_bytes(b'rpm')
    calls, checked = _stage_env(monkeypatch, tmp_path)
    real_run = B.subprocess.run

    def run(cmd, **kw):
        if cmd[0] == 'cat':
            calls.append((list(cmd), kw))
            return subprocess.CompletedProcess(cmd, 1, b'', b'cat: write error: No space left on device')
        return real_run(cmd, **kw)
    monkeypatch.setattr(B.subprocess, 'run', run)
    monkeypatch.setattr(B.shutil, 'which', lambda n, path=None: '/usr/bin/' + n)
    with pytest.raises(B.Denied, match='not enough free disk space'):
        B._do_exec({'argv': ['dnf', '-y', 'install', './takserver-5.8-RELEASE84.noarch.rpm'],
                    'cwd': str(tmp_path)})
    assert not checked and os.listdir(tmp_path / 'stage') == []
