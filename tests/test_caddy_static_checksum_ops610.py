"""The static Caddy build that Rocky/RHEL boxes install is SHA-512 checked (ops #610).

Rocky/RHEL boxes take Caddy from Caddy's official static build whenever the COPR package is
missing, broken or behind the security floor. That build used to come from caddyserver.com's
download API and was only checked by running `caddy version`. It now comes from the GitHub
release tarball and is checked against the release's caddy_<ver>_checksums.txt, the same way
_caddy_install_github_deb() checks the .deb. Three places installed it; all three now go
through _caddy_install_official_static().

The helpers run here against a fake GitHub (urllib) and a fake host; no network.
"""
import ast
import hashlib
import io
import pathlib
import re
import tarfile
import tempfile
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

VER = '2.11.9'
GOOD_BINARY = b'#!/bin/sh\necho v2.11.9 h1:fake\n'


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _tarball(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


class _Resp:
    def __init__(self, body=b'', url=''):
        self._body, self._url = body, url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body

    def geturl(self):
        return self._url


class _GitHub:
    """A fake GitHub release: a tarball per arch and the release's checksums file."""

    def __init__(self, arch='amd64', served=None, listed=None, members=None, tag_url=None):
        self.arch = arch
        self.name = f'caddy_{VER}_linux_{arch}.tar.gz'
        self.tarball = _tarball(members if members is not None else {'caddy': GOOD_BINARY,
                                                                      'LICENSE': b'x'})
        # `served` is what the download returns; `listed` is what the checksums file vouches for.
        self.served = self.tarball if served is None else served
        listed = self.tarball if listed is None else listed
        self.sums = f'{hashlib.sha512(listed).hexdigest()}  {self.name}\n'
        self.tag_url = tag_url or f'https://github.com/caddyserver/caddy/releases/tag/v{VER}'
        self.urls = []

    def urlopen(self, url, timeout=None):
        self.urls.append(url)
        if url.endswith('/releases/latest'):
            return _Resp(url=self.tag_url)
        if url.endswith('_checksums.txt'):
            return _Resp(self.sums.encode())
        if url.endswith(self.name):
            return _Resp(self.served)
        raise OSError(f'unexpected url {url}')


def _ns(gh, arch='amd64', **extra):
    ns = {
        're': re, 'hashlib': hashlib, 'tempfile': tempfile,
        'urllib': SimpleNamespace(request=SimpleNamespace(urlopen=gh.urlopen)),
        '_host_arch': lambda: arch,
    }
    ns.update(extra)
    return ns


def _fetch(gh, dest, arch='amd64'):
    ns = _ns(gh, arch)
    exec(compile(_segment('_caddy_fetch_release_binary'), 'app.py:_caddy_fetch_release_binary', 'exec'), ns)
    log = []
    return ns['_caddy_fetch_release_binary'](str(dest), log.append), log


def test_a_tarball_that_matches_the_checksums_file_is_written(tmp_path):
    gh = _GitHub()
    dest = tmp_path / 'caddy'
    ver, log = _fetch(gh, dest)
    assert ver == VER
    assert dest.read_bytes() == GOOD_BINARY
    assert any(u.endswith(f'/v{VER}/caddy_{VER}_checksums.txt') for u in gh.urls)


def test_a_tampered_tarball_is_refused_and_nothing_is_written(tmp_path):
    """The proof: the download is not what the release's checksums file vouches for."""
    evil = _tarball({'caddy': b'#!/bin/sh\necho owned\n'})
    gh = _GitHub(served=evil)
    dest = tmp_path / 'caddy'
    ver, log = _fetch(gh, dest)
    assert ver is None
    assert not dest.exists()
    assert any('SHA-512' in m for m in log)


def test_a_tarball_the_checksums_file_does_not_list_is_refused(tmp_path):
    gh = _GitHub()
    gh.sums = f'{"0" * 128}  caddy_{VER}_linux_riscv64.tar.gz\n'
    dest = tmp_path / 'caddy'
    ver, log = _fetch(gh, dest)
    assert ver is None and not dest.exists()
    assert any('not listed' in m for m in log)


def test_a_tarball_with_no_caddy_binary_is_refused(tmp_path):
    gh = _GitHub(members={'LICENSE': b'x', 'README.md': b'y'})
    dest = tmp_path / 'caddy'
    ver, log = _fetch(gh, dest)
    assert ver is None and not dest.exists()


def test_an_unreadable_release_page_gives_nothing(tmp_path):
    gh = _GitHub(tag_url='https://github.com/caddyserver/caddy/releases')
    ver, log = _fetch(gh, tmp_path / 'caddy')
    assert ver is None


def test_a_network_failure_gives_nothing_and_does_not_raise(tmp_path):
    gh = _GitHub()

    def boom(url, timeout=None):
        raise OSError('network is unreachable')
    gh.urlopen = boom
    ver, log = _fetch(gh, tmp_path / 'caddy')
    assert ver is None and any('failed' in m for m in log)


def test_arm64_boxes_take_the_arm64_tarball(tmp_path):
    gh = _GitHub(arch='arm64')
    ver, _ = _fetch(gh, tmp_path / 'caddy', arch='arm64')
    assert ver == VER
    assert any(u.endswith(f'caddy_{VER}_linux_arm64.tar.gz') for u in gh.urls)


class _Host:
    """A fake dnf host for _caddy_install_official_static."""

    def __init__(self, fetch_result=VER, runs=True):
        self.fetch_result, self.runs = fetch_result, runs
        self.calls, self.log = [], []

    def fetch(self, dest, log_fn=None):
        self.calls.append(('fetch',))
        if self.fetch_result:
            pathlib.Path(dest).write_bytes(GOOD_BINARY)
        return self.fetch_result

    def run(self, argv, **kw):
        self.calls.append(tuple(argv))
        if len(argv) == 2 and argv[1] == 'version':
            return SimpleNamespace(returncode=0 if self.runs else 1,
                                   stdout=f'v{VER} h1:fake\n' if self.runs else '', stderr='')
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    def install(self):
        ns = {
            'os': __import__('os'), 'shutil': __import__('shutil'), 'tempfile': tempfile,
            'subprocess': SimpleNamespace(run=self.run, TimeoutExpired=__import__('subprocess').TimeoutExpired),
            '_sudo_wrap': lambda argv: ['sudo'] + list(argv),
            '_run_priv_chain': lambda cmds, mode='and', **k: self.calls.append(('chain',) + tuple(map(tuple, cmds))),
            '_caddy_fetch_release_binary': self.fetch,
            '_caddy_version_cache': {'ver': 'stale'},
        }
        exec(compile(_segment('_caddy_install_official_static'),
                     'app.py:_caddy_install_official_static', 'exec'), ns)
        ok = ns['_caddy_install_official_static'](self.log.append)
        return ok, ns['_caddy_version_cache']

    @property
    def installed(self):
        return any(c[:2] == ('sudo', 'install') and c[-1] == '/usr/bin/caddy' for c in self.calls)


def test_a_verified_build_that_runs_is_installed_and_labelled():
    host = _Host()
    ok, cache = host.install()
    assert ok and host.installed
    assert any(c[0] == 'chain' for c in host.calls)
    assert cache['ver'] is None
    assert any('SHA-512 verified' in m for m in host.log)


def test_a_failed_checksum_never_reaches_usr_bin_caddy():
    """fetch says no (checksum, listing, network): nothing is run and nothing is installed."""
    host = _Host(fetch_result=None)
    ok, _ = host.install()
    assert not ok and not host.installed
    assert not any(len(c) == 2 and c[1] == 'version' for c in host.calls)


def test_a_verified_build_that_does_not_run_is_not_installed():
    host = _Host(runs=False)
    ok, _ = host.install()
    assert not ok and not host.installed


def test_the_download_scratch_folder_is_removed():
    host = _Host()
    host.install()
    ran = [c[0] for c in host.calls if len(c) == 2 and c[1] == 'version']
    assert ran and not pathlib.Path(ran[0]).exists()


def test_no_caddy_download_skips_the_checksum_any_more():
    """All three installs go through the checked helper; the API download is gone."""
    assert 'caddyserver.com/api/download' not in APP
    deploy = _segment('run_caddy_deploy')
    assert deploy.count('_caddy_install_official_static(plog)') >= 3
    assert 'curl' not in _segment('_caddy_install_official_static')
