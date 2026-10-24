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
"""v10.3.0 W1 — the apt codename is read, never guessed.

The PGDG writer used to fall back to the literal 'jammy' when `lsb_release -cs` was
missing or empty. Noble cloud/minimal images ship without lsb-release, so a fresh
24.04 box would have been handed 22.04's PostgreSQL channel. _apt_codename() reads
VERSION_CODENAME first, then lsb_release, and returns '' when neither works; every
apt-source writer must refuse on ''. The shell-side twin used for Server One and the
printed operator steps guards the same way. Also pins the noble row of the kernel CVE
table (Ubuntu security tracker: linux 6.8.0-117.117).
"""

import builtins
import io
import pathlib
import re
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
# source-level assertions look at CODE lines only — comments may quote the old pattern
CODE = '\n'.join(l for l in APP.splitlines() if not l.lstrip().startswith('#'))


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _const(name):
    # a module-level constant runs to the first blank line (dict/tuple closers sit at col 0)
    m = re.search(r'^%s = .*?\n(?=\n)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


class Box:
    """Fake /etc/os-release + fake `lsb_release -cs`."""

    def __init__(self, os_release, lsb=None, lsb_raises=False):
        real_open = builtins.open

        def fake_open(path, *a, **kw):
            if path == '/etc/os-release':
                if os_release is None:
                    raise FileNotFoundError(path)
                return io.StringIO(os_release)
            return real_open(path, *a, **kw)

        def fake_run(argv, **kw):
            assert argv == ['lsb_release', '-cs']
            if lsb_raises:
                raise FileNotFoundError('lsb_release')
            return types.SimpleNamespace(stdout=lsb or '', returncode=0)

        self.ns = {'open': fake_open, 're': re,
                   'subprocess': types.SimpleNamespace(run=fake_run)}
        for name in ('_apt_codename', '_running_kernel_tuple', '_kernel_cve_banner'):
            exec(compile(_fn(name), f'app.py:{name}', 'exec'), self.ns)
        exec(compile(_const('_KERNEL_CVE_FIXES'), 'app.py:_KERNEL_CVE_FIXES', 'exec'), self.ns)


NOBLE = 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\n'
JAMMY = 'ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\n'
BOOKWORM = 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n'
NO_CODENAME = 'ID=ubuntu\nVERSION_ID="24.04"\n'


@pytest.mark.parametrize('text,want', [(NOBLE, 'noble'), (JAMMY, 'jammy'), (BOOKWORM, 'bookworm')])
def test_codename_comes_from_os_release(text, want):
    box = Box(text, lsb='WRONG')  # lsb_release must not even be consulted
    assert box.ns['_apt_codename']() == want


def test_lsb_release_is_the_fallback_only():
    assert Box(NO_CODENAME, lsb='noble\n').ns['_apt_codename']() == 'noble'
    assert Box(None, lsb='Jammy\n').ns['_apt_codename']() == 'jammy'


def test_unknown_is_empty_never_jammy():
    assert Box(NO_CODENAME, lsb='').ns['_apt_codename']() == ''
    assert Box(NO_CODENAME, lsb_raises=True).ns['_apt_codename']() == ''
    assert Box(None, lsb_raises=True).ns['_apt_codename']() == ''
    # lsb_release garbage (an error line, a path) never becomes a suite name
    assert Box(None, lsb='No LSB modules are available.\n').ns['_apt_codename']() == ''


def test_pgdg_writer_refuses_instead_of_guessing():
    """The console's own PGDG source writer: no 'jammy' literal, refuses on ''."""
    i = APP.index("_cn = _apt_codename()")
    region = APP[i:i + 600]
    assert "refusing to write {_PGDG_LIST}" in region
    assert 'return False' in region
    # the old guess is gone everywhere
    assert "or 'jammy'" not in CODE
    assert "_cn = 'jammy'" not in CODE


def test_no_bare_lsb_release_in_shell_fragments():
    """Every shell-side `$(lsb_release -cs)` is wrapped in the os-release-first twin."""
    for m in re.finditer(r'\$\(lsb_release -cs[^)]*\)', CODE):
        line = CODE[CODE.rfind('\n', 0, m.start()) + 1:CODE.find('\n', m.end())]
        assert 'VERSION_CODENAME' in line, f'bare lsb_release in shell: {line.strip()[:120]}'


def test_shell_twin_guards_empty_codename():
    ns = {}
    exec(_const('_APT_CODENAME_SH'), ns)
    s = APP[APP.index('_PGDG_APT_HOST = '):]
    s = s[:s.index('\n)\n', s.index('_PGDG_REMOTE_SETUP_SH = (')) + 3]
    exec(s, ns)
    frag = ns['_PGDG_REMOTE_SETUP_SH']
    assert '${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null)}' in frag
    assert '[ -n "$cn" ]' in frag and '${cn}-pgdg main' in frag
    # the twin itself, run by bash against a noble os-release, yields 'noble'
    code = ('cn=' + ns['_APT_CODENAME_SH'].replace('/etc/os-release', '$OSR') + '; echo "$cn"')
    r = subprocess.run(['bash', '-c', code], capture_output=True, text=True,
                       env={'OSR': '/dev/stdin', 'PATH': '/usr/bin:/bin'}, input=NOBLE)
    assert r.stdout.strip() == 'noble', r


def test_kernel_cve_table_noble_row():
    """https://ubuntu.com/security/CVE-2026-31431 — linux fixed in 6.8.0-117.117 (noble),
    5.15.0-179.189 (jammy). Older running kernel -> named CVE; fixed or newer -> None."""
    box = Box(NOBLE)
    banner = box.ns['_kernel_cve_banner']
    assert banner('6.8.0-116-generic') == 'CVE-2026-31431 (Copy Fail)'
    assert banner('6.8.0-117-generic') is None
    assert banner('6.8.0-124-generic') is None
    jam = Box(JAMMY).ns['_kernel_cve_banner']
    assert jam('5.15.0-178-generic') == 'CVE-2026-31431 (Copy Fail)'
    # dev's CVE-2026-53266 row (jammy only) takes over once Copy Fail is patched
    assert jam('5.15.0-179-generic') == 'CVE-2026-53266'
    assert jam('5.15.0-198-generic') is None
    # unknown codename: never claim exposure
    assert Box(BOOKWORM).ns['_kernel_cve_banner']('6.1.0-10-amd64') is None
