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
"""TAK Portal Marketplace "Deploy To Caddy": "Caddy rejected the updated file" (ops #298).

The Portal runs `caddy validate` over SSH as the non-root console user. Validate opens
Caddy's access log (0644 caddy:caddy) for append and reads /var/lib/caddy, which that user
cannot do, so it exits 1 with "permission denied" for a good file (reproduced on nuc, Rocky 9,
Caddy 2.11.7). The Portal's retry is `sudo -n bash -lc`, which the console user does not have.

infra-TAK puts scripts/takportal-caddy-validate-shim.sh at ~/.local/bin/caddy (first on the
console user's login PATH). It must pass a validate whose ONLY errors are permission-denied and
leave every other outcome alone. The error lines below are verbatim from nuc.
"""

import ast
import os
import pathlib
import shutil
import stat
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SHIM = ROOT / 'scripts' / 'takportal-caddy-validate-shim.sh'
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

pytestmark = pytest.mark.skipif(shutil.which('bash') is None, reason='needs bash')

_INFO = '{"level":"info","ts":1793196472.83,"msg":"adapted config to JSON","adapter":"caddyfile"}'
_WARN = '{"level":"warn","ts":1793196472.83,"msg":"Caddyfile input is not formatted"}'
_LOG_DENIED = ('{"level":"error","ts":1793196397.87,"msg":"setting up custom log \'log0\': opening log '
               'writer using &logging.FileWriter{Filename:\\"/var/log/caddy/takportal-access.log\\"}: '
               'open /var/log/caddy/takportal-access.log: permission denied"}')
_CERT_DENIED = ('{"level":"error","ts":1793196626.49,"msg":"loading http app module: provision tls.ca_pool.'
                'source.file: reading /var/lib/caddy/atlas/device-ca.crt: open /var/lib/caddy/atlas/'
                'device-ca.crt: permission denied"}')
_PARSE = ('{"level":"error","ts":1793196700.16,"msg":"adapting config using caddyfile: /tmp/x:2: '
          'unrecognized directive: bogus_directive"}')


def _fake_caddy(directory, lines, rc):
    """A stand-in `caddy` that prints `lines` to stderr and exits `rc` for `validate`,
    and prints its argv for anything else."""
    directory.mkdir(parents=True, exist_ok=True)
    body = '\n'.join(lines)
    p = directory / 'caddy'
    p.write_text('#!/bin/bash\n'
                 'if [ "$1" = validate ]; then\n'
                 "cat >&2 <<'EOT'\n" + body + '\nEOT\n'
                 'exit ' + str(rc) + '\nfi\n'
                 'echo "REAL-CADDY $*"\nexit 7\n')
    p.chmod(0o755)
    return p


def _run(tmp_path, lines, rc, args=('validate', '--config', '/tmp/x', '--adapter', 'caddyfile')):
    real = tmp_path / 'usr-bin'
    _fake_caddy(real, lines, rc)
    home_bin = tmp_path / 'home' / '.local' / 'bin'
    home_bin.mkdir(parents=True)
    shim = home_bin / 'caddy'
    shutil.copy(SHIM, shim)
    shim.chmod(0o755)
    env = {'PATH': f'{home_bin}:{real}:/usr/bin:/bin', 'HOME': str(tmp_path / 'home')}
    return subprocess.run(['bash', '-lc', 'caddy "$@"', 'caddy', *args], env=env,
                          capture_output=True, text=True, timeout=30)


# ── the shim ─────────────────────────────────────────────────────────────────

def test_good_config_passes_through(tmp_path):
    r = _run(tmp_path, [_INFO, 'Valid configuration'], 0)
    assert r.returncode == 0
    assert 'Valid configuration' in r.stderr
    assert 'infra-TAK' not in r.stderr          # no note when nothing was carved out


def test_log_file_permission_denied_is_ok(tmp_path):
    """The reported failure: only the access-log writer could not be opened."""
    r = _run(tmp_path, [_INFO, _WARN, _LOG_DENIED, 'Error: validate: loading: permission denied'], 1)
    assert r.returncode == 0
    assert 'permission denied' in r.stderr and 'Treating as OK' in r.stderr


def test_cert_dir_permission_denied_is_ok(tmp_path):
    """Same class on a box with a client-CA under /var/lib/caddy (nuc, ATLAS)."""
    r = _run(tmp_path, [_INFO, _CERT_DENIED], 1)
    assert r.returncode == 0


def test_two_permission_denied_errors_are_ok(tmp_path):
    r = _run(tmp_path, [_LOG_DENIED, _CERT_DENIED], 1)
    assert r.returncode == 0


def test_parse_error_still_fails(tmp_path):
    r = _run(tmp_path, [_INFO, _PARSE], 1)
    assert r.returncode == 1
    assert 'bogus_directive' in r.stderr
    assert 'Treating as OK' not in r.stderr


def test_permission_denied_next_to_a_real_error_still_fails(tmp_path):
    """A real problem must not hide behind an unreadable log."""
    r = _run(tmp_path, [_LOG_DENIED, _PARSE], 1)
    assert r.returncode == 1
    assert 'Treating as OK' not in r.stderr


def test_failure_with_no_error_line_keeps_caddys_exit_code(tmp_path):
    r = _run(tmp_path, ['something odd happened'], 3)
    assert r.returncode == 3


def test_other_subcommands_are_untouched(tmp_path):
    r = _run(tmp_path, [], 0, args=('reload', '--config', '/tmp/x'))
    assert r.returncode == 7                      # the real caddy's own exit code
    assert 'REAL-CADDY reload --config /tmp/x' in r.stdout


@pytest.mark.skipif(os.path.exists('/usr/bin/caddy') or os.path.exists('/usr/local/bin/caddy'),
                    reason='the shim falls back to a host caddy in those paths')
def test_no_real_caddy_is_a_clean_error(tmp_path):
    home_bin = tmp_path / 'home' / '.local' / 'bin'
    home_bin.mkdir(parents=True)
    shim = home_bin / 'caddy'
    shutil.copy(SHIM, shim)
    shim.chmod(0o755)
    r = subprocess.run([shutil.which('bash'), str(shim), 'validate'], env={'PATH': str(home_bin)},
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 127
    assert 'not found' in r.stderr


def test_shim_carries_the_marker_app_py_looks_for():
    assert 'infratak-caddy-validate-shim' in SHIM.read_text(encoding='utf-8')
    assert "TAKPORTAL_CADDY_SHIM_MARKER = 'infratak-caddy-validate-shim'" in APP


# ── the installer ────────────────────────────────────────────────────────────

def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


@pytest.fixture()
def install(tmp_path, monkeypatch):
    """_takportal_install_caddy_validate_shim cut out of app.py, run against a temp HOME."""
    home = tmp_path / 'home'
    home.mkdir()
    real = tmp_path / 'usr-bin'
    _fake_caddy(real, [], 0)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('PATH', f'{home}/.local/bin:{real}:/usr/bin:/bin')
    monkeypatch.setattr(os, 'geteuid', lambda: 1000)
    ns = {'os': os, 'shutil': shutil,
          'TAKPORTAL_CADDY_SHIM_SRC': str(SHIM),
          'TAKPORTAL_CADDY_SHIM_MARKER': 'infratak-caddy-validate-shim'}
    exec(compile(_segment('_takportal_install_caddy_validate_shim'), 'app.py:install', 'exec'), ns)
    ns['_dest'] = home / '.local' / 'bin' / 'caddy'
    ns['_real'] = real
    return ns


def test_installs_an_executable_copy(install):
    logs = []
    assert install['_takportal_install_caddy_validate_shim'](logs.append) == 'installed'
    dest = install['_dest']
    assert dest.read_text(encoding='utf-8') == SHIM.read_text(encoding='utf-8')
    assert dest.stat().st_mode & stat.S_IXUSR
    assert not (dest.parent / 'caddy.tmp-infratak').exists()
    assert any('Caddy validate helper installed' in m for m in logs)


def test_second_run_changes_nothing(install):
    f = install['_takportal_install_caddy_validate_shim']
    assert f() == 'installed'
    before = install['_dest'].stat().st_mtime_ns
    assert f() == 'current'
    assert install['_dest'].stat().st_mtime_ns == before


def test_updates_an_older_copy_of_ours(install):
    f = install['_takportal_install_caddy_validate_shim']
    dest = install['_dest']
    dest.parent.mkdir(parents=True)
    dest.write_text('#!/bin/bash\n# infratak-caddy-validate-shim\n# old version\n')
    assert f() == 'installed'
    assert dest.read_text(encoding='utf-8') == SHIM.read_text(encoding='utf-8')


def test_never_replaces_someone_elses_caddy(install):
    f = install['_takportal_install_caddy_validate_shim']
    dest = install['_dest']
    dest.parent.mkdir(parents=True)
    dest.write_text('#!/bin/bash\necho operators own caddy\n')
    logs = []
    assert f(logs.append) == 'skipped'
    assert 'operators own caddy' in dest.read_text(encoding='utf-8')
    assert any('leaving it alone' in m for m in logs)


def test_root_console_needs_nothing(install, monkeypatch):
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    assert install['_takportal_install_caddy_validate_shim']() == 'skipped'
    assert not install['_dest'].exists()


def test_no_host_caddy_installs_nothing(install, monkeypatch):
    shutil.rmtree(install['_real'])
    monkeypatch.setenv('PATH', str(install['_dest'].parent.parent.parent))   # no caddy anywhere
    assert install['_takportal_install_caddy_validate_shim']() == 'skipped'
    assert not install['_dest'].exists()


def test_our_own_shim_does_not_count_as_a_host_caddy(install, monkeypatch):
    """Only the shim exists on PATH (real caddy removed): still nothing to wrap."""
    f = install['_takportal_install_caddy_validate_shim']
    assert f() == 'installed'
    shutil.rmtree(install['_real'])
    monkeypatch.setenv('PATH', f"{install['_dest'].parent}")
    install['_dest'].unlink()
    install['_dest'].write_text(SHIM.read_text(encoding='utf-8'))
    install['_dest'].chmod(0o755)
    assert f() == 'skipped'


def test_hooks_are_wired():
    """Called from the Portal SSH setup (deploy / update / Repair) and from the startup heal."""
    setup = _segment('_takportal_setup_ssh')
    assert '_takportal_install_caddy_validate_shim(log_fn=log_fn)' in setup
    startup = _segment('_startup_migrations')
    assert '_takportal_install_caddy_validate_shim(' in startup
