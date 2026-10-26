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
"""v10.3.0 W1.a — TAK .deb signature verification works on a non-root console.

Found by the W2 fresh deploy on aws-noble (24.04) and reproduced on aws-jammy (22.04),
2026-10-13: every born-non-root TAK deploy printed "Verification exit code 13 —
installing anyway". Two causes, both broker-shaped:
  * the keyring import `gpg --no-default-keyring --keyring <kr> --import <key>` is
    not a gpg shape the broker allows (WOULD-DENY in the audit log), and
  * debsig-verify shells out to `gpg`, which resolved to the console's PATH shim, so
    every internal signature check went to the root broker and was refused.
Run by hand as root or as takwerx with a normal PATH, the same package verifies.
"""

import importlib.util
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CODE = '\n'.join(l for l in APP.splitlines() if not l.lstrip().startswith('#'))
BROKER_PY = REPO / 'broker' / 'takwerx_broker.py'

i = APP.index('━━━ Step 3/9: Package Verification ━━━')
STEP3 = APP[i:APP.index('━━━ Step 4/9', i)]
STEP3_CODE = '\n'.join(l for l in STEP3.splitlines() if not l.lstrip().startswith('#'))


@pytest.fixture(scope='module')
def broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_debsig_test', BROKER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_keyring_import_shape_is_gone():
    assert '--no-default-keyring --keyring /usr/share/debsig' not in CODE
    assert '--import {config' not in STEP3_CODE


def test_keyring_written_with_the_dearmor_shape(broker):
    assert "gpg --batch --yes --dearmor -o {_kr} {shlex.quote(_key)}" in STEP3_CODE
    # ... and that exact argv passes the broker's gpg gate for a real policy id
    kr = '/usr/share/debsig/keyrings/F06237936851F5B5/debsig.gpg'
    broker._check_gpg(['gpg', '--batch', '--yes', '--dearmor', '-o', kr,
                       '/opt/infratak/uploads/takserver-public-gpg.key'])
    assert broker._path_allowed(kr)
    assert broker._path_allowed('/etc/debsig/policies/F06237936851F5B5/debsig.pol')
    # the shape it replaced is still refused — the fix did not widen the broker
    with pytest.raises(broker.Denied):
        broker._check_gpg(['gpg', '--no-default-keyring', '--keyring', kr, '--import', '/tmp/k'])


def test_binary_key_is_copied_not_dearmored():
    assert "_kf.read(64).lstrip().startswith(b'-----BEGIN PGP')" in STEP3_CODE
    assert "run_cmd(f'cp {shlex.quote(_key)} {_kr}')" in STEP3_CODE


def test_debsig_verify_runs_with_a_system_path_and_no_shell():
    assert "subprocess.run(['debsig-verify', '-v', pkg]" in STEP3_CODE
    assert "_dv_env['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'" in STEP3_CODE
    assert 'env=_dv_env' in STEP3_CODE
    assert "f'debsig-verify -v {pkg}'" not in CODE        # the shell-string form is gone
    # no shim directory may sneak back into the verification PATH
    assert '.shims' not in STEP3_CODE and '_broker_shim_env' not in STEP3_CODE


def test_policy_id_is_validated_before_use():
    assert "_re_pid.fullmatch(r'[0-9A-Fa-f]{16}', pid)" in STEP3_CODE
    assert STEP3_CODE.index("_re_pid.fullmatch(r'[0-9A-Fa-f]{16}', pid)") < STEP3_CODE.index('mkdir -p /usr/share/debsig/keyrings/')
    for good in ('F06237936851F5B5', 'f06237936851f5b5'):
        assert re.fullmatch(r'[0-9A-Fa-f]{16}', good)
    for bad in ('F062379368', 'F06237936851F5B5; rm -rf /', '../../etc', ''):
        assert not re.fullmatch(r'[0-9A-Fa-f]{16}', bad)


def test_step3_uses_no_module_name_the_function_makes_local():
    """run_takserver_deploy does `import re` further down, so `re` is a LOCAL for the
    whole function and a bare `re.` in Step 3 raises UnboundLocalError at runtime. That
    is exactly how the first W1.a build failed on aws-noble (2026-10-13) while every
    source-level test passed. Check the real scope table, not the text."""
    import ast, symtable
    tree = ast.parse(APP)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_takserver_deploy')
    ns = symtable.symtable(ast.get_source_segment(APP, fn), 'app.py', 'exec').lookup('run_takserver_deploy').get_namespace()
    used = set(re.findall(r'(?<![\w.])([a-z_][a-z0-9_]*)\.[a-z_]', STEP3_CODE))
    for mod in sorted(used & {'re', 'os', 'shlex', 'subprocess', 'json', 'time', 'shutil'}):
        try:
            local = ns.lookup(mod).is_local()
        except KeyError:
            local = False
        assert not local, f'Step 3 uses `{mod}.` but `{mod}` is local in run_takserver_deploy'



# ---------------------------------------------------------------------------
# Operator decision 2026-10-13: "deploy should stop" — verification is enforced once a
# key and a policy were uploaded; no key/policy at all still skips (logged, unchanged).
# ---------------------------------------------------------------------------
def test_a_failed_signature_stops_the_deploy_before_install():
    assert 'installing anyway' not in STEP3_CODE
    i = STEP3_CODE.index('if v.returncode == 0: log_step("✓ Package signature VERIFIED")')
    fail = STEP3_CODE[i:STEP3_CODE.index("else:\n            log_step(\"No GPG key/policy", i)]
    assert 'FATAL: package signature verification FAILED' in fail
    assert "deploy_status.update({'error': True, 'running': False}); return" in fail
    assert 'Nothing has been installed' in fail


def test_a_policy_without_a_usable_key_id_stops_the_deploy():
    i = STEP3_CODE.index("if not pid or not _re_pid.fullmatch(r'[0-9A-Fa-f]{16}', pid):")
    blk = STEP3_CODE[i:STEP3_CODE.index("if pid:", i + 10)]
    assert 'FATAL' in blk and "deploy_status.update({'error': True, 'running': False}); return" in blk
    assert 'skipping verification' not in STEP3_CODE.split('No GPG key/policy')[0]   # only the no-upload case skips


def test_no_key_and_policy_still_skips_with_a_log_line():
    assert 'log_step("No GPG key/policy — skipping verification")' in STEP3_CODE


def test_refusal_happens_before_anything_is_installed():
    step3_end = APP.index('━━━ Step 4/9: Installing TAK Server ━━━')
    assert APP.index('FATAL: package signature verification FAILED') < step3_end
