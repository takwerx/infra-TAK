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
"""TAK Portal sudo grant, hardened variant (TAK Portal 2.0.19+).

The hardened grant has no rule for a script in a tak-owned directory, runs the
CoreConfig cat/tee as `tak` through root-owned wrappers, and grants only a
hash-pinned marketplace helper. The legacy text is kept byte-for-byte for older
portals.
"""

import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture()
def b():
    spec = importlib.util.spec_from_file_location('takwerx_broker_t217', REPO / 'broker' / 'takwerx_broker.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    # Deterministic binary resolution regardless of the host running the tests.
    m._sudoers_safe_binaries = lambda name: {
        'cat': ['/usr/bin/cat', '/bin/cat'], 'tee': ['/usr/bin/tee'], 'bash': ['/usr/bin/bash'],
        'systemctl': ['/usr/bin/systemctl', '/bin/systemctl'], 'setpriv': ['/usr/bin/setpriv'],
        'visudo': ['/usr/sbin/visudo'],
    }.get(name, [])
    return m


def _grant_lines(text):
    return [l for l in text.splitlines() if l and not l.startswith('#')]


# --------------------------------------------------------------------------- text
def test_legacy_text_is_unchanged_for_old_portals(b):
    t = b._takportal_sudoers_text(user='takwerx')
    assert t == b._takportal_sudoers_text(user='takwerx', variant='legacy')
    assert 'NOPASSWD: /usr/bin/tee /opt/tak/utils/tak-portal-repair-certs.sh' in t
    assert 'NOPASSWD: /usr/bin/bash /opt/tak/utils/tak-portal-repair-certs.sh' in t
    assert 'NOPASSWD: /usr/bin/cat /opt/tak/CoreConfig.xml' in t


def test_hardened_has_no_script_rules_and_no_root_cat_tee(b):
    t = b._takportal_sudoers_text(user='takwerx', variant='hardened', helper=True)
    body = '\n'.join(_grant_lines(t))
    assert 'tak-portal-repair-certs' not in body
    assert '/opt/tak/utils' not in body
    # No bare tee/bash/cat/tail/reboot/ALL-as-root.
    for bad in ('/usr/bin/tee', '/usr/bin/bash', '/bin/bash', '/usr/bin/cat', 'tail', 'reboot',
                '(root) NOPASSWD: ALL', '(ALL)'):
        assert bad not in body, bad
    assert 'NOPASSWD: ALL' not in [l.split('=', 1)[1].split(')', 1)[1].strip()
                                   for l in _grant_lines(t) if 'ALL=(root)' in l]


def test_hardened_rules_are_exactly_these(b):
    t = b._takportal_sudoers_text(user='takwerx', variant='hardened', helper=True)
    w = b.TAKPORTAL_WRAP_DIR
    assert _grant_lines(t) == [
        'Defaults:takwerx !requiretty',
        f'Defaults:takwerx secure_path="{w}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
        f'takwerx ALL=(root) NOPASSWD: {w}/cat /opt/tak/CoreConfig.xml',
        f'takwerx ALL=(root) NOPASSWD: {w}/tee /opt/tak/CoreConfig.xml',
        'takwerx ALL=(root) NOPASSWD: /usr/bin/systemctl restart takserver',
        'takwerx ALL=(root) NOPASSWD: /bin/systemctl restart takserver',
        'takwerx ALL=(tak) NOPASSWD: ALL',
        'takwerx ALL=(root) NOPASSWD: /usr/local/libexec/tak-portal/marketplace-helper',
    ]


def test_helper_rule_only_when_helper_is_in_place(b):
    assert 'marketplace-helper' not in b._takportal_sudoers_text(user='takwerx', variant='hardened', helper=False)


def test_wrapper_and_helper_live_where_tak_cannot_write(b):
    # Root-owned locations only: not /opt/tak, not the console user's home.
    for p in (b.TAKPORTAL_WRAP_DIR, b.TAKPORTAL_HELPER):
        assert p.startswith('/usr/local/libexec/')


def test_unsafe_user_and_variant_refused(b):
    with pytest.raises(b.Denied):
        b._takportal_sudoers_text(user='x; ALL', variant='hardened')
    with pytest.raises(b.Denied):
        b._takportal_sudoers_text(user='takwerx', variant='bogus')


# ------------------------------------------------------------------------ wrapper
def test_wrapper_drops_to_tak_for_exactly_coreconfig(b):
    for name in ('cat', 'tee'):
        t = b._takportal_wrapper_text(name)
        assert t.startswith('#!/bin/sh\n')
        assert '--reuid=tak --regid=tak --init-groups' in t
        assert f'/usr/bin/{name} -- "$1"' in t
        assert f'exec /usr/bin/{name} "$@"' in t          # anything else: unchanged
        subprocess.run(['sh', '-n'], input=t.encode(), check=True)


def test_wrapper_passes_other_calls_through_when_not_root(b, tmp_path):
    f = tmp_path / 'f.txt'
    f.write_text('hello\n')
    t = b._takportal_wrapper_text('cat').replace('/usr/bin/cat', '/bin/cat')
    w = tmp_path / 'cat'
    w.write_text(t)
    w.chmod(0o755)
    out = subprocess.run([str(w), str(f)], capture_output=True, text=True)
    assert out.stdout == 'hello\n'


def test_wrapper_refused_when_binaries_cannot_be_resolved(b):
    b._sudoers_safe_binaries = lambda name: []
    with pytest.raises(b.Denied):
        b._takportal_wrapper_text('cat')


# --------------------------------------------------------------- variant decision
def _portal(tmp_path, monkeypatch, b, version=None, helper=None):
    home = tmp_path / 'home'
    d = home / 'TAK-Portal'
    d.mkdir(parents=True)
    if version is not None:
        (d / 'package.json').write_text(json.dumps({'version': version}))
    if helper is not None:
        (d / 'host-helpers').mkdir()
        (d / 'host-helpers' / 'marketplace-helper').write_bytes(helper)
    monkeypatch.setattr(b.pwd, 'getpwnam', lambda u: type('P', (), {'pw_dir': str(home)})())
    return d


def test_old_portal_stays_on_legacy(b, tmp_path, monkeypatch):
    _portal(tmp_path, monkeypatch, b, version='2.0.18')
    d = b._takportal_decide()
    assert d['variant'] == 'legacy' and '2.0.19' in d['reason']


def test_new_portal_with_pinned_helper_is_hardened(b, tmp_path, monkeypatch):
    helper = b'#!/bin/bash\necho pinned\n'
    monkeypatch.setattr(b, 'TAKPORTAL_HELPER_SHA256', frozenset({hashlib.sha256(helper).hexdigest()}))
    _portal(tmp_path, monkeypatch, b, version='2.0.21', helper=helper)
    d = b._takportal_decide()
    assert d['variant'] == 'hardened' and d['helper_bytes'] == helper


def test_unreviewed_helper_is_never_installed(b, tmp_path, monkeypatch):
    _portal(tmp_path, monkeypatch, b, version='2.0.40', helper=b'#!/bin/bash\nrm -rf /\n')
    d = b._takportal_decide()
    assert d['variant'] == 'hardened'
    assert d['helper_bytes'] is None and 'not reviewed' in d['helper_reason']
    assert d['helper_unreviewed'] is True


def test_helper_file_proves_new_even_if_package_json_lags(b, tmp_path, monkeypatch):
    _portal(tmp_path, monkeypatch, b, version='2.0.14', helper=b'x')
    assert b._takportal_decide()['variant'] == 'hardened'


def test_no_checkout_or_unknown_version_is_hardened_not_legacy(b, tmp_path, monkeypatch):
    monkeypatch.setattr(b.pwd, 'getpwnam', lambda u: type('P', (), {'pw_dir': str(tmp_path / 'nohome')})())
    assert b._takportal_decide()['variant'] == 'hardened'
    _portal(tmp_path, monkeypatch, b, version=None)
    assert b._takportal_decide()['variant'] == 'hardened'


def test_symlinked_portal_dir_is_not_followed(b, tmp_path, monkeypatch):
    real = tmp_path / 'elsewhere'
    real.mkdir()
    (real / 'package.json').write_text('{"version":"2.0.1"}')
    home = tmp_path / 'home'
    home.mkdir()
    (home / 'TAK-Portal').symlink_to(real)
    monkeypatch.setattr(b.pwd, 'getpwnam', lambda u: type('P', (), {'pw_dir': str(home)})())
    assert b._takportal_decide()['variant'] == 'hardened'


def test_pinned_hash_matches_portal_2_0_19_to_2_0_21_helper(b):
    assert 'c240a12aa8978e106c94c0303a0e116f3e08dff0ba7c6a9273c0422ad92e3bb4' in b.TAKPORTAL_HELPER_SHA256


def test_portal_2_0_23_helper_stays_unpinned_until_reviewed(b):
    # Helper v2 (TAK Portal 2.0.23+) has not been reviewed.
    # It must not be pinned as is; pin only after the review (ops #295).
    assert 'e05feed906832e649b5257caf840c19044aeac45352952b268e547117dc4c7f2' not in b.TAKPORTAL_HELPER_SHA256


# ------------------------------------------------------------- ownership refusals
def test_root_file_check_refuses_non_root_owned(b, tmp_path):
    if os.getuid() == 0:
        pytest.skip('running as root')
    f = tmp_path / 'w'
    f.write_text('x')
    assert not b._root_file_ok(str(f), want_bytes=b'x')
    with pytest.raises(b.Denied):
        b._ensure_root_dir(str(tmp_path / 'sub'))     # parents are not root-owned


def test_failed_wrapper_install_means_no_grant(b, tmp_path, monkeypatch):
    out = tmp_path / 'tak-portal'
    monkeypatch.setattr(b, 'TAKPORTAL_SUDOERS_PATH', str(out))
    monkeypatch.setattr(b, '_takportal_decide', lambda user=b.BROKER_USER: {
        'variant': 'hardened', 'reason': '', 'portal_version': '2.0.21', 'helper_bytes': None, 'helper_reason': ''})

    def boom():
        raise b.Denied('not root-owned')
    monkeypatch.setattr(b, '_takportal_install_wrappers', boom)
    r = b._do_takportal_sudoers({'action': 'install'})
    assert r['ok'] is False and 'not installed' in r['error']
    assert not out.exists()


def test_leftover_marketplace_dropin_removed_only_when_regular_file(b, tmp_path, monkeypatch):
    f = tmp_path / 'tak-portal-marketplace'
    monkeypatch.setattr(b, 'TAKPORTAL_LEFTOVER_SUDOERS', str(f))
    assert b._takportal_remove_leftover() is False
    f.write_text('takwerx ALL=NOPASSWD: ALL\n')
    assert b._takportal_remove_leftover() is True and not f.exists()
    target = tmp_path / 'target'
    target.write_text('keep')
    f.symlink_to(target)
    assert b._takportal_remove_leftover() is False and target.exists()


def test_status_reports_variant_and_legacy_row_in_console():
    app = (REPO / 'app.py').read_text()
    assert "grant.get('variant') == 'legacy'" in app
    assert 'removed leftover /etc/sudoers.d/tak-portal-marketplace' in app
