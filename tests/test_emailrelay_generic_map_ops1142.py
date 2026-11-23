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
"""ops #1142 (infra-TAK GH #665) — the sender map is keyed on the name Postfix stamps.

Postfix stamps local mail from root with its origin: /etc/mailname (the saved FQDN) on
Debian/Ubuntu. The email relay used to key /etc/postfix/generic on a bare `hostname -f`,
so on a host where that differs from the saved FQDN the key never matched and the sender
was never rewritten, with no message. deploy() runs here for real, against a fake ctx and
a fake subprocess, and the file it hands to the privileged writer is what is checked.
"""

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.emailrelay as er  # noqa: E402

FQDN = 'tak.example.org'
SHORT = 'vps-1234'
FROM = 'noreply@example.org'


# ── the pure helper ─────────────────────────────────────────────────────────

def test_map_holds_one_line_per_distinct_name_saved_fqdn_first():
    text, names = er._generic_map_text(FROM, FQDN, SHORT)
    assert text == f'root@{FQDN}    {FROM}\nroot@{SHORT}    {FROM}\n'
    assert names == sorted([FQDN, SHORT])


def test_same_name_twice_or_blank_or_zero_gives_one_line():
    text, names = er._generic_map_text(FROM, FQDN, '', None, FQDN.upper(), '0', FQDN)
    assert text == f'root@{FQDN}    {FROM}\n'
    assert names == [FQDN]


# ── deploy() end to end against fakes ───────────────────────────────────────

class _Run:
    def __init__(self, hostname_f=SHORT):
        self.hostname_f = hostname_f
        self.calls = []

    def __call__(self, cmd, *a, **kw):
        self.calls.append(list(cmd))
        out = ''
        if list(cmd) == ['hostname', '-f']:
            out = self.hostname_f + '\n'
        elif list(cmd) == ['hostname']:
            out = self.hostname_f.split('.')[0] + '\n'
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr='')


def _deploy(monkeypatch, tmp_path, *, os_type, saved_fqdn, hostname_f, mailname=''):
    runner = _Run(hostname_f)
    monkeypatch.setattr(er.subprocess, 'run', runner)
    monkeypatch.setenv('HOME', str(tmp_path))  # no ~/authentik, so no Authentik step
    # raising=False: the deploy-level tests must reach their assertions on the base branch
    # too (where this helper does not exist), so they fail for the right reason.
    monkeypatch.setattr(er, '_read_mailname', lambda: mailname, raising=False)
    written = {}
    ctx = {
        'load_settings': lambda: {'fqdn': saved_fqdn} if saved_fqdn else {},
        'save_settings': lambda s: None,
        'os_type': lambda: os_type,
        'wait_for_apt_lock': lambda plog, log: None,
        '_pkg_install': lambda pkgs, log_fn=None, timeout=0: (True, ''),
        '_sudo_wrap': lambda c: list(c),
        '_read_priv': lambda p: '',
        '_write_priv': lambda p, text, perm=None: written.__setitem__(p, text),
        '_takportal_push_settings': lambda plog: False,
    }
    job = {'log': [], 'running': True}
    params = {'provider': 'custom', 'smtp_user': 'u', 'smtp_pass': 'p', 'from_addr': FROM,
              'from_name': 'TAK', 'relay_host': 'smtp.example.org', 'relay_port': '587'}
    er.deploy(ctx, job, params)
    assert job.get('complete') is True, job
    return written['/etc/postfix/generic'], runner


@pytest.mark.parametrize('os_type', ['debian', 'rhel'])
def test_generic_map_is_keyed_on_the_saved_fqdn_when_hostname_f_differs(
        monkeypatch, tmp_path, os_type):
    """The proof test: red on the base branch (only root@<hostname -f>), green with the fix."""
    text, _ = _deploy(monkeypatch, tmp_path, os_type=os_type,
                      saved_fqdn=FQDN, hostname_f=SHORT)
    keys = [ln.split()[0] for ln in text.splitlines()]
    assert f'root@{FQDN}' in keys, text          # what Postfix stamps (/etc/mailname)
    assert f'root@{SHORT}' in keys, text         # and what `hostname -f` says today
    assert all(ln.split()[1] == FROM for ln in text.splitlines())


def test_live_etc_mailname_is_keyed_too(monkeypatch, tmp_path):
    """An OS upgrade or an earlier install can leave /etc/mailname on a third name."""
    text, _ = _deploy(monkeypatch, tmp_path, os_type='debian', saved_fqdn=FQDN,
                      hostname_f=SHORT, mailname='old.example.org')
    keys = [ln.split()[0] for ln in text.splitlines()]
    assert keys == [f'root@{FQDN}', 'root@old.example.org', f'root@{SHORT}']


def test_matching_names_still_give_a_single_line(monkeypatch, tmp_path):
    text, _ = _deploy(monkeypatch, tmp_path, os_type='debian', saved_fqdn=FQDN,
                      hostname_f=FQDN, mailname=FQDN)
    assert text == f'root@{FQDN}    {FROM}\n'


def test_no_saved_fqdn_falls_back_to_hostname_f(monkeypatch, tmp_path):
    text, _ = _deploy(monkeypatch, tmp_path, os_type='rhel', saved_fqdn='', hostname_f=SHORT)
    assert text == f'root@{SHORT}    {FROM}\n'


def test_a_disagreement_is_said_in_the_deploy_log(monkeypatch, tmp_path):
    logged = []
    monkeypatch.setattr(er, '_plog', lambda m: logged.append(m))
    _deploy(monkeypatch, tmp_path, os_type='rhel', saved_fqdn=FQDN, hostname_f=SHORT)
    assert any('disagree' in m and FQDN in m and SHORT in m for m in logged), logged
