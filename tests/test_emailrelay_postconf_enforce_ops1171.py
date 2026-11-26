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
"""Email Relay's postconf reads pass the broker rulebook (ops #1171).

On a box whose broker enforces, `postconf -hx myorigin` was refused ("postconf option not
allowed: -hx"): the broker reads one flag per argument. The query failed quietly, so the
root-mail sender rewrite and the root recipient map left out Postfix's own names
(GH #665 / #667 again). Email Relay now sends `-h -x`. Nothing is executed: every argv the
module would run is handed to the broker's own `check_exec`.
"""

import importlib.util
import pathlib
import subprocess
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.emailrelay as er  # noqa: E402


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops1171',
                                                  ROOT / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()


def test_postfix_origins_only_sends_argv_the_enforcing_broker_allows(monkeypatch):
    sent, refused = [], []

    def fake_run(argv, *a, **kw):
        argv = list(argv)
        sent.append(argv)
        try:
            B.check_exec(argv)
        except B.Denied as e:
            refused.append((argv, str(e)))
            return types.SimpleNamespace(returncode=1, stdout='', stderr=str(e))
        val = {'myorigin': 'box1.internal', 'myhostname': 'box1.localdomain'}[argv[-1]]
        return types.SimpleNamespace(returncode=0, stdout=val + '\n', stderr='')

    monkeypatch.setattr(er.subprocess, 'run', fake_run)
    names = er._postfix_origins()
    assert [a for a in sent if a[0] == 'postconf'], 'no postconf query was sent'
    assert refused == []
    # Both Postfix names came back, so they reach the sender rewrite and the root map.
    assert names == ['box1.internal', 'box1.localdomain']


@pytest.mark.parametrize('argv', [
    ['postconf', '-h', '-x', 'myorigin'],
    ['postconf', '-h', '-x', 'myhostname'],
])
def test_broker_allows_the_split_read_flags(argv):
    B.check_exec(argv)


def test_broker_still_refuses_unknown_postconf_flags():
    # The fix is on the console side: the rulebook is not widened.
    for argv in (['postconf', '-hx', 'myorigin'], ['postconf', '-M', 'smtp/inet'],
                 ['postconf', '-c', '/tmp/x', '-h', 'myorigin']):
        with pytest.raises(B.Denied):
            B.check_exec(argv)
