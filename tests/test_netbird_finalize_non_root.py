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
"""NetBird account-store finalize must work when the console is not root.

Field (non-root RHEL box): the NetBird container runs as root and creates
~/netbird/data/store.db root:root 644. The takwerx console opened it directly with sqlite3,
so every finalize failed with "attempt to write a readonly database" and the onboarding /
user-approval gates were never cleared.

app.py cannot be imported in a test, so the function is cut out of it and run: the code
under test is the shipped text. A read-only store stands in for "owned by root"; the fake
broker chown makes it writable again, the way a real chown to the console user does.
"""

import ast
import os
import pathlib
import sqlite3
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_WANT = {'_netbird_finalize_account_store'}


def _make_store(nb_dir):
    data = nb_dir / 'data'
    data.mkdir(parents=True)
    db = data / 'store.db'
    conn = sqlite3.connect(db)
    conn.executescript(
        'CREATE TABLE account_onboardings (onboarding_flow_pending INT, signup_form_pending INT);'
        'INSERT INTO account_onboardings VALUES (1, 1);'
        'CREATE TABLE accounts (settings_extra_user_approval_required INT);'
        'INSERT INTO accounts VALUES (1);'
        'CREATE TABLE users (role TEXT, pending_approval INT);'
        "INSERT INTO users VALUES ('owner', 1), ('user', 1);"
    )
    conn.commit()
    conn.close()
    return db


def _load(nb_dir, monkeypatch, uid):
    parts = [ast.get_source_segment(APP, n) for n in ast.parse(APP).body
             if isinstance(n, ast.FunctionDef) and n.name in _WANT]
    assert len(parts) == len(_WANT), 'a function under test was renamed or removed'
    calls = []

    def fake_run(argv, *a, **k):
        calls.append(list(argv))
        if argv[:2] == ['broker', 'chown']:
            os.chmod(argv[3], 0o644)
        return subprocess.CompletedProcess(argv, 0, '', '')

    monkeypatch.setattr(subprocess, 'run', fake_run)
    monkeypatch.setattr(os, 'getuid', lambda: uid)
    monkeypatch.setattr(os, 'getgid', lambda: uid)
    ns = {
        'os': os, 'subprocess': subprocess,
        'NETBIRD_INSTALL_DIR': str(nb_dir),
        '_sudo_wrap': lambda argv: ['broker'] + list(argv),
    }
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns['_netbird_finalize_account_store'], calls


def _gates(db):
    conn = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
    try:
        return (conn.execute('SELECT * FROM account_onboardings').fetchall(),
                conn.execute('SELECT * FROM accounts').fetchall(),
                conn.execute('SELECT * FROM users ORDER BY role').fetchall())
    finally:
        conn.close()


@pytest.mark.skipif(os.geteuid() == 0, reason='root can write a 0444 file, so it cannot stand in for root-owned')
def test_non_root_console_takes_the_store_and_clears_the_gates(tmp_path, monkeypatch):
    db = _make_store(tmp_path / 'netbird')
    os.chmod(db, 0o444)
    finalize, calls = _load(tmp_path / 'netbird', monkeypatch, uid=1000)
    log = []
    assert finalize(log.append) is True, log
    assert calls == [['broker', 'chown', '1000:1000', str(db)]]
    assert _gates(db) == ([(0, 0)], [(0,)], [('owner', 0), ('user', 1)])


def test_writable_store_is_not_chowned(tmp_path, monkeypatch):
    db = _make_store(tmp_path / 'netbird')
    finalize, calls = _load(tmp_path / 'netbird', monkeypatch, uid=1000)
    assert finalize() is True
    assert calls == []
    assert _gates(db)[0] == [(0, 0)]


def test_root_console_never_asks_the_broker(tmp_path, monkeypatch):
    db = _make_store(tmp_path / 'netbird')
    finalize, calls = _load(tmp_path / 'netbird', monkeypatch, uid=0)
    assert finalize() is True
    assert calls == []
