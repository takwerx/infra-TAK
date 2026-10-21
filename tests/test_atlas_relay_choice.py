# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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

"""ATLAS starts on InfraTAK's Email Relay, once (#155).

⚠️ **The tick is the operator's after the first time.** ATLAS stores its
"Use InfraTAK's email configuration" box as a row that exists, ticked or
not, from the first save of its Email page. These tests run the in-container
script against a stand-in for ATLAS's session and prove it only ever adds
that row when there is none, and never touches one an operator saved.
"""

import contextlib
import io
import pathlib
import re
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402

SOURCE = io.open(ROOT / 'modules' / 'atlas.py', encoding='utf-8').read()
CODE = re.sub(r'#[^\n]*', '', re.sub(r'"""[\s\S]*?"""', '', SOURCE))


def _body(name):
    start = CODE.index('def %s(' % name)
    rest = CODE[start:]
    end = rest.index(chr(10) + 'def ', 1)
    return rest[:end]


class _Row:
    def __init__(self, key, value='', updated_by=None):
        self.key, self.value, self.updated_by = key, value, updated_by


class _Session:
    """ATLAS's `app_setting` table, as the script sees it."""

    def __init__(self, table):
        self.table = table
        self.committed = False

    def get(self, model, key):
        return self.table.get(key)

    def add(self, row):
        self.table[row.key] = row

    def commit(self):
        self.committed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _run_seed(monkeypatch, table):
    """Run the script exactly as `python -c` would inside the container."""
    session = _Session(table)
    base = types.ModuleType('app.db.base')
    base.SessionLocal = lambda: session
    models = types.ModuleType('app.db.models')
    models.AppSetting = _Row
    for name, mod in (('app', types.ModuleType('app')),
                      ('app.db', types.ModuleType('app.db')),
                      ('app.db.base', base), ('app.db.models', models)):
        monkeypatch.setitem(sys.modules, name, mod)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exec(compile(atlas._SEED_RELAY_CHOICE, '<seed>', 'exec'), {})
    return out.getvalue(), session


def test_a_never_saved_email_page_is_ticked(monkeypatch):
    table = {}
    out, session = _run_seed(monkeypatch, table)

    assert 'relay-choice: ticked' in out
    row = table[atlas.RELAY_CHOICE_KEY]
    assert row.value == 'true' and row.updated_by == 'infra-TAK'
    assert session.committed


@pytest.mark.parametrize('stored', ['', 'true'])
def test_an_operator_choice_is_never_changed(monkeypatch, stored):
    """`""` is a deliberate untick, not an absence."""
    row = _Row(atlas.RELAY_CHOICE_KEY, stored, 'operator')
    table = {atlas.RELAY_CHOICE_KEY: row}
    out, session = _run_seed(monkeypatch, table)

    assert 'relay-choice: kept' in out
    assert table[atlas.RELAY_CHOICE_KEY] is row
    assert row.value == stored and row.updated_by == 'operator'
    assert not session.committed


def test_an_own_smtp_server_is_never_rerouted(monkeypatch):
    table = {'smtp.host': _Row('smtp.host', 'mail.example.org')}
    out, session = _run_seed(monkeypatch, table)

    assert 'relay-choice: own-smtp' in out
    assert atlas.RELAY_CHOICE_KEY not in table
    assert not session.committed


def test_a_blank_smtp_host_is_not_an_own_server(monkeypatch):
    table = {'smtp.host': _Row('smtp.host', '  ')}
    out, _ = _run_seed(monkeypatch, table)

    assert 'relay-choice: ticked' in out


def _ctx(from_addr):
    return {'load_settings': lambda: {'email_relay': {'from_addr': from_addr}}}


def test_nothing_runs_without_a_relay(monkeypatch):
    calls = []
    monkeypatch.setattr(atlas, '_compose_exec',
                        lambda *a, **k: calls.append(a) or '')
    atlas._seed_relay_choice(_ctx(''), lambda m: None)

    assert calls == []


def test_it_runs_in_the_deployment_it_was_asked_about(monkeypatch):
    seen = {}

    def fake(ctx, argv, timeout=60, stdin=None, inst=None):
        seen.update(argv=argv, inst=inst)
        return 'relay-choice: ticked\n'

    monkeypatch.setattr(atlas, '_compose_exec', fake)
    logged = []
    atlas._seed_relay_choice(_ctx('tak@example.org'), logged.append,
                             inst={'slug': 'corona'})

    assert seen['argv'] == ['python', '-c', atlas._SEED_RELAY_CHOICE]
    assert seen['inst'] == {'slug': 'corona'}
    assert any('Email Relay' in m for m in logged)


@pytest.mark.parametrize('out', [None, 'Traceback: no such table'])
def test_a_failed_seed_says_so_and_does_not_raise(monkeypatch, out):
    monkeypatch.setattr(atlas, '_compose_exec', lambda *a, **k: out)
    logged = []
    atlas._seed_relay_choice(_ctx('tak@example.org'), logged.append)

    assert any(m.startswith('⚠') for m in logged)


@pytest.mark.parametrize('runner', ['deploy', '_run_update'])
def test_seeded_after_the_relay_is_handed_over(runner):
    """Ticked before the api has the relay's address, ATLAS would show it
    as ticked and unconfigured."""
    body = _body(runner)

    assert '_seed_relay_choice(' in body, runner
    assert body.index('_push_email_relay(') < body.index('_seed_relay_choice(')
