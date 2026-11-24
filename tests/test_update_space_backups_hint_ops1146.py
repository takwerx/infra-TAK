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
"""A "not enough free disk" message of an update says where the big files are (ops #1146, infra-TAK #670).

Field: a user whose CloudTAK Update was refused for disk space asked which old backups are safe to
remove. The message said "delete old logs or backups" and named no page. Every update refusal now
carries one sentence naming the Guard Dog "Full-stack backups" list and the TAK Server snapshots.

app.py cannot be imported in a test, so the pieces are cut out of it.
"""

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
GUARDDOG = (REPO / 'templates' / 'guarddog.html').read_text(encoding='utf-8')
TAKSERVER = (REPO / 'templates' / 'takserver.html').read_text(encoding='utf-8')
GB = 1024 ** 3


def _hint():
    for node in ast.parse(APP).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == '_FREE_SPACE_BACKUPS_HINT' for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('_FREE_SPACE_BACKUPS_HINT is missing from app.py')


def test_hint_names_the_lists_a_user_sees_on_screen():
    hint = _hint()
    assert 'Guard Dog' in hint and '"Full-stack backups"' in hint
    assert 'TAK Server' in hint and '"Snapshots & Recovery"' in hint and 'snapshots' in hint
    # the names must be the ones on the pages, or the user cannot find them
    assert '>Full-stack backups<' in GUARDDOG
    assert 'Snapshots &amp; Recovery' in TAKSERVER and 'TAK Server Snapshots' in TAKSERVER
    assert 'stackbkDelete' in GUARDDOG and 'deleteSnapshot' in TAKSERVER, 'both lists must have a Delete'


def test_cloudtak_update_refusal_carries_the_hint():
    fn = next(n for n in ast.parse(APP).body
              if isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_update_space_lines')
    ns = {'_FREE_SPACE_BACKUPS_HINT': _hint()}
    exec(compile(ast.get_source_segment(APP, fn), 'app.py', 'exec'), ns)
    lines = ns['_cloudtak_update_space_lines'](
        {'what': 'the CloudTAK images and build cache', 'where': '/var/lib/docker',
         'free': 3 * GB, 'need': 25 * GB})
    assert _hint() in '\n'.join(lines)


# Each place that refuses (or fails) an update for disk space, found by its own wording. The hint
# must be used within the same message.
_SITES = [
    'Update Now needs ~1 GB free',                              # console Update Now
    'Free space and retry - see the Disk card',                 # CloudTAK build died on a full disk
    'not enough free disk for the WebODM database upgrade',     # WebODM database upgrade
    'Not enough disk for a rollback-safe migration: %s free',   # TAK Server 5.8 migration (this box)
    'not enough free disk for a full-stack backup',             # the backup an update takes first
]


def test_every_update_space_message_uses_the_hint():
    for site in _SITES:
        assert APP.count(site) == 1, f'message not found exactly once: {site!r}'
        i = APP.index(site)
        assert '_FREE_SPACE_BACKUPS_HINT' in APP[i:i + 900], f'no backups hint with: {site!r}'
