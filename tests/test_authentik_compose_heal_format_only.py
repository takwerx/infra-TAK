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
"""The compose self-heal leaves a formatting-only difference alone (ops #860).

Found on a box test of ops #814: the pool-size writer (PyYAML defaults) and the
pgbouncer / compose-patch / worker direct-pg writers (width=200, allow_unicode) dump
the Authentik compose differently. A console start then saw "not canonical", rewrote
the file, logged "normalized YAML", and every caller recreated the LDAP outpost under
a running TAK Server. Users got no groups over HTTPS until the repair ended.

Only duplicate mapping keys are real damage. Real `_self_heal_authentik_compose` and
`_validate_authentik_compose` are run here on files in each writer's format.
"""

import ast
import datetime
import os
import pathlib
import subprocess

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
FUNCS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}

# A postgres command line over 80 characters is what makes width=200 and the default
# dump differ on a real Authentik compose.
LONG_CMD = ('postgres -c max_connections=2000 -c shared_buffers=12GB -c effective_cache_size=36GB '
            '-c work_mem=16MB -c maintenance_work_mem=2GB -c wal_buffers=64MB -c max_wal_size=4GB '
            '-c statement_timeout=120s -c idle_session_timeout=300s')
DOC = {
    'services': {
        'postgresql': {'image': 'docker.io/library/postgres:16-alpine', 'command': LONG_CMD,
                       'cap_drop': ['ALL']},
        'pgbouncer': {'image': 'edoburu/pgbouncer', 'environment': {
            'DEFAULT_POOL_SIZE': 300, 'RESERVE_POOL_SIZE': 50, 'MAX_CLIENT_CONN': 5000}},
        'ldap': {'image': 'ghcr.io/goauthentik/ldap', 'restart': 'unless-stopped'},
    },
}


def _dump_default(data):
    # _ensure_authentik_pgbouncer_pool_size and the heal itself
    return yaml.safe_dump(data, default_flow_style=False, sort_keys=False)


def _dump_w200(data):
    # _ensure_authentik_pgbouncer, _ensure_authentik_compose_patches, worker direct-pg
    return yaml.safe_dump(data, default_flow_style=False, sort_keys=False,
                          allow_unicode=True, width=200)


@pytest.fixture
def heal(tmp_path):
    src = '\n'.join(ast.get_source_segment(APP, FUNCS[n]) for n in
                    ('_validate_authentik_compose', '_self_heal_authentik_compose'))
    # Keep the stamp file out of /var/lib.
    src = src.replace("'/var/lib/takwerx-console/authentik-compose-heal.last'",
                      repr(str(tmp_path / 'heal.last')))
    ns = {'os': os, 'subprocess': subprocess, 'datetime': datetime.datetime,
          'VERSION': 'test'}
    exec(src, ns)
    return ns['_self_heal_authentik_compose'], tmp_path / 'docker-compose.yml', tmp_path / 'heal.last'


def test_formats_really_differ():
    """Guards the premise: if this ever passes the two dumps are equal, the other tests prove nothing."""
    assert _dump_default(DOC) != _dump_w200(DOC)


def test_width200_file_is_left_alone_and_does_not_signal_a_recreate(heal):
    run, path, stamp = heal
    text = _dump_w200(DOC)
    path.write_text(text)
    assert run(str(path)) is None, 'a formatting-only difference must not report "normalized YAML"'
    assert path.read_text() == text, 'file must not be rewritten'
    assert 'only formatting differs' in stamp.read_text()


def test_pool_size_then_other_writer_then_heal_never_signals(heal):
    """Each writer in turn, then the heal at the next console start."""
    run, path, _ = heal
    for dump in (_dump_default, _dump_w200, _dump_default, _dump_w200):
        path.write_text(dump(DOC))
        msg = run(str(path))
        assert not msg or 'normalized YAML' not in msg


def test_duplicate_keys_are_still_healed_and_signal_a_recreate(heal):
    run, path, _ = heal
    dup = _dump_w200(DOC).replace(
        "    cap_drop:\n    - ALL\n", "    cap_drop:\n    - ALL\n    cap_drop:\n    - NET_RAW\n", 1)
    assert dup.count('cap_drop') == 2
    yaml.safe_load(dup)  # PyYAML accepts duplicate keys (last wins); docker compose does not
    path.write_text(dup)
    msg = run(str(path))
    assert msg and 'normalized YAML' in msg
    healed = path.read_text()
    assert healed.count('cap_drop') == 1
    assert yaml.safe_load(healed)['services']['postgresql']['cap_drop'] == ['NET_RAW']
    assert run(str(path)) is None, 'second pass is a no-op'


def test_wiring_callers_recreate_only_on_normalized_yaml():
    """The three callers still gate the outpost recreate on the message text the heal
    returns only for real repairs."""
    assert APP.count("'normalized YAML' in _heal_msg") == 2
    assert APP.count("'normalized YAML' not in _heal_msg") == 1
