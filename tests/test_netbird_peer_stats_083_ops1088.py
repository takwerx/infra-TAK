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
"""NetBird 0.83: the card's peer count must read the new connection tables (ops #1088).

NetBird 0.83.0 stopped reading and writing peers.peer_status_connected (the column stays,
frozen at its last 0.82 value). A peer counts as connected while peer_connections.instance_id
names a management_instances row whose last_seen is under 5 minutes old. On a box with no PAT
the card reads store.db directly, so after the pin moved to 0.83 it showed every peer that was
connected at the update (or none) for ever, with no error.

app.py cannot be imported in a test, so the function is cut out of it and run: the code under
test is the shipped text. The stores are built the way the 0.83 migration leaves them: the old
column kept, peer_connections and management_instances added.
"""

import ast
import os
import pathlib
import re
import sqlite3

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _fn():
    parts = [ast.get_source_segment(APP, n) for n in ast.parse(APP).body
             if isinstance(n, ast.FunctionDef) and n.name == '_netbird_peer_stats_from_db']
    assert len(parts) == 1, 'the function under test was renamed or removed'
    ns = {'os': os, 'NETBIRD_INSTALL_DIR': '/nonexistent'}
    exec(compile(parts[0], 'app.py', 'exec'), ns)
    return ns['_netbird_peer_stats_from_db']


def _store(tmp_path, peers, instances=None, connections=None):
    """peers: [(id, frozen peer_status_connected)]. instances: [(id, seconds_since_heartbeat)].
    connections: [(peer_id, instance_id or None)]. instances None = a 0.82 store (old tables only)."""
    data = tmp_path / 'data'
    data.mkdir(parents=True)
    conn = sqlite3.connect(data / 'store.db')
    conn.execute('CREATE TABLE peers (id TEXT PRIMARY KEY, account_id TEXT, peer_status_connected INTEGER)')
    conn.executemany("INSERT INTO peers VALUES (?, 'acc', ?)", peers)
    if instances is not None:
        conn.execute('CREATE TABLE management_instances (id TEXT PRIMARY KEY, hostname TEXT, '
                     'started_at DATETIME, last_seen DATETIME)')
        conn.execute('CREATE TABLE peer_connections (peer_id TEXT PRIMARY KEY, account_id TEXT, '
                     'instance_id TEXT, session_started_at INTEGER, last_seen DATETIME)')
        for iid, age in instances:
            conn.execute("INSERT INTO management_instances VALUES (?, 'h', CURRENT_TIMESTAMP, "
                         "datetime('now', ?))", (iid, f'-{age} seconds'))
        conn.executemany("INSERT INTO peer_connections VALUES (?, 'acc', ?, 0, NULL)", connections or [])
    conn.commit()
    conn.close()
    return str(tmp_path)


def test_083_store_counts_peers_held_by_a_live_instance_not_the_frozen_column(tmp_path):
    # All three peers were connected when 0.82 stopped writing the column. Now only p1 is held.
    nb = _store(tmp_path, [('p1', 1), ('p2', 1), ('p3', 1)],
                instances=[('i1', 30)], connections=[('p1', 'i1'), ('p2', None), ('p3', None)])
    assert _fn()(nb) == {'total': 3, 'connected': 1}


def test_083_store_counts_a_peer_that_connected_after_the_update(tmp_path):
    # The column says 0 (the peer joined on 0.83, the column was never written); it is connected.
    nb = _store(tmp_path, [('p1', 0), ('p2', 0)],
                instances=[('i1', 10)], connections=[('p1', 'i1')])
    assert _fn()(nb) == {'total': 2, 'connected': 1}


def test_083_peer_held_by_a_dead_instance_is_not_connected(tmp_path):
    # i-dead stopped heartbeating 10 minutes ago (a crashed server); i-live is the running one.
    nb = _store(tmp_path, [('p1', 1), ('p2', 1), ('p3', 1)],
                instances=[('i-dead', 600), ('i-live', 5)],
                connections=[('p1', 'i-dead'), ('p2', 'i-live'), ('p3', 'i-dead')])
    assert _fn()(nb) == {'total': 3, 'connected': 1}


def test_082_store_still_reads_the_old_column(tmp_path):
    nb = _store(tmp_path, [('p1', 1), ('p2', 0), ('p3', 1)])
    assert _fn()(nb) == {'total': 3, 'connected': 2}


def test_rollback_to_082_on_a_083_store_reads_the_old_column_again(tmp_path):
    # 0.82.1 started on a migrated store: the new tables stay but nothing heartbeats them (the only
    # instance row is 10 minutes old), and 0.82.1 writes the old column again.
    nb = _store(tmp_path, [('p1', 1), ('p2', 1), ('p3', 0)],
                instances=[('i-old', 600)], connections=[('p1', 'i-old'), ('p2', 'i-old')])
    assert _fn()(nb) == {'total': 3, 'connected': 2}


def test_missing_store_or_a_broken_one_gives_none(tmp_path):
    assert _fn()(str(tmp_path)) is None
    (tmp_path / 'data').mkdir()
    (tmp_path / 'data' / 'store.db').write_bytes(b'not a database')
    assert _fn()(str(tmp_path)) is None


def test_dev_pair_is_0_83_2_and_vetted_pair_has_not_moved():
    # ops #1088: the 0.83.2 / v2.98.0 pair is under trial on dev; main boxes stay on 0.82.1 / v2.96.0
    # until the lead promotes it after the gated T&E.
    def pin(name):
        return re.search(rf'^{name} = "[^:"]+:v?([^"]+)"', APP, re.M).group(1)
    assert pin('NETBIRD_SERVER_DEV_IMAGE') == '0.83.2'
    assert pin('NETBIRD_DASHBOARD_DEV_IMAGE') == '2.98.0'
    assert pin('NETBIRD_SERVER_IMAGE') == '0.82.1'
    assert pin('NETBIRD_DASHBOARD_IMAGE') == '2.96.0'
