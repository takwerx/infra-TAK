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
"""WebODM 4.0.0 → 4.0.1 (ops #820): project permission checks hardened (upstream PR 2061).

4.0.1 has no database migration and no compose change, so a box already on 4.0.0 (PostgreSQL 18)
must move to the new image with no backup and no stop of the database, and a box still on 3.3.1
must reach 4.0.1 through the same 3.x → 4.x path as before.
"""

import importlib.util
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('wo579', HERE / 'test_webodm_v4_upgrade_ops579.py')
wo579 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wo579)


def _on_400():
    """A box that took 4.0.0 (PostgreSQL 18 already, 4.0.0 webapp and worker)."""
    box = wo579.Box(pg='18')
    box.compose = wo579.OLD.replace('webodm_webapp:3.3.1', 'webodm_webapp:4.0.0')
    return box


def test_pin_is_4_0_1():
    _, ns = wo579._run(wo579.Box(pg='18'))
    assert ns['WEBODM_VERSION'] == '4.0.1'
    assert ns['WEBODM_IMAGES']['wo_webapp'] == ns['WEBODM_IMAGES']['wo_worker'] == 'webodm/webodm_webapp:4.0.1'
    # the database image is unchanged: upstream has no newer webodm_db:18 (ops #755 watches it)
    assert re.fullmatch(r'webodm/webodm_db:18@sha256:[0-9a-f]{64}', ns['WEBODM_IMAGES']['wo_db'])


def test_box_on_400_updates_to_401_without_backup_or_database_stop():
    box = _on_400()
    status, ns = wo579._run(box)
    assert status['complete'] and not status['error'], status['log']
    imgs = wo579._images(box.running_images)
    assert imgs['wo_webapp'] == imgs['wo_worker'] == 'webodm/webodm_webapp:4.0.1'
    flat = ' '.join(' '.join(map(str, c[1])) for c in box.calls)
    assert 'pg_dumpall' not in flat and 'docker stop' not in flat and 'du -sk' not in flat


def test_box_on_331_reaches_401_through_the_upgrade_path():
    box = wo579.Box()
    status, _ = wo579._run(box)
    assert status['complete'] and not status['error'], status['log']
    assert wo579._images(box.running_images)['wo_webapp'] == 'webodm/webodm_webapp:4.0.1'
    assert any('pg_dumpall' in ' '.join(c[1]) for c in box.calls if c[0] == 'run')
