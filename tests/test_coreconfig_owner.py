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
"""TAK Server can read its own CoreConfig.xml after a managed-database install.

Field 2026-10-15: two fresh external_db installs (AWS RDS) on non-root consoles. The deploy
seeds CoreConfig.xml from the example before TAK's first start; the broker created that file
as root, and at 640 TAK (user `tak`) could no longer read it:
    DistributedConfiguration - CoreConfig.xml (Permission denied)
    Failed to find deployed service: distributed-configuration
TAK ran on what it had loaded until the next restart, then could not start at all. The rpm
and container seeds always chowned their seed; this one did not.
"""

import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, name
    return m.group(0)


TAK_UID = 997


def _heal(owner_uid=0, exists=True, container=False, has_tak=True, chown_ok=True):
    chowns, logs = [], []

    def stat(p):
        assert p == '/opt/tak/CoreConfig.xml'
        if not exists:
            raise FileNotFoundError(p)
        return types.SimpleNamespace(st_uid=owner_uid)

    def getpwnam(name):
        assert name == 'tak'
        if not has_tak:
            raise KeyError(name)
        return types.SimpleNamespace(pw_uid=TAK_UID)

    def chown():
        chowns.append(1)
        return chown_ok

    ns = {'os': __import__('os'), 'CORECONFIG_PATH': '/opt/tak/CoreConfig.xml',
          '_tak_is_container': lambda: container, '_tak_coreconfig_give_to_tak': chown}
    exec(compile(_fn('_startup_heal_coreconfig_owner'), 'app.py', 'exec'), ns)
    out = ns['_startup_heal_coreconfig_owner'](logs.append, stat=stat, getpwnam=getpwnam, chown=chown)
    return out, chowns, logs


def test_root_owned_coreconfig_goes_back_to_tak():
    out, chowns, logs = _heal(owner_uid=0)
    assert out is True and chowns == [1]
    assert 'gave it back to tak:tak' in logs[0]


def test_tak_owned_coreconfig_is_left_alone():
    out, chowns, logs = _heal(owner_uid=TAK_UID)
    assert out is False and chowns == [] and logs == []


def test_container_tak_is_left_alone():
    assert _heal(owner_uid=0, container=True)[1] == []


def test_no_coreconfig_or_no_tak_user_does_nothing():
    assert _heal(exists=False)[1] == []
    assert _heal(has_tak=False)[1] == []


def test_failed_chown_says_what_it_means():
    out, chowns, logs = _heal(owner_uid=0, chown_ok=False)
    assert out is False and chowns == [1]
    assert 'cannot read its config' in logs[0]


def test_chown_is_argv_through_the_broker():
    src = _fn('_tak_coreconfig_give_to_tak')
    assert "_sudo_wrap(['chown', 'tak:tak', CORECONFIG_PATH])" in src
    assert 'shell=True' not in src


def test_external_db_seed_chowns_right_after_writing():
    i = APP.index("_write_priv('/opt/tak/CoreConfig.xml', _seed)")
    seg = APP[i:i + 600]
    assert seg.index('_tak_coreconfig_give_to_tak()') < seg.index('seeded CoreConfig.xml from CoreConfig.example.xml')


def test_startup_heal_runs_before_the_8446_heal():
    start = APP[APP.index('def _startup_migrations('):]
    assert start.index('_startup_heal_coreconfig_owner(') < start.index('_selfheal_takserver_le_cert(')
