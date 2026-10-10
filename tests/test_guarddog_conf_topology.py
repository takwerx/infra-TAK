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
"""guarddog.conf carries the database topology on every box shape (GH #101).

The writer and its helpers are cut out of app.py and run against a fake box: a
dict standing in for /opt/tak-guarddog/guarddog.conf behind the broker, a
CoreConfig string, and settings. The first test is the reporter's box: a split
install whose settings.json never said two_server, with a 29-byte guarddog.conf
holding only the cert password.
"""

import copy
import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

GD = '/opt/tak-guarddog/guarddog.conf'
SPLIT_CC = '<connection url="jdbc:postgresql://10.20.0.5:5432/cot" username="martiuser" password="x"/>'
LOCAL_CC = '<connection url="jdbc:postgresql://127.0.0.1:5432/cot" username="martiuser" password="x"/>'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


FUNCS = ('_tak_deployment_defaults', '_deep_merge_dict', '_normalize_tak_deployment_config',
         '_get_tak_deployment_config', '_tak_db_is_remote', '_tak_db_endpoint_from_coreconfig',
         '_guarddog_db_topology', '_write_guarddog_conf')


class Box:
    def __init__(self, conf=None, coreconfig=SPLIT_CC, container=False, local_ips=('10.20.0.9',)):
        self.files = {}
        if conf is not None:
            self.files[GD] = conf if isinstance(conf, str) else json.dumps(conf)
        self.coreconfig = coreconfig
        self.container = container
        self.writes = []
        self.read_fails = False
        ns = {
            'os': _FakeOs(self), 'json': json, 're': re, 'copy': copy,
            'socket': _FakeSocket(), '_list_local_ipv4s': lambda: list(local_ips),
            'GUARDDOG_CONF_PATH': GD,
            '_GD_DB_KEYS': ('two_server', 'external_db', 'db_host', 'db_port'),
            '_read_priv': self._read_priv, '_write_priv': self._write_priv,
            '_read_coreconfig': self._read_coreconfig,
            '_tak_is_container': lambda: self.container,
        }
        for name in FUNCS:
            exec(compile(_fn(name), f'app.py:{name}', 'exec'), ns)
        self.ns = ns

    def _read_priv(self, path):
        if self.read_fails:
            raise PermissionError(13, 'Permission denied', path)
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def _write_priv(self, path, content, mode='w', perm=None):
        assert perm == 0o600, 'guarddog.conf holds the cert password: must stay 600'
        self.writes.append(path)
        self.files[path] = content

    def _read_coreconfig(self):
        if self.coreconfig is None:
            raise PermissionError(13, 'Permission denied', '/opt/tak/CoreConfig.xml')
        return self.coreconfig

    def write(self, settings=None, updates=None):
        return self.ns['_write_guarddog_conf'](settings or {}, updates)

    @property
    def conf(self):
        return json.loads(self.files[GD])


class _FakeOs:
    def __init__(self, box):
        self.box = box
        self.path = self

    def exists(self, p):
        return p in self.box.files


class _FakeSocket:
    @staticmethod
    def gethostname():
        return 'app-node'

    @staticmethod
    def getfqdn():
        return 'app-node.example'


def test_reporters_box_split_install_settings_never_knew():
    box = Box(conf={'tak_cert_pass': 'atakatak'})          # the 29-byte file
    ok, msg = box.write({})                                 # settings: no tak_deployment
    assert ok, msg
    c = box.conf
    assert c['two_server'] is True and c['external_db'] is False
    assert (c['db_host'], c['db_port']) == ('10.20.0.5', 5432)
    assert c['tak_cert_pass'] == 'atakatak'
    assert (c['db_topology'], c['db_topology_source']) == ('two_server', 'coreconfig')


def test_settings_two_server_wins_and_keeps_its_port():
    box = Box(conf={})
    box.write({'tak_deployment': {'mode': 'two_server', 'server_one': {'host': '10.9.9.9'},
                                  'database': {'port': 6543}}})
    c = box.conf
    assert (c['two_server'], c['db_host'], c['db_port']) == (True, '10.9.9.9', 6543)
    assert c['db_topology_source'] == 'settings'


def test_two_server_without_host_falls_back_to_coreconfig():
    box = Box(conf={})
    box.write({'tak_deployment': {'mode': 'two_server'}})
    assert box.conf['db_host'] == '10.20.0.5'
    assert box.conf['db_topology_source'] == 'coreconfig'


def test_external_db():
    box = Box(conf={})
    box.write({'tak_deployment': {'mode': 'external_db',
                                  'external_db': {'host': 'db.rds.example', 'port': 5433}}})
    c = box.conf
    assert (c['two_server'], c['external_db'], c['db_host'], c['db_port']) == \
        (False, True, 'db.rds.example', 5433)
    assert c['db_topology'] == 'external_db'


def test_port_comes_from_the_jdbc_url():
    box = Box(conf={}, coreconfig=SPLIT_CC.replace(':5432/', ':6432/'))
    box.write({})
    assert box.conf['db_port'] == 6432


def test_local_db_clears_a_stale_split_section():
    box = Box(conf={'two_server': True, 'db_host': '10.1.1.1', 'db_port': 5432,
                    'tak_cert_pass': 'p'}, coreconfig=LOCAL_CC)
    box.write({})
    c = box.conf
    assert not any(k in c for k in ('two_server', 'external_db', 'db_host', 'db_port'))
    assert (c['db_topology'], c['db_topology_source'], c['tak_cert_pass']) == ('local', 'coreconfig', 'p')


def test_own_address_in_coreconfig_is_local():
    box = Box(conf={}, coreconfig=SPLIT_CC.replace('10.20.0.5', '10.20.0.9'))
    box.write({})
    assert box.conf['db_topology'] == 'local'


def test_container_alias_is_not_mistaken_for_a_remote_db():
    cc = SPLIT_CC.replace('10.20.0.5', 'tak-database')
    box = Box(conf={'two_server': True, 'db_host': 'tak-database', 'db_port': 5432},
              coreconfig=cc, container=True)
    box.write({})
    assert 'db_host' not in box.conf
    assert box.conf['db_topology_source'] == 'container'


def test_unreadable_coreconfig_keeps_what_the_file_says():
    box = Box(conf={'two_server': True, 'db_host': '10.1.1.1', 'db_port': 5432},
              coreconfig=None)
    ok, _ = box.write({})
    assert ok
    c = box.conf
    assert (c['two_server'], c['db_host']) == (True, '10.1.1.1')
    assert c['db_topology_source'] == 'kept'


def test_unreadable_conf_is_never_replaced():
    """The old metrics migration: open() fails on a non-root console, conf = {}, and the
    whole file was replaced by the cert password alone."""
    box = Box(conf={'two_server': True, 'db_host': '10.1.1.1', 'db_port': 5432})
    box.read_fails = True
    ok, msg = box.write({}, {'tak_cert_pass': 'atakatak'})
    assert not ok and 'unreadable' in msg
    assert box.writes == []


def test_corrupt_conf_is_repaired():
    box = Box(conf='{"tak_cert_pass": "p"')
    ok, _ = box.write({}, {'tak_cert_pass': 'p'})
    assert ok
    assert (box.conf['tak_cert_pass'], box.conf['db_host']) == ('p', '10.20.0.5')


def test_merge_keeps_unrelated_keys_and_none_removes():
    box = Box(conf={'tak_cert_pass': 'p', 'tak_mode': 'container', 'tak_container': 'takserver'},
              coreconfig=LOCAL_CC)
    box.write({}, {'tak_mode': None, 'tak_container': None, 'db_container': None})
    c = box.conf
    assert 'tak_mode' not in c and 'tak_container' not in c
    assert c['tak_cert_pass'] == 'p'


def test_no_rewrite_when_nothing_changed():
    box = Box(conf={'tak_cert_pass': 'p'})
    box.write({})
    box.writes.clear()
    ok, msg = box.write({}, {'tak_cert_pass': 'p'})
    assert ok and msg.startswith('unchanged')
    assert box.writes == []


def test_fresh_box_without_a_conf():
    box = Box(conf=None)
    ok, _ = box.write({}, {'tak_cert_pass': 'p'})
    assert ok
    assert box.conf['db_host'] == '10.20.0.5'


def test_every_writer_goes_through_the_one_writer():
    """No second code path may write guarddog.conf by itself again."""
    hits = [m.start() for m in re.finditer(r"_write_priv\([^\n]*guarddog\.conf", APP)]
    assert hits == [], 'a guarddog.conf write bypasses _write_guarddog_conf()'
    writer = _fn('_write_guarddog_conf')
    assert '_write_priv(GUARDDOG_CONF_PATH' in writer
    assert APP.count('_write_priv(GUARDDOG_CONF_PATH') == 1
