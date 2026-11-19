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
"""A new ATLAS deploy on a non-root console must get its Postgres volume (ops #933).

`modules/atlas.py::_bind_pg_volume` runs, through the broker:

    docker volume create --driver local -o type=none -o device=<store>/pgdata -o o=bind <name>

`_check_docker_volume` (ops #645) refused every option, so every NEW deploy stopped at
"Reserved store". The broker must accept exactly that shape, and nothing wider:
the device must sit inside an ATLAS deployment's store, and every other volume
option stays refused (`device=/etc` is the escape the rule exists for).

Nothing is executed: the rulebook is called directly.
"""

import importlib.util
import os
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops933',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()
HOME = B._NONROOT_HOME
STORE = HOME + '/atlas/%s/store/pgdata'


def _create(device, name='takmdm_pgdata', driver='local', extra=()):
    return (['docker', 'volume', 'create', '--driver', driver,
             '-o', 'type=none', '-o', 'device=' + device, '-o', 'o=bind']
            + list(extra) + [name])


LEGIT = [
    # the exact calls modules/atlas.py::_bind_pg_volume sends (plain and agency)
    _create(STORE % 'default', 'takmdm_pgdata'),
    _create(STORE % 'corona', 'takmdm-corona_pgdata'),
    # a root-era console keeps its deployments under /root
    _create('/root/atlas/default/store/pgdata', 'takmdm_pgdata'),
    # the plain forms that always worked
    ['docker', 'volume', 'create', 'takserver-db-data'],
    ['docker', 'volume', 'inspect', 'takmdm_pgdata', '--format', '{{.Options.device}}'],
    ['docker', 'volume', 'rm', '-f', 'takmdm_pgdata'],
]


ESCAPES = [
    # the ops #645 escapes stay refused
    ['docker', 'volume', 'create', '--opt', 'type=none', '--opt', 'device=/etc',
     '--opt', 'o=bind', 'etcvol'],
    ['docker', 'volume', 'create', '-o', 'device=/etc', 'etcvol'],
    ['docker', 'volume', 'create', '--driver', 'evil', 'v'],
    # the ATLAS shape, pointed outside an ATLAS store
    _create('/etc', 'takmdm_pgdata'),
    _create('/etc/caddy/store/pgdata', 'takmdm_pgdata'),
    _create(HOME + '/atlas/../.ssh/store/pgdata', 'takmdm_pgdata'),
    _create(HOME + '/atlas/default/store/pgdata/../../../../.ssh', 'takmdm_pgdata'),
    _create(HOME + '/TAK-Portal/store/pgdata', 'takmdm_pgdata'),
    _create(HOME + '/atlas/default/other', 'takmdm_pgdata'),
    _create(HOME + '/atlas/store/pgdata', 'takmdm_pgdata'),
    _create(HOME + '/atlas/a/b/store/pgdata', 'takmdm_pgdata'),
    _create('relative/atlas/default/store/pgdata', 'takmdm_pgdata'),
    # the volume name must be an ATLAS Postgres volume
    _create(STORE % 'default', 'takserver-db-data'),
    _create(STORE % 'default', '../x'),
    _create(STORE % 'default', 'takmdm_pgdata\n'),
    _create(STORE % 'default' + '\n', 'takmdm_pgdata'),
    # every option must be one of the three ATLAS sends, once, with its exact value
    _create(STORE % 'default', extra=['-o', 'o=bind,rw']),
    _create(STORE % 'default', extra=['-o', 'device=/etc']),
    _create(STORE % 'default', extra=['--label', 'x=y']),
    _create(STORE % 'default', extra=['--opt=device=/etc']),
    ['docker', 'volume', 'create', '--driver', 'local', '-o', 'type=tmpfs',
     '-o', 'device=' + STORE % 'default', '-o', 'o=bind', 'takmdm_pgdata'],
    ['docker', 'volume', 'create', '--driver', 'local', '-o', 'type=none',
     '-o', 'device=' + STORE % 'default', '-o', 'o=bind,suid', 'takmdm_pgdata'],
    # missing pieces: a volume that is not a bind to the store is not the ATLAS call
    ['docker', 'volume', 'create', '--driver', 'local', '-o', 'device=' + STORE % 'default',
     'takmdm_pgdata'],
    ['docker', 'volume', 'create', '-o', 'type=none', '-o', 'o=bind', 'takmdm_pgdata'],
    ['docker', 'volume', 'create', '--driver', 'local', '-o', 'type=none',
     '-o', 'device=' + STORE % 'default', '-o', 'o=bind'],
    # two names
    _create(STORE % 'default', 'takmdm_pgdata') + ['second'],
]


@pytest.mark.parametrize('argv', LEGIT, ids=lambda a: ' '.join(a)[:90])
def test_atlas_volume_shape_allowed(argv):
    B.check_exec(list(argv))


@pytest.mark.parametrize('argv', ESCAPES, ids=lambda a: ' '.join(a)[:90])
def test_wider_volume_shapes_still_denied(argv):
    with pytest.raises(B.Denied):
        B.check_exec(list(argv))


def test_symlinked_store_is_denied(tmp_path, monkeypatch):
    """The console owns `<home>/atlas/...`, so it can plant a link that points the
    bind at a root-only directory. The device is resolved, not just read."""
    home = tmp_path / 'home' / 'takwerx'
    (home / 'atlas' / 'default' / 'store').mkdir(parents=True)
    target = tmp_path / 'secret'
    target.mkdir()
    link = home / 'atlas' / 'default' / 'store' / 'pgdata'
    os.symlink(target, link)
    root = str(home / 'atlas') + '/'
    monkeypatch.setattr(B, '_ATLAS_VOLUME_ROOTS', (root,))
    monkeypatch.setattr(B, 'PATH_ALLOW', B.PATH_ALLOW + (root,))
    monkeypatch.setattr(B, '_CONSOLE_OWNED_PREFIXES', B._CONSOLE_OWNED_PREFIXES + (root,))
    with pytest.raises(B.Denied):
        B.check_exec(_create(str(link)))
    link.unlink()
    link.mkdir()
    B.check_exec(_create(str(link)))


def test_atlas_module_sends_the_shape_the_broker_accepts(monkeypatch):
    """The caller and the rule must stay one thing: read the real argv out of
    modules/atlas.py and run it through the rulebook."""
    from modules import atlas
    calls = []
    monkeypatch.setattr(
        atlas, '_run_root',
        lambda argv, timeout=120: (calls.append(list(argv)) or
                                   ((1, '') if argv[2] == 'inspect' else (0, ''))))
    for slug, vol in ((None, 'takmdm_pgdata'), ('corona', 'takmdm-corona_pgdata')):
        calls.clear()
        pgdir = STORE % (slug or 'default')
        assert atlas._bind_pg_volume(pgdir, lambda *_: None, volume=vol) is None
        create = [c for c in calls if c[:3] == ['docker', 'volume', 'create']]
        assert len(create) == 1
        B.check_exec(create[0])
