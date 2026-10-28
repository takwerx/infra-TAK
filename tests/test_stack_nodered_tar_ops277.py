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
"""The full-stack backup's Node-RED archive must not cross the broker socket (ops #277).

The tar used to stream out through the exec proxy, which returns stdout base64-encoded in one
reply capped at MAX_MSG (32 MiB). A busy Node-RED (26.7 MB tar on test12) went past it and
"Back up now" ended INCOMPLETE. The broker's `stack_nodered_tar` op now writes the file itself.
"""
import hashlib
import importlib.util
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER_PY = REPO / 'broker' / 'takwerx_broker.py'


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


@pytest.fixture(scope='module')
def broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops277', BROKER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def tree(broker, tmp_path, monkeypatch):
    root = tmp_path / 'backups'
    monkeypatch.setattr(broker, 'STACK_BACKUP_DIR', str(root))
    return root


def _fake_docker(tmp_path, body):
    docker = tmp_path / 'docker'
    docker.write_text('#!/bin/sh\n' + body)
    docker.chmod(0o755)
    return str(docker)


def test_op_writes_a_tar_bigger_than_max_msg_to_disk(broker, tree, tmp_path, monkeypatch):
    # 40 MiB of stdout: as one base64 reply this is what blew the 32 MiB cap.
    n_mib = 40
    docker = _fake_docker(tmp_path, 'head -c %d /dev/zero\n' % (n_mib * 1024 * 1024))
    monkeypatch.setattr(broker.shutil, 'which', lambda n, path=None: docker if n == 'docker' else None)
    path = tree / 'stack-1' / 'nodered-data.tar'
    res = broker._do_stack_nodered_tar({'path': str(path), 'timeout': 60})
    assert res['ok'] is True
    assert res['size'] == n_mib * 1024 * 1024 > broker.MAX_MSG
    assert res['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert (path.stat().st_mode & 0o777) == 0o600
    assert not (tree / 'stack-1' / 'nodered-data.tar.hmac').exists()   # not a pg dump


def test_op_runs_only_the_fixed_argv(broker, tree, tmp_path, monkeypatch):
    docker = _fake_docker(tmp_path, 'echo "$@" >&2\nexit 3\n')
    monkeypatch.setattr(broker.shutil, 'which', lambda n, path=None: docker if n == 'docker' else None)
    res = broker._do_stack_nodered_tar({'path': str(tree / 'x' / 'nodered-data.tar'),
                                        'container': 'evil', 'argv': ['rm', '-rf', '/']})
    assert res['ok'] is False and res['returncode'] == 3
    assert res['error'] == 'exec nodered sh -c %s\n' % broker._STACK_NODERED_TAR_SH
    assert not (tree / 'x' / 'nodered-data.tar').exists()   # no truncated tar left behind


def test_op_refuses_an_empty_tar(broker, tree, tmp_path, monkeypatch):
    docker = _fake_docker(tmp_path, 'exit 0\n')
    monkeypatch.setattr(broker.shutil, 'which', lambda n, path=None: docker if n == 'docker' else None)
    path = tree / 'x' / 'nodered-data.tar'
    res = broker._do_stack_nodered_tar({'path': str(path)})
    assert res['ok'] is False and 'empty' in res['error']
    assert not path.exists()


@pytest.mark.parametrize('rel', [
    '../evil/nodered-data.tar',           # out of the tree
    'x/other.tar',                        # only the one file name
    'x/y/nodered-data.tar',               # one level deep, no nesting
    'nodered-data.tar',                   # needs a label dir
    '.hidden/nodered-data.tar',           # label must start alnum
])
def test_check_denies_anything_but_label_slash_nodered_data_tar(broker, tree, rel):
    with pytest.raises(broker.Denied):
        broker._check_stack_nodered_tar({'path': str(tree / rel)})


def test_check_allows_the_one_destination(broker, tree):
    p = tree / 'stack-20261027-154356' / 'nodered-data.tar'
    assert broker._check_stack_nodered_tar({'path': str(p)}) == str(p)


def test_op_is_gated_and_dispatched(broker):
    src = BROKER_PY.read_text(encoding='utf-8')
    assert "elif op == 'stack_nodered_tar':\n            _check_stack_nodered_tar(req)" in src
    assert "'stack_nodered_tar', 'stack_pg_restore'" in src
    assert "return _do_stack_nodered_tar(req)" in src
    verdict, _ = broker._evaluate({'op': 'stack_nodered_tar', 'path': '/etc/evil.tar'})
    assert verdict == 'DENY'


def test_console_and_broker_run_the_same_script(broker):
    ns = {}
    m = re.search(r'^_STACK_NODERED_TAR_SH = \(.*?\)\n', APP, re.S | re.M)
    exec(m.group(0), ns)
    assert ns['_STACK_NODERED_TAR_SH'] == broker._STACK_NODERED_TAR_SH


def test_stack_backup_no_longer_streams_the_tar_through_the_exec_proxy():
    body = _cut('_stack_backup')
    code = re.sub(r'#.*', '', body)
    assert '_stack_nodered_tar_priv(' in code
    assert "'nodered', 'sh', '-c'" not in code      # no docker exec of the tar from the console
    assert "nodered-data.tar'" in code


def test_console_helper_uses_the_broker_op_when_routing():
    code = re.sub(r'#.*', '', _cut('_stack_nodered_tar_priv'))
    assert "'op': 'stack_nodered_tar'" in code
    assert '_broker_should_route()' in code
