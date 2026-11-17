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
"""Node.js 22.23.5 security release (2026-11-11): our own image pins moved (ops #824).

The etl-shim base and the simulator base are pinned by index digest, so they never move on
their own. This test fails while either pin is on the digest of the release before.
Digests read from Docker Hub on 2026-11-16: node:22-alpine = node:22.23.5-alpine,
python:3.12-slim = python:3.12.16-slim (multi-arch indexes, amd64 + arm64).
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent

NODE_22_23_5_ALPINE = 'sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a'
NODE_22_23_4_ALPINE = 'sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914'
PYTHON_3_12_16_SLIM = 'sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b'
PYTHON_3_12_14_SLIM = 'sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea'


def _from_lines(path):
    text = (REPO / path).read_text(encoding='utf-8')
    return re.findall(r'^FROM\s+(\S+)', text, re.M)


def test_etl_shim_base_is_node_22_23_5():
    (base,) = _from_lines('modules/etlrunner/shim/Dockerfile')
    assert base == f'node:22-alpine@{NODE_22_23_5_ALPINE}'
    assert NODE_22_23_4_ALPINE not in (REPO / 'modules/etlrunner/shim/Dockerfile').read_text()


def test_simulator_base_is_python_3_12_16():
    (base,) = _from_lines('simulator/Dockerfile')
    assert base == f'python:3.12-slim@{PYTHON_3_12_16_SLIM}'
    assert PYTHON_3_12_14_SLIM not in (REPO / 'simulator/Dockerfile').read_text()


def test_the_console_names_22_23_5_as_the_fixed_node_for_the_22_line():
    # the red card flag and the Guard Dog "Security update pending" email read this table
    app = (REPO / 'app.py').read_text(encoding='utf-8')
    assert "'fixed': {22: '22.23.5', 24: '24.22.3', 26: '26.13.1'}" in app
