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
"""Dependabot must not bump the simulator's python line (ops #885).

Dependabot opened PR 515 (python 3.12-slim to 3.15-slim in /simulator). It failed
tests/test_node_pins_ops824.py, which pins the 3.12 line on purpose. 3.12 to 3.15 is a
minor bump, and the old ignore rule only covered major bumps. The /simulator docker block
must ignore python minor and major updates and leave patch updates on.
"""

import pathlib

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent


def _simulator_block():
    cfg = yaml.safe_load((REPO / '.github' / 'dependabot.yml').read_text(encoding='utf-8'))
    blocks = [u for u in cfg['updates']
              if u['package-ecosystem'] == 'docker' and u['directory'] == '/simulator']
    assert len(blocks) == 1
    return blocks[0]


def _ignored_types(block, name):
    types = set()
    for rule in block.get('ignore', []):
        if rule['dependency-name'] in (name, '*'):
            types.update(rule.get('update-types', []))
    return types


def test_simulator_python_minor_and_major_bumps_are_ignored():
    ignored = _ignored_types(_simulator_block(), 'python')
    assert 'version-update:semver-minor' in ignored
    assert 'version-update:semver-major' in ignored


def test_simulator_python_patch_bumps_stay_on():
    # a rule with no update-types would ignore every update, patches too
    block = _simulator_block()
    for rule in block.get('ignore', []):
        assert rule.get('update-types'), rule
    assert 'version-update:semver-patch' not in _ignored_types(block, 'python')


def test_simulator_dockerfile_is_still_the_python_3_12_line():
    # the ignore rule is only right while the pin is 3.12 (see test_node_pins_ops824.py)
    text = (REPO / 'simulator' / 'Dockerfile').read_text(encoding='utf-8')
    assert 'FROM python:3.12-slim@sha256:' in text


def test_the_other_docker_and_pip_blocks_still_ignore_major_bumps():
    cfg = yaml.safe_load((REPO / '.github' / 'dependabot.yml').read_text(encoding='utf-8'))
    for block in cfg['updates']:
        assert 'version-update:semver-major' in _ignored_types(block, '*'), block['directory']
