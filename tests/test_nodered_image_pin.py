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
"""Node-RED image moved off 4.0 (Node-RED 4.0.9 on end-of-life Node 20).

The 4.0 tag carried jsonata 2.0.5 (CVE-2026-77413/14/15), multer 1.4.5-lts.1 and
ws 7.5.10 (CVE-2026-48779). 4.1.16-22 is Node-RED 4.1.16 on Node 22.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _pin():
    return re.search(r"^NODERED_IMAGE = '([^']+)'", APP, re.M).group(1)


def _line_re():
    src = re.search(r"^_NODERED_IMAGE_LINE_RE = (re\.compile\(.*\))$", APP, re.M).group(1)
    return eval(src, {'re': re})


def _v(s):
    return tuple(int(x) for x in re.findall(r'\d+', s)[:3])


def test_pin_is_exact_and_past_the_advisories():
    pin = _pin()
    repo, tag = pin.split(':')
    assert repo == 'nodered/node-red'
    # exact Node-RED version + Node major, never a moving tag like 4.1 or latest
    m = re.fullmatch(r'(\d+\.\d+\.\d+)-(\d+)', tag)
    assert m, tag
    assert _v(m.group(1)) >= (4, 1, 16)
    assert int(m.group(2)) >= 22


def test_no_compose_template_hardcodes_a_node_red_tag():
    # both deploy templates (local + remote) take the constant
    assert len(re.findall(r'^    image: \{NODERED_IMAGE\}$', APP, re.M)) == 2
    hard = re.findall(r'image: nodered/node-red:[^\s\'"]+', APP)
    assert hard == [], hard


def test_remote_template_is_an_fstring_so_the_pin_renders():
    i = APP.index('    image: {NODERED_IMAGE}\n    container_name: nodered\n    restart: unless-stopped\n'
                  '    user: "1000:1000"')
    assert APP[APP.rindex('compose_yml = ', 0, i):i].startswith('compose_yml = f"""')


def test_update_moves_any_old_tag_onto_the_pin():
    rx, pin = _line_re(), _pin()
    for old in ('latest', '4.0', '4.0.9', '4.1', '3.1.9'):
        compose = ('services:\n  node-red:\n    image: nodered/node-red:%s\n'
                   '    container_name: nodered\n' % old)
        m = rx.search(compose)
        assert m, old
        out = rx.sub(lambda mm: mm.group(1) + pin, compose, count=1)
        assert '    image: %s\n' % pin in out
        assert 'node-red:%s\n' % old not in out


def test_update_leaves_other_images_alone():
    rx = _line_re()
    assert not rx.search('    image: ghcr.io/x/node-red:4.0\n')
    assert not rx.search('    image: nodered/node-red-docker:4.0\n')


def test_update_path_pulls_before_recreate_and_covers_remote():
    body = APP[APP.index('def _auto_nodered():'):]
    body = body[:body.index('_auto_harden_containers()\n')]
    assert '_NODERED_IMAGE_LINE_RE.sub(' in body
    assert body.index('_docker_compose_pull(None, nr_dir') < body.index(
        "subprocess.run(_sudo_wrap(['docker', 'compose', 'up', '-d']), cwd=nr_dir")
    assert 'def _auto_nodered_image_remote():' in body
    assert re.search(r'^            _auto_nodered_image_remote\(\)$', body, re.M)
