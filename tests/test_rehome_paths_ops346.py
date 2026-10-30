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
"""ops #346 — moving a module dir out of /root must take its absolute self-references with it.

CloudTAK's .env carries COMPOSE_FILE=/root/CloudTAK/docker-compose.yml:... , so after the
root->non-root re-home moved the dir, compose followed COMPOSE_FILE to files that no longer
existed, `up -d` failed, and the re-home rolled back on every start. The helper is cut out of
app.py and run here (app.py cannot be imported in a test), so the code under test is the shipped
text; the order of steps in the re-home itself is checked on the source.
"""

import ast
import os
import pathlib
import re
import stat

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

SRC, DST = '/root/CloudTAK', '/home/takwerx/CloudTAK'
ENV = ('CLOUDTAK_Mode=docker-compose\n'
       'COMPOSE_FILE=/root/CloudTAK/docker-compose.yml:/root/CloudTAK/docker-compose.override.yml'
       ':/root/CloudTAK/docker-compose.custom.yml\n'
       'OTHER=/root/CloudTAK2/keep:/root/CloudTAK-old\n')


def _node(cls, name):
    return next(n for n in TREE.body if isinstance(n, cls) and (
        n.name == name if cls is ast.FunctionDef else
        any(isinstance(t, ast.Name) and t.id == name for t in n.targets)))


def _helper():
    ns = {'os': os, 're': re}
    src = '\n\n'.join(ast.get_source_segment(APP, _node(c, n)) for c, n in (
        (ast.Assign, '_REHOME_COMPOSE_FILE_RE'), (ast.FunctionDef, '_rehome_rewrite_paths')))
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns['_rehome_rewrite_paths']


def _project(tmp_path):
    d = tmp_path / 'CloudTAK'
    d.mkdir()
    (d / '.env').write_text(ENV)
    os.chmod(d / '.env', 0o600)
    (d / 'docker-compose.yml').write_text('services:\n  api:\n    image: cloudtak-api\n')
    (d / 'docker-compose.override.yml').write_text(
        'services:\n  print:\n    build:\n      context: /root/cloudtak-plugin-print/service\n'
        '    volumes:\n      - /root/CloudTAK/data:/data\n')
    (d / 'notes.txt').write_text('see /root/CloudTAK\n')
    return d


def test_rewrites_env_and_compose_files_to_the_new_dir(tmp_path):
    d = _project(tmp_path)
    changed = _helper()(str(d), SRC, DST)
    assert changed == ['.env', 'docker-compose.override.yml']
    env = (d / '.env').read_text()
    assert ('COMPOSE_FILE=%s/docker-compose.yml:%s/docker-compose.override.yml:%s/docker-compose.custom.yml\n'
            % (DST, DST, DST)) in env
    assert '/root/CloudTAK/' not in env.replace('/root/CloudTAK2/', '')
    assert '      - %s/data:/data' % DST in (d / 'docker-compose.override.yml').read_text()


def test_leaves_sibling_names_and_paths_outside_the_dir_alone(tmp_path):
    d = _project(tmp_path)
    _helper()(str(d), SRC, DST)
    assert 'OTHER=/root/CloudTAK2/keep:/root/CloudTAK-old\n' in (d / '.env').read_text()
    # a plugin build context elsewhere under /root still builds (compose runs as root)
    assert 'context: /root/cloudtak-plugin-print/service' in (d / 'docker-compose.override.yml').read_text()
    assert (d / 'notes.txt').read_text() == 'see /root/CloudTAK\n'      # not a compose file


def test_keeps_mode_and_round_trips_for_the_rollback(tmp_path):
    d = _project(tmp_path)
    h = _helper()
    before = {n: (d / n).read_text() for n in ('.env', 'docker-compose.override.yml')}
    h(str(d), SRC, DST)
    assert stat.S_IMODE(os.stat(d / '.env').st_mode) == 0o600
    assert h(str(d), DST, SRC) == ['.env', 'docker-compose.override.yml']
    assert {n: (d / n).read_text() for n in before} == before


def test_nothing_to_do_and_missing_dir(tmp_path):
    h = _helper()
    d = tmp_path / 'empty'
    d.mkdir()
    assert h(str(d), SRC, DST) == []
    assert h(str(tmp_path / 'gone'), SRC, DST) == []


# ── the re-home itself: order of steps ───────────────────────────────────────

def _rehome_src():
    return ast.get_source_segment(APP, _node(ast.FunctionDef, '_startup_rehome_module'))


def test_forward_path_rewrites_before_compose_up_and_skips_container_data():
    s = _rehome_src()
    chown = s.index("'--from=root:root', 'takwerx:takwerx', dst")
    rewrite = s.index('_rehome_rewrite_paths(dst, src, dst)')
    up = s.index("_compose(dst, 'up -d')")
    assert chown < rewrite < up
    assert "['chown', '-R', 'takwerx:takwerx', dst]" not in s       # the blanket chown is gone


def test_rollback_points_files_home_and_hands_ownership_back_to_root():
    s = _rehome_src()
    tail = s[s.index('ROLLING BACK'):]
    rewrite = tail.index('_rehome_rewrite_paths(dst, dst, src)')
    mv = tail.index("['mv', dst, src]")
    chown = tail.index("'--from=takwerx:takwerx', 'root:root', src")
    up = tail.index("_compose(src, 'up -d')")
    assert rewrite < mv < chown < up
