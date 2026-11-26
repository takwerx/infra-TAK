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
"""The "not enough free disk" message gives prune commands that free what `docker system df` shows
(ops #1146, infra-TAK #670).

Field: a user was refused for 2 GB with 13 GB "reclaimable" (8.9 GB build cache, 4.5 GB images). The
message told him `docker builder prune -f` and `docker image prune -f`. Without `-a` Docker removes
only dangling cache and untagged images, and `docker system df` counts every unused one. Checked on
a Rocky 9.8 box: `docker image prune -f` freed 0 B on an unused tagged image, `-af` freed it.

app.py cannot be imported in a test, so the pieces are cut out of it.
"""

import ast
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
GB = 1024 ** 3


def _lines():
    fn = next(n for n in ast.parse(APP).body
              if isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_update_space_lines')
    ns = {'_FREE_SPACE_BACKUPS_HINT': 'HINT'}
    exec(compile(ast.get_source_segment(APP, fn), 'app.py', 'exec'), ns)
    return ns['_cloudtak_update_space_lines'](
        {'what': 'the CloudTAK images and build cache', 'where': '/var/lib/docker',
         'free': 15 * GB, 'need': 17 * GB})


def test_refusal_message_uses_the_all_unused_prune_forms():
    text = '\n'.join(_lines())
    assert '`docker builder prune -af`' in text
    assert '`docker image prune -af`' in text


def test_refusal_message_does_not_offer_the_weak_plain_forms():
    text = '\n'.join(_lines())
    assert not re.search(r'docker (builder|image) prune -f\b', text)
    # never volumes: they hold the user's data
    assert 'prune --volumes' not in text and 'system prune' not in text
    assert 'Do not delete Docker volumes' in text
