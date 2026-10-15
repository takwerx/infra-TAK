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
"""An uninstall always answers JSON (GH #137 follow-up).

Field report on v10.2.14: removing ATLAS showed
`Uninstall failed: SyntaxError: JSON.parse: unexpected character at line 1 column 1`.
The registry's uninstall view let any exception escape to Flask's HTML 500 page,
and the page does `JSON.parse` on whatever comes back, so the operator saw a parse
error instead of the reason. ATLAS's teardown had two steps that could raise: a
`docker compose down` that outlives its timeout, and the final Caddy regen.
"""

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

import modules as mod_registry  # noqa: E402
import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402
from atlas_layout import deployment_dir  # noqa: E402
from test_atlas_instance_removal import _make_box, box, actions  # noqa: E402,F401


# --------------------------------------------------------------------------- #
# The registry route
# --------------------------------------------------------------------------- #


@pytest.fixture
def client():
    flask = pytest.importorskip('flask')
    from werkzeug.security import generate_password_hash

    calls = {'n': 0}

    def exploding_uninstall(ctx, job, params):
        calls['n'] += 1
        raise subprocess.TimeoutExpired(['docker', 'compose', 'down'], 300)

    desc = {'key': 'gh137probe', 'uninstall': exploding_uninstall}
    ctx = {'load_auth': lambda: {'password_hash': generate_password_hash('pw')}}
    views = mod_registry._make_views(desc, ctx)
    app = flask.Flask('gh137')
    app.add_url_rule('/api/gh137probe/uninstall', view_func=views['uninstall'],
                     methods=['POST'])
    yield app.test_client(), calls
    mod_registry._JOBS.pop('gh137probe', None)
    mod_registry._LOCKS.pop('gh137probe', None)


def test_a_crashing_uninstall_still_answers_json(client):
    c, calls = client
    r = c.post('/api/gh137probe/uninstall', json={'password': 'pw'})

    assert calls['n'] == 1
    assert r.is_json, 'an exception reached the page as HTML: %r' % r.data[:80]
    d = r.get_json()
    assert d['success'] is False
    assert 'TimeoutExpired' in d['error']
    assert 'journalctl -u takwerx-console' in d['error']


def test_a_crashing_uninstall_leaves_the_job_slot_usable(client):
    c, _ = client
    c.post('/api/gh137probe/uninstall', json={'password': 'pw'})

    assert mod_registry._job('gh137probe')['running'] is False


def test_the_password_gate_is_unchanged(client):
    c, calls = client
    r = c.post('/api/gh137probe/uninstall', json={'password': 'wrong'})

    assert r.status_code == 403
    assert calls['n'] == 0


# --------------------------------------------------------------------------- #
# ATLAS teardown
# --------------------------------------------------------------------------- #


def test_a_hung_compose_down_is_a_failure_not_a_crash(box, actions, monkeypatch):
    """⚠️ It must stop *before* the store and directory go: the containers may
    still be running on them."""
    def hung(ctx, action, timeout=180, inst=None):
        raise subprocess.TimeoutExpired(['docker', 'compose', 'down'], timeout)

    monkeypatch.setattr(atlas, '_compose', hung)
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    result = atlas.uninstall(ctx, None, {})

    assert result['success'] is False
    assert 'docker compose down did not finish' in result['error']
    assert actions['store'] == [], 'store removed under running containers'
    assert deployment_dir('atlas-corona').exists()
    assert [i.get('slug') for i in atlas.load_instances(ctx)] == ['corona']
    assert ctx.settings['atlas_corona_pg_password'] == 'secret'


def test_a_caddy_error_after_everything_is_removed_is_reported(box, actions):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])
    seen = {'n': 0}

    def caddy(_s):
        # The first regen is the per-deployment one inside remove_instance; the
        # second is the box-wide one at the end, which used to be unguarded.
        seen['n'] += 1
        if seen['n'] == 2:
            raise OSError('Caddyfile write refused')

    ctx['generate_caddyfile'] = caddy

    result = atlas.uninstall(ctx, None, {})

    assert result['success'] is True
    assert ctx.settings['atlas_enabled'] is False
    assert any('Caddy could not be regenerated' in s for s in result['steps'])


# --------------------------------------------------------------------------- #
# The page
# --------------------------------------------------------------------------- #


def test_the_page_does_not_parse_the_uninstall_response_blind():
    html = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')
    start = html.index('async function doUninstall')
    body = html[start:html.index('\n}\n', start)]

    assert 'await r.json()' not in body
    assert 'await r.text()' in body
    assert 'r.status' in body
