# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""An ATLAS deployment that still reads the plain identity headers says so on its row.

ops #1151, the Security lead's note: the switch to Authentik's signed token keeps a
deployment on `headers` whenever a check is not met (an older ATLAS, no key published,
a Caddyfile that does not pass the token). That was one `⚠` line in the update log.
ATLAS cannot check those headers, so an operator has to be able to see which
deployments are still on them.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402
from modules import atlas_signed_identity as asi  # noqa: E402

PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)

NEW_COMPOSE = ('services:\n  api:\n    environment:\n'
               '      TAKMDM_ADMIN_IDENTITY_SOURCE: ${TAKMDM_ADMIN_IDENTITY_SOURCE:-headers}\n'
               '      TAKMDM_PROXY_AUTH_SECRET: ${TAKMDM_PROXY_AUTH_SECRET:-}\n')
OLD_COMPOSE = ('services:\n  api:\n    environment:\n'
               '      TAKMDM_PROXY_AUTH_SECRET: ${TAKMDM_PROXY_AUTH_SECRET:-}\n')


def deployment(tmp_path, env, compose=NEW_COMPOSE):
    if env is not None:
        (tmp_path / '.env').write_text(env, encoding='utf-8')
    if compose is not None:
        (tmp_path / 'docker-compose.yml').write_text(compose, encoding='utf-8')
    return str(tmp_path)


def note(dirpath):
    return asi.card_note(dirpath, atlas.env_keys_compose_passes)


def test_a_deployment_on_the_signed_token_has_no_note(tmp_path):
    d = deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=s3\nTAKMDM_ADMIN_IDENTITY_SOURCE=jwt\n')

    assert note(d) is None


def test_a_new_atlas_still_on_headers_says_press_update(tmp_path):
    d = deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=s3\nTAKMDM_ADMIN_IDENTITY_SOURCE=headers\n')

    said = note(d)

    assert 'plain identity headers' in said
    assert 'Press Update' in said
    assert 'update log' in said


def test_a_new_atlas_never_checked_says_press_update(tmp_path):
    """Right after the console update, before Update is pressed on the ATLAS card:
    `.env` has no line yet. Not reading the signed token is the fact, line or no line."""
    d = deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=s3\n')

    assert 'Press Update' in note(d)


def test_an_older_atlas_names_the_release_that_can(tmp_path):
    d = deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=s3\nTAKMDM_ADMIN_IDENTITY_SOURCE=headers\n',
                   compose=OLD_COMPOSE)

    said = note(d)

    assert '2.10.0' in said
    assert 'plain identity headers' in said
    # ⚠️ Not "the update log says what is missing": nothing is missing, the release is older.
    assert 'update log' not in said


def test_no_authentik_in_front_is_not_a_warning(tmp_path):
    """No proxy-auth secret in `.env` means Caddy does not sign the request in through
    Authentik for this deployment. The signed token is not on offer there."""
    d = deployment(tmp_path, 'TAKMDM_ADMIN_IDENTITY_SOURCE=headers\n')

    assert note(d) is None


def test_an_empty_secret_counts_as_none(tmp_path):
    d = deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=\nTAKMDM_ADMIN_IDENTITY_SOURCE=headers\n')

    assert note(d) is None


def test_files_that_cannot_be_read_are_not_a_warning(tmp_path):
    """"Could not look" is not "still on headers"."""
    (tmp_path / 'a').mkdir()
    assert note(deployment(tmp_path / 'a', None, None)) is None
    (tmp_path / 'b').mkdir()
    no_compose = deployment(tmp_path / 'b', 'TAKMDM_PROXY_AUTH_SECRET=s3\n', compose=None)
    assert note(no_compose) is None


def test_a_commented_line_is_not_the_setting(tmp_path):
    d = deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=s3\n# TAKMDM_ADMIN_IDENTITY_SOURCE=jwt\n')

    assert 'Press Update' in note(d)


def test_the_note_never_raises():
    def broken(_dirpath):
        raise RuntimeError('boom')

    assert asi.card_note('/nonexistent/ops1151', broken) is None


def test_the_row_declares_the_field():
    assert 'admin_signin_problem' in atlas.INSTANCE_FIELDS


def test_the_page_shows_it_on_the_row():
    page = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')
    row = page[page.index('function instanceRow('):page.index('function controlInstance(')]

    assert 'i.admin_signin_problem' in row
    # `textContent`, like every other text on this row.
    assert "warn.textContent = '⚠ ' + i.admin_signin_problem" in row
    assert 'innerHTML' not in row


def payload_row(monkeypatch, tmp_path, built):
    monkeypatch.setattr(atlas, 'compose_projects_present', lambda _ctx: set())
    monkeypatch.setattr(atlas, '_latest_version', lambda **_k: '2.10.0')
    monkeypatch.setattr(atlas, '_channel_of', lambda _ctx: 'main')
    monkeypatch.setattr(atlas, 'load_instances', lambda _ctx: [PLAIN])
    monkeypatch.setattr(atlas, 'instance_is_built', lambda *_a: built)
    monkeypatch.setattr(atlas, 'instance_is_stranded', lambda *_a: False)
    monkeypatch.setattr(atlas, '_installed_version', lambda *_a: '2.10.0')
    monkeypatch.setattr(atlas, 'api_container', lambda *_a: 'takmdm-api-1')
    monkeypatch.setattr(atlas, 'instance_paths', lambda *_a: {
        'dir': str(tmp_path), 'vhost': '/y', 'compose_project': 'p'})
    monkeypatch.setattr(atlas, 'capacity_facts', lambda *_a, **_k: {})
    monkeypatch.setattr(atlas, 'root_key_holders', lambda *_a: [])

    class Ran:
        stdout = 'true\n'

    ctx = {'load_settings': lambda: {}, 'probe_run': lambda *_a, **_k: Ran()}
    return atlas.instances_payload(ctx)['instances'][0]


def test_the_page_route_carries_the_note(monkeypatch, tmp_path):
    deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=s3\nTAKMDM_ADMIN_IDENTITY_SOURCE=headers\n')

    row = payload_row(monkeypatch, tmp_path, built=True)

    assert 'plain identity headers' in row['admin_signin_problem']


def test_the_page_route_says_nothing_once_on_the_signed_token(monkeypatch, tmp_path):
    deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=s3\nTAKMDM_ADMIN_IDENTITY_SOURCE=jwt\n')

    row = payload_row(monkeypatch, tmp_path, built=True)

    assert row['admin_signin_problem'] is None


def test_an_unfinished_deployment_has_no_note(monkeypatch, tmp_path):
    deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=s3\nTAKMDM_ADMIN_IDENTITY_SOURCE=headers\n')

    row = payload_row(monkeypatch, tmp_path, built=False)

    assert row['admin_signin_problem'] is None


def test_the_dashboard_poll_does_not_read_the_files(monkeypatch, tmp_path):
    """`instance_status` without `settings` is the dashboard's poll (`detect`); only the
    page's own route asks about sign-in."""
    deployment(tmp_path, 'TAKMDM_PROXY_AUTH_SECRET=s3\nTAKMDM_ADMIN_IDENTITY_SOURCE=headers\n')
    monkeypatch.setattr(atlas, 'instance_is_built', lambda *_a: True)
    monkeypatch.setattr(atlas, 'instance_is_stranded', lambda *_a: False)
    monkeypatch.setattr(atlas, '_installed_version', lambda *_a: '2.10.0')
    monkeypatch.setattr(atlas, 'api_container', lambda *_a: 'takmdm-api-1')
    monkeypatch.setattr(atlas, 'instance_paths', lambda *_a: {'dir': str(tmp_path)})

    def refuse(*_a, **_k):
        raise AssertionError('the dashboard poll must not read the deployment files')

    monkeypatch.setattr(asi, 'card_note', refuse)

    class Ran:
        stdout = 'true\n'

    status = atlas.instance_status({'probe_run': lambda *_a, **_k: Ran()}, PLAIN, set())

    assert status['admin_signin_problem'] is None
