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
"""ATLAS comes back by itself when Docker restarts (ops #1221).

⚠️ **The bug.** An OS update that included docker-ce restarted Docker on nuc. Every container came
back except the two ATLAS ones (`takmdm-api-1`, `takmdm-db-1`), which stayed `Exited (0)` until
someone pressed Start, and no device could check in. `docker inspect` showed restart policy `no`.
nuc runs ATLAS 1.51.0, whose own compose file names no policy on `api` or `db`; newer releases set
`unless-stopped` themselves, so the gap is every deployment that has not updated yet.

⚠️ **The fix is in the file this module owns.** `docker-compose.override.yml` now carries
`restart: unless-stopped` for `api` and `db` (never `init`, which is one-shot), and an update
rewrites an existing deployment's override that lacks it, then recreates the containers.

⚠️ **Driven, not grepped.** The override is parsed as YAML, the real override from nuc is fed to
`ensure_restart_policy`, and `_run_update` is run for both of its paths.
"""

import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402

#: The override exactly as a deployment written before this fix has it (nuc, written Sep 19).
OLD_OVERRIDE = '''# Written by the infra-TAK ATLAS module.
#
# Caddy is the only thing that talks to this application, so it binds loopback
# and publishes nothing else. ATLAS's own nginx is simply not started — `up -d
# api` brings the database and the migration step with it and stops there.
services:
  api:
    ports:
      - "127.0.0.1:8760:8000"

  # ⚠️ **No `user:` here, and that was tried.** Running the containers as
  # the console's own uid would have removed the host-side chown entirely.

  # No self-signed server certificate. Caddy holds a publicly-issued one, and a
  # local CA here would end up pinned in provisioning QRs that then fail.
  init:
    command: ["python", "-m", "app.cli", "init-pki"]
'''


def services_of(body):
    return yaml.safe_load(body)['services']


def policies(body):
    """The restart policy compose would see for each of api and db (None when unset)."""
    services = services_of(body)
    return {name: services.get(name, {}).get('restart') for name in ('api', 'db')}


SET = {'api': 'unless-stopped', 'db': 'unless-stopped'}


# --------------------------------------------------------------------------- #
# The proof tests: red on the base branch, green with the fix
# --------------------------------------------------------------------------- #


def test_a_new_deployments_override_restarts_api_and_db_with_docker():
    """⚠️ **The reported case, at the source.** What a fresh deploy writes names the policy."""
    services = services_of(atlas._COMPOSE_OVERRIDE.format(app_port=8760))

    assert services['api']['restart'] == 'unless-stopped', services
    assert services['db']['restart'] == 'unless-stopped', services


def test_the_one_shot_init_step_is_never_set_to_restart():
    """Restarting `init` would loop it: it exits 0 on purpose after making the CA."""
    services = services_of(atlas._COMPOSE_OVERRIDE.format(app_port=8760))

    assert 'restart' not in services['init'], services['init']


def test_the_override_still_binds_the_allocated_port_on_loopback_only():
    services = services_of(atlas._COMPOSE_OVERRIDE.format(app_port=8761))

    assert services['api']['ports'] == ['127.0.0.1:8761:8000']


def test_an_existing_deployment_override_is_brought_up_to_date(tmp_path):
    """⚠️ **nuc's own file.** Without a rewrite the containers keep policy `no` for ever, since
    only a deploy wrote this file."""
    path = tmp_path / 'docker-compose.override.yml'
    path.write_text(OLD_OVERRIDE, encoding='utf-8')
    log = []

    changed = atlas.ensure_restart_policy(str(tmp_path), log.append)

    assert changed is True
    services = services_of(path.read_text(encoding='utf-8'))
    assert services['api']['restart'] == 'unless-stopped'
    assert services['db']['restart'] == 'unless-stopped'
    # The port was allocated at deploy time and lives nowhere else: it must survive.
    assert services['api']['ports'] == ['127.0.0.1:8760:8000']
    assert services['init']['command'] == ['python', '-m', 'app.cli', 'init-pki']
    assert any('restart by themselves' in line for line in log), log


def test_rewriting_twice_changes_nothing_the_second_time(tmp_path):
    path = tmp_path / 'docker-compose.override.yml'
    path.write_text(OLD_OVERRIDE, encoding='utf-8')
    atlas.ensure_restart_policy(str(tmp_path), lambda _m: None)
    first = path.read_text(encoding='utf-8')

    assert atlas.ensure_restart_policy(str(tmp_path), lambda _m: None) is False
    assert path.read_text(encoding='utf-8') == first


def test_an_agency_deployments_port_is_kept(tmp_path):
    path = tmp_path / 'docker-compose.override.yml'
    path.write_text(OLD_OVERRIDE.replace('8760', '8763'), encoding='utf-8')

    atlas.ensure_restart_policy(str(tmp_path), lambda _m: None)

    assert services_of(path.read_text(encoding='utf-8'))['api']['ports'] == ['127.0.0.1:8763:8000']


def test_a_file_whose_port_cannot_be_read_is_left_alone_and_says_so(tmp_path):
    """Guessing a port would point Caddy's upstream at nothing."""
    odd = 'services:\n  api:\n    ports:\n      - "8760:8000"\n'
    path = tmp_path / 'docker-compose.override.yml'
    path.write_text(odd, encoding='utf-8')
    log = []

    assert atlas.ensure_restart_policy(str(tmp_path), log.append) is False
    assert path.read_text(encoding='utf-8') == odd
    assert any('left alone' in line for line in log), log


def test_no_override_file_means_nothing_is_created(tmp_path):
    assert atlas.ensure_restart_policy(str(tmp_path), lambda _m: None) is False
    assert not (tmp_path / 'docker-compose.override.yml').exists()


def test_a_policy_in_a_comment_does_not_count(tmp_path):
    body = OLD_OVERRIDE.replace('services:', '# restart: unless-stopped\nservices:')

    assert atlas.override_restart_policy_missing(body) == ['api', 'db']


def test_a_policy_on_init_alone_does_not_count_for_api_and_db():
    body = OLD_OVERRIDE.replace('    command:', '    restart: unless-stopped\n    command:')

    assert atlas.override_restart_policy_missing(body) == ['api', 'db']


# --------------------------------------------------------------------------- #
# The update button, both paths
# --------------------------------------------------------------------------- #


class Stop(Exception):
    pass


@pytest.fixture
def box(monkeypatch, tmp_path):
    """A built deployment with the old override, and every collaborator of `_run_update` stubbed."""
    dep = tmp_path / 'atlas' / 'default'
    (dep / '.git').mkdir(parents=True)
    (dep / 'docker-compose.override.yml').write_text(OLD_OVERRIDE, encoding='utf-8')
    events = []
    dirpath = str(dep).replace(chr(92), '/')

    monkeypatch.setattr(atlas, 'install_base', lambda c=None: str(tmp_path))
    monkeypatch.setattr(atlas, '_channel_of', lambda _c: 'main')
    monkeypatch.setattr(atlas, 'deployment_identity', lambda c, i, s: {
        'name': 'atlas', 'dir': dirpath, 'settings_prefix': 'atlas_', 'compose_project': 'takmdm'})
    monkeypatch.setattr(atlas, '_installed_version', lambda _c, _i=None: '2.1.2')
    monkeypatch.setattr(atlas, '_module_head', lambda c, d: None)
    monkeypatch.setattr(atlas, '_unfinished_update', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_reconcile_access', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_repair_env_ownership', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_arm_admin_gates', lambda *a, **k: False)
    monkeypatch.setattr(atlas, '_push_email_relay', lambda *a, **k: False)
    monkeypatch.setattr(atlas, '_global_admin_group', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_reconcile_signed_identity', lambda *a, **k: False)
    monkeypatch.setattr(atlas, '_seed_relay_choice', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_set_trusted_proxies', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_write_build_file', lambda *a, **k: None)
    monkeypatch.setattr(atlas, 'refresh_database', lambda *a, **k: None)
    monkeypatch.setattr(atlas, 'backup_database', lambda *a, **k: None)
    monkeypatch.setattr(atlas.atlas_renewal, 'ensure',
                        lambda *a, **k: {'env_changed': False, 'ready': False})
    monkeypatch.setattr(atlas.atlas_renewal, 'start', lambda *a, **k: None)
    monkeypatch.setattr(atlas.atlas_tak_cas, 'refresh', lambda *a, **k: {'recreated': False})

    def compose(ctx, action, timeout=180, inst=None):
        # What the override said at the moment compose ran: that is what the containers get.
        body = (dep / 'docker-compose.override.yml').read_text(encoding='utf-8')
        events.append((action, policies(body)))
        return type('R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})()

    monkeypatch.setattr(atlas, '_compose', compose)
    store = {'s': {}}
    ctx = {'load_settings': lambda: dict(store['s']),
           'save_settings': lambda s: store.__setitem__('s', dict(s)),
           'generate_caddyfile': lambda s: None,
           '_caddy_reload': lambda plog: None,
           '_module_git': lambda *a, **k: None}
    return {'ctx': ctx, 'events': events, 'dep': dep}


def run_update(box):
    slot = atlas._update_slot(None)
    slot.clear()
    atlas._run_update(box['ctx'], None)
    return slot


def test_updating_a_deployment_already_on_the_newest_release_recreates_it_with_the_policy(
        box, monkeypatch):
    """⚠️ **The nuc case after the fleet update.** Nothing to install, but the containers still
    have policy `no`: the update rewrites the override and recreates `api` (and `db` with it)
    from the new file."""
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=False, channel=None: '2.1.2')

    slot = run_update(box)

    assert slot['complete'] and not slot['error'], slot['log']
    assert ('up -d api', SET) in box['events'], box['events']
    assert policies((box['dep'] / 'docker-compose.override.yml').read_text(encoding='utf-8')) == SET


def test_updating_a_deployment_with_nothing_to_change_does_not_recreate_it(box, monkeypatch):
    """A deployment that already has the policy is not bounced for no reason."""
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=False, channel=None: '2.1.2')
    (box['dep'] / 'docker-compose.override.yml').write_text(
        atlas._COMPOSE_OVERRIDE.format(app_port=8760), encoding='utf-8')

    run_update(box)

    assert box['events'] == [], box['events']


def test_a_real_update_rewrites_the_override_before_the_rebuild(box, monkeypatch):
    """⚠️ The rebuild is what recreates the containers, so the file has to be right before it."""
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=False, channel=None: '2.2.0')
    monkeypatch.setattr(atlas, '_channel_commit', lambda *a, **k: 'abc')
    monkeypatch.setattr(atlas, '_ls_remote', lambda *a, **k: '')
    monkeypatch.setattr(atlas, '_verify_release', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_verify_checkout', lambda *a, **k: None)
    monkeypatch.setattr(atlas.subprocess, 'run',
                        lambda *a, **k: type('R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})())

    slot = run_update(box)

    assert slot['complete'] and not slot['error'], slot['log']
    rebuild = [e for e in box['events'] if e[0] == 'up -d --build api']
    assert rebuild == [('up -d --build api', SET)], box['events']
