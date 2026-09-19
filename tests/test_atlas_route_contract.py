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
"""What the page reads and what the route sends (2026-09-18).

⚠️ **The bug this file exists for.** The deployments card rendered
*"stopped  version unknown"* over a deployment that was up, healthy and
reachable. Measured on the box: `takmdm-corona-api-1` up 8 minutes,
`docker inspect` answering `true`, `VERSION` reading 1.47.3.

`instance_status` — which answers exactly those two questions — had been wired
into `detect` and `version_drift` and **not** into the route the page reads.
The route still returned the bare record plus `built`, so `i.running` and
`i.version` were `undefined` in the browser: falsy, and rendered as stopped and
unknown.

⚠️ **The node harness could not catch it, and that is the point.** It feeds
`renderInstances` a hand-written object carrying `running` and `version` — a
contract the server did not keep. A harness that invents its own input tests the
page against a server that does not exist. So the guard here reads the page's
*actual* property accesses out of the template and checks them against the
route's *actual* payload; neither half can move without the other noticing.
"""

import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402


PAGE = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')


def _page_section(start, end):
    i = PAGE.index(start)
    return PAGE[i:PAGE.index(end, i)]


class Probe:
    def __init__(self, stdout=''):
        self.stdout = stdout
        self.stderr = ''
        self.returncode = 0


@pytest.fixture
def ctx(monkeypatch, tmp_path):
    """A box with corona built, running and on 1.47.3 — the state on the dev
    box at the moment the page said it was stopped."""
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, 'compose_projects_present',
                        lambda c=None: {'takmdm-corona'})
    monkeypatch.setattr(atlas, 'capacity_facts',
                        lambda c, size_gb=None: {'budget_gb': 353.2})
    d = tmp_path / 'atlas' / 'corona'
    d.mkdir(parents=True, exist_ok=True)
    (d / 'VERSION').write_text('1.47.3', encoding='utf-8')
    settings = {'atlas_enabled': True,
                ai.INSTANCES_KEY: [ai.make('corona', ai.MODE_DYNAMIC, 354.6, 8760)]}
    return {'load_settings': lambda: dict(settings),
            'probe_run': lambda argv, **k: Probe('true')}


# --------------------------------------------------------------------------- #
# The contract itself
# --------------------------------------------------------------------------- #


def test_the_route_sends_every_field_the_rows_read():
    """⚠️ **The guard.** Every `i.<field>` the deployments card reads must be a
    key the route actually sends. Two undefined ones — `running` and `version` —
    are what made a serving deployment read as stopped."""
    source = _page_section('function stateLabel', 'function controlInstance')
    read = set(re.findall(r'\bi\.([a-z_]+)', source))

    assert read, 'the rows no longer read anything off a deployment'
    assert read <= set(atlas.INSTANCE_FIELDS), \
        'the page reads %s, which the route does not send' % sorted(
            read - set(atlas.INSTANCE_FIELDS))


def test_renderinstances_reads_nothing_the_route_withholds():
    source = _page_section('function renderInstances', 'function stateLabel')
    read = set(re.findall(r'\bi\.([a-z_]+)', source))

    assert read <= set(atlas.INSTANCE_FIELDS), sorted(
        read - set(atlas.INSTANCE_FIELDS))


def test_the_payload_really_carries_those_fields(ctx):
    """The list above is only worth having if the route honours it."""
    row = atlas.instances_payload(ctx)['instances'][0]

    for field in atlas.INSTANCE_FIELDS:
        assert field in row, field


# --------------------------------------------------------------------------- #
# And the values are the true ones
# --------------------------------------------------------------------------- #


def test_a_running_deployment_is_sent_as_running(ctx):
    row = atlas.instances_payload(ctx)['instances'][0]

    assert row['running'] is True
    assert row['built'] is True


def test_its_version_is_sent(ctx):
    assert atlas.instances_payload(ctx)['instances'][0]['version'] == '1.47.3'


def test_the_record_s_own_fields_survive(ctx):
    """`slug`, `mode` and `size_gb` are what the summary line is built from."""
    row = atlas.instances_payload(ctx)['instances'][0]

    assert row['slug'] == 'corona'
    assert row['mode'] == ai.MODE_DYNAMIC
    assert row['size_gb'] == 354.6


def test_the_route_does_not_probe_containers_for_their_version(ctx, monkeypatch):
    """⚠️ This route is polled while the page is open. An HTTP round-trip per
    deployment, with a five-second timeout, would make the card slower the more
    agencies a box has — exactly backwards."""
    asked = []
    monkeypatch.setattr(atlas, '_running_version',
                        lambda c=None, i=None: asked.append(1) or '1.47.3')

    atlas.instances_payload(ctx)

    assert asked == []


def test_the_capacity_travels_with_it(ctx):
    assert 'capacity' in atlas.instances_payload(ctx)


def test_a_size_asked_about_reaches_the_capacity_calculation(ctx, monkeypatch):
    """The form asks "does 50 GB fit" while the operator types it."""
    seen = {}
    monkeypatch.setattr(atlas, 'capacity_facts',
                        lambda c, size_gb=None: seen.setdefault('size', size_gb) or {})

    atlas.instances_payload(ctx, size_gb=50.0)

    assert seen['size'] == 50.0


# --------------------------------------------------------------------------- #
# Which deployments are behind (W222)
# --------------------------------------------------------------------------- #


def test_a_deployment_on_an_older_release_is_behind():
    assert atlas.update_available_for('1.48.1', '1.49.0') is True


def test_a_deployment_on_the_newest_is_not():
    assert atlas.update_available_for('1.49.0', '1.49.0') is False


def test_a_deployment_ahead_of_the_newest_is_not():
    """A checkout on an unreleased build is not "behind"; offering to move it
    backwards would be worse than saying nothing."""
    assert atlas.update_available_for('1.50.0', '1.49.0') is False


def test_the_comparison_is_on_numbers_not_text():
    """⚠️ **The one that would fail silently.** `0.10.0` sorts *before* `0.9.0`
    as a string, so a text comparison stops offering updates at the tenth
    release of any series — and says nothing about it."""
    assert atlas.update_available_for('0.9.0', '0.10.0') is True
    assert atlas.update_available_for('1.9.0', '1.10.0') is True


def test_an_unreachable_github_claims_nothing():
    """⚠️ A missing badge means "no newer release established", which covers
    both "you are current" and "the check could not run". Rendering the second
    as the first would be a reassurance nothing earned."""
    assert atlas.update_available_for('1.48.1', None) is False
    assert atlas.update_available_for('1.48.1', '') is False


def test_a_deployment_with_no_version_claims_nothing():
    """An unfinished deployment has no version to be behind."""
    assert atlas.update_available_for(None, '1.49.0') is False


def test_a_version_that_is_not_three_numbers_claims_nothing():
    assert atlas.update_available_for('nightly', '1.49.0') is False


def test_the_row_carries_the_badge_and_what_it_points_at(ctx, monkeypatch):
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.49.0')

    row = atlas.instances_payload(ctx)['instances'][0]

    assert row['version'] == '1.47.3'
    assert row['latest'] == '1.49.0'
    assert row['update_available'] is True


def test_a_current_deployment_carries_no_badge(ctx, monkeypatch):
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.47.3')

    assert atlas.instances_payload(ctx)['instances'][0]['update_available'] is False


def test_the_newest_release_is_asked_for_once_not_once_per_row(ctx, monkeypatch):
    """⚠️ A GitHub call behind a 15-minute cache, and the allowance is 60 an
    hour per IP. A box with five agencies polling this route would spend it on
    one page."""
    calls = []
    monkeypatch.setattr(atlas, '_latest_version',
                        lambda use_cache=True, channel=None: calls.append(1) or '1.49.0')

    atlas.instances_payload(ctx)

    assert len(calls) == 1
