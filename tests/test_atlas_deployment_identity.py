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
"""What a deployment calls itself (W216 chunk 7).

⚠️ **The failure these pin.** After the compose fix, `deploy` built an agency in
the right directory under the right compose project — and then configured it as
if it were the plain deployment: the plain hostname in `.env`, the plain
loopback port in the compose override, the plain settings keys for the database
password, and the plain deployment's Authentik application. Every one of those
was a module constant, so every one had to be found separately.

Two properties carry the whole chunk:

1. **The plain deployment is byte-identical to what is deployed today.** A box
   that has not asked for anything must not move.
2. **No two deployments share a name, a port, a key or an application.**
"""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402


PLAIN_HOST = 'atlas.leckliter.net'


@pytest.fixture
def ctx(monkeypatch, tmp_path):
    """Enough console for identity; nothing that touches a box."""
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'store.img'))
    return {'_get_service_domain': lambda settings, key: PLAIN_HOST}


def identity(ctx, inst):
    return atlas.deployment_identity(ctx, inst, {})


# --------------------------------------------------------------------------- #
# Authentik names
# --------------------------------------------------------------------------- #


def test_the_plain_deployment_keeps_the_authentik_objects_it_has():
    """⚠️ **These three strings exist in Authentik on every deployed box.**
    Renaming one would orphan the live application: the deploy would create a
    second, the outpost would hold both, and the policy binding would follow the
    new one while Caddy's forward_auth still pointed at the old — an MDM console
    signed in to by nobody, or worse, restricted by nothing."""
    names = ai.authentik_names(None)

    assert names['provider'] == 'ATLAS MDM Proxy'
    assert names['app_slug'] == 'atlas'
    assert names['app_name'] == 'ATLAS MDM'


def test_an_agency_gets_its_own_authentik_objects():
    names = ai.authentik_names({'slug': 'corona'})

    assert names['provider'] == 'ATLAS MDM Proxy (corona)'
    assert names['app_slug'] == 'atlas-corona'
    assert names['app_name'] == 'ATLAS MDM (corona)'


def test_no_two_deployments_share_an_authentik_object():
    """⚠️ **The tenancy break.** Sharing the application slug meant an agency
    deploy repointed the *existing* deployment's application at the agency's
    hostname — signing every plain-deployment administrator into the agency
    console, and nobody into their own."""
    a = ai.authentik_names(None)
    b = ai.authentik_names({'slug': 'corona'})
    c = ai.authentik_names({'slug': 'redlands'})

    for field in ('provider', 'app_slug', 'app_name'):
        values = [a[field], b[field], c[field]]
        assert len(set(values)) == 3, f'{field} is shared: {values}'


def test_the_application_slug_is_the_name_derive_already_owns():
    """One name for the install directory, the Caddy CA directory and the
    Authentik application, so there is one place to be wrong."""
    inst = {'slug': 'corona'}

    assert ai.authentik_names(inst)['app_slug'] == ai.derive(inst)['name']


# --------------------------------------------------------------------------- #
# The hostname, and its agreement with Caddy
# --------------------------------------------------------------------------- #


def test_the_plain_deployment_writes_the_host_it_always_wrote(ctx):
    me = identity(ctx, None)

    assert me['host'] == PLAIN_HOST
    assert me['console_url'] == 'https://atlas.leckliter.net'
    assert me['device_url'] == 'https://atlas.leckliter.net:8449'
    assert me['apk_url'] == \
        'http://atlas.leckliter.net/api/v1/provisioning/agent.apk'


def test_an_agency_writes_its_own_host(ctx):
    me = identity(ctx, {'slug': 'corona'})

    assert me['host'] == 'atlas.corona.leckliter.net'
    assert me['console_url'] == 'https://atlas.corona.leckliter.net'
    assert me['device_url'] == 'https://atlas.corona.leckliter.net:8449'


@pytest.mark.parametrize('slug', [None, 'corona', 'redlands'])
def test_the_env_host_is_the_host_caddy_serves(monkeypatch, tmp_path, ctx, slug):
    """⚠️ **The invariant that makes enrolment work.** `.env` is what the
    provisioning QR is minted from, and Caddy is what answers the name in it. If
    these two disagreed, every tablet enrolled from that QR would point at a
    hostname with no site — and the failure would surface days later, on
    hardware, as "the tablet cannot check in"."""
    monkeypatch.setattr(atlas, 'sync_device_ca_for_caddy', lambda inst=None: None)
    inst = (ai.make(None, ai.MODE_FIXED, 100, 8760) if slug is None
            else ai.make(slug, ai.MODE_DYNAMIC, 50, 8761))
    # ⚠️ Recorded explicitly. This used to leave the list empty for the plain
    # case and lean on `load_instances` synthesising one — the migration path
    # for boxes that predate the list. An empty list now means *no* deployment,
    # which is what removing the last one leaves behind, so a test that relied
    # on the old conflation was describing a box that cannot exist.
    settings = {'atlas_enabled': True, ai.INSTANCES_KEY: [inst]}

    me = atlas.deployment_identity(ctx, inst, settings)
    sites = atlas.caddy_sites(settings, PLAIN_HOST)

    assert [s['host'] for s in sites] == [me['host']]


def test_no_domain_yields_no_urls_rather_than_half_formed_ones(tmp_path,
                                                               monkeypatch):
    """`https://:8449` in a provisioning QR fails on the tablet with nothing to
    point at; an empty string is a condition the deploy log already reports."""
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'store.img'))
    ctx = {'_get_service_domain': lambda settings, key: ''}

    me = atlas.deployment_identity(ctx, {'slug': 'corona'}, {})

    assert me['host'] == ''
    assert me['console_url'] == ''
    assert me['device_url'] == ''
    assert me['apk_url'] == ''


# --------------------------------------------------------------------------- #
# Port and settings keys
# --------------------------------------------------------------------------- #


def test_the_plain_deployment_binds_the_port_it_always_bound(ctx):
    assert identity(ctx, None)['app_port'] == atlas.APP_PORT == 8760


def test_an_agency_binds_its_allocated_port(ctx):
    """⚠️ Two deployments both binding 127.0.0.1:8760 leave the second failing
    to start, with a port conflict that says nothing about which deployment
    claimed it — and Caddy's upstream for the second pointing at the first."""
    me = identity(ctx, ai.make('corona', ai.MODE_DYNAMIC, 50, 8761))

    assert me['app_port'] == 8761


def test_the_plain_deployment_keeps_the_settings_keys_on_disk(ctx):
    assert identity(ctx, None)['settings_prefix'] == 'atlas_'


def test_an_agency_records_its_own_database_password(ctx):
    """⚠️ Under the shared `atlas_pg_password` an agency deploy overwrote the
    plain deployment's record. Postgres bakes the password in when it
    initialises the volume and ignores it ever after, so the database it
    belonged to becomes permanently unopenable — `FATAL: password
    authentication failed for user "takmdm"`, forever."""
    prefix = identity(ctx, {'slug': 'corona'})['settings_prefix']

    assert prefix == 'atlas_corona_'
    assert prefix + 'pg_password' != 'atlas_pg_password'


def test_no_two_deployments_share_any_identity_value(ctx):
    a = identity(ctx, None)
    b = identity(ctx, ai.make('corona', ai.MODE_DYNAMIC, 50, 8761))

    for field in ('dir', 'host', 'app_port', 'settings_prefix',
                  'console_url', 'device_url', 'apk_url'):
        assert a[field] != b[field], f'{field} is shared between deployments'


# --------------------------------------------------------------------------- #
# Where the access-control answer is recorded
# --------------------------------------------------------------------------- #


def test_the_plain_access_keys_are_the_ones_already_on_disk():
    """A rename here would report every existing box as never checked."""
    assert atlas.access_keys(None) == (atlas.ACCESS_KEY,
                                       atlas.ACCESS_CHECKED_KEY)
    assert atlas.ACCESS_KEY == 'atlas_access_restricted'


def test_an_agency_records_its_own_access_answer():
    restricted, checked = atlas.access_keys({'slug': 'corona'})

    assert restricted == 'atlas_corona_access_restricted'
    assert checked == 'atlas_corona_access_checked_at'


def _box(monkeypatch, tmp_path, instances, settings):
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'store.img'))
    settings = dict(settings)
    settings[ai.INSTANCES_KEY] = instances
    return {'load_settings': lambda: settings}, settings


def test_one_unrestricted_deployment_makes_the_box_unrestricted(monkeypatch,
                                                                tmp_path):
    """⚠️ **The safety direction.** The warning is about an MDM console —
    remote wipe, factory reset, policy push — reachable by every authenticated
    user. A second, correctly restricted deployment does not make the first one
    safe, so the answer cannot be an average or a majority."""
    ctx, s = _box(monkeypatch, tmp_path, [
        ai.make(None, ai.MODE_FIXED, 100, 8760),
        ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
    ], {'atlas_access_restricted': True,
        'atlas_corona_access_restricted': False})

    assert atlas.access_state(ctx, s) is False


def test_every_deployment_restricted_makes_the_box_restricted(monkeypatch,
                                                              tmp_path):
    ctx, s = _box(monkeypatch, tmp_path, [
        ai.make(None, ai.MODE_FIXED, 100, 8760),
        ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
    ], {'atlas_access_restricted': True,
        'atlas_corona_access_restricted': True})

    assert atlas.access_state(ctx, s) is True


def test_a_deployment_nobody_checked_is_not_restricted(monkeypatch, tmp_path):
    """⚠️ **Unknown must not average into True.** Reporting an access control
    that has never been verified as verified is the H-1 failure with extra
    steps — the tile goes green on the strength of a deployment that was
    checked, for one that was not."""
    ctx, s = _box(monkeypatch, tmp_path, [
        ai.make(None, ai.MODE_FIXED, 100, 8760),
        ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
    ], {'atlas_access_restricted': True})

    assert atlas.access_state(ctx, s) is None


def test_a_box_from_before_the_instance_list_reads_the_plain_key(monkeypatch,
                                                                 tmp_path):
    """Every existing installation predates the list and has only the plain
    keys; reading None there would blank a warning that had been shown."""
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'store.img'))
    s = {'atlas_access_restricted': False}
    ctx = {'load_settings': lambda: s}

    assert atlas.access_state(ctx, s) is False


def test_the_open_deployments_are_named(monkeypatch, tmp_path):
    """On a box with five agencies, "one of them is open" is not something an
    operator can act on."""
    ctx, s = _box(monkeypatch, tmp_path, [
        ai.make(None, ai.MODE_FIXED, 100, 8760),
        ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
        ai.make('redlands', ai.MODE_DYNAMIC, 50, 8762),
    ], {'atlas_access_restricted': True,
        'atlas_corona_access_restricted': False,
        'atlas_redlands_access_restricted': False})

    assert atlas.unrestricted_deployments(ctx, s) == ['atlas-corona',
                                                      'atlas-redlands']


def test_a_restricted_deployment_is_not_named(monkeypatch, tmp_path):
    ctx, s = _box(monkeypatch, tmp_path, [
        ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
    ], {'atlas_corona_access_restricted': True})

    assert atlas.unrestricted_deployments(ctx, s) == []


def test_recording_an_answer_writes_the_deployment_s_own_key(monkeypatch,
                                                             tmp_path):
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'store.img'))
    saved = {}
    ctx = {'load_settings': lambda: dict(saved),
           'save_settings': lambda s: saved.update(s)}

    atlas._record_access_state(ctx, False, inst={'slug': 'corona'})

    assert saved['atlas_corona_access_restricted'] is False
    assert 'atlas_access_restricted' not in saved


# --------------------------------------------------------------------------- #
# The Docker network the trusted-proxy range is read from
# --------------------------------------------------------------------------- #


def test_the_plain_deployment_reads_the_network_it_always_read(monkeypatch):
    """`takmdm_default` is the network on every deployed box; asking for another
    name would send every one of them to the RFC1918 fallback."""
    asked = {}

    class R:
        returncode = 0
        stdout = '172.24.0.0/16'

    def fake_run(argv, **k):
        asked['argv'] = argv
        return R

    monkeypatch.setattr(atlas.subprocess, 'run', fake_run)

    assert atlas._bridge_gateway() == '172.24.0.0/16'
    assert 'takmdm_default' in asked['argv']


def test_an_agency_reads_its_own_network(monkeypatch):
    """⚠️ Hardcoding `takmdm_default` meant an agency always took the fallback
    and never narrowed — the S-1 mitigation quietly not applying to exactly the
    deployments a box gains from here on. Not a lockout, which is why nothing
    would have reported it."""
    asked = {}

    class R:
        returncode = 0
        stdout = '172.31.0.0/16'

    def fake_run(argv, **k):
        asked['argv'] = argv
        return R

    monkeypatch.setattr(atlas.subprocess, 'run', fake_run)

    assert atlas._bridge_gateway('takmdm-corona') == '172.31.0.0/16'
    assert 'takmdm-corona_default' in asked['argv']


def test_an_unreadable_network_still_refuses_public_addresses(monkeypatch):
    """A wrong guess locks an operator out of their own console; the broad value
    still refuses a request arriving from a public address, which is the case
    worth closing."""
    monkeypatch.setattr(atlas.subprocess, 'run',
                        lambda argv, **k: (_ for _ in ()).throw(OSError('no docker')))

    assert atlas._bridge_gateway('takmdm-corona') == atlas._TRUSTED_FALLBACK


def test_the_identity_carries_the_compose_project(ctx):
    """So the network name comes from the same place every other name does."""
    assert identity(ctx, None)['compose_project'] == 'takmdm'
    assert identity(ctx, {'slug': 'corona'})['compose_project'] == 'takmdm-corona'
