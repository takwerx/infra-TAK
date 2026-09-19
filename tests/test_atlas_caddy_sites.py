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
"""Caddy sites, one per ATLAS deployment (W216 chunk 6).

⚠️ **The safety property.** `generate_caddyfile` writes the Caddyfile for the
*whole box* — Authentik, TAK server, CloudTAK, NetBird, the console itself. A
file that differs by one character takes all of them down, not just ATLAS's
vhost. So the requirement is not "agencies work", it is:

**on a box with one deployment, the emitted configuration is unchanged.**

That reduces to `caddy_sites` returning exactly one entry carrying the host,
upstream and CA path the generator used before this existed — the values are
pinned below against what was read off the live box.
"""

import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402


# --------------------------------------------------------------------------- #
# The hostname an agency gets
# --------------------------------------------------------------------------- #


def test_the_plain_deployment_keeps_the_host_it_has():
    assert ai.agency_host('atlas.leckliter.net', None) == 'atlas.leckliter.net'


def test_an_agency_qualifies_the_first_label():
    """⚠️ Inserted after the service label, not prepended to the whole name —
    `atlas.agencya.<fqdn>`, not `agencya.atlas.<fqdn>`. The first label says
    what the service is; the agency qualifies it."""
    assert ai.agency_host('atlas.leckliter.net', 'agencya') == \
        'atlas.agencya.leckliter.net'


def test_a_custom_console_domain_is_qualified_the_same_way():
    """A box whose operator renamed the console still gets a sensible agency
    name rather than one built from a constant."""
    assert ai.agency_host('mdm.example.com', 'pd') == 'mdm.pd.example.com'


def test_a_single_label_host_still_works():
    assert ai.agency_host('atlas', 'pd') == 'atlas.pd'


def test_no_host_yields_no_host():
    """Before an FQDN is set there is nothing to qualify, and inventing one
    would put a certificate request in for a name nobody owns."""
    assert ai.agency_host('', 'pd') == ''
    assert ai.agency_host(None, 'pd') is None


# --------------------------------------------------------------------------- #
# The sites themselves
# --------------------------------------------------------------------------- #


def posix(p):
    return str(p).replace(chr(92), '/')


def _stage(monkeypatch, tmp_path, *slugs):
    """Put a device CA where Caddy would read it, under tmp_path."""
    base = tmp_path / 'caddy'
    monkeypatch.setattr(atlas, 'caddy_base', lambda: posix(base))
    for slug in slugs:
        d = base / ai.derive({'slug': slug} if slug else None)['name']
        d.mkdir(parents=True, exist_ok=True)
        (d / 'device-ca.crt').write_text('-----BEGIN CERTIFICATE-----\n',
                                         encoding='utf-8')


@pytest.fixture
def one_deployment(monkeypatch, tmp_path):
    """A box with the single plain deployment, as every box has today."""
    # ⚠️ `caddy_sites` no longer *writes* the trust pool — it reports one
    # that is already staged (W230). So the fixture stages files instead of
    # stubbing a writer, under `tmp_path` rather than a real `/var/lib/caddy`.
    _stage(monkeypatch, tmp_path, None, 'agencya')
    return {'atlas_enabled': True}


def test_one_deployment_produces_exactly_one_site(one_deployment):
    sites = atlas.caddy_sites(one_deployment, 'atlas.leckliter.net')

    assert len(sites) == 1


def test_that_one_site_is_what_the_generator_used_before(one_deployment):
    """⚠️ **The byte-identical guarantee, in one assertion.** These three values
    are what the hardcoded block carried: the console host, `127.0.0.1:8760`, and
    `/var/lib/caddy/atlas/device-ca.crt`. If any of them moves, the Caddyfile
    changes on a box that has not asked for anything."""
    site = atlas.caddy_sites(one_deployment, 'atlas.leckliter.net')[0]

    assert site['host'] == 'atlas.leckliter.net'
    assert site['upstream'] == '127.0.0.1:8760'
    assert site['ca_path'].endswith('/caddy/atlas/device-ca.crt')
    assert site['slug'] is None


def test_nothing_installed_produces_no_sites(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'store.img'))

    assert atlas.caddy_sites({}, 'atlas.leckliter.net') == []


@pytest.fixture
def two_deployments(monkeypatch, tmp_path):
    # ⚠️ `caddy_sites` no longer *writes* the trust pool — it reports one
    # that is already staged (W230). So the fixture stages files instead of
    # stubbing a writer, under `tmp_path` rather than a real `/var/lib/caddy`.
    _stage(monkeypatch, tmp_path, None, 'agencya')
    return {
        'atlas_enabled': True,
        ai.INSTANCES_KEY: [
            ai.make(None, ai.MODE_FIXED, 100, 8760),
            ai.make('agencya', ai.MODE_DYNAMIC, 50, 8761),
        ],
    }


def test_each_deployment_gets_its_own_site(two_deployments):
    sites = atlas.caddy_sites(two_deployments, 'atlas.leckliter.net')

    assert [s['host'] for s in sites] == [
        'atlas.leckliter.net', 'atlas.agencya.leckliter.net']


def test_each_deployment_has_its_own_upstream_port(two_deployments):
    """Two agencies on one upstream would send every request to whichever
    container happened to bind first."""
    sites = atlas.caddy_sites(two_deployments, 'atlas.leckliter.net')

    assert [s['upstream'] for s in sites] == ['127.0.0.1:8760', '127.0.0.1:8761']


def test_each_deployment_has_its_own_device_ca(two_deployments):
    """⚠️ **The one that matters for tenancy.** `client_auth` verifies against
    exactly one trust pool. Pointing two agencies at one file would have Caddy
    accept either agency's devices at either agency's hostname — the
    cryptographic separation the whole design rests on, undone by a shared
    path."""
    sites = atlas.caddy_sites(two_deployments, 'atlas.leckliter.net')

    paths = [s['ca_path'] for s in sites]

    assert [p.split('/caddy/', 1)[1] for p in paths] == [
        'atlas/device-ca.crt', 'atlas-agencya/device-ca.crt']
    assert len(set(paths)) == 2


def test_no_two_sites_share_anything(two_deployments):
    a, b = atlas.caddy_sites(two_deployments, 'atlas.leckliter.net')

    for field in ('host', 'upstream', 'ca_path', 'slug'):
        assert a[field] != b[field], f'{field} is shared between deployments'


def test_a_deployment_without_a_ca_reports_none(monkeypatch, tmp_path):
    """Caddy cannot verify devices without one, and the generator skips the
    device site rather than emitting a `pem_file` that does not exist — which
    stops Caddy from starting at all."""
    # Nothing staged: the pool is simply absent.
    monkeypatch.setattr(atlas, 'caddy_base', lambda: posix(tmp_path / 'caddy'))

    site = atlas.caddy_sites({'atlas_enabled': True}, 'atlas.leckliter.net')[0]

    assert site['ca_path'] is None


# --------------------------------------------------------------------------- #
# Where the CA copy lands
# --------------------------------------------------------------------------- #


def test_the_ca_copy_is_per_deployment(monkeypatch, tmp_path):
    """⚠️ A shared `atlas/device-ca.crt` would have the last deployment to run
    overwrite every other agency's trust pool — and Caddy would then verify
    one agency's devices against another agency's CA.

    ⚠️ **Asserted on the destination, not on a spied `os.makedirs`.** This
    used to watch that call inside a `try/except: pass`, because the write
    itself needed a real `/var/lib/caddy`. The write now goes through
    `ctx['_write_priv']`, so the fake writer *is* the observation and nothing
    has to be swallowed.
    """
    src = tmp_path / 'atlas' / 'agencya' / 'pki'
    src.mkdir(parents=True)
    (src / 'ca.crt').write_text(
        '-----BEGIN CERTIFICATE-----' + chr(10) + 'x' + chr(10)
        + '-----END CERTIFICATE-----', encoding='utf-8')
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: posix(tmp_path))
    monkeypatch.setattr(atlas, 'caddy_base', lambda: posix(tmp_path / 'caddy'))

    written = {}
    ctx = {'_write_priv': lambda path, body, **k: written.update(
        {'path': path, 'body': body})}
    # ⚠️ Recorded rather than run. The broker's `write` does NOT create
    # parent directories -- measured against the live broker, a write to a
    # missing parent returns FileNotFoundError -- so the module makes the
    # directory first. Letting the real `mkdir` run here would make this test
    # depend on the host having a POSIX one.
    ran = []
    monkeypatch.setattr(atlas, '_run_root',
                        lambda argv, timeout=120: (ran.append(argv), (0, ''))[1])

    dest = atlas.sync_device_ca_for_caddy(
        ai.make('agencya', ai.MODE_FIXED, 50, 8761), ctx)

    assert dest.endswith('atlas-agencya/device-ca.crt'), dest
    assert written['path'] == dest
    assert 'BEGIN CERTIFICATE' in written['body']
    # ⚠️ **Caddy's directory did not nest, and must not.** W233 moved the
    # *install* directory; this one is `/var/lib/caddy/<name>`, keyed by
    # the deployment name Caddy's config already refers to. Renaming it
    # would point every generated vhost at a trust pool that is not there.
    assert ['mkdir', '-p', posix(tmp_path / 'caddy' / 'atlas-agencya')] in ran, ran


def test_the_ca_is_not_staged_when_its_directory_cannot_be_made(monkeypatch, tmp_path):
    """⚠️ **The failure that cost a deploy.** The comment here used to claim
    `_write_priv` creates the parent; it does not, and nothing else did once
    the old `os.makedirs` was removed. A staging that cannot happen must
    report None so `deploy` refuses -- not write into nowhere."""
    src = tmp_path / 'atlas' / 'default' / 'pki'
    src.mkdir(parents=True)
    (src / 'ca.crt').write_text('-----BEGIN CERTIFICATE-----', encoding='utf-8')
    monkeypatch.setattr(atlas, 'install_base', lambda ctx=None: posix(tmp_path))
    monkeypatch.setattr(atlas, 'caddy_base', lambda: posix(tmp_path / 'caddy'))
    monkeypatch.setattr(atlas, '_run_root',
                        lambda argv, timeout=120: (1, 'Permission denied'))

    assert atlas.sync_device_ca_for_caddy(
        None, {'_write_priv': lambda *a, **k: None}) is None


def test_the_ca_is_not_written_without_a_privileged_writer(monkeypatch, tmp_path):
    """⚠️ `/var/lib/caddy` is not the console's to write. With no
    `_write_priv` in `ctx` there is nothing to do but say so — and `deploy`
    turns that None into a refusal, because a device channel that silently
    does not exist is worse than a deploy that stops."""
    src = tmp_path / 'atlas' / 'default' / 'pki'
    src.mkdir(parents=True)
    (src / 'ca.crt').write_text('-----BEGIN CERTIFICATE-----', encoding='utf-8')
    monkeypatch.setattr(atlas, 'install_base', lambda ctx=None: posix(tmp_path))
    monkeypatch.setattr(atlas, 'caddy_base', lambda: posix(tmp_path / 'caddy'))

    assert atlas.sync_device_ca_for_caddy(None, {}) is None
