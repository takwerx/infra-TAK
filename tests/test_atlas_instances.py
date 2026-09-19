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
"""The ATLAS instance model (W216, chunk 1).

⚠️ **What these protect.** The operator's rules for multi-instance ATLAS are
small enough to hold in your head and easy to get subtly wrong:

* one non-agency deployment at most, and the setup question disappears while it
  exists — *"for as long as a non-agency atlas (no slug) is deployed"*, which
  means derived state, not a latch;
* a slug that is simultaneously a DNS label, a systemd unit name, a Compose
  project and a Docker volume;
* and a plain instance that must keep deriving **exactly** what is already
  running on the box, because a refactor that moved `/root/atlas` would strand a
  live deployment.

All pure. No box, no Docker, no filesystem.
"""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import atlas_instances as inst  # noqa: E402


PLAIN = inst.make(None, inst.MODE_FIXED, 100, 8760)
AGENCY_A = inst.make('agencya', inst.MODE_DYNAMIC, 100, 8761)


# --------------------------------------------------------------------------- #
# The rule: at most one non-agency deployment
# --------------------------------------------------------------------------- #


def test_a_plain_deployment_is_allowed_on_an_empty_box():
    assert inst.may_deploy_plain([]) is True


def test_a_plain_deployment_is_allowed_alongside_agencies():
    """Agencies do not consume the single plain slot."""
    assert inst.may_deploy_plain([AGENCY_A]) is True


def test_a_second_plain_deployment_is_refused():
    """⚠️ The operator's rule: once a slug-less ATLAS exists, another cannot be
    deployed, so the console stops asking the question."""
    assert inst.may_deploy_plain([PLAIN]) is False


def test_the_question_returns_when_the_plain_instance_goes_away():
    """⚠️ **Derived, never latched.** *"for as long as a non-agency atlas is
    deployed"* — so uninstalling it makes the option available again. A flag set
    once at first deploy would answer "no" for ever and strand the box."""
    instances = [PLAIN, AGENCY_A]
    assert inst.may_deploy_plain(instances) is False

    instances = [AGENCY_A]

    assert inst.may_deploy_plain(instances) is True


def test_the_plain_instance_is_found_among_many():
    assert inst.plain([AGENCY_A, PLAIN]) is PLAIN


def test_no_plain_instance_reads_as_none():
    assert inst.plain([AGENCY_A]) is None
    assert inst.plain([]) is None


# --------------------------------------------------------------------------- #
# Slugs: four identifiers at once
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("good", ["agencya", "pd", "countysheriff", "corona"])
def test_a_usable_slug_is_accepted(good):
    slug, err = inst.validate_slug(good)

    assert err is None
    assert slug == good


@pytest.mark.parametrize(
    "bad,because",
    [
        ("", "required"),
        (None, "required"),
        ("   ", "required"),
        # ⚠️ Hyphens and digits are refused now, not merely discouraged
        # (operator decision): the slug becomes part of `atlas-<slug>`, and a
        # hyphen inside it cannot be told from the separator.
        ("-lead", "lowercase letters only"),
        ("trail-", "lowercase letters only"),
        ("under_score", "lowercase letters only"),
        ("two words", "lowercase letters only"),
        ("agency-a", "lowercase letters only"),
        ("county1", "lowercase letters only"),
        ("sub.domain", "one label"),
        ("x" * 40, "characters or fewer"),
    ],
)
def test_an_unusable_slug_is_refused_with_a_reason(bad, because):
    slug, err = inst.validate_slug(bad)

    assert slug is None
    assert err and because in err


@pytest.mark.parametrize(
    "typed,stored",
    [("AgencyA", "agencya"), ("PD", "pd"), ("  Corona  ", "corona")],
)
def test_case_is_forced_rather_than_refused(typed, stored):
    """⚠️ **Operator decision: force lowercase.** The slug is a DNS label, a
    systemd unit name, a Compose project and a volume name, none of which agree
    about case, and a capital letter has exactly one sensible interpretation.

    The *normalised* value is what comes back, because it is what gets stored and
    what the hostname is built from — the console has to show the operator
    `atlas.agencya.<fqdn>` rather than echoing what they typed."""
    slug, err = inst.validate_slug(typed)

    assert err is None
    assert slug == stored


@pytest.mark.parametrize("bad", ["two words", "under_score", "sub.domain"])
def test_only_case_is_forced_and_nothing_else_is(bad):
    """⚠️ There is one obvious reading of a capital letter and no obvious reading
    of a space or an underscore. Guessing at those would put a hostname on the
    box that the operator never chose."""
    slug, err = inst.validate_slug(bad)

    assert slug is None
    assert err


def test_uniqueness_survives_the_case_change():
    """A consequence worth pinning: `AgencyA` and `agencya` resolve to the same
    hostname, so the second must be refused as a duplicate."""
    slug, err = inst.validate_slug("AgencyA", [AGENCY_A])

    assert slug is None
    assert "already" in err


def test_a_reserved_slug_cannot_be_smuggled_in_by_case():
    """⚠️ `PG` must be as reserved as `pg` — the collision it causes is with
    `atlas_pg_password`, which does not care how it was typed."""
    slug, err = inst.validate_slug("PG")

    assert slug is None
    assert "reserved" in err


def test_a_duplicate_slug_is_refused():
    slug, err = inst.validate_slug("agencya", [AGENCY_A])

    assert slug is None
    assert "already" in err


def test_a_slug_that_would_collide_with_a_settings_key_is_refused():
    """⚠️ **The non-obvious one.** The settings prefix is `atlas_<slug>_`, so a
    slug of `pg` produces `atlas_pg_password` — the *plain* instance's own
    database password key. Two deployments would then share one secret."""
    slug, err = inst.validate_slug("pg")

    assert slug is None
    assert "reserved" in err


@pytest.mark.parametrize("reserved", sorted(inst.RESERVED_SLUGS))
def test_every_reserved_slug_is_refused(reserved):
    slug, err = inst.validate_slug(reserved)

    assert slug is None


def test_no_reserved_slug_can_produce_an_existing_plain_settings_key():
    """The reserved list has to actually cover the collision it claims to.

    ⚠️ Asserted against the real keys rather than a copy: for each `atlas_x_*`
    prefix a slug could create, the first segment must be reserved.
    """
    live_plain_keys = [
        "atlas_enabled", "atlas_pg_password", "atlas_commit_sha",
        "atlas_access_restricted", "atlas_access_checked_at", "atlas_instances",
    ]

    for key in live_plain_keys:
        first_segment = key[len("atlas_"):].split("_")[0]
        assert first_segment in inst.RESERVED_SLUGS, (
            f"a slug of {first_segment!r} would collide with {key}"
        )


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("mode", [inst.MODE_FIXED, inst.MODE_DYNAMIC])
def test_both_modes_are_accepted(mode):
    chosen, err = inst.validate_mode(mode)

    assert err is None and chosen == mode


@pytest.mark.parametrize("bad", ["elastic", "", None, "FIXED"])
def test_any_other_mode_is_refused(bad):
    chosen, err = inst.validate_mode(bad)

    assert chosen is None
    assert "sizing mode" in err


def test_the_size_field_is_labelled_by_what_it_means():
    """⚠️ One field, two meanings. Under `fixed` the number is space taken from
    the box and held; under `dynamic` it is only a ceiling and nothing is held.
    Labelling them the same would be the dishonest-number problem again."""
    assert inst.size_label(inst.MODE_FIXED) == "reserved"
    assert inst.size_label(inst.MODE_DYNAMIC) == "maximum"


# --------------------------------------------------------------------------- #
# Ports
# --------------------------------------------------------------------------- #


def test_the_first_instance_takes_the_port_already_in_use_today():
    """8760 is what the deployed plain instance binds, so it must stay its."""
    assert inst.next_port([]) == inst.BASE_PORT == 8760


def test_a_second_instance_gets_the_next_port():
    assert inst.next_port([PLAIN]) == 8761


def test_ports_already_taken_are_skipped():
    assert inst.next_port([PLAIN, AGENCY_A]) == 8762


def test_a_port_observed_on_the_box_is_skipped():
    """This module cannot see the box, so the caller passes what it found."""
    assert inst.next_port([], taken=[8760, 8761]) == 8762


def test_other_modules_ports_are_never_handed_out():
    """⚠️ 8449 is ATLAS's own device channel and 8888/9443 belong to other
    stacks. Handing one out would produce a deploy that fails at bind time with
    nothing on the page to explain it.

    ⚠️ **Crowded up to a known-taken port on purpose.** The first version
    filled 8760-8789 and asserted the answer was not in the reserved set — which
    it never could be, because nothing reserved lives there. The assertion was
    vacuous and survived deleting the guard. 8888 is the first reserved port the
    allocator can actually walk into, so the test walks it there.
    """
    assert 8888 in inst.KNOWN_TAKEN_PORTS

    port = inst.next_port([], taken=range(inst.BASE_PORT, 8888))

    assert port == 8889, "the allocator handed out a port another stack holds"


def test_allocation_is_deterministic():
    assert inst.next_port([PLAIN]) == inst.next_port([PLAIN])


# --------------------------------------------------------------------------- #
# derive(): one place to be wrong
# --------------------------------------------------------------------------- #


def test_the_plain_instance_derives_exactly_what_is_deployed_today():
    """⚠️ **The most important test in this file.** These are the names a
    *running* deployment is identified by, read off the live box: compose
    project `takmdm`, volume `takmdm_pgdata`, `/var/lib/caddy/atlas`, settings
    keyed `atlas_*`, api on 127.0.0.1:8760. A refactor that moved any of them
    would strand a running deployment.

    ⚠️ **Directories are not among them any more (W233).** They used to be,
    and the entry was a hardcoded `/root/<name>` that `instance_paths`
    overwrote on its first line -- so this test was pinning a value nothing
    read, and it went stale the moment deployments nested. Where a deployment
    sits is asserted in `test_atlas_multi_instance.py`, against the function
    that actually decides."""
    d = inst.derive(PLAIN, fqdn="leckliter.net")

    for absent in ("dir", "store", "artifacts", "cache", "image"):
        assert absent not in d, (
            "%r is a *location*, and only `instance_paths` can answer that: "
            "it is the one that knows whether this box keeps deployments "
            "under /root or a home directory." % absent)
    assert d["compose_project"] == "takmdm"
    assert d["pg_volume"] == "takmdm_pgdata"
    assert d["caddy_ca_dir"] == "/var/lib/caddy/atlas"
    assert d["settings_prefix"] == "atlas_"
    assert d["authentik_slug"] == "atlas"
    assert d["vhost"] == "atlas.leckliter.net"
    assert d["port"] == 8760


def test_an_agency_instance_derives_a_parallel_set():
    d = inst.derive(AGENCY_A, fqdn="leckliter.net")

    for absent in ("dir", "store", "artifacts", "cache", "image"):
        assert absent not in d
    assert d["compose_project"] == "takmdm-agencya"
    assert d["pg_volume"] == "takmdm-agencya_pgdata"
    assert d["caddy_ca_dir"] == "/var/lib/caddy/atlas-agencya"
    assert d["settings_prefix"] == "atlas_agencya_"
    assert d["authentik_slug"] == "atlas-agencya"
    assert d["admin_group"] == "atlas-agencya-admins"
    assert d["vhost"] == "atlas.agencya.leckliter.net"
    assert d["port"] == 8761


def test_the_agency_hostname_is_a_third_level_label():
    """`atlas.<slug>.<fqdn>` — proven to work in this deployment, since
    `tiles.map.leckliter.net` already holds its own certificate."""
    d = inst.derive(AGENCY_A, fqdn="example.org")

    assert d["vhost"] == "atlas.agencya.example.org"
    assert d["device_host"] == "atlas.agencya.example.org"


def test_no_two_instances_share_any_derived_name():
    """⚠️ The whole point of deriving in one place. Every path, project, volume
    and prefix has to differ, or two agencies would write to each other."""
    a = inst.derive(PLAIN, fqdn="x.net")
    b = inst.derive(AGENCY_A, fqdn="x.net")
    # ⚠️ Paths are not here any more (W233) -- `instance_paths` owns them,
    # and `test_no_instance_shares_a_path_with_another` makes the same
    # assertion against the function that decides.
    shared = ("compose_project", "pg_volume", "caddy_ca_dir",
              "settings_prefix", "authentik_slug", "job_key", "vhost", "port")

    for field in shared:
        assert a[field] != b[field], f"{field} is the same for both instances"


def test_the_job_key_is_acceptable_to_the_module_registry():
    """⚠️ Descriptor and job keys are validated `[a-z0-9_-]+`, so a colon would
    fail at import — `atlas:agencya` was the obvious first shape and is not
    allowed."""
    for record in (PLAIN, AGENCY_A):
        key = inst.derive(record)["job_key"]
        assert key and all(c.isalnum() or c in "-_" for c in key)


def test_deriving_without_a_domain_leaves_the_hostnames_unset():
    """The fqdn is not known on every call site; absent is better than a
    hostname built from the string "None"."""
    d = inst.derive(AGENCY_A)

    assert d["vhost"] is None and d["device_host"] is None


def test_the_mode_travels_with_the_instance():
    assert inst.derive(PLAIN)["mode"] == inst.MODE_FIXED
    assert inst.derive(AGENCY_A)["mode"] == inst.MODE_DYNAMIC


def test_a_fixed_and_a_dynamic_instance_coexist():
    """The operator's requirement: side by side on one box."""
    instances = [PLAIN, AGENCY_A]
    modes = {i["mode"] for i in instances}

    assert modes == {inst.MODE_FIXED, inst.MODE_DYNAMIC}
    assert (inst.derive(PLAIN)["compose_project"]
            != inst.derive(AGENCY_A)["compose_project"])
