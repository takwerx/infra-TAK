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
"""The agency a deployment serves, collected and passed on (W217).

Operator, 2026-09-18: a field beside the slug, passed into the deployment, shown
in the footer of that deployment's own console above the version.

⚠️ **The slug is not the name.** `corona` is what goes into a hostname, a
systemd unit, a Compose project and a Docker volume, and it has to satisfy the
intersection of all four. "Corona Fire Department" is what the agency calls
itself. The whole reason the field exists is that one cannot be derived from the
other.
"""

import os
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from atlas_pin import pin_at_least  # noqa: E402
from modules import atlas_instances as ai
from atlas_layout import deployment_dir  # noqa: E402


# --------------------------------------------------------------------------- #
# What counts as a name
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('name', [
    'Corona Fire Department',
    "St Mary's Fire District",
    'Police & Fire, Redlands',
    'Comté de Saint-Étienne',
    'A',
])
def test_an_ordinary_agency_name_is_accepted(name):
    """⚠️ Free text on purpose. Spaces, capitals, ampersands, apostrophes and
    accents are all ordinary in the name of an agency; running it through the
    slug rules would produce something nobody calls themselves."""
    value, err = ai.validate_agency_name(name)

    assert err is None, err
    assert value == name


def test_blank_is_allowed_and_means_no_name():
    """Most deployments never set it, and the footer then reads exactly as it
    did before."""
    assert ai.validate_agency_name('') == ('', None)
    assert ai.validate_agency_name(None) == ('', None)


def test_surrounding_whitespace_is_trimmed():
    assert ai.validate_agency_name('  Corona Fire Department  ')[0] == \
        'Corona Fire Department'


def test_whitespace_alone_is_no_name():
    """An operator who typed a space has not named anything, and a footer with
    an invisible name in it is a footer that grew a blank line."""
    assert ai.validate_agency_name('   ') == ('', None)


def test_a_line_break_is_refused_not_stripped():
    """⚠️ Refused, because a name that silently loses a character is a name the
    operator will not recognise — and anything arriving here with a newline in
    it came from something other than the field."""
    value, err = ai.validate_agency_name('Corona Fire\nDepartment')

    assert value is None
    assert err and 'line breaks' in err


def test_a_control_character_is_refused():
    value, err = ai.validate_agency_name('Corona\x00Fire')

    assert value is None
    assert err


def test_a_name_too_long_for_a_footer_is_refused():
    """⚠️ Not a database limit — the footer is. A 400-character name would wrap
    across the bottom of every page and push the version off screen, which is
    the one thing the footer already had to say."""
    value, err = ai.validate_agency_name('x' * (ai.AGENCY_NAME_MAX + 1))

    assert value is None
    assert err and str(ai.AGENCY_NAME_MAX) in err


def test_a_name_at_the_limit_is_accepted():
    assert ai.validate_agency_name('x' * ai.AGENCY_NAME_MAX)[1] is None


# --------------------------------------------------------------------------- #
# It rides on the record
# --------------------------------------------------------------------------- #


def test_a_new_deployment_carries_its_name():
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761,
                   agency_name='Corona Fire Department')

    assert inst['agency_name'] == 'Corona Fire Department'


def test_a_deployment_made_without_one_has_an_empty_name():
    """Every deployment that already exists was made before the field did, so
    reading it must not raise — and must not invent a name either."""
    assert ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)['agency_name'] == ''


def test_the_name_is_not_derived_from_the_slug():
    """⚠️ The point of the field. `corona` is not "Corona Fire Department", and
    guessing would produce a footer nobody recognises."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)

    assert 'corona' not in inst['agency_name'].lower()
    assert inst['agency_name'] == ''


# --------------------------------------------------------------------------- #
# And reaches the deployment
# --------------------------------------------------------------------------- #


@pytest.fixture
def ctx(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    return {'_get_service_domain': lambda s, k: 'atlas.leckliter.net'}


def test_the_identity_carries_the_name(ctx):
    """One place `deploy` reads it from, beside the hostname and the port."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761,
                   agency_name='Corona Fire Department')

    me = atlas.deployment_identity(ctx, inst, {})

    assert me['agency_name'] == 'Corona Fire Department'


def test_an_unnamed_deployment_carries_an_empty_name(ctx):
    me = atlas.deployment_identity(ctx, ai.make('corona', ai.MODE_DYNAMIC, 50, 8761), {})

    assert me['agency_name'] == ''


def test_the_env_template_passes_it_to_the_application():
    """⚠️ `TAKMDM_AGENCY_NAME` is what ATLAS reads; a different spelling here
    would write a setting the application ignores, and the footer would stay
    blank with nothing to explain why."""
    body = atlas._ENV_TEMPLATE.format(
        trusted_proxies='10.0.0.0/8', pg_password='x', device_url='',
        apk_url='', console_url='',
        agency_name=atlas._env_quote('Corona Fire Department'))

    assert 'TAKMDM_AGENCY_NAME="Corona Fire Department"' in body


def test_deploy_writes_the_name_it_resolved():
    """The identity is only useful if the write uses it."""
    source = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    start = source.index(chr(10) + 'def deploy(')
    end = source.index(chr(10) + 'def ', start + 1)

    # ⚠️ Quoted at this one site. The instance record keeps the plain name —
    # it is what the console renders — and the escaping belongs only where
    # compose parses it (upstream review, item 7).
    assert "agency_name=_env_quote(_me['agency_name'])" in source[start:end]


def test_the_pin_points_at_the_release_that_renders_it():
    """⚠️ The name reaching `.env` does nothing until the deployment runs a
    release that knows the setting. A fresh install lands on the pin, so the pin
    has to be that release or the feature ships invisible.

    ⚠️ **At least, not exactly**, and the SHA is not asserted here at all:
    this test is about a capability, and a commit hash says nothing about one.
    Whether the pin matches the promoted release is
    `test_the_pin_names_the_stable_release`, which is the single place a
    promotion touches.
    """
    ok, why = pin_at_least('v1.49.0')

    assert ok, why


# --------------------------------------------------------------------------- #
# Naming a deployment that already exists
# --------------------------------------------------------------------------- #


def test_one_line_is_replaced_not_appended(tmp_path):
    env = tmp_path / '.env'
    env.write_text('A=1\nTAKMDM_AGENCY_NAME=Old\nB=2\n', encoding='utf-8')

    changed = atlas.write_env_value(str(env), 'TAKMDM_AGENCY_NAME', 'New')

    assert changed is True
    assert env.read_text(encoding='utf-8') == 'A=1\nTAKMDM_AGENCY_NAME=New\nB=2\n'


def test_a_missing_key_is_added(tmp_path):
    """⚠️ Every deployment made before this setting existed has an `.env`
    without it, and `deploy` is the only thing that rewrites the file wholesale.
    Without appending, the only way to add a setting to a running deployment
    would be to deploy it again."""
    env = tmp_path / '.env'
    env.write_text('A=1\n', encoding='utf-8')

    atlas.write_env_value(str(env), 'TAKMDM_AGENCY_NAME',
                          atlas._env_quote('Corona Fire Department'))

    assert 'TAKMDM_AGENCY_NAME="Corona Fire Department"' in \
        env.read_text(encoding='utf-8')


def test_a_line_that_merely_mentions_the_key_is_left_alone(tmp_path):
    """⚠️ The *line*, not a substring. The template ships a comment block naming
    the setting directly above it, and a substring rewrite would eat the
    comment and leave the setting."""
    env = tmp_path / '.env'
    env.write_text('# TAKMDM_AGENCY_NAME is the agency\n'
                   'TAKMDM_AGENCY_NAME=Old\n', encoding='utf-8')

    atlas.write_env_value(str(env), 'TAKMDM_AGENCY_NAME', 'New')
    body = env.read_text(encoding='utf-8')

    assert '# TAKMDM_AGENCY_NAME is the agency' in body
    assert 'TAKMDM_AGENCY_NAME=New' in body
    assert 'TAKMDM_AGENCY_NAME=Old' not in body


def test_writing_the_same_value_changes_nothing(tmp_path):
    env = tmp_path / '.env'
    env.write_text('TAKMDM_AGENCY_NAME=Same\n', encoding='utf-8')

    assert atlas.write_env_value(str(env), 'TAKMDM_AGENCY_NAME', 'Same') is False


def test_a_missing_file_is_reported_rather_than_swallowed(tmp_path):
    """⚠️ **Inverted deliberately (upstream review, item 8).** This used to
    assert that a missing `.env` returned False — and the route above it
    reported "Written to the deployment configuration" either way, so a
    permissions problem read as success and the operator went looking for the
    name in a footer that was never going to show it."""
    with pytest.raises(OSError):
        atlas.write_env_value(str(tmp_path / 'nope'), 'K', 'v')


def test_the_route_reports_a_write_that_failed(tmp_path, monkeypatch):
    """And the caller turns it into an error rather than a step."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    d = tmp_path / 'atlas' / 'corona'
    d.mkdir(parents=True)
    (d / '.env').write_text('TAKMDM_AGENCY_NAME=""\n', encoding='utf-8')
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    saved = {ai.INSTANCES_KEY: [inst]}
    ctx = {'load_settings': lambda: dict(saved),
           'save_settings': lambda s: saved.update(s)}

    def refuse(*a, **k):
        raise OSError(13, 'Permission denied')

    monkeypatch.setattr(atlas, 'write_env_value', refuse)

    steps, err = atlas.set_agency_name(ctx, inst, 'Corona Fire Department')

    assert err and 'Permission denied' in err
    assert 'Written to the deployment configuration' not in steps


class Result:
    returncode = 0
    stdout = ''
    stderr = ''


@pytest.fixture
def built(monkeypatch, tmp_path):
    """A deployment with an `.env`, and compose faked."""
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    d = tmp_path / 'atlas' / 'corona'
    d.mkdir(parents=True)
    (d / '.env').write_text('TAKMDM_AGENCY_NAME=\n', encoding='utf-8')
    saved = {'atlas_enabled': True, ai.INSTANCES_KEY: [inst]}
    ran = []
    monkeypatch.setattr(atlas, '_compose',
                        lambda c, a, timeout=180, inst=None:
                        ran.append((a, (inst or {}).get('slug'))) or Result())
    ctx = {'load_settings': lambda: dict(saved),
           'save_settings': lambda s: saved.update(s)}
    return ctx, inst, d, saved, ran


def test_naming_an_existing_deployment_records_it(built):
    ctx, inst, _d, saved, _ran = built

    steps, err = atlas.set_agency_name(ctx, inst, 'Corona Fire Department')

    assert err is None, err
    assert saved[ai.INSTANCES_KEY][0]['agency_name'] == 'Corona Fire Department'


def test_it_reaches_the_deployment_s_configuration(built):
    ctx, inst, d, _saved, _ran = built

    atlas.set_agency_name(ctx, inst, 'Corona Fire Department')

    assert 'TAKMDM_AGENCY_NAME="Corona Fire Department"' in \
        (d / '.env').read_text(encoding='utf-8')


def test_the_deployment_is_recreated_to_pick_it_up(built):
    """⚠️ **`up -d`, not `restart`. Measured on the box.** The name was in
    `.env`, the record and the log both said it had been applied, and `printenv`
    inside the container showed nothing.

    Compose interpolates `${TAKMDM_AGENCY_NAME}` when it *renders* the
    configuration and bakes the result in at container **create** time.
    `restart` stops and starts the same container, so a changed `.env` value
    never reaches it. `up -d` re-renders, sees the difference and recreates.
    """
    ctx, inst, _d, _saved, ran = built

    atlas.set_agency_name(ctx, inst, 'Corona Fire Department')

    assert ran == [('up -d api', 'corona')]


def test_it_restarts_that_deployment_and_not_another(built):
    ctx, inst, _d, _saved, ran = built

    atlas.set_agency_name(ctx, inst, 'Corona Fire Department')

    assert ran[0][1] == 'corona'


def test_a_bad_name_changes_nothing(built):
    ctx, inst, d, saved, ran = built

    steps, err = atlas.set_agency_name(ctx, inst, 'x' * 200)

    assert err
    assert ran == []
    assert saved[ai.INSTANCES_KEY][0].get('agency_name', '') == ''
    assert 'TAKMDM_AGENCY_NAME=\n' in (d / '.env').read_text(encoding='utf-8')


def test_a_name_can_be_cleared(built):
    ctx, inst, d, saved, _ran = built
    atlas.set_agency_name(ctx, inst, 'Corona Fire Department')

    steps, err = atlas.set_agency_name(ctx, inst, '')

    assert err is None
    assert saved[ai.INSTANCES_KEY][0]['agency_name'] == ''
    assert 'TAKMDM_AGENCY_NAME=""\n' in (d / '.env').read_text(encoding='utf-8')


def test_a_deployment_with_no_configuration_is_refused(monkeypatch, tmp_path):
    """Nothing to write to. Reporting success would leave an operator waiting
    for a footer that cannot change."""
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    ctx = {'load_settings': lambda: {}, 'save_settings': lambda s: None}

    steps, err = atlas.set_agency_name(
        ctx, ai.make('corona', ai.MODE_DYNAMIC, 50, 8761), 'Corona')

    assert err and 'no configuration' in err


def test_renaming_one_deployment_leaves_the_others_alone(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, '_compose',
                        lambda c, a, timeout=180, inst=None: Result())
    corona = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    redlands = ai.make('redlands', ai.MODE_DYNAMIC, 50, 8762,
                       agency_name='Redlands PD')
    for name in ('atlas-corona', 'atlas-redlands'):
        d = deployment_dir(name)
        d.mkdir(parents=True)
        (d / '.env').write_text('TAKMDM_AGENCY_NAME=\n', encoding='utf-8')
    saved = {'atlas_enabled': True, ai.INSTANCES_KEY: [corona, redlands]}
    ctx = {'load_settings': lambda: dict(saved),
           'save_settings': lambda s: saved.update(s)}

    atlas.set_agency_name(ctx, corona, 'Corona Fire Department')

    by_slug = {i['slug']: i['agency_name'] for i in saved[ai.INSTANCES_KEY]}

    assert by_slug == {'corona': 'Corona Fire Department',
                       'redlands': 'Redlands PD'}


# --------------------------------------------------------------------------- #
# The page sees it
# --------------------------------------------------------------------------- #


PAGE = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')


def test_the_row_is_sent_the_name():
    assert 'agency_name' in atlas.INSTANCE_FIELDS


def test_the_form_asks_for_it_beside_the_slug():
    slug_at = PAGE.index('id="agencySlug"')
    name_at = PAGE.index('id="agencyName"')
    error_at = PAGE.index('id="addInstanceError"')

    assert slug_at < name_at < error_at, 'the name field left the deploy form'


def test_the_field_is_capped_where_the_validator_caps_it():
    """⚠️ A browser that accepts 200 characters and a server that refuses 61 is
    a form that fails after the operator has finished typing."""
    field = PAGE[PAGE.index('id="agencyName"'):][:400]

    assert 'maxlength="60"' in field
    assert ai.AGENCY_NAME_MAX == 60


def test_the_request_carries_it():
    assert 'agency_name: typedAgencyName()' in PAGE


def test_the_confirmation_repeats_it_back():
    """It is free text nobody validates for spelling; the operator reading it is
    the check, and the modal is the only place they get to."""
    assert "'  name        ' + (name || 'not set')" in PAGE


# --------------------------------------------------------------------------- #
# Recording a named deployment
# --------------------------------------------------------------------------- #


@pytest.fixture
def empty_box(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, '_pool_gb', lambda c, instances: 100.0)
    monkeypatch.setattr(atlas, '_ports_in_use', lambda: ())
    saved = {'atlas_enabled': True, ai.INSTANCES_KEY: []}
    return {'load_settings': lambda: dict(saved),
            'save_settings': lambda s: saved.update(s)}, saved


def test_a_deployment_is_recorded_with_the_name_it_was_given(empty_box):
    ctx, saved = empty_box

    inst, err = atlas.add_instance(ctx, True, 'corona', ai.MODE_DYNAMIC, None,
                                   'Corona Fire Department')

    assert err is None, err
    assert inst['agency_name'] == 'Corona Fire Department'
    assert saved[ai.INSTANCES_KEY][0]['agency_name'] == 'Corona Fire Department'


def test_a_deployment_recorded_without_one_has_no_name(empty_box):
    ctx, _saved = empty_box

    inst, err = atlas.add_instance(ctx, True, 'corona', ai.MODE_DYNAMIC, None)

    assert err is None, err
    assert inst['agency_name'] == ''


def test_a_bad_name_refuses_the_whole_deployment(empty_box):
    """⚠️ Refused before the record is written, so a name the footer cannot
    show does not leave a slug and a port claimed behind it."""
    ctx, saved = empty_box

    inst, err = atlas.add_instance(ctx, True, 'corona', ai.MODE_DYNAMIC, None,
                                   'Corona\nFire')

    assert inst is None
    assert err and 'line breaks' in err
    assert saved[ai.INSTANCES_KEY] == []


def test_a_name_is_trimmed_before_it_is_recorded(empty_box):
    ctx, _saved = empty_box

    inst, _err = atlas.add_instance(ctx, True, 'corona', ai.MODE_DYNAMIC, None,
                                    '  Corona Fire Department  ')

    assert inst['agency_name'] == 'Corona Fire Department'


def test_a_record_made_before_the_field_existed_still_reports_a_name(
        monkeypatch, tmp_path):
    """⚠️ Every deployment on every box today was recorded without this key.
    The page reads `i.agency_name`; a row missing it would be `undefined` in the
    browser — falsy, rendered as nothing, with no error to explain it. The same
    shape of bug as "stopped version unknown"."""
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, 'compose_projects_present',
                        lambda c=None: {'takmdm-corona'})
    monkeypatch.setattr(atlas, 'capacity_facts', lambda c, size_gb=None: {})
    (tmp_path / 'atlas' / 'corona').mkdir(parents=True)
    # The record as an older console wrote it: no `agency_name` key at all.
    old = {'slug': 'corona', 'mode': ai.MODE_DYNAMIC, 'size_gb': 50,
           'port': 8761}
    settings = {'atlas_enabled': True, ai.INSTANCES_KEY: [old]}
    ctx = {'load_settings': lambda: dict(settings),
           'probe_run': lambda argv, **k: Result()}

    row = atlas.instances_payload(ctx)['instances'][0]

    assert row['agency_name'] == ''


# --------------------------------------------------------------------------- #
# A setting the release cannot read (W219)
# --------------------------------------------------------------------------- #
#
# ⚠️ **The fourth occurrence of one failure.** ATLAS's `docker-compose.yml` has
# no `env_file`, so a `TAKMDM_*` in `.env` reaches the container only where
# compose names it. It has happened with `TAKMDM_INCLUDE_SERVER_CA`
# (provisioning went on pinning a CA it should not have), with
# `TAKMDM_TRUSTED_PROXIES` (SEC_AUDIT S-1's mitigation shipped inert for a
# release), and with `TAKMDM_AGENCY_NAME` — that one *with* a warning comment
# and a test in the product repository, both in place, neither able to see this
# repository.
#
# The two files only exist together on the box, after the clone. That is the one
# moment the question can be answered, so it is answered there.


def test_every_key_the_template_writes_is_reported():
    """Read out of the template, so a setting added there cannot be forgotten
    here."""
    written = atlas.env_keys_written()

    assert 'TAKMDM_AGENCY_NAME' in written
    assert 'TAKMDM_TRUSTED_PROXIES' in written
    assert all(k.startswith('TAKMDM_') for k in written), written


def _checkout(tmp_path, declared):
    d = tmp_path / 'atlas' / 'corona'
    d.mkdir(parents=True, exist_ok=True)
    body = ['services:', '  api:', '    environment:']
    body += ['      %s: ${%s-}' % (k, k) for k in declared]
    (d / 'docker-compose.yml').write_text(chr(10).join(body) + chr(10),
                                          encoding='utf-8')
    return str(d)


def test_a_release_that_names_everything_reports_nothing(tmp_path):
    path = _checkout(tmp_path, atlas.env_keys_written())

    assert atlas.env_keys_that_reach_nothing(path) == []


def test_a_setting_compose_does_not_name_is_reported(tmp_path):
    """⚠️ The exact bug. The value is correct in every file an operator would
    look at, and the application never sees it."""
    declared = [k for k in atlas.env_keys_written() if k != 'TAKMDM_AGENCY_NAME']
    path = _checkout(tmp_path, declared)

    assert atlas.env_keys_that_reach_nothing(path) == ['TAKMDM_AGENCY_NAME']


def test_an_unreadable_compose_file_raises_no_alarm(tmp_path):
    """⚠️ "We could not look" is not "nothing is declared". Reporting the second
    would put a false warning in the log of every deploy that raced the clone."""
    assert atlas.env_keys_that_reach_nothing(str(tmp_path / 'nowhere')) == []
    assert atlas.env_keys_compose_passes(str(tmp_path / 'nowhere')) is None


def test_a_release_that_names_more_than_we_write_is_fine(tmp_path):
    """The product has settings the module does not write — defaults it sets
    itself. Only the other direction is a fault."""
    path = _checkout(tmp_path, atlas.env_keys_written() + ['TAKMDM_SOMETHING_ELSE'])

    assert atlas.env_keys_that_reach_nothing(path) == []


def test_the_deploy_log_says_so():
    """⚠️ In the deploy log, where an operator will actually see it. Not fatal:
    the deployment works, minus whatever that setting did, and failing the
    deploy over it would be worse than naming it."""
    source = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    start = source.index(chr(10) + 'def deploy(')
    end = source.index(chr(10) + 'def ', start + 1)
    body = source[start:end]

    assert 'env_keys_that_reach_nothing(dirpath)' in body
    assert 'does not read' in body


def test_a_variable_that_is_only_interpolated_still_counts(tmp_path):
    """⚠️ **A false positive the first run produced, on the box.**
    `TAKMDM_DB_PASSWORD` is never a key under `environment:` — it is
    interpolated into `POSTGRES_PASSWORD` for the database and into
    `TAKMDM_DATABASE_URL` for the application. Reporting it as unread would put
    a warning an operator cannot act on into every deploy log, which is how a
    warning stops being read at all."""
    d = tmp_path / 'atlas' / 'corona'
    d.mkdir(parents=True)
    (d / 'docker-compose.yml').write_text(
        'services:' + chr(10)
        + '  db:' + chr(10)
        + '    environment:' + chr(10)
        + '      POSTGRES_PASSWORD: ${TAKMDM_DB_PASSWORD:-takmdm}' + chr(10),
        encoding='utf-8')

    assert 'TAKMDM_DB_PASSWORD' in atlas.env_keys_compose_passes(str(d))
    assert 'TAKMDM_DB_PASSWORD' not in atlas.env_keys_that_reach_nothing(str(d))
