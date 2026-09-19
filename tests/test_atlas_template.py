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
"""The ATLAS console page, rendered (W214).

Three things an operator asked for, and one bug found while doing them:

* the deploy log is the **first** card, not the last;
* the **Install** card stands down while a deploy is running;
* the break-glass commands are sized to their content instead of getting a
  340px box around one line of `sed`.

⚠️ **The bug.** Those commands used `.log-box`, which had no `white-space`
rule — so the CSS default `normal` collapsed the newline between the two
commands and printed them as one line:

    sed -i '/^TAKMDM_PROXY_AUTH_SECRET=/d' /root/atlas/.env cd /root/atlas && ...

`sed` then treats `cd` and `/root/atlas` as further files to edit and the
command fails. That is the recovery path for an ATLAS lockout, so it mattered
more than the empty space that led to finding it. The same missing rule made a
running deploy's log render as one run-on paragraph, because `renderLog` joins
its lines with a newline into `textContent`.

These render the real template with the real loader rather than matching source
text, because what is asserted here is the *output* an operator sees.
"""

import pathlib
import re
import sys

import pytest

jinja2 = pytest.importorskip("jinja2", reason="jinja2 not installed")

ROOT = pathlib.Path(__file__).resolve().parents[1]


def render(**ctx):
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(ROOT / "templates")),
        undefined=jinja2.ChainableUndefined,
    )
    return env.get_template("atlas.html").render(**ctx)


def card_titles(html):
    """Every card's title, in page order.

    ⚠️ **`[^>]*` is not decoration.** Without it this matched only titles whose
    element carries no attributes, so the "Update log" card — whose title has an
    `id` so the poll can retitle it — was invisible to every card-order
    assertion in this file. Moving that card to the top changed nothing any test
    could see.
    """
    return re.findall(r'class="card-title"[^>]*>([^<]+)<', html)


def visible_cards(html):
    """The cards an operator can actually see, in page order.

    A card hidden by `hidden` or `display:none` is on the page and not on the
    screen, and "first card" is a claim about the screen.
    """
    out = []
    for match in re.finditer(r'<div class="card"([^>]*)>', html):
        attrs = match.group(1)
        rest = html[match.end():]
        title = re.search(r'class="card-title"[^>]*>([^<]+)<', rest)
        if not title:
            continue
        if ' hidden' in attrs or 'display:none' in attrs:
            continue
        out.append(title.group(1))
    return out


def attrs_of(html, element_id):
    """The attributes on an element, or None when it is not on the page."""
    found = re.search(r'id="%s"([^>]*)>' % element_id, html)
    return found.group(1).strip() if found else None


@pytest.fixture
def idle():
    return render(installed=False, deploy_log=[], deploy_running=False)


@pytest.fixture
def deploying():
    return render(installed=False, deploy_running=True,
                  deploy_log=["cloning", "building"])


@pytest.fixture
def installed():
    return render(installed=True, deploy_log=[], deploy_running=False)


# --------------------------------------------------------------------------- #
# Where the deploy log sits
# --------------------------------------------------------------------------- #


def test_the_deploy_log_is_the_first_card_an_operator_sees(deploying):
    """⚠️ It used to be last, below two cards of prose — so the one thing worth
    watching for five to ten minutes was off-screen when it started moving.

    Asserted against the *visible* cards: the update-log card sits above it in
    the markup and is hidden during a deploy, which is the whole arrangement.
    """
    assert visible_cards(deploying)[0] == "Deploy log"


def test_both_log_cards_sit_above_the_deployments(idle):
    """⚠️ The same reason, for the other long job. An update is minutes of build
    output; three cards down it was off screen at the moment it started, and the
    only sign anything was happening was a button that had stopped responding.
    """
    titles = card_titles(idle)

    assert titles.index("Update log") < titles.index("ATLAS deployments")
    assert titles.index("Deploy log") < titles.index("ATLAS deployments")


def test_the_update_log_card_starts_hidden(idle):
    """It is revealed by whichever poll writes to it, which also sets its title
    — so the card says which of update, update-all or removal it is showing."""
    assert "hidden" in (attrs_of(idle, "updateCard") or "")


def test_the_deploy_log_is_above_install(deploying):
    titles = card_titles(deploying)

    assert titles.index("Deploy log") < titles.index("Install")


def test_the_deploy_log_is_hidden_until_there_is_one(idle):
    assert 'style="display:none"' in attrs_of(idle, "deployCard")


def test_the_deploy_log_is_shown_while_deploying(deploying):
    assert attrs_of(deploying, "deployCard") == ""


# --------------------------------------------------------------------------- #
# The Install card standing down
# --------------------------------------------------------------------------- #


def test_install_is_offered_when_nothing_is_running(idle):
    assert attrs_of(idle, "installCard") == ""


def test_install_is_hidden_while_a_deploy_runs(deploying):
    """Nothing on it can be acted on: the button is disabled, the size is
    already committed, and the prose describes a decision made."""
    assert 'style="display:none"' in attrs_of(deploying, "installCard")


def test_install_is_not_on_the_page_at_all_once_installed(installed):
    assert attrs_of(installed, "installCard") is None


def function_body(js, name):
    """The text of one JS function, by brace matching from its opening `{`."""
    start = js.index("function %s(" % name)
    opened = js.index("{", start)
    depth = 0
    for i in range(opened, len(js)):
        if js[i] == "{":
            depth += 1
        elif js[i] == "}":
            depth -= 1
            if depth == 0:
                return js[opened:i + 1]
    raise AssertionError("unbalanced braces in %s" % name)


# ⚠️ **Three paths, asserted separately, because counting was not a check.**
# This was one test asserting `count("setInstallCard(true)") >= 2`. A mutation
# deleting the call from the refusal branch left two others behind and the test
# passed — a count is a proxy for the thing, and any hedge in an assertion is a
# hole in it. Each failure path is now named and checked where it lives.
#
# The reserved-storage field lives on the Install card, so a failure that hides
# it and leaves it hidden strands an operator with nothing left to act on.


def test_a_deploy_that_fails_midway_restores_the_install_card(idle):
    """The deploy started and then failed — the log is up, and retrying still
    needs the card."""
    failed = re.search(r"if \(d\.error && !d\.running\) \{(.*?)\n    \}",
                       function_body(idle, "pollDeploy"), re.S)

    assert failed, "pollDeploy has no failure branch"
    assert "setInstallCard(true)" in failed.group(1)


def test_the_failure_banner_points_at_the_log_s_new_position(idle):
    assert "see the log above" in idle
    assert "see the log below" not in idle


# --------------------------------------------------------------------------- #
# The note promising a refresh
# --------------------------------------------------------------------------- #

# ⚠️ **A promise the page has to keep.** `pollDeploy` reloads on
# `d.complete && !d.error` and on nothing else, so the note belongs to a
# *running* deploy only. Above a failed one it would send an operator off to
# wait for something that is never coming, instead of reading the error under
# it — which is worse than saying nothing at all.


def test_the_note_is_at_the_top_of_the_deploy_log_card(deploying):
    """Asked for at the top of the card: after the title, before the log.

    ⚠️ Asserted as an ordering rather than by matching the markup between the
    two. The first attempt looked for `</div>` immediately followed by the
    log-box and matched nothing, because the note and its comment sit in
    between — the regex encoded the layout it was supposed to be checking.
    """
    span = deploying[deploying.index('id="deployCard"'):
                     deploying.index('class="log-box" id="deployLog"')]

    assert "card-title" in span, "the card has no title"
    assert 'id="deployNote"' in span, "the note is not above the log"
    assert span.index("card-title") < span.index('id="deployNote"'), (
        "the note sits above the card's own title"
    )


def test_the_note_says_the_page_will_refresh(deploying):
    note = re.search(r'id="deployNote"[^>]*>(.*?)</p>', deploying, re.S)

    assert note, "there is no deploy note"
    text = " ".join(note.group(1).split())
    assert "refreshes itself" in text
    assert "deployed" in text


def test_the_note_is_shown_while_deploying(deploying):
    attrs = re.search(r'id="deployNote"(.*?)>', deploying, re.S).group(1)

    assert "display:none" not in attrs, "the note is hidden during a deploy"


def test_the_note_is_absent_when_no_deploy_is_running(idle):
    """⚠️ Including when the card itself is up showing a *finished* log."""
    attrs = re.search(r'id="deployNote"(.*?)>', idle, re.S).group(1)

    assert "display:none" in attrs


def test_the_page_really_does_reload_on_success(idle):
    """The note is only honest if this line exists. If the reload is ever
    removed, the note becomes a lie and this test is what says so."""
    body = function_body(idle, "pollDeploy")
    success = re.search(r"if \(d\.complete && !d\.error\) \{([^}]*)\}", body)

    assert success, "pollDeploy no longer has a success branch"
    assert "location.reload()" in success.group(1)


def test_a_failed_deploy_stops_promising_a_refresh(idle):
    failed = re.search(r"if \(d\.error && !d\.running\) \{(.*?)\n    \}",
                       function_body(idle, "pollDeploy"), re.S)

    assert failed, "pollDeploy has no failure branch"
    assert "setDeployNote(false)" in failed.group(1)


def test_an_accepted_deploy_puts_the_note_up(idle):
    body = function_body(idle, "startDeployFor")

    assert "setDeployNote(true)" in body, (
        "the note never appears for a deploy started from this page"
    )


# --------------------------------------------------------------------------- #
# The break-glass commands
# --------------------------------------------------------------------------- #


def test_the_break_glass_card_is_gone(installed):
    """Removed at the operator's request (W224).

    ⚠️ **It was already wrong.** Every command in it was hardcoded to
    `/root/atlas` and `takmdm-api-1` — the plain deployment. On a box whose
    deployments are `atlas-corona` and `atlas-test`, `sed` would have edited a
    file that does not exist and `docker logs` named a container that does not
    exist. Recovery instructions that fail silently are worse than none: they
    are read during an outage, by someone who then believes they have tried the
    fix.
    """
    assert "locked out of ATLAS" not in installed
    # ⚠️ The command blocks, not the whole page. `.cmd`'s own CSS comment
    # still recounts the `sed` bug as the reason the rule exists — which is
    # history worth keeping, and would make a page-wide search fail for the
    # wrong reason.
    blocks = re.findall(r'<div class="cmd"[^>]*>(.*?)</div>', installed, re.S)

    assert not [b for b in blocks if "sed -i" in b], blocks


def test_cmd_blocks_are_rendered_with_a_whitespace_preserving_rule(installed):
    """A newline in the source is only two lines on screen if the CSS says so.

    ⚠️ Still load-bearing after the break-glass card went: the capacity panel
    and the uninstall dialog's list of deployments are both `.cmd`, and both are
    several lines that mean nothing run together.
    """
    rule = re.search(r'\.cmd\{([^}]*)\}', installed)

    assert rule, ".cmd is not defined"
    assert "white-space:pre-wrap" in rule.group(1)


def test_cmd_blocks_are_not_given_a_log_sized_box(installed):
    """⚠️ The empty space in the screenshot: `.log-box` is `height:340px`,
    which is right for a stream and absurd for a three-line list.

    ⚠️ Anchored to a property boundary, because `"height:" not in rule` is
    satisfied by `line-height:1.55` — which it was, on the first run. Sixth
    time an assertion on this project has matched the wrong occurrence.
    """
    rule = re.search(r'\.cmd\{([^}]*)\}', installed).group(1)

    assert not re.search(r'(?:^|;)\s*height:', rule), (
        "a command block was given a fixed height"
    )


def test_no_static_command_still_uses_the_log_viewer(installed):
    """The four snippets were `.log-box`. If one comes back, the 340px box and
    the collapsed newline come back with it.

    ⚠️ Asked of the log-boxes rather than of the commands. Searching backwards
    from each command found the `sed -i` written *inside the CSS comment* that
    explains this very bug, where there is no enclosing element at all.
    """
    boxes = re.findall(r'<div[^>]*class="log-box"[^>]*>(.*?)</div>',
                       installed, re.S)

    for box in boxes:
        for snippet in ("sed -i", "docker logs --tail"):
            assert snippet not in box, f"{snippet!r} is back inside a log-box"


# --------------------------------------------------------------------------- #
# The streaming log, which had the same missing rule
# --------------------------------------------------------------------------- #


def test_the_streaming_log_preserves_its_newlines(idle):
    """⚠️ `renderLog` sets `textContent` to lines joined with a newline, so
    without this rule a running deploy rendered as one run-on paragraph — the
    same root cause as the commands, on the card an operator watches."""
    rule = re.search(r'\.log-box\{([^}]*)\}', idle)

    assert rule, ".log-box is not defined"
    assert "white-space:pre-wrap" in rule.group(1)


def test_the_streaming_log_keeps_a_stable_height(idle):
    """Deliberately fixed, unlike `.cmd`: the box exists before the first line
    arrives and must not resize under the operator as output lands."""
    rule = re.search(r'\.log-box\{([^}]*)\}', idle).group(1)

    assert "height:340px" in rule


# --------------------------------------------------------------------------- #
# Deployments: several ATLAS instances on one box (W216)
# --------------------------------------------------------------------------- #


def test_the_deployments_card_is_always_offered(installed):
    """The operator asked for it to be there always: *"there should always be an
    option on the infratak atlas page to 'Deploy additional instance'"*."""
    assert 'id="addInstanceBtn"' in installed
    assert 'Deploy additional instance' in installed


def test_one_card_lists_every_deployment(installed):
    """⚠️ One card for N instances, not N cards. `register()` runs only at
    console import, so a deployment created from this page would not exist as a
    module until a restart — and the button has to work without one."""
    assert installed.count('id="instancesCard"') == 1
    assert 'id="instanceList"' in installed


def test_both_sizing_modes_are_offered(installed):
    assert 'value="fixed"' in installed
    assert 'value="dynamic"' in installed


def test_the_capacity_panel_names_the_binding_constraint(installed):
    """⚠️ The panel's whole job beyond adding up. Disk 4, memory 12 — an
    operator shown only the larger number would plan for three times what
    fits."""
    body = function_body(installed, 'renderInstances')

    assert 'is the limit' in body
    assert 'c.binding' in body
    assert 'by_disk' in body and 'by_ram' in body


def test_the_capacity_panel_shows_the_protected_floor(installed):
    body = function_body(installed, 'renderInstances')

    assert 'floor_gb' in body


def test_capacity_is_fetched_live_rather_than_rendered_once(installed):
    """⚠️ Free space and memory move as the other modules grow. A figure baked
    in at page load would offer room that has since gone, and the operator would
    then be refused by a validator quoting a different number."""
    body = function_body(installed, 'refreshCapacity')

    assert "fetch('/api/atlas/instances" in body


def test_a_refused_deployment_shows_the_reason(installed):
    body = function_body(installed, 'createInstance')

    assert 'addInstanceError' in body
    assert 'd.error' in body


# --------------------------------------------------------------------------- #
# Choosing a deployment: type first, then slug (operator design, 2026-09-17)
# --------------------------------------------------------------------------- #


def test_the_type_is_asked_first_and_defaults_to_dynamic(installed):
    """⚠️ Dynamic is the default because it is the choice hardest to regret: it
    takes nothing from the box until the agency stores something. Neither the
    type nor the slug can be changed afterwards — `resize2fs` will not shrink a
    mounted filesystem, and a fixed store cannot become sparse once allocated."""
    assert 'value="dynamic" checked' in installed
    assert 'value="fixed"' in installed
    assert 'Deployment type' in installed


def test_only_fixed_is_asked_for_a_size(installed):
    """A dynamic deployment shares the pool, so there is no number to choose."""
    body = function_body(installed, 'onModeChanged')

    assert "getElementById('sizeField')" in body
    assert "isFixed ? '' : 'none'" in body


def test_dynamic_says_what_it_will_share(installed):
    body = function_body(installed, 'onModeChanged')

    assert 'pool_gb' in body
    assert 'shares the' in body


def test_fixed_still_warns_that_free_disk_drops(installed):
    """⚠️ The W205 warning, carried across rather than lost in the redesign."""
    span = installed[installed.index('id="sizeField"'):]

    assert 'Free disk drops by this much immediately' in span[:900]


def test_the_slug_field_says_blank_means_the_general_atlas(installed):
    """*"blank is no slug"* — and the field has to say so, because an empty box
    is exactly where an operator cannot infer it."""
    span = installed[installed.index('id="agencySlug"'):]

    assert 'Leave it blank' in span[:900]
    assert 'general ATLAS' in span[:900]
    assert 'Lowercase letters' in span[:900]
    # ⚠️ The field refuses the characters as typed, not only on submit.
    assert 'pattern="[a-z]*"' in span[:900]


def test_the_slug_is_shown_back_normalised(installed):
    """⚠️ Case is forced server-side, so echoing what was typed would promise a
    hostname that is not the one created."""
    assert 'toLowerCase()' in function_body(installed, 'typedSlug')
    body = function_body(installed, 'previewSlug')
    assert 'Will deploy as' in body


# ⚠️ **These assert the *conditions*, not the messages.** Written as
# `'already has a general ATLAS' in body`, three of them survived mutations that
# replaced the guard with `if (false)` — the message stayed in the source, so the
# assertion matched while the rule did nothing. Source-text assertions can only
# ever pin what the code *says*; pinning the condition is the closest they get to
# pinning what it does, and it is what kills that mutation.


def test_a_blank_slug_is_refused_once_a_general_atlas_exists(installed):
    """*"if instance with no slug already exists, reject submission with blank"*
    — refused before anything is recorded, so the operator is never left with a
    claimed slug and nothing built."""
    body = function_body(installed, 'addInstanceProblem')

    assert 'if (!slug && !mayPlain)' in body, 'the blank-slug rule is not enforced'
    assert 'already has a general ATLAS' in body


def test_a_slug_already_in_use_is_refused(installed):
    body = function_body(installed, 'addInstanceProblem')

    assert 'capacityState.slugs || []).indexOf(slug) !== -1' in body
    assert 'already a deployment for' in body


def test_a_fixed_deployment_without_a_size_is_refused(installed):
    body = function_body(installed, 'addInstanceProblem')

    assert "currentMode() === 'fixed'" in body
    assert "size.value === '' || Number(size.value) <= 0" in body
    assert 'Enter a size' in body


def test_the_button_is_gated_on_the_same_check_the_submit_uses(installed):
    """⚠️ One predicate for both, so the button cannot be enabled for something
    the submit would refuse."""
    gate = function_body(installed, 'refreshAddGate')

    assert 'const problem = addInstanceProblem();' in gate
    assert 'btn.disabled = problem !== null' in gate


def test_the_summary_modal_lists_every_choice(installed):
    """*"summary of selections should be shown on a modal for final approval"*."""
    body = function_body(installed, 'openInstanceConfirm')

    for field in ('agency', 'hostname', 'type', 'storage'):
        assert field in body, f'the summary does not mention {field}'
    assert 'instanceModal' in body


def test_the_modal_will_not_open_on_an_invalid_choice(installed):
    body = function_body(installed, 'openInstanceConfirm')

    assert 'addInstanceProblem() !== null' in body


def test_the_deploy_only_happens_after_approval(installed):
    """Nothing is recorded or built until the operator approves the summary."""
    confirm = function_body(installed, 'confirmCreateInstance')

    assert 'createInstance()' in confirm
    assert 'onclick="openInstanceConfirm()"' in installed


def test_the_request_carries_the_choices(installed):
    body = function_body(installed, 'createInstance')

    assert 'agency_specific: !!slug' in body
    assert "mode: mode" in body


# --------------------------------------------------------------------------- #
# Structure: the checks that would have caught a stacked page
# --------------------------------------------------------------------------- #

# ⚠️ **Every test above asserts that something is *present*. None of them
# noticed a page with the entire tail of a previous form left behind**, because
# the strings they look for were all still there — twice. The page rendered with
# an unbalanced `</div>`, so the cards stacked on top of one another, and with a
# second `sizeMode` radio group whose `fixed` was checked, so `querySelector`
# found the wrong one and the default was silently wrong.
#
# Presence is not structure. These three check the shape.


@pytest.mark.parametrize("state", ["idle", "deploying", "installed"])
def test_the_page_closes_every_element_it_opens(state, idle, deploying, installed):
    html = {"idle": idle, "deploying": deploying, "installed": installed}[state]

    opened = len(re.findall(r"<div[ >]", html))
    closed = len(re.findall(r"</div>", html))

    assert opened == closed, (
        f"{opened - closed:+d} unbalanced <div> — the cards will overlap"
    )


@pytest.mark.parametrize("state", ["idle", "deploying", "installed"])
def test_no_element_id_appears_twice(state, idle, deploying, installed):
    """⚠️ `getElementById` and `querySelector` return the *first* match, so a
    duplicated id does not fail — it quietly wires the page to the wrong
    control."""
    import collections

    html = {"idle": idle, "deploying": deploying, "installed": installed}[state]
    counts = collections.Counter(re.findall(r'id="([^"]+)"', html))
    repeated = sorted(i for i, n in counts.items() if n > 1)

    assert repeated == [], f"duplicated ids: {repeated}"


def test_exactly_one_sizing_mode_is_preselected(installed):
    """Two radio groups with the same name is how the default ends up being
    whichever fragment happens to come first in the document."""
    checked = re.findall(r'name="sizeMode" value="(\w+)" checked', installed)

    assert checked == ["dynamic"]


def test_the_button_does_not_offer_to_add_to_nothing(installed):
    """⚠️ "Deploy additional instance" on a box with none is a contradiction.

    The markup ships the empty-box wording so a fresh box reads correctly on
    first paint, and `renderInstances` corrects it once the count is known —
    rather than the other way round, which would flash the wrong word at exactly
    the operator who has never deployed anything.
    """
    button = installed[installed.index('id="addInstanceBtn"'):][:260]

    assert 'Deploy instance' in button
    assert 'Deploy additional instance' not in button


def test_the_wording_follows_the_count(installed):
    body = function_body(installed, 'renderInstances')

    assert "rows.length" in body
    assert "'Deploy additional instance'" in body
    assert "'Deploy instance'" in body


# --------------------------------------------------------------------------- #
# A deploy that never starts
# --------------------------------------------------------------------------- #


def test_both_failure_paths_go_through_one_handler(idle):
    """⚠️ The refusal and the network failure used to each restore the page
    themselves. One handler means they cannot drift into cleaning up
    differently — and only one of them was ever going to be exercised by hand."""
    body = function_body(idle, 'startDeployFor')

    assert body.count('deployRefused(') == 2


def test_a_refused_deploy_puts_the_operator_back_where_they_were(idle):
    body = function_body(idle, 'deployRefused')

    assert 'setInstallCard(true)' in body
    assert 'setDeployNote(false)' in body
    assert "form.hidden = false" in body, 'the form is not reopened to correct'


def test_a_refused_deploy_shows_the_reason_on_the_page(idle):
    """An `alert()` is dismissed and gone; the reason belongs beside the field
    that has to change."""
    body = function_body(idle, 'deployRefused')

    assert 'addInstanceError' in body
    assert 'alert(' not in body


def test_a_refused_deploy_releases_the_slug(idle):
    """⚠️ **The bug this came from.** The instance record is written before the
    deploy so the slug and port are held while it runs. When the deploy was
    refused, that record was the only trace — and a retry under the same name
    was then refused as a duplicate, with nothing built and no way forward from
    the page."""
    body = function_body(idle, 'deployRefused')

    assert '/forget' in body
    assert 'inst.slug' in body


def test_the_deploy_log_appears_when_the_deploy_starts(idle):
    """⚠️ It used to be revealed only by `renderLog`, on the first poll — so a
    deploy refused before that never showed the card at all, and the page looked
    like nothing had happened."""
    body = function_body(idle, 'startDeployFor')

    assert 'showDeployCard()' in body
    reveal = function_body(idle, 'showDeployCard')
    assert "getElementById('deployCard')" in reveal
    assert "style.display = ''" in reveal


# --------------------------------------------------------------------------- #
# When the deploy log card stands down (2026-09-18)
# --------------------------------------------------------------------------- #
#
# ⚠️ **The condition was `deploy_log`**, which is the registry's job log and
# stays populated until the *next* deploy starts. So a successful deployment
# left its own log pinned to the top of the page through every refresh, above
# the deployment it had just created. Operator: *"the logs are still on the
# screen, even after refresh"*.


def test_the_log_card_is_up_while_a_deploy_runs():
    html = render(installed=False, deploy_log=['[03:14] Step 1/7'],
                  deploy_running=True, deploy_error=False)

    assert 'display:none' not in (attrs_of(html, 'deployCard') or '')


def test_the_log_card_stays_up_after_a_failure():
    """⚠️ Deliberately. That log is the only account of what went wrong, and it
    has to survive the refresh an operator reaches for first."""
    html = render(installed=False, deploy_log=['[03:14] ERROR: boom'],
                  deploy_running=False, deploy_error=True)

    assert 'display:none' not in (attrs_of(html, 'deployCard') or '')


def test_the_log_card_steps_aside_after_a_deploy_that_worked():
    html = render(installed=True, deploy_log=['[03:14] ✓ ATLAS deployed.'],
                  deploy_running=False, deploy_error=False)

    assert 'display:none' in (attrs_of(html, 'deployCard') or '')


def test_a_box_that_has_never_deployed_shows_no_log_card():
    html = render(installed=False, deploy_log=[], deploy_running=False,
                  deploy_error=False)

    assert 'display:none' in (attrs_of(html, 'deployCard') or '')


# --------------------------------------------------------------------------- #
# The removal dialog's busy state (W218)
# --------------------------------------------------------------------------- #
#
# ⚠️ A teardown is a `docker compose down -v`, three unmounts, a loop device and
# an `rmtree` over a store — a minute or more. The dialog used to close on click
# and leave the log to appear in a card further down the page, so the only
# honest reading of the moment after the click was that it had missed. Operator:
# *"i want the modal to show a removing placeholder that will dismiss when the
# removal is complete"*.


def test_the_removal_dialog_ships_a_busy_state(idle):
    assert attrs_of(idle, "removeBusy") is not None
    assert attrs_of(idle, "removeBusyText") is not None


def test_it_starts_hidden(idle):
    """The prompt is what an operator sees first; the spinner replaces it only
    once they have committed."""
    assert "hidden" in (attrs_of(idle, "removeBusy") or "")


def test_the_prompt_is_a_block_that_can_stand_down(idle):
    """⚠️ Hiding the field and the buttons *together* is what keeps a Cancel
    button from sitting beside a running teardown — there is nothing to go back
    to once `down -v` has run."""
    assert attrs_of(idle, "removeAsk") is not None


def test_the_steps_land_in_the_dialog_not_in_the_update_card(idle):
    """⚠️ The update-log card is for updates. A teardown shown under "update
    log" is how somebody comes to believe a deployment was updated when it was
    destroyed."""
    assert attrs_of(idle, "removeSteps") is not None
    assert "log-box" in (attrs_of(idle, "removeSteps") or "")


def test_it_promises_the_reload_it_performs(idle):
    """⚠️ The dialog says the page reloads itself, and `pollRemove` is what
    makes that true. A promise the code does not keep is how an operator comes
    to sit waiting on a dialog that has finished."""
    assert "reloads itself when it is done" in idle
    assert "location.reload()" in idle


def test_the_spinner_is_the_one_the_uninstall_dialog_uses(idle):
    """The operator asked for the pattern they already know. A second spinner
    with its own markup would drift from it."""
    busy = idle[idle.index('id="removeBusy"'):][:600]

    assert 'class="spinner-row"' in busy
    assert 'class="spinner"' in busy


def _js_function(html, name):
    """The body of one top-level page function.

    ⚠️ Used only for the thin `.then` bodies the node harness cannot execute —
    the polling wiring, not the decisions. `renderRemoval` exists precisely so
    that everything worth asserting is reachable behaviourally; these two cover
    what is left, and both were mutations that survived.
    """
    start = html.index("function %s(" % name)
    end = html.index(chr(10) + "}" + chr(10), start)
    return html[start:end]


def test_the_removal_dialog_is_not_closed_on_click(idle):
    """⚠️ The operator's complaint, in one assertion. `doRemove` used to close
    the dialog and leave the log to appear in a card further down the page, so
    the moment after the click looked exactly like a click that had missed."""
    body = _js_function(idle, "doRemove")

    assert "closeRemove(" not in body, \
        "doRemove closes the dialog it is supposed to keep open"


def test_a_finished_removal_reloads_the_page(idle):
    """⚠️ The dialog promises it — *"this page reloads itself when it is
    done"* — and a promise the code does not keep leaves an operator waiting on
    a dialog that has finished."""
    body = _js_function(idle, "pollRemove")
    done = body[body.index("'done'"):]

    assert "location.reload()" in done, done[:200]


def test_the_agency_name_field_has_no_placeholder(idle):
    """⚠️ Operator decision, 2026-09-18. A greyed-out example in an agency-name
    field reads as a value that is already there — and a field that is optional
    *and* looks filled in is one an operator walks past. The prose below it says
    what it is for."""
    field = attrs_of(idle, "agencyName")

    assert field is not None
    assert "placeholder" not in field, field


# --------------------------------------------------------------------------- #
# What uninstall actually removes (W223)
# --------------------------------------------------------------------------- #
#
# ⚠️ It removes **every** deployment — `uninstall` iterates `load_instances` and
# runs the full teardown on each. The dialog's prose said otherwise: "the
# database volume", "the device CA", "the ATLAS application", all singular,
# written when a box ran one ATLAS. Operator asked what the button did, which is
# the clearest evidence the wording was not carrying it.


def test_the_uninstall_dialog_says_every_deployment(idle):
    modal = idle[idle.index('id="uninstallModal"'):][:1800]

    assert "every deployment on this box" in modal, modal[:400]


def test_it_warns_about_every_certificate_authority_not_one(idle):
    """⚠️ Each deployment has its own CA and its own fleet. "the device CA"
    understates the blast radius by however many agencies the box runs."""
    modal = idle[idle.index('id="uninstallModal"'):][:1800]

    assert "every device CA and every database" in modal, modal[:600]


def test_it_has_somewhere_to_list_them(idle):
    assert attrs_of(idle, "uninstallScope") is not None
    assert "hidden" in (attrs_of(idle, "uninstallScope") or "")


def test_it_points_at_the_per_deployment_alternative(idle):
    """An operator who wanted to remove one agency should not discover that by
    removing all of them."""
    assert attrs_of(idle, "uninstallOneInstead") is not None
    assert "leave the others running" in idle


def test_the_module_really_does_remove_them_all():
    """⚠️ The prose is only worth fixing if it is true. Asserted against the
    function, so a change to either has to face the other."""
    source = (ROOT / "modules" / "atlas.py").read_text(encoding="utf-8")
    start = source.index(chr(10) + "def uninstall(")
    end = source.index(chr(10) + "def ", start + 1)
    body = source[start:end]

    assert "for inst in found:" in body
    assert "remove_instance(ctx, inst)" in body


# --------------------------------------------------------------------------- #
# The renewal takes the key file, not a paste (W236)
# --------------------------------------------------------------------------- #


def _page():
    return (ROOT / "templates" / "atlas.html").read_text(encoding="utf-8")


def test_the_renewal_offers_a_file_picker():
    """⚠️ The operator has the root key as a *file* -- "Save ... recovery
    file" downloaded it. Asking them to open it in an editor and paste the
    PEM was friction at the one moment they are handling the most dangerous
    secret in the system."""
    page = _page()

    assert 'id="renewKeyFile"' in page
    assert 'type="file"' in page.split('id="renewKeyFile"')[0].rsplit("<input", 1)[-1] \
        or 'type="file" id="renewKeyFile"' in page


def test_the_renewal_accepts_the_same_kinds_of_file_as_the_recovery_check():
    """⚠️ One page, one answer. A picker that accepted something different
    from the modal two steps away would be a trap dressed as a convenience."""
    page = _page()
    accepts = re.findall(r'<input type="file"[^>]*accept="([^"]*)"', page)

    assert len(accepts) == 2, accepts
    assert accepts[0] == accepts[1], accepts


def test_the_pasted_key_box_is_gone():
    """⚠️ Replaced, not supplemented -- the operator asked for the upload
    *instead*, and the recovery-check modal has been file-only without
    complaint. A root key held in a password manager would have to be saved
    to a file first; that is the trade, and it is recorded in
    PROJECT_STATE."""
    page = _page()

    assert 'id="renewKey"' not in page, "the textarea is still there"


def test_choosing_nothing_still_means_use_the_key_on_the_server():
    """⚠️ **The normal path**, and the one W235 had just restored -- the
    console can finally see a root key that is already there. A picker that
    demanded a file would undo that. Asserted on the prose the operator
    reads; the behaviour itself is driven by the node harness below."""
    page = _page()

    assert "Choose nothing if the root key is still on this server" in page


def test_the_renewal_upload_behaves():
    """⚠️ Driven, not matched.

    The template will contain `type="file"` and `.text()` whether or not the
    bytes ever reach the request body, and the behaviour that matters most
    is a *negative*: no file chosen must still send an empty `root_key`.
    A string search cannot see that at all, which is the same reason
    `check_deploy_gate.js` and `check_channel_card.js` exist.
    """
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip(
            "no node on PATH, so the renewal modal is unexercised. The rest of "
            "this module only checks the markup is present."
        )

    result = subprocess.run(
        [node, str(ROOT / "scripts" / "check_renew_upload.js")],
        cwd=str(ROOT), capture_output=True, text=True, timeout=120,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 0, output
    assert "all renewal-upload checks passed" in output, output


# --------------------------------------------------------------------------- #
# The removal dialog asks for the password the route demands (W247)
# --------------------------------------------------------------------------- #


def test_the_removal_dialog_has_a_password_field():
    """⚠️ **The route and the page disagreed, and only the operator
    found out.** `instance_remove_view` requires the console password; this
    dialog collected only the typed slug, so every teardown came back
    "invalid admin password" with no field to supply one in.

    ⚠️ Asserted on the markup, not through the node harness: that
    harness auto-creates any element it is asked for, so renaming this field
    passes there while the real page has nowhere to type. A mutation doing
    exactly that survived the harness.
    """
    page = (ROOT / "templates" / "atlas.html").read_text(encoding="utf-8")
    start = page.index('id="instanceRemoveModal"')
    modal = page[start:page.index("</div>" + chr(10) + "</div>", start)]

    assert 'id="removePw"' in modal, 'no password field in the removal dialog'
    assert 'type="password"' in modal


def test_the_removal_dialog_matches_the_other_destructive_ones():
    """⚠️ One page, one wording. Uninstall and the three CA dialogs have
    always asked for the "Console password"; a fourth that asked differently
    would read as a different kind of secret."""
    page = (ROOT / "templates" / "atlas.html").read_text(encoding="utf-8")
    start = page.index('id="instanceRemoveModal"')
    modal = page[start:page.index("</div>" + chr(10) + "</div>", start)]

    assert "Console password" in modal


def test_the_removal_password_is_cleared_once_it_is_sent():
    """⚠️ The dialog stays open for the length of a teardown — a minute
    or more — and leaving the console password in the DOM for that long is
    gratuitous.

    ⚠️ **A source guard, and it is second choice.** The node harness
    would be better, but its `fetch` double resolves on a microtask and the
    harness prints its summary synchronously, so a check placed after the
    response runs *after* the exit code is decided and can never fail. A
    test that cannot fail is worse than a source assertion that can.
    """
    page = (ROOT / "templates" / "atlas.html").read_text(encoding="utf-8")
    start = page.index("function doRemove(")
    body = page[start:page.index("function renderRemoval(", start)]

    # ⚠️ The *statement*, not the substring. `if (false) pw.value = ''`
    # still contains the text, and a mutation doing exactly that survived
    # the first version of this guard.
    assert "if (pw) pw.value = ''" in body, (
        "the console password is left in the DOM after the removal is sent")
