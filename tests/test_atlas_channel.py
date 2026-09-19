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
"""Which branch of the mirror a box takes updates from (W228).

Operator, 2026-09-18: a `dev` branch carries forward work, `main` carries what
has been tested, and the ATLAS card picks between them.

⚠️ **The fact the whole feature turns on: `_latest_version` used to read the
GitHub *tags* API.** Tags are branch-independent, so reverting `main` would
have changed nothing at all — every box would still have been offered the
newest tag in the repository whichever channel it followed, and "stable" would
have been a word on a card with nothing behind it. A channel is therefore
`VERSION` at that branch tip.

⚠️ **Tag reachability is not an alternative and cannot become one.** The mirror
publishes one *orphan* commit per release — `git log` shows a single commit and
every tag is an island — so no tag is reachable from any branch except the one
pointing directly at it. A future refactor reaching for `--merged` here would
resolve nothing on both channels and report "no update" forever.

⚠️ **Only the resolution is per-channel; the fetch is not.** `_run_update`
still fetches and checks out `v<version>`, and that tag exists whichever branch
points at it. Tests below pin that down, because moving the fetch to a branch
would silently give up `--depth=1` tag immutability.
"""

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from atlas_pin import PROMOTED, PROMOTED_SHA  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402


PAGE = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')
MODULE = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')


@pytest.fixture(autouse=True)
def clean_cache():
    """⚠️ The version cache is module state and lives for the process. Without
    this, the first test to reach GitHub decides every later test's answer."""
    atlas._latest_cache.clear()
    yield
    atlas._latest_cache.clear()


@pytest.fixture
def offers(monkeypatch):
    """Make each channel offer a stated version, without touching the network."""

    def _set(**by_channel):
        def fake(use_cache=True, channel=None):
            return by_channel.get(channel or atlas.DEFAULT_CHANNEL)

        monkeypatch.setattr(atlas, '_latest_version', fake)

    return _set


class Probe:
    returncode = 0
    stdout = ''
    stderr = ''


def box(settings=None):
    saved = dict(settings or {})
    return {'load_settings': lambda: dict(saved),
            'save_settings': lambda s: saved.update(s)}, saved


# --------------------------------------------------------------------------- #
# Reading the setting
# --------------------------------------------------------------------------- #


def test_a_box_that_has_never_chosen_follows_stable():
    """⚠️ The default has to be `main`. A box upgraded into this feature has no
    setting at all, and defaulting to `dev` would move every existing
    deployment onto untested releases on the strength of a module update
    nobody asked for."""
    assert atlas._channel_of(settings={}) == 'main'
    assert atlas.DEFAULT_CHANNEL == 'main'


def test_the_chosen_channel_is_read_back():
    assert atlas._channel_of(settings={'atlas_channel': 'dev'}) == 'dev'


def test_case_and_whitespace_do_not_change_the_answer():
    """The value is a plain string in a settings file an operator can edit."""
    assert atlas._channel_of(settings={'atlas_channel': ' DEV\n'}) == 'dev'


@pytest.mark.parametrize('value', ['garbage', '', None, 'MAIN/../dev', 'origin/dev'])
def test_an_unrecognised_channel_reads_as_stable(value):
    """⚠️ **Not as itself.** This string is pasted into a GitHub URL as a ref.
    A typo, or a channel a newer module knew about, must not become a branch
    name the request goes looking for — and stable is the safe reading of
    "I do not understand what this box asked for"."""
    assert atlas._channel_of(settings={'atlas_channel': value}) == 'main'


def test_a_settings_read_that_throws_does_not_take_the_page_down():
    """A box whose settings file is briefly unreadable still renders."""
    class Angry(dict):
        def __getitem__(self, key):
            raise RuntimeError('settings unavailable')

    assert atlas._channel_of(Angry()) == 'main'


# --------------------------------------------------------------------------- #
# Resolving what a channel offers
# --------------------------------------------------------------------------- #


def _urlopen_returning(body, recorder=None):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return body.encode('utf-8')

    def fake(request, timeout=None):
        if recorder is not None:
            recorder.append(request.full_url)
        return Response()

    return fake


def test_the_version_is_read_from_the_branch_not_from_the_tag_list(monkeypatch):
    """⚠️ The guard on the whole design. `/tags` is branch-blind, so a module
    that went back to it would offer `dev`'s release to a box on `main` and the
    switch would be decoration."""
    seen = []
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen',
                        _urlopen_returning('1.49.0\n', seen))

    atlas._latest_version(use_cache=False, channel='main')

    assert seen, 'nothing was requested'
    assert '/contents/VERSION' in seen[0]
    assert 'ref=main' in seen[0]
    assert '/tags' not in seen[0]


def test_each_channel_asks_for_its_own_branch(monkeypatch):
    seen = []
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen',
                        _urlopen_returning('1.50.0', seen))

    atlas._latest_version(use_cache=False, channel='dev')

    assert 'ref=dev' in seen[0]


def test_a_json_envelope_is_decoded_rather_than_parsed_as_a_version(monkeypatch):
    """⚠️ The raw media type is a request, not a guarantee — a proxy that
    rewrites Accept answers with the envelope. Without this the version string
    would be `{"name":"VERSION"...`, which `_parse_version` rejects, and the
    box would report "unknown" forever with nothing to explain it."""
    import base64
    import urllib.request
    envelope = json.dumps(
        {'name': 'VERSION',
         'content': base64.b64encode(b'1.50.0\n').decode(),
         'encoding': 'base64'})
    monkeypatch.setattr(urllib.request, 'urlopen', _urlopen_returning(envelope))

    assert atlas._latest_version(use_cache=False, channel='dev') == '1.50.0'


def test_a_branch_that_does_not_exist_is_unknown_not_up_to_date(monkeypatch):
    """⚠️ A 404 is what a mirror with no `dev` branch answers. None means
    *unknown*; reporting "no update available" would leave a box a release
    behind with a page that looks perfectly healthy."""
    import urllib.request

    def boom(request, timeout=None):
        raise OSError('HTTP Error 404: Not Found')

    monkeypatch.setattr(urllib.request, 'urlopen', boom)

    assert atlas._latest_version(use_cache=False, channel='dev') is None


def test_a_body_that_is_not_a_version_is_unknown(monkeypatch):
    """An HTML error page served by a proxy must not become a version."""
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen',
                        _urlopen_returning('<html>rate limited</html>'))

    assert atlas._latest_version(use_cache=False, channel='main') is None


def test_the_cache_is_per_channel(monkeypatch):
    """⚠️ One shared slot would serve `dev`'s number to a box that had just
    switched to `main`, for up to fifteen minutes — an update badge offering a
    release that channel does not carry, which is exactly the confusion the
    switch exists to remove."""
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen', _urlopen_returning('1.50.0'))
    atlas._latest_version(use_cache=False, channel='dev')

    monkeypatch.setattr(urllib.request, 'urlopen', _urlopen_returning('1.49.0'))
    atlas._latest_version(use_cache=False, channel='main')

    assert atlas._latest_cache['dev']['value'] == '1.50.0'
    assert atlas._latest_cache['main']['value'] == '1.49.0'


def test_a_cached_channel_is_not_re_fetched(monkeypatch):
    calls = []
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen',
                        _urlopen_returning('1.49.0', calls))

    atlas._latest_version(use_cache=True, channel='main')
    atlas._latest_version(use_cache=True, channel='main')

    assert len(calls) == 1, 'the 60-per-hour allowance is the reason for the cache'


def test_an_unknown_channel_resolves_stable_rather_than_requesting_it(monkeypatch):
    """Defence in depth behind `_channel_of`: even called directly, a junk
    channel never reaches the URL."""
    seen = []
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen',
                        _urlopen_returning('1.49.0', seen))

    atlas._latest_version(use_cache=False, channel='../../etc/passwd')

    assert 'ref=main' in seen[0]


# --------------------------------------------------------------------------- #
# Every caller follows the box's channel
# --------------------------------------------------------------------------- #


def test_no_caller_asks_without_a_channel():
    """⚠️ A single caller left on the default would quietly pin one surface of
    the page to stable — the update badge, say, disagreeing with the drift
    table on the same screen."""
    import re

    calls = re.findall(r'_latest_version\(([^)]*)\)', MODULE)
    # The definition itself is `use_cache=True, channel=None`; every other
    # occurrence is a call and must name a channel.
    calls = [c for c in calls if 'channel=None' not in c]

    assert calls, 'the regex matched nothing; this guard is not guarding'
    for call in calls:
        assert 'channel=' in call, f'_latest_version({call}) does not pass a channel'


@pytest.fixture
def asked(monkeypatch):
    """Record the channel each caller actually asks for.

    ⚠️ **The textual guard above is not enough on its own.** Thirteen
    existing test doubles were widened to accept `channel` when this landed,
    and every one of them ignores it — so those suites would stay green if a
    caller passed the wrong channel, or a constant. These drive the real
    functions and read back what they asked.
    """
    seen = []

    def fake(use_cache=True, channel=None):
        seen.append(channel)
        return '1.49.0'

    monkeypatch.setattr(atlas, '_latest_version', fake)
    return seen


@pytest.fixture
def one_box(monkeypatch, tmp_path):
    """A box with one built deployment, and a settable channel."""
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, 'compose_projects_present',
                        lambda c=None: {'takmdm-corona'})
    monkeypatch.setattr(atlas, 'capacity_facts',
                        lambda c, size_gb=None: {'budget_gb': 353.2})
    d = tmp_path / 'atlas' / 'corona'
    d.mkdir(parents=True, exist_ok=True)
    (d / 'VERSION').write_text('1.47.3', encoding='utf-8')

    def _make(channel):
        settings = {'atlas_enabled': True,
                    atlas.CHANNEL_KEY: channel,
                    ai.INSTANCES_KEY: [
                        ai.make('corona', ai.MODE_DYNAMIC, 354.6, 8760)]}
        return {'load_settings': lambda: dict(settings),
                'probe_run': lambda argv, **k: Probe()}

    return _make


@pytest.mark.parametrize('channel', ['main', 'dev'])
def test_the_deployments_route_asks_for_the_boxs_channel(asked, one_box, channel):
    """The update badge every row carries."""
    atlas.instances_payload(one_box(channel))

    assert asked == [channel]


@pytest.mark.parametrize('channel', ['main', 'dev'])
def test_the_drift_table_asks_for_the_boxs_channel(asked, one_box, channel):
    """⚠️ On the same screen as the badge. Two surfaces disagreeing about
    which release is available is worse than either being wrong alone."""
    result = atlas.version_drift(one_box(channel))

    assert asked == [channel]
    assert result['channel'] == channel


def test_the_deployments_route_still_asks_only_once(asked, one_box):
    """⚠️ Unchanged by the channel work, and worth re-stating: it is a GitHub
    call behind a cache and the allowance is 60 an hour per IP. A box with five
    agencies polling this route would spend it on one page."""
    atlas.instances_payload(one_box('dev'))

    assert len(asked) == 1


def test_the_update_runner_targets_the_channel_the_box_follows(monkeypatch, offers):
    """The one that actually moves a deployment."""
    offers(main='1.49.0', dev='1.50.0')
    ctx, _ = box({'atlas_channel': 'dev'})

    assert atlas._channel_of(ctx) == 'dev'
    assert atlas._latest_version(channel=atlas._channel_of(ctx)) == '1.50.0'


def test_the_fetch_is_still_by_tag_not_by_branch():
    """⚠️ The channel decides *which version*; it must never decide what is
    fetched. A branch fetch would give up the tag immutability that
    `--depth=1 origin <tag>` relies on, and a box could be moved by someone
    force-pushing a branch."""
    runner = MODULE[MODULE.index('def _run_update(') :
                    MODULE.index('def _run_update_all(')]

    assert "'fetch', '--tags', '--depth=1', 'origin', tag" in runner
    assert "tag = 'v' + target" in runner
    assert 'origin', 'the fetch must still name a tag'
    for branchy in ("origin', channel", 'origin/dev', 'origin/main'):
        assert branchy not in runner, branchy


# --------------------------------------------------------------------------- #
# Not going backwards
# --------------------------------------------------------------------------- #


@pytest.fixture
def runner(monkeypatch, tmp_path):
    """`_run_update` with everything past the version comparison made loud.

    ⚠️ **Driven, not grepped.** The first version of these two tests searched
    the function's source for `there < here` and for the word "Refusing", which
    a mutation replacing the branch with `if False:` would have left untouched
    in the very same source. Git and compose are replaced with things that
    raise, so reaching them at all is a failure with a name.
    """
    d = tmp_path / 'atlas'
    d.mkdir(parents=True, exist_ok=True)
    (d / '.git').mkdir(exist_ok=True)

    def forbidden(*a, **k):
        raise AssertionError('the update ran past the version check')

    monkeypatch.setattr(atlas, '_module_git', forbidden, raising=False)
    monkeypatch.setattr(atlas, '_compose', forbidden)
    monkeypatch.setattr(atlas, '_write_build_file', forbidden)
    monkeypatch.setattr(atlas, 'deployment_identity',
                        lambda c, i, s: {'name': 'corona',
                                         'dir': str(d).replace(chr(92), '/'),
                                         'settings_prefix': 'atlas_',
                                         'compose_project': 'takmdm'})

    def _run(installed, channel, offers):
        monkeypatch.setattr(atlas, '_installed_version', lambda c, i=None: installed)
        monkeypatch.setattr(atlas, '_latest_version',
                            lambda use_cache=True, channel=None: offers.get(channel))
        ctx, _ = box({atlas.CHANNEL_KEY: channel})
        slot = atlas._update_slot(None)
        slot.clear()
        atlas._run_update(ctx, None)
        return slot

    return _run


def test_a_deployment_newer_than_its_channel_is_not_downgraded(runner):
    """⚠️ Switching from `dev` to `main`, or withdrawing a release by moving
    `main` back, leaves a deployment ahead of its channel. Running older code
    against a database a newer release has already migrated is data loss, so
    the way back is a forward fix — never this button."""
    slot = runner('1.50.0', 'main', {'main': '1.49.0', 'dev': '1.50.0'})

    log = chr(10).join(slot['log'])
    assert 'Refusing to downgrade' in log, log
    assert '1.49.0' in log and '1.50.0' in log
    assert slot['error'] is False, 'a refusal is not a failure to report'
    assert slot['complete'] is True


def test_the_refusal_explains_itself_rather_than_looking_like_a_no_op(runner):
    """A button that appears to have done nothing is a button an operator
    presses again."""
    slot = runner('1.50.0', 'main', {'main': '1.49.0'})

    log = chr(10).join(slot['log'])
    assert 'migrated' in log, log
    assert 'Already on the newest release' not in log, log


def test_a_deployment_level_with_its_channel_is_a_plain_no_op(runner):
    """The ordinary case must not be dressed up as a refusal."""
    slot = runner('1.49.0', 'main', {'main': '1.49.0'})

    log = chr(10).join(slot['log'])
    assert 'Already on the newest release' in log, log
    assert 'Refusing' not in log
    assert slot['error'] is False


def test_a_box_on_dev_is_offered_the_dev_release(runner):
    """The forward case, and the reason the switch exists.

    Asserted on the log rather than on reaching a booby-trapped git: the fetch
    goes through `ctx['_module_git']`, not the module attribute, so it fails
    on its own the moment it is reached. What matters is *which tag* the runner
    decided on before it got there.
    """
    slot = runner('1.49.0', 'dev', {'main': '1.49.0', 'dev': '1.50.0'})

    log = chr(10).join(slot['log'])
    assert 'dev offers 1.50.0' in log, log
    # ⚠️ A tag, not a branch. The channel picks the number; the fetch is
    # still `v<version>`, which is what keeps it immutable.
    assert 'Fetching v1.50.0' in log, log


def test_a_box_on_main_is_not_offered_the_dev_release(runner):
    """The same box, the other channel: nothing to do, and no fetch."""
    slot = runner('1.49.0', 'main', {'main': '1.49.0', 'dev': '1.50.0'})

    assert 'Already on the newest release' in chr(10).join(slot['log'])


def test_a_channel_that_cannot_be_read_is_an_error_not_a_silent_success(runner):
    """⚠️ None means unknown. Treating it as "up to date" would leave a box a
    release behind with an update log that claimed success."""
    slot = runner('1.49.0', 'dev', {'main': '1.49.0'})   # dev resolves to None

    log = chr(10).join(slot['log'])
    assert slot['error'] is True, log
    assert 'dev' in log


# --------------------------------------------------------------------------- #
# The setting belongs to the box
# --------------------------------------------------------------------------- #


def test_the_channel_survives_removing_one_deployment():
    """⚠️ In `BOX_SETTINGS_KEYS`, so a per-deployment teardown cannot sweep it.
    Taken with one agency, the remaining ones would fall back to `main` and
    stop being offered the release they are actually running — which reads as
    "no update available" on a box mid-rollout."""
    assert atlas.CHANNEL_KEY in ai.BOX_SETTINGS_KEYS

    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    keys = ['atlas_channel', 'atlas_corona_port', 'atlas_corona_size_gb']

    owned = ai.owned_settings_keys(inst, keys, instances=[inst])

    assert 'atlas_channel' not in owned


def test_the_plain_deployment_cannot_take_it_either():
    """`atlas_` is a prefix of `atlas_channel`, which is exactly the trap
    `owned_settings_keys` was written for."""
    plain = ai.make(None, ai.MODE_DYNAMIC, 50, 8760)

    owned = ai.owned_settings_keys(plain, ['atlas_channel', 'atlas_port'],
                                   instances=[plain])

    assert 'atlas_channel' not in owned
    assert 'atlas_port' in owned


# --------------------------------------------------------------------------- #
# The card
# --------------------------------------------------------------------------- #


def test_the_page_has_a_channel_card_above_the_deployments():
    """Operator asked for it at the top. The update and deploy logs sit above
    it and are hidden when idle, so this is the first card on a quiet box."""
    assert PAGE.index('id="channelCard"') < PAGE.index('id="instancesCard"')


def test_the_card_renders_a_button_per_channel_from_the_route():
    """Not a hardcoded pair. A third channel added server-side must appear
    without a template change, or the two would drift."""
    assert "for (const c of (d.channels || []))" in PAGE


def test_the_card_shows_what_each_channel_offers():
    """The decision is between two numbers, not two words."""
    assert "'offers ' + c.version" in PAGE


def test_an_unresolvable_channel_says_so_rather_than_looking_current():
    assert 'could not ask GitHub' in PAGE


def test_the_card_warns_where_a_deployment_is_already_ahead():
    """⚠️ On the button itself. Update refuses to move a deployment backwards,
    so on that channel the button would do nothing and look broken."""
    assert 'Already newer than this channel' in PAGE
    assert 'will not move' in PAGE


def test_the_card_says_a_fresh_install_ignores_the_channel():
    """⚠️ The one place the channel does not apply. A dev-channel operator
    deploying a new agency gets the pinned release and an immediate update
    prompt; unexplained, that reads as a bug."""
    assert 'A new deployment always installs' in PAGE


class _Flask:
    """A flask stand-in for the duration of one call.

    ⚠️ **Stubbed rather than asserted as text.** `register()` imports flask
    when it runs and the console supplies it on the box; nothing here does.
    Grepping the source for a URL would pass just as happily on a route defined
    inside an `if False:` — this runs the function that builds the table and,
    below, the view itself.
    """

    def __init__(self, body=None):
        self.body = body or {}
        self.status = None
        self.payload = None

    def __enter__(self):
        import types

        module = types.ModuleType('flask')
        module.jsonify = self._jsonify
        module.request = types.SimpleNamespace(
            get_json=lambda silent=False: dict(self.body), args={}, form={})
        self._saved = sys.modules.get('flask')
        sys.modules['flask'] = module
        return self

    def __exit__(self, *a):
        if self._saved is None:
            sys.modules.pop('flask', None)
        else:
            sys.modules['flask'] = self._saved
        return False

    def _jsonify(self, payload):
        self.payload = payload
        return payload


def _register(ctx=None):
    """Build the spec. ⚠️ A flask stub must already be installed.

    `register()` does `from flask import jsonify, request` **when it runs**, so
    each view closes over whichever stub was in place at that moment. Calling a
    view inside a *different* stub therefore records nothing — which is how
    three tests here first passed their assertions into a stub nobody read.
    Registration and invocation share one [_Flask].
    """
    captured = {}
    original = atlas.register_module
    ctx = ctx if ctx is not None else {
        'load_settings': lambda: {}, 'save_settings': lambda s: None}
    try:
        atlas.register_module = lambda spec: captured.update(spec)
        atlas.register(ctx)
    finally:
        atlas.register_module = original
    return captured


def _registered_spec(ctx=None):
    with _Flask():
        return _register(ctx)


def _view(spec, url_suffix, method):
    return next(r['view'] for r in spec['extra_routes']
                if r['url'].endswith(url_suffix) and r['methods'] == [method])


def test_the_routes_are_registered():
    urls = {(r['url'], tuple(r['methods']))
            for r in _registered_spec()['extra_routes']}

    assert ('/api/atlas/channel', ('GET',)) in urls
    assert ('/api/atlas/channel', ('POST',)) in urls


def test_switching_channel_writes_the_setting(monkeypatch):
    monkeypatch.setattr(atlas, '_latest_version',
                        lambda use_cache=True, channel=None:
                        {'main': '1.49.0', 'dev': '1.50.0'}.get(channel))
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [])
    ctx, saved = box()

    with _Flask({'channel': 'dev'}) as flask:
        _view(_register(ctx), '/channel', 'POST')()

    assert saved[atlas.CHANNEL_KEY] == 'dev'
    assert flask.payload['channel'] == 'dev'


def test_switching_channel_starts_nothing(monkeypatch):
    """⚠️ **Changes nothing on disk and runs no compose command.** It decides
    which version the *next* update targets; the operator still presses Update
    and still watches the log. A toggle that silently began rebuilding every
    deployment on the box would be a very surprising thing to click."""
    monkeypatch.setattr(atlas, '_latest_version',
                        lambda use_cache=True, channel=None: '1.50.0')
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [])

    ran = []
    monkeypatch.setattr(atlas, '_compose',
                        lambda *a, **k: ran.append(a) or Probe())
    monkeypatch.setattr(atlas, '_run_update',
                        lambda *a, **k: ran.append(('update',) + a))

    ctx, _ = box()
    with _Flask({'channel': 'dev'}):
        _view(_register(ctx), '/channel', 'POST')()

    assert ran == [], f'switching the channel ran {ran}'


def test_the_route_refuses_a_channel_it_does_not_know(monkeypatch):
    """The value reaches a URL as a ref; the route is where that stops."""
    monkeypatch.setattr(atlas, '_latest_version',
                        lambda use_cache=True, channel=None: '1.49.0')
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [])
    ctx, saved = box()

    with _Flask({'channel': '../../etc/passwd'}):
        result = _view(_register(ctx), '/channel', 'POST')()

    body, status = result
    assert status == 400
    assert body['success'] is False
    assert atlas.CHANNEL_KEY not in saved, 'a refused channel must not be stored'


def test_the_card_payload_reports_both_channels_and_what_is_ahead(monkeypatch):
    """⚠️ Both, not just the selected one. An operator deciding whether to
    switch needs to see what the other offers *before* switching; a card that
    showed only the current channel would make them flip it to find out, which
    on a box mid-rollout is a question they cannot un-ask."""
    monkeypatch.setattr(atlas, '_latest_version',
                        lambda use_cache=True, channel=None:
                        {'main': '1.49.0', 'dev': '1.50.0'}.get(channel))
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761,
                   agency_name='Corona Fire Department')
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [inst])
    monkeypatch.setattr(atlas, '_installed_version', lambda c, i: '1.50.0')
    monkeypatch.setattr(atlas, 'deployment_identity',
                        lambda c, i, s: {'name': 'corona'})

    ctx, _ = box()
    with _Flask() as flask:
        _view(_register(ctx), '/channel', 'GET')()

    by_key = {c['key']: c for c in flask.payload['channels']}
    assert by_key['main']['version'] == '1.49.0'
    assert by_key['dev']['version'] == '1.50.0'
    # On 1.50.0 already, so `main` would be a downgrade and `dev` would not.
    assert by_key['main']['ahead'] == ['corona']
    assert by_key['dev']['ahead'] == []


def test_the_payload_names_the_install_pin(monkeypatch):
    """The one place the channel does not apply, said rather than discovered."""
    monkeypatch.setattr(atlas, '_latest_version',
                        lambda use_cache=True, channel=None: '1.49.0')
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [])

    ctx, _ = box()
    with _Flask() as flask:
        _view(_register(ctx), '/channel', 'GET')()

    assert flask.payload['install_tag'] == atlas.ATLAS_TAG


def test_an_unknown_channel_is_refused_by_the_route():
    """The value reaches a URL as a ref; the route is where that stops."""
    source = MODULE[MODULE.index('def channel_set_view('):]
    source = source[:source.index('register_module(')]

    assert 'wanted not in CHANNELS' in source
    assert '400' in source


# --------------------------------------------------------------------------- #
# The pin
# --------------------------------------------------------------------------- #


def test_the_install_pin_is_a_tag_and_a_commit():
    """⚠️ Unchanged by this work, and it must stay that way: the channel is a
    branch that moves, and `_verify_pin` exists to refuse a tag that has. A
    fresh install resolving its tag from a branch would give that up."""
    assert atlas.ATLAS_TAG.startswith('v')
    assert len(atlas.ATLAS_SHA) == 40


def test_the_pin_names_the_stable_release():
    """Fresh installs land on what has been promoted, whichever channel the box
    follows afterwards.

    ⚠️ **This is the one guard a promotion is supposed to change**, and
    the only one that means equality. `PROMOTED` is written down separately
    rather than read from `ATLAS_TAG`: a test that computes its expectation
    from the value under test passes for every value.
    """
    assert atlas.ATLAS_TAG == PROMOTED, (
        'the pin is %s and the promoted release is %s. If a release was just '
        'promoted, both move together; if not, a fresh install is about to '
        'land on something that has not been.' % (atlas.ATLAS_TAG, PROMOTED))
    assert atlas.ATLAS_SHA == PROMOTED_SHA, (
        "the tag moved and the commit did not, or the other way round. "
        "⚠️ The SHA is the MIRROR's commit for that tag, never this "
        "repository's -- every release has two.")
