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
"""Beta update channel (ops #245).

A console with update_beta on takes vX.Y.Z-alpha-rcN GitHub pre-releases about a day
before the stable tag. What must hold:
- stable consoles (today's code and this code) never see an rc;
- a beta console is offered the newest of stable and rc, rc2 over rc1, and the stable
  tag over its own rc only when that rc is not the one being promoted;
- Update Now on a beta box never falls back to an older stable tag (a downgrade);
- the update email and the Help → Report an issue link say "beta".
The functions are cut out of app.py and run with GitHub and git faked.
"""

import html
import json
import os
import pathlib
import re
import sys
import types
import urllib.request as _ur
from urllib.parse import parse_qs, urlsplit

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CONSOLE_HTML = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M).group(0)


def _exec(n, *names, consts=()):
    src = '\n'.join([_const(c) for c in consts] + [_cut(x) for x in names])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


PICK = ('_release_key', '_console_running_release', '_beta_pick')


def _pick_ns():
    return _exec({'re': re}, *PICK, consts=('_RELEASE_TAG_RE',))


def rel(tag, pre=False, draft=False, body=''):
    return {'tag_name': tag, 'prerelease': pre, 'draft': draft, 'body': body,
            'html_url': f'https://github.com/takwerx/infra-TAK/releases/tag/{tag}'}


STABLE_30 = rel('v10.2.30-alpha')
RC1_31 = rel('v10.2.31-alpha-rc1', pre=True)
RC2_31 = rel('v10.2.31-alpha-rc2', pre=True)
STABLE_31 = rel('v10.2.31-alpha')


def pick(releases, head_tags, version):
    return _pick_ns()['_beta_pick'](releases, head_tags, version)


# ── tag ordering ──────────────────────────────────────────────────────────────

def test_release_key_orders_stable_above_its_own_rcs():
    k = _pick_ns()['_release_key']
    assert k('v10.2.31-alpha') > k('v10.2.31-alpha-rc2') > k('v10.2.31-alpha-rc1') > k('v10.2.30-alpha')
    assert k('v10.2.32-alpha-rc1') > k('v10.2.31-alpha')
    assert k('10.2.31-alpha') == k('v10.2.31-alpha')


@pytest.mark.parametrize('tag', ['v10.2.31-beta1', 'v10.2.31-alpha-rc', 'dev', 'v10.2', 'v10.2.31-alpha-rc1-x', ''])
def test_release_key_rejects_anything_else(tag):
    assert _pick_ns()['_release_key'](tag) is None


# ── stable boxes never see an rc (today's parsers, unchanged) ─────────────────

def _fake_urllib(routes):
    class _Resp:
        def __init__(self, b):
            self.b = b

        def read(self):
            return self.b

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, 'full_url') else req
        for k, v in routes.items():
            if k in url:
                if isinstance(v, BaseException):
                    raise v
                return _Resp(json.dumps(v).encode())
        raise AssertionError('unexpected url ' + url)
    return types.SimpleNamespace(Request=_ur.Request, urlopen=urlopen)


class _patched_urllib:
    def __init__(self, routes):
        self.fake = _fake_urllib(routes)

    def __enter__(self):
        import urllib
        self.real_mod, self.real_attr = sys.modules['urllib.request'], urllib.request
        sys.modules['urllib.request'] = self.fake
        urllib.request = self.fake
        return self

    def __exit__(self, *a):
        import urllib
        sys.modules['urllib.request'] = self.real_mod
        urllib.request = self.real_attr
        return False


def test_stable_update_now_target_ignores_rc_tags():
    n = _exec({'json': json, 'GITHUB_REPO': 'takwerx/infra-TAK'}, '_fetch_latest_tag_name')
    tags = [{'name': 'v10.2.31-alpha-rc2'}, {'name': 'v10.2.31-alpha-rc1'}, {'name': 'v10.2.30-alpha'}]
    with _patched_urllib({'/tags': tags}):
        assert n['_fetch_latest_tag_name']() == 'v10.2.30-alpha'


def test_stable_check_and_banner_parsers_drop_rc_tags():
    # update_check / _warm_update_cache_bg / the notifier all read X.Y.Z with int(); an rc
    # must fail that parse (that is what keeps it off every stable box in the field).
    name = 'v10.2.31-alpha-rc1'.lstrip('v').replace('-alpha', '').replace('-beta', '')
    with pytest.raises(ValueError):
        tuple(int(p) for p in name.split('.'))


# ── the beta decision ─────────────────────────────────────────────────────────

def test_stable_box_on_beta_gets_the_rc():
    p = pick([RC1_31, STABLE_30], ['v10.2.30-alpha'], '10.2.30-alpha')
    assert p['available'] and p['tag'] == 'v10.2.31-alpha-rc1' and p['prerelease']
    assert p['running_tag'] == 'v10.2.30-alpha'


def test_rc1_box_gets_rc2():
    p = pick([RC2_31, RC1_31, STABLE_30], ['v10.2.31-alpha-rc1'], '10.2.31-alpha')
    assert p['available'] and p['tag'] == 'v10.2.31-alpha-rc2'


def test_promotion_of_the_rc_this_box_runs_is_up_to_date():
    p = pick([STABLE_31, RC1_31, STABLE_30], ['v10.2.31-alpha-rc1'], '10.2.31-alpha')
    assert p['tag'] == 'v10.2.31-alpha' and not p['available']


def test_promotion_after_an_rc_this_box_did_not_take_is_offered():
    p = pick([STABLE_31, RC2_31, RC1_31], ['v10.2.31-alpha-rc1'], '10.2.31-alpha')
    assert p['available'] and p['tag'] == 'v10.2.31-alpha'


def test_promotion_after_this_rc_was_pulled_is_offered():
    # rc1 was deleted (bad beta); the stable tag carries different code.
    p = pick([STABLE_31, STABLE_30], ['v10.2.31-alpha-rc1'], '10.2.31-alpha')
    assert p['available'] and p['tag'] == 'v10.2.31-alpha'


def test_dev_build_without_a_tag_moves_onto_the_rc():
    p = pick([RC1_31, STABLE_30], [], '10.2.31-alpha')
    assert p['available'] and p['running_tag'] is None


def test_up_to_date_on_stable_with_no_beta_out():
    p = pick([STABLE_30], ['v10.2.30-alpha'], '10.2.30-alpha')
    assert p['tag'] == 'v10.2.30-alpha' and not p['available']


def test_newer_stable_box_is_not_offered_an_older_rc():
    p = pick([RC1_31, STABLE_30], ['v10.2.32-alpha'], '10.2.32-alpha')
    assert not p['available']


@pytest.mark.parametrize('bad', [
    rel('v10.2.31-alpha-rc1', pre=False),          # rc not marked pre-release
    rel('v10.2.31-alpha', pre=True),               # stable name published as pre-release
    rel('v10.2.31-alpha-rc1', pre=True, draft=True),
    rel('v10.2.31-beta1', pre=True),
])
def test_only_published_rc_prereleases_and_stable_releases_count(bad):
    p = pick([bad, STABLE_30], ['v10.2.30-alpha'], '10.2.30-alpha')
    assert p['tag'] == 'v10.2.30-alpha' and not p['available']


def test_running_tag_ignores_tags_of_another_version():
    n = _pick_ns()
    k, t = n['_console_running_release'](['v10.2.30-alpha', 'v10.2.31-alpha-rc1'], '10.2.31-alpha')
    assert t == 'v10.2.31-alpha-rc1' and k == (10, 2, 31, 0, 1)


def test_no_releases_is_none():
    assert pick([], [], '10.2.30-alpha') is None
    assert pick({'message': 'API rate limit exceeded'}, [], '10.2.30-alpha') is None


# ── the update email ──────────────────────────────────────────────────────────

def _notify_ns(version, head_tags):
    n = {'json': json, 're': re, 'os': os, 'subprocess': None, 'VERSION': version,
         'GITHUB_REPO': 'takwerx/infra-TAK'}
    _exec(n, '_console_pending_update', '_beta_update_target', '_release_security_summary', *PICK,
          consts=('_RELEASE_TAG_RE', '_SECURITY_RELEASE_HEADLINE_RE'))
    n['_console_head_tags'] = lambda: list(head_tags)
    return n


def test_email_names_the_rc_as_beta():
    n = _notify_ns('10.2.30-alpha', ['v10.2.30-alpha'])
    with _patched_urllib({'/releases?': [RC1_31, STABLE_30]}):
        item = n['_console_pending_update']({'update_channel': 'main', 'update_beta': True})
    assert item['target'] == 'v10.2.31-alpha-rc1 (beta)' and item['identity'] == 'v10.2.31-alpha-rc1'
    assert item['installed'] == 'v10.2.30-alpha' and item['security'] == []


def test_email_flags_a_security_release_on_the_way_to_the_target():
    sec = rel('v10.2.31-alpha', body='## Security: Authentik 2026.8.5\n')
    n = _notify_ns('10.2.30-alpha', ['v10.2.30-alpha'])
    with _patched_urllib({'/releases?': [rel('v10.2.32-alpha-rc1', pre=True), sec, STABLE_30]}):
        item = n['_console_pending_update']({'update_channel': 'main', 'update_beta': True})
    assert item['target'] == 'v10.2.32-alpha-rc1 (beta)'
    assert item['security'] == ['v10.2.31-alpha is a security release: Authentik 2026.8.5']


def test_email_silent_after_promotion_of_the_running_rc():
    n = _notify_ns('10.2.31-alpha', ['v10.2.31-alpha-rc1'])
    with _patched_urllib({'/releases?': [STABLE_31, RC1_31]}):
        assert n['_console_pending_update']({'update_channel': 'main', 'update_beta': True}) is None


def test_email_without_beta_uses_releases_latest_as_before():
    n = _notify_ns('10.2.30-alpha', ['v10.2.30-alpha'])
    with _patched_urllib({'/releases/latest': STABLE_30, '/releases?': [RC1_31, STABLE_30]}):
        assert n['_console_pending_update']({'update_channel': 'main'}) is None


def test_email_body_says_beta_is_on():
    src = _cut('_update_notify_check_once')
    assert "(beta releases on)" in src


# ── /api/update/check on a beta box ───────────────────────────────────────────

def _check(head_tags, version, routes, settings=None):
    n = {'json': json, 're': re, 'os': os, 'time': __import__('time'), 'VERSION': version,
         'GITHUB_REPO': 'takwerx/infra-TAK', 'subprocess': None,
         'update_cache': {'latest': None, 'checked': 0, 'notes': '', 'body': ''},
         'load_settings': lambda: settings or {'update_channel': 'main', 'update_beta': True},
         'request': types.SimpleNamespace(args={'refresh': '1'}),
         '_update_check_response': lambda d: d}
    _exec(n, 'update_check', '_update_beta_on', '_beta_update_target', *PICK,
          consts=('_RELEASE_TAG_RE', '_beta_check_cache'))
    n['_console_head_tags'] = lambda: list(head_tags)
    with _patched_urllib(routes):
        return n['update_check']()


def test_check_offers_the_rc_with_its_notes():
    body_rel = dict(RC1_31, body='Fixes the thing.')
    d = _check(['v10.2.30-alpha'], '10.2.30-alpha', {'/releases?': [body_rel, STABLE_30]})
    assert d['update_available'] and d['latest'] == '10.2.31-alpha-rc1' and d['beta'] is True
    assert d['notes'] == 'Beta pre-release' and d['current'] == '10.2.30-alpha'
    assert d['body'].startswith('Fixes the thing.') and 'releases/tag/v10.2.31-alpha-rc1' in d['body']


def test_check_on_rc_shows_the_rc_as_current():
    d = _check(['v10.2.31-alpha-rc1'], '10.2.31-alpha', {'/releases?': [STABLE_31, RC1_31]})
    assert d['current'] == '10.2.31-alpha-rc1' and not d['update_available']


def test_check_failure_is_check_failed_not_up_to_date():
    d = _check([], '10.2.30-alpha', {'/releases?': OSError('rate limited')})
    assert d['check_failed'] and not d['update_available']


def test_dev_channel_ignores_beta():
    src = _cut('_update_beta_on')
    n = _exec({}, '_update_beta_on')
    assert n['_update_beta_on']({'update_channel': 'main', 'update_beta': True})
    assert not n['_update_beta_on']({'update_channel': 'dev', 'update_beta': True})
    assert not n['_update_beta_on']({'update_channel': 'main'})
    assert 'update_channel' in src


# ── Update Now ────────────────────────────────────────────────────────────────

def test_update_now_resolves_beta_before_lock_and_snapshot():
    src = _cut('update_apply')
    i_beta = src.index('_beta_update_target()')
    assert i_beta < src.index('_update_lock = ') < src.index("_s['console_rollback']")
    assert "tag_name = _beta_tag or _fetch_latest_tag_name()" in src


def test_update_now_never_falls_back_to_main_on_beta():
    src = _cut('update_apply')
    i_guard = src.index('if _beta_tag and not target_ref:')
    assert i_guard < src.index("target_ref = 'refs/remotes/origin/main'")
    # up to date or GitHub unreadable: refuse, never pick a stable tag instead
    assert "'Already up to date on the beta channel.'" in src


def test_beta_route_is_login_protected_and_bool_only():
    m = re.search(r"@app\.route\('/api/update/beta', methods=\['POST'\]\)\n@login_required\ndef set_update_beta",
                  APP)
    assert m
    src = _cut('set_update_beta')
    assert 'isinstance(enabled, bool)' in src and 'password' not in src.split('"""')[2]


# ── UI: Console switch, Help → Report an issue ────────────────────────────────

def test_console_has_beta_switch_hidden_on_dev():
    assert 'id="ch-beta-btn"' in CONSOLE_HTML and "fetchRetry('/api/update/beta'" in CONSOLE_HTML
    btn = re.search(r'<button[^>]*id="ch-beta-btn".*?</button>', CONSOLE_HTML, re.S).group(0)
    assert "settings.get('update_channel','main')=='dev'" in btn and 'display:none' in btn


def _help(report_version=None):
    jinja2 = pytest.importorskip("jinja2", reason="jinja2 not installed")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(REPO / 'templates')),
                             undefined=jinja2.ChainableUndefined, autoescape=True)
    kw = dict(settings={'os_name': 'Ubuntu 22.04.5 LTS', 'arch': 'amd64'}, version='10.2.31-alpha',
              current_ssh_port=22, diag_support_email='', diag_email_ready=False)
    if report_version is not None:
        kw['report_version'] = report_version
    page = env.get_template('help.html').render(**kw)
    tag = re.search(r'<a [^>]*id="report-issue-link"[^>]*>', page).group(0)
    q = parse_qs(urlsplit(html.unescape(re.search(r'href="([^"]*)"', tag).group(1))).query)
    return q


def test_report_link_marks_beta_and_names_the_rc():
    q = _help('v10.2.31-alpha-rc1 (beta channel)')
    assert q['version'] == ['v10.2.31-alpha-rc1 (beta channel)']
    assert 'Console: v10.2.31-alpha-rc1 (beta channel) · Ubuntu 22.04.5 LTS · amd64' in q['what'][0]


def test_report_link_without_beta_is_unchanged():
    q = _help()
    assert q['version'] == ['v10.2.31-alpha']
    assert 'Console: v10.2.31-alpha · Ubuntu' in q['what'][0]


def test_help_route_builds_report_version_from_the_running_tag():
    src = _cut('help_page')
    assert '_console_running_release(_console_head_tags(), VERSION)' in src
    assert "' (beta channel)' if _update_beta_on(settings)" in src
