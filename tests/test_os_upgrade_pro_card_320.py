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
"""GH #320 — the "Upgrade to Ubuntu 24.04" card is one line on a 22.04 box that Ubuntu Pro
security updates already cover. Code-only proof: the Pro check needs positive evidence
(attached + esm-infra enabled + unexpired) and any doubt is False, the status route only
asks when the idle card can show, and the template keeps the button in both layouts."""

import json
import pathlib
import re
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TPL = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _covered():
    import os
    import types
    ns = {'json': json, 'os': os, 'subprocess': subprocess, 'datetime': datetime, 'types': types}
    exec(compile(_fn('_ubuntu_pro_security_covered'), 'app.py:pro', 'exec'), ns)
    return ns['_ubuntu_pro_security_covered']


def _status(attached=True, esm='enabled', expires='future', services=None):
    if expires == 'future':
        expires = (datetime.now(timezone.utc) + timedelta(days=400)).isoformat()
    elif expires == 'past':
        expires = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    d = {'attached': attached, 'expires': expires,
         'services': services if services is not None else [
             {'name': 'esm-apps', 'status': 'enabled'}, {'name': 'esm-infra', 'status': esm}]}
    if expires is None:
        del d['expires']
    return json.dumps(d)


def test_attached_and_enabled_is_covered():
    assert _covered()(_status()) is True


def test_free_token_far_future_expiry_is_covered():
    assert _covered()(_status(expires='9999-12-31T00:00:00+00:00')) is True


@pytest.mark.parametrize('raw', [
    _status(attached=False),
    _status(esm='disabled'),
    _status(esm='n/a'),
    _status(expires='past'),
    _status(expires=None),
    _status(expires='not a date'),
    _status(expires='2099-01-01T00:00:00'),                    # no timezone: can't judge it
    _status(services=[]),
    _status(services=[{'name': 'esm-apps', 'status': 'enabled'}]),   # esm-infra is the security feed
    _status(services=[{'name': 'esm-infra', 'status': 'enabled'}, {'name': 'esm-infra', 'status': 'enabled'}]),
    '', 'not json', '[]', 'null', '{"attached": "true"}',
])
def test_any_doubt_is_not_covered(raw):
    assert _covered()(raw) is False


def test_missing_pro_client_is_not_covered(monkeypatch):
    import os
    monkeypatch.setattr(os.path, 'exists', lambda p: False)
    assert _covered()() is False


def test_command_failure_is_not_covered(monkeypatch):
    import os
    monkeypatch.setattr(os.path, 'exists', lambda p: True)
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 1, '', 'boom'))
    assert _covered()() is False

    def boom(*a, **k):
        raise subprocess.TimeoutExpired('pro', 15)
    monkeypatch.setattr(subprocess, 'run', boom)
    assert _covered()() is False


def test_pro_status_is_a_plain_read_only_call():
    src = _fn('_ubuntu_pro_security_covered')
    assert "'status', '--format', 'json'" in src
    assert '_sudo_wrap' not in src and 'shell=True' not in src and "'attach'" not in src and "'enable'" not in src


def test_status_route_only_asks_when_the_idle_card_can_show():
    src = _fn('console_os_upgrade_status_api')
    m = re.search(r"st\['pro_covered'\] = (.*)", src)
    assert m, 'status route must expose pro_covered'
    expr = m.group(1)
    assert "st['can_start']" in expr and "st['state'] == 'idle'" in expr
    assert expr.index("st['can_start']") < expr.index('_ubuntu_pro_security_covered()')   # short-circuit


def test_template_keeps_the_button_in_both_layouts():
    idle = TPL[TPL.index('id="osup-idle"'):TPL.index('id="osup-progress"')]
    assert 'id="osup-idle-pro"' in idle and 'id="osup-idle-full"' in idle
    assert idle.count('osupOpenPreflight()') == 2
    assert 'Check &amp; upgrade' in idle[idle.index('osup-idle-pro'):idle.index('osup-idle-full')]
    # the long text, the 5.8 requirement and the two-server note stay in the full layout only
    pro_part = idle[idle.index('osup-idle-pro'):idle.index('osup-idle-full')]
    assert 'standard support ends' not in pro_part and 'Requires TAK Server' not in pro_part
    # progress and result views are never touched by the Pro mode
    assert 'pro_covered' not in TPL[TPL.index('function _osupRenderResult'):TPL.index('function _osupStartPolling')]


def test_template_defaults_to_the_full_card():
    assert re.search(r'id="osup-idle-pro" style="display:none', TPL)
    assert re.search(r'id="osup-idle-full" style="display:block', TPL)
    assert 'var pro=!!(d&&d.pro_covered)' in TPL
