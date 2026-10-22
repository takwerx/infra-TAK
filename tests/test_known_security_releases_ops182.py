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
"""Known security releases without a GitHub advisory (ops #182).

CloudTAK 13.112.2 moved its API image onto Node 26 with the Oct 21 Node security
fixes but published no GHSA, so the update notice called it a plain update. An
infra-TAK-side list of such releases is merged with the GHSA results. The
functions are cut out of app.py and run with CloudTAK / GitHub faked.
"""

import os
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    # a multi-line tuple's closing paren sits in column 0: it ends the constant, not the cut
    return re.search(rf'^{name} = .*?(?=^(?!\))\S)', APP, re.S | re.M).group(0)


def _exec(n, *names, consts=()):
    src = '\n'.join([_const(c) for c in consts] + [_cut(x) for x in names])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


def _known_ns():
    return _exec({'re': re}, '_semver_tuple', '_known_security_fixed_by',
                 consts=('KNOWN_SECURITY_RELEASES',))


def test_seeded_with_cloudtak_13_112_2():
    n = _known_ns()
    e = [x for x in n['KNOWN_SECURITY_RELEASES'] if x['component'] == 'cloudtak']
    assert e and e[0]['fixed_in'] == '13.112.2'
    assert 'CVE-2026-111497' in e[0]['reason'] and 'CVE-2026-106069' in e[0]['reason']
    for x in n['KNOWN_SECURITY_RELEASES']:
        assert set(x) == {'component', 'fixed_in', 'reason'}
        assert n['_semver_tuple'](x['fixed_in']) is not None


@pytest.mark.parametrize('installed, target, flagged', [
    ('13.111.0', '13.112.2', True),     # below -> exactly the fix
    ('13.100.4', '13.115.0', True),     # below -> past the fix
    ('v13.112.1', 'v13.112.2', True),
    ('13.112.2', '13.113.0', False),    # already at the fix
    ('13.113.0', '13.114.0', False),    # above the fix
    ('13.100.0', '13.112.1', False),    # target does not reach the fix
    ('13.112.0-beta', '13.113.0', False),  # unparseable: claim nothing
    ('', '13.113.0', False),
])
def test_cloudtak_known_release_range(installed, target, flagged):
    got = _known_ns()['_known_security_fixed_by']('cloudtak', installed, target)
    assert bool(got) is flagged
    if flagged:
        assert got[0].endswith('(fixed in v13.112.2)') and 'CVE-2026-111497' in got[0]


def test_other_component_is_not_flagged():
    assert _known_ns()['_known_security_fixed_by']('takportal', '13.0.0', '14.0.0') == []


# ── merged with the GHSA results in the pending-update collector ─────────────

GHSA = 'CVE-2026-55177 (high): Authenticated full-read SSRF in /api/esri*'


def _collect(installed, latest, ghsa):
    """Run _collect_pending_updates with only CloudTAK pending; `ghsa` is the
    advisory list _gh_advisories_fixed_by returns, or an exception it raises."""
    def advisories(repo, inst, tgt):
        assert repo == 'dfpc-coe/CloudTAK' and (inst, tgt) == (installed, latest)
        if isinstance(ghsa, BaseException):
            raise ghsa
        return ghsa

    n = _known_ns()
    n.update({
        'os': os,
        '_console_pending_update': lambda s: None,
        '_get_cloudtak_version_info': lambda: {
            'version': installed, 'latest': latest, 'update_available': True},
        '_gh_advisories_fixed_by': advisories,
        '_os_security_items': lambda seen, unknown: [],
        '_detect_cloudtak_plugins': lambda: [],
    })
    _exec(n, '_apply_security_identity', '_collect_pending_updates')
    real_isdir = os.path.isdir
    os.path.isdir = lambda p: p == os.path.expanduser('~/CloudTAK') or real_isdir(p)
    try:
        pending = n['_collect_pending_updates']({})
    finally:
        os.path.isdir = real_isdir
    assert [p['key'] for p in pending] == ['cloudtak']
    return pending[0]


def test_cloudtak_below_fix_is_flagged_security_without_a_ghsa():
    ct = _collect('13.111.0', '13.112.2', [])
    assert len(ct['security']) == 1
    assert ct['security'][0].startswith('Fixes Node.js security fixes CVE-2026-111497')
    assert ct['identity'] == '13.112.2+security'


def test_cloudtak_at_or_above_fix_is_a_plain_update():
    ct = _collect('13.112.2', '13.113.0', [])
    assert ct['security'] == [] and ct['identity'] == '13.113.0'


def test_ghsa_flagging_still_works_and_merges():
    ct = _collect('13.113.0', '13.114.0', [GHSA])
    assert ct['security'] == ['Fixes ' + GHSA] and ct['identity'] == '13.114.0+security'
    ct = _collect('13.5.0', '13.114.0', [GHSA])
    assert ct['security'][0] == 'Fixes ' + GHSA
    assert 'CVE-2026-111497' in ct['security'][1] and len(ct['security']) == 2


def test_advisories_unreadable_still_flags_known_release():
    ct = _collect('13.111.0', '13.112.2', OSError('rate limited'))
    assert ct['security_unknown'] is True
    assert ct['security'] and ct['identity'] == '13.112.2+security'


def test_advisories_unreadable_above_fix_stays_unknown_not_security():
    ct = _collect('13.113.0', '13.114.0', OSError('rate limited'))
    assert ct['security_unknown'] is True and not ct.get('security')
    assert ct['identity'] == '13.114.0' and ct['seen_ok'] == ['13.114.0', '13.114.0+security']
