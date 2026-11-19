# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #972 (infra-TAK #590): the Guard Dog card and the Guard Dog page agree.

The main-page card showed a blue "update" whenever a newer console release existed.
The Guard Dog page offers "Update Guard Dog" only when its deployed scripts differ from
the running console (or the alert email / nickname changed). On a box with a newer console
release out and Guard Dog current, the card said update and the page said "up to date"
with no button. Both screens now ask _guarddog_needs_update().
"""
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
VERSION = '10.3.12-alpha'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _versions(settings, latest='10.3.13', installed=True):
    """Run the real get_all_module_versions() with only Guard Dog installed."""
    ns = {
        'VERSION': VERSION,
        'detect_modules': lambda: {'guarddog': {'installed': installed}},
        'update_cache': {'latest': latest, 'checked': 1},
        'load_settings': lambda: settings,
        '_node_card_gaps': lambda: {},
        '_safe_module_version_info': lambda key, info: info,
    }
    exec(_fn('_guarddog_needs_update') + '\n' + _fn('get_all_module_versions'), ns)
    return ns['get_all_module_versions']()


def _page_says_update(settings, installed=True):
    ns = {'VERSION': VERSION}
    exec(_fn('_guarddog_needs_update'), ns)
    return ns['_guarddog_needs_update'](settings, installed)


CURRENT = {
    'guarddog_deployed_version': VERSION,
    'guarddog_deployed_email': 'ops@example.org',
    'guarddog_alert_email': 'ops@example.org',
    'guarddog_deployed_nickname': 'fltak',
    'guarddog_server_nickname': 'fltak',
}


def test_newer_console_release_alone_is_not_a_guard_dog_update():
    # The reported box: console v10.3.12-alpha, a newer release is out, Guard Dog is current.
    assert _page_says_update(CURRENT) is False
    card = _versions(dict(CURRENT), latest='10.3.13')['guarddog']
    assert card['update_available'] is False


def test_card_and_page_agree_in_every_state():
    states = {
        'current': dict(CURRENT),
        'old scripts': {**CURRENT, 'guarddog_deployed_version': '10.3.11'},
        'never stamped': {k: v for k, v in CURRENT.items() if k != 'guarddog_deployed_version'},
        'email changed': {**CURRENT, 'guarddog_alert_email': 'new@example.org'},
        'nickname changed': {**CURRENT, 'guarddog_server_nickname': 'other'},
    }
    for name, st in states.items():
        for latest in ('10.3.13', VERSION, None):
            card = _versions(dict(st), latest=latest)['guarddog']['update_available']
            assert card == _page_says_update(st), (name, latest)
    assert _page_says_update(states['old scripts']) is True
    assert _page_says_update(states['email changed']) is True
    assert _page_says_update(states['nickname changed']) is True


def test_not_installed_never_offers_an_update():
    assert _page_says_update({'guarddog_deployed_version': '1.0'}, installed=False) is False
    assert 'guarddog' not in _versions({}, installed=False)


def test_page_banner_uses_the_same_helper():
    src = _fn('guarddog_page') if re.search(r'^def guarddog_page\(', APP, re.M) else APP
    assert '_guarddog_needs_update(settings, gd.get(\'installed\'))' in src
