"""PR 525: the "this console runs as root" notice bar and its per-login dismissal id.

Runs the real `_stamp_notice_login` and `_root_console_bar` from app.py with the real Flask
session. The bar shows only for uid 0, links to the Console Security Guard card, and its
dismissal key changes on every password login (so a dismissal does not outlive the login).
"""

import ast
import pathlib
import secrets
import types

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError('%s not found in app.py' % name)


def _ns(uid):
    ns = {'session': flask.session, 'secrets': secrets,
          'os': types.SimpleNamespace(getuid=lambda: uid)}
    exec(_func('_stamp_notice_login'), ns)
    exec(_func('_root_console_bar'), ns)
    return ns


@pytest.fixture
def ctx():
    app = flask.Flask('pr525')
    app.secret_key = 'x'
    with app.test_request_context('/'):
        yield


def test_root_console_gets_the_bar_with_link_and_login_key(ctx):
    ns = _ns(0)
    ns['_stamp_notice_login'](True)
    spec = ns['_root_console_bar']({})
    assert spec is not None
    assert '/hardening#console-guard' in spec['html']
    assert 'Switch to non-root' in spec['html']
    assert spec['key'] == 'rootconsole:' + flask.session['notice_login']


def test_non_root_console_gets_no_bar(ctx):
    ns = _ns(994)
    ns['_stamp_notice_login'](True)
    assert ns['_root_console_bar']({}) is None


def test_password_login_makes_a_new_id_so_a_dismissal_does_not_carry_over(ctx):
    ns = _ns(0)
    ns['_stamp_notice_login'](True)
    first = ns['_root_console_bar']({})['key']
    ns['_stamp_notice_login'](True)
    assert ns['_root_console_bar']({})['key'] != first


def test_sso_path_keeps_the_id_on_every_request_but_sets_one_when_missing(ctx):
    ns = _ns(0)
    ns['_stamp_notice_login'](False)           # new SSO session: no id yet
    first = flask.session['notice_login']
    assert first
    ns['_stamp_notice_login'](False)           # later requests must not rotate it
    assert flask.session['notice_login'] == first


def test_bar_is_wired_into_the_notice_bars_and_the_anchor_exists():
    body = _func('_render_notice_bars_inner')
    assert '_root_console_bar(settings)' in body
    assert 'id="console-guard"' in (REPO / 'templates' / 'hardening.html').read_text(encoding='utf-8')
