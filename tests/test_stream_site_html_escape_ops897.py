# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #897: a name must reach the stream site's pages as text only.

The stream site (mediamtx_ldap_overlay.py) has two pages that build HTML in the browser:

  1. Active Streams (/viewer)      stream names and their visibility go into the Watch and
                                   Share buttons' inline handlers
  2. Stream Access (/stream-access) user ids and group names go into the row's inline handlers

and one that the server fills in: /viewer writes the signed-in username, the title and the
subtitle into the page.

These tests run each page's own JavaScript in node with a small stand-in for the browser, give
it hostile values, then read the HTML it built with Python's HTML parser (which decodes
attributes the way a browser does). A pass needs both halves: nothing is injected, and the value
still works (Watch gets the exact stream name, the group toggle gets the exact group).

The stand-in's createElement escapes & < > only, as a browser's textContent/innerHTML pair does,
so the old helper behaves here as it did in the browser.
"""
import builtins
import importlib.util
import io
import json
import pathlib
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIVE = '&<>"\''
FIVE_ESCAPED = '&amp;&lt;&gt;&quot;&#39;'

# Each way out: close the attribute with a quote, close the JavaScript string with a quote or
# through a backslash or an entity, open a new element. Then plain names that must keep working.
HOSTILE = [
    'x" onmouseover="pwn()',
    "x' onmouseover='pwn()",
    "x');pwn();//",
    "x\\');pwn();//",
    '&quot;);pwn();//',
    '&#39;);pwn();//',
    '<img src=x onerror=pwn()>',
    'a"b<c>&d\'e\\f',
]
PLAIN = ['live/drone1', 'cam_1.main', "chief's cam", 'vid_private']

BROWSER = r'''
var __els = {}, __fetch = {}, __pwned = 0;
function pwn(){ __pwned++; }
function __el(id){
  if(!__els[id]) __els[id] = {id:id, innerHTML:'', textContent:'', value:'', className:'', disabled:false,
    style:{}, classList:{add:function(){}, remove:function(){}}};
  return __els[id];
}
var document = {
  body: __el('__body'),
  getElementById: function(id){ return __el(id); },
  createElement: function(){
    var t = '';
    return {
      set textContent(v){ t = (v == null ? '' : String(v)); },
      get textContent(){ return t; },
      get innerHTML(){ return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    };
  }
};
var window = {location: {origin: 'https://stream.example', hostname: 'stream.example'}};
window.self = window; window.top = window;
var screen = {width: 1920, height: 1080};
function fetch(url){
  var key = String(url).split('?')[0];
  return Promise.resolve({ok:true, status:200, json:function(){ return Promise.resolve(__fetch[key]); }});
}
'''


def _node():
    node = shutil.which('node')
    if node is None:
        pytest.skip('no node on PATH, so the page JavaScript is unexercised')
    return node


def _run(program):
    r = subprocess.run([_node(), '-'], input=program, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def _overlay():
    spec = importlib.util.spec_from_file_location('overlay_ops897', ROOT / 'mediamtx_ldap_overlay.py')
    ov = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ov)
    return ov


def _page_script(page_html):
    """The page's own script block: from the first <script> line to the last </script>."""
    start = page_html.index('<script>\n') + len('<script>\n')
    return page_html[start:page_html.rindex('</script>')]


def _render(page_html, fetches):
    """Run the page script with these fetch answers. Returns the HTML of every element it wrote
    and how often pwn() ran while it did."""
    program = (BROWSER + '__fetch = ' + json.dumps(fetches) + ';\n' + _page_script(page_html) +
               '\nsetTimeout(function(){ var o = {pwned: __pwned, html: {}};'
               ' for(var k in __els) o.html[k] = __els[k].innerHTML;'
               ' console.log(JSON.stringify(o)); }, 50);\n')
    return _run(program)


def _helper(page_html, name, value):
    """What the page's own escape helper returns for a value."""
    program = (BROWSER + _page_script(page_html).split('(async function(){')[0].split('loadUsers();')[0] +
               '\nconsole.log(JSON.stringify(%s(%s)));\n' % (name, json.dumps(value)))
    return _run(program)


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.text = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)


def _parse(html):
    p = _Page()
    p.feed(html)
    p.close()
    return p


def _run_handlers(handlers, function_names):
    """Run each inline handler as the browser does (the attribute is already decoded). Returns,
    per handler, the calls it made to the named page functions and how often it ran pwn()."""
    stubs = ''.join('function %s(){ __calls.push([%s].concat([].slice.call(arguments))); }\n'
                    % (n, json.dumps(n)) for n in function_names)
    program = ('var __res = [];\n' + json.dumps(handlers) + '.forEach(function(code){\n'
               '  var __calls = [], __pwned = 0, __err = null;\n'
               '  function pwn(){ __pwned++; }\n' + stubs +
               '  try { (function(){ eval(code); }).call("THIS"); } catch(e) { __err = String(e); }\n'
               '  __res.push({calls: __calls, pwned: __pwned, err: __err});\n'
               '});\nconsole.log(JSON.stringify(__res));\n')
    return _run(program)


def _handlers(page):
    return [(tag, k, v) for tag, attrs in page.tags for k, v in attrs.items() if k.startswith('on')]


# ── the helpers ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('const,helper', [('ACTIVE_STREAMS_VIEWER_HTML', 'escapeHtml'),
                                          ('STREAM_ACCESS_HTML', 'esc')])
def test_the_escape_helper_covers_all_five_characters(const, helper):
    page_html = getattr(_overlay(), const)
    assert _helper(page_html, helper, FIVE) == FIVE_ESCAPED
    assert _helper(page_html, helper, None) == ''


# ── 1. Active Streams ────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('name', HOSTILE + PLAIN)
def test_a_stream_name_is_text_and_watch_and_share_get_the_exact_name(name):
    ov = _overlay()
    out = _render(ov.ACTIVE_STREAMS_VIEWER_HTML,
                  {'/api/viewer/streams': {'streams': [{'name': name, 'ready': True, 'visibility': 'private'}]}})
    assert out['pwned'] == 0
    page = _parse(out['html']['content'])
    # The row is the same for every name: no element and no attribute that the name brought.
    assert [t for t, _ in page.tags] == ['table', 'thead', 'tr', 'th', 'th', 'th', 'tbody', 'tr', 'td',
                                         'span', 'span', 'span', 'td', 'td', 'button', 'span', 'button']
    buttons = [a for t, a in page.tags if t == 'button']
    assert [sorted(a) for a in buttons] == [['class', 'onclick'], ['class', 'onclick']]
    assert name in page.text
    handlers = _handlers(page)
    assert [(t, k) for t, k, _ in handlers] == [('button', 'onclick'), ('button', 'onclick')]
    res = _run_handlers([v for _, _, v in handlers], ['watchStream', 'shareStream'])
    assert [r['err'] for r in res] == [None, None]
    assert [r['pwned'] for r in res] == [0, 0]
    assert res[0]['calls'] == [['watchStream', name]]
    assert res[1]['calls'] == [['shareStream', name, 'private', 'THIS']]


@pytest.mark.parametrize('vis', ["public');pwn();//", 'x" onmouseover="pwn()', "\\');pwn();//"])
def test_the_visibility_value_cannot_leave_the_share_handler(vis):
    ov = _overlay()
    out = _render(ov.ACTIVE_STREAMS_VIEWER_HTML,
                  {'/api/viewer/streams': {'streams': [{'name': 'cam1', 'ready': True, 'visibility': vis}]}})
    page = _parse(out['html']['content'])
    handlers = _handlers(page)
    assert [(t, k) for t, k, _ in handlers] == [('button', 'onclick'), ('button', 'onclick')]
    res = _run_handlers([v for _, _, v in handlers], ['watchStream', 'shareStream'])
    assert [r['pwned'] for r in res] == [0, 0] and [r['err'] for r in res] == [None, None]
    assert res[1]['calls'] == [['shareStream', 'cam1', vis, 'THIS']]


# ── 2. Stream Access ─────────────────────────────────────────────────────────────────────────

def _access(users, groups, group_pks=None):
    ov = _overlay()
    out = _render(ov.STREAM_ACCESS_HTML, {'/api/stream-access/users': {
        'users': users, 'available_groups': groups, 'group_pks': group_pks or {}, 'admin_group_pk': 7}})
    assert out['pwned'] == 0
    return _parse(out['html']['content'])


_ACCESS_FUNCS = ['sortBy', 'toggleRole', 'toggleGroup', 'openEdit', 'toggleActive', 'openDelete']


@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_a_user_row_is_text_and_its_buttons_get_the_exact_values(value):
    user = {'pk': value, 'username': value, 'name': value, 'email': value, 'groups': [value],
            'role': 'viewer', 'is_active': True}
    page = _access([user], [value])
    # Same row for every value: 4 sortable headers, role badge, one group badge, 3 buttons.
    assert [t for t, _ in page.tags].count('button') == 3
    assert not [t for t, _ in page.tags if t in ('img', 'script', 'iframe', 'svg')]
    handlers = _handlers(page)
    assert [(t, k) for t, k, _ in handlers] == [('th', 'onclick')] * 4 + [('span', 'onclick')] * 2 + \
        [('button', 'onclick')] * 3
    for tag, attrs in page.tags:
        assert set(attrs) <= {'class', 'onclick', 'style'}, (tag, attrs)
    assert page.text.count(value) >= 3          # username, name, email
    res = _run_handlers([v for _, _, v in handlers], _ACCESS_FUNCS)
    assert [r['err'] for r in res] == [None] * 9
    assert [r['pwned'] for r in res] == [0] * 9
    calls = [r['calls'] for r in res[4:]]
    assert calls == [[['toggleRole', 'THIS', value, False]],
                     [['toggleGroup', 'THIS', value, value, True]],
                     [['openEdit', value]],
                     [['toggleActive', value, False]],
                     [['openDelete', value]]]


def test_a_normal_user_row_still_works():
    user = {'pk': 42, 'username': 'alice', 'name': 'Alice', 'email': 'a@example.org',
            'groups': ['vid_private'], 'role': 'admin', 'is_active': False}
    page = _access([user], ['vid_private', 'vid_public'], {'vid_private': 'g1', 'vid_public': 'g2'})
    badges = [a['class'] for t, a in page.tags if t == 'span' and 'gbadge' in a.get('class', '')]
    assert badges == ['gbadge on vid_private', 'gbadge off vid_public']
    assert 'private' in page.text and 'public' in page.text
    handlers = _handlers(page)
    res = _run_handlers([v for _, _, v in handlers], _ACCESS_FUNCS)
    assert [r['calls'][0] for r in res[4:]] == [
        ['toggleRole', 'THIS', '42', True],
        ['toggleGroup', 'THIS', '42', 'vid_private', True],
        ['toggleGroup', 'THIS', '42', 'vid_public', False],
        ['openEdit', '42'],
        ['toggleActive', '42', True],
        ['openDelete', '42'],
    ]


# ── 3. /viewer, filled in by the server ──────────────────────────────────────────────────────

flask = pytest.importorskip('flask')


def _viewer(monkeypatch, username, theme=None):
    ov = _overlay()
    real_open = builtins.open

    def fake_open(path, *a, **kw):
        if str(path).endswith('theme_config.json'):
            if theme is None:
                raise FileNotFoundError(path)
            return io.StringIO(json.dumps(theme))
        return real_open(path, *a, **kw)
    monkeypatch.setattr(ov, 'open', fake_open, raising=False)
    app = flask.Flask('overlay-ops897')
    app.secret_key = 'test'
    ov.apply_ldap_overlay(app)
    r = app.test_client().get('/viewer', headers={'X-Authentik-Username': username,
                                                  'X-Authentik-Groups': 'vid_public'})
    assert r.status_code == 200
    return r.get_data(as_text=True)


def _static_shape(html):
    """Tags and attribute names outside the page script (the script is not HTML)."""
    page = _parse(html[:html.index('<script>\n')])
    return [(t, sorted(a)) for t, a in page.tags], page


@pytest.mark.parametrize('username', HOSTILE + ['alice', "o'brien", '{{HEADER_TITLE}}'])
def test_the_username_is_text_on_the_viewer_page(monkeypatch, username):
    want, _ = _static_shape(_viewer(monkeypatch, 'alice'))
    got, page = _static_shape(_viewer(monkeypatch, username))
    assert got == want
    assert username in page.text


@pytest.mark.parametrize('value', ['<script>pwn()</script>', '</title><img src=x onerror=pwn()>',
                                   'Agency & "Video" <1>'])
def test_the_title_and_subtitle_are_text_on_the_viewer_page(monkeypatch, value):
    want, _ = _static_shape(_viewer(monkeypatch, 'alice'))
    got, page = _static_shape(_viewer(monkeypatch, 'alice', {'headerTitle': value, 'subtitle': value}))
    assert got == want
    assert page.text.count(value) == 3          # <title>, <h1> and the subtitle


@pytest.mark.parametrize('colour,kept', [
    ('#0f766e', True), ('#fff', True), ('rebeccapurple', True), ('rgb(30, 58, 138)', True),
    ('hsl(210 50% 40% / 0.8)', True),
    ('red}</style><script>pwn()</script>', False), ('url(https://x.example/a)', False),
    ('#1e3a8a;}body{display:none', False), ('', False),
])
def test_a_theme_colour_is_a_plain_css_colour_or_the_default(monkeypatch, colour, kept):
    html = _viewer(monkeypatch, 'alice', {'headerColor': colour, 'headerColorEnd': colour,
                                          'accentColor': colour})
    want, _ = _static_shape(_viewer(monkeypatch, 'alice'))
    got, _ = _static_shape(html)
    assert got == want
    style = html[html.index('<style>'):html.index('</style>')]
    if kept:
        assert 'linear-gradient(135deg,%s 0%%,%s 100%%)' % (colour, colour) in style
        assert 'border-top-color:%s;' % colour in style
    else:
        assert 'linear-gradient(135deg,#1e3a8a 0%,#1e293b 100%)' in style
        assert 'border-top-color:#3b82f6;' in style
