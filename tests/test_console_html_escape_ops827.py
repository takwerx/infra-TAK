# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #827: text that somebody else chooses must reach a console page as text only.

Four console pages built HTML from a name that the admin does not control:

  1. a WiFi network name            templates/connectivity.html  scanWifi()
  2. a TAK group name               static/takserver.js          loadGroups()
  3. an Authentik username          templates/authentik.html     renderMfaRow()
  4. a module version string        templates/console.html       refreshModuleVersions()
                                    templates/remote_assist.html refreshRaVersion()

Each name has to stay text. These tests run the page's own JavaScript in node with a small stand-in for the
browser, give it hostile names, then read the HTML it built with Python's HTML parser (which
decodes attributes the way a browser does). A pass needs both halves: nothing is injected, and
the name still works (the right group, the right user, the right network).

The stand-in's createElement escapes & < > only, as a browser's textContent/innerHTML pair does,
so the old helpers behave here as they did in the browser.
"""
import json
import pathlib
import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIVE = '&<>"\''
FIVE_ESCAPED = '&amp;&lt;&gt;&quot;&#39;'

# Names that try each way out: close the JavaScript string through an entity, close the
# attribute with a quote, open a new element, and plain names that must keep working.
HOSTILE = [
    '&quot;);pwn();//',
    'x" onmouseover="pwn()',
    "x' onmouseover='pwn()",
    '<img src=x onerror=pwn()>',
    'a"b<c>&d\'e\\f',
    '&amp;&lt;b&gt;',
]
PLAIN = ['Field Kit 5G', "Chief's iPhone", 'tak_ops']

BROWSER = r'''
var __els = {}, __missing = [], __fetch = {}, __pwned = 0;
function pwn(){ __pwned++; }
function __el(id){
  if(!__els[id]) __els[id] = {id:id, innerHTML:'', textContent:'', title:'', value:'', disabled:false,
    style:{}, classList:{add:function(){}, remove:function(){}},
    setAttribute:function(){}, getAttribute:function(){ return null; }};
  return __els[id];
}
var document = {
  getElementById: function(id){ return __missing.indexOf(id) >= 0 ? null : __el(id); },
  createElement: function(){
    var t = '';
    return {
      set textContent(v){ t = (v == null ? '' : String(v)); },
      get textContent(){ return t; },
      get innerHTML(){ return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    };
  }
};
function fetch(url){
  var key = String(url).split('?')[0];
  return Promise.resolve({ok:true, status:200, json:function(){ return Promise.resolve(__fetch[key]); }});
}
function __out(extra){
  var o = {pwned: __pwned, html: {}};
  for(var k in __els) o.html[k] = __els[k].innerHTML;
  for(var e in (extra || {})) o[e] = extra[e];
  console.log(JSON.stringify(o));
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


def _read(rel):
    return (ROOT / rel).read_text(encoding='utf-8')


def _function(src, name, required=True):
    """A top-level function, from its first line to the closing brace in column 0 (or the whole
    line when it is written on one line)."""
    lines = src.split('\n')
    for i, line in enumerate(lines):
        if re.match(r'(async\s+)?function\s+%s\s*\(' % re.escape(name), line):
            if line.rstrip().endswith('}') and line.count('{') == line.count('}'):
                return line
            for j in range(i + 1, len(lines)):
                if lines[j].rstrip() == '}':
                    return '\n'.join(lines[i:j + 1])
    assert not required, 'function %s not found' % name
    return ''


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
               '  try { eval(code); } catch(e) { __err = String(e); }\n'
               '  __res.push({calls: __calls, pwned: __pwned, err: __err});\n'
               '});\nconsole.log(JSON.stringify(__res));\n')
    return _run(program)


# ── the shared helper ────────────────────────────────────────────────────────────────────────

_HELPER_NAMES = r'(?:escapeHtml|escAttr|\w*Esc|_esc|esc)'
_HELPER_DEF = re.compile(r'^\s*(?:function\s+(%s)\s*\(|(?:var|const|let)\s+(%s)\s*=\s*function\b)'
                         % (_HELPER_NAMES, _HELPER_NAMES))
_CONSOLE_FILES = (sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'templates').glob('*.html'))
                  + sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'static').glob('*.js'))
                  + ['app.py'])


def _helper_defs(rel):
    """(line number, name, source) of every escape helper defined in a console file."""
    lines = _read(rel).split('\n')
    out = []
    for i, line in enumerate(lines):
        m = _HELPER_DEF.match(line)
        if not m:
            continue
        j, depth, seen = i, 0, False
        while j < len(lines):
            depth += lines[j].count('{') - lines[j].count('}')
            seen = seen or '{' in lines[j]
            if seen and depth <= 0:
                break
            j += 1
        out.append((i + 1, m.group(1) or m.group(2), '\n'.join(lines[i:j + 1])))
    return out


def test_no_console_escape_helper_is_built_on_textcontent():
    """The old helper (textContent in, innerHTML out) leaves both quotes alone, so its result is
    not safe inside an attribute. None may remain in a console page."""
    old = re.compile(r'textContent\s*=[^;\n]*;\s*return\s+[\w.]+\.innerHTML')
    found = []
    for rel in _CONSOLE_FILES:
        for n, line in enumerate(_read(rel).split('\n'), 1):
            if old.search(line):
                found.append('%s:%d' % (rel, n))
    assert not found, 'escape helper that does not escape quotes: ' + ', '.join(found)


def test_every_console_escape_helper_escapes_all_five_characters():
    checked = []
    for rel in _CONSOLE_FILES:
        defs = _helper_defs(rel)
        if not defs:
            continue
        # Helpers in one file may call each other (escAttr -> esc -> escapeHtml), so load a file's
        # helpers together, then ask each one. A later definition of a name wins, as in the page.
        body = '\n'.join(src for _, _, src in defs)
        names = sorted({name for _, name, _ in defs})
        program = (BROWSER + body + '\nvar __r = {};\n'
                   + ''.join('__r[%s] = [%s(%s), %s(7)];\n' % (json.dumps(n), n, json.dumps(FIVE), n)
                             for n in names)
                   + 'console.log(JSON.stringify(__r));\n')
        for name, got in _run(program).items():
            assert got == [FIVE_ESCAPED, '7'], '%s %s() returned %r' % (rel, name, got)
            checked.append((rel, name))
    # The four pages of ops #827 each have their helper, and it was looked at.
    for want in (('templates/console.html', 'escapeHtml'), ('templates/authentik.html', 'escapeHtml'),
                 ('static/takserver.js', 'escapeHtml'), ('templates/connectivity.html', 'esc'),
                 ('templates/remote_assist.html', 'raEsc'), ('app.py', 'esc')):
        assert want in checked, 'no escape helper checked for %s %s' % want


# ── 1. WiFi network name ─────────────────────────────────────────────────────────────────────

def _wifi_scan_html(names):
    src = _read('templates/connectivity.html')
    program = (BROWSER + _function(src, 'esc') + '\n' + _function(src, 'jsArg', required=False) + '\n'
               + 'function refreshWifiSaved(){}\n' + _function(src, 'scanWifi') + '\n'
               + '__fetch["/api/connectivity/wifi/scan"] = %s;\n'
               % json.dumps({'networks': [{'ssid': n, 'signal': '70'} for n in names]})
               + 'scanWifi().then(function(){ __out(); });\n')
    return _run(program)['html']['wifi-scan-list']


@pytest.mark.parametrize('name', HOSTILE + PLAIN)
def test_wifi_name_is_text_and_can_still_be_picked(name):
    page = _parse(_wifi_scan_html([name]))
    buttons = [a for t, a in page.tags if t == 'button']
    assert [t for t, _ in page.tags] == ['button', 'span'], page.tags
    assert len(buttons) == 1
    assert set(buttons[0]) == {'type', 'class', 'style', 'onclick'}, buttons[0]
    assert ''.join(page.text) == name + ' · 70'
    got = _run_handlers([buttons[0]['onclick']], ['pickWifi'])[0]
    assert got == {'calls': [['pickWifi', name]], 'pwned': 0, 'err': None}, got


def test_wifi_scan_list_keeps_every_network():
    names = HOSTILE + PLAIN
    page = _parse(_wifi_scan_html(names))
    buttons = [a for t, a in page.tags if t == 'button']
    assert len(buttons) == len(names)
    got = _run_handlers([b['onclick'] for b in buttons], ['pickWifi'])
    assert [g['calls'] for g in got] == [[['pickWifi', n]] for n in names]
    assert not any(g['pwned'] or g['err'] for g in got), got


def test_saved_wifi_and_reach_buttons_use_the_same_safe_argument():
    """Known Networks (Use, Remove) and Copy URL build inline handlers the same way."""
    src = _read('templates/connectivity.html')
    assert 'JSON.stringify(' not in re.sub(r'function jsArg\(v\)\{[^\n]*', '', src).replace(
        'body: JSON.stringify(', '').replace('body:JSON.stringify(', ''), \
        'an inline handler argument is built without jsArg()'
    program = (BROWSER + _function(src, 'esc') + '\n' + _function(src, 'jsArg') + '\n'
               + 'console.log(JSON.stringify(%s.map(jsArg)));\n' % json.dumps(HOSTILE + PLAIN))
    for name, arg in zip(HOSTILE + PLAIN, _run(program)):
        page = _parse('<button onclick="useWifi(%s)">Use</button>' % arg)
        assert [(t, set(a)) for t, a in page.tags] == [('button', {'onclick'})]
        got = _run_handlers([page.tags[0][1]['onclick']], ['useWifi'])[0]
        assert got == {'calls': [['useWifi', name]], 'pwned': 0, 'err': None}, got


# ── 2. TAK group name ────────────────────────────────────────────────────────────────────────

def _groups_html(reply):
    src = _read('static/takserver.js')
    program = (BROWSER + _function(src, 'escapeHtml') + '\n' + _function(src, 'loadGroups') + '\n'
               + '__fetch["/api/takserver/groups"] = %s;\n' % json.dumps(reply)
               + 'loadGroups().then(function(){ __out(); });\n')
    return _run(program)['html']['cc-groups-list']


@pytest.mark.parametrize('name', ['tak_' + n for n in HOSTILE] + PLAIN)
def test_tak_group_name_is_text_and_keeps_its_exact_name(name):
    page = _parse(_groups_html({'groups': [{'name': name}]}))
    assert {t for t, _ in page.tags} == {'div', 'input'}, page.tags
    boxes = [a for t, a in page.tags if t == 'input']
    assert [b['class'] for b in boxes] == ['cc-grp-read', 'cc-grp-write', 'cc-grp-both']
    for b in boxes:
        assert set(b) == {'type', 'class', 'data-group', 'style', 'onchange'}, b
        # createClientCert() reads this attribute, so it must be the group's exact name.
        assert b['data-group'] == name
    assert page.text[-1] == name


def test_tak_group_error_text_is_text():
    page = _parse(_groups_html({'error': '<img src=x onerror=pwn()>" onmouseover="pwn()', 'groups': []}))
    assert [(t, set(a)) for t, a in page.tags] == [('span', {'style'}), ('button', {'type', 'onclick', 'style'})]
    assert page.text[0] == '<img src=x onerror=pwn()>" onmouseover="pwn()'


@pytest.mark.parametrize('name', ['tak_a"b', 'tak_a\\b', "tak_a'b", 'tak_a]b', 'tak_ok'])
def test_both_box_ticks_read_and_write_for_any_group_name(name):
    """The BOTH box finds its row's READ and WRITE boxes. Built from the name, the selector threw
    for a name with a quote or a backslash, so the row did nothing."""
    src = _read('static/takserver.js')
    program = (BROWSER + r'''
var __boxes = [];
function __box(cls, grp){ var b = {cls:cls, grp:grp, checked:false,
  getAttribute:function(a){ return a === 'data-group' ? this.grp : null; }}; __boxes.push(b); return b; }
document.querySelectorAll = function(sel){
  var m = /^\.([\w-]+)$/.exec(sel); if(!m) throw new SyntaxError('selector ' + sel);
  return __boxes.filter(function(b){ return b.cls === m[1]; });
};
document.querySelector = function(sel){
  // A browser reads the quoted value as a CSS string: a bare quote ends it and a backslash escapes.
  var m = /^\.([\w-]+)\[data-group="([^"\\]*)"\]$/.exec(sel);
  if(!m) throw new SyntaxError("'" + sel + "' is not a valid selector");
  return __boxes.filter(function(b){ return b.cls === m[1] && b.grp === m[2]; })[0] || null;
};
''' + _function(src, 'ccGroupChanged') + '\n'
               + 'var other = [__box("cc-grp-read","tak_other"), __box("cc-grp-write","tak_other"), __box("cc-grp-both","tak_other")];\n'
               + 'var name = %s;\n' % json.dumps(name)
               + 'var r = __box("cc-grp-read", name), w = __box("cc-grp-write", name), b = __box("cc-grp-both", name);\n'
               + 'b.checked = true; ccGroupChanged(b, "both");\n'
               + 'var first = [r.checked, w.checked];\n'
               + 'r.checked = false; ccGroupChanged(r, "read");\n'
               + '__out({first:first, both:b.checked, other:other.map(function(o){ return o.checked; })});\n')
    got = _run(program)
    assert got['first'] == [True, True] and got['both'] is False and got['other'] == [False, False, False], got


# ── 3. Authentik username ────────────────────────────────────────────────────────────────────

def _mfa_row_html(user):
    src = _read('templates/authentik.html')
    program = (BROWSER + _function(src, 'escapeHtml') + '\n' + _function(src, 'renderMfaRow') + '\n'
               + '__out({row: renderMfaRow(%s)});\n' % json.dumps(user))
    return _run(program)['row']


@pytest.mark.parametrize('name', HOSTILE + ['x" style="position:fixed;inset:0;z-index:9999" onmouseover="pwn()',
                                            'jane.doe', "o'brien"])
def test_authentik_username_is_text_and_revoke_gets_the_exact_name(name):
    user = {'pk': 7, 'username': name, 'email': 'a&b"c@example.org', 'is_active': True, 'device_count': 1,
            'devices': [{'label': 'TOTP "phone" <b>'}]}
    page = _parse(_mfa_row_html(user))
    assert {t for t, _ in page.tags} == {'div', 'span', 'button'}, page.tags
    row = page.tags[0]
    assert row[0] == 'div' and set(row[1]) == {'id', 'data-username', 'style'}, row
    # mfaConfirm() and mfaReset() read the username back from this attribute.
    assert row[1]['data-username'] == name
    for tag, attrs in page.tags[1:]:
        assert set(attrs) <= {'id', 'style', 'type', 'onclick'}, (tag, attrs)
    assert name in page.text and 'TOTP "phone" <b>' in page.text
    button = [a for t, a in page.tags if t == 'button'][0]
    assert button['onclick'] == 'mfaConfirm(7)'


# ── 4. module version strings ────────────────────────────────────────────────────────────────

def _versions_html(data):
    src = _read('templates/console.html')
    program = (BROWSER + _function(src, 'escapeHtml') + '\n' + _function(src, 'refreshModuleVersions') + '\n'
               + '__fetch["/api/modules/version"] = %s;\n' % json.dumps(data)
               + 'refreshModuleVersions();\nsetTimeout(function(){ __out(); }, 20);\n')
    out = _run(program)
    assert out['pwned'] == 0
    return {k[len('module-version-'):]: v for k, v in out['html'].items()}


def test_module_version_badges_show_hostile_versions_as_text():
    bad = '1.0.0"><img src=x onerror=pwn()><span title=\'x'
    html = _versions_html({
        'nodered': {'version': bad},
        'authentik': {'version': '2026.8.5', 'channel': 'dev', 'vetted_release': bad, 'update_available': True},
        'netbird': {'version': '0.80.0', 'channel': 'dev', 'vetted': bad},
        'webodm': {'version': '3.2.1', 'ahead_of_vetted': True},
        'cloudtak': {'version': '13.119.0', 'node_security': bad},
        'fedhub': {'version': bad, 'update_available': True},
    })
    for key, h in html.items():
        page = _parse(h)
        assert {t for t, _ in page.tags} <= {'span'}, (key, page.tags)
        for _, attrs in page.tags:
            assert set(attrs) <= {'style', 'title'}, (key, attrs)
    assert _parse(html['nodered']).text == ['v' + bad]
    assert _parse(html['fedhub']).text == ['v' + bad + ' ', 'update']
    auth = _parse(html['authentik'])
    assert auth.tags[0][1]['title'] == 'Dev channel — main is pinned at v' + bad
    assert auth.text[:2] == ['v2026.8.5 ', '· main: v' + bad]
    assert _parse(html['netbird']).tags[0][1]['title'] == 'Dev channel — main is pinned at v' + bad
    assert _parse(html['cloudtak']).tags[-1][1]['title'] == bad


def test_module_version_badges_still_show_for_normal_versions():
    html = _versions_html({
        'caddy': {'version': 'v2.10.2', 'update_available': True},
        'mediamtx': {'version': 'MediaMTX v1.15.3 · editor v2.4.0'},
        'netbird': {'version': '0.80.0 · dash v2.14.0', 'vetted': '0.80.0'},
        'takserver': {'version': '5.8-RELEASE12'},
        'cloudtak': {'version': '13.119.0', 'latest': '13.119.0'},
        'authentik': {'version': '2026.8.5', 'vetted_release': '2026.8.5'},
    })
    text = {k: ''.join(_parse(h).text) for k, h in html.items()}
    assert text == {
        'caddy': 'vv2.10.2 update',
        'mediamtx': 'MediaMTX v1.15.3 · editor v2.4.0',
        'netbird': 'v0.80.0 · dash v2.14.0 vetted ✓',
        'takserver': 'v5.8-RELEASE12',
        'cloudtak': 'v13.119.0 latest ✓',
        'authentik': 'v2026.8.5 vetted ✓',
    }


def test_remote_assist_page_shows_hostile_versions_as_text():
    src = _read('templates/remote_assist.html')
    bad = '1.2.3"><img src=x onerror=pwn()>'
    program = (BROWSER + _function(src, 'raEsc', required=False) + '\n' + _function(src, 'refreshRaVersion') + '\n'
               + '__fetch["/api/remote-assist/version"] = %s;\n'
               % json.dumps({'version': bad, 'latest': bad, 'running': bad + 'r', 'update_available': True})
               + 'refreshRaVersion(false);\nsetTimeout(function(){ __out(); }, 20);\n')
    html = _run(program)['html']
    latest, inst = _parse(html['ra-latest-version']), _parse(html['ra-installed-version'])
    assert [(t, set(a)) for t, a in latest.tags] == [('span', {'id', 'style'})]
    assert latest.text == ['v' + bad + ' ', 'update ready']
    assert [(t, set(a)) for t, a in inst.tags] == [('span', {'style'})]
    assert inst.text == ['v' + bad + ' ', '(running v' + bad + 'r)']


# ── 4b. the server refuses a version that cannot be one ──────────────────────────────────────

def _version_code():
    app = _read('app.py')
    end = app.index("@app.route('/api/modules/version')")
    start = app.rfind('\n_MODULE_VERSION_RE = ', 0, end)
    if start < 0:
        start = app.rfind('\ndef get_all_module_versions():', 0, end)
    return app[start:end]


def _versions_from_server(infos):
    """get_all_module_versions() with every module installed and each helper returning infos[key]."""
    class _Mod:
        def __init__(self, key):
            self.key = key

        def get_version_info(self, _ctx):
            return infos[self.key]

    class _Registry:
        tvr, simulator = _Mod('tak_video_restreamer'), _Mod('simulator')

        @staticmethod
        def get_ctx():
            return {}

    ns = {'re': re, 'VERSION': '10.4.2-alpha', 'update_cache': {}, 'mod_registry': _Registry,
          'detect_modules': lambda: {k: {'installed': True} for k in list(infos) + ['guarddog']},
          '_node_card_gaps': lambda: {'nodered': 'gap'}, '_node_card_flag': lambda gap: 'Node.js is out of date',
          # ops #972: the Guard Dog card reads the stamped deploy version (Guard Dog is current here)
          'load_settings': lambda: {'guarddog_deployed_version': '10.4.2-alpha'}}
    for key in infos:
        ns['_get_%s_version_info' % key] = (lambda k: lambda: infos[k])(key)
    exec(compile(_version_code(), 'app.py', 'exec'), ns)
    return ns['get_all_module_versions']()


def test_server_drops_a_version_that_cannot_be_a_version():
    bad = '1.0.0"><img src=x onerror=alert(1)>'
    infos = {
        'nodered': {'version': bad, 'update_available': False},
        'fedhub': {'version': '5.8-RELEASE-12<script>', 'update_available': True, 'latest': None},
        'cloudtak': {'version': '13.119.0 onerror=x', 'latest': bad, 'vetted_release': bad},
        'takportal': {'version': '2.0.36', 'beta_version': bad, 'upstream_latest': bad, 'dev_release': bad,
                      'final_target': bad, 'upstream_url': 'https://example.org/releases/tag/v1'},
        'netbird': {'version': '0.80.0', 'vetted': bad, 'channel': 'dev'},
        'remote_assist': {'version': '1.4.0', 'running': bad, 'latest': '1.4.0', 'latest_tag': 'v1.4.0'},
    }
    got = _versions_from_server(infos)
    assert got['nodered'] == {'version': '', 'update_available': False, 'node_security': 'Node.js is out of date'}
    assert got['fedhub'] == {'version': '', 'update_available': True, 'latest': None}
    assert got['cloudtak'] == {'version': '', 'latest': '', 'vetted_release': ''}
    # Every version field is checked; a field that is not a version (a link) is left as it is.
    assert got['takportal'] == {'version': '2.0.36', 'beta_version': '', 'upstream_latest': '', 'dev_release': '',
                                'final_target': '', 'upstream_url': 'https://example.org/releases/tag/v1'}
    assert got['netbird'] == {'version': '0.80.0', 'vetted': '', 'channel': 'dev'}
    assert got['remote_assist'] == {'version': '1.4.0', 'running': '', 'latest': '1.4.0', 'latest_tag': 'v1.4.0'}
    # The helpers cache their dict; the check works on a copy.
    assert infos['nodered']['version'] == bad
    for info in got.values():
        for field, value in info.items():
            if field != 'upstream_url':
                assert not (isinstance(value, str) and re.search(r'[<>"\'&=()/]', value)), info


def test_server_keeps_every_real_version_shape():
    infos = {
        'caddy': {'version': 'v2.10.2', 'update_available': False, 'update_check_failed': False},
        'authentik': {'version': '2026.8.5', 'update_available': False, 'latest': None,
                      'vetted_release': '2026.8.5', 'channel': 'main'},
        'nodered': {'version': '4.1.17', 'update_available': False},
        'cloudtak': {'version': '13.119.0', 'update_available': False, 'latest': '13.119.0',
                     'vetted_release': '13.119.0', 'channel': 'main'},
        'mediamtx': {'version': '1.15.3', 'update_available': False, 'latest': '1.15.3',
                     'editor_version': '2.4.0', 'editor_update_available': False, 'editor_latest': '2.4.0',
                     'vetted_release': '1.15.3'},
        'takportal': {'version': '2.0.30', 'beta_version': '', 'channel': 'release', 'update_available': False},
        'takserver': {'version': '5.8-RELEASE12', 'update_available': False, 'latest': None},
        'fedhub': {'version': '1:5.8-RELEASE-12~rc1+b2', 'update_available': False, 'latest': None},
        'fail2ban': {'version': '1.1.0', 'update_available': False, 'latest': '1.1.0-1ubuntu0.1'},
        'webodm': {'version': '3.2.1', 'update_available': False, 'latest': '3.2.1'},
        'tak_video_restreamer': {'version': 'a1b2c3d', 'update_available': False, 'latest': 'a1b2c3d'},
        'simulator': {'version': '10.4.2-alpha', 'latest': '10.4.2-alpha', 'update_available': False},
        'netbird': {'version': '0.80.0 · dash v2.14.0', 'update_available': False, 'latest': None,
                    'vetted': '0.80.0'},
        'remote_assist': {'version': '3.4.1', 'update_available': False, 'latest': '3.4.1',
                          'latest_tag': 'eud_3.4.1', 'running': '3.4.1', 'is_current': True},
    }
    # Shapes a fleet box returned on Tue Nov 17, 2026: a -dev editor, a distro package version.
    infos['mediamtx'].update(editor_version='2.1.16-dev', upstream_latest='1.21.4',
                             upstream_url='https://github.com/bluenviron/mediamtx/releases/tag/v1.21.4')
    infos['fail2ban']['latest'] = '1.0.2-3ubuntu0.1'
    infos['netbird'].update(version='0.82.1 · dash 2.96.0', upstream_latest='0.83.1')
    infos['authentik'].update(dev_release='2026.8.5', final_target='2026.8.5', env_tag='')
    got = _versions_from_server(infos)
    want = {k: dict(v) for k, v in infos.items()}
    want['mediamtx']['version'] = 'MediaMTX v1.15.3 · editor v2.1.16-dev'
    want['nodered']['node_security'] = 'Node.js is out of date'
    want['guarddog'] = {'version': '10.4.2-alpha', 'update_available': False, 'latest': None}
    assert got == want
