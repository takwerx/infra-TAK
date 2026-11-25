# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #897 (item 3): a value from the server must reach these console pages as text only.

Five places built HTML, or the argument of an inline handler, from a value with hand-made quotes:

  1. a snapshot label             templates/takserver.html   loadSnapshots()
  2. a truststore alias           static/takserver.js        loadCAInfo()
  3. a plugin class and jar name  static/takserver.js        loadPlugins()
  4. an address                   templates/fail2ban.html    renderChips(), renderAuthBanList(), the
                                                             other ban and watch lists
  5. server message text          templates/console.html     doConsoleRollback(), applyUpdate()

These tests run each page's own JavaScript in node with a small stand-in for the browser, give
it hostile values, then read the HTML it built with Python's HTML parser (which decodes
attributes the way a browser does). A pass needs both halves: nothing is injected, and the value
still works (Restore gets the exact label, Unban gets the exact address).
"""
import json
import pathlib
import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Each way out: close the JavaScript string with a quote, through a backslash or through an
# entity, close the attribute with a quote, open a new element. None has a space in it, so the
# same list also goes through the whitelist box of the Fail2ban page (it splits on spaces).
HOSTILE = [
    "x');pwn();//",
    "x\\');pwn();//",
    '&#39;);pwn();//',
    '&quot;);pwn();//',
    'x"onmouseover="pwn()',
    "x'onmouseover='pwn()",
    '<img/src=x/onerror=pwn()>',
    'a"b<c>&d\'e\\f',
]
PLAIN = ['203.0.113.7', '2001:db8::1', 'pre-upgrade-5.8', 'com.example.Plugin']

BROWSER = r'''
var window = globalThis;
var __els = {}, __fetch = {}, __pwned = 0;
function pwn(){ __pwned++; }
function __el(id){
  if(!__els[id]) __els[id] = {id:id, innerHTML:'', textContent:'', title:'', value:'', disabled:false,
    style:{}, classList:{add:function(){}, remove:function(){}},
    setAttribute:function(){}, getAttribute:function(){ return null; }};
  return __els[id];
}
var document = { getElementById: function(id){ return __el(id); } };
function confirm(){ return true; }
window.prompt = function(){ return 'pw'; };
function fetch(url){
  var key = String(url).split('?')[0];
  return Promise.resolve({ok:true, status:200, json:function(){ return Promise.resolve(__fetch[key]); }});
}
function __out(){
  var o = {pwned: __pwned, html: {}};
  for(var k in __els) o.html[k] = __els[k].innerHTML;
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


def _clicks(page):
    return [a['onclick'] for t, a in page.tags if t == 'button' and 'onclick' in a]


def _only_these_attributes(page, allowed):
    """No value may add an attribute (an event handler, a style) to any element."""
    for tag, attrs in page.tags:
        assert set(attrs) <= allowed, (tag, attrs)


# The takserver page loads static/takserver.js, so its helpers are the page's helpers. The new
# helper is loaded only when the tree has it: on the old code the old functions run and the
# tests fail on what they return.
def _tak_helpers():
    js = _read('static/takserver.js')
    return _function(js, 'escapeHtml') + '\n' + _function(js, 'jsArg', required=False) + '\n'


# ── 1. snapshot label ────────────────────────────────────────────────────────────────────────

def _snapshots_html(snaps):
    program = (BROWSER + _tak_helpers() + _function(_read('templates/takserver.html'), 'loadSnapshots') + '\n'
               + '__fetch["/api/takserver/snapshots"] = %s;\n' % json.dumps({'snapshots': snaps})
               + 'loadSnapshots(); setTimeout(__out, 20);\n')
    out = _run(program)
    assert out['pwned'] == 0
    return out['html']['snap-table-container']


@pytest.mark.parametrize('label', HOSTILE + PLAIN)
def test_snapshot_label_is_text_and_each_button_gets_the_exact_label(label):
    page = _parse(_snapshots_html([{'label': label, 'taken_at': '2026-11-25T10:00:00Z', 'source': 'manual',
                                    'tak_version': '5.8', 'size_mb': 12}]))
    assert {t for t, _ in page.tags} == {'div', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'button'}, page.tags
    _only_these_attributes(page, {'style', 'class', 'onclick'})
    assert label in page.text
    got = _run_handlers(_clicks(page), ['restoreSnapshot', 'downloadSnapshot', 'deleteSnapshot'])
    assert got == [{'calls': [[fn, label]], 'pwned': 0, 'err': None}
                   for fn in ('restoreSnapshot', 'downloadSnapshot', 'deleteSnapshot')], got


@pytest.mark.parametrize('field', ['taken_at', 'source', 'tak_version', 'size_mb'])
def test_other_snapshot_columns_are_text(field):
    bad = '<img src=x onerror=pwn()>'
    snap = {'label': 'ok', 'taken_at': '2026-11-25T10:00:00Z', 'source': 'manual', 'tak_version': '5.8', 'size_mb': 12}
    snap[field] = bad
    page = _parse(_snapshots_html([snap]))
    assert 'img' not in {t for t, _ in page.tags}, page.tags
    assert any(bad in t for t in page.text), page.text


# ── 2. truststore alias ──────────────────────────────────────────────────────────────────────

def _old_ca_html(aliases, names=None):
    program = (BROWSER + _tak_helpers() + 'function validateCaName(){}\n'
               + _function(_read('static/takserver.js'), 'loadCAInfo') + '\n'
               + '__fetch["/api/takserver/ca-info"] = %s;\n'
               % json.dumps({'old_cas_in_truststore': aliases, 'old_ca_names': names or {}})
               + 'loadCAInfo().then(__out, __out);\n')
    out = _run(program)
    assert out['pwned'] == 0
    return out['html']['revoke-ca-list']


@pytest.mark.parametrize('alias', HOSTILE + PLAIN)
def test_truststore_alias_is_text_and_revoke_gets_the_exact_alias(alias):
    page = _parse(_old_ca_html([alias], {alias: 'CN of ' + alias}))
    assert [t for t, _ in page.tags] == ['div', 'span', 'button'], page.tags
    _only_these_attributes(page, {'style', 'type', 'onclick'})
    assert page.text[0] == '%s (CN of %s)' % (alias, alias)
    got = _run_handlers(_clicks(page), ['revokeOldCA'])
    assert got == [{'calls': [['revokeOldCA', alias]], 'pwned': 0, 'err': None}], got


# ── 3. plugin class and jar names ────────────────────────────────────────────────────────────

def _plugins_html(plugins):
    program = (BROWSER + _tak_helpers() + _function(_read('static/takserver.js'), 'loadPlugins') + '\n'
               + '__fetch["/api/takserver/plugins/list"] = %s;\n' % json.dumps({'plugins': plugins})
               + 'loadPlugins(); setTimeout(__out, 20);\n')
    out = _run(program)
    assert out['pwned'] == 0
    return out['html']['tak-plugins-list']


@pytest.mark.parametrize('name', HOSTILE + PLAIN)
def test_plugin_names_are_text_and_each_button_gets_the_exact_name(name):
    jar = name + '.jar'
    page = _parse(_plugins_html([{'jar': jar, 'classname': name, 'has_config': True}]))
    assert {t for t, _ in page.tags} == {'div', 'span', 'button', 'textarea'}, page.tags
    _only_these_attributes(page, {'style', 'type', 'onclick', 'id', 'spellcheck'})
    assert jar in page.text and name + '.yaml' in page.text
    # takPluginToggleConfig() and takPluginSaveConfig() find these three by the exact class name.
    ids = [a['id'] for _, a in page.tags if 'id' in a]
    assert ids == ['tak-plugin-cfg-' + name, 'tak-plugin-cfg-txt-' + name, 'tak-plugin-cfg-msg-' + name]
    got = _run_handlers(_clicks(page), ['takPluginToggleConfig', 'takPluginRemove', 'takPluginSaveConfig'])
    assert got == [{'calls': [['takPluginToggleConfig', name]], 'pwned': 0, 'err': None},
                   {'calls': [['takPluginRemove', jar]], 'pwned': 0, 'err': None},
                   {'calls': [['takPluginSaveConfig', name]], 'pwned': 0, 'err': None}], got


# ── 4. Fail2ban addresses ────────────────────────────────────────────────────────────────────

def _f2b_helpers():
    src = _read('templates/fail2ban.html')
    return (_function(src, 'f2bEsc', required=False) + '\n' + _function(src, 'f2bArg', required=False) + '\n'
            + _function(src, '_authIpToNum') + '\n')


@pytest.mark.parametrize('ip', HOSTILE + PLAIN)
def test_whitelist_chip_is_text_and_remove_gets_the_exact_value(ip):
    src = _read('templates/fail2ban.html')
    program = (BROWSER + _f2b_helpers() + _function(src, 'renderChips') + '\n'
               + '__el("in").value = %s;\nrenderChips("in", "chips"); __out();\n' % json.dumps(ip))
    out = _run(program)
    page = _parse(out['html']['chips'])
    assert [t for t, _ in page.tags] == ['span', 'button'], page.tags
    _only_these_attributes(page, {'class', 'title', 'onclick'})
    assert page.text[0] == ip
    got = _run_handlers(_clicks(page), ['removeChip'])
    assert got == [{'calls': [['removeChip', 'in', 'chips', ip]], 'pwned': 0, 'err': None}], got


@pytest.mark.parametrize('ip', HOSTILE + PLAIN)
def test_banned_address_is_text_and_unban_gets_the_exact_address(ip):
    src = _read('templates/fail2ban.html')
    program = (BROWSER + 'window._authSortAsc = true;\n' + _f2b_helpers() + _function(src, 'renderAuthBanList')
               + '\nrenderAuthBanList(%s); __out();\n' % json.dumps([ip]))
    out = _run(program)
    page = _parse(out['html']['ban-list-container'])
    assert {t for t, _ in page.tags} == {'table', 'thead', 'tbody', 'tr', 'th', 'td', 'button'}, page.tags
    _only_these_attributes(page, {'style', 'class', 'onclick'})
    assert ip in page.text
    got = _run_handlers(_clicks(page), ['unbanIP'])
    assert got == [{'calls': [['unbanIP', ip]], 'pwned': 0, 'err': None}], got


_HAND_QUOTED = re.compile(r"""\(\s*\\'\s*'\s*\+""")           # f(\''+value   the old way
_HANDLER_ARG = re.compile(r"""on[a-z]+=\\?"[\w.]+\('\s*\+\s*([\w.]+)\(""")   # f('+helper(value


@pytest.mark.parametrize('rel', ['templates/fail2ban.html', 'templates/takserver.html',
                                 'static/takserver.js', 'templates/console.html'])
def test_no_inline_handler_argument_is_quoted_by_hand(rel):
    """The ban and watch lists of the other jails (TAK Server, SSH, MediaMTX, TAK Portal, repeat
    offenders) are built the same way inside larger functions. None may build its quotes by hand,
    and each must use the page's argument helper."""
    src = _read(rel)
    found = ['%s:%d' % (rel, n) for n, line in enumerate(src.split('\n'), 1) if _HAND_QUOTED.search(line)]
    assert not found, 'inline handler argument quoted by hand: ' + ', '.join(found)
    helpers = set(_HANDLER_ARG.findall(src))
    assert helpers <= {'f2bArg', 'jsArg'}, helpers
    if rel == 'templates/fail2ban.html':
        assert len(_HANDLER_ARG.findall(src)) >= 12
        # An address cell of a ban or watch list is escaped text.
        raw = re.findall(r""">'\+(?:ip|w\.ip|w\.attempts|w\.last_seen)\+'</td>""", src)
        assert not raw, raw


def test_argument_helpers_escape_for_the_attribute_and_the_string():
    program = (BROWSER + _tak_helpers() + _f2b_helpers()
               + 'console.log(JSON.stringify(%s.map(function(v){ return [jsArg(v), f2bArg(v)]; })));\n'
               % json.dumps(HOSTILE + PLAIN))
    for value, args in zip(HOSTILE + PLAIN, _run(program)):
        for arg in args:
            page = _parse('<button onclick="go(%s)">x</button>' % arg)
            assert [(t, set(a)) for t, a in page.tags] == [('button', {'onclick'})]
            got = _run_handlers([page.tags[0][1]['onclick']], ['go'])[0]
            assert got == {'calls': [['go', value]], 'pwned': 0, 'err': None}, got


# ── 5. console message text ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('reply_key', ['message', 'error'])
def test_rollback_message_from_the_server_is_text(reply_key):
    bad = '<img src=x onerror=pwn()> a"b\'c'
    src = _read('templates/console.html')
    reply = {'ok': reply_key == 'message', reply_key: bad}
    program = (BROWSER + 'var __real = setTimeout; setTimeout = function(f, ms){ if(ms < 1000) __real(f, ms); };\n'
               + _function(src, 'escapeHtml') + '\n' + _function(src, 'doConsoleRollback') + '\n'
               + '__fetch["/api/console/rollback"] = %s;\n' % json.dumps(reply)
               + 'doConsoleRollback().then(__out, __out);\n')
    out = _run(program)
    page = _parse(out['html']['console-rollback-bar'])
    assert [t for t, _ in page.tags] == ['div'], page.tags
    assert bad in ''.join(page.text)


def test_update_messages_from_the_server_are_escaped():
    src = _function(_read('templates/console.html'), 'applyUpdate')
    assert "'+d.restart_message+'" not in src and "'+d.workaround+'" not in src
    assert 'escapeHtml(d.restart_message)' in src and 'escapeHtml(d.workaround)' in src
