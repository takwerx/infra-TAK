# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #897: a name from a feed must reach the Node-RED configurator page as text only.

The configurator (nodered/configurator.html) builds most of its page in the browser from values
that the operator does not choose: the feed's layer names, field names, field types, class values
and sample attribute values, and what a saved config or an uploaded CSV holds.

These tests load the page's own script in node with a small stand-in for the browser, give it
hostile values through the same fetch replies and state the page uses, then read the HTML it built
with Python's HTML parser (which decodes attributes the way a browser does). A pass needs both
halves: nothing is injected, and the value still works (the handler gets the exact name).
"""
import json
import pathlib
import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PAGE = ROOT / 'nodered' / 'configurator.html'

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
PLAIN = ['IncidentName', "Chief's Unit", 'IR Heat Perimeter', 'GIS_ACRES']

BROWSER = r'''
var __pwned = 0, __els = {}, __made = [];
function pwn(){ __pwned++; }
function __node(id){
  var kids = [];
  var n = {id: id || '', innerHTML: '', textContent: '', value: '', checked: false, disabled: false,
    title: '', src: '', className: '', selectedOptions: [], options: [], files: [], dataset: {},
    style: {cssText: '', display: ''}, children: kids,
    classList: {add: function(){}, remove: function(){}, toggle: function(){}, contains: function(){ return false; }},
    addEventListener: function(){}, removeEventListener: function(){}, setAttribute: function(){},
    removeAttribute: function(){}, getAttribute: function(){ return null; }, appendChild: function(c){ kids.push(c); return c; },
    querySelector: function(){ return null; }, querySelectorAll: function(){ return []; }, closest: function(){ return null; },
    focus: function(){}, click: function(){}, remove: function(){}, scrollIntoView: function(){},
    insertBefore: function(c){ kids.push(c); return c; }, removeChild: function(){}, contains: function(){ return false; }};
  return n;
}
var document = {
  body: __node('__body'), documentElement: __node('__html'), readyState: 'complete', cookie: '',
  getElementById: function(id){ if(!__els[id]) __els[id] = __node(id); return __els[id]; },
  createElement: function(){ var n = __node(''); __made.push(n); return n; },
  querySelector: function(){ return null; }, querySelectorAll: function(){ return []; },
  addEventListener: function(){}, removeEventListener: function(){}
};
var __fetch = {};
function fetch(url){
  var key = String(url).split('?')[0];
  var body = (key in __fetch) ? __fetch[key] : {};
  return Promise.resolve({ok: true, status: 200, json: function(){ return Promise.resolve(JSON.parse(JSON.stringify(body))); },
                          text: function(){ return Promise.resolve(JSON.stringify(body)); }});
}
var window = globalThis;
window.location = {origin: 'https://nodered.example', hostname: 'nodered.example', href: 'https://nodered.example/configurator', search: '', pathname: '/configurator'};
window.addEventListener = function(){}; window.removeEventListener = function(){};
var localStorage = {getItem: function(){ return null; }, setItem: function(){}, removeItem: function(){}};
var sessionStorage = localStorage;
function alert(){} function confirm(){ return true; }
var __realSetTimeout = setTimeout;
setInterval = function(){ return 0; };
setTimeout = function(fn, ms){ return (ms && ms > 50) ? 0 : __realSetTimeout(fn, ms || 0); };
function __html(id){ return (__els[id] || {}).innerHTML || ''; }
function __out(extra){
  var o = {pwned: __pwned, html: {}, made: __made.map(function(n){ return n.innerHTML; }).filter(Boolean)};
  for(var k in __els) if(__els[k].innerHTML) o.html[k] = __els[k].innerHTML;
  for(var e in (extra || {})) o[e] = extra[e];
  console.log('__OUT__' + JSON.stringify(o));
  process.exit(0);
}
'''


def _node():
    node = shutil.which('node')
    if node is None:
        pytest.skip('no node on PATH, so the page JavaScript is unexercised')
    return node


def _page_script():
    """The page's main script: the block that holds the configurator's functions."""
    html = PAGE.read_text(encoding='utf-8')
    blocks = re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', html, flags=re.S)
    main = [b for b in blocks if 'function renderClassMappings' in b]
    assert len(main) == 1
    return main[0]


def _run(fetches, steps):
    """Load the page script with these fetch replies, wait for its start-up, run `steps` (JavaScript,
    may await), then print every element's HTML."""
    program = (BROWSER + '__fetch = ' + json.dumps(fetches) + ';\n' + _page_script() +
               '\n;(async function(){\n'
               '  await new Promise(function(r){ __realSetTimeout(r, 150); });\n'
               '  __pwned = 0; __made.length = 0; for (var k in __els) __els[k].innerHTML = "";\n'
               + steps +
               '\n  await new Promise(function(r){ __realSetTimeout(r, 100); });\n'
               '  __out();\n'
               '})().catch(function(e){ console.log("__ERR__" + (e && e.stack || e)); process.exit(3); });\n')
    r = subprocess.run([_node(), '-'], input=program, capture_output=True, text=True, timeout=120)
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith('__OUT__')]
    assert lines, (r.stdout[-1500:], r.stderr[-1500:])
    return json.loads(lines[-1][len('__OUT__'):])


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


def _shape(html):
    """Tag names and attribute names, in order: what the value must not change."""
    return [(t, sorted(a)) for t, a in _parse(html).tags]


def _handlers(html):
    return [v for _, attrs in _parse(html).tags for k, v in attrs.items() if k.startswith('on')]


def _run_handlers(handlers, function_names):
    """Run each inline handler as the browser does (the attribute is already decoded). Returns,
    per handler, the calls it made to the named page functions and how often it ran pwn()."""
    stubs = ''.join('function %s(){ __calls.push([%s].concat([].slice.call(arguments))); }\n'
                    % (n, json.dumps(n)) for n in function_names)
    program = ('var __res = [];\n' + json.dumps(handlers) + '.forEach(function(code){\n'
               '  var __calls = [], __pwned = 0, __err = null;\n'
               '  var event = {stopPropagation: function(){}};\n'
               '  var document = {getElementById: function(){ return {}; }};\n'
               '  function pwn(){ __pwned++; }\n' + stubs +
               '  try { (function(){ eval(code); }).call({value: "V", checked: true, closest: function(){ return {remove: function(){}}; }}); }'
               ' catch(e) { __err = String(e); }\n'
               '  __res.push({calls: __calls, pwned: __pwned, err: __err});\n'
               '});\nconsole.log("__OUT__" + JSON.stringify(__res));\n')
    r = subprocess.run([_node(), '-'], input=program, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-1500:]
    return json.loads(r.stdout.strip().splitlines()[-1][len('__OUT__'):])


def _clean(handlers, function_names):
    res = _run_handlers(handlers, function_names)
    assert [r['err'] for r in res] == [None] * len(res), res
    assert [r['pwned'] for r in res] == [0] * len(res), res
    return [c for r in res for c in r['calls']]


_REF = {}


def _plain(key, render):
    """The page drawn with a plain name: the reference for every hostile value (drawn once)."""
    if key not in _REF:
        _REF[key] = render('PlainName')
    return _REF[key]


def _same_as_plain(key, render, value, ids):
    """The HTML for a hostile value has the same elements and attributes as for a plain one."""
    out = render(value)
    ref = _plain(key, render)
    assert out['pwned'] == 0
    for i in ids:
        assert _shape(out['html'].get(i, '')) == _shape(ref['html'].get(i, '')), i
        assert out['html'].get(i), i
    return out


# ── the helpers ──────────────────────────────────────────────────────────────────────────────

def test_the_escape_helper_covers_all_five_characters():
    out = _run({}, '  __out({a: _esc(\'&<>"\\\'\'), b: _esc(null), c: _jsArg("a\\"b\'c")});')
    assert out['a'] == '&amp;&lt;&gt;&quot;&#39;'
    assert out['b'] == ''
    assert out['c'] == '&quot;a\\&quot;b&#39;c&quot;'


# ── class mappings (class values come from the feed's features) ──────────────────────────────

_CLASS_FUNCS = ['toggleClassPanel', 'toggleClassEnabled', 'openIconPicker', 'setClassCotType', 'setClassColor',
                'clearClassColor', 'setClassStrokeColor', 'clearClassStrokeColor', 'setClassFillColor',
                'clearClassFillColor', 'setClassFillAlpha', 'setClassStrokeWeight', 'setClassStrokeStyle',
                'toggleClassLabelField', 'setClassLabelCustomText', 'setClassUpperCase', 'setClassLabelsOn',
                'toggleClassRemarkField', 'setClassRemarksCustomText']


def _class_steps(value, geom):
    v = json.dumps(value)
    return ('  state.classValues = [%s]; state.classMappings = {};\n'
            '  state.classMappings[%s] = {enabled: true, geometryType: %s, cotType: %s, color: %s, strokeColor: %s,'
            ' fillColor: %s, fillAlpha: %s, customLabel: %s, iconB64: %s, iconsetpath: "x", iconLabel: %s,'
            ' labelFields: [%s], remarksFields: [%s], labelCustomText: %s, remarksCustomText: %s};\n'
            '  state.fields = [{name: %s, type: "esriFieldTypeString"}]; state.layerFields = {};\n'
            '  state._openClassPanel = %s;\n'
            '  renderClassMappings();\n' % ((v, v, json.dumps(geom)) + (v,) * 14))


@pytest.mark.parametrize('geom', ['esriGeometryPoint', 'esriGeometryPolygon'])
@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_a_class_value_is_text_and_every_control_gets_the_exact_value(value, geom):
    out = _same_as_plain('class-' + geom, lambda v: _run({}, _class_steps(v, geom)), value, ['classMappings'])
    html = out['html']['classMappings']
    assert value in ''.join(_parse(html).text)
    calls = _clean(_handlers(html), _CLASS_FUNCS)
    assert calls, 'no handler ran'
    # Every call names this class value first; the field pills pass the field name second.
    assert all(c[1] == value for c in calls), calls
    pills = [c for c in calls if c[0] in ('toggleClassLabelField', 'toggleClassRemarkField')]
    assert [c[2] for c in pills] == [value, value]


# ── field pills ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_a_field_name_is_text_in_every_picker(value):
    steps = ('  state.fields = [{name: %s, type: %s}]; state.selectedLayers = []; state.layerFields = {};\n'
             '  state.uniformLabelFields = [];\n'
             '  renderUniformLabelUI(); populateRemarksPicker(); populateIdFieldsPicker();\n'
             '  addRemarkField(%s); addIdField(%s);\n')
    ids = ['uniformLabelPills', 'remarksAvailable', 'remarksSelected', 'idFieldsAvailable', 'idFieldsSelected']

    def render(v):
        j = json.dumps(v)
        return _run({}, steps % (j, json.dumps('esriFieldType' + v), j, j))
    out = _same_as_plain('fields', render, value, ids)
    for i in ids:
        assert value in ''.join(_parse(out['html'][i]).text), i
    calls = _clean(_handlers(''.join(out['html'][i] for i in ids[:2] + ids[3:4])),
                   ['toggleUniformLabelField', 'addRemarkField', 'addIdField'])
    assert calls == [['toggleUniformLabelField', value], ['addRemarkField', value], ['addIdField', value]]


@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_a_filter_value_is_text_and_its_remove_button_gets_the_exact_value(value):
    steps = ('  state.filterField = "F"; state.domains = {}; state.selectedValues = [%s]; state.manualValues = [%s];\n'
             '  renderAllSelectedTags();\n')

    def render(v):
        j = json.dumps(v)
        return _run({}, steps % (j, j))
    out = _same_as_plain('filter', render, value, ['allSelectedTags'])
    html = out['html']['allSelectedTags']
    assert value in ''.join(_parse(html).text)
    calls = _clean(_handlers(html), ['removeCheckboxFilter', 'removeManualFilter'])
    assert calls and all(c[1] == value for c in calls), calls


# ── the status line ──────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('value', HOSTILE)
def test_a_status_message_is_text(value):
    out = _same_as_plain('status', lambda v: _run({}, '  status("svcStatus", "Error: " + %s, false);\n' % json.dumps(v)),
                         value, ['svcStatus'])
    assert ''.join(_parse(out['html']['svcStatus']).text) == 'Error: ' + value


# ── layers, fields and sample rows from the service ──────────────────────────────────────────

@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_layer_names_from_the_service_are_text(value):
    def render(v):
        return _run({'/arcgis-tak/arcgis/service': {'layers': [{'id': 0, 'name': v, 'geometryType': 'esriGeometry' + v}]}},
                    '  document.getElementById("serviceUrl").value = "https://feed.example/FeatureServer";\n'
                    '  await fetchService();\n')
    out = render(value)
    ref = _plain('layers', render)
    assert out['pwned'] == 0 and out['made'], 'no layer row was drawn'
    assert [_shape(h) for h in out['made']] == [_shape(h) for h in ref['made']]
    assert value in ''.join(_parse(''.join(out['made'])).text)
    assert _clean(_handlers(''.join(out['made'])), ['onLayerCheck']) == [['onLayerCheck']]


# ── saved configs and Tablet Command ─────────────────────────────────────────────────────────

@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_the_config_list_is_text_and_opens_the_exact_config(value):
    def render(v):
        cfg = {'id': v, 'configName': v, 'agencyUrl': 'https://' + v, 'agencyIds': v, 'pollInterval': v,
               'pollIntervalSec': v, 'activated': True, 'takDestinationLabel': v, 'missionName': v}
        j = json.dumps(cfg)
        return _run({'/tc/config/load': {'configs': [cfg]}},
                    '  _ppConfigs = [%s]; _ipawsActiveCfg = {pollInterval: %s, states: [%s], severity: [%s]};\n'
                    '  _savedConfigs = [{configName: %s, sourceType: "arcgis", missionName: %s,'
                    ' source: {serviceUrl: %s}, filter: {values: [%s]}}];\n'
                    '  await renderConfigList();\n' % ((j,) + (json.dumps(v),) * 7))
    out = _same_as_plain('configs', render, value, ['configList'])
    html = out['html']['configList']
    assert value in ' '.join(_parse(html).text)
    calls = _clean(_handlers(html), ['selectIpawsConfig', 'openPpConfig', 'deletePpConfig', 'openTcConfig',
                                     'deleteTcConfigById', 'selectConfig', 'purgeOrphans', 'seedGhostSweep',
                                     'deleteConfig'])
    by = {c[0]: c[1:] for c in calls}
    assert by['openPpConfig'] == [value] and by['deletePpConfig'] == [value]
    assert by['openTcConfig'] == [value] and by['deleteTcConfigById'] == [value]
    assert by['selectConfig'] == [0] and by['deleteConfig'] == [0]


@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_a_tablet_command_unit_row_is_text(value):
    def render(v):
        j = json.dumps(v)
        return _run({}, '  tcAddUnitRow(%s, %s, "a-f-G", %s);\n' % (j, j, j))
    out = render(value)
    ref = _plain('tc-row', render)
    assert out['pwned'] == 0 and len(out['made']) == 1
    assert _shape(out['made'][0]) == _shape(ref['made'][0])
    inputs = [a for t, a in _parse(out['made'][0]).tags if t == 'input']
    assert [a['value'] for a in inputs] == [value, value]
    custom = [a for t, a in _parse(out['made'][0]).tags if t == 'option' and 'selected' in a and a['value'] == value]
    assert len(custom) == 1


@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_a_tablet_command_remark_field_from_a_saved_config_is_text(value):
    def render(v):
        return _run({}, '  _tcRemarksFields = [%s]; tcRenderRemarks();\n' % json.dumps(v))
    out = _same_as_plain('tc-remarks', render, value, ['tcRemarksSelected'])
    html = out['html']['tcRemarksSelected']
    assert value in ''.join(_parse(html).text)
    assert _clean(_handlers(html), ['tcToggleRemarkField']) == [['tcToggleRemarkField', value]]


# ── fields, field types, sample rows and filter values from the service ──────────────────────

_LAYER_FUNCS = ['setLyr', 'setLyrDedup', 'dupLayerEntry', 'rmLayerEntry', 'loadLayerClassValues', 'renderLayerSetup',
                'addRemarkField', 'addIdField', 'toggleUniformLabelField', 'onLayerCheck', 'filterToggle',
                'filterSelectAll', 'filterSelectNone']


def _load_layers(v):
    layer = {'name': v, 'geometryType': 'esriGeometryPolygon', 'domains': {},
             'fields': [{'name': v, 'type': 'esriFieldTypeString'}, {'name': 'T', 'type': 'esriFieldType' + v},
                        {'name': 'D', 'type': 'esriFieldTypeDate'}]}
    sample = {'features': [{'attributes': {v: v, 'T': 1, 'D': 5}}]}
    j = json.dumps(v)
    return _run({'/arcgis-tak/arcgis/layer': layer, '/arcgis-tak/arcgis/sample': sample},
                '  state.serviceUrl = "https://feed.example/FeatureServer";\n'
                '  state.layers = [{id: 0, name: %s, geometryType: "esriGeometryPolygon"},'
                ' {id: 1, name: %s + "2", geometryType: "esriGeometry" + %s}];\n'
                '  document.querySelectorAll = function(sel){ return sel === ".layerCb:checked" ? [{value: "0"}, {value: "1"}] : []; };\n'
                '  await fetchSelectedLayers();\n'
                '  renderLayerSetup();\n' % (j, j, j))


@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_fields_types_and_sample_rows_from_the_service_are_text(value):
    out = _load_layers(value)
    ref = _plain('load-layers', _load_layers)
    assert out['pwned'] == 0
    drawn = ['timeField', 'filterField', 'dedupField', 'entityIdField', 'classField', 'sampleData',
             'remarksAvailable', 'idFieldsAvailable', 'uniformLabelPills', 'layerStatus', 'layerSetupCards']
    for i in drawn:
        assert ref['html'].get(i), i
        assert _shape(out['html'].get(i, '')) == _shape(ref['html'][i]), i
    cells = _parse(out['html']['sampleData']).text
    assert cells.count(value) == 2                       # the column name and the row's value
    options = [a.get('value') for t, a in _parse(out['html']['filterField']).tags if t == 'option']
    assert value in options
    cards = _parse(out['html']['layerSetupCards'])
    assert [a['value'] for t, a in cards.tags if t == 'input'][0] == value      # the Entry name box
    all_html = ''.join(out['html'][i] for i in drawn)
    calls = _clean(_handlers(all_html), _LAYER_FUNCS)
    assert ['addRemarkField', value] in calls and ['addIdField', value] in calls
    assert ['toggleUniformLabelField', value] in calls


@pytest.mark.parametrize('value', HOSTILE + PLAIN)
def test_distinct_filter_values_from_the_service_are_text(value):
    def render(v):
        return _run({'/arcgis-tak/arcgis/distinct': {'values': [v]}},
                    '  state.serviceUrl = "https://feed.example/FeatureServer"; state.domains = {};\n'
                    '  document.getElementById("filterField").value = "F";\n'
                    '  await fetchDistinct();\n')
    out = _same_as_plain('distinct', render, value, ['distinctValues'])
    assert value.strip() in _parse(out['html']['distinctValues']).text
    assert _clean(_handlers(out['html']['distinctValues']), _LAYER_FUNCS)
