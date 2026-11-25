"""ops #1119 (Federation Hub): the Fed Hub card and page say "Current Release" or "Newer Version Available".

AJ, Wed Nov 25: "We should do the same for fed hub." Federation Hub ships in the same tak.gov release as TAK Server
(the takserver-fed-hub 5.8-RELEASE105 package reads Version 5.8-RELEASE105), so the one signed "latest tested"
file drives both. Rules this file holds:
  * the Fed Hub card gets its own fields (tested, tested_date, tested_state); `latest` and `update_available` are not touched
  * the lookup asks for the Fed Hub version, never the TAK Server one
  * no signed file, a failing lookup, or a box ahead of what we tested: no line, card exactly as before
  * the line is built as text, never as HTML (the version comes from a signed file)
  * the Fed Hub page shows the same row as the TAK Server page and names its own update button
  * no new Guard Dog mail: the TAK Server mail already covers the release
"""
import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
CONSOLE = (ROOT / 'templates' / 'console.html').read_text(encoding='utf-8')
FEDHUB = (ROOT / 'templates' / 'fedhub.html').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}


def _fn(name):
    return ast.get_source_segment(APP, _FNS[name])


def _tst():
    from modules import takserver_tested
    return takserver_tested


BASE = {'version': '5.8-RELEASE104', 'latest': None, 'update_available': False}


def _versions(info, card_state, installed=True, tak_installed=False):
    """The real get_all_module_versions() with only Federation Hub (and maybe TAK Server) installed."""
    mods = {'fedhub': {'installed': installed}}
    if tak_installed:
        mods['takserver'] = {'installed': True}
    ns = {'detect_modules': lambda: mods,
          '_get_fedhub_version_info': lambda: info,
          '_get_takserver_version_info': lambda: {'version': '5.8-RELEASE999'},
          '_takserver_tested_card_state': card_state,
          '_safe_module_version_info': lambda k, i: i,
          '_module_release_notes_url': lambda k, i: '',
          '_node_card_gaps': lambda: {}, 'print': lambda *a, **k: None}
    exec(compile(_fn('get_all_module_versions'), 'app.py', 'exec'), ns)
    return ns['get_all_module_versions']()


def _state(tested='5.8-RELEASE105', date='2026-11-24', state='behind'):
    return lambda v: {'tested': tested, 'tested_date': date, 'state': state}


# ── the version call ──────────────────────────────────────────────────────────

def test_the_fedhub_card_gets_the_tested_fields_and_leaves_the_update_badge_alone():
    f = _versions(dict(BASE), _state())['fedhub']
    assert (f['tested'], f['tested_date'], f['tested_state']) == ('5.8-RELEASE105', '2026-11-24', 'behind')
    assert f['latest'] is None and f['update_available'] is False and f['version'] == '5.8-RELEASE104'


def test_the_lookup_asks_for_the_fedhub_version_not_the_takserver_one():
    seen = []
    _versions(dict(BASE), lambda v: seen.append(v) or {'tested': '', 'tested_date': '', 'state': 'unknown'},
              tak_installed=True)
    assert '5.8-RELEASE104' in seen                       # Fed Hub
    assert seen.count('5.8-RELEASE999') == 1              # the TAK Server card asks once, for its own version


def test_the_helper_dict_is_copied_not_changed():
    shared = dict(BASE)
    _versions(shared, _state())
    assert 'tested' not in shared                         # the version helper may cache its dict


def test_no_signed_file_means_the_fedhub_card_is_exactly_as_before():
    out = _versions(dict(BASE), lambda v: {'tested': '', 'tested_date': '', 'state': 'unknown'})
    assert out['fedhub'] == BASE


def test_a_failing_lookup_never_blanks_the_fedhub_card():
    def boom(v):
        raise RuntimeError('cache unreadable')
    assert _versions(dict(BASE), boom)['fedhub'] == BASE


def test_a_missing_helper_never_blanks_the_fedhub_card():
    ns = {'detect_modules': lambda: {'fedhub': {'installed': True}},
          '_get_fedhub_version_info': lambda: dict(BASE),
          '_safe_module_version_info': lambda k, i: i, '_module_release_notes_url': lambda k, i: '',
          '_node_card_gaps': lambda: {}, 'print': lambda *a, **k: None}
    exec(compile(_fn('get_all_module_versions'), 'app.py', 'exec'), ns)
    assert ns['get_all_module_versions']()['fedhub'] == BASE


def test_no_fedhub_installed_means_no_lookup():
    called = []
    out = _versions(dict(BASE), lambda v: called.append(v), installed=False)
    assert 'fedhub' not in out and not called


def test_a_fedhub_with_no_readable_version_gets_no_line():
    # the remote host did not answer: version is empty, the real rules say 'unknown'
    out = _versions({'version': '', 'latest': None, 'update_available': False},
                    lambda v: _tst().page_state(v, {'version': '5.8-RELEASE105', 'tested': '2026-11-24'}))
    assert out['fedhub'].get('tested_state', 'unknown') == 'unknown'   # the card template hides 'unknown'


def test_the_real_rules_for_a_fedhub_package_version():
    rec = {'version': '5.8-RELEASE105', 'tested': '2026-11-24'}
    for inst, state in (('5.8-RELEASE104', 'behind'), ('5.8-RELEASE105', 'current'), ('5.8-RELEASE106', 'newer')):
        assert _tst().page_state(inst, rec)['state'] == state


# ── the card line ─────────────────────────────────────────────────────────────

def _snippet():
    m = re.search(r"\{% if key == 'fedhub' and mod\.installed %\}\{% set _ft = .*?\{% endif %\}\n", CONSOLE)
    assert m, 'the Fed Hub card line is missing from console.html'
    return m.group(0)


def _render(fh, installed=True):
    import jinja2
    env = jinja2.Environment(autoescape=True)
    return env.from_string(_snippet()).render(key='fedhub', mod={'installed': installed},
                                              module_versions={'fedhub': fh} if fh is not None else {})


def test_card_text_behind():
    html = _render({'tested': '5.8-RELEASE105', 'tested_state': 'behind'})
    assert 'Newer Version Available' in html and 'Current Release' not in html and 'display:none' not in html
    assert 'title="Latest release we tested: 5.8-RELEASE105"' in html


def test_card_text_current():
    html = _render({'tested': '5.8-RELEASE104', 'tested_state': 'current'})
    assert 'Current Release' in html and 'Newer Version Available' not in html and 'display:none' not in html


def test_card_is_hidden_when_the_box_is_ahead_of_what_we_tested():
    html = _render({'tested': '5.8-RELEASE104', 'tested_state': 'newer'})
    assert 'display:none' in html and 'Current Release' not in html and 'Newer Version Available' not in html


def test_no_file_means_a_hidden_empty_line():
    for fh in (None, {}, {'version': '5.8-RELEASE104'}, {'tested': '5.8-RELEASE104', 'tested_state': 'unknown'}):
        html = _render(fh)
        assert 'display:none' in html and 'Current Release' not in html and 'Newer Version Available' not in html


def test_no_line_when_fedhub_is_not_installed():
    assert _render({'tested': '5.8-RELEASE105', 'tested_state': 'behind'}, installed=False).strip() == ''


def test_the_version_is_escaped_in_the_server_rendered_line():
    html = _render({'tested': '<img src=x onerror=alert(1)>', 'tested_state': 'current'})
    assert '<img' not in html and '&lt;img' in html


def test_the_card_line_sits_only_on_the_fedhub_card_and_the_takserver_one_is_unchanged():
    assert _snippet().startswith("{% if key == 'fedhub'")
    assert CONSOLE.count('id="fedhub-card-tested"') == 1 and CONSOLE.count('id="takserver-card-tested"') == 1


# ── the script ────────────────────────────────────────────────────────────────

def _js():
    return CONSOLE[CONSOLE.index('function applyTakTested('):CONSOLE.index('function refreshModuleVersions()')]


def test_the_script_sets_text_never_html():
    js = _js()
    assert 'innerHTML' not in js and 'textContent' in js


def test_the_poll_updates_both_cards_and_one_failing_never_stops_the_other_or_the_badges():
    poll = CONSOLE[CONSOLE.index('function refreshModuleVersions()'):]
    tak = "try{if(data&&data.takserver)applyTakTested(data.takserver);}catch(e){}"
    fed = "try{if(data&&data.fedhub)applyTakTested(data.fedhub,'fedhub-card-tested','Latest release we tested');}catch(e){}"
    assert tak in poll[:700] and fed in poll[:700]
    assert poll.index(fed) < poll.index('for(var key in data)')


def test_the_takserver_card_default_is_unchanged():
    js = _js()
    assert "document.getElementById(id||'takserver-card-tested')" in js
    assert "(what||'Latest we tested')" in js


# ── the page ──────────────────────────────────────────────────────────────────

def _row():
    m = re.search(r"\{% if fh\.installed and fedhub_tested and fedhub_tested\.tested %\}.*?\n  \{% endif %\}\n", FEDHUB, re.S)
    assert m, 'the Fed Hub page row is missing from fedhub.html'
    return m.group(0)


def _page(tested, version='5.8-RELEASE104', installed=True):
    import jinja2
    env = jinja2.Environment(autoescape=True)
    return env.from_string(_row()).render(fh={'installed': installed}, fedhub_tested=tested, fedhub_version=version)


def test_page_row_behind_names_the_fedhub_update_button():
    html = _page({'tested': '5.8-RELEASE105', 'tested_date': '2026-11-24', 'state': 'behind'})
    assert 'Latest release we tested:' in html and '5.8-RELEASE105' in html
    assert 'Update Federation Hub' in html and 'takserver-fed-hub' in html
    assert 'Update TAK Server' not in html
    assert 'tak.gov may have a newer release still' in html


def test_page_row_current_and_newer():
    cur = _page({'tested': '5.8-RELEASE104', 'tested_date': 'd', 'state': 'current'})
    assert 'runs the release we tested' in cur and 'older' not in cur
    new = _page({'tested': '5.8-RELEASE104', 'tested_date': 'd', 'state': 'newer'}, version='5.8-RELEASE106')
    assert 'newer than the release we tested' in new and 'We have not tested it yet' in new


def test_page_row_needs_a_file_and_an_installed_fedhub():
    assert _page(None).strip() == ''
    assert _page({'tested': '', 'tested_date': '', 'state': 'unknown'}).strip() == ''
    assert _page({'tested': '5.8-RELEASE105', 'tested_date': 'd', 'state': 'behind'}, installed=False).strip() == ''


def test_page_row_escapes_the_version():
    html = _page({'tested': '<img src=x onerror=alert(1)>', 'tested_date': 'd', 'state': 'current'})
    assert '<img' not in html and '&lt;img' in html


def test_the_route_gives_the_page_its_state_and_a_failure_never_blocks_the_page():
    src = _fn('fedhub_page') if 'fedhub_page' in _FNS else APP
    i = src.index('_fedhub_tested = _takserver_tested_page_state(_fedhub_ver) if _fedhub_ver else None')
    assert 'except Exception:\n        _fedhub_tested = None' in src[i:i + 300]
    assert 'fedhub_tested=_fedhub_tested,' in src


def test_no_guard_dog_mail_for_fedhub():
    # the TAK Server mail covers the release; Fed Hub stays a gated row with no tested-new item
    items = _fn('_takserver_tested_items')
    assert 'fedhub' not in items
    assert "('fedhub', 'Federation Hub', None, True," in APP
