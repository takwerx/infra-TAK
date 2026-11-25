"""ops #1119 (card): the TAK Server card on the console shows "Latest we tested: X", same data as the page.

AJ asked for it on the card too (ops #1180: where does the "latest we tested" show?). Rules this file holds:
  * the card gets its own fields (tested, tested_date, tested_state); `latest` and `update_available`, which drive
    the cyan update badge, are not touched
  * the card never waits for the network: it reads the verified cache and starts the 30-minute refresh in a thread
  * no signed file, or a failure in the lookup, leaves the card exactly as before
  * the line is built as text, never as HTML (the version comes from a signed file)
"""
import ast
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
CONSOLE = (ROOT / 'templates' / 'console.html').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}


def _fn(name):
    return ast.get_source_segment(APP, _FNS[name])


def _tst():
    from modules import takserver_tested
    return takserver_tested


def _versions(info, card_state, installed=True):
    """The real get_all_module_versions() with only TAK Server installed."""
    ns = {'detect_modules': lambda: {'takserver': {'installed': installed}},
          '_get_takserver_version_info': lambda: info,
          '_takserver_tested_card_state': card_state,
          '_safe_module_version_info': lambda k, i: i,
          '_module_release_notes_url': lambda k, i: '',
          '_node_card_gaps': lambda: {}, 'print': lambda *a, **k: None}
    exec(compile(_fn('get_all_module_versions'), 'app.py', 'exec'), ns)
    return ns['get_all_module_versions']()


BASE = {'version': '5.8-RELEASE104', 'latest': None, 'update_available': False}


def test_the_card_gets_the_tested_fields_and_leaves_the_update_badge_alone():
    out = _versions(dict(BASE), lambda v: {'tested': '5.8-RELEASE105', 'tested_date': '2026-11-24', 'state': 'behind'})
    t = out['takserver']
    assert (t['tested'], t['tested_date'], t['tested_state']) == ('5.8-RELEASE105', '2026-11-24', 'behind')
    assert t['latest'] is None and t['update_available'] is False and t['version'] == '5.8-RELEASE104'


def test_the_helper_dict_is_copied_not_changed():
    shared = dict(BASE)
    _versions(shared, lambda v: {'tested': '5.8-RELEASE105', 'tested_date': 'd', 'state': 'behind'})
    assert 'tested' not in shared                       # the version helper may cache its dict


def test_the_card_asks_for_the_installed_version():
    seen = []
    _versions(dict(BASE), lambda v: seen.append(v) or {'tested': '', 'tested_date': '', 'state': 'unknown'})
    assert seen == ['5.8-RELEASE104']


def test_no_signed_file_means_the_card_is_exactly_as_before():
    out = _versions(dict(BASE), lambda v: {'tested': '', 'tested_date': '', 'state': 'unknown'})
    assert out['takserver'] == BASE


def test_a_failing_lookup_never_blanks_the_card():
    def boom(v):
        raise RuntimeError('cache unreadable')
    assert _versions(dict(BASE), boom)['takserver'] == BASE


def test_a_missing_helper_never_blanks_the_card():
    # other tests cut get_all_module_versions out of app.py without the new helper: that must not break it
    ns = {'detect_modules': lambda: {'takserver': {'installed': True}},
          '_get_takserver_version_info': lambda: dict(BASE),
          '_safe_module_version_info': lambda k, i: i, '_module_release_notes_url': lambda k, i: '',
          '_node_card_gaps': lambda: {}, 'print': lambda *a, **k: None}
    exec(compile(_fn('get_all_module_versions'), 'app.py', 'exec'), ns)
    assert ns['get_all_module_versions']()['takserver'] == BASE


def test_no_tak_server_installed_means_no_tested_lookup():
    called = []
    out = _versions(dict(BASE), lambda v: called.append(v), installed=False)
    assert 'takserver' not in out and not called


# ── the card helper never waits for the network ───────────────────────────────

class _Thread:
    started = []

    def __init__(self, target=None, daemon=None):
        self.target, self.daemon = target, daemon

    def start(self):
        _Thread.started.append(self)


def _card_ns(record, attempt_ts):
    import time
    refreshed = []
    _Thread.started = []
    ns = {'time': time, '_tst': _tst(), '_takserver_tested_attempt': {'ts': attempt_ts},
          '_TAKSERVER_TESTED_CACHE': '/nowhere', '_takserver_tested_refresh': lambda *a, **k: refreshed.append(1),
          'threading': type('T', (), {'Thread': _Thread})}
    ns['_tst'] = type('P', (), {'TESTED_CHECK_SEC': 1800, 'page_state': staticmethod(_tst().page_state),
                                'cached': staticmethod(lambda d: record)})
    exec(compile(_fn('_takserver_tested_card_state'), 'app.py', 'exec'), ns)
    return ns, refreshed


REC = {'version': '5.8-RELEASE105', 'tested': '2026-11-24'}


def test_the_card_reads_the_cache_and_does_not_fetch_in_the_request():
    ns, refreshed = _card_ns(REC, 0.0)
    st = ns['_takserver_tested_card_state']('5.8-RELEASE104')
    assert st['state'] == 'behind' and st['tested'] == '5.8-RELEASE105'
    assert not refreshed                                # the network fetch is not run in this call
    assert len(_Thread.started) == 1 and _Thread.started[0].daemon is True
    assert _Thread.started[0].target is ns['_takserver_tested_refresh']


def test_no_new_thread_while_the_last_check_is_recent():
    import time
    ns, _ = _card_ns(REC, time.time() - 60)
    ns['_takserver_tested_card_state']('5.8-RELEASE104')
    assert not _Thread.started


def test_card_state_never_raises():
    ns, _ = _card_ns(REC, 0.0)
    ns['_tst'] = None                                   # everything it touches is broken
    assert ns['_takserver_tested_card_state']('5.8-RELEASE104')['state'] == 'unknown'


def test_the_three_card_states_from_the_real_rules():
    for inst, state in (('5.8-RELEASE104', 'behind'), ('5.8-RELEASE105', 'current'), ('5.8-RELEASE106', 'newer')):
        ns, _ = _card_ns(REC, 0.0)
        assert ns['_takserver_tested_card_state'](inst)['state'] == state
    ns, _ = _card_ns(None, 0.0)
    assert ns['_takserver_tested_card_state']('5.8-RELEASE104')['state'] == 'unknown'


# ── the template ──────────────────────────────────────────────────────────────

def _snippet():
    m = re.search(r"\{% if key == 'takserver' and mod\.installed %\}\{% set _tt = .*?\{% endif %\}\n", CONSOLE)
    assert m, 'the card line is missing from console.html'
    return m.group(0)


def _render(tak):
    import jinja2
    env = jinja2.Environment(autoescape=True)
    return env.from_string(_snippet()).render(key='takserver', mod={'installed': True},
                                              module_versions={'takserver': tak} if tak is not None else {})


def test_card_text_behind():
    html = _render({'tested': '5.8-RELEASE105', 'tested_state': 'behind'})
    assert 'Newer Version Available' in html and 'display:none' not in html
    assert 'Current Release' not in html
    assert 'title="Latest we tested: 5.8-RELEASE105"' in html      # the version is only a tooltip; the line is AJ's words


def test_card_text_current():
    html = _render({'tested': '5.8-RELEASE104', 'tested_state': 'current'})
    assert 'Current Release' in html and 'Newer Version Available' not in html and 'display:none' not in html


def test_card_is_hidden_when_the_box_is_ahead_of_what_we_tested():
    # no claim either way: nothing newer is known, and we have not tested what it runs
    html = _render({'tested': '5.8-RELEASE104', 'tested_state': 'newer'})
    assert 'display:none' in html and 'Current Release' not in html and 'Newer Version Available' not in html


def test_no_file_means_a_hidden_empty_line():
    for tak in (None, {}, {'version': '5.8-RELEASE104'}, {'tested': '5.8-RELEASE104', 'tested_state': 'unknown'}):
        html = _render(tak)
        assert 'display:none' in html and 'Latest we tested' not in html
        assert 'Current Release' not in html and 'Newer Version Available' not in html


def test_the_version_is_escaped_in_the_server_rendered_line():
    html = _render({'tested': '<img src=x onerror=alert(1)>', 'tested_state': 'current'})
    assert '<img' not in html and '&lt;img' in html


def test_the_script_sets_text_never_html_and_runs_on_every_poll():
    js = CONSOLE[CONSOLE.index('function applyTakTested(d)'):CONSOLE.index('function refreshModuleVersions()')]
    assert 'innerHTML' not in js and 'textContent' in js
    poll = CONSOLE[CONSOLE.index('function refreshModuleVersions()'):]
    assert 'applyTakTested(data.takserver)' in poll[:400]
    assert 'try{if(data&&data.takserver)applyTakTested(data.takserver);}catch(e){}' in poll[:400]  # never stops the badges


def test_the_script_uses_the_two_card_phrases():
    js = CONSOLE[CONSOLE.index('function applyTakTested(d)'):CONSOLE.index('function refreshModuleVersions()')]
    assert "'Newer Version Available'" in js and "'Current Release'" in js
    assert 'yours is' not in js and 'you run it' not in js and "'Latest we tested: '+d.tested" in js  # tooltip only


def test_the_card_line_sits_only_on_the_takserver_card():
    assert _snippet().startswith("{% if key == 'takserver'")
    assert CONSOLE.count('id="takserver-card-tested"') == 1
