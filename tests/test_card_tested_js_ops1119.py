"""ops #1119: the REAL applyTakTested() from templates/console.html, run in node against a stub page with both cards.

The TAK Server card calls it with one argument (the old way) and must behave exactly as before; the Federation Hub card
calls it with its own element id and tooltip. Skipped when node is not installed (the template-JS gate covers syntax)."""
import json
import pathlib
import shutil
import subprocess
import textwrap

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONSOLE = (ROOT / 'templates' / 'console.html').read_text(encoding='utf-8')
FN = CONSOLE[CONSOLE.index('function applyTakTested('):CONSOLE.index('function refreshModuleVersions()')]

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')

HARNESS = textwrap.dedent("""
    function mkEl(){return {style:{},textContent:'x',title:'',_a:{},setAttribute(k,v){this._a[k]=v;},
      removeAttribute(k){delete this._a[k];if(k==='title')this.title='';}};}
    const els={'takserver-card-tested':mkEl(),'fedhub-card-tested':mkEl()};
    const document={getElementById:(id)=>els[id]||null};
    %s
    const out={};
    function snap(el){return {text:el.textContent,color:el.style.color,display:el.style.display,title:el.title,state:el._a['data-state']||''};}
    applyTakTested({tested:'5.8-RELEASE105',tested_state:'behind'});
    out.tak_behind=snap(els['takserver-card-tested']);
    applyTakTested({tested:'5.8-RELEASE105',tested_state:'current'});
    out.tak_current=snap(els['takserver-card-tested']);
    applyTakTested({tested:'5.8-RELEASE105',tested_state:'newer'});
    out.tak_newer=snap(els['takserver-card-tested']);
    applyTakTested({tested:'5.8-RELEASE105',tested_state:'behind'},'fedhub-card-tested','Latest release we tested');
    out.fh_behind=snap(els['fedhub-card-tested']);
    out.fh_behind_tak_untouched=snap(els['takserver-card-tested']);
    applyTakTested({tested:'5.8-RELEASE105',tested_state:'current'},'fedhub-card-tested','Latest release we tested');
    out.fh_current=snap(els['fedhub-card-tested']);
    applyTakTested({tested:'',tested_state:'unknown'},'fedhub-card-tested','Latest release we tested');
    out.fh_nofile=snap(els['fedhub-card-tested']);
    applyTakTested({tested:'5.8-RELEASE105',tested_state:'behind'},'no-such-card');
    console.log(JSON.stringify(out));
""") % FN


@pytest.fixture(scope='module')
def out():
    r = subprocess.run(['node', '-e', HARNESS], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_takserver_card_called_the_old_way_is_unchanged(out):
    assert out['tak_behind'] == {'text': 'Newer Version Available', 'color': 'var(--yellow,#eab308)', 'display': '',
                                 'title': 'Latest we tested: 5.8-RELEASE105', 'state': 'behind'}
    assert out['tak_current']['text'] == 'Current Release' and out['tak_current']['color'] == 'var(--green)'
    assert out['tak_current']['title'] == 'Latest we tested: 5.8-RELEASE105'
    assert out['tak_newer']['text'] == '' and out['tak_newer']['display'] == 'none' and out['tak_newer']['title'] == ''


def test_fedhub_card_uses_its_own_element_and_tooltip(out):
    assert out['fh_behind'] == {'text': 'Newer Version Available', 'color': 'var(--yellow,#eab308)', 'display': '',
                                'title': 'Latest release we tested: 5.8-RELEASE105', 'state': 'behind'}
    assert out['fh_current']['text'] == 'Current Release' and out['fh_current']['display'] == ''
    assert out['fh_nofile']['text'] == '' and out['fh_nofile']['display'] == 'none'


def test_the_two_cards_do_not_touch_each_other_and_a_missing_card_does_not_throw(out):
    assert out['fh_behind_tak_untouched'] == out['tak_newer']   # still the hidden state the TAK Server card was left in
