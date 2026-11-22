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
"""A Docker TAK Server tells the operator when the Java inside its image is out of date (ops #968).

A Docker TAK Server carries its own Java inside the image, so the host's package manager and
the restart notice for native installs (ops #963) never see it. The image is only rebuilt when
TAK Server is updated. Promises, each tested with the real functions cut out of app.py:

  1. The Java the RUNNING container reports (`docker exec takserver java -version`) is compared
     with the newest Temurin 17 build we pin (_TEMURIN17_FIXED_TAG). Older = a notice. Equal,
     newer, another Java line, a runtime that is not Temurin, a native install: no claim.
  2. A container that is not running, or that cannot be asked, is "could not tell": nothing is
     claimed and the email sweep carries its earlier state (never re-mails on a guess).
  3. The Guard Dog update email names it once per gap, as a plain update (not a security claim we
     cannot prove), with the one place to click.
  4. The wiring cannot silently disappear: the sweep collects the item, /api/os-updates returns
     `java_image`, and the console has a banner that shows, hides and stays quiet for a day.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess as _real_subprocess
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CONSOLE = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?\n(?=\n)', APP, re.S | re.M).group(0)


# What `java -version` prints (on stderr). The first two are verbatim from the Docker TAK Server
# 5.8 hardened image built on nuc (shipped base 17.0.19_10, patched base 17.0.21_9; ops #963, Nov 19).
JAVA_17_0_19 = '''openjdk version "17.0.19" 2026-04-21 LTS
OpenJDK Runtime Environment Temurin-17.0.19+10 (build 17.0.19+10-LTS)
OpenJDK 64-Bit Server VM Temurin-17.0.19+10 (build 17.0.19+10-LTS, mixed mode, sharing)
'''
JAVA_17_0_21 = '''openjdk version "17.0.21" 2026-10-20 LTS
OpenJDK Runtime Environment Temurin-17.0.21+9 (build 17.0.21+9-LTS)
OpenJDK 64-Bit Server VM Temurin-17.0.21+9 (build 17.0.21+9-LTS, mixed mode, sharing)
'''
JAVA_17_0_21_1 = JAVA_17_0_21.replace('17.0.21+9', '17.0.21.1+2').replace('"17.0.21"', '"17.0.21.1"')
JAVA_21 = JAVA_17_0_19.replace('17.0.19+10', '21.0.5+11').replace('"17.0.19"', '"21.0.5"')
JAVA_DEBIAN = '''openjdk version "17.0.18" 2026-01-20
OpenJDK Runtime Environment (build 17.0.18+8-Debian-1)
OpenJDK 64-Bit Server VM (build 17.0.18+8-Debian-1, mixed mode, sharing)
'''

FIXED_TAG = '17.0.21_9-jdk-ubi10-minimal'


def _facts_ns(java_text='', *, container=True, running=True, rc=0, fixed_tag=FIXED_TAG, boom=None,
              arch='amd64', arm_tag=FIXED_TAG):
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        if boom:
            raise boom
        return types.SimpleNamespace(returncode=rc, stdout='', stderr=java_text)

    n = {'re': re, 'os': os, 'time': time, 'subprocess': types.SimpleNamespace(run=run),
         'print': lambda *a, **k: None,
         '_tak_is_container': lambda: container,
         '_tak_container_running': lambda name: running,
         '_sudo_wrap': lambda argv: list(argv),
         'TAK_CONTAINER': 'takserver',
         '_TEMURIN17_FIXED_TAG': fixed_tag, '_TEMURIN17_FIXED_TAG_ARM64': arm_tag,
         '_host_arch': lambda: arch,
         '_JAVA_RUNTIME_RE': None, '_TEMURIN_JDK_TAG_RE': None, '_tak_java_img_cache': {'at': 0.0, 'data': None}}
    src = '\n'.join([_const('_TEMURIN_JDK_TAG_RE'), _const('_JAVA_RUNTIME_RE'),
                     _cut('_temurin_tag_key'), _cut('_temurin17_fixed_tag'), _cut('_temurin_runtime_build'), _cut('_temurin_tag_build'),
                     _cut('_tak_container_java_facts'), _cut('_tak_container_java_facts_cached'),
                     _const('_JAVA_IMAGE_HOW'), _cut('_java_image_items')])
    exec(compile(src, 'app.py', 'exec'), n)
    n['_calls'] = calls
    return n


# ── 1. reading Java, and comparing it ─────────────────────────────────────────────────────────

def test_java_version_text_is_read_as_a_comparable_temurin_build():
    n = _facts_ns()
    f = n['_temurin_runtime_build']
    assert f(JAVA_17_0_19)[0] == '17.0.19+10'
    assert f(JAVA_17_0_21)[0] == '17.0.21+9'
    assert f(JAVA_17_0_21_1)[0] == '17.0.21.1+2'
    assert f(JAVA_17_0_19)[1] < f(JAVA_17_0_21)[1] < f(JAVA_17_0_21_1)[1]
    # the same number from a runtime and from a Docker tag compares equal
    assert f(JAVA_17_0_21)[1] == n['_temurin_tag_key'](FIXED_TAG)
    assert n['_temurin_tag_build'](FIXED_TAG) == '17.0.21+9'


def test_a_runtime_that_is_not_temurin_is_not_read():
    f = _facts_ns()['_temurin_runtime_build']
    assert f(JAVA_DEBIAN) == (None, None)
    assert f('') == (None, None)
    assert f(None) == (None, None)


def test_older_java_in_the_container_is_stale():
    n = _facts_ns(JAVA_17_0_19)
    f = n['_tak_container_java_facts']()
    assert f['applicable'] and f['readable'] and f['stale']
    assert (f['running'], f['newest']) == ('17.0.19+10', '17.0.21+9')
    assert f['sig'] == 'java-image@17.0.19+10>17.0.21+9'
    assert n['_calls'] == [['docker', 'exec', 'takserver', 'java', '-version']]   # read only, no flags


def test_java_on_the_newest_build_or_newer_is_clear():
    assert not _facts_ns(JAVA_17_0_21)['_tak_container_java_facts']()['stale']
    assert not _facts_ns(JAVA_17_0_21_1)['_tak_container_java_facts']()['stale']


def test_the_pin_moving_makes_the_notice_appear_without_other_changes():
    # Docker Hub lists 17.0.21.1_2: the one constant moves, a box on 17.0.21+9 is now behind
    new_tag = '17.0.21.1_2-jdk-ubi10-minimal'
    f = _facts_ns(JAVA_17_0_21, fixed_tag=new_tag)['_tak_container_java_facts']()
    assert f['stale'] and f['newest'] == '17.0.21.1+2'


def test_an_arm64_box_is_compared_with_the_arm64_pin_not_a_tag_it_cannot_pull():
    # amd64 pin 17.0.21.1_2 has no arm64 image; an ARM box on 17.0.21+9 is as new as it can get,
    # so it must NOT be told to rebuild for a Java it cannot receive (a notice it could never clear).
    new_tag = '17.0.21.1_2-jdk-ubi10-minimal'
    arm = _facts_ns(JAVA_17_0_21, fixed_tag=new_tag, arch='arm64', arm_tag=FIXED_TAG)
    f = arm['_tak_container_java_facts']()
    assert f['applicable'] and not f['stale'] and f['newest'] == '17.0.21+9'
    assert arm['_java_image_items'](set()) == []
    # an ARM box still on the shipped Java is told to rebuild, naming the build it can get
    f = _facts_ns(JAVA_17_0_19, fixed_tag=new_tag, arch='arm64', arm_tag=FIXED_TAG)['_tak_container_java_facts']()
    assert f['stale'] and f['newest'] == '17.0.21+9'
    # the same Java on an amd64 box is behind the amd64 pin
    assert _facts_ns(JAVA_17_0_21, fixed_tag=new_tag)['_tak_container_java_facts']()['stale']


def test_another_java_line_or_vendor_claims_nothing():
    f = _facts_ns(JAVA_21)['_tak_container_java_facts']()
    assert f['applicable'] and not f['stale']                       # a 21 is never "older" than 17
    f = _facts_ns(JAVA_DEBIAN)['_tak_container_java_facts']()
    assert not f['applicable'] and not f['stale'] and f['readable']


def test_a_native_install_is_not_this_notice():
    n = _facts_ns(JAVA_17_0_19, container=False)
    f = n['_tak_container_java_facts']()
    assert not f['applicable'] and f['readable'] and not f['stale']
    assert n['_calls'] == []                                         # no docker call on a native box


def test_a_stopped_container_or_a_failed_exec_is_could_not_tell():
    f = _facts_ns(JAVA_17_0_19, running=False)['_tak_container_java_facts']()
    assert not f['readable'] and not f['stale'] and not f['applicable']
    f = _facts_ns('Error response from daemon', rc=1)['_tak_container_java_facts']()
    assert not f['readable'] and not f['stale']
    f = _facts_ns(boom=_real_subprocess.TimeoutExpired('docker', 30))['_tak_container_java_facts']()
    assert not f['readable'] and not f['stale']


def test_the_check_is_cached_so_a_page_visit_is_not_a_docker_call():
    n = _facts_ns(JAVA_17_0_19)
    a = n['_tak_container_java_facts_cached']()
    b = n['_tak_container_java_facts_cached']()
    assert a is b and len(n['_calls']) == 1


# ── 2. the update email ───────────────────────────────────────────────────────────────────────

def test_stale_java_is_one_plain_update_item_with_the_step():
    n = _facts_ns(JAVA_17_0_19)
    unknown = set()
    (item,) = n['_java_image_items'](unknown)
    assert item['key'] == 'java-image' and unknown == set()
    assert (item['installed'], item['target']) == ('Java 17.0.19+10', 'Java 17.0.21+9')
    assert item['identity'] == 'java-image@17.0.19+10>17.0.21+9'
    assert 'security' not in item          # we cannot name an advisory between two builds: no claim
    assert 'Update TAK Server' in item['how'] and 'takserver-docker' in item['how']
    assert 'inside its image' in ' '.join(item['detail'])
    assert item['detail'][0] == 'TAK Server runs Java 17.0.19+10. Java 17.0.21+9 is available.'


def test_clear_not_applicable_and_native_say_nothing_and_carry_nothing():
    for kw in ({}, {'container': False}):
        unknown = set()
        text = JAVA_17_0_21 if not kw else JAVA_17_0_19
        assert _facts_ns(text, **kw)['_java_image_items'](unknown) == [] and unknown == set()
    unknown = set()
    assert _facts_ns(JAVA_DEBIAN)['_java_image_items'](unknown) == [] and unknown == set()


def test_a_container_that_could_not_be_asked_carries_its_state_instead_of_guessing():
    unknown = set()
    assert _facts_ns(JAVA_17_0_19, running=False)['_java_image_items'](unknown) == []
    assert unknown == {'java-image'}


def _sweep(pending, state):
    sent, saved = [], []
    n = {
        'socket': types.SimpleNamespace(gethostname=lambda: 'box'),
        'load_settings': lambda: {'guarddog_alert_email': 'ops@example.com', 'fqdn': 'tak.example.com',
                                  'console_port': 5001, 'update_channel': 'main'},
        '_safe_alert_email_list': lambda v: v,
        '_gd_quiet_state': lambda: (False, 0, ''),
        '_guarddog_server_identifier': lambda s: 'tak-docker-1',
        '_update_notify_state_load': lambda: json.loads(json.dumps(state)),
        '_update_notify_state_save': lambda s: saved.append(s),
        '_guarddog_send_alert_email_via_relay': lambda to, subj, body: sent.append((subj, body)),
        'print': lambda *a, **k: None,
        'time': time,
        'PATCH_NOW_REPEAT_S': 24 * 3600,
        '_collect_patch_now_items': lambda feed, unknown, now=None: ([], feed),
        '_collect_pending_updates': lambda settings, seen=None, unknown=None, etl=None: json.loads(json.dumps(pending)),
    }
    src = '\n'.join([_cut('_carried_by_unknown'), _cut('_update_notify_check_once')])
    exec(compile(src, 'app.py', 'exec'), n)
    return n['_update_notify_check_once'](), sent, saved


def test_the_mail_names_both_builds_and_the_step_once_then_stays_quiet():
    (item,) = _facts_ns(JAVA_17_0_19)['_java_image_items'](set())
    r, sent, saved = _sweep([item], {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '⬆ Update pending on tak-docker-1'                    # not a "Security update" claim
    assert 'Java (TAK Server container): Java 17.0.19+10 → Java 17.0.21+9' not in body   # summary is used
    assert 'Java inside the TAK Server container: a newer Java is available' in body
    assert '      TAK Server runs Java 17.0.19+10. Java 17.0.21+9 is available.' in body
    assert 'To install: TAK Server page → Update TAK Server' in body
    assert saved[-1]['java-image'] == 'java-image@17.0.19+10>17.0.21+9'
    r2, sent2, _ = _sweep([item], saved[-1])
    assert r2['emailed'] is False and sent2 == []


def test_a_new_gap_mails_again_and_a_rebuild_clears_the_state():
    (item,) = _facts_ns(JAVA_17_0_19)['_java_image_items'](set())
    _, _, saved = _sweep([item], {})
    # the pin moves on: same box, a bigger gap, one more mail
    (item2,) = _facts_ns(JAVA_17_0_19, fixed_tag='17.0.21.1_2-jdk-ubi10-minimal')['_java_image_items'](set())
    assert item2['identity'] != item['identity']
    r, sent, saved2 = _sweep([item2], saved[-1])
    assert r['emailed'] is True and len(sent) == 1
    # the image was rebuilt: nothing pending, the entry is dropped so a later gap mails again
    r3, _, saved3 = _sweep([], saved2[-1])
    assert r3['emailed'] is False and 'java-image' not in saved3[-1]


# ── 3. the wiring ─────────────────────────────────────────────────────────────────────────────

def test_the_email_sweep_collects_the_docker_java_item():
    assert 'pending.extend(_java_image_items(unknown))' in _cut('_collect_pending_updates')


def test_os_updates_answer_carries_the_docker_java_state():
    facts = {'applicable': True, 'stale': True, 'running': '17.0.19+10', 'newest': '17.0.21+9',
             'sig': 'java-image@17.0.19+10>17.0.21+9'}
    n = {'request': types.SimpleNamespace(args={}), 'jsonify': lambda d: d,
         '_os_updates_summary': lambda force=False: {'total': 0},
         '_kernel_reboot_state': lambda: {'pending': False, 'kernel': False, 'running': 'k'},
         '_kernel_cve_banner': lambda r: None,
         '_java_restart_state': lambda: {'stale': [], 'sig': ''},
         '_tak_container_java_facts_cached': lambda: facts,
         '_JAVA_IMAGE_HOW': 'how'}
    exec(compile(_cut('os_updates_api'), 'app.py', 'exec'), n)
    ji = n['os_updates_api']()['java_image']
    assert ji == {'stale': True, 'running': '17.0.19+10', 'newest': '17.0.21+9',
                  'sig': 'java-image@17.0.19+10>17.0.21+9', 'how': 'how'}
    facts.update(applicable=False, stale=True)        # not a Docker install: never shown
    assert n['os_updates_api']()['java_image']['stale'] is False


def test_the_console_has_the_docker_java_banner():
    assert 'id="java-image-banner"' in CONSOLE
    assert 'try{_javaImageRender(ud);}catch(e){}' in CONSOLE
    # text from the server is set as text, never as HTML
    j = CONSOLE[CONSOLE.index('function _javaImageRender'):CONSOLE.index('function dismissJavaImage')]
    assert 'textContent' in j and 'innerHTML' not in j


_BANNER_JS_HARNESS = r'''
const store = {};
global.localStorage = {getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }};
function mk() { return {style: {}, attrs: {}, textContent: '', setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k] || null; }}; }
const els = {'java-image-banner': mk(), 'java-image-body': mk(), 'java-image-how': mk()};
global.document = {getElementById: id => els[id] || null};
%s
const b = els['java-image-banner'];
const out = [];
const J = (sig) => ({java_image: {stale: true, running: '17.0.19+10', newest: '17.0.21+9', sig: sig, how: 'Update TAK Server'}});
_javaImageRender(J('a'));                                   out.push(b.style.display);     // block
_javaImageRender({java_image: {stale: false}});             out.push(b.style.display);     // none
_javaImageRender({});                                       out.push(b.style.display);     // none
_javaImageRender(J('a'));                                   out.push(b.style.display);     // block
dismissJavaImage();                                         out.push(b.style.display);     // none
_javaImageRender(J('a'));                                   out.push(b.style.display);     // none (dismissed)
_javaImageRender(J('b'));                                   out.push(b.style.display);     // block (new gap)
store['java-image-dismissed'] = JSON.stringify({sig: 'b', ts: Date.now() - 25 * 3600 * 1000});
_javaImageRender(J('b'));                                   out.push(b.style.display);     // block (24 h passed)
console.log(out.join(','));
console.log(els['java-image-body'].textContent);
'''


@pytest.mark.skipif(not shutil.which('node'), reason='node not installed')
def test_banner_shows_hides_and_stays_quiet_for_a_day_per_gap(tmp_path):
    a = CONSOLE.index('// ops #968')
    b = CONSOLE.index('async function checkKernelPatch(){')
    js = tmp_path / 'banner.js'
    js.write_text(_BANNER_JS_HARNESS % CONSOLE[a:b])
    r = _real_subprocess.run(['node', str(js)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    lines = r.stdout.strip().splitlines()
    assert lines[0] == 'block,none,none,block,none,none,block,block'
    assert 'Java 17.0.19+10' in lines[1] and 'Java 17.0.21+9 is available' in lines[1]
