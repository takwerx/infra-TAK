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
"""infra-TAK #815 (ops #1451): the old red "Last update failed" card must go when a new TAK Server update starts.

Runs the REAL startTakUpdate() from static/takserver.js in node against a stub page. The stub page holds
the TAK Server failure card and one card of another module; its querySelectorAll only understands the
selector shape the real card has (class module-last-result, data-module="NAME"), so a selector that does
not match the card in templates/_module_result.html cannot pass. Skipped when node is not installed.

Reported with a fix by Sentinel6Systems (PR #816)."""
import json
import pathlib
import shutil
import subprocess
import textwrap

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
JS = (ROOT / 'static' / 'takserver.js').read_text(encoding='utf-8')
FN = JS[JS.index('async function startTakUpdate('):JS.index('function pollUpgradeLog(')]

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')

HARNESS = textwrap.dedent("""
    let upgradeFileReady = true, upgradeLogIndex = 0, polled = 0;
    function isUpgradeTwoServerMode(){ return false; }
    function pollUpgradeLog(){ polled++; }
    function mkEl(){ return {style:{}, textContent:'', disabled:false}; }
    const els = {'tak-update-btn': mkEl(), 'tak-update-msg': mkEl(), 'upgrade-log-wrap': mkEl(), 'upgrade-log': mkEl()};
    let cards;
    const document = {
      body: {getAttribute: () => null},
      getElementById: (id) => els[id] || null,
      querySelectorAll: (sel) => {
        const m = /^\\.module-last-result\\[data-module="([a-z-]+)"\\]$/.exec(sel);
        if (!m) throw new Error('selector the real card cannot match: ' + sel);
        return cards.filter(c => c.module === m[1]);
      },
    };
    %s
    async function scenario(fetchImpl){
      cards = [];
      ['takserver', 'authentik'].forEach(m => {
        const c = {module: m, removed: false};
        c.remove = () => { c.removed = true; cards = cards.filter(x => x !== c); };
        cards.push(c);
      });
      const all = cards.slice();
      globalThis.fetch = fetchImpl;
      polled = 0; els['tak-update-btn'].disabled = false; els['tak-update-msg'].textContent = '';
      await startTakUpdate();
      return {tak_removed: all[0].removed, other_removed: all[1].removed, polled,
              btn_disabled: els['tak-update-btn'].disabled, msg: els['tak-update-msg'].textContent};
    }
    (async () => {
      const out = {};
      out.accepted = await scenario(async () => ({json: async () => ({status: 'started'})}));
      out.refused = await scenario(async () => ({json: async () => ({error: 'Upload a .deb package first.'})}));
      out.network = await scenario(async () => { throw new Error('Failed to fetch'); });
      console.log(JSON.stringify(out));
    })();
""") % FN


@pytest.fixture(scope='module')
def out():
    r = subprocess.run(['node', '-e', HARNESS], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_accepted_update_removes_the_old_failure_card_and_starts_polling(out):
    assert out['accepted']['tak_removed'] is True
    assert out['accepted']['polled'] == 1


def test_only_the_takserver_card_is_removed(out):
    assert out['accepted']['other_removed'] is False


def test_refused_update_keeps_the_old_card_so_the_customer_still_sees_why(out):
    assert out['refused']['tak_removed'] is False
    assert out['refused']['polled'] == 0
    assert out['refused']['msg'] == 'Upload a .deb package first.'
    assert out['refused']['btn_disabled'] is False


def test_network_error_keeps_the_old_card_and_the_button_usable(out):
    assert out['network']['tak_removed'] is False
    assert out['network']['polled'] == 0
    assert out['network']['msg'] == 'Error: Failed to fetch'
    assert out['network']['btn_disabled'] is False


def test_the_selector_matches_the_markup_of_the_real_card():
    card = (ROOT / 'templates' / '_module_result.html').read_text(encoding='utf-8')
    assert '<div class="module-last-result" data-module="{{ module }}"' in card
    page = (ROOT / 'templates' / 'takserver.html').read_text(encoding='utf-8')
    assert "last_update_result('takserver')" in page
