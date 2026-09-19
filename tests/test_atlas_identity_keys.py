# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""Every key the long jobs read off their identity exists (W220).

⚠️ **The bug.** `_run_update` logged with `_me['name']` and
`deployment_identity` never returned that key. Every update of every deployment
raised `KeyError: 'name'` on its second log line — and then again *inside the
`except` handler's own `plog`*, so the job died without even recording the
failure. The page showed an error with nothing in it.

⚠️ **It had never once run.** The reference arrived with chunk 8 and the update
button has been dead ever since; the box only reached v1.48.0 because the
operator removed the deployment and deployed it again, which is a different code
path. Four weeks of "update is per-deployment now" was true of the plumbing and
false of the function.

⚠️ **And nothing caught it.** `_run_update` has no behavioural test — it wants
git, Docker, a firewall and Authentik — so it is covered by source-shape guards
that check every `_compose` call passes `inst=`. A missing key in a dict is
invisible to that: it is not a signature, it is a runtime lookup. This file
closes the class rather than the instance.
"""

import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402


SOURCE = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')

#: The jobs that resolve an identity once and then read it for a minute or more.
#: ⚠️ Both, because they are the same code with the destructive half removed —
#: and the half that ran is not the half that broke.
JOBS = ('deploy', '_run_update')


def _function_source(name):
    start = SOURCE.index(chr(10) + 'def %s(' % name) + 1
    end = SOURCE.index(chr(10) + 'def ', start + 1)
    return SOURCE[start:end]


@pytest.fixture
def identity(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    ctx = {'_get_service_domain': lambda s, k: 'atlas.leckliter.net'}
    return atlas.deployment_identity(
        ctx, ai.make('corona', ai.MODE_DYNAMIC, 50, 8761,
                     agency_name='Corona Fire Department'), {})


@pytest.mark.parametrize('job', JOBS)
def test_every_identity_key_a_job_reads_actually_exists(job, identity):
    """⚠️ **The guard this file is for.** `_me['name']` was read three times in
    `_run_update` and returned by nothing."""
    read = set(re.findall(r"_me\[['\"]([a-z_]+)['\"]\]", _function_source(job)))

    assert read, '%s no longer reads its identity' % job
    missing = sorted(read - set(identity))

    assert not missing, (
        '%s reads %s off its identity, which deployment_identity does not '
        'return — a KeyError the moment that line runs' % (job, missing))


def test_the_identity_carries_the_name_the_logs_use(identity):
    assert identity['name'] == 'atlas-corona'


def test_the_plain_deployment_s_name_is_the_one_on_every_box(monkeypatch,
                                                             tmp_path):
    monkeypatch.setattr(atlas, 'install_base',
                        lambda c=None: str(tmp_path).replace(chr(92), '/'))
    ctx = {'_get_service_domain': lambda s, k: 'atlas.leckliter.net'}

    assert atlas.deployment_identity(ctx, None, {})['name'] == 'atlas'


def test_the_update_can_build_its_log_prefix(identity):
    """The exact expression that raised, evaluated. A test asserting the key is
    present is one refactor away from being true while the line is not."""
    assert '[' + identity['name'] + '] update: fetching' == \
        '[atlas-corona] update: fetching'


def test_a_failure_can_still_report_itself(identity):
    """⚠️ The second failure, and the worse one. `plog` itself raised, so the
    `except` handler's own `plog('ERROR: ...')` raised too and the job died
    silently — the page showed an error containing nothing at all."""
    prefix = '[' + identity['name'] + '] update: '

    assert prefix + 'ERROR: boom' == '[atlas-corona] update: ERROR: boom'
