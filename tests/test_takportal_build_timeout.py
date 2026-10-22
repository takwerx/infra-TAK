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
"""TAK Portal's image build gets the time it asks for, and a failed build says why.

Found standing up two fresh split installs on 4-vCPU AWS boxes (2026-10-21): both Portal
deploys died at exactly 10 minutes with

    takwerx_broker: TIMEOUT: command timed out
    ✗ Docker build failed
    ✗ FATAL ERROR: 'NoneType' object has no attribute 'strip'

Two bugs. The build ran through the broker, which kills its child at its own DEFAULT_TIMEOUT
(600 s) unless the request carries TAKWERX_BROKER_TIMEOUT, so the 900 s both Deploy and Update
passed to subprocess.run never applied (Portal 2.x builds web + worker and took just over
10 min). And Deploy merges stderr into stdout, then read r.stderr on failure: None, so every
failed deploy crashed instead of reporting. The same None-read sat in two TAK Server restart
warnings.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER = (REPO / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')
BROKERCTL = (REPO / 'broker' / 'takwerx_brokerctl.py').read_text(encoding='utf-8')


def _body(start, end):
    return APP[APP.index(start):APP.index(end)]


def _broker_const(name):
    return int(re.search(r'^%s = (\d+)' % name, BROKER, re.M).group(1))


DEPLOY = _body('def run_takportal_deploy():',
               '_ensure_infratak_network_for_portal()\n        _ensure_infratak_network_for_authentik()\n\n        # Seed real settings.json')
DEPLOY_BUILD = DEPLOY[DEPLOY.index('Building image (this may take a minute)'):]
UPDATE = _body('def _takportal_run_update(portal_dir):', "@app.route('/api/takportal/update/status')")


def test_build_budget_exceeds_the_broker_default_and_fits_its_ceiling():
    budget = int(re.search(r'^_TAKPORTAL_BUILD_TIMEOUT = (\d+)', APP, re.M).group(1))
    assert _broker_const('DEFAULT_TIMEOUT') < budget <= _broker_const('MAX_TIMEOUT')


def test_build_env_carries_the_budget_to_the_broker():
    assert "'TAKWERX_BROKER_TIMEOUT': str(_TAKPORTAL_BUILD_TIMEOUT)" in APP
    # the client forwards that variable on the request; the daemon clamps it to MAX_TIMEOUT
    assert "os.environ.get('TAKWERX_BROKER_TIMEOUT')" in BROKERCTL


def test_both_builds_pass_the_budget_and_wait_past_it():
    for name, body in (('deploy', DEPLOY_BUILD), ('update', UPDATE)):
        call = body[body.index("_sudo_wrap(['docker', 'compose', 'up', '-d', '--build'"):]
        call = call[:call.index('except subprocess.TimeoutExpired')]
        assert 'env=_takportal_build_env()' in call, name
        assert 'timeout=_TAKPORTAL_BUILD_TIMEOUT + 60' in call, name
        assert 'timeout=900' not in call, name


def test_deploy_reports_a_failed_build_instead_of_crashing():
    assert 'stderr=subprocess.STDOUT' in DEPLOY_BUILD
    assert not re.search(r'\br\.stderr\.\w+\(', DEPLOY_BUILD)
    assert 'except subprocess.TimeoutExpired:' in DEPLOY_BUILD
    assert 'Docker build failed (exit {r.returncode})' in DEPLOY_BUILD


def test_no_merged_stderr_is_read_back_anywhere():
    """A subprocess.run(..., stderr=subprocess.STDOUT) result has .stderr None; reading it
    unguarded crashes exactly when the command failed — the one time its output matters."""
    lines = APP.split('\n')
    bad = []
    for i, line in enumerate(lines):
        m = re.match(r'\s*(\w+)\s*=\s*subprocess\.run\(', line)
        if not m or 'stderr=subprocess.STDOUT' not in '\n'.join(lines[i:i + 4]):
            continue
        var = m.group(1)
        for j in range(i + 1, min(i + 40, len(lines))):
            if re.match(r'\s*%s\s*=' % var, lines[j]):
                break
            hit = re.search(r'\b%s\.stderr\.(strip|split|splitlines|lower)\(' % var, lines[j])
            if hit and not re.search(r'if %s\.stderr else' % var, lines[j]):
                bad.append(f'app.py:{j + 1}: {lines[j].strip()[:120]}')
    assert not bad, '\n'.join(bad)
