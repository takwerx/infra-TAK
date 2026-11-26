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
"""The Rocky 9 / RHEL 9 Caddy install tells why it failed and tries again (ops #1295).

In the 10.4.8 test the Caddy step on Rocky 9 failed in 2 seconds with only "Caddy install failed"
in the log; every later module then said "not tried". The same install passed minutes later, so
the @caddy/caddy COPR had answered badly for a moment. The old code did not check the COPR step,
never retried, and never printed what dnf said.
The helper is cut out of app.py and run against stubs: the code under test is the shipped text.
"""

import ast
import pathlib
import subprocess
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _cp(rc, out=''):
    return subprocess.CompletedProcess([], rc, out, None)


def _load(results):
    """results: outcome of each dnf call in turn (last repeats). An Exception is raised instead."""
    rec = SimpleNamespace(calls=[], slept=[], logs=[])
    queue = list(results)

    def fake_run(cmd, **kw):
        rec.calls.append((cmd, kw))
        out = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(out, Exception):
            raise out
        return out

    ns = {
        'subprocess': SimpleNamespace(run=fake_run, PIPE=-1, STDOUT=-2, CompletedProcess=subprocess.CompletedProcess,
                                      TimeoutExpired=subprocess.TimeoutExpired),
        'time': SimpleNamespace(sleep=rec.slept.append),
        '_sudo_wrap': lambda c: c,
    }
    for name in ('CADDY_DNF_TRIES', 'CADDY_DNF_DELAY', '_caddy_dnf_install'):
        exec(_segment(name), ns)
    return ns, rec


PLUGIN = _cp(0)
COPR_DOWN = _cp(1, 'Error: Failed to connect to copr.fedorainfracloud.org port 443: Connection timed out')
ENABLED = _cp(0)
NO_MATCH = _cp(1, 'Error: Unable to find a match: caddy')
INSTALLED = _cp(0, 'Complete!')


def _argv(rec):
    return [' '.join(c[0]) for c in rec.calls]


def test_a_failed_dnf_step_prints_what_dnf_said():
    ns, rec = _load([PLUGIN, COPR_DOWN])
    assert ns['_caddy_dnf_install'](rec.logs.append, tries=1) is False
    text = '\n'.join(rec.logs)
    assert 'dnf copr enable @caddy/caddy failed (try 1 of 1)' in text
    assert 'copr.fedorainfracloud.org' in text


def test_only_the_last_300_characters_of_dnf_output_are_printed():
    long = _cp(1, 'A' * 5000 + 'THE-REASON')
    ns, rec = _load([PLUGIN, long])
    ns['_caddy_dnf_install'](rec.logs.append, tries=1)
    line = next(m for m in rec.logs if 'failed (try 1' in m)
    assert 'THE-REASON' in line and 'A' * 400 not in line


def test_a_failed_copr_step_is_tried_again_and_the_install_then_passes():
    ns, rec = _load([PLUGIN, COPR_DOWN, ENABLED, INSTALLED])
    assert ns['_caddy_dnf_install'](rec.logs.append) is True
    assert _argv(rec) == [
        'dnf install -y dnf-command(copr)',
        'dnf copr enable -y @caddy/caddy',
        'dnf copr enable -y @caddy/caddy',
        'dnf install -y caddy',
    ]
    assert rec.slept == [ns['CADDY_DNF_DELAY']]


def test_a_failed_install_after_a_good_enable_is_tried_again():
    ns, rec = _load([PLUGIN, ENABLED, NO_MATCH, ENABLED, INSTALLED])
    assert ns['_caddy_dnf_install'](rec.logs.append) is True
    assert 'the caddy package install failed (try 1 of' in '\n'.join(rec.logs)
    assert len(rec.slept) == 1


def test_install_is_not_run_when_the_copr_step_failed():
    ns, rec = _load([PLUGIN, COPR_DOWN])
    ns['_caddy_dnf_install'](rec.logs.append, tries=2, delay=0)
    assert 'dnf install -y caddy' not in _argv(rec)


def test_it_gives_up_after_the_set_number_of_tries_and_waits_between_them():
    ns, rec = _load([PLUGIN, COPR_DOWN])
    assert ns['_caddy_dnf_install'](rec.logs.append, tries=3, delay=7) is False
    assert _argv(rec).count('dnf copr enable -y @caddy/caddy') == 3
    assert rec.slept == [7, 7]           # no wait after the last try
    assert ns['CADDY_DNF_TRIES'] >= 3


def test_a_timeout_is_a_failed_try_not_a_crash():
    hang = subprocess.TimeoutExpired('dnf', 120)
    ns, rec = _load([PLUGIN, hang])
    assert ns['_caddy_dnf_install'](rec.logs.append, tries=1) is False
    assert 'timed out after 120 seconds' in '\n'.join(rec.logs)


def test_a_missing_copr_plugin_is_logged_and_the_install_goes_on():
    ns, rec = _load([_cp(1, 'No match for argument: dnf-command(copr)'), ENABLED, INSTALLED])
    assert ns['_caddy_dnf_install'](rec.logs.append) is True
    assert any('copr plugin' in m and 'No match' in m for m in rec.logs)


def test_deploy_uses_the_helper_and_says_why_it_stopped():
    body = _segment('run_caddy_deploy')
    assert '_caddy_dnf_install(plog)' in body
    # the old branch ran the COPR step unchecked and stopped with a bare line
    assert "plog(f\"✗ Caddy install failed\")" not in body
    assert "'copr', 'enable'" not in body
    stop = body[body.index('_caddy_dnf_install(plog)'):]
    stop = stop[:stop.index('# Verify install')]
    assert 'dnf could not install Caddy' in stop and 'reason above' in stop


def test_a_dnf_failure_goes_on_only_when_part_of_caddy_is_already_here():
    """The static build has no caddy user or service, so with no caddy and no rpm, stop."""
    body = _segment('run_caddy_deploy')
    stop = body[body.index('_caddy_dnf_install(plog)'):]
    stop = stop[:stop.index('# Verify install')]
    assert "'caddy version'" in stop and "['rpm', '-q', 'caddy']" in stop
    assert 'if _have_bin or _have_rpm' in stop
    assert "caddy_deploy_status.update({'running': False, 'error': True})" in stop
