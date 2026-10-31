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
"""TAK Portal Update keeps the real build failure line (ops #380, Aust-TAK diagnostics).

Field (ops1, v10.3.3): the Update record said `2.0.25 -> ?` and `Build failed: Image
tak-portal-tak-portal-worker Building`. The code kept the HEAD of compose's output
(`[:400]`), which is only the progress ledger; the reason sits at the end. The target
version was also only recorded on success.

app.py cannot be imported in a test, so the helpers are cut out of it.
"""

import ast
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_NAMES = {'_ANSI_RE', '_UPDATE_NOISE_RE', '_UPDATE_ERROR_RE', '_update_error_line', '_mod_result_scrub',
          '_BUILD_PROGRESS_RE', '_BUILD_STEP_PREFIX_RE', '_BUILD_FAILED_STEP_RE', '_BUILD_LISTING_RE',
          '_build_failure_text'}


def _ns():
    from collections import deque
    tree = ast.parse(APP)
    body = []
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name in _NAMES:
            body.append(n)
        elif isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in _NAMES for t in n.targets):
            body.append(n)
    assert {getattr(n, 'name', None) or n.targets[0].id for n in body} == _NAMES
    ns = {'re': re, 'deque': deque}
    exec(compile(ast.Module(body=body, type_ignores=[]), 'app.py', 'exec'), ns)
    return ns


# Shape of `docker compose up -d --build` stderr when a Dockerfile step fails: the ledger first,
# buildkit steps in the middle, the reason and the wrapper last.
COMPOSE_APK_FAIL = '\n'.join([
    ' Image tak-portal-tak-portal Building',
    ' Image tak-portal-tak-portal-worker Building',
    '#1 [tak-portal-worker internal] load build definition from Dockerfile',
    '#1 DONE 0.0s',
    '#5 [tak-portal-worker 2/6] RUN apk add --no-cache git nodejs-current npm',
    '#5 11.25 ERROR: unable to select packages:',
    '#5 11.25   nodejs-current (no such package):',
    '#5 11.25     required by: world[nodejs-current]',
    '#5 ERROR: process "/bin/sh -c apk add --no-cache git nodejs-current npm" did not complete '
    'successfully: exit code: 1',
    '------',
    ' > [tak-portal-worker 2/6] RUN apk add --no-cache git nodejs-current npm:',
    '------',
    'failed to solve: process "/bin/sh -c apk add --no-cache git nodejs-current npm" did not complete '
    'successfully: exit code: 1',
])

COMPOSE_DNS_FAIL = '\n'.join([
    '[+] Building 60.2s (9/12)',
    ' Image tak-portal-tak-portal-worker Building',
    '#9 42.85 Resolving github.com (github.com)... failed: Try again.',
    '#9 ERROR: process "/bin/sh -c wget -O data.zip $URL" did not complete successfully: exit code: 4',
    'failed to solve: process "/bin/sh -c wget -O data.zip $URL" did not complete successfully: exit code: 4',
])


# Captured from a real failing `docker compose -p x up -d --no-start --build` on test6 (Ubuntu 24.04,
# TAK Portal 2.0.25 with a bad `apk add` inserted): non-tty compose puts the buildkit step output
# on STDOUT and only a Dockerfile excerpt plus the "failed to solve" wrapper on STDERR.
REAL_STDOUT = """#1 [internal] load local bake definitions
#1 reading from stdin 913B done
#1 DONE 0.0s

#7 [tak-portal-worker 2/8] RUN apk add --no-cache nosuchpackage-ops380
#7 1.964 ERROR: unable to select packages:
#7 1.964   nosuchpackage-ops380 (no such package):
#7 1.964     required by: world[nosuchpackage-ops380]
#7 ERROR: process "/bin/sh -c apk add --no-cache nosuchpackage-ops380" did not complete successfully: exit code: 1
------
 > [tak-portal-worker 2/8] RUN apk add --no-cache nosuchpackage-ops380:
1.964 ERROR: unable to select packages:
1.964   nosuchpackage-ops380 (no such package):
1.964     required by: world[nosuchpackage-ops380]
------
"""
REAL_STDERR = """ Image tp380-tak-portal-worker Building
 Image tp380-tak-portal Building
Dockerfile:3

--------------------

   1 |     # Dockerfile

   2 |     FROM node:22-alpine

   3 | >>> RUN apk add --no-cache nosuchpackage-ops380

   4 |     

--------------------

target tak-portal: failed to solve: process "/bin/sh -c apk add --no-cache nosuchpackage-ops380" did not complete successfully: exit code: 1
"""


def test_real_compose_output_gives_the_reason_and_not_the_dockerfile_listing():
    ns = _ns()
    out = ns['_build_failure_text'](REAL_STDOUT + '\n' + REAL_STDERR)
    assert 'ERROR: unable to select packages' in out
    assert 'nosuchpackage-ops380 (no such package)' in out
    assert 'failed step: apk add --no-cache nosuchpackage-ops380, exit code 1' in out
    assert 'Image tp380' not in out and '>>>' not in out and 'Dockerfile:3' not in out
    assert out.count('unable to select packages') == 1          # buildkit prints it twice


def test_failed_to_solve_with_a_real_reason_is_kept():
    ns = _ns()
    out = ns['_build_failure_text']('failed to solve: node:22-alpine: failed to resolve source metadata for '
                                    'docker.io/library/node:22-alpine: dial tcp: lookup registry-1.docker.io: no such host')
    assert 'lookup registry-1.docker.io: no such host' in out


def test_cause_and_failed_step_survive():
    ns = _ns()
    out = ns['_build_failure_text'](COMPOSE_APK_FAIL)
    assert 'unable to select packages' in out
    assert 'no such package' in out
    assert 'failed step: apk add --no-cache git nodejs-current npm' in out
    assert '\n' not in out
    assert 'Image tak-portal' not in out and 'DONE' not in out


def test_network_failure_names_the_host():
    ns = _ns()
    out = ns['_build_failure_text'](COMPOSE_DNS_FAIL)
    assert 'Resolving github.com' in out and 'failed' in out
    assert 'wget -O data.zip' in out


def test_record_line_carries_the_cause():
    # _mod_result_finish stores _update_error_line(error): that single line must be the cause
    ns = _ns()
    err = 'Build failed: ' + ns['_build_failure_text'](COMPOSE_DNS_FAIL)
    line = ns['_update_error_line'](err)
    assert 'Resolving github.com' in line
    assert 'Resolving github.com' in err[:200]      # the 200-char summary shows it too


def test_error_status_lines_are_not_dropped_as_progress():
    ns = _ns()
    out = ns['_build_failure_text'](' Container tak-portal-postgres Error\n'
                                    'dependency failed to start: container tak-portal-postgres is unhealthy')
    assert 'Container tak-portal-postgres Error' in out and 'unhealthy' in out


def test_only_progress_gives_empty_so_caller_says_no_reason():
    ns = _ns()
    assert ns['_build_failure_text'](' Image a Building\n Image b Built\n#1 DONE 0.0s') == ''
    assert ns['_build_failure_text']('') == '' and ns['_build_failure_text'](None) == ''


def test_secrets_are_scrubbed_and_length_capped():
    ns = _ns()
    out = ns['_build_failure_text']('ERROR: fetch https://user:hunter2@example.com/x failed\n' + 'x' * 2000)
    assert 'hunter2' not in out
    assert len(out) <= 500


def test_update_uses_the_helper_and_records_target_and_steps():
    start = APP.index('def _takportal_run_update(')
    body = APP[start:APP.index("@app.route('/api/takportal/update/status')", start)]
    assert '_build_failure_text(' in body
    assert "build.stderr or build.stdout or 'Build failed'" not in body
    assert ".strip()[:400]" not in body
    assert "_mod_result_versions('takportal'" in body       # target recorded even when the build fails
    assert "_mod_result_step('takportal'" in body
