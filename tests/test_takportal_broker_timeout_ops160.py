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
"""TAK Portal Update and Deploy builds get their 900 s on non-root boxes too (ops #160).

On a non-root box _sudo_wrap() sends the command through the broker client, and the broker
kills anything that does not ask for longer at its 600 s default. TAK Portal's Update and
Deploy builds allowed 900 s in subprocess.run but never told the broker, so a slow build on
test12 was killed at 600 s. A caller asks for more with TAKWERX_BROKER_TIMEOUT in the env.
"""

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

BROKER_DEFAULT = 600   # broker/takwerx_broker.py DEFAULT_TIMEOUT
_RUNNERS = {'subprocess.run', '_sp.run', 'subprocess.check_output'}


def _functions():
    return {n.name: n for n in ast.walk(TREE) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _long_broker_calls(fn):
    """subprocess calls in fn that go through _sudo_wrap() with a timeout past the broker default."""
    out = []
    for n in ast.walk(fn):
        if not (isinstance(n, ast.Call) and ast.unparse(n.func) in _RUNNERS and n.args):
            continue
        a0 = n.args[0]
        if not (isinstance(a0, ast.Call) and ast.unparse(a0.func) == '_sudo_wrap'):
            continue
        kw = {k.arg: k.value for k in n.keywords}
        t = kw.get('timeout')
        if isinstance(t, ast.Constant) and isinstance(t.value, (int, float)) and t.value > BROKER_DEFAULT:
            out.append((n, t.value, kw.get('env')))
    return out


def _broker_timeout(env):
    """The TAKWERX_BROKER_TIMEOUT an env={**os.environ, ...} literal sets, or None."""
    if not isinstance(env, ast.Dict):
        return None
    for k, v in zip(env.keys, env.values):
        if isinstance(k, ast.Constant) and k.value == 'TAKWERX_BROKER_TIMEOUT':
            return int(ast.literal_eval(v)) if isinstance(v, ast.Constant) else None
    return None


def _build_call(fn_name, argv_text):
    calls = [c for c in _long_broker_calls(_functions()[fn_name]) if argv_text in ast.unparse(c[0].args[0])]
    assert len(calls) == 1, (fn_name, calls)
    return calls[0]


def test_update_build_tells_the_broker_its_timeout():
    _, timeout, env = _build_call('_takportal_run_update', "'compose', 'up', '-d', '--build'")
    assert timeout == 900
    assert _broker_timeout(env) == timeout


def test_deploy_build_tells_the_broker_its_timeout():
    _, timeout, env = _build_call('run_takportal_deploy', "'--build', '--no-start'")
    assert timeout == 900
    assert _broker_timeout(env) == timeout


def test_env_keeps_the_rest_of_the_environment():
    # env= replaces the child's whole environment: PATH (the broker shims) and HOME must survive.
    for fn, argv in (('_takportal_run_update', "'--build'"), ('run_takportal_deploy', "'--no-start'")):
        _, _, env = _build_call(fn, argv)
        assert any(k is None and ast.unparse(v) == 'os.environ' for k, v in zip(env.keys, env.values)), fn


# Other long _sudo_wrap() calls found by the same scan that still leave the broker at 600 s.
# Out of scope for ops #160 and listed so a new one fails here; remove an entry when it is fixed.
KNOWN_GAPS = {
    '_cloudtak_build_arm64_media': 1,
    '_auto_authentik_tasklog_purge': 2,
    '_tak58_container_export': 1,
    'run_takserver_58_two_server_migration': 1,
}


def _passes_timeout(env):
    return env is not None and ('TAKWERX_BROKER_TIMEOUT' in ast.unparse(env)
                                or ast.unparse(env) == '_tak58_long_env()')


def test_no_new_long_broker_call_without_a_timeout():
    gaps = {}
    for name, fn in _functions().items():
        n = sum(not _passes_timeout(env) for _, _, env in _long_broker_calls(fn))
        if n:
            gaps[name] = n
    assert gaps == KNOWN_GAPS
