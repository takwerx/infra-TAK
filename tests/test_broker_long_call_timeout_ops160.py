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
"""No new long broker call that leaves the broker at its 600 s default (ops #160).

On a non-root box _sudo_wrap() sends the command through the broker client, and the broker
kills anything that does not ask for longer at its 600 s default. A caller asks with
TAKWERX_BROKER_TIMEOUT in the env. TAK Portal's Deploy and Update builds gave subprocess.run
900 s and never told the broker, so slow builds died at exactly 10 minutes. This scans every
subprocess.run(_sudo_wrap(...), timeout=N) in app.py with N past the broker default.
"""

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
TREE = ast.parse((REPO / 'app.py').read_text(encoding='utf-8'))

BROKER_DEFAULT = 600   # broker/takwerx_broker.py DEFAULT_TIMEOUT
_RUNNERS = {'subprocess.run', '_sp.run', 'subprocess.check_output'}
# env helpers that set TAKWERX_BROKER_TIMEOUT themselves
_ENV_HELPERS = {'_tak58_long_env()', '_takportal_build_env()'}

# Long _sudo_wrap() calls that still leave the broker at 600 s, found when this test was
# written. Listed so a NEW one fails here; remove an entry when it is fixed.
KNOWN_GAPS = {
    '_cloudtak_build_arm64_media': 1,
    '_auto_authentik_tasklog_purge': 2,
    '_tak58_container_export': 1,
    'run_takserver_58_two_server_migration': 1,
}


# module-level int constants, so `timeout=_TAKPORTAL_BUILD_TIMEOUT + 60` is scanned too
_CONSTS = {t.id: s.value.value for s in TREE.body if isinstance(s, ast.Assign)
           and isinstance(s.value, ast.Constant) and type(s.value.value) is int
           for t in s.targets if isinstance(t, ast.Name)}


def _seconds(node):
    """The value of a timeout= expression built from ints, module constants, + - * //; else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.Name):
        return _CONSTS.get(node.id)
    if isinstance(node, ast.BinOp):
        a, b = _seconds(node.left), _seconds(node.right)
        if a is None or b is None:
            return None
        ops = {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b,
               ast.FloorDiv: lambda: a // b if b else None}
        return ops[type(node.op)]() if type(node.op) in ops else None
    return None


def _long_broker_calls(fn):
    out = []
    for n in ast.walk(fn):
        if not (isinstance(n, ast.Call) and ast.unparse(n.func) in _RUNNERS and n.args):
            continue
        a0 = n.args[0]
        if not (isinstance(a0, ast.Call) and ast.unparse(a0.func) == '_sudo_wrap'):
            continue
        kw = {k.arg: k.value for k in n.keywords}
        t = _seconds(kw['timeout']) if 'timeout' in kw else None
        if t is not None and t > BROKER_DEFAULT:
            out.append(kw.get('env'))
    return out


def _passes_timeout(env):
    return env is not None and ('TAKWERX_BROKER_TIMEOUT' in ast.unparse(env)
                                or ast.unparse(env) in _ENV_HELPERS)


def test_takportal_builds_are_scanned_and_pass():
    fns = {n.name: n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)}
    for name in ('_takportal_run_update', 'run_takportal_deploy'):
        envs = _long_broker_calls(fns[name])
        assert envs and all(_passes_timeout(e) for e in envs), name


def test_no_new_long_broker_call_without_a_timeout():
    gaps = {}
    for fn in ast.walk(TREE):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            n = sum(not _passes_timeout(env) for env in _long_broker_calls(fn))
            if n:
                gaps[fn.name] = n
    assert gaps == KNOWN_GAPS
