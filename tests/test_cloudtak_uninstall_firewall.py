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
"""CloudTAK uninstall closes what deploy opened; the hardening pass works on RHEL (v10.2.8 W4).

Field, lutak2.net diagnostics: ufw allows for 5000/5002/9997 with nothing listening behind
them — cloudtak_uninstall() tore down containers and never touched the firewall. And the
hardening pass ran a bare `ufw deny …`: on RHEL the broker shim has no ufw behind it, so it
did nothing while printing "CloudTAK UFW rules applied".
"""

import ast
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _module_ns():
    """The CLOUDTAK_FW_* constants + the closer, exec'd from app.py source."""
    tree = ast.parse(APP)
    parts = []
    for n in tree.body:
        if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id.startswith('CLOUDTAK_FW_') for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
        if isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_close_firewall':
            parts.append(ast.get_source_segment(APP, n))
    return '\n\n'.join(parts)


def _close(cfg, backend='ufw', fail=()):
    fw_calls, raw = [], []

    def module_fw(c, verb, port, proto='tcp', log_fn=None):
        fw_calls.append((verb, port, proto))
        return (port not in fail), ('nope' if port in fail else 'ok')
    ns = {
        '_module_fw': module_fw,
        '_fw_backend': lambda: backend,
        '_sudo_wrap': lambda cmd: list(cmd),
        'subprocess': types.SimpleNamespace(
            run=lambda argv, **k: raw.append(list(argv)) or types.SimpleNamespace(returncode=0)),
    }
    exec(compile(_module_ns(), 'app.py', 'exec'), ns)
    logs = []
    closed, failed = ns['_cloudtak_close_firewall'](cfg, log=logs.append)
    return ns, fw_calls, raw, closed, failed, logs


def test_local_ufw_closes_every_allow_and_the_hardening_denies():
    ns, fw, raw, closed, failed, _ = _close({'target_mode': 'local'})
    assert set((p, pr) for _, p, pr in fw) == set(ns['CLOUDTAK_FW_ALLOW'])
    assert all(v == 'remove' for v, _, _ in fw)
    for port in (9997, 18554, 11935, 18890, 5000, 5002):
        assert any(c.startswith(f'{port}/') for c in closed)
    deny_deletes = [a for a in raw if a[:4] == ['ufw', '--force', 'delete', 'deny']]
    assert sorted(int(a[4].split('/')[0]) for a in deny_deletes) == sorted(ns['CLOUDTAK_FW_DENY'])
    assert failed == []


def test_firewalld_has_no_deny_rules_to_delete():
    _, fw, raw, _, _, _ = _close({'target_mode': 'local'}, backend='firewalld')
    assert fw and raw == []


def test_remote_target_goes_through_module_fw_only():
    _, fw, raw, _, _, _ = _close({'target_mode': 'remote', 'remote': {'host': 'x'}})
    assert fw and raw == []


def test_a_failure_is_reported_not_raised():
    _, _, _, closed, failed, logs = _close({'target_mode': 'local'}, fail=(9997,))
    assert any(f.startswith('9997/tcp') for f in failed)
    assert any('could not close' in l for l in logs)
    assert closed


def test_uninstall_calls_the_closer_after_teardown():
    body = re.search(r"^def cloudtak_uninstall\(.*?(?=^@app\.route)", APP, re.S | re.M).group(0)
    rm = body.index("_sudo_wrap(['rm', '-rf', cloudtak_dir])")
    close = body.index('_cloudtak_close_firewall(cfg)')
    deployed = body.index("cfg['deployed'] = False")
    assert rm < close < deployed


def test_deploy_and_stream_opener_read_the_same_constants():
    assert 'for _p, _pr in CLOUDTAK_FW_WEB:' in APP
    opener = re.search(r'^def _cloudtak_open_stream_ports\(.*?(?=^def )', APP, re.S | re.M).group(0)
    assert 'CLOUDTAK_FW_STREAM' in opener


def test_hardening_pass_has_no_bare_ufw_deny_or_allow():
    start = APP.index('def _auto_harden_cloudtak():')
    body = APP[start:start + 40000]
    body = body[:body.index('# 7. Recreate the stack only if clean')]
    code = re.sub(r'#.*', '', body)
    assert "['ufw', 'deny'" not in code
    assert "['ufw', 'allow'" not in code
    assert '_fw_deny(_port' in code and '_fw_allow(9997' in code
