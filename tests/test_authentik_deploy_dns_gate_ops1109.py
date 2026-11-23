# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1109: an Authentik deploy before the Authentik DNS name exists must say so.

A fresh Authentik deploy leaves the LDAP outpost on internal routing until it can move the
outpost to https://<authentik name> through Caddy. With no A record for that name the move is
skipped, and on Authentik 2026.x internal routing spirals every bind, so the deploy ended with
"Final LDAP SA bind FAILED ... flow spiral" and the operator could not tell the cause was DNS
(seen twice on Nov 22, 2026, ops #1083).

`_authentik_deploy_dns_gate` runs first in a fresh deploy. These tests run the real functions
out of app.py (it cannot be imported in a test) against stubs for the resolver, the clock and
the log. The code under test is the shipped text.
"""
import ast
import pathlib
import socket
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = {'SERVICE_DOMAIN_DEFAULTS', '_get_service_domain', '_get_authentik_host',
          '_dns_resolve_ipv4', '_AK_DEPLOY_DNS_WAIT_S', '_AK_DEPLOY_DNS_POLL_S',
          '_authentik_deploy_dns_gate'}
# The new helper is loaded only when the tree has it. On the base branch the deploy has no
# gate and always goes on, so the tests fail on what that returns, not on a missing name.
_NEW = {'_AK_DEPLOY_DNS_WAIT_S', '_AK_DEPLOY_DNS_POLL_S', '_authentik_deploy_dns_gate'}


def _module():
    src = []
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            src.append(ast.get_source_segment(APP, node))
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], 'id', None) in _NAMES):
            src.append(ast.get_source_segment(APP, node))
    ns = {'socket': socket, 'time': time}
    exec(compile('\n\n'.join(src), 'app_cutout', 'exec'), ns)
    missing = _NAMES - _NEW - set(ns)
    assert not missing, f'not found in app.py: {sorted(missing)}'
    return ns


NS = _module()
GATE = NS.get('_authentik_deploy_dns_gate') or (lambda settings, plog, **kw: True)

LINE = '✗ DNS name tak.example.org has no A record yet. Add it, then press Deploy again.'


class Fake:
    """A resolver, a clock and a sleep that move together, so waiting costs no real time."""

    def __init__(self, answers):
        self.answers = list(answers)   # one answer per lookup; the last repeats
        self.lookups = []
        self.now = 1000.0
        self.logs = []

    def resolve(self, host):
        self.lookups.append(host)
        i = min(len(self.lookups) - 1, len(self.answers) - 1)
        return self.answers[i]

    def clock(self):
        return self.now

    def sleep(self, s):
        self.now += s

    def run(self, settings, **kw):
        return GATE(settings, self.logs.append, resolve=self.resolve, clock=self.clock,
                    sleep=self.sleep, **kw)


MISSING = ([], 'missing')
FOUND = (['203.0.113.10'], None)
SETTINGS = {'fqdn': 'example.org'}


def test_missing_name_stops_the_deploy_with_one_plain_line():
    f = Fake([MISSING])
    assert f.run(SETTINGS, wait_s=0) is False
    assert f.logs == [LINE]
    assert f.lookups == ['tak.example.org']


def test_missing_name_waits_for_a_fresh_record_then_stops():
    f = Fake([MISSING])
    assert f.run(SETTINGS, wait_s=20, poll_s=5) is False
    assert len(f.lookups) == 5            # now, then every 5 s for 20 s
    assert f.logs[-1] == LINE
    assert sum('waiting' in l for l in f.logs) == 1


def test_name_that_resolves_deploys_as_today_and_logs_nothing():
    f = Fake([FOUND])
    assert f.run(SETTINGS) is True
    assert f.logs == []
    assert f.lookups == ['tak.example.org']


def test_record_that_appears_during_the_wait_lets_the_deploy_go_on():
    f = Fake([MISSING, MISSING, FOUND])
    assert f.run(SETTINGS, wait_s=30, poll_s=5) is True
    assert LINE not in f.logs
    assert any('resolves now' in l for l in f.logs)


def test_lookup_failure_on_this_box_never_blocks():
    f = Fake([([], 'error: [Errno -3] Temporary failure in name resolution')])
    assert f.run(SETTINGS, wait_s=0) is True
    assert f.logs == []


def test_box_without_a_domain_has_no_name_to_check():
    f = Fake([MISSING])
    assert f.run({}) is True
    assert f.lookups == []


def test_the_name_checked_is_the_one_set_in_domains():
    f = Fake([MISSING])
    f.run({'fqdn': 'example.org', 'authentik_domain': 'sso'}, wait_s=0)
    assert f.lookups == ['sso.example.org']
    assert f.logs == ['✗ DNS name sso.example.org has no A record yet. Add it, then press Deploy again.']


def test_real_resolver_no_such_name_counts_as_missing(monkeypatch):
    def nxdomain(*a, **k):
        raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')
    monkeypatch.setattr(socket, 'getaddrinfo', nxdomain)
    logs = []
    assert GATE(SETTINGS, logs.append, wait_s=0) is False
    assert logs == [LINE]


def test_real_resolver_answer_counts_as_found(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo',
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('203.0.113.10', 0))])
    logs = []
    assert GATE(SETTINGS, logs.append, wait_s=0) is True
    assert logs == []


# ---- where the gate sits in run_authentik_deploy -------------------------------------------

def _deploy_fn():
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'run_authentik_deploy':
            return node
    raise AssertionError('run_authentik_deploy not found')


def test_deploy_runs_the_gate_first_on_a_fresh_deploy_and_stops_before_any_change():
    fn = _deploy_fn()
    gate_ifs = [n for n in ast.walk(fn) if isinstance(n, ast.If)
                and '_authentik_deploy_dns_gate' in ast.get_source_segment(APP, n.test)]
    assert len(gate_ifs) == 1, 'run_authentik_deploy must call the DNS gate exactly once'
    gate = gate_ifs[0]
    test_src = ast.get_source_segment(APP, gate.test)
    assert 'not reconfigure' in test_src, 'Reconfigure must not be stopped by the DNS gate'
    assert any(isinstance(s, ast.Return) for s in gate.body), 'a failed gate must return'
    body_src = '\n'.join(ast.get_source_segment(APP, s) for s in gate.body)
    assert "'error': True" in body_src and "'running': False" in body_src

    # Nothing that changes the box may come before it: the first docker/compose/file write
    # and the first outpost helper all sit below the gate.
    gate_line = gate.lineno
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and node.lineno < gate_line:
            name = ast.get_source_segment(APP, node.func)
            assert not any(w in name for w in ('subprocess', '_ak_compose_run_locked', 'outpost',
                                               'ldap', 'open', 'write', 'save_settings')), \
                f'{name} runs before the DNS gate (line {node.lineno})'
