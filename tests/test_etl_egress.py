# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ETL Runner W5 (v10.4.0): the egress block for ETL containers.

Pins:
  * the allow-list only ever opens private / CGNAT networks — never loopback, link-local
    (the cloud metadata service) or a public range — and console and broker agree;
  * the rule set blocks every private / CGNAT / link-local range and the host itself;
  * converge is idempotent, heals a flushed chain or a lost hook, and teardown leaves nothing;
  * etl_egress is console-only: the gate checks its schema and the ETL socket refuses it;
  * the overlay pins the bridge name the rules match.
"""
import importlib.util
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / 'broker' / 'takwerx_broker.py'
sys.path.insert(0, str(ROOT))
from modules import etlrunner as etl  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location('tb_etl_egress_test', SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def m():
    return _load()


class FakeIpt:
    """Just enough of iptables -S/-N/-F/-X/-A/-I/-C/-D for converge/teardown."""

    def __init__(self, docker_user=True):
        self.chains = {'INPUT': [], 'FORWARD': []}
        if docker_user:
            self.chains['DOCKER-USER'] = []
        self.calls = []

    def __call__(self, binary, *args):
        self.calls.append(args)
        op, chain, rest = args[0], args[1], list(args[2:])
        ok = lambda out='': subprocess.CompletedProcess(args, 0, out, '')  # noqa: E731
        bad = subprocess.CompletedProcess(args, 1, '', 'No chain/target/match by that name.')
        if op == '-S':
            if chain not in self.chains:
                return bad
            return ok('\n'.join([f'-N {chain}'] + [f'-A {chain} ' + ' '.join(r) for r in self.chains[chain]]))
        if op == '-N':
            if chain in self.chains:
                return bad
            self.chains[chain] = []
            return ok()
        if chain not in self.chains:
            return bad
        if op == '-F':
            self.chains[chain] = []
        elif op == '-X':
            del self.chains[chain]
        elif op == '-A':
            self.chains[chain].append(rest)
        elif op == '-I':
            self.chains[chain].insert(int(rest[0]) - 1, rest[1:])
        elif op == '-C':
            return ok() if rest in self.chains[chain] else bad
        elif op == '-D':
            if rest not in self.chains[chain]:
                return bad
            self.chains[chain].remove(rest)
        return ok()


@pytest.fixture
def fake(m, monkeypatch):
    f = FakeIpt()
    monkeypatch.setattr(m, '_ipt', f)
    monkeypatch.setattr(m, '_etl_egress_tools', lambda: [(4, '/usr/sbin/iptables')])
    return f


# ── allow-list ───────────────────────────────────────────────────────────────────────────────
GOOD = ['192.168.10.0/24', '10.1.2.3', '100.64.5.0/24', '172.20.0.0/16', 'fd00:1::/64']
BAD = ['169.254.169.254/32', '127.0.0.1', '0.0.0.0/0', '8.8.8.8/32', '10.0.0.0/7',
       'fe80::1', '::1', '224.0.0.1', 'not-a-cidr', '10.0.0.0/8; rm -rf /']


@pytest.mark.parametrize('a', GOOD)
def test_allow_accepts_private(m, a):
    assert m._etl_egress_allow_norm([a]) == etl.egress_allow_norm([a])


@pytest.mark.parametrize('a', BAD)
def test_allow_refuses_rest(m, a):
    with pytest.raises(m.Denied):
        m._etl_egress_allow_norm([a])
    with pytest.raises(ValueError):
        etl.egress_allow_norm([a])


def test_allow_normalizes_and_caps(m):
    assert m._etl_egress_allow_norm(['10.1.2.3/24', '10.1.2.0/24']) == ['10.1.2.0/24']
    with pytest.raises(m.Denied):
        m._etl_egress_allow_norm([f'10.0.{i}.0/24' for i in range(m.ETL_EGRESS_MAX_ALLOW + 1)])
    with pytest.raises(m.Denied):
        m._etl_egress_allow_norm('10.0.0.0/24')


# ── rule set ─────────────────────────────────────────────────────────────────────────────────
def test_specs_block_private_metadata_and_host(m):
    fwd, inp, tag = m._etl_egress_specs(4, [])
    blocked = [r[1] for r in fwd if r[:1] == ['-d'] and 'REJECT' in r]
    for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16',
                '127.0.0.0/8'):
        assert net in blocked
    assert ['-o', m.ETL_BRIDGE, '-j', 'RETURN'] in fwd          # ETL -> api on its own network
    assert inp[-1][:2] == ['-j', 'REJECT']                     # nothing from ETLs reaches the host
    assert tag in fwd[0][-1] and tag in inp[0][-1]


def test_allow_precedes_block_and_never_reaches_input(m):
    fwd, inp, _ = m._etl_egress_specs(4, ['192.168.10.0/24', 'fd00::/64'])
    i_allow = fwd.index(['-d', '192.168.10.0/24', '-j', 'RETURN'])
    i_block = next(i for i, r in enumerate(fwd) if r[:2] == ['-d', '192.168.0.0/16'])
    assert i_allow < i_block
    assert not any('fd00::/64' in r for r in fwd)              # v6 entry stays out of v4 rules
    assert not any('192.168.10.0/24' in r for r in inp)


def test_tag_changes_with_allow(m):
    assert m._etl_egress_specs(4, [])[2] != m._etl_egress_specs(4, ['10.9.0.0/16'])[2]


# ── converge / heal / teardown ───────────────────────────────────────────────────────────────
def test_converge_then_idempotent(m, fake):
    assert m._etl_egress_converge([]) == {'v4': 'applied'}
    assert ['-i', m.ETL_BRIDGE, '-j', m.ETL_EGRESS_CHAIN] == fake.chains['DOCKER-USER'][0]
    assert ['-i', m.ETL_BRIDGE, '-j', m.ETL_EGRESS_CHAIN_IN] == fake.chains['INPUT'][0]
    n = len(fake.calls)
    assert m._etl_egress_converge([]) == {'v4': 'kept'}
    assert not any(c[0] in ('-A', '-F', '-I') for c in fake.calls[n:])


def test_converge_heals_flush_and_lost_hook(m, fake):
    m._etl_egress_converge([])
    fake.chains[m.ETL_EGRESS_CHAIN] = []          # firewall reload
    fake.chains['INPUT'] = []                     # hook lost
    assert m._etl_egress_converge([]) == {'v4': 'applied'}
    fwd, _, _ = m._etl_egress_specs(4, [])
    assert fake.chains[m.ETL_EGRESS_CHAIN] == fwd
    assert fake.chains['INPUT'][0] == ['-i', m.ETL_BRIDGE, '-j', m.ETL_EGRESS_CHAIN_IN]


def test_converge_rewrites_on_allow_change(m, fake):
    m._etl_egress_converge([])
    m._etl_egress_converge(['10.9.0.0/16'])
    assert ['-d', '10.9.0.0/16', '-j', 'RETURN'] in fake.chains[m.ETL_EGRESS_CHAIN]
    assert fake.chains['DOCKER-USER'].count(['-i', m.ETL_BRIDGE, '-j', m.ETL_EGRESS_CHAIN]) == 1


def test_converge_without_docker_user_hooks_forward(m, monkeypatch):
    f = FakeIpt(docker_user=False)
    monkeypatch.setattr(m, '_ipt', f)
    monkeypatch.setattr(m, '_etl_egress_tools', lambda: [(4, 'iptables')])
    m._etl_egress_converge([])
    assert f.chains['FORWARD'][0] == ['-i', m.ETL_BRIDGE, '-j', m.ETL_EGRESS_CHAIN]


def test_forward_hook_moves_to_docker_user(m, monkeypatch):
    f = FakeIpt(docker_user=False)
    monkeypatch.setattr(m, '_ipt', f)
    monkeypatch.setattr(m, '_etl_egress_tools', lambda: [(4, 'iptables')])
    m._etl_egress_converge([])                       # broker came up before Docker
    f.chains['DOCKER-USER'] = []                     # Docker starts
    m._etl_egress_converge([])
    assert f.chains['DOCKER-USER'] == [['-i', m.ETL_BRIDGE, '-j', m.ETL_EGRESS_CHAIN]]
    assert ['-i', m.ETL_BRIDGE, '-j', m.ETL_EGRESS_CHAIN] not in f.chains['FORWARD']


def test_ipv4_failure_raises_ipv6_failure_reports(m, monkeypatch):
    f4, f6 = FakeIpt(), FakeIpt()
    f6.chains = {}                                   # no ip6 filter table
    monkeypatch.setattr(m, '_etl_egress_tools', lambda: [(4, 'v4'), (6, 'v6')])
    monkeypatch.setattr(m, '_ipt', lambda b, *a: (f4 if b == 'v4' else f6)(b, *a))
    st = m._etl_egress_converge([])
    assert st['v4'] == 'applied' and st['v6'].startswith('error')
    monkeypatch.setattr(m, '_ipt', lambda b, *a: f6(b, *a))
    with pytest.raises(RuntimeError):
        m._etl_egress_converge([])


def test_teardown_leaves_nothing(m, fake):
    m._etl_egress_converge([])
    fake.chains['DOCKER-USER'].insert(0, ['-i', m.ETL_BRIDGE, '-j', m.ETL_EGRESS_CHAIN])   # dup
    m._etl_egress_teardown()
    assert m.ETL_EGRESS_CHAIN not in fake.chains and m.ETL_EGRESS_CHAIN_IN not in fake.chains
    assert fake.chains['DOCKER-USER'] == [] and fake.chains['INPUT'] == []


def test_apply_remove_status(m, fake, tmp_path, monkeypatch):
    monkeypatch.setattr(m, 'ETL_EGRESS_CONF', str(tmp_path / 'egress.json'))
    r = m._do_etl_egress({'op': 'etl_egress', 'action': 'apply', 'allow': ['10.9.0.0/16']})
    assert r['ok'] and r['allow'] == ['10.9.0.0/16']
    assert (tmp_path / 'egress.json').stat().st_mode & 0o777 == 0o600
    st = m._do_etl_egress({'op': 'etl_egress', 'action': 'status'})
    assert st['enforced'] and st['v4'] is True and st['allow'] == ['10.9.0.0/16']
    assert m._do_etl_egress({'op': 'etl_egress', 'action': 'remove'})['ok']
    st = m._do_etl_egress({'op': 'etl_egress', 'action': 'status'})
    assert not st['enforced'] and st['v4'] is False


def test_damaged_conf_fails_closed(m, tmp_path, monkeypatch):
    p = tmp_path / 'egress.json'
    p.write_text('{"allow": ["8.8.8.8/32"]}')
    monkeypatch.setattr(m, 'ETL_EGRESS_CONF', str(p))
    assert m._etl_egress_conf_read() == []        # enforced, nothing allowed


# ── gate ─────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize('req', [
    {'op': 'etl_egress', 'action': 'apply', 'allow': ['8.8.8.0/24']},
    {'op': 'etl_egress', 'action': 'apply', 'allow': ['10.0.0.0/24'], 'chain': 'INPUT'},
    {'op': 'etl_egress', 'action': 'flush'},
    {'op': 'etl_egress', 'action': 'remove', 'allow': []},
])
def test_gate_denies(m, req):
    assert m._evaluate(req)[0] == 'DENY'


def test_gate_allows(m):
    assert m._evaluate({'op': 'etl_egress', 'action': 'apply', 'allow': ['10.0.0.0/24']})[0] == 'ALLOW'
    assert m._evaluate({'op': 'etl_egress', 'action': 'status'})[0] == 'ALLOW'


def test_etl_socket_refuses_egress(m, monkeypatch):
    monkeypatch.setattr(m, 'audit', lambda *a, **k: None)
    r = m._etl_dispatch({'op': 'etl_egress', 'action': 'remove'}, peer={'uid': 999})
    assert r['ok'] is False and r['code'] == 'DENIED'


# ── overlay ──────────────────────────────────────────────────────────────────────────────────
def test_overlay_pins_bridge_name(m):
    y = etl.overlay_yml('/home/x/CloudTAK', 990, 990, '/run/takwerx-etl', '/var/lib/takwerx-etl',
                        '/var/lib/takwerx-etl-tls')
    assert f'com.docker.network.bridge.name: "{m.ETL_BRIDGE}"' in y
    assert etl.ETL_BRIDGE == m.ETL_BRIDGE and len(m.ETL_BRIDGE) <= 15
