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
"""DNS pre-check before Caddy asks Let's Encrypt for certificates.

A fresh install whose A records all pointed at 168.163.75.58 — the box is
198.163.75.58 — went straight into Let's Encrypt: Caddy got no certificate and
every FQDN URL failed, with nothing in setup saying why. The deploy and the
domain saves now resolve each name first, stop with a plain message when a name
Caddy is about to serve does not point here, and let an operator behind NAT or
a proxy continue anyway.

app.py cannot be imported in a test, so its helpers are cut out of it and run
against stubs: the code under test is the shipped text.
"""

import ast
import pathlib
import re
import shutil
import socket
import subprocess
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (ROOT / 'templates' / 'caddy.html').read_text(encoding='utf-8')

BOX = '198.163.75.58'
TYPO = '168.163.75.58'


def _node(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return node
    raise AssertionError(f'{name} not found at module level in app.py')


def _segment(name):
    return ast.get_source_segment(APP, _node(name))


class _Blocked:
    def __init__(self, body):
        self.body = body


def _load(installed=()):
    ns = {
        'socket': socket, 'threading': threading, 'time': time,
        'jsonify': _Blocked,
        'detect_modules': lambda fresh=False: {m: {'installed': True} for m in installed},
    }
    for name in ('SERVICE_DOMAIN_DEFAULTS', '_get_service_domain', 'DNS_PRECHECK_TIMEOUT',
                 '_dns_resolve_ipv4', '_dns_precheck_hosts', '_dns_precheck_message',
                 '_dns_precheck', '_dns_precheck_gate'):
        exec(compile(_segment(name), 'app.py', 'exec'), ns)
    return ns


def _resolver(table):
    """table: host -> list of IPs | 'missing' | 'error'. Unlisted hosts have no record."""
    def resolve(host):
        v = table.get(host, 'missing')
        if v == 'missing':
            return [], 'missing'
        if v == 'error':
            return [], 'error: [Errno -3] Temporary failure in name resolution'
        return sorted(v), None
    return resolve


def _settings(**kw):
    s = {'fqdn': 'cmd.takserver.us', 'server_ip': BOX}
    s.update(kw)
    return s


def _row(res, host):
    return next(r for r in res['hosts'] if r['host'] == host)


# --- match / mismatch / missing ---------------------------------------------------------

def test_match_passes_with_no_message():
    ns = _load()
    res = ns['_dns_precheck'](_settings(), {}, resolve=_resolver({'infratak.cmd.takserver.us': [BOX]}))
    assert res['ok'] is True
    assert res['message'] == '' and res['problems'] == []
    assert _row(res, 'infratak.cmd.takserver.us')['status'] == 'ok'


def test_mismatch_stops_with_the_plain_message():
    ns = _load()
    res = ns['_dns_precheck'](_settings(), {}, resolve=_resolver({'infratak.cmd.takserver.us': [TYPO]}))
    assert res['ok'] is False
    assert res['problems'] == ['infratak.cmd.takserver.us']
    assert res['message'] == (
        f'infratak.cmd.takserver.us points to {TYPO}, but this server is {BOX}.\n'
        'Fix the A record at your DNS provider, wait a few minutes, then press Retry.')


def test_missing_record_stops_the_same_way():
    ns = _load()
    res = ns['_dns_precheck'](_settings(), {}, resolve=_resolver({}))
    assert res['ok'] is False
    assert _row(res, 'infratak.cmd.takserver.us')['status'] == 'missing'
    assert res['message'].startswith(
        f'infratak.cmd.takserver.us has no DNS A record. Create one pointing to {BOX}.\n')
    assert res['message'].endswith('then press Retry.')


def test_the_field_box_every_record_typod_lists_each_name_once():
    """The cmd.takserver.us report: TAK Server, Authentik and TAK Portal installed, every
    record on 168.x. One line per name Caddy serves, then the instruction once."""
    ns = _load()
    hosts = ['infratak', 'takserver', 'tak', 'takportal']
    table = {f'{h}.cmd.takserver.us': [TYPO] for h in hosts}
    modules = {m: {'installed': True} for m in ('takserver', 'authentik', 'takportal')}
    res = ns['_dns_precheck'](_settings(), modules, resolve=_resolver(table))
    assert res['ok'] is False
    assert res['problems'] == [f'{h}.cmd.takserver.us' for h in hosts]
    lines = res['message'].split('\n')
    assert len(lines) == 5
    assert lines[-1] == 'Fix the A records at your DNS provider, wait a few minutes, then press Retry.'


def test_extra_round_robin_ip_still_counts_as_pointing_here():
    ns = _load()
    res = ns['_dns_precheck'](_settings(), {}, resolve=_resolver({'infratak.cmd.takserver.us': [BOX, '203.0.113.9']}))
    assert res['ok'] is True


# --- which names can block --------------------------------------------------------------

def test_names_for_services_not_installed_never_block():
    """A box with individual A records has none for Node-RED or CloudTAK until those are
    installed; a fresh install must not stop for them. A wrong one is still reported."""
    ns = _load()
    table = {'infratak.cmd.takserver.us': [BOX], 'nodered.cmd.takserver.us': [TYPO]}
    res = ns['_dns_precheck'](_settings(), {}, resolve=_resolver(table))
    assert res['ok'] is True
    assert _row(res, 'nodered.cmd.takserver.us') == {
        'host': 'nodered.cmd.takserver.us', 'needed': False, 'ips': [TYPO],
        'status': 'mismatch', 'error': ''}
    assert _row(res, 'map.cmd.takserver.us')['status'] == 'missing'


def test_an_installed_module_makes_its_name_required():
    ns = _load()
    hosts = ns['_dns_precheck_hosts'](_settings(), {'cloudtak': {'installed': True}})
    assert hosts['infratak.cmd.takserver.us'] is True
    for h in ('map', 'tiles.map', 'video'):
        assert hosts[f'{h}.cmd.takserver.us'] is True
    assert hosts['takserver.cmd.takserver.us'] is False


def test_shared_stream_name_is_required_if_either_owner_is_installed():
    ns = _load()
    hosts = ns['_dns_precheck_hosts'](_settings(), {'tak_video_restreamer': {'installed': True}})
    assert hosts['stream.cmd.takserver.us'] is True


def test_per_service_override_is_the_name_checked():
    ns = _load()
    hosts = ns['_dns_precheck_hosts'](_settings(infratak_domain='console.other.org'), {})
    assert hosts.get('console.other.org') is True
    assert 'infratak.cmd.takserver.us' not in hosts


# --- never block on what is not the record's fault ---------------------------------------

def test_lookup_failure_on_this_box_is_reported_but_does_not_block():
    ns = _load()
    res = ns['_dns_precheck'](_settings(), {}, resolve=_resolver({'infratak.cmd.takserver.us': 'error'}))
    assert res['ok'] is True
    row = _row(res, 'infratak.cmd.takserver.us')
    assert row['status'] == 'error' and 'Temporary failure' in row['error']


def test_unknown_server_ip_does_not_block():
    ns = _load()
    res = ns['_dns_precheck'](_settings(server_ip=''), {}, resolve=_resolver({'infratak.cmd.takserver.us': [TYPO]}))
    assert res['ok'] is True
    assert _row(res, 'infratak.cmd.takserver.us')['status'] == 'unknown'


def test_a_hung_resolver_is_bounded_by_the_timeout():
    ns = _load()
    release = threading.Event()

    def hang(host):
        release.wait(5)
        return [BOX], None
    t0 = time.time()
    res = ns['_dns_precheck'](_settings(), {}, resolve=hang, timeout=0.3)
    release.set()
    assert time.time() - t0 < 2
    assert res['ok'] is True
    assert _row(res, 'infratak.cmd.takserver.us')['error'] == 'error: lookup timed out'


def test_resolver_classifies_nxdomain_as_missing_and_temp_failure_as_error(monkeypatch):
    ns = _load()

    def fake(errno):
        def gai(*a, **k):
            raise socket.gaierror(errno, 'x')
        return gai
    monkeypatch.setattr(socket, 'getaddrinfo', fake(socket.EAI_NONAME))
    assert ns['_dns_resolve_ipv4']('x.example') == ([], 'missing')
    monkeypatch.setattr(socket, 'getaddrinfo', fake(socket.EAI_AGAIN))
    ips, problem = ns['_dns_resolve_ipv4']('x.example')
    assert ips == [] and problem.startswith('error: ')
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', (BOX, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', (BOX, 0))])
    assert ns['_dns_resolve_ipv4']('x.example') == ([BOX], None)


# --- the gate: stop, continue anyway (NAT), custom cert ----------------------------------

def _gate(ns, settings, data, ssl_mode=None, table=None):
    resolve = _resolver(table if table is not None else {'infratak.cmd.takserver.us': [TYPO]})
    real = ns['_dns_precheck']
    ns['_dns_precheck'] = lambda s, m: real(s, m, resolve=resolve)
    try:
        return ns['_dns_precheck_gate'](settings, data, ssl_mode)
    finally:
        ns['_dns_precheck'] = real


def test_gate_blocks_with_409_and_the_result():
    ns = _load()
    blocked, res = _gate(ns, _settings(), {})
    assert blocked is not None
    body, code = blocked
    assert code == 409
    assert body.body['success'] is False
    assert body.body['error'] == res['message']
    assert body.body['dns_check']['problems'] == ['infratak.cmd.takserver.us']


@pytest.mark.parametrize('flag', [True, 'true', '1', 'on'])
def test_nat_override_continues_and_still_returns_the_result(flag):
    """JSON sends a bool, the multipart deploy form sends a string."""
    ns = _load()
    blocked, res = _gate(ns, _settings(), {'skip_dns_check': flag})
    assert blocked is None
    assert res['ok'] is False   # the caller logs that it was overridden


@pytest.mark.parametrize('flag', [False, '', 'false', None])
def test_override_off_values_do_not_skip(flag):
    ns = _load()
    blocked, _ = _gate(ns, _settings(), {'skip_dns_check': flag})
    assert blocked is not None


def test_custom_certificate_skips_the_check():
    ns = _load()
    assert _gate(ns, _settings(), {}, ssl_mode='custom') == (None, None)
    assert _gate(ns, _settings(ssl_mode='custom'), {}) == (None, None)


def test_gate_passes_when_dns_is_right():
    ns = _load()
    blocked, res = _gate(ns, _settings(), {}, table={'infratak.cmd.takserver.us': [BOX]})
    assert blocked is None and res['ok'] is True


# --- wiring: every path that hands Caddy a new name checks first -------------------------

def _func_src(name):
    return _segment(name)


@pytest.mark.parametrize('fn', ['caddy_deploy', 'caddy_update_domain', 'caddy_save_domains'])
def test_gate_runs_before_anything_is_saved(fn):
    src = _func_src(fn)
    assert '_dns_precheck_gate(' in src
    gate = src.index('_dns_precheck_gate(')
    assert gate < src.index('save_settings(settings)')
    assert re.search(r'blocked, \w+ = _dns_precheck_gate\([^)]*\)[^\n]*\n\s+if blocked:\n\s+return blocked', src)


def test_deploy_checks_before_the_deploy_thread_and_logs_an_override():
    src = _func_src('caddy_deploy')
    assert src.index('_dns_precheck_gate(') < src.index('threading.Thread(target=run_caddy_deploy')
    assert 'DNS pre-check overridden' in src
    # the multipart (custom cert) branch must define `data` too, or the gate NameErrors
    multipart = src.split('if request.files or', 1)[1].split('else:', 1)[0]
    assert 'data = request.form' in multipart


def test_dns_check_route_requires_login():
    node = _node('caddy_dns_check')
    decos = [ast.get_source_segment(APP, d) for d in node.decorator_list]
    assert "app.route('/api/caddy/dns-check')" in decos
    assert 'login_required' in decos


# --- the page ----------------------------------------------------------------------------

def test_page_has_retry_override_and_recheck():
    for marker in ('id="dns-check-panel"', 'id="dns-retry-btn"', 'id="dns-skip-btn"',
                   'id="dns-check-box"', 'id="dns-recheck-btn"', "fetch('/api/caddy/dns-check')",
                   'skip_dns_check:!!opts.skipDns', 'skip_dns_check:true'):
        assert marker in TEMPLATE, marker


def test_dns_result_is_rendered_with_textcontent_not_html():
    fn = TEMPLATE.split('function renderDnsCheck', 1)[1].split('\nfunction ', 1)[0]
    assert 'innerHTML=' in fn and "innerHTML=''" in fn   # only ever cleared
    assert fn.count('innerHTML') == 1


@pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')
def test_page_scripts_parse(tmp_path):
    scripts = re.findall(r'<script>(.*?)</script>', TEMPLATE, re.S)
    assert scripts
    for i, s in enumerate(scripts):
        s = re.sub(r'\{%.*?%\}', '', s, flags=re.S)
        s = re.sub(r'\{\{.*?\}\}', '0', s, flags=re.S)
        p = tmp_path / f's{i}.js'
        p.write_text(s, encoding='utf-8')
        r = subprocess.run(['node', '--check', str(p)], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
