# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #977: the weekly "is the bundled ETL catalog behind the live one" check.

tools/etl_catalog_freshness.py compares the bundled catalog's serial with the signed live one.
Pins:
  * a live serial newer than the bundled one fails (exit 1), whatever else is true;
  * an equal serial passes, and so does a bundled serial that is ahead (a catalog PR waiting);
  * a live catalog whose signature does not verify fails (exit 2) even when its serial looks
    newer: an unsigned catalog never counts as "the live one";
  * a fetch failure fails (exit 3) instead of passing quietly;
  * the workflow is scheduled, can be started by hand, is NOT a pull_request check, is read-only
    and pins every action to a commit SHA.
"""
import base64
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / 'tools' / 'etl_catalog_freshness.py'
WORKFLOW = ROOT / '.github' / 'workflows' / 'etl-catalog-freshness.yml'

_spec = importlib.util.spec_from_file_location('etl_catalog_freshness', TOOL)
fresh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fresh)
etl = fresh._load_etlrunner()

needs_openssl = pytest.mark.skipif(shutil.which('openssl') is None, reason='needs the openssl CLI')


def _keypair(d, name):
    k, p = d / f'{name}.pem', d / f'{name}.pub'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', str(k)], check=True,
                   capture_output=True)
    pub = subprocess.run(['openssl', 'pkey', '-in', str(k), '-pubout'], check=True,
                         capture_output=True, text=True).stdout
    p.write_text('# comment line\n' + pub)
    return k, p


def _sign(raw, key, d):
    m, s = d / 'm', d / 's'
    m.write_bytes(raw)
    subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(m),
                    '-out', str(s)], check=True, capture_output=True)
    return base64.b64encode(s.read_bytes()).decode() + '\n'


def _cat(serial):
    e = {'prefix': 'etl-x', 'version': '1.0.0', 'sha': 'a' * 40, 'source': 'dfpc-coe/etl-x',
         'name': 'etl-x', 'flags': {'schedule': True}, 'reviewed': 'scan'}
    return (json.dumps({'schema': 1, 'serial': serial, 'entries': [e]}, indent=2) + '\n').encode()


@pytest.fixture
def keys(tmp_path):
    key, pub = _keypair(tmp_path, 'good')
    return tmp_path, key, pub


@needs_openssl
def test_live_newer_than_bundled_fails(keys):
    d, key, pub = keys
    live = _cat(202611190517)
    code, msg = fresh.judge(etl, live, _sign(live, key, d), _cat(202611160342), str(pub))
    assert code == fresh.BEHIND == 1
    assert '202611160342' in msg and '202611190517' in msg
    assert 'catalog.json' in msg          # says what to copy


@needs_openssl
def test_equal_serial_passes(keys):
    d, key, pub = keys
    live = _cat(202611190517)
    code, msg = fresh.judge(etl, live, _sign(live, key, d), _cat(202611190517), str(pub))
    assert code == fresh.OK == 0
    assert 'current' in msg


@needs_openssl
def test_bundled_ahead_passes(keys):
    d, key, pub = keys
    live = _cat(202611160342)
    code, msg = fresh.judge(etl, live, _sign(live, key, d), _cat(202611190517), str(pub))
    assert code == fresh.OK
    assert 'ahead' in msg


@needs_openssl
def test_newer_live_catalog_with_bad_signature_is_not_a_freshness_answer(keys):
    d, key, pub = keys
    live = _cat(202611190517)
    other_key, _ = _keypair(d, 'other')
    code, msg = fresh.judge(etl, live, _sign(live, other_key, d), _cat(202611160342), str(pub))
    assert code == fresh.BAD_SIG == 2
    assert 'behind' not in msg


@needs_openssl
def test_tampered_live_catalog_fails_signature(keys):
    d, key, pub = keys
    live = _cat(202611190517)
    sig = _sign(live, key, d)
    code, _ = fresh.judge(etl, live.replace(b'1.0.0', b'9.9.9'), sig, _cat(202611160342), str(pub))
    assert code == fresh.BAD_SIG


@needs_openssl
def test_unreadable_live_catalog_fails(keys):
    d, key, pub = keys
    junk = b'<html>rate limited</html>'
    code, msg = fresh.judge(etl, junk, _sign(junk, key, d), _cat(1), str(pub))
    assert code == fresh.NO_FETCH == 3
    assert 'not readable' in msg


def test_fetch_failure_exits_3_not_0(monkeypatch, capsys):
    def boom():
        raise RuntimeError('network down')
    monkeypatch.setattr(fresh, '_live_commit', boom)
    assert fresh.main([]) == fresh.NO_FETCH
    assert 'network down' in capsys.readouterr().out


@needs_openssl
def test_main_reads_both_files_at_one_commit(monkeypatch, keys, capsys):
    """Both URLs carry the same commit, so a CDN cannot pair a new catalog with an old signature."""
    d, key, pub = keys
    live = _cat(202611190517)
    sig = _sign(live, key, d)
    sha = 'b' * 40
    seen = []

    def get(url, limit, **kw):
        seen.append(url)
        return live if url.endswith('catalog.json') else sig.encode()
    monkeypatch.setattr(fresh, '_live_commit', lambda: sha)
    monkeypatch.setattr(fresh, '_get', get)
    bundled = d / 'bundled.json'
    bundled.write_bytes(_cat(202611160342))
    monkeypatch.setattr(fresh, 'PUBKEY', str(pub))
    monkeypatch.setattr(fresh, 'BUNDLED', str(bundled))
    assert fresh.main([]) == fresh.BEHIND
    assert len(seen) == 2 and all(f'/{sha}/catalog.json' in u for u in seen)
    assert seen[1].endswith('catalog.json.sig')
    assert 'behind' in capsys.readouterr().out


def test_tool_uses_the_consoles_own_signature_check():
    """It must not grow its own openssl call: the console's verify_signature is the rule."""
    src = TOOL.read_text(encoding='utf-8')
    assert 'etl.verify_signature(' in src and 'openssl' not in src.replace('etl.verify_signature', '')


def test_bundled_catalog_and_key_are_readable():
    raw = (ROOT / 'modules' / 'etlrunner' / 'catalog.json').read_bytes()
    assert etl.catalog_serial(etl.parse_catalog(raw)) > 0
    assert etl._pubkeys(fresh.PUBKEY)


# ── the workflow file ─────────────────────────────────────────────────────────────────────────

def _wf():
    return WORKFLOW.read_text(encoding='utf-8')


def test_workflow_is_weekly_and_manual_not_a_pr_check():
    wf = _wf()
    assert re.search(r"^\s*schedule:\s*\n\s*- cron: '[^']+'", wf, re.M)
    assert re.search(r'^\s*workflow_dispatch:', wf, re.M)
    # live moves on its own: a PR check would turn every open PR red
    assert not re.search(r'^\s*(pull_request|pull_request_target|push):', wf, re.M)
    assert '0 * * * *' not in wf
    m = re.search(r"cron: '(\S+) (\S+) (\S+) (\S+) (\S+)'", wf)
    assert m and m.group(5) not in ('*', '*/1'), 'weekly means one weekday, not every day'


def test_workflow_actions_are_pinned_to_a_commit_sha():
    uses = re.findall(r'^\s*-?\s*uses:\s*(\S+)', _wf(), re.M)
    assert uses, 'the job checks the repo out'
    for u in uses:
        assert re.fullmatch(r'[\w./-]+@[0-9a-f]{40}', u), f'{u} is not pinned to a commit SHA'


def test_workflow_is_read_only_and_runs_the_tool():
    wf = _wf()
    assert re.search(r'^permissions:\s*\n\s+contents: read\s*$', wf, re.M)
    assert 'secrets.' not in wf
    assert 'tools/etl_catalog_freshness.py' in wf
    assert 'persist-credentials: false' in wf
