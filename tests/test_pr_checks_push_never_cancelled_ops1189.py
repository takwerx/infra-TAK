# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1189: a PR checks run on dev or main is never cancelled by a newer run.

Before, every run shared `concurrency: group: pr-checks-<PR number or ref>` with `cancel-in-progress: true`.
Two quick merges to dev put the two push runs in the same group (the same ref), so the second cancelled the
first. A red dev then showed "cancelled" and nobody saw it (ops #1174).

What must hold, read from the workflow as text (no YAML library needed):
  * cancel-in-progress is on for pull_request runs only, never a bare `true`;
  * a pull_request run is grouped by PR number, so a newer push to a PR still cancels the older run;
  * a push run is grouped by commit (github.sha), never by branch: with cancel-in-progress off GitHub still
    cancels a run that is WAITING in a group when a newer one arrives, so a per-branch group would still lose
    the middle run of three quick merges.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PR_CHECKS = ROOT / '.github' / 'workflows' / 'pr-checks.yml'


def _code():
    text = PR_CHECKS.read_text(encoding='utf-8')
    return '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))


def _concurrency():
    """The two keys under the top-level `concurrency:` block."""
    m = re.search(r'^concurrency:\s*\n((?:[ \t]+.*\n)+)', _code() + '\n', re.M)
    assert m, 'pr-checks.yml has no concurrency: block'
    keys = dict(re.findall(r'^\s+([a-z-]+):\s*(.+?)\s*$', m.group(1), re.M))
    assert set(keys) == {'group', 'cancel-in-progress'}, keys
    return keys


def _expr(value):
    m = re.fullmatch(r'\$\{\{\s*(.*?)\s*\}\}', value)
    assert m, f'expected one ${{{{ }}}} expression, got: {value}'
    return m.group(1)


def test_cancelling_is_for_pull_requests_only():
    cip = _concurrency()['cancel-in-progress']
    assert cip.lower() != 'true', 'cancel-in-progress: true cancels dev and main push runs too (ops #1189)'
    assert _expr(cip) == "github.event_name == 'pull_request'"


def test_a_pull_request_run_is_grouped_by_pr_number():
    group = _expr(_concurrency()['group'])
    pr_part = group.split('||')[0]
    assert "github.event_name == 'pull_request'" in pr_part
    assert 'github.event.pull_request.number' in pr_part


def test_a_push_run_is_grouped_by_commit_not_by_branch():
    group = _expr(_concurrency()['group'])
    assert '||' in group, 'no separate group for push runs'
    push_part = group.split('||', 1)[1]
    assert 'github.sha' in push_part, 'push runs must get one group per commit'
    assert 'github.ref' not in group, 'a per-branch group makes two quick merges to dev cancel each other'
    assert 'github.event.pull_request.number' not in push_part


def test_only_the_concurrency_block_changed_meaning():
    """The jobs still run on both triggers (ops #691) and checks-ok still fails a cancelled job."""
    t = _code()
    assert re.search(r'^  push:\s*\n\s+branches:\s*\[dev, main\]', t, re.M)
    assert re.search(r'^  pull_request:\s*\n\s+branches:\s*\[dev, main\]', t, re.M)
    assert '*" failure "*|*" cancelled "*' in t
