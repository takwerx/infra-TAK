# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1014: CodeQL and OpenSSF Scorecard run in GitHub, safely.

Pins, read from the workflow files as text (no YAML library needed):
  * codeql.yml exists, covers python, javascript-typescript and actions, runs on PRs into dev,
    on pushes to dev and main, and weekly, and builds nothing (build-mode none);
  * scorecard.yml exists, runs weekly and on main, publishes results, and is never a pull_request
    check (Scorecard only publishes from the default branch);
  * every `uses:` in EVERY workflow is a full 40-character commit SHA with a version comment
    (a tag or branch can be moved under us; a SHA cannot);
  * neither new workflow uses a self-hosted runner, pull_request_target or a secret, and every
    write permission is on a job, never at the top level;
  * neither is wired into checks-ok yet: a new check must run clean once before it is required.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / '.github' / 'workflows'
CODEQL = WORKFLOWS / 'codeql.yml'
SCORECARD = WORKFLOWS / 'scorecard.yml'
PR_CHECKS = WORKFLOWS / 'pr-checks.yml'

USES = re.compile(r'^\s*-?\s*uses:\s*(\S+)(.*)$', re.M)
FULL_SHA = re.compile(r'^[^@\s]+@[0-9a-f]{40}$')


def _text(p):
    assert p.is_file(), f'{p.relative_to(ROOT)} is missing'
    return p.read_text(encoding='utf-8')


def _code(text):
    """The file without comment lines, so a word in a comment never counts."""
    return '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))


def _triggers(text):
    """The block under the top-level `on:` key, as text."""
    m = re.search(r'^on:\s*\n((?:[ \t]+.*\n|\s*\n)+)', _code(text) + '\n', re.M)
    assert m, 'no on: block'
    return m.group(1)


def test_every_action_in_every_workflow_is_pinned_to_a_full_sha():
    files = sorted(WORKFLOWS.glob('*.yml'))
    assert CODEQL in files and SCORECARD in files
    bad = []
    for f in files:
        for m in USES.finditer(_code(_text(f))):
            ref, rest = m.group(1), m.group(2)
            if ref.startswith('./'):
                continue
            if not FULL_SHA.match(ref):
                bad.append(f'{f.name}: {ref}')
            elif not re.search(r'#\s*v?\d', rest):
                bad.append(f'{f.name}: {ref} has no version comment')
    assert not bad, 'unpinned or uncommented actions: ' + ', '.join(bad)


def test_codeql_covers_python_js_and_actions_and_builds_nothing():
    t = _code(_text(CODEQL))
    langs = re.search(r'language:\s*\[([^\]]*)\]', t)
    assert langs, 'no language matrix'
    got = {x.strip() for x in langs.group(1).split(',')}
    assert got == {'python', 'javascript-typescript', 'actions'}
    assert re.search(r'build-mode:\s*none', t)
    assert 'github/codeql-action/init@' in t and 'github/codeql-action/analyze@' in t


def test_codeql_runs_on_prs_to_dev_pushes_and_weekly():
    on = _triggers(_text(CODEQL))
    assert 'pull_request:' in on and re.search(r'branches:\s*\[[^\]]*\bdev\b', on)
    assert 'push:' in on
    assert 'schedule:' in on and re.search(r"cron:\s*'[^']+'", on)
    assert 'pull_request_target' not in on


def test_scorecard_is_weekly_publishes_and_is_not_a_pr_check():
    t = _code(_text(SCORECARD))
    on = _triggers(_text(SCORECARD))
    assert 'schedule:' in on and re.search(r"cron:\s*'[^']+'", on)
    assert re.search(r'branches:\s*\[main\]', on)
    assert 'pull_request' not in on, 'Scorecard publishes only from the default branch'
    assert 'ossf/scorecard-action@' in t
    assert re.search(r'publish_results:\s*true', t)
    # Scorecard's publish step refuses a top-level env or defaults block.
    assert not re.search(r'^(env|defaults):', t, re.M)


def test_new_workflows_are_least_privilege_and_hosted():
    for f in (CODEQL, SCORECARD):
        t = _code(_text(f))
        assert 'self-hosted' not in t, f'{f.name} must not use the Studio runners'
        assert 'pull_request_target' not in t
        assert 'secrets.' not in t, f'{f.name} needs no secret'
        assert re.search(r'runs-on:\s*ubuntu-24\.04', t)
        assert 'persist-credentials: false' in t
        # A write permission belongs on the job. Top-level permissions are read-only.
        top = re.search(r'^permissions:\s*(.*)\n((?:[ \t]+.*\n)*)', t + '\n', re.M)
        assert top, f'{f.name} has no top-level permissions'
        assert 'write' not in top.group(0), f'{f.name}: top-level permissions must be read-only'
        assert 'write-all' not in t


def test_new_workflows_are_not_required_checks_yet():
    t = _text(PR_CHECKS)
    needs = re.search(r'checks-ok:.*?needs:\s*\[([^\]]*)\]', t, re.S)
    assert needs, 'checks-ok has no needs list'
    assert 'codeql' not in needs.group(1).lower() and 'scorecard' not in needs.group(1).lower()
    assert 'codeql' not in t.lower() and 'scorecard' not in t.lower()
