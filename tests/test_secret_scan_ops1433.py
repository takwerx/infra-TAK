# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1433: a PR that adds a key, token or password goes red.

Two old credentials sit in this public repo's git history (an OpenRouteService key and the old LDAP
service password). Deleting them from the files does not help; they were rotated. This is the check
that stops the next one: `.github/ci/secret_scan.sh` runs gitleaks over every commit of a change.

What must hold:
  * the `secret-scan` job exists in pr-checks.yml, scans the commits (full history checked out, no
    credentials kept, no secret, no write permission), runs its own proof test first, and `checks-ok`
    waits for it;
  * the scanner download is pinned to a version and a SHA-256, and the hash is checked BEFORE the
    archive is unpacked;
  * the script's exit codes: 0 clean, 1 a secret was found, 2 the check could not run. A scanner that
    stopped for any other reason, a range git cannot read and a missing range are never a pass
    (run here against a stub scanner, so these tests need no gitleaks);
  * the allow-list stays narrow: gitleaks' own rules are on, no whole folder or file is skipped;
  * where gitleaks is installed, the end-to-end proof test (a planted key fails, a clean change
    passes, the log never shows the value) runs too. CI always runs it in the `secret-scan` job.
"""
import os
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PR_CHECKS = ROOT / '.github' / 'workflows' / 'pr-checks.yml'
SCRIPT = ROOT / '.github' / 'ci' / 'secret_scan.sh'
PROOF = ROOT / '.github' / 'ci' / 'test_secret_scan.sh'
CONFIG = ROOT / '.github' / 'ci' / 'gitleaks.toml'


def _code(text):
    return '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))


def _job(name):
    text = _code(PR_CHECKS.read_text(encoding='utf-8'))
    m = re.search(r'(?ms)^  %s:\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)' % re.escape(name), text)
    assert m, f'pr-checks.yml has no job {name}'
    return m.group(1)


# ------------------------------------------------------------------ the workflow job

def test_secret_scan_job_scans_every_commit_without_credentials_or_secrets():
    job = _job('secret-scan')
    assert 'fetch-depth: 0' in job, 'a range scan needs the full history'
    assert 'persist-credentials: false' in job
    assert 'secrets.' not in job and 'permissions:' not in job
    assert 'pull_request_target' not in _code(PR_CHECKS.read_text(encoding='utf-8'))
    assert 'secret_scan.sh "origin/${BASE_REF}..HEAD"' in job, 'a PR is scanned against its base branch'
    assert '${BEFORE_SHA}..${AFTER_SHA}' in job, 'a push is scanned from the commit before it'
    assert '--last 50' in job, 'a push with no usable before-commit still scans something'


def test_proof_test_runs_before_the_scan_in_the_job():
    job = _job('secret-scan')
    proof = job.index('.github/ci/test_secret_scan.sh')
    scan = job.index('.github/ci/secret_scan.sh')
    assert proof < scan, 'the proof test must run first: a check that cannot fail proves nothing'


def test_checks_ok_waits_for_secret_scan():
    needs = re.search(r'(?m)^    needs: \[(.+)\]$', _job('checks-ok')).group(1)
    assert 'secret-scan' in [n.strip() for n in needs.split(',')]


def test_no_third_party_action_in_the_secret_scan_job():
    # the scanner comes from a pinned, hash-checked download, not from a marketplace action
    uses = re.findall(r'uses:\s*(\S+)', _job('secret-scan'))
    assert uses and all(u.startswith('actions/checkout@') for u in uses), uses


# ------------------------------------------------------------------ the pinned download

def test_scanner_download_is_pinned_and_hash_checked_before_unpacking():
    t = _code(SCRIPT.read_text(encoding='utf-8'))
    assert re.search(r'(?m)^GITLEAKS_VERSION=\d+\.\d+\.\d+$', t)
    assert re.search(r'(?m)^GITLEAKS_SHA256=[0-9a-f]{64}$', t)
    assert 'latest' not in t
    assert t.index('sha256sum') < t.index('tar -xzf'), 'the hash must be checked before the archive is unpacked'
    assert '--redact' in t, 'CI logs of a public repo are public: findings must be printed without the value'


# ------------------------------------------------------------------ exit codes, with a stub scanner

def _repo(tmp_path):
    r = tmp_path / 'repo'
    (r / '.github' / 'ci').mkdir(parents=True)
    shutil.copy(SCRIPT, r / '.github' / 'ci' / 'secret_scan.sh')
    shutil.copy(CONFIG, r / '.github' / 'ci' / 'gitleaks.toml')
    env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.invalid',
               GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid')
    for args in (['init', '-q'], ['config', 'commit.gpgsign', 'false'], ['add', '-A'], ['commit', '-q', '-m', 'base']):
        subprocess.run(['git', '-C', str(r)] + args, check=True, env=env, capture_output=True)
    return r


def _stub(tmp_path, exit_code, write_report=True):
    """A fake gitleaks that exits with exit_code and (optionally) writes one finding without a value."""
    s = tmp_path / 'fake-gitleaks'
    s.write_text(
        '#!/bin/sh\n'
        'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && report="$2"; shift; done\n'
        + ('[ -n "$report" ] && echo \'[{"RuleID":"generic-api-key","File":"x.py","StartLine":3,"Commit":"abcdef012345"}]\' > "$report"\n'
           if write_report else '')
        + 'exit %d\n' % exit_code, encoding='utf-8')
    s.chmod(0o755)
    return s


def _run(repo, stub, *args):
    env = dict(os.environ, GITLEAKS_BIN=str(stub))
    return subprocess.run(['bash', '.github/ci/secret_scan.sh'] + list(args), cwd=repo, env=env,
                          capture_output=True, text=True)


@pytest.mark.parametrize('stub_exit, want', [(0, 0), (1, 1), (126, 2), (127, 2), (7, 2)])
def test_exit_codes_clean_found_and_could_not_run(tmp_path, stub_exit, want):
    repo = _repo(tmp_path)
    r = _run(repo, _stub(tmp_path, stub_exit), 'HEAD..HEAD')
    assert r.returncode == want, (r.returncode, r.stdout, r.stderr)
    if want == 1:
        assert 'generic-api-key' in r.stdout and 'x.py:3' in r.stdout and 'abcdef01' in r.stdout
        assert 'rotate' in r.stdout


def test_a_range_git_cannot_read_is_never_a_pass(tmp_path):
    repo = _repo(tmp_path)
    r = _run(repo, _stub(tmp_path, 0), 'no-such-branch..HEAD')
    assert r.returncode == 2 and 'cannot read the range' in r.stderr


@pytest.mark.parametrize('args', [[], ['--last'], ['--last', 'x'], ['--bogus']])
def test_missing_or_bad_arguments_are_never_a_pass(tmp_path, args):
    repo = _repo(tmp_path)
    assert _run(repo, _stub(tmp_path, 0), *args).returncode == 2


def test_a_missing_scanner_binary_is_never_a_pass(tmp_path):
    repo = _repo(tmp_path)
    r = _run(repo, tmp_path / 'does-not-exist', 'HEAD..HEAD')
    assert r.returncode == 2


# ------------------------------------------------------------------ the config

def test_config_uses_gitleaks_default_rules_and_skips_no_folder_or_file():
    t = _code(CONFIG.read_text(encoding='utf-8'))
    assert re.search(r'(?m)^useDefault\s*=\s*true$', t)
    assert not re.search(r'(?m)^\s*(paths|commits)\s*=', t), 'allow-list entries match values, never whole files or commits'
    # every allow-list entry names its reason and matches the secret itself
    entries = t.split('[[allowlists]]')[1:]
    assert entries
    for e in entries:
        assert 'description' in e and 'regexTarget = "secret"' in e and 'regexes' in e
    # no catch-all pattern
    assert not re.search(r"'''\^?\.\*\$?'''|'''\.\+'''", t)


# ------------------------------------------------------------------ end to end (needs gitleaks)

def test_planted_key_goes_red_end_to_end():
    gl = os.environ.get('GITLEAKS_BIN') or shutil.which('gitleaks')
    if not gl:
        pytest.skip('gitleaks is not installed here; the secret-scan CI job runs this proof test')
    r = subprocess.run(['bash', str(PROOF)], env=dict(os.environ, GITLEAKS_BIN=gl), capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'all secret-check proof tests passed' in r.stdout
