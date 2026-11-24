# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1192: the `scanners` PR check runs on a GitHub-hosted runner and reads the private scanners safely.

History: the job asked for a Studio runner (self-hosted, macOS, tak-worker) that was never registered for this repo, so every
PR job sat queued, and the repo variable TIER1_SCANNERS was switched to false on Nov 12. checks-ok counts a skipped job as
passed, so nothing was scanned for 12 days. The job now runs on ubuntu-24.04 and fetches the scanners from the private notes
repo with a fine-grained read-only token (secret SCANNERS_READ_TOKEN). The first version used an SSH deploy key; a deploy key
needs a terminal to make, and AJ's setup must be click-only, so it is a token made on GitHub's web page.

Pins, read from the workflow as text (no YAML library needed):
  * the job runs on ubuntu-24.04, never a self-hosted runner (a self-hosted runner on a public repo is a risk for fork PRs);
  * it runs only when TIER1_SCANNERS is 'true' and, for a PR, only from a branch in this repo (a fork never gets a secret) and
    not from Dependabot (it has its own empty secret store, so the job would fail for a reason that is not the code);
  * the secret appears in exactly two places: the step that stops with a clear message when it is missing or cannot read the
    notes repo, and the `token` of the notes checkout. Never in a `run:` body, never in the step that runs the scanners;
  * no SSH deploy key anywhere (`ssh-key`, SCANNERS_READ_KEY): the one secret is SCANNERS_READ_TOKEN;
  * the notes checkout is read-only in effect: pinned action, persist-credentials false, only the two scanner folders;
  * the scanners run inside the PR checkout (working-directory: pr), with no machine path written in;
  * pull_request_target is never used in the workflow, and checks-ok still waits for the job.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
WF = ROOT / '.github' / 'workflows' / 'pr-checks.yml'


def _text():
    assert WF.is_file(), 'pr-checks.yml is missing'
    return WF.read_text(encoding='utf-8')


def _code(text):
    """Without comment lines, so a word in a comment never counts."""
    return '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))


def _job(name):
    """The text of one job: from `  name:` to the next line indented two spaces that starts a key or a comment block."""
    lines = _text().splitlines()
    start = next((i for i, l in enumerate(lines) if l == f'  {name}:'), None)
    assert start is not None, f'job {name} not found'
    end = len(lines)
    for i in range(start + 1, len(lines)):
        l = lines[i]
        if re.match(r'^  (#|[A-Za-z0-9_-]+:)', l):
            end = i
            break
    return _code('\n'.join(lines[start:end]))


def _steps(job):
    """Split a job's text into step blocks (each starts at `      - `)."""
    body = job.split('    steps:\n', 1)[1]
    return [s for s in re.split(r'(?m)^      - ', body) if s.strip()]


def test_runs_on_a_github_hosted_runner():
    job = _job('scanners')
    assert re.search(r'(?m)^    runs-on: ubuntu-24\.04$', job)
    assert 'self-hosted' not in job and 'tak-worker' not in job


def test_runs_only_for_trusted_code():
    job = _job('scanners')
    cond = re.search(r'(?m)^    if: (.+)$', job).group(1)
    assert "vars.TIER1_SCANNERS == 'true'" in cond
    assert 'github.event.pull_request.head.repo.full_name == github.repository' in cond
    assert "github.actor != 'dependabot[bot]'" in cond
    assert "github.event_name == 'push'" in cond


def test_secret_only_in_the_guard_step_and_the_notes_checkout_key():
    job = _job('scanners')
    assert job.count('secrets.') == 2, 'the scanners job may use exactly two secret references'
    steps = _steps(job)
    holders = [s for s in steps if 'secrets.SCANNERS_READ_TOKEN' in s]
    assert len(holders) == 2
    guard = next(s for s in holders if 'run:' in s)
    assert re.search(r'env:\n\s+SCANNERS_READ_TOKEN: \$\{\{ secrets\.SCANNERS_READ_TOKEN \}\}', guard)
    run_body = guard.split('run:', 1)[1]
    assert 'secrets.' not in run_body, 'a secret must reach a script through env, never pasted into the script text'
    assert 'exit 1' in run_body, 'a missing token must fail the job, never skip it'
    checkout = next(s for s in holders if 'uses:' in s)
    assert re.search(r'(?m)^\s+token: \$\{\{ secrets\.SCANNERS_READ_TOKEN \}\}$', checkout)
    for s in steps:
        if s not in holders:
            assert 'secrets.' not in s


def test_notes_checkout_is_narrow_and_keeps_no_credentials():
    steps = _steps(_job('scanners'))
    co = next(s for s in steps if 'repository: takwerx/infra-TAK-notes' in s)
    assert re.search(r'uses: actions/checkout@[0-9a-f]{40} # v', co), 'pin the action to a commit SHA'
    assert 'persist-credentials: false' in co
    assert 'ref: main' in co
    assert 'path: notes' in co
    sparse = co.split('sparse-checkout: |', 1)[1]
    folders = [l.strip() for l in sparse.splitlines()[1:] if l.strip().startswith('claude-skills/')]
    assert folders == ['claude-skills/redteam-selfaudit', 'claude-skills/pre-merge-check']


def test_the_pr_is_checked_out_without_credentials_and_scanned_in_place():
    job = _job('scanners')
    steps = _steps(job)
    pr = next(s for s in steps if 'uses: actions/checkout@' in s and 'repository:' not in s)
    assert 'path: pr' in pr and 'persist-credentials: false' in pr
    run = next(s for s in steps if 'redteam-selfaudit/scan.py' in s)
    assert 'working-directory: pr' in run
    for script in ('scan.py', 'smoke.py', 'check-template-js.py'):
        assert script in run
    assert 'secrets.' not in run
    assert '/Users/' not in job


def test_scanners_are_copied_in_and_the_notes_checkout_is_removed_before_they_run():
    steps = _steps(_job('scanners'))
    copy = next(s for s in steps if 'cp -R notes/claude-skills/redteam-selfaudit' in s)
    assert 'pr/.claude/skills' in copy
    assert 'rm -rf notes' in copy
    assert '--require-hashes -r pr/requirements.txt' in copy, 'jinja2 comes from the hashed requirements, not a bare pip install'
    order = [steps.index(copy), steps.index(next(s for s in steps if 'redteam-selfaudit/scan.py' in s))]
    assert order[0] < order[1]


def test_workflow_never_uses_pull_request_target_and_checks_ok_waits_for_scanners():
    code = _code(_text())
    assert 'pull_request_target' not in code
    needs = re.search(r'(?m)^    needs: \[(.+)\]$', _job('checks-ok')).group(1)
    assert 'scanners' in [n.strip() for n in needs.split(',')]


def test_every_action_in_the_workflow_is_pinned_to_a_commit():
    for m in re.finditer(r'(?m)^\s*-?\s*uses:\s*(\S+)', _code(_text())):
        assert re.match(r'^[^@\s]+@[0-9a-f]{40}$', m.group(1)), m.group(1)


def test_no_ssh_deploy_key_is_left_in_the_workflow():
    """The old wording must not survive anywhere: the job's comments, its secret name or an ssh-key input."""
    text = _text()
    assert 'SCANNERS_READ_KEY' not in text
    assert 'ssh-key' not in text
    assert 'deploy key' not in text.lower()


def test_a_missing_token_fails_with_the_page_links_and_an_expired_token_is_told_apart():
    guard = next(s for s in _steps(_job('scanners')) if 'run:' in s and 'secrets.SCANNERS_READ_TOKEN' in s)
    run_body = guard.split('run:', 1)[1]
    assert 'https://github.com/settings/personal-access-tokens/new' in run_body
    assert 'settings/secrets/actions' in run_body
    assert re.search(r'\[ -z "\$SCANNERS_READ_TOKEN" \]', run_body)
    # A token that exists but cannot read the notes repo (expired after its one year, or made for another repo) is a
    # different failure from "not set": one request to the notes repo says which, in plain words, before the checkout.
    assert 'api.github.com/repos/takwerx/infra-TAK-notes' in run_body
    assert 'expired' in run_body
    assert run_body.count('exit 1') == 2


def test_the_token_is_sent_only_to_the_notes_repo_and_never_stays_in_the_checkout():
    job = _job('scanners')
    assert job.count('Authorization: Bearer $SCANNERS_READ_TOKEN') == 1
    assert 'echo "$SCANNERS_READ_TOKEN"' not in job and 'echo $SCANNERS_READ_TOKEN' not in job
    co = next(s for s in _steps(job) if 'repository: takwerx/infra-TAK-notes' in s)
    assert 'persist-credentials: false' in co
