# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1113: the console's Python pins have ONE copy, so a Dependabot bump needs no hand relock.

Before: CI installed .github/ci/requirements-ci.lock, a second copy of every pin in requirements.txt and
.github/ci/requirements-test.txt. Dependabot edits only those two files, so any bump of flask, werkzeug,
gunicorn, pytest ... failed test_ci_lock_matches_requirements_files until someone regenerated the lock
by hand (Dependabot werkzeug 3.1.8 -> 3.1.9, PR 294, was closed for that reason).

Now requirements.txt carries the hashes and the transitive pins itself and CI installs that very file.
These tests pin the shape: no second copy anywhere, every line hashed, CI and customer installs use the
same file, and the job that installs it on Python 3.9, 3.10 and 3.12 exists and is required.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQ = ROOT / 'requirements.txt'
CI = ROOT / '.github' / 'ci'
TEST_REQ = CI / 'requirements-test.txt'
PR_CHECKS = ROOT / '.github' / 'workflows' / 'pr-checks.yml'
RELOCK = ROOT / 'tools' / 'relock-console-requirements.sh'

TOP_LEVEL = ('flask', 'werkzeug', 'gunicorn', 'psutil', 'pyyaml', 'pystun3')
TEST_TOP_LEVEL = ('pytest', 'pytest-xdist', 'pytest-timeout')

PIN = re.compile(r'^([A-Za-z0-9_.\-]+)==([^\s;\\]+)(?:\s*;\s*([^\\]+?))?\s*\\?\s*$')


def _norm(name):
    return name.lower().replace('_', '-')


def _blocks(text):
    """[(name, version, marker, [hashes])] for every pinned requirement in a hashed requirements file."""
    out = []
    cur = None
    for line in text.splitlines():
        m = PIN.match(line)
        if m:
            cur = [_norm(m.group(1)), m.group(2), (m.group(3) or '').strip(), []]
            out.append(cur)
            continue
        h = re.match(r'^\s+--hash=sha256:([0-9a-f]{64})\s*\\?\s*$', line)
        if h and cur is not None:
            cur[3].append(h.group(1))
    return [tuple(b) for b in out]


def _pins(text):
    """name -> {version, ...} (a name can have one line per Python range)."""
    d = {}
    for name, ver, _marker, _hashes in _blocks(text):
        d.setdefault(name, set()).add(ver)
    return d


def _read(p):
    assert p.is_file(), f'{p.relative_to(ROOT)} is missing'
    return p.read_text(encoding='utf-8')


def _code(text):
    return '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))


def _job(text, name):
    m = re.search(rf'^  {re.escape(name)}:\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)', text, re.S | re.M)
    assert m, f'job {name} not found in pr-checks.yml'
    return m.group(1)


# ---------------------------------------------------------------- one copy

def test_the_second_copy_is_gone():
    assert not (CI / 'requirements-ci.lock').exists(), (
        'requirements-ci.lock is a second copy of the pins; CI installs requirements.txt itself (ops #1113)')


def test_no_other_file_in_the_ci_folder_pins_a_console_package():
    """The red-Dependabot cause: a package pinned in requirements.txt AND in a CI file Dependabot does not edit."""
    bad = []
    for f in sorted(CI.iterdir()):
        if not f.is_file() or f.name == 'requirements-test.txt':
            continue
        if f.suffix not in ('.lock', '.txt', '.in'):
            continue
        for name in _pins(f.read_text(encoding='utf-8')):
            if name in TOP_LEVEL:
                bad.append(f'{f.name} pins {name}')
    assert not bad, '; '.join(bad)


def test_test_tools_file_agrees_with_the_console_file_on_shared_packages():
    """Both files go into one pip run, so a package in both (packaging) must have the same version."""
    console = _pins(_read(REQ))
    tools = _pins(_read(TEST_REQ))
    for name in sorted(set(console) & set(tools)):
        assert console[name] & tools[name], f'{name}: requirements.txt has {console[name]}, requirements-test.txt has {tools[name]}'
    for name in TOP_LEVEL:
        assert name not in tools, f'{name} is a console package; it belongs only in requirements.txt'
    for name in TEST_TOP_LEVEL:
        assert name in tools, name
        assert name not in console, f'{name} is test tooling; customer boxes must not install it'


def test_a_dependabot_style_bump_leaves_every_consistency_check_true():
    """Simulate Dependabot: change one pin's version in requirements.txt (and nothing else). With one copy,
    nothing else in the repo names that pin, so no check can disagree with it."""
    text = _read(REQ)
    cur = next(v for n, v, _m, _h in _blocks(text) if n == 'werkzeug')
    new = cur + '.1'
    bumped = re.sub(rf'^werkzeug=={re.escape(cur)}', f'werkzeug=={new}', text, flags=re.M)
    assert bumped != text
    assert _pins(bumped)['werkzeug'] == {new}
    # every other file that could hold a copy of the pin:
    holders = []
    for f in list(CI.iterdir()) + [ROOT / 'start.sh', ROOT / 'fix-console-after-pull.sh', PR_CHECKS]:
        if f.is_file() and re.search(r'\bwerkzeug\s*==', f.read_text(encoding='utf-8', errors='replace')):
            holders.append(f.relative_to(ROOT).as_posix())
    assert holders == [], f'werkzeug is pinned outside requirements.txt: {holders}'


# ---------------------------------------------------------------- the file itself

def test_every_requirements_line_is_exact_and_hashed():
    for p in (REQ, TEST_REQ):
        text = _read(p)
        blocks = _blocks(text)
        assert blocks, p.name
        for name, ver, marker, hashes in blocks:
            assert hashes, f'{p.name}: {name}=={ver} has no --hash'
        # any requirement line that is not an exact pin would make pip refuse the file in hash mode
        for line in _code(text).splitlines():
            s = line.strip()
            if not s or s.startswith('--hash='):
                continue
            assert PIN.match(line), f'{p.name}: not an exact `name==version` pin: {line!r}'


def test_top_level_pins_are_present_and_versions_that_have_two_lines_are_marked():
    text = _read(REQ)
    pins = _pins(text)
    for name in TOP_LEVEL:
        assert name in pins, f'requirements.txt lost {name}'
        assert len(pins[name]) == 1, f'{name} has two versions: top-level packages stay one version for the whole fleet'
    seen = {}
    for name, ver, marker, _h in _blocks(text):
        seen.setdefault(name, []).append(marker)
    for name, markers in seen.items():
        if len(markers) > 1:
            assert all('python_full_version' in m for m in markers) and len(set(markers)) == len(markers), (
                f'{name} appears {len(markers)} times without a distinct python_full_version marker on each line')


def test_gunicorn_stays_on_the_last_python_3_9_release():
    assert _pins(_read(REQ))['gunicorn'] == {'23.0.0'}, 'gunicorn 24+ needs Python 3.10; RHEL/Rocky 9 has 3.9'


def test_the_header_names_the_one_copy_and_the_relock_script():
    head = '\n'.join(l for l in _read(REQ).splitlines() if l.startswith('#'))
    assert 'ONLY copy' in head and 'tools/relock-console-requirements.sh' in head


# ---------------------------------------------------------------- CI and customers use the same file

def test_pytest_job_installs_the_console_file_by_hash():
    job = _code(_job(_read(PR_CHECKS), 'pytest'))
    m = re.search(r'pip install ([^\n]*)', job)
    assert m, 'pytest job has no pip install'
    cmd = m.group(1)
    assert '--require-hashes' in cmd
    assert re.search(r'-r requirements\.txt\b', cmd) and '-r .github/ci/requirements-test.txt' in cmd
    assert 'requirements-ci.lock' not in job


def test_console_deps_job_installs_requirements_on_3_9_3_10_and_3_12():
    job = _code(_job(_read(PR_CHECKS), 'console-deps'))
    for v in ("'3.9'", "'3.10'", "'3.12'"):
        assert v in job, f'console-deps does not cover Python {v}'
    assert 'pip" install --require-hashes -r requirements.txt' in job
    assert 'pip" check' in job, 'a missing transitive pin must fail the job'


def test_console_deps_is_required_by_checks_ok():
    text = _read(PR_CHECKS)
    m = re.search(r'checks-ok:.*?needs:\s*\[([^\]]*)\]', text, re.S)
    assert m and 'console-deps' in [x.strip() for x in m.group(1).split(',')]


def test_customer_install_paths_install_the_same_file():
    for rel in ('start.sh', 'fix-console-after-pull.sh'):
        t = _code(_read(ROOT / rel))
        assert re.search(r'pip"? install[^\n]*-r "\$INSTALL_DIR/requirements\.txt"', t), rel
        # --no-deps would skip the closure the hash file guarantees; a second index would escape the hashes
        assert '--no-deps' not in t and '--index-url' not in t and '--extra-index-url' not in t, rel


# ---------------------------------------------------------------- the relock script

def test_relock_script_keeps_the_same_top_level_names():
    t = _read(RELOCK)
    assert 'TOP_LEVEL="' + ' '.join(TOP_LEVEL) + '"' in t
    assert 'TEST_TOP_LEVEL="' + ' '.join(TEST_TOP_LEVEL) + '"' in t
    assert '--python-version 3.9' in t and '--generate-hashes' in t
    assert RELOCK.stat().st_mode & 0o111, 'tools/relock-console-requirements.sh must be executable'
