"""External sources are pinned to a tag and commit or a version, and nothing new may float (ops #637).

Covered: the MediaMTX web editor and its Python packages, the WebODM overlay plugin, the Docker
install (Docker's own package repo, key checked), the Authentik redis image, and Update Now's git
trust entry.

The last test is the ratchet: it scans app.py, start.sh and modules/ for a branch name, a moving
image tag, an unpinned `pip install`, or the Docker convenience script. A new one fails the test. The
few that are left are listed with the reason they stay; the count may only go down.
"""
import ast
import glob
import os
import pathlib
import re
import shlex
import stat
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
START_SH = (ROOT / 'start.sh').read_text(encoding='utf-8')
TREE = ast.parse(APP)

SHA_RE = re.compile(r'^[0-9a-f]{40}$')
TAG_RE = re.compile(r'^v\d+\.\d+\.\d+$')


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found at module level in app.py')


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


# --------------------------------------------------------------------------- editor + overlay pins

def test_editor_is_pinned_to_a_tag_and_a_commit():
    assert TAG_RE.match(_const('MEDIAMTX_EDITOR_REF')), 'the editor ref must be a release tag, never a branch'
    assert SHA_RE.match(_const('MEDIAMTX_EDITOR_SHA'))


def test_editor_raw_urls_use_the_commit_not_a_branch_or_tag():
    sha = _const('MEDIAMTX_EDITOR_SHA')
    for line in APP.splitlines():
        if line.startswith(('MEDIAMTX_EDITOR_RAW_URL', 'MEDIAMTX_EDITOR_TEST_VIDEO_URL')):
            assert '{MEDIAMTX_EDITOR_SHA}' in line and '{MEDIAMTX_EDITOR_REF}' not in line, line
    assert 'test_video_url = MEDIAMTX_EDITOR_TEST_VIDEO_URL' in APP
    assert sha  # constant exists


def _run_clone(tmp_path, expected_sha):
    """Run _mediamtx_editor_clone_cmd against a throwaway local repo (no network)."""
    repo = tmp_path / 'src'
    repo.mkdir()
    env = {**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't',
           'GIT_COMMITTER_EMAIL': 't@t', 'HOME': str(tmp_path), 'GIT_CONFIG_NOSYSTEM': '1'}

    def git(*a):
        return subprocess.run(['git', '-C', str(repo), *a], check=True, capture_output=True, text=True, env=env).stdout.strip()
    git('init', '-q', '-b', 'main')
    (repo / 'config-editor').mkdir()
    (repo / 'config-editor' / 'mediamtx_config_editor.py').write_text('app = Flask\n')
    git('add', '.')
    git('commit', '-q', '-m', 'v1')
    git('tag', 'v9.9.9')
    real = git('rev-parse', 'HEAD')
    ns = {'shlex': shlex, 'MEDIAMTX_EDITOR_REF': 'v9.9.9', 'MEDIAMTX_EDITOR_REPO': f'file://{repo}',
          'MEDIAMTX_EDITOR_SHA': real if expected_sha == 'real' else expected_sha}
    exec(compile(_segment('_mediamtx_editor_clone_cmd'), 'app.py', 'exec'), ns)
    dest = tmp_path / 'clone'
    r = subprocess.run(ns['_mediamtx_editor_clone_cmd'](str(dest)), shell=True, capture_output=True, text=True, env=env)
    return r.returncode, dest


def test_editor_clone_succeeds_when_the_tag_is_at_the_pinned_commit(tmp_path):
    rc, dest = _run_clone(tmp_path, 'real')
    assert rc == 0
    assert (dest / 'config-editor' / 'mediamtx_config_editor.py').exists()


def test_editor_clone_fails_when_the_tag_moved(tmp_path):
    """A tag that now points at a different commit than the pinned one must not install."""
    rc, _ = _run_clone(tmp_path, '0' * 40)
    assert rc != 0


def test_both_editor_clone_sites_use_the_checked_clone():
    assert APP.count('_mediamtx_editor_clone_cmd(') >= 2            # def + remote deploy
    assert "'--branch', MEDIAMTX_EDITOR_REF" in APP                 # local deploy (argv, no shell)
    assert "_eh != MEDIAMTX_EDITOR_SHA" in APP                      # ... and it checks the commit
    assert '--branch "{MEDIAMTX_EDITOR_REF}"' not in APP


def test_editor_python_packages_are_exact_versions():
    pkgs = _const('_MEDIAMTX_EDITOR_PY_PKGS')
    assert pkgs and all(re.fullmatch(r'[A-Za-z0-9_.]+==\d[\w.]*', p) for p in pkgs), pkgs
    assert re.fullmatch(r'certifi==\d[\w.]*', _const('_MEDIAMTX_EDITOR_CERTIFI'))
    assert "'install', '-U', 'certifi'" not in APP and '_pi -U certifi' not in APP


def test_overlay_plugin_is_pinned_and_both_clones_check_the_commit():
    assert TAG_RE.match(_const('WEBODM_OVERLAY_REF'))
    assert SHA_RE.match(_const('WEBODM_OVERLAY_SHA'))
    assert "'--branch', WEBODM_OVERLAY_REF" in APP                       # local deploy
    assert '--branch {WEBODM_OVERLAY_REF}' in APP                        # remote deploy
    assert APP.count('WEBODM_OVERLAY_SHA') >= 4                          # def + remote check + local check + msg


def test_authentik_redis_is_not_a_moving_tag():
    img = _const('AUTHENTIK_REDIS_IMAGE')
    assert re.search(r':\d+\.\d+\.\d+(-alpine)?$', img), img
    assert 'redis:alpine' not in APP
    assert APP.count('AUTHENTIK_REDIS_IMAGE') >= 4                       # def + compose + 2 patchers


# --------------------------------------------------------------------------- Docker

def test_docker_is_never_installed_from_the_convenience_script():
    assert not re.search(r'get\.docker\.com\s*\|\s*(?:ba)?sh', APP)
    assert not re.search(r'get\.docker\.com\s*\|\s*(?:ba)?sh', START_SH)


def test_docker_key_fingerprint_matches_between_app_and_start_sh():
    fpr = _const('DOCKER_APT_KEY_FPR')
    assert re.fullmatch(r'[0-9A-F]{40}', fpr)
    assert fpr in START_SH


def _docker_script_env(tmp_path, key_fpr):
    """The apt branch of _docker_install_script() with /etc moved under tmp and apt/curl/gpg faked."""
    ns = {'shlex': shlex, 'DOCKER_APT_KEY_FPR': _const('DOCKER_APT_KEY_FPR')}
    exec(compile(_segment('_docker_install_script'), 'app.py', 'exec'), ns)
    script = ns['_docker_install_script']().replace('/etc/', f'{tmp_path}/etc/')
    (tmp_path / 'etc' / 'apt' / 'keyrings').mkdir(parents=True)
    (tmp_path / 'etc' / 'apt' / 'sources.list.d').mkdir(parents=True)
    (tmp_path / 'etc' / 'debian_version').write_text('12\n')
    (tmp_path / 'etc' / 'os-release').write_text('ID=ubuntu\nVERSION_CODENAME=jammy\n')
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'calls.log'
    fakes = {
        'apt-get': f'echo "apt-get $*" >> {log}',
        'curl': 'while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done; echo KEYDATA > "$out"',
        'gpg': f'echo "pub:-:4096:1:0000:1::::::scESCA::::::23::0:"; echo "fpr:::::::::{key_fpr}:"',
        'dpkg': 'echo arm64',
        'systemctl': f'echo "systemctl $*" >> {log}',
    }
    for name, body in fakes.items():
        f = bindir / name
        f.write_text('#!/bin/sh\n' + body + '\n')
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    env = {'PATH': f'{bindir}:/usr/bin:/bin'}
    r = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True, env=env)
    return r, tmp_path / 'etc' / 'apt', log


def test_docker_script_installs_from_dockers_repo_when_the_key_matches(tmp_path):
    r, apt, log = _docker_script_env(tmp_path, _const('DOCKER_APT_KEY_FPR'))
    assert r.returncode == 0, r.stderr
    lst = (apt / 'sources.list.d' / 'docker.list').read_text()
    assert 'signed-by=' in lst and 'https://download.docker.com/linux/ubuntu jammy stable' in lst and 'arch=arm64' in lst
    calls = log.read_text()
    assert 'install -y docker-ce docker-ce-cli containerd.io' in calls and 'enable --now docker' in calls


def test_docker_script_refuses_a_key_with_the_wrong_fingerprint(tmp_path):
    r, apt, log = _docker_script_env(tmp_path, 'A' * 40)
    assert r.returncode != 0
    assert 'refused' in r.stderr
    assert not (apt / 'sources.list.d' / 'docker.list').exists(), 'repo must not be added on a bad key'
    assert not (apt / 'keyrings' / 'docker.asc').exists(), 'bad key must be removed'
    assert 'docker-ce' not in log.read_text()


def test_non_root_docker_install_checks_the_same_fingerprint():
    body = _segment('_install_docker_nonroot')
    assert '_docker_key_fingerprint(' in body and 'DOCKER_APT_KEY_FPR' in body
    assert body.index('DOCKER_APT_KEY_FPR') < body.index('docker.asc')


# --------------------------------------------------------------------------- Update Now

def test_update_now_no_longer_writes_a_wildcard_safe_directory():
    assert "'--replace-all', 'safe.directory', '*'" not in APP
    assert "'--unset-all', 'safe.directory'" in APP          # an old wildcard is removed
    assert "'--add', 'safe.directory', console_dir" in APP    # the console's own checkout is named


# --------------------------------------------------------------------------- the ratchet

# Floating references that are NOT code run on the box, or that are tracked as the next step.
# Each entry is (file, pattern name) -> how many lines are allowed. The number may only go down.
_ALLOWED = {
    # data, not code: first-party JSON feed and a version-number lookup, and a logo URL
    ('app.py', 'raw-main'): 2,
    ('modules/tvr.py', 'raw-main'): 1,
    # ops #637 follow-up, waiting on the lead's call on "latest release vs frozen" (CloudTAK falls back
    # to the default branch when GitHub cannot be reached; plugin repos clone their default branch)
    ('app.py', 'clone-no-branch'): 8,
    # TVR clones, then checkout_pin() moves it to TVR_SHA straight after (modules/tvr.py)
    ('modules/tvr.py', 'clone-no-branch'): 1,
}

_PATTERNS = {
    'docker-pipe': r'get\.docker\.com\s*\|\s*(?:ba)?sh',
    'float-image': r'''image['"]?\s*[:=]\s*f?['"]?[\w./${}:-]+:(?:latest|alpine|stable|main|master|dev|edge)\b''',
    'branch-flag': r'''--branch[ =]+["']?(?:main|master|dev|develop)\b''',
    'raw-main': r'raw\.githubusercontent\.com/[\w.-]+/[\w.-]+/(?:main|master|dev)\b',
    'ref-const': r'''^\w*_REF\s*=\s*["'](?:main|master|dev|develop)["']''',
    'pip-unpinned': r'''pip3? install[^\n]*\b(?:flask|requests|psutil|ruamel\.yaml)\b(?![=<>.\w-])''',
    'clone-no-branch': r'''(?:git clone(?!.*--branch)(?!.*--no-checkout)|\[\s*'git',\s*'clone'(?!.*--branch)(?!.*--no-checkout))''',
}


def _scan():
    found = {}
    files = ['app.py', 'start.sh'] + sorted(os.path.relpath(p, ROOT) for p in glob.glob(str(ROOT / 'modules' / '*.py')))
    for rel in files:
        for lineno, line in enumerate((ROOT / rel).read_text(encoding='utf-8', errors='replace').splitlines(), 1):
            s = line.strip()
            if s.startswith('#'):
                continue
            for name, pat in _PATTERNS.items():
                if re.search(pat, line, re.I if name != 'ref-const' else 0):
                    found.setdefault((rel, name), []).append((lineno, s[:110]))
    return found


def test_no_new_branch_floating_image_or_unpinned_install_reference():
    found = _scan()
    problems = []
    for key, hits in sorted(found.items()):
        allowed = _ALLOWED.get(key, 0)
        # prose lines (docstrings) that mention a clone are not code
        code_hits = [h for h in hits if not re.match(r'^(?:[A-Z][a-z]+ |["\']{3})', h[1]) and 'nothing they could edit' not in h[1]
                     and "git clone and NOT" not in h[1] and 'Restoring plugin' not in h[1] and 'raise RuntimeError' not in h[1]]
        if len(code_hits) > allowed:
            problems.append(f'{key[0]} [{key[1]}] {len(code_hits)} > {allowed} allowed:\n  ' +
                            '\n  '.join(f'{n}: {t}' for n, t in code_hits))
    assert not problems, '\n'.join(problems)


def test_the_ratchet_catches_each_kind_of_floating_reference():
    """The scanner itself: one sample per pattern must match, a pinned sample must not."""
    bad = {
        'docker-pipe': 'ok, out = run("curl -fsSL https://get.docker.com | sh")',
        'float-image': "    image: docker.io/library/redis:alpine",
        'branch-flag': 'git clone --depth 1 --branch main https://x/y.git',
        'raw-main': "url = 'https://raw.githubusercontent.com/o/r/main/a.py'",
        'ref-const': 'EDITOR_REF = "main"',
        'pip-unpinned': "pip3 install Flask ruamel.yaml",
        'clone-no-branch': "git clone --depth 1 https://github.com/o/r.git /tmp/r",
    }
    for name, line in bad.items():
        assert re.search(_PATTERNS[name], line, re.I if name != 'ref-const' else 0), name
    good = ["git clone --depth 1 --branch v1.2.3 https://x/y.git", 'EDITOR_REF = "v2.1.14"',
            "    image: docker.io/library/redis:8.10.2-alpine", "pip3 install Flask==3.1.3",
            "url = 'https://raw.githubusercontent.com/o/r/8d39e26d81601e107873ca8c81b4a8076bb2e028/a.py'"]
    for line in good:
        assert not any(re.search(p, line, re.I) for n, p in _PATTERNS.items() if n != 'ref-const'), line
        assert not re.search(_PATTERNS['ref-const'], line), line
