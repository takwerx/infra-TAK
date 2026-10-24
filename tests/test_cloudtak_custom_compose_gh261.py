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
"""GH #261 — what an operator or a CloudTAK plugin adds to CloudTAK's compose survives.

A user added the clptak print service (a container on :5010) to CloudTAK. There was no
place for it that infra-TAK left alone: docker-compose.override.yml is infra-TAK's own and is
regenerated on every console start, and CloudTAK Update resets docker-compose.yml.

Now ~/CloudTAK/docker-compose.custom.yml is the operator's: created once, never written
again, and loaded LAST by every compose run through COMPOSE_FILE in CloudTAK's .env —
set before each compose action (local) and in each remote SSH command. The helpers are
cut out of app.py and run here (app.py cannot be imported in a test), so the code under
test is the shipped text.
"""

import ast
import os
import pathlib
import re
import shlex
import stat
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

ENV = ('CLOUDTAK_Mode=docker-compose\n'
       '# a comment the helper must keep\n'
       'SigningSecret=abc\n'
       'POSTGRES_PASSWORD=pw\n')
OPERATOR = ('services:\n  print:\n    image: example/print\n'
            '    ports:\n      - "127.0.0.1:5010:5010"\n')


def _fn(name):
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(APP, node)


def _assign(name):
    node = next(n for n in TREE.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.get_source_segment(APP, node)


def _helpers():
    ns = {'os': os, 're': re, 'shlex': shlex}
    src = '\n\n'.join([_assign('_CT_ENV_LINE_RE'), _assign('CLOUDTAK_CUSTOM_COMPOSE'),
                       _assign('_CLOUDTAK_CUSTOM_COMPOSE_SEED'),
                       _assign('_CLOUDTAK_TAKPORTAL_CSP_COMPOSE'),
                       _fn('_cloudtak_env_read'), _fn('_cloudtak_env_set'),
                       _fn('_cloudtak_compose_file_value'), _fn('_cloudtak_ensure_custom_compose'),
                       _fn('_cloudtak_remote_custom_compose_sh')])
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


@pytest.fixture
def ct(tmp_path):
    d = tmp_path / 'CloudTAK'
    d.mkdir()
    (d / 'docker-compose.yml').write_text('services:\n  api:\n    image: cloudtak-api\n')
    (d / 'docker-compose.override.yml').write_text('# TAKWERX: infra-TAK owns this\nservices: {}\n')
    (d / '.env').write_text(ENV)
    os.chmod(d / '.env', 0o600)
    return d


def _compose_file(d):
    vals = [ln.split('=', 1)[1] for ln in (d / '.env').read_text().splitlines()
            if ln.startswith('COMPOSE_FILE=')]
    assert len(vals) == 1, (d / '.env').read_text()
    return vals[0]


def _expected(d, override=True):
    files = ['docker-compose.yml'] + (['docker-compose.override.yml'] if override else []) \
        + ['docker-compose.custom.yml']
    return ':'.join(str(d / f) for f in files)


# ── local helper ─────────────────────────────────────────────────────────────

def test_seeds_the_operator_file_and_loads_it_last(ct):
    h, log = _helpers(), []
    assert h['_cloudtak_ensure_custom_compose'](str(ct), log.append) is True
    seed = (ct / 'docker-compose.custom.yml').read_text()
    assert seed == h['_CLOUDTAK_CUSTOM_COMPOSE_SEED']
    assert seed.rstrip().endswith('services: {}')      # a valid, empty compose file
    assert _compose_file(ct) == _expected(ct)          # base, infra-TAK's override, then theirs
    # every other .env line is byte-identical, and the file keeps its mode (it holds secrets)
    assert (ct / '.env').read_text().startswith(ENV)
    assert stat.S_IMODE(os.stat(ct / '.env').st_mode) == 0o600
    assert any('docker-compose.custom.yml' in m for m in log)


def test_an_existing_operator_file_is_never_written(ct):
    h = _helpers()
    (ct / 'docker-compose.custom.yml').write_text(OPERATOR)
    h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    assert (ct / 'docker-compose.custom.yml').read_text() == OPERATOR
    # an empty file is theirs too — not "missing", not re-seeded
    (ct / 'docker-compose.custom.yml').write_text('')
    h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    assert (ct / 'docker-compose.custom.yml').read_text() == ''


def test_a_symlinked_operator_file_is_left_alone(ct, tmp_path):
    h = _helpers()
    target = tmp_path / 'mine.yml'
    target.write_text(OPERATOR)
    os.symlink(target, ct / 'docker-compose.custom.yml')
    h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    assert os.path.islink(ct / 'docker-compose.custom.yml')
    assert target.read_text() == OPERATOR


def test_idempotent(ct):
    h = _helpers()
    h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    before = (ct / '.env').read_text()
    assert h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None) is False
    assert (ct / '.env').read_text() == before


def test_a_rewritten_env_gets_compose_file_back(ct):
    # Deploy writes .env from scratch; the call after it must restore the line.
    h = _helpers()
    h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    (ct / '.env').write_text(ENV)
    assert h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None) is True
    assert _compose_file(ct) == _expected(ct)


def test_a_deleted_operator_file_is_recreated_before_compose_would_fail(ct):
    h = _helpers()
    h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    os.remove(ct / 'docker-compose.custom.yml')
    h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    assert (ct / 'docker-compose.custom.yml').exists()


def test_no_override_file_is_not_listed(ct):
    h = _helpers()
    os.remove(ct / 'docker-compose.override.yml')
    h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    assert _compose_file(ct) == _expected(ct, override=False)


def test_not_deployed_is_a_no_op(ct):
    h = _helpers()
    os.remove(ct / '.env')
    assert h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None) is False
    assert not (ct / 'docker-compose.custom.yml').exists()


def test_never_raises(ct):
    h, log = _helpers(), []
    os.chmod(ct, 0o500)                                  # cannot create the file
    try:
        assert h['_cloudtak_ensure_custom_compose'](str(ct), log.append) is False
    finally:
        os.chmod(ct, 0o700)
    assert log and log[-1].startswith('  ⚠')


def test_seed_example_is_valid_compose_yaml():
    yaml = pytest.importorskip('yaml')
    seed = _helpers()['_CLOUDTAK_CUSTOM_COMPOSE_SEED']
    assert yaml.safe_load(seed) == {'services': {}}
    # the commented example, uncommented in place of `services: {}`, parses to two services
    lines = seed.splitlines()
    start = lines.index('# services:')
    example = '\n'.join(ln[2:] for ln in lines[start:] if ln.startswith('# '))
    doc = yaml.safe_load(example)
    assert set(doc['services']) == {'print', 'events'}
    assert doc['services']['print']['ports'] == ['127.0.0.1:5010:5010']   # loopback, never 0.0.0.0


# ── remote helper (same behaviour, as sh over SSH) ───────────────────────────

def _run_remote(home):
    sh = _helpers()['_cloudtak_remote_custom_compose_sh']()
    r = subprocess.run(['sh', '-c', sh], env={'HOME': str(home), 'PATH': os.environ['PATH']},
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr


def test_remote_sh_matches_the_local_helper(ct):
    h = _helpers()
    _run_remote(ct.parent)
    assert (ct / 'docker-compose.custom.yml').read_text() == h['_CLOUDTAK_CUSTOM_COMPOSE_SEED']
    assert _compose_file(ct) == _expected(ct)
    assert (ct / '.env').read_text().startswith(ENV)
    assert stat.S_IMODE(os.stat(ct / '.env').st_mode) == 0o600
    assert not (ct / '.env.ct261.tmp').exists()
    _run_remote(ct.parent)                                # idempotent: still one line
    assert _compose_file(ct) == _expected(ct)


def test_remote_sh_never_writes_an_existing_operator_file(ct):
    (ct / 'docker-compose.custom.yml').write_text(OPERATOR)
    _run_remote(ct.parent)
    assert (ct / 'docker-compose.custom.yml').read_text() == OPERATOR


def test_remote_sh_not_deployed_is_a_no_op(ct):
    os.remove(ct / '.env')
    _run_remote(ct.parent)
    assert not (ct / 'docker-compose.custom.yml').exists()


# ── TAK Portal's marketplace pins its CSP overlay into the same COMPOSE_FILE ──
# Its script appends the relative name `docker-compose.marketplace.yml` and later checks for
# it with an exact match (`tr ':' '\n' | grep -Fxq`). Our rewrite must keep it, verbatim.

MARKET = 'docker-compose.marketplace.yml'


def _takportal_sees_its_pin(d):
    r = subprocess.run(['sh', '-c', f"printf '%s\\n' \"$1\" | tr ':' '\\n' | grep -Fxq {MARKET}",
                        'sh', _compose_file(d)], timeout=10)
    return r.returncode == 0


def _with_market(d):
    return ':'.join([str(d / 'docker-compose.yml'), str(d / 'docker-compose.override.yml'),
                     MARKET, str(d / 'docker-compose.custom.yml')])


def _takportal_pins(d):
    # what TAK Portal's pin_csp_compose_file() leaves behind after ours: its file appended
    (d / MARKET).write_text('# Managed by TAK Portal CloudTAK marketplace.\nservices: {}\n')
    env = (d / '.env').read_text()
    cur = _compose_file(d)
    (d / '.env').write_text(env.replace(f'COMPOSE_FILE={cur}', f'COMPOSE_FILE={cur}:{MARKET}'))


@pytest.mark.parametrize('remote', [False, True])
def test_takportal_csp_pin_survives_and_ours_stays_last(ct, remote):
    h = _helpers()
    run = (lambda: _run_remote(ct.parent)) if remote else \
        (lambda: h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None))
    run()
    _takportal_pins(ct)
    run()
    assert _compose_file(ct) == _with_market(ct)
    assert _takportal_sees_its_pin(ct)
    run()                                                 # idempotent
    assert _compose_file(ct) == _with_market(ct)


@pytest.mark.parametrize('remote', [False, True])
def test_deploy_rewriting_env_puts_takportal_overlay_back(ct, remote):
    h = _helpers()
    (ct / MARKET).write_text('services: {}\n')
    (ct / '.env').write_text(ENV)                         # Deploy: .env from scratch
    if remote:
        _run_remote(ct.parent)
    else:
        h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    assert _compose_file(ct) == _with_market(ct)


@pytest.mark.parametrize('remote', [False, True])
def test_a_listed_file_that_is_gone_is_dropped(ct, remote):
    # compose refuses to run at all if one COMPOSE_FILE entry is missing
    h = _helpers()
    with open(ct / '.env', 'a') as f:
        f.write(f'COMPOSE_FILE=docker-compose.yml:gone.yml:{ct}/docker-compose.yml\n')
    if remote:
        _run_remote(ct.parent)
    else:
        h['_cloudtak_ensure_custom_compose'](str(ct), lambda m: None)
    assert _compose_file(ct) == _expected(ct)


# ── remote Deploy deletes and re-clones ~/CloudTAK ───────────────────────────

FAKE_GIT = """#!/bin/sh
# clone: make the target with a base compose file; -C DIR rev-parse: a repo only if DIR/.git
# exists (real git exits 128 outside one); anything else: pass
for last; do :; done
case "$1" in clone) [ "$FAIL" = 1 ] && exit 1; mkdir -p "$last" && echo 'services: {}' > "$last/docker-compose.yml" ;;
  fetch) [ "$FAIL" = 1 ] && exit 1 ;;
  -C) [ "$3" = rev-parse ] && [ ! -d "$2/.git" ] && exit 128 ;; esac
exit 0
"""
FAKE_DOCKER = "#!/bin/sh\nexit 0\n"


def _reclone(home, tag, fail=False):
    sh = _helpers_reclone()['_cloudtak_remote_reclone_sh'](tag)
    bin_ = home / 'bin'
    bin_.mkdir(exist_ok=True)
    for name, body in (('git', FAKE_GIT), ('docker', FAKE_DOCKER)):
        (bin_ / name).write_text(body)
        os.chmod(bin_ / name, 0o755)
    return subprocess.run(['sh', '-c', sh], capture_output=True, text=True, timeout=30,
                          env={'HOME': str(home), 'PATH': f"{bin_}:{os.environ['PATH']}",
                               'FAIL': '1' if fail else '0'})


def _helpers_reclone():
    ns = {'shlex': shlex}
    src = '\n\n'.join([_assign('CLOUDTAK_CUSTOM_COMPOSE'), _fn('_cloudtak_remote_reclone_sh')])
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


@pytest.mark.parametrize('tag', ['v13.113.0', None])
def test_remote_reclone_keeps_the_operator_file(ct, tag):
    (ct / 'docker-compose.custom.yml').write_text(OPERATOR)
    if tag is None:
        assert not (ct / '.git').exists()                 # the no-tag path re-clones only then
    r = _reclone(ct.parent, tag)
    assert r.returncode == 0, r.stderr
    assert (ct / 'docker-compose.custom.yml').read_text() == OPERATOR
    assert not (ct / '.env').exists()                     # the tree really was replaced
    assert not (ct.parent / '.cloudtak-custom-compose.keep').exists()


def test_remote_reclone_without_an_operator_file_creates_none(ct):
    r = _reclone(ct.parent, 'v13.113.0')
    assert r.returncode == 0, r.stderr
    assert not (ct / 'docker-compose.custom.yml').exists()   # seeded later, by the ensure step


def test_remote_reclone_failure_keeps_it_for_the_next_run(ct):
    (ct / 'docker-compose.custom.yml').write_text(OPERATOR)
    assert _reclone(ct.parent, 'v13.113.0', fail=True).returncode != 0
    assert (ct.parent / '.cloudtak-custom-compose.keep').read_text() == OPERATOR
    assert _reclone(ct.parent, 'v13.113.0').returncode == 0
    assert (ct / 'docker-compose.custom.yml').read_text() == OPERATOR


def test_remote_deploy_over_a_valid_checkout_updates_in_place(ct):
    """ops #198: the re-clone deleted .docker-garage (the store's live data) and .env with the
    tree. A valid checkout is now updated in place, so both survive a remote Deploy."""
    (ct / '.git').mkdir()
    (ct / 'docker-compose.yml').write_text('services: {}\n')
    (ct / 'docker-compose.custom.yml').write_text(OPERATOR)
    (ct / '.docker-garage' / 'meta').mkdir(parents=True)
    (ct / '.docker-garage' / 'meta' / 'node_key').write_text('cluster identity')
    r = _reclone(ct.parent, 'v13.113.0')
    assert r.returncode == 0, r.stderr
    assert (ct / '.env').read_text() == ENV
    assert (ct / '.docker-garage' / 'meta' / 'node_key').read_text() == 'cluster identity'
    assert (ct / 'docker-compose.custom.yml').read_text() == OPERATOR


def test_remote_in_place_update_failure_is_reported(ct):
    (ct / '.git').mkdir()
    (ct / 'docker-compose.yml').write_text('services: {}\n')
    assert _reclone(ct.parent, 'v13.113.0', fail=True).returncode != 0   # the fetch fails
    assert (ct / '.env').read_text() == ENV       # and nothing was deleted


def test_remote_deploy_uses_the_reclone_helper():
    src = _fn('run_cloudtak_deploy')
    assert 'prep_cmd = _cloudtak_remote_reclone_sh(remote_release_tag)' in src
    assert 'rm -rf ~/CloudTAK' not in src


def test_local_reclone_fallback_carries_the_operator_file():
    src = _fn('run_cloudtak_deploy')
    i = src.find('docker-compose.yml missing — re-cloning')
    seg = src[i:i + 1600]
    _before(seg, 'CLOUDTAK_CUSTOM_COMPOSE), \'rb\')', "rm -rf {cloudtak_dir}")
    _before(seg, 'git clone --depth 1{_rclone_branch}', "CLOUDTAK_CUSTOM_COMPOSE), 'wb')")


# ── every compose action sets it up first ────────────────────────────────────

def _before(src, first, then):
    i, j = src.find(first), src.find(then)
    assert i != -1, f'{first!r} missing'
    assert j != -1, f'{then!r} missing'
    assert i < j, f'{first!r} must come before {then!r}'


def test_console_restart_migration_sets_it_up_before_the_recreate():
    src = _fn('_startup_harden_cloudtak_ports')
    _before(src, "_new_override = _cloudtak_build_override_yml", '_cloudtak_ensure_custom_compose(')
    _before(src, '_cloudtak_ensure_custom_compose(', "'up', '-d', '--force-recreate'")


def test_deploy_restores_it_after_writing_env_and_before_pull_and_up():
    src = _fn('run_cloudtak_deploy')
    _before(src, "with open(env_path, 'w')", '_cloudtak_ensure_custom_compose(cloudtak_dir')
    _before(src, '_cloudtak_ensure_custom_compose(cloudtak_dir', '_docker_compose_pull(None, cloudtak_dir')
    _before(src, '_cloudtak_ensure_custom_compose(cloudtak_dir', "'up', '-d', '--force-recreate'")
    _before(src, 'mv /tmp/docker-compose.override.yml', '_cloudtak_remote_custom_compose_sh()')


def test_update_config_and_restart_sets_it_up_before_up():
    src = _fn('run_cloudtak_redeploy')
    _before(src, "with open(env_path, 'w')", '_cloudtak_ensure_custom_compose(cloudtak_dir')
    _before(src, '_cloudtak_ensure_custom_compose(cloudtak_dir', 'up -d --force-recreate')
    _before(src, '_cloudtak_remote_custom_compose_sh()', 'docker compose up -d')


def test_cloudtak_update_sets_it_up_before_the_build():
    src = _fn('run_cloudtak_update')
    _before(src, '_cloudtak_ensure_custom_compose(cloudtak_dir', "build --no-cache' +")
    _before(src, '_ssh_probe(remote_cfg, _cloudtak_remote_custom_compose_sh()',
            'f"cd ~/CloudTAK && {dcc} build --no-cache"')


def test_plugin_install_sets_it_up_before_the_rebuild_and_recreate():
    src = _fn('_run_cloudtak_plugin_action')
    _before(src, '_cloudtak_ensure_custom_compose(ct_dir', "'build', '--no-cache', 'api'")


def test_start_stop_restart_set_it_up_first():
    src = _fn('cloudtak_control')
    _before(src, '_cloudtak_ensure_custom_compose(cloudtak_dir)', "'docker', 'compose', 'up', '-d'")
    _before(src, '_cloudtak_remote_custom_compose_sh()', '_ssh_probe(rcfg, cmd')


def test_logs_load_the_operator_services_too():
    src = _fn('cloudtak_container_logs')
    assert "'-f', compose_yml" not in src


def test_nothing_else_writes_the_operator_file():
    # Only the seed path may write it, and only when it does not exist ('x' / `[ -e ] ||`).
    for fn in ('_cloudtak_build_override_yml', '_cloudtak_refresh_override',
               '_patch_cloudtak_compose_ports', '_cloudtak_build_env_content'):
        assert 'custom' not in _fn(fn).lower(), fn
    assert "open(custom, 'x')" in _fn('_cloudtak_ensure_custom_compose')
