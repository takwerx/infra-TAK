"""ops #950 follow-up: a box that is ALREADY in the media restart loop must heal itself.

PR "Stop two CloudTAK media heals from leaving duplicate hls keys" stops new doubled keys, but a box that
got one on 10.4.1 stays stuck: MediaMTX refuses the file, the cloudtak-media container exits and restarts in
a loop, `docker exec` into it fails, so the heal that runs INSIDE the container never runs.

The repair fixes /mediamtx.yml from OUTSIDE with `docker cp` (works on a looping container), then restarts.

These tests run the real heal code (local path and the remote shell command) against a fake `docker` that
behaves like the real one where it matters here: the "container" is a folder, `docker cp` works in any state,
`docker exec` fails unless the container is running, and a restart only gets the container running when its
mediamtx.yml has no duplicate key (MediaMTX's own rule).
"""
import ast
import os
import re
import subprocess
import types
from pathlib import Path

import pytest

APP = (Path(__file__).resolve().parent.parent / 'app.py').read_text(encoding='utf-8')

KEYS = ('hlsVariant', 'hlsAlwaysRemux', 'hlsSegmentCount', 'hlsSegmentDuration', 'hlsPartDuration')
GOOD_BLOCK = ('hlsVariant: mpegts\nhlsAlwaysRemux: no\nhlsSegmentCount: 3\n'
              'hlsSegmentDuration: 500ms\nhlsPartDuration: 200ms\n')
IMAGE_YML = """logLevel: info
hls: yes
hlsAddress: :8888
hlsVariant: fmp4

webrtc: true

pathDefaults:
  rtspDemuxMpegts: yes
"""
DOUBLED = IMAGE_YML + GOOD_BLOCK                    # `hlsVariant` twice: the state the box showed
CORRECT = IMAGE_YML.replace('hlsVariant: fmp4\n', '') + GOOD_BLOCK


def _count(text, key):
    return len(re.findall(r'^' + key + ':', text, re.M))


def _script(name):
    m = re.search(r"^" + name + r" = r'''(.*?)'''", APP, re.S | re.M)
    assert m, name
    return m.group(1)


def _load(*names):
    """exec the named top-level functions / constants of app.py that exist on this branch."""
    tree = ast.parse(APP)
    parts = []
    for n in tree.body:
        nm = None
        if isinstance(n, ast.FunctionDef):
            nm = n.name
        elif isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
            nm = n.targets[0].id
        if nm in names:
            parts.append(ast.get_source_segment(APP, n))
    return '\n\n'.join(parts)


# --- the yml fix itself -----------------------------------------------------------------------

def _fix_ns():
    ns = {'re': re}
    exec(compile(_load('_CT_MEDIA_HLS_KEYS', '_CT_MEDIA_HLS_BLOCK', '_ct_media_fix_yml'), 'app.py', 'exec'), ns)
    return ns


def test_fix_yml_turns_a_doubled_file_into_one_of_each_key():
    fix = _fix_ns()['_ct_media_fix_yml']
    new, changed = fix(DOUBLED)
    assert changed
    assert [_count(new, k) for k in KEYS] == [1] * 5
    assert 'hlsVariant: fmp4' not in new
    assert 'pathDefaults:\n  rtspDemuxMpegts: yes\n' in new


def test_fix_yml_leaves_a_correct_file_alone():
    fix = _fix_ns()['_ct_media_fix_yml']
    assert fix(CORRECT) == (CORRECT, False)


def test_fix_yml_is_idempotent_and_handles_a_file_without_a_final_newline():
    fix = _fix_ns()['_ct_media_fix_yml']
    once, _ = fix(IMAGE_YML.rstrip('\n'))
    assert [_count(once, k) for k in KEYS] == [1] * 5 and once.endswith('\n')
    assert fix(once) == (once, False)


def test_fix_yml_says_changed_when_a_value_is_wrong():
    fix = _fix_ns()['_ct_media_fix_yml']
    new, changed = fix(CORRECT.replace('hlsSegmentCount: 3', 'hlsSegmentCount: 7'))
    assert changed and 'hlsSegmentCount: 3' in new and 'hlsSegmentCount: 7' not in new


# --- a fake docker: the "container" is a folder -----------------------------------------------

def _make_docker(tmp_path, yml, status='restarting', exit_code='1'):
    fs = tmp_path / 'fs'
    fs.mkdir()
    (fs / 'mediamtx.yml').write_text(yml)
    (tmp_path / 'status').write_text(status)
    (tmp_path / 'code').write_text(exit_code)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'docker.log'
    (bindir / 'docker').write_text(f"""#!/bin/sh
FS={fs}
echo "$@" >> {log}
st=$(cat {tmp_path}/status)
dups() {{
  for k in hlsVariant hlsAlwaysRemux hlsSegmentCount hlsSegmentDuration hlsPartDuration; do
    [ "$(grep -c "^$k:" $FS/mediamtx.yml)" -le 1 ] || return 0
  done
  return 1
}}
case "$1" in
  ps) if [ "$2" = -a ] || [ "$st" = running ] || [ "$st" = restarting ]; then echo cloudtak-media-1; fi ;;
  inspect)
    case "$3" in
      *State.Running*) [ "$st" = running ] && echo true || echo false ;;
      *) echo "$st $(cat {tmp_path}/code)" ;;
    esac ;;
  cp)
    case "$2" in
      cloudtak-media-1:*)
        if [ -e {tmp_path}/cp_read_fails ]; then echo "Error: no such container" >&2; exit 1; fi
        f="$FS/${{2#cloudtak-media-1:}}"
        if [ "$3" = - ]; then COPYFILE_DISABLE=1 tar -cf - -C "$(dirname "$f")" "$(basename "$f")"; else cp "$f" "$3"; fi ;;
      *) cp "$2" "$FS/${{3#cloudtak-media-1:}}" ;;
    esac ;;
  restart|start)
    if dups; then echo restarting > {tmp_path}/status; echo 1 > {tmp_path}/code
    else echo running > {tmp_path}/status; echo 0 > {tmp_path}/code; fi ;;
  exec)
    body=$(cat)
    if [ "$st" != running ]; then echo "Error response from daemon: Container cloudtak-media-1 is $st" >&2; exit 1; fi
    echo "$body" | sed "s#/mediamtx.yml#$FS/mediamtx.yml#g; s#/tmp/.ct-media-heal.lock#{tmp_path}/heal.lock#g" | sh ;;
esac
""")
    (bindir / 'docker').chmod(0o755)
    return fs, bindir, log


def _env(bindir):
    return dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}')


# --- the remote heal (shell command sent over ssh) ---------------------------------------------

def _remote_heal(tmp_path, yml, **kw):
    fs, bindir, log = _make_docker(tmp_path, yml, **kw)
    sent = []
    import base64 as _b
    ns = {'_b64': _b, '_ssh_probe': lambda cfg, cmd, timeout=0: sent.append(cmd) or (True, ''),
          'time': types.SimpleNamespace(sleep=lambda s: None)}
    for n in ('_CT_MEDIA_CHECK_SH', '_CT_MEDIA_APPLY_SH', '_CT_MEDIA_OUTSIDE_SH'):
        if f'\n{n} = r' in APP:
            ns[n] = _script(n)
    ns.setdefault('_CT_MEDIA_OUTSIDE_SH', 'echo FAIL')       # base branch has no repair script
    exec(compile(_load('_ct_media_converged', '_cloudtak_media_hls_heal'), 'app.py', 'exec'), ns)
    ns['_cloudtak_media_hls_heal'](plog=lambda m: None, remote_cfg={'host': 'x'})
    r = subprocess.run(['sh', '-c', sent[0]], capture_output=True, text=True, env=_env(bindir), timeout=90)
    return r.stdout.strip(), (fs / 'mediamtx.yml').read_text(), log.read_text()


def test_remote_heal_repairs_a_container_stuck_in_the_restart_loop(tmp_path):
    """The proof test for a box already stuck. Red without the repair (the heal gave up: FAIL, file still doubled)."""
    out, text, calls = _remote_heal(tmp_path, DOUBLED)
    assert out == 'HEALED', out
    assert [_count(text, k) for k in KEYS] == [1] * 5, text
    assert (tmp_path / 'status').read_text().strip() == 'running'


def test_remote_heal_does_not_touch_a_looping_container_whose_file_is_fine(tmp_path):
    out, text, calls = _remote_heal(tmp_path, CORRECT)
    assert out != 'HEALED' and out != 'OK', out
    assert text == CORRECT
    assert 'restart' not in calls and 'cp ' + str(tmp_path) not in calls


def test_remote_heal_leaves_a_container_that_exited_cleanly_alone(tmp_path):
    out, text, calls = _remote_heal(tmp_path, DOUBLED, status='exited', exit_code='0')
    assert out == 'NOCONTAINER', out
    assert text == DOUBLED
    assert 'restart' not in calls


def test_remote_heal_says_fail_when_the_file_cannot_be_read(tmp_path):
    (tmp_path / 'cp_read_fails').write_text('x')
    out, text, calls = _remote_heal(tmp_path, DOUBLED)
    assert out == 'FAIL', out
    assert 'restart' not in calls


# --- the local heal (python, through _sudo_wrap) -----------------------------------------------

def _local_heal(tmp_path, yml, **kw):
    fs, bindir, log = _make_docker(tmp_path, yml, **kw)
    logs = []

    class _Sub:
        TimeoutExpired = subprocess.TimeoutExpired

        @staticmethod
        def run(cmd, **k):
            return subprocess.run(cmd, env=_env(bindir), **k)

    ns = {'subprocess': _Sub, '_sudo_wrap': lambda c: list(c), 'time': __import__('time'), 're': re, 'os': os,
          'tempfile': __import__('tempfile'),
          '_b64': None, '_ssh_probe': None}
    for n in ('_CT_MEDIA_CHECK_SH', '_CT_MEDIA_APPLY_SH'):
        ns[n] = _script(n).replace('/tmp/.ct-media-heal.lock', str(tmp_path / 'heal.lock'))
    names = ('_CT_MEDIA_HLS_KEYS', '_CT_MEDIA_HLS_BLOCK', '_ct_media_fix_yml', '_ct_media_state',
             '_ct_media_can_be_stuck', '_cloudtak_media_repair_outside', '_ct_media_converged',
             '_cloudtak_media_hls_heal')
    exec(compile(_load(*names), 'app.py', 'exec'), ns)
    res = ns['_cloudtak_media_hls_heal'](plog=logs.append)
    return res, (fs / 'mediamtx.yml').read_text(), log.read_text(), logs


def test_local_heal_repairs_a_container_stuck_in_the_restart_loop(tmp_path):
    """Red on the base branch: the heal returns False and the file stays doubled."""
    res, text, calls, logs = _local_heal(tmp_path, DOUBLED)
    assert res is True, logs
    assert [_count(text, k) for k in KEYS] == [1] * 5, text
    assert (tmp_path / 'status').read_text().strip() == 'running'
    assert calls.count('restart') == 1                    # one restart, by the repair; the heal adds none
    assert any('repaired from outside' in l for l in logs)


def test_local_heal_repairs_a_container_that_gave_up_restarting(tmp_path):
    """Exited with an error and not in plain `docker ps`."""
    res, text, calls, logs = _local_heal(tmp_path, DOUBLED, status='exited', exit_code='1')
    assert res is True, logs
    assert [_count(text, k) for k in KEYS] == [1] * 5
    assert (tmp_path / 'status').read_text().strip() == 'running'


def test_local_heal_does_not_touch_a_looping_container_whose_file_is_fine(tmp_path):
    res, text, calls, logs = _local_heal(tmp_path, CORRECT)
    assert res is False
    assert text == CORRECT
    assert 'restart' not in calls
    assert any('another cause' in l for l in logs)


def test_local_heal_leaves_a_container_that_exited_cleanly_alone(tmp_path):
    res, text, calls, logs = _local_heal(tmp_path, DOUBLED, status='exited', exit_code='0')
    assert res is False
    assert text == DOUBLED
    assert 'restart' not in calls


def test_local_heal_gives_up_cleanly_when_the_file_cannot_be_read(tmp_path):
    (tmp_path / 'cp_read_fails').write_text('x')
    res, text, calls, logs = _local_heal(tmp_path, DOUBLED)
    assert res is False
    assert text == DOUBLED
    assert 'restart' not in calls


def test_local_heal_still_does_nothing_on_a_healthy_running_container(tmp_path):
    res, text, calls, logs = _local_heal(tmp_path, CORRECT, status='running', exit_code='0')
    assert res is True
    assert text == CORRECT
    assert 'restart' not in calls and ' cp ' not in calls
