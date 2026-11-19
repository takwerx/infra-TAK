"""ops #950: the CloudTAK media heal must never leave a duplicate hls key in /mediamtx.yml.

Found in the 10.4.2 update test (Ubuntu 22.04, 10.4.1 baseline): right after the MediaMTX deploy the
cloudtak-media container restarted in a loop with `mapping key "hlsVariant" already defined`, and CloudTAK
had no video. media-infra reads /mediamtx.yml and MediaMTX refuses a duplicate key.

What was proved (a media-infra v9.15.1 container, the old apply script run three at a time): 84 of 200
runs left `hlsVariant` twice. The old check used `grep -q` per key, so it also called a file with
duplicate keys "converged", and no later heal repaired it.

The scripts are plain sh, so these tests run them for real against a temp copy of the image's yml.
"""
import ast
import os
import re
import shutil
import subprocess
import sys
import types
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

APP = (Path(__file__).resolve().parent.parent / 'app.py').read_text(encoding='utf-8')

KEYS = ('hlsVariant', 'hlsAlwaysRemux', 'hlsSegmentCount', 'hlsSegmentDuration', 'hlsPartDuration')

# The part of media-infra v9.15.1's own mediamtx.yml that matters here: it ships `hlsVariant: fmp4`
# in the middle of the file and `pathDefaults:` as the last block.
PRISTINE = """logLevel: info
srt: yes
srtAddress: :8890

hls: yes
hlsAddress: :8888
hlsEncryption: no
# fMP4-based HLS - supports H264, H265, Opus, MPEG-4 Audio (AAC) & more.
hlsVariant: fmp4

webrtc: true
webrtcAddress: :8889

pathDefaults:
  rtspDemuxMpegts: yes
"""

GOOD_BLOCK = ('hlsVariant: mpegts\nhlsAlwaysRemux: no\nhlsSegmentCount: 3\n'
              'hlsSegmentDuration: 500ms\nhlsPartDuration: 200ms\n')


def _script(name):
    m = re.search(r"^" + name + r" = r'''(.*?)'''", APP, re.S | re.M)
    assert m, name
    return m.group(1)


def _run(script, tmp_path, yml):
    """Run one of the container scripts with sh, pointed at a temp yml and a temp lock."""
    body = (script.replace('/mediamtx.yml', str(yml))
                  .replace('/tmp/.ct-media-heal.lock', str(tmp_path / 'heal.lock')))
    return subprocess.run(['sh'], input=body, capture_output=True, text=True, timeout=60)


def _count(text, key):
    return len(re.findall(r'^' + key + ':', text, re.M))


def test_check_calls_a_file_with_duplicate_hls_keys_drift(tmp_path):
    """The state the box showed. Red on the old check (it said `ok`), so no heal ever repaired it."""
    yml = tmp_path / 'm.yml'
    yml.write_text(PRISTINE + GOOD_BLOCK)          # hlsVariant: fmp4 AND hlsVariant: mpegts
    r = _run(_script('_CT_MEDIA_CHECK_SH'), tmp_path, yml)
    assert r.stdout.split()[0] == 'drift', r.stdout + r.stderr


def test_check_still_calls_a_correct_file_ok(tmp_path):
    yml = tmp_path / 'm.yml'
    yml.write_text(PRISTINE.replace('hlsVariant: fmp4\n', '') + GOOD_BLOCK)
    r = _run(_script('_CT_MEDIA_CHECK_SH'), tmp_path, yml)
    assert r.stdout.split()[0] == 'ok', r.stdout + r.stderr


def test_apply_repairs_a_file_with_duplicate_keys(tmp_path):
    yml = tmp_path / 'm.yml'
    yml.write_text(PRISTINE + GOOD_BLOCK)
    r = _run(_script('_CT_MEDIA_APPLY_SH'), tmp_path, yml)
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'CHANGED' in r.stdout and 'UNCHANGED' not in r.stdout
    text = yml.read_text()
    for k in KEYS:
        assert _count(text, k) == 1, (k, text)
    assert 'hlsVariant: fmp4' not in text
    assert 'pathDefaults:\n  rtspDemuxMpegts: yes\n' in text     # the rest of the file is kept


def test_apply_replaces_the_image_hls_variant_once(tmp_path):
    yml = tmp_path / 'm.yml'
    yml.write_text(PRISTINE)
    r = _run(_script('_CT_MEDIA_APPLY_SH'), tmp_path, yml)
    assert r.returncode == 0 and 'CHANGED' in r.stdout, r.stdout + r.stderr
    text = yml.read_text()
    assert [_count(text, k) for k in KEYS] == [1] * 5
    assert 'hlsVariant: mpegts' in text and 'fmp4' not in text.split('hls: yes')[1].split('webrtc')[0].replace('# fMP4', '')


def test_apply_on_a_correct_file_changes_nothing_and_says_so(tmp_path):
    """UNCHANGED is what keeps the caller from restarting the container a second time."""
    yml = tmp_path / 'm.yml'
    yml.write_text(PRISTINE.replace('hlsVariant: fmp4\n', '') + GOOD_BLOCK)
    before = yml.read_text()
    r = _run(_script('_CT_MEDIA_APPLY_SH'), tmp_path, yml)
    assert r.returncode == 0 and 'UNCHANGED' in r.stdout, r.stdout + r.stderr
    assert yml.read_text() == before


def test_apply_fails_loudly_when_the_file_cannot_be_read(tmp_path):
    r = _run(_script('_CT_MEDIA_APPLY_SH'), tmp_path, tmp_path / 'missing.yml')
    assert r.returncode != 0
    assert 'UNCHANGED' not in r.stdout


@pytest.mark.skipif(shutil.which('flock') is None, reason='flock (util-linux or busybox) not installed')
def test_overlapping_heals_never_duplicate_a_key(tmp_path):
    """The proof test. Three heals at once on a freshly created container's file, 60 rounds.
    Red on the old apply script (duplicate hlsVariant in most rounds), green with the lock."""
    apply = _script('_CT_MEDIA_APPLY_SH')
    bad = []
    for i in range(60):
        yml = tmp_path / f'm{i}.yml'
        yml.write_text(PRISTINE)
        with ThreadPoolExecutor(3) as ex:
            list(ex.map(lambda _: _run(apply, tmp_path, yml), range(3)))
        text = yml.read_text()
        counts = {k: _count(text, k) for k in KEYS}
        if any(v != 1 for v in counts.values()):
            bad.append((i, counts))
    assert not bad, f'{len(bad)} of 60 rounds left a duplicate or missing hls key, first: {bad[0]}'


def _load_heal(runs, restarts):
    """Load _cloudtak_media_hls_heal with a fake docker."""
    tree = ast.parse(APP)
    src = ast.get_source_segment(APP, next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_media_hls_heal'))
    conv = ast.get_source_segment(APP, next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_ct_media_converged'))

    def fake_run(cmd, input=None, **kw):
        cmd = list(cmd)
        if cmd[:2] == ['docker', 'ps']:
            return types.SimpleNamespace(stdout='cloudtak-media-1\n', stderr='', returncode=0)
        if cmd[:2] == ['docker', 'restart']:
            restarts.append(cmd)
            return types.SimpleNamespace(stdout='', stderr='', returncode=0)
        return runs.pop(0)

    ns = {'subprocess': types.SimpleNamespace(run=fake_run), '_sudo_wrap': lambda c: c,
          '_CT_MEDIA_CHECK_SH': 'check', '_CT_MEDIA_APPLY_SH': 'apply', 'time': types.SimpleNamespace(sleep=lambda s: None),
          '_b64': None, '_ssh_probe': None}
    exec(compile(conv + '\n' + src, 'app.py', 'exec'), ns)
    return ns['_cloudtak_media_hls_heal']


def _out(stdout, rc=0, stderr=''):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=rc)


def test_heal_restarts_once_when_it_changed_the_file():
    restarts = []
    heal = _load_heal([_out('drift ok na'), _out('CHANGED\n')], restarts)
    assert heal(plog=lambda m: None) is True
    assert len(restarts) == 1


def test_heal_does_not_restart_when_another_heal_already_fixed_it():
    """Two heals overlap: the second waits on the lock, finds the file fixed (UNCHANGED), and leaves the
    restart to the first one."""
    restarts = []
    heal = _load_heal([_out('drift ok na'), _out('UNCHANGED\n')], restarts)
    assert heal(plog=lambda m: None) is True
    assert restarts == []


def test_heal_reports_failure_and_does_not_restart_when_apply_fails():
    restarts, logs = [], []
    heal = _load_heal([_out('drift ok na'), _out('', rc=1, stderr='media profile did not converge: drift ok na')], restarts)
    assert heal(plog=logs.append) is False
    assert restarts == []
    assert any('apply failed' in l for l in logs)


def test_remote_heal_command_skips_the_second_restart():
    """The remote one-liner must treat UNCHANGED as already healed, like the local path."""
    tree = ast.parse(APP)
    fn = ast.get_source_segment(APP, next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_media_hls_heal'))
    assert '*UNCHANGED*) echo OK' in fn
    assert 'docker restart' in fn
