"""ops #950 (10.4.3 candidate, ARM fresh install): the CloudTAK media heal must not edit /mediamtx.yml
while the image's own start script is still writing it.

Found in the ubuntu-22.04-arm64 fresh install of the 10.4.3 candidate: the MediaMTX deploy recreated the
cloudtak-media container, the heal ran one second later and logged
`cloudtak-media heal apply failed: media profile did not converge: drift ok ok`, and CloudTAK video
answered HTTP 500 until the autorepair job rebuilt the container 13 minutes later.

What was proved (real media-infra v9.15.1 container on arm64, apply script run at a random 0.0 to 0.6 s
after `docker run`, 120 runs, 10 at once): 5 runs went wrong. 4 left `webrtcAdditionalHosts: []` and
MediaMTX exited with `at least one between 'webrtcIPsFromInterfaces' or 'webrtcAdditionalHosts' must be
filled`; 1 printed the exact box message `media profile did not converge: drift ok ok`.
Cause: the image's /start runs `node /dist/configure.js` first. It reads /mediamtx.yml and writes the whole
file back (hosts, log level, auth address), then starts MediaMTX. A heal that edits the file in between has
its edit undone by that write, or undoes that write itself.

The fix: the apply script waits until configure.js has ended, and puts the new file in place with `mv`
(one atomic step, never an empty file a reader could catch).

The scripts are plain sh, so these tests run them for real against a temp copy of the yml. A shim `ps`
stands in for the container's process list, and a small sh script plays configure.js.
"""
import os
import re
import stat
import subprocess
import threading
import time
from pathlib import Path

APP = (Path(__file__).resolve().parent.parent / 'app.py').read_text(encoding='utf-8')

KEYS = ('hlsVariant', 'hlsAlwaysRemux', 'hlsSegmentCount', 'hlsSegmentDuration', 'hlsPartDuration')

# media-infra v9.15.1's own file, cut down: `webrtcAdditionalHosts: []` is what configure.js replaces
# with the host of CLOUDTAK_Config_media_url.
PRISTINE = """logLevel: info
api: yes
apiAddress: :4000
hls: yes
hlsVariant: fmp4

webrtc: true
webrtcAdditionalHosts: []
"""
HOSTS_LINE = 'webrtcAdditionalHosts:\n  - "video.example.org"\n'


def _script(name):
    m = re.search(r"^" + name + r" = r'''(.*?)'''", APP, re.S | re.M)
    assert m, name
    return m.group(1)


def _shim_ps(bindir, running_flag):
    """A `ps` that lists `node /dist/configure.js` while the flag file exists, like the container does."""
    bindir.mkdir(exist_ok=True)
    ps = bindir / 'ps'
    ps.write_text('#!/bin/sh\n'
                  'echo "  PID USER TIME COMMAND"\n'
                  f'[ -f {running_flag} ] && echo "   42 root 0:00 node /dist/configure.js"\n'
                  'echo "    1 root 0:00 sh /start"\n'
                  'exit 0\n')
    ps.chmod(ps.stat().st_mode | stat.S_IXUSR)


def _run_apply(tmp_path, yml, env_path=None):
    body = (_script('_CT_MEDIA_APPLY_SH').replace('/mediamtx.yml', str(yml))
            .replace('/tmp/.ct-media-heal.lock', str(tmp_path / 'heal.lock')))
    env = dict(os.environ)
    if env_path:
        env['PATH'] = env_path + os.pathsep + env['PATH']
    return subprocess.run(['sh'], input=body, capture_output=True, text=True, timeout=60, env=env)


def _run_check(tmp_path, yml):
    body = _script('_CT_MEDIA_CHECK_SH').replace('/mediamtx.yml', str(yml))
    return subprocess.run(['sh'], input=body, capture_output=True, text=True, timeout=30).stdout.split()


def _fake_configure(yml, flag, write_after):
    """What the image's configure.js does, with the gap between its read and its write made wide: it
    reads the file now, and writes the whole file back `write_after` seconds later with the host line."""
    def run():
        flag.write_text('')
        text = yml.read_text()                      # read ...
        time.sleep(write_after)                     # ... (the CoTURN fetch, node start-up) ...
        text = text.replace('webrtcAdditionalHosts: []\n', HOSTS_LINE)
        yml.write_text(text)                        # ... write the whole file back
        flag.unlink()
    t = threading.Thread(target=run)
    t.start()
    return t


def test_heal_during_startup_keeps_both_the_hls_profile_and_configure_js_output(tmp_path):
    """The proof test. configure.js reads the file, the heal runs while it is still going, configure.js
    writes. Red on the old apply (it edits at once, configure.js's write then puts the image's
    `hlsVariant: fmp4` back and the final state is drift); green with the wait."""
    yml = tmp_path / 'm.yml'
    yml.write_text(PRISTINE)
    flag = tmp_path / 'configure.running'
    _shim_ps(tmp_path / 'bin', flag)
    t = _fake_configure(yml, flag, write_after=1.0)
    time.sleep(0.2)                                  # the heal arrives inside the window
    r = _run_apply(tmp_path, yml, env_path=str(tmp_path / 'bin'))
    t.join()
    text = yml.read_text()
    assert r.returncode == 0, r.stdout + r.stderr
    assert _run_check(tmp_path, yml)[0] == 'ok', text      # the profile is in the final file
    assert [len(re.findall('^' + k + ':', text, re.M)) for k in KEYS] == [1] * 5, text
    assert HOSTS_LINE in text, text                        # and so is what configure.js wrote
    assert 'webrtcAdditionalHosts: []' not in text, text   # (MediaMTX refuses to start on this one)


def test_apply_does_not_wait_when_configure_js_is_not_running(tmp_path):
    """A heal on a box whose container has been up for hours must stay instant."""
    yml = tmp_path / 'm.yml'
    yml.write_text(PRISTINE)
    flag = tmp_path / 'configure.running'              # never created
    _shim_ps(tmp_path / 'bin', flag)
    start = time.time()
    r = _run_apply(tmp_path, yml, env_path=str(tmp_path / 'bin'))
    assert r.returncode == 0 and 'CHANGED' in r.stdout, r.stdout + r.stderr
    assert time.time() - start < 5


def test_apply_gives_up_waiting_after_20_seconds_instead_of_hanging(tmp_path):
    """If a process called configure.js never ends, the heal still runs (the caller allows 40 s)."""
    body = _script('_CT_MEDIA_APPLY_SH')
    m = re.search(r'while \[ \$w -lt (\d+) \]', body)
    assert m, 'the wait loop is gone'
    assert int(m.group(1)) * 0.5 <= 25, 'the wait must stay under the 40 s the caller allows for the script'


def test_new_file_is_put_in_place_in_one_step_never_empty(tmp_path):
    """The old apply opened the live file with `cat tmp > file`, which is empty for a moment. A reader
    that catches that moment (configure.js did, on the box) sees no config at all. `mv` is one step."""
    body = _script('_CT_MEDIA_APPLY_SH')
    assert '> "$F"' not in body.replace('> "$F.ops950.tmp"', ''), 'the live file is opened for writing again'
    assert 'mv -f "$F.ops950.tmp" "$F"' in body
    yml = tmp_path / 'm.yml'
    seen_empty = []
    for _ in range(25):
        yml.write_text(PRISTINE)                     # outside the reader's window
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                try:
                    if yml.read_text() == '':
                        seen_empty.append(1)
                except FileNotFoundError:
                    seen_empty.append(1)
        th = threading.Thread(target=reader)
        th.start()
        try:
            r = _run_apply(tmp_path, yml)
        finally:
            stop.set()
            th.join()
        assert r.returncode == 0 and 'CHANGED' in r.stdout, r.stdout + r.stderr
    assert not seen_empty, f'a reader saw an empty or missing /mediamtx.yml {len(seen_empty)} times during the apply'
    assert _run_check(tmp_path, yml)[0] == 'ok'
