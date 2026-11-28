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
"""The PostGIS pin is never forced onto data a newer PostgreSQL wrote (ops #1335).

The CloudTAK override pins postgis/postgis:17-3.7-alpine on every box at every console start.
Nothing read the data's PostgreSQL major first. A volume on PostgreSQL 18 under that pin starts an
older server on newer files ("database files are incompatible with server") and crash-loops
(the ops #1306 shape). The data major is read with `docker cp` from PG_VERSION, which works on a
stopped or crash-looping container; data above the pin is not forced.

app.py cannot be imported in a test, so the functions are cut out of it and run: the code under
test is the shipped text.
"""

import ast
import io
import os
import pathlib
import re
import subprocess as _real_subprocess
import tarfile
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

PIN = 'postgis/postgis:17-3.7-alpine'
PIN_ARM = 'imresamu/postgis:17-3.6-alpine'


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    return None


def _src(names, optional=()):
    parts = {}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in set(names) | set(optional):
            parts[node.name] = ast.get_source_segment(APP, node)
    missing = set(names) - set(parts)
    assert not missing, f'missing from app.py: {sorted(missing)}'
    return '\n\n'.join(parts[n] for n in (*names, *optional) if n in parts)


class _R:
    def __init__(self, rc=0, out='', err=''):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _tar(text):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tf:
        data = text.encode()
        ti = tarfile.TarInfo('PG_VERSION')
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class FakeDocker:
    """The docker calls the guard makes. `cid`: container id ('' = no container). `files`: the
    PG_VERSION text by data dir ({'data': '17'} or {'18/docker': '18'}). `image` / `image_major`:
    what `docker inspect` says the container runs. `broken`: Docker not answering."""

    def __init__(self, cid='abc123', files=None, image='postgis/postgis:17-3.7-alpine', image_major='17',
                 broken=False, stopped=False):
        self.cid, self.files, self.image, self.image_major = cid, files or {}, image, image_major
        self.broken, self.stopped = broken, stopped
        self.calls = []

    def run(self, argv, **kw):
        argv = list(argv)
        self.calls.append(argv)
        if self.broken:
            return _R(1, '', 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock.')
        if argv[:5] == ['docker', 'ps', '-a', '-q', '-f']:
            return _R(0, (self.cid + '\n') if self.cid else '')
        if argv[:2] == ['docker', 'inspect']:
            env = f'PATH=/usr/local/bin\n' + (f'PG_MAJOR={self.image_major}\n' if self.image_major else '')
            return _R(0, f'{self.image}\n{env}')
        if argv[:2] == ['docker', 'cp']:
            m = re.fullmatch(r'abc123:/var/lib/postgresql/(.+)/PG_VERSION', argv[2])
            if m and m.group(1) in self.files:
                # the broker on a non-root console (nuc, ops #1335) gives an EMPTY stdout for
                # `docker cp C:PATH -`; a copy to a host folder works, so that is what the guard asks for
                # and a folder target is not enough: the broker then names the file `f`, not PG_VERSION
                assert argv[3] != '-' and argv[3].endswith('/PG_VERSION'), argv
                with open(argv[3], 'w') as fh:
                    fh.write(self.files[m.group(1)] + '\n')
                return types.SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
            return types.SimpleNamespace(returncode=1, stdout=b'',
                                         stderr=b'Error: No such container:path: abc123:/var/lib/postgresql/x')
        raise AssertionError(f'unexpected docker call {argv}')

    @property
    def cps(self):
        return [c for c in self.calls if c[:2] == ['docker', 'cp']]


GUARD_NAMES = ('_cloudtak_postgis_state', '_cloudtak_postgis_guard')


def _ns(docker, ssh=None, settings_remote=None, required=True):
    ns = {
        'os': os, 're': re, 'shutil': __import__('shutil'), 'tempfile': __import__('tempfile'),
        'subprocess': types.SimpleNamespace(run=docker.run, PIPE=_real_subprocess.PIPE,
                                            STDOUT=_real_subprocess.STDOUT),
        '_sudo_wrap': lambda argv: list(argv),
        '_ssh_probe': ssh or (lambda cfg, cmd, timeout=30: (False, '')),
        '_get_cloudtak_deployment_config': lambda s: ({'target_mode': 'remote', 'remote': settings_remote}
                                                      if settings_remote is not None else {'target_mode': 'local'}),
    }
    for c in ('_CT_POSTGIS_DATA_DIRS', '_CT_POSTGIS_IMAGE_RE', '_CT_POSTGIS_REMOTE_PROBE_SH', '_CT_POSTGIS_NOTED',
              'POSTGIS_IMAGE', 'POSTGIS_IMAGE_ARM64'):
        text = _const(c)
        if text:
            exec(compile(text, 'app.py', 'exec'), ns)
    # required=False: the override test runs on the base branch too, where the guard does not exist
    # and the pin is forced; it must fail there on the behaviour, not on a missing name
    exec(compile(_src(GUARD_NAMES if required else (), optional=GUARD_NAMES), 'app.py', 'exec'), ns)
    return ns


def _guard(docker, pin=PIN, **kw):
    ns = _ns(docker, **{k: v for k, v in kw.items() if k in ('ssh', 'settings_remote')})
    logs = []
    img = ns['_cloudtak_postgis_guard'](pin, {}, kw.get('is_remote', False), log=logs.append)
    return img, logs


# ---- boxes whose data is on the pin's major (every box today): nothing changes

def test_data_on_the_pin_major_keeps_the_pin():
    d = FakeDocker(files={'data': '17'})
    assert _guard(d) == (PIN, [])


def test_arm_pin_is_kept_too():
    d = FakeDocker(files={'data': '17'}, image=PIN_ARM)
    assert _guard(d, pin=PIN_ARM) == (PIN_ARM, [])


def test_older_data_keeps_the_pin():
    # an older major is the pin's job to move to, as before; this guard only stops a downgrade
    assert _guard(FakeDocker(files={'data': '16'}))[0] == PIN
    assert _guard(FakeDocker(files={'data': '9.5'}))[0] == PIN


def test_no_container_means_no_data_to_protect():
    d = FakeDocker(cid='')
    assert _guard(d) == (PIN, [])
    assert d.cps == []


def test_docker_not_answering_keeps_the_pin():
    assert _guard(FakeDocker(broken=True)) == (PIN, [])


def test_no_cluster_in_the_container_keeps_the_pin():
    assert _guard(FakeDocker(files={})) == (PIN, [])


# ---- the proof: data a newer PostgreSQL wrote

def test_data_on_postgresql_18_is_not_forced_back_to_17_and_the_running_image_is_kept():
    d = FakeDocker(files={'18/docker': '18'}, image='postgis/postgis:18-3.6-alpine', image_major='18')
    img, logs = _guard(d)
    assert img == 'postgis/postgis:18-3.6-alpine'
    assert len(logs) == 1 and 'PostgreSQL 18 data' in logs[0] and 'NOT forced' in logs[0]
    assert 'keeps running postgis/postgis:18-3.6-alpine' in logs[0]


def test_a_stopped_or_crash_looping_container_is_read_the_same_way():
    # docker cp reads the volume with no running postgres; the container's own image is the 17 pin
    # (the crash loop of ops #1306), which cannot read the data, so no image is forced at all
    d = FakeDocker(files={'18/docker': '18'}, image=PIN, image_major='17', stopped=True)
    img, logs = _guard(d)
    assert img == ''
    assert 'No image is set here' in logs[0]


def test_data_dir_of_older_images_is_read_first_and_18_dirs_after():
    d = FakeDocker(files={'18/docker': '18'})
    _guard(d)
    assert d.cps[0][2] == 'abc123:/var/lib/postgresql/data/PG_VERSION'
    assert d.cps[1][2].startswith('abc123:/var/lib/postgresql/18/docker/')


def test_the_reason_is_logged_once_not_at_every_override_build():
    d = FakeDocker(files={'18/docker': '18'}, image='postgis/postgis:18-3.6-alpine', image_major='18')
    ns = _ns(d)
    logs = []
    for _ in range(3):
        ns['_cloudtak_postgis_guard'](PIN, {}, False, log=logs.append)
    assert len(logs) == 1


def test_an_image_name_that_is_not_a_plain_image_reference_is_never_written_into_yaml():
    d = FakeDocker(files={'18/docker': '18'}, image='x" evil: 1', image_major='18')
    assert _guard(d)[0] == ''


def test_a_guard_error_keeps_the_pin():
    ns = _ns(FakeDocker(files={'18/docker': '18'}))
    ns['_cloudtak_postgis_state'] = lambda remote_cfg=None: 1 / 0
    logs = []
    assert ns['_cloudtak_postgis_guard'](PIN, {}, False, log=logs.append) == PIN
    assert 'skipped' in logs[0]


def test_the_local_read_copies_to_a_folder_and_leaves_none_behind(tmp_path, monkeypatch):
    # `docker cp C:PATH -` answers with nothing through the broker on a non-root console (nuc), so the
    # guard must copy to a folder; the folder is private to this read and is removed afterwards
    made = []
    real_mkdtemp = __import__('tempfile').mkdtemp
    monkeypatch.setattr('tempfile.mkdtemp', lambda **kw: made.append(real_mkdtemp(dir=tmp_path, **kw)) or made[-1])
    d = FakeDocker(files={'18/docker': '18'}, image='postgres:18-alpine', image_major='18')
    assert _guard(d)[0] == 'postgres:18-alpine'
    assert len(made) == 1 and not os.path.exists(made[0])
    assert all(c[3] != '-' for c in d.cps)


# ---- a CloudTAK on a remote host

def test_remote_reads_the_data_over_ssh():
    seen = []

    def ssh(cfg, cmd, timeout=30):
        seen.append((cfg, cmd))
        return True, 'IMAGE postgis/postgis:18-3.6-alpine\nIMGMAJOR 18\nMAJOR 18\n'

    img, logs = _guard(FakeDocker(), ssh=ssh, settings_remote={'host': 'h'}, is_remote=True)
    assert img == 'postgis/postgis:18-3.6-alpine'
    assert seen[0][0] == {'host': 'h'} and 'docker cp' in seen[0][1] and '/var/lib/postgresql/$d/PG_VERSION' in seen[0][1]
    assert 'PostgreSQL 18 data' in logs[0]


def test_remote_data_on_17_or_no_answer_keeps_the_pin():
    assert _guard(FakeDocker(), ssh=lambda c, s, timeout=30: (True, 'IMAGE x\nIMGMAJOR 17\nMAJOR 17\n'),
                  settings_remote={'host': 'h'}, is_remote=True)[0] == PIN
    assert _guard(FakeDocker(), ssh=lambda c, s, timeout=30: (False, ''),
                  settings_remote={'host': 'h'}, is_remote=True)[0] == PIN
    assert _guard(FakeDocker(), ssh=lambda c, s, timeout=30: (True, 'NONE\n'),
                  settings_remote={'host': 'h'}, is_remote=True)[0] == PIN


def test_remote_with_no_saved_host_does_not_guess():
    assert _guard(FakeDocker(), settings_remote={}, is_remote=True)[0] == PIN


def test_remote_probe_script_runs_as_a_shell_script_and_reads_a_real_file(tmp_path):
    # the script text itself, run with a stand-in `docker` that serves a PG_VERSION tar
    tar = tmp_path / 'v.tar'
    tar.write_bytes(_tar('18\n'))
    fake = tmp_path / 'docker'
    fake.write_text(
        '#!/bin/sh\n'
        'case "$1" in\n'
        '  ps) echo abc123;;\n'
        '  inspect) case "$*" in *Config.Image*) echo postgis/postgis:18-3.6-alpine;; *) printf "PATH=/x\\nPG_MAJOR=18\\n";; esac;;\n'
        f'  cp) case "$2" in *18/docker/PG_VERSION) cat {tar};; *) echo "no such" >&2; exit 1;; esac;;\n'
        'esac\n')
    fake.chmod(0o755)
    probe = re.search(r'^_CT_POSTGIS_REMOTE_PROBE_SH = \(.*?^\)', APP, re.S | re.M).group(0)
    ns = {}
    exec(compile(_const('_CT_POSTGIS_DATA_DIRS'), 'app.py', 'exec'), ns)
    exec(compile(probe, 'app.py', 'exec'), ns)
    r = _real_subprocess.run(['sh', '-c', ns['_CT_POSTGIS_REMOTE_PROBE_SH']], capture_output=True, text=True,
                             env={'PATH': f'{tmp_path}:/usr/bin:/bin'})
    assert r.returncode == 0, r.stderr
    assert 'IMAGE postgis/postgis:18-3.6-alpine' in r.stdout
    assert 'IMGMAJOR 18' in r.stdout and 'MAJOR 18' in r.stdout.splitlines()


# ---- the override file itself

def _override(docker, remote=False):
    ns = _ns(docker, required=False)
    ns.update({
        'CONFIG_DIR': '/nonexistent', 'MEDIA_INFRA_IMAGE': 'ghcr.io/dfpc-coe/media-infra:v9.15.1',
        'INFRATAK_DOCKER_NETWORK': 'infratak',
        '_get_takserver_host': lambda s: '', '_cloudtak_video_host_pin': lambda s: '',
        '_cloudtak_stream_host_pin': lambda s: '', '_cloudtak_takserver_host_pin': lambda s: None,
        '_ensure_infratak_docker_network': lambda: None, '_host_arch': lambda: 'amd64',
        '_container_ca_trust': lambda node=False: ('', ''),
    })
    exec(compile(_src(['_cloudtak_build_override_yml']), 'app.py', 'exec'), ns)
    return ns['_cloudtak_build_override_yml']({})


def _postgis_block(yml):
    return re.search(r'(?ms)^  postgis:\n(.*?)(?=^  \S|^\S|\Z)', yml).group(1)


def test_override_pins_postgis_when_the_data_is_on_17():
    block = _postgis_block(_override(FakeDocker(files={'data': '17'})))
    assert f'    image: {PIN}\n' in block
    assert 'POSTGRES_PASSWORD' in block


def test_override_does_not_force_the_pin_on_postgresql_18_data():
    yml = _override(FakeDocker(files={'18/docker': '18'}, image='postgis/postgis:18-3.6-alpine', image_major='18'))
    block = _postgis_block(yml)
    assert 'image: postgis/postgis:18-3.6-alpine' in block
    assert PIN not in yml


def test_override_with_no_usable_image_has_no_image_line_but_keeps_the_password_setting():
    yml = _override(FakeDocker(files={'18/docker': '18'}, image=PIN, image_major='17'))
    block = _postgis_block(yml)
    assert 'image:' not in block
    assert 'POSTGRES_PASSWORD: "${POSTGRES_PASSWORD:-docker}"' in block
    yaml = __import__('pytest').importorskip('yaml')
    assert 'environment' in yaml.safe_load(yml)['services']['postgis']


def test_every_caller_goes_through_the_builder_so_none_can_skip_the_guard():
    # the pin is written in one place; the guard sits right at it
    body = re.search(r'^def _cloudtak_build_override_yml\(.*?(?=^def )', APP, re.S | re.M).group(0)
    assert 'image: {postgis_image}\n' not in body.split('return f"""', 1)[1]
    assert body.count('{postgis_image_line}') == 1
    assert body.index('_cloudtak_postgis_guard(') < body.index('postgis_image_line =')
