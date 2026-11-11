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
"""Uploaded zip and tar archives only ever write inside the folder they unpack into.

The Cesium tiles zip upload, the TAK Server bundle unpack and the snapshot import all
go through the shared `_safe_extract_zip` / `_safe_tar_check` helpers in app.py. The
upload route below is run with its own source from app.py, on crafted zips, in a temp dir.
"""

import io
import os
import pathlib
import re
import tarfile
import types
import zipfile

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _func_src(name):
    m = re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M)
    return m.group(0) if m else ''


def _ns():
    """app.py's own helpers + the upload route, with Flask and the box stubbed out."""
    import shutil
    ns = {'os': os, 're': re, 'shutil': shutil, 'zipfile': zipfile, 'tarfile': tarfile}
    for n in ('_safe_archive_name', '_safe_extract_zip', '_safe_tar_check'):
        src = _func_src(n)
        if src:
            exec(compile(src, f'app.py:{n}', 'exec'), ns)
    return ns


def _upload(tmp_path, entries, name='ds'):
    """Run the real cesium_tiles_upload() on a zip built from [(entry, data|ZipInfo), ...]."""
    ct = tmp_path / 'ct'
    ct.mkdir(exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for ent, data in entries:
            z.writestr(ent, data)
    buf.seek(0)
    ns = _ns()
    ns.update({
        '_cesium_dir': lambda: str(ct),
        '_cesium_ensure_dir': lambda: None,
        'load_settings': lambda: {},
        '_cesium_list_datasets': lambda s: [],
        'jsonify': lambda d: d,
        'request': types.SimpleNamespace(
            form={'name': name},
            files={'file': types.SimpleNamespace(filename='t.zip', stream=buf)}),
    })
    src = _func_src('cesium_tiles_upload')
    assert src, 'cesium_tiles_upload() not found in app.py'
    exec(compile(src, 'app.py:cesium_tiles_upload', 'exec'), ns)
    return ns['cesium_tiles_upload'](), ct


def test_wrapped_zip_with_dotdot_entry_cannot_escape(tmp_path):
    # `w/tileset.json` makes it a valid dataset; `w/../../x` is the zip-slip entry
    res, ct = _upload(tmp_path, [('w/tileset.json', '{}'), ('w/../../x', 'pwned')])
    assert not (tmp_path / 'x').exists(), 'the entry wrote outside the dataset folder'
    assert not (ct / 'x').exists()
    assert res['success'] is False
    assert not (ct / 'ds').exists(), 'a refused zip must leave no half-unpacked dataset'


def test_deep_dotdot_entry_cannot_reach_other_directories(tmp_path):
    res, ct = _upload(tmp_path, [('w/tileset.json', '{}'), ('w/../../../escaped.txt', 'pwned')])
    assert not (tmp_path.parent / 'escaped.txt').exists()
    assert not (tmp_path / 'escaped.txt').exists()
    assert res['success'] is False


def test_unwrapped_zip_with_dotdot_entry_is_refused(tmp_path):
    res, ct = _upload(tmp_path, [('tileset.json', '{}'), ('../x', 'pwned')])
    assert not (ct / 'x').exists() and not (tmp_path / 'x').exists()
    assert res['success'] is False


def test_absolute_entry_is_refused(tmp_path):
    target = tmp_path / 'abs-target'
    res, ct = _upload(tmp_path, [('w/tileset.json', '{}'), (str(target), 'pwned')])
    assert not target.exists()
    assert res['success'] is False


def test_symlink_entry_is_refused(tmp_path):
    link = zipfile.ZipInfo('w/link')
    link.external_attr = (0o120777 << 16)
    res, ct = _upload(tmp_path, [('w/tileset.json', '{}'), (link, '/etc')])
    assert res['success'] is False
    assert not (ct / 'ds').exists()


def test_good_wrapped_zip_still_unpacks_without_the_wrapper(tmp_path):
    res, ct = _upload(tmp_path, [('w/', ''), ('w/tileset.json', '{"a":1}'), ('w/tiles/0.b3dm', 'x')])
    assert res['success'] is True, res
    assert (ct / 'ds' / 'tileset.json').read_text() == '{"a":1}'
    assert (ct / 'ds' / 'tiles' / '0.b3dm').read_text() == 'x'
    assert not (ct / 'ds' / 'w').exists()


def test_good_unwrapped_zip_still_unpacks(tmp_path):
    res, ct = _upload(tmp_path, [('tileset.json', '{}'), ('tiles/0.b3dm', 'x')])
    assert res['success'] is True, res
    assert (ct / 'ds' / 'tiles' / '0.b3dm').exists()


# ── the shared helpers ──────────────────────────────────────────────────────────

def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for ent, data in entries:
            z.writestr(ent, data)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def test_helper_writes_nothing_when_any_entry_is_refused(tmp_path):
    ns = _ns()
    dest = tmp_path / 'd'
    dest.mkdir()
    with pytest.raises(ValueError):
        ns['_safe_extract_zip'](_zip([('ok.txt', 'a'), ('../bad.txt', 'b')]), str(dest))
    assert list(dest.iterdir()) == []
    assert not (tmp_path / 'bad.txt').exists()


def test_helper_does_not_follow_a_symlink_already_in_the_folder(tmp_path):
    ns = _ns()
    outside = tmp_path / 'outside'
    outside.mkdir()
    dest = tmp_path / 'd'
    dest.mkdir()
    os.symlink(outside, dest / 'sub')
    with pytest.raises(ValueError):
        ns['_safe_extract_zip'](_zip([('sub/f.txt', 'pwned')]), str(dest))
    assert not (outside / 'f.txt').exists()


def test_helper_modes_keep_exec_bits_but_drop_setuid(tmp_path):
    ns = _ns()
    z = io.BytesIO()
    with zipfile.ZipFile(z, 'w') as zf:
        a = zipfile.ZipInfo('run.sh')
        a.external_attr = (0o104755 << 16)       # setuid + rwxr-xr-x
        zf.writestr(a, '#!/bin/sh\n')
    dest = tmp_path / 'd'
    dest.mkdir()
    ns['_safe_extract_zip'](zipfile.ZipFile(z), str(dest), apply_modes=True)
    mode = (dest / 'run.sh').stat().st_mode
    assert mode & 0o777 == 0o755
    assert not mode & 0o4000


def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tf:
        for name, kind, link in members:
            ti = tarfile.TarInfo(name)
            if kind == 'file':
                ti.size = 1
                tf.addfile(ti, io.BytesIO(b'x'))
            else:
                ti.type = {'sym': tarfile.SYMTYPE, 'hard': tarfile.LNKTYPE, 'chr': tarfile.CHRTYPE}[kind]
                ti.linkname = link
                tf.addfile(ti)
    buf.seek(0)
    return tarfile.open(fileobj=buf)


@pytest.mark.parametrize('members', [
    [('snap/../../etc/x', 'file', '')],
    [('/etc/x', 'file', '')],
    [('snap/l', 'sym', '/etc')],
    [('snap/l', 'sym', '../../etc')],
    [('snap/l', 'hard', '../etc/passwd')],
    [('snap/dev', 'chr', '')],
])
def test_tar_check_refuses_unsafe_members(tmp_path, members):
    with pytest.raises(ValueError):
        _ns()['_safe_tar_check'](_tar(members), str(tmp_path))


def test_tar_check_allows_a_normal_snapshot(tmp_path):
    _ns()['_safe_tar_check'](_tar([
        ('snap/CoreConfig.xml', 'file', ''),
        ('snap/cot.pgdump', 'file', ''),
        ('snap/current', 'sym', 'CoreConfig.xml'),
        ('snap/sub/l', 'sym', '../cot.pgdump'),
    ]), str(tmp_path))


# ── nothing in the code base unpacks an upload any other way ────────────────────

def test_no_raw_zip_or_tar_extraction_left_in_console_code():
    files = [REPO / 'app.py', REPO / 'broker' / 'takwerx_broker.py', REPO / 'selfheal_ip.py',
             REPO / 'mediamtx_ldap_overlay.py'] + sorted((REPO / 'modules').glob('*.py'))
    bad = []
    for f in files:
        if not f.exists():
            continue
        for i, line in enumerate(f.read_text(encoding='utf-8').splitlines(), 1):
            code = line.split('#', 1)[0]
            if re.search(r'\.extractall\(|\b(?:zf|z|zip_file|zipf)\.extract\(', code):
                bad.append(f'{f.name}:{i}: {line.strip()}')
    assert not bad, 'use _safe_extract_zip instead:\n' + '\n'.join(bad)


def test_uploaded_archives_go_through_the_helpers():
    assert APP.count('_safe_extract_zip(') >= 4          # def + cesium + 2 TAK bundle unpacks
    snap = APP[APP.index("tmp_path = dest_path + '.tmp.tar.gz'"):]
    snap = snap[:snap.index("['tar', '-xzf', tmp_path")]
    assert '_safe_tar_check(tf, SNAPSHOT_DIR)' in snap
