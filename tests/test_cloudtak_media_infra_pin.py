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
"""One media-infra pin for every architecture (v10.2.8 W2).

ghcr, 2026-10-08: media-infra v9.7.0 is a single-arch amd64 manifest; v9.10.0 and v9.11.0 are
image indexes with amd64 + arm64. So the ARM-only v9.1.1 pin (and its RTSP-lease caveat) and
the on-box arm64 source build — which built CloudTAK's own tag, an image the override never
ran — both go. v9.9.0 also fixes HLS proxy playback dying at 10 minutes.
"""

import ast
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _func(name):
    return re.search(rf'^def {name}\(.*?(?=^def |^[A-Z_]+ = )', APP, re.S | re.M).group(0)


def test_single_multiarch_pin():
    assert "MEDIA_INFRA_IMAGE = 'ghcr.io/dfpc-coe/media-infra:v9.11.0'" in APP
    assert 'MEDIA_INFRA_MULTIARCH = True' in APP
    body = _func('_cloudtak_build_override_yml')
    assert 'media_image = MEDIA_INFRA_IMAGE' in body
    assert "'arm64', 'aarch64'" not in re.sub(r'#.*', '', body.split('media_image =')[1][:200])
    assert 'image: {media_image}' in body


def test_constant_is_defined_before_its_first_user():
    assert APP.index('MEDIA_INFRA_IMAGE = ') < APP.index('def _cloudtak_build_override_yml(')


def test_arm64_source_build_is_skipped_for_a_multiarch_pin():
    src = ast.get_source_segment(APP, next(
        n for n in ast.parse(APP).body
        if isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_build_arm64_media'))
    ran, logs = [], []
    ns = {'_host_arch': lambda: 'arm64', 'MEDIA_INFRA_MULTIARCH': True,
          'MEDIA_INFRA_IMAGE': 'ghcr.io/dfpc-coe/media-infra:v9.11.0',
          'subprocess': types.SimpleNamespace(run=lambda *a, **k: ran.append(a))}
    exec(compile(src, 'app.py', 'exec'), ns)
    assert ns['_cloudtak_build_arm64_media']('/nonexistent', plog=logs.append) is False
    assert ran == []
    assert any('publishes an arm64 image' in l for l in logs)


def test_arm_prepull_includes_media_when_the_pin_is_multiarch():
    assert "if _host_arch() == 'arm64' and not MEDIA_INFRA_MULTIARCH:" in APP


def test_media_patch_still_replaces_upstream_hls_variant():
    # v9.10.0 started shipping `hlsVariant: fmp4`; ours must replace it, not duplicate it.
    apply = re.search(r"^_CT_MEDIA_APPLY_SH = r'''(.*?)'''", APP, re.S | re.M).group(1)
    assert '/^hlsVariant:/d' in apply
    assert apply.index('/^hlsVariant:/d') < apply.index('hlsVariant: mpegts')
