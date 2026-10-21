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
"""Security update for TAK Video Restreamer (v10.2.21).

Three things, each of which used to be missing:
  * the upstream clone is checked out at a pinned commit, not whatever `main` is today;
  * the MediaMTX in the image is the console's pinned, checksum-verified release, not the
    one upstream's Dockerfile downloads;
  * publishing from outside the container needs a login; viewing stays open.
"""

import base64
import hashlib
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.tvr as tvr  # noqa: E402

SRC = (ROOT / 'modules' / 'tvr.py').read_text(encoding='utf-8')
PAGE = (ROOT / 'templates' / 'tvr.html').read_text(encoding='utf-8')

# Upstream's Dockerfile step, verbatim at TVR_SHA.
UPSTREAM_STEP = (
    'RUN MEDIAMTX_VERSION=v1.19.2 && \\\n'
    '    wget https://github.com/bluenviron/mediamtx/releases/download/${MEDIAMTX_VERSION}/'
    'mediamtx_${MEDIAMTX_VERSION}_linux_amd64.tar.gz && \\\n'
    '    tar -xzf mediamtx_${MEDIAMTX_VERSION}_linux_amd64.tar.gz && \\\n'
    '    rm mediamtx_${MEDIAMTX_VERSION}_linux_amd64.tar.gz && \\\n'
    '    chmod +x mediamtx\n')
UPSTREAM_DOCKERFILE = ('FROM python:3.11-slim\nWORKDIR /opt/app\n\n# Download and install MediaMTX\n'
                       + UPSTREAM_STEP + '\n# Copy MediaMTX configuration\n'
                       'COPY mediaMTX.yml /opt/app/mediamtx.yml\n')


def _v(s):
    return tuple(int(x) for x in re.findall(r'\d+', s)[:3])


# ── pin ────────────────────────────────────────────────────────────────────────

def test_clone_is_pinned_to_a_full_commit():
    assert re.fullmatch(r'[0-9a-f]{40}', tvr.TVR_SHA)


def test_no_path_follows_upstream_main_any_more():
    assert 'get_latest_commit_sha' not in SRC
    assert 'api.github.com/repos/raytheonbbn' not in SRC
    # both the deploy and the self-update go through the pin, and nothing else pulls
    assert 'commit_sha = checkout_pin(_git, plog)' in SRC
    assert "new_sha = checkout_pin(lambda *a: ctx['_module_git'](dirpath, *a" in SRC
    assert SRC.count("'pull', '--ff-only'") == 1


class FakeGit:
    """Records calls; `have_pin` says whether the clone already holds TVR_SHA."""

    def __init__(self, have_pin=True, fetch_ok=True, head=None):
        self.calls, self.have_pin, self.fetch_ok = [], have_pin, fetch_ok
        self.head = head

    def __call__(self, *args):
        self.calls.append(args)
        rc, out = 0, ''
        if args[:2] == ('checkout', '-q') and args[2] == tvr.TVR_SHA:
            rc = 0 if self.have_pin else 1
            if rc == 0 and self.head is None:
                self.head = tvr.TVR_SHA
        elif args[0] == 'fetch':
            rc = 0 if self.fetch_ok else 128
            self.have_pin = self.have_pin or self.fetch_ok
        elif args[0] == 'rev-parse':
            out = (self.head or '') + '\n'
        return subprocess.CompletedProcess(args, rc, out, '' if rc == 0 else 'error: pathspec')


def test_checkout_pin_discards_overlay_and_lands_on_the_pin():
    g = FakeGit()
    assert tvr.checkout_pin(g, lambda m: None) == tvr.TVR_SHA
    assert g.calls[0] == ('checkout', '--', '.')
    assert g.calls[1] == ('checkout', '-q', 'main')
    assert ('pull', '--ff-only') in g.calls
    assert not any(c[0] == 'fetch' for c in g.calls)


def test_checkout_pin_fetches_by_sha_when_a_shallow_clone_lacks_it():
    g = FakeGit(have_pin=False)
    assert tvr.checkout_pin(g, lambda m: None) == tvr.TVR_SHA
    assert ('fetch', '-q', '--depth=1', 'origin', tvr.TVR_SHA) in g.calls


def test_checkout_pin_fails_closed():
    with pytest.raises(RuntimeError, match='pinned commit'):
        tvr.checkout_pin(FakeGit(have_pin=False, fetch_ok=False), lambda m: None)
    with pytest.raises(RuntimeError, match='expected pinned commit'):
        tvr.checkout_pin(FakeGit(head='0' * 40), lambda m: None)


def test_checkout_pin_only_uses_git_verbs_the_broker_admits_plus_the_fetch_fallback():
    # /root/tak-video-restreamer on a flipped box runs git through the broker
    broker = (ROOT / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')
    subcmds = eval(re.search(r'^_GIT_SUBCMDS = (\{.*\})$', broker, re.M).group(1))
    subflags = eval(re.search(r'^_GIT_SUBFLAGS = (\{.*?\})$', broker, re.M | re.S).group(1))
    g = FakeGit()
    tvr.checkout_pin(g, lambda m: None)
    for call in g.calls:
        assert call[0] in subcmds, call
        for a in call[1:]:
            assert not a.startswith('-') or a in subflags, call
            assert ':' not in a and not a.startswith('/'), call


# ── MediaMTX in the image ──────────────────────────────────────────────────────

def test_mediamtx_pin_is_past_the_fix_and_matches_the_console_pin_floor():
    assert _v(tvr.TVR_MEDIAMTX_VERSION) >= (1, 21, 1)
    app = (ROOT / 'app.py').read_text(encoding='utf-8')
    vetted = re.search(r'^MEDIAMTX_VETTED_RELEASE = "([^"]+)"', app, re.M).group(1)
    assert _v(tvr.TVR_MEDIAMTX_VERSION) >= _v(vetted)
    assert set(tvr.TVR_MEDIAMTX_SHA256) == {'amd64', 'arm64'}
    for h in tvr.TVR_MEDIAMTX_SHA256.values():
        assert re.fullmatch(r'[0-9a-f]{64}', h)


@pytest.mark.parametrize('arch', ['amd64', 'arm64'])
def test_dockerfile_step_is_replaced_and_checksum_verified(arch):
    out = tvr.patch_dockerfile(UPSTREAM_DOCKERFILE, arch)
    ver = tvr.TVR_MEDIAMTX_VERSION
    tarball = f'mediamtx_{ver}_linux_{arch}.tar.gz'
    assert 'v1.19.2' not in out and '${MEDIAMTX_VERSION}' not in out
    assert f'/releases/download/{ver}/{tarball}' in out
    assert f'echo "{tvr.TVR_MEDIAMTX_SHA256[arch]}  {tarball}" | sha256sum -c -' in out
    other = 'arm64' if arch == 'amd64' else 'amd64'
    assert f'linux_{other}' not in out
    # the rest of the Dockerfile is untouched
    assert out.startswith('FROM python:3.11-slim\nWORKDIR /opt/app\n')
    assert out.endswith('COPY mediaMTX.yml /opt/app/mediamtx.yml\n')
    # re-patching an already-patched file is a no-op, not a failure
    assert tvr.patch_dockerfile(out, arch) == out


def test_dockerfile_patch_fails_closed():
    with pytest.raises(RuntimeError, match='refusing to build'):
        tvr.patch_dockerfile('FROM python:3.11-slim\nRUN pip install x\n', 'amd64')
    with pytest.raises(RuntimeError, match='arch'):
        tvr.patch_dockerfile(UPSTREAM_DOCKERFILE, 'armv7')


def test_arm64_is_no_longer_a_warn_and_carry_on_patch():
    assert "_dfc.replace('_linux_amd64', '_linux_arm64')" not in SRC
    assert 'bundled mediamtx may be wrong-arch' not in SRC


# ── publish login ──────────────────────────────────────────────────────────────

def _auth_entries(yml):
    block = yml.split('authInternalUsers:\n', 1)[1].split('\n\n', 1)[0]
    entries = re.split(r'\n  - ', '\n' + block.strip('\n').lstrip())[1:]
    return [{'user': re.search(r'user: (\S+)', e).group(1),
             'pass': (re.search(r'pass: (\S+)', e) or [None, None])[1],
             'ips': re.search(r'ips: (\[.*?\])', e).group(1),
             'actions': re.findall(r'action: (\w+)', e)} for e in entries]


def test_anonymous_publish_is_loopback_only():
    entries = _auth_entries(tvr.mediamtx_yml('abc123'))
    assert len(entries) == 3
    for e in entries:
        if 'publish' in e['actions'] and e['user'] == 'any':
            assert e['ips'] == "['127.0.0.1', '::1']"
        if e['ips'] == '[]':
            assert e['user'] != 'any' or 'publish' not in e['actions']


def test_publisher_login_is_hashed_and_viewing_stays_open():
    pw = '0123456789abcdef01234567'
    yml = tvr.mediamtx_yml(pw)
    assert pw not in yml
    want = 'sha256:' + base64.b64encode(hashlib.sha256(pw.encode()).digest()).decode()
    pub = [e for e in _auth_entries(yml) if e['user'] == tvr.TVR_PUBLISH_USER]
    assert pub == [{'user': tvr.TVR_PUBLISH_USER, 'pass': want, 'ips': '[]', 'actions': ['publish']}]
    viewers = [e for e in _auth_entries(yml) if e['user'] == 'any' and e['ips'] == '[]']
    assert viewers and set(viewers[0]['actions']) == {'read', 'playback'}
    # api / metrics / pprof stay loopback-only
    for e in _auth_entries(yml):
        if {'api', 'metrics', 'pprof'} & set(e['actions']):
            assert e['ips'] == "['127.0.0.1', '::1']"


def test_empty_password_is_refused_not_written():
    with pytest.raises(ValueError):
        tvr.mediamtx_yml('')


def test_publish_password_is_kept_and_url_safe_when_new():
    assert tvr.publish_password({'tak_video_restreamer_publish_password': 'keep'}) == 'keep'
    new = tvr.publish_password({})
    assert re.fullmatch(r'[0-9a-f]{24}', new)


def test_api_has_no_browser_origins_and_moq_is_off():
    yml = tvr.mediamtx_yml('x')
    assert re.search(r'^apiAddress: 127\.0\.0\.1:8889$', yml, re.M)
    assert re.search(r'^apiAllowOrigins: \[\]$', yml, re.M)
    assert re.search(r'^moq: no$', yml, re.M)


def test_deploy_and_update_write_the_rendered_yml_and_record_the_build():
    assert 'f.write(TVR_MEDIAMTX_YML)' not in SRC
    assert "'mediaMTX.yml'), TVR_MEDIAMTX_YML)" not in SRC
    assert SRC.count('mediamtx_yml(publish_pass)') == 2
    assert SRC.count("s['tak_video_restreamer_mediamtx_version'] = TVR_MEDIAMTX_VERSION") == 2
    assert SRC.count("s['tak_video_restreamer_publish_password'] = publish_pass") == 2


# ── existing installs are offered the update ──────────────────────────────────

def _ctx(settings, head=tvr.TVR_SHA):
    return {
        '_module_git': lambda d, *a, **k: subprocess.CompletedProcess(a, 0, head + '\n', ''),
        '_sudo_wrap': lambda argv: ['false'],
        'load_settings': lambda: dict(settings),
    }


CURRENT = {'tak_video_restreamer_publish_password': 'p',
           'tak_video_restreamer_mediamtx_version': tvr.TVR_MEDIAMTX_VERSION}


def test_up_to_date_box_has_no_update():
    info = tvr.get_version_info(_ctx(CURRENT))
    assert info['update_available'] is False and info['security_update'] is False
    assert info['latest'] == tvr.TVR_SHA[:7]


def test_box_built_before_this_release_gets_the_security_update():
    info = tvr.get_version_info(_ctx({}))
    assert info['update_available'] and info['security_update'] and info['publish_login_new']
    old_mtx = dict(CURRENT, tak_video_restreamer_mediamtx_version='v1.19.2')
    info = tvr.get_version_info(_ctx(old_mtx))
    assert info['security_update'] and not info['publish_login_new']


def test_box_off_the_pin_gets_an_ordinary_update():
    info = tvr.get_version_info(_ctx(CURRENT, head='1' * 40))
    assert info['update_available'] and not info['security_update']


def test_page_warns_before_the_update_and_shows_the_login_after():
    assert "tvr_vinfo.get('publish_login_new')" in PAGE
    assert "settings.get('tak_video_restreamer_publish_password')" in PAGE
    assert 'streamid=publish:&lt;stream&gt;:publish:&lt;password&gt;' in PAGE
    assert 'function togglePubPw()' in PAGE
