# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""An ATLAS release is installed only if its tag is signed by a trusted key.

ATLAS security audit H3: whoever could push to the mirror (the account, or a
token lifted from the publishing workstation) could ship code to every box.
Install checked that the tag was its channel's tip; update checked nothing.
Both now also require the tag to be signed by a key in
`ATLAS_ALLOWED_SIGNERS`, which lives here rather than on the mirror it vouches
for.

⚠️ **Real signatures, real `ssh-keygen`.** Each test signs a tag in a
throwaway repository with a throwaway key, exactly as the ATLAS publisher
does, and the module checks it the way a box does. A stubbed verifier would
prove that a function was called, not that a box could tell a forged release
from a real one.
"""

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402


MODULE = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')


def _run(*argv, cwd=None, data=None):
    return subprocess.run(list(argv), cwd=cwd, input=data, capture_output=True, check=True)


def _key(directory, name):
    """A throwaway ed25519 key. Returns ``(private key path, public key text)``."""
    path = directory / name
    _run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', name, '-f', str(path))
    kind, blob = (directory / (name + '.pub')).read_text().split()[:2]
    return path, kind + ' ' + blob


@pytest.fixture(scope='module')
def keys(tmp_path_factory):
    directory = tmp_path_factory.mktemp('keys')
    return {name: _key(directory, name) for name in ('release', 'recovery', 'stranger')}


@pytest.fixture(autouse=True)
def trusted(monkeypatch, keys):
    """The module trusts the throwaway release and recovery keys, never the real ones."""
    monkeypatch.setattr(atlas, 'ATLAS_ALLOWED_SIGNERS', (
        ('atlas-release', keys['release'][1]),
        ('atlas-recovery', keys['recovery'][1]),
    ))


class Repo:
    """A checkout standing in for an ATLAS deployment's, with tags made the
    way the ATLAS publisher makes them."""

    def __init__(self, path):
        self.path = path
        _run('git', 'init', '-q', str(path))
        self.commit = self.make_commit('a release')

    def git(self, *args, data=None):
        return _run('git', '-C', str(self.path), *args, data=data).stdout.decode().strip()

    def make_commit(self, message):
        tree = self.git('write-tree')
        return self.git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
                        'commit-tree', tree, '-m', message)

    def payload(self, tag, commit=None, message=None):
        return (f'object {commit or self.commit}\ntype commit\ntag {tag}\n'
                f'tagger ATLAS <atlas@example.invalid> 1760000000 +0000\n\n'
                f'{message or "ATLAS " + tag}\n').encode()

    def signed(self, tag, key, commit=None, message=None):
        """A tag object signed with `key`, as `git tag -s` with gpg.format=ssh makes it."""
        body = self.path / 'tag-payload'
        body.write_bytes(self.payload(tag, commit, message))
        # ⚠️ ssh-keygen will not overwrite an existing .sig, and with no
        # terminal to ask it keeps the old one: a second tag would carry the
        # first tag's signature.
        (self.path / 'tag-payload.sig').unlink(missing_ok=True)
        _run('ssh-keygen', '-Y', 'sign', '-n', 'git', '-f', str(key), str(body))
        signature = (self.path / 'tag-payload.sig').read_bytes().replace(b'\r\n', b'\n')
        return self.payload(tag, commit, message) + signature

    def place(self, ref_name, raw):
        """Write `raw` as a tag object and point refs/tags/`ref_name` at it."""
        sha = self.git('hash-object', '-t', 'tag', '-w', '--stdin', '--literally', data=raw)
        self.git('update-ref', 'refs/tags/' + ref_name, sha)
        return sha


@pytest.fixture
def repo(tmp_path):
    return Repo(tmp_path / 'atlas')


@pytest.fixture
def plog():
    return []


def _verify(repo, plog, tag, commit=None):
    atlas._verify_release(str(repo.path), plog.append, tag, commit or repo.commit)


# --------------------------------------------------------------------------- #
# What is accepted
# --------------------------------------------------------------------------- #


def test_a_release_signed_by_the_release_key_is_accepted(repo, keys, plog):
    repo.place('v1.0.0', repo.signed('v1.0.0', keys['release'][0]))

    _verify(repo, plog, 'v1.0.0')

    assert any('Signature verified: v1.0.0 signed by atlas-release' in line for line in plog)


def test_a_release_signed_by_the_recovery_key_is_accepted(repo, keys, plog):
    """The recovery key exists so a lost release key does not strand every box."""
    repo.place('v1.0.0', repo.signed('v1.0.0', keys['recovery'][0]))

    _verify(repo, plog, 'v1.0.0')

    assert any('signed by atlas-recovery' in line for line in plog)


# --------------------------------------------------------------------------- #
# What is refused
# --------------------------------------------------------------------------- #


def test_a_release_signed_by_any_other_key_is_refused(repo, keys, plog):
    """The attack itself: a valid signature, from a key the box does not trust."""
    repo.place('v1.0.0', repo.signed('v1.0.0', keys['stranger'][0]))

    with pytest.raises(RuntimeError, match='not by a trusted ATLAS release key'):
        _verify(repo, plog, 'v1.0.0')


def test_an_unsigned_annotated_tag_is_refused(repo, plog):
    repo.place('v1.0.0', repo.payload('v1.0.0'))

    with pytest.raises(RuntimeError, match='is not signed'):
        _verify(repo, plog, 'v1.0.0')


def test_a_lightweight_tag_is_refused(repo, plog):
    """What the mirror published before signing: a ref straight to a commit."""
    repo.git('update-ref', 'refs/tags/v1.0.0', repo.commit)

    with pytest.raises(RuntimeError, match='not an annotated, signed tag'):
        _verify(repo, plog, 'v1.0.0')


def test_an_old_signed_tag_replayed_under_a_newer_name_is_refused(repo, keys, plog):
    """⚠️ A signature says who made the object, not which release it is. An
    old, genuinely signed v1.0.0 pushed as v1.1.0 (with the branch moved onto
    its commit) would otherwise verify, and an update would be a downgrade."""
    repo.place('v1.1.0', repo.signed('v1.0.0', keys['release'][0]))

    with pytest.raises(RuntimeError, match='replayed under a newer name'):
        _verify(repo, plog, 'v1.1.0')


def test_a_signed_tag_on_a_different_commit_is_refused(repo, keys, plog):
    """The tag must be on the commit the channel's branch tip is."""
    repo.place('v1.0.0', repo.signed('v1.0.0', keys['release'][0]))
    elsewhere = repo.make_commit('not the release')

    with pytest.raises(RuntimeError, match='does not describe'):
        _verify(repo, plog, 'v1.0.0', commit=elsewhere)


def test_a_tag_altered_after_signing_is_refused(repo, keys, plog):
    """The signature covers the whole payload, message included."""
    raw = repo.signed('v1.0.0', keys['release'][0])
    tampered = raw.replace(b'ATLAS v1.0.0', b'ATLAS v1.0.0 (trust me)', 1)
    repo.place('v1.0.0', tampered)

    with pytest.raises(RuntimeError, match='not by a trusted ATLAS release key'):
        _verify(repo, plog, 'v1.0.0')


def test_a_missing_tag_is_refused(repo, plog):
    with pytest.raises(RuntimeError, match='not an annotated, signed tag'):
        _verify(repo, plog, 'v9.9.9')


# --------------------------------------------------------------------------- #
# Where the checks sit
# --------------------------------------------------------------------------- #
#
# Read from the source, as test_atlas_channel does for the same functions:
# `deploy` and `_run_update` need Docker, a box and a network, and the property
# that matters is the order of the git commands, which is visible here.


def _body(name, end):
    source = MODULE[MODULE.index('def ' + name + '('):]
    return source[:source.index(end)]


def test_the_update_path_checks_everything_before_touching_the_tree():
    """⚠️ The gap this file exists for: `_run_update` used to fetch a tag and
    check it out with no check at all. And a refusal must leave the running
    deployment's files as they were, so nothing touches the tree first."""
    source = _body('_run_update', "plog('━━━ Step 2/3")

    tip = source.index('_channel_commit(')
    fetch = source.index('_fetch_tag_argv(dirpath, tag)')
    signature = source.index('_verify_release(dirpath, plog, tag, commit)')
    discard = source.index("'checkout', '--', '.'")
    checkout = source.index("'checkout', '-f', tag")
    landed = source.index('_verify_checkout(ctx, dirpath, plog, tag, commit)')

    assert tip < fetch < signature < discard < checkout < landed


def test_an_install_checks_the_signature_before_it_checks_out_or_builds():
    source = _body('deploy', '# ── 3/7 Configuration')

    fetched = source.index('_fetch_tag_argv(dirpath, tag)')
    assert fetched < source.index('_verify_release(dirpath, plog, tag, expected)', fetched) \
        < source.index("'checkout', '-f', tag", fetched)
    cloned = source.index("'git', 'clone'")
    assert cloned < source.index('_verify_release(dirpath, plog, tag, expected)', cloned) \
        < source.index('_verify_checkout(ctx, dirpath, plog, tag, expected)')


def test_only_the_offline_pin_skips_the_signature():
    """The pin is held to a commit recorded in this file, which is stronger than a
    signature; anything resolved from a channel is not."""
    assert atlas._is_pin_fallback(atlas.ATLAS_TAG, atlas.ATLAS_SHA)
    assert not atlas._is_pin_fallback(atlas.ATLAS_TAG, '0' * 40)
    assert not atlas._is_pin_fallback('v9.9.9', atlas.ATLAS_SHA)


def test_install_and_update_share_one_channel_rule():
    """So they cannot drift apart on what "the channel's release" means again."""
    assert MODULE.count('_channel_commit(') == 3  # the definition and both callers
    with pytest.raises(RuntimeError, match='not the dev release'):
        atlas._channel_commit({'refs/heads/dev': 'a' * 40, 'refs/tags/v1.0.0': 'b' * 40},
                              'dev', 'v1.0.0')
    assert atlas._channel_commit(
        {'refs/heads/dev': 'c' * 40, 'refs/tags/v1.0.0': 'd' * 40,
         'refs/tags/v1.0.0^{}': 'c' * 40}, 'dev', 'v1.0.0') == 'c' * 40


# --------------------------------------------------------------------------- #
# The keys themselves
# --------------------------------------------------------------------------- #


def test_the_embedded_keys_are_the_release_and_recovery_keys(monkeypatch):
    monkeypatch.undo()  # the real list, not the throwaway one
    principals = [p for p, _ in atlas.ATLAS_ALLOWED_SIGNERS]
    assert principals == ['atlas-release', 'atlas-recovery']
    keys = [k for _, k in atlas.ATLAS_ALLOWED_SIGNERS]
    assert len(set(keys)) == 2, 'the recovery key must not be the release key'
    for key in keys:
        assert key.startswith('ssh-ed25519 ')
        listed = subprocess.run(['ssh-keygen', '-l', '-f', '-'], input=key.encode(),
                                capture_output=True)
        assert listed.returncode == 0, 'not a parseable public key: ' + key


# --------------------------------------------------------------------------- #
# The fetch (review of PR #180)
# --------------------------------------------------------------------------- #


@pytest.fixture
def box(tmp_path, keys):
    """A mirror with an old lightweight v1.0.0, and a box that installed it."""
    source = Repo(tmp_path / 'source')
    source.git('update-ref', 'refs/tags/v1.0.0', source.commit)
    mirror = tmp_path / 'mirror.git'
    _run('git', 'clone', '-q', '--bare', str(source.path), str(mirror))
    deployed = tmp_path / 'deployed'
    _run('git', 'clone', '-q', '--depth=1', '--branch', 'v1.0.0',
         mirror.as_uri(), str(deployed))
    return source, mirror, deployed


def _publish(source, mirror, ref_name, raw):
    source.place(ref_name, raw)
    _run('git', '-C', str(source.path), 'push', '-q', '--force', str(mirror),
         'refs/tags/' + ref_name)


def test_an_old_tag_changed_upstream_breaks_the_old_fetch(box, keys):
    """The reviewer's reproduction, kept as the reason for `_fetch_tag_argv`:
    `--tags` refuses to clobber v1.0.0, so the update to v1.1.0 fails."""
    source, mirror, deployed = box
    _publish(source, mirror, 'v1.0.0', source.signed('v1.0.0', keys['release'][0]))
    new = source.make_commit('v1.1.0')
    _publish(source, mirror, 'v1.1.0', source.signed('v1.1.0', keys['release'][0], commit=new))

    old = subprocess.run(['git', '-C', str(deployed), 'fetch', '--tags', '--depth=1',
                          'origin', 'v1.1.0'], capture_output=True, text=True)

    assert old.returncode != 0 and 'clobber' in old.stderr


def test_the_single_tag_fetch_installs_despite_an_old_tag_changed_upstream(box, keys, plog):
    source, mirror, deployed = box
    _publish(source, mirror, 'v1.0.0', source.signed('v1.0.0', keys['release'][0]))
    new = source.make_commit('v1.1.0')
    _publish(source, mirror, 'v1.1.0', source.signed('v1.1.0', keys['release'][0], commit=new))
    # Another tag on the same commit: git would follow it in unless told not to.
    _publish(source, mirror, 'v1.1.0-rc', source.signed('v1.1.0-rc', keys['release'][0], commit=new))

    _run(*atlas._fetch_tag_argv(str(deployed), 'v1.1.0'))

    atlas._verify_release(str(deployed), plog.append, 'v1.1.0', new)
    tags = _run('git', '-C', str(deployed), 'tag').stdout.decode().split()
    assert sorted(tags) == ['v1.0.0', 'v1.1.0']
    assert _run('git', '-C', str(deployed), 'cat-file', '-t', 'refs/tags/v1.0.0') \
        .stdout.decode().strip() == 'commit', 'other tags must be left alone'


def test_a_moved_tag_is_fetched_and_then_caught(box, keys, plog):
    """Forcing the one tag means a moved tag replaces the local copy; the
    signature check is what refuses it, which is the point."""
    source, mirror, deployed = box
    first = source.make_commit('v1.1.0')
    _publish(source, mirror, 'v1.1.0', source.signed('v1.1.0', keys['release'][0], commit=first))
    _run(*atlas._fetch_tag_argv(str(deployed), 'v1.1.0'))

    moved = source.make_commit('something else')
    _publish(source, mirror, 'v1.1.0', source.signed('v1.1.0', keys['stranger'][0], commit=moved))
    _run(*atlas._fetch_tag_argv(str(deployed), 'v1.1.0'))

    with pytest.raises(RuntimeError, match='not by a trusted ATLAS release key'):
        atlas._verify_release(str(deployed), plog.append, 'v1.1.0', moved)


def test_install_and_update_fetch_the_same_way():
    assert MODULE.count('_fetch_tag_argv(dirpath, tag),') == 2
    assert "'fetch', '--tags'" not in MODULE


def test_a_refused_clone_is_removed():
    source = _body('deploy', '# ── 3/7 Configuration')
    cloned = source[source.index("'git', 'clone'"):]
    refused = cloned[cloned.index('_verify_release(dirpath, plog, tag, expected)'):]
    assert refused.index('except RuntimeError:') < refused.index('_rm_priv(dirpath') \
        < refused.index('raise\n')
