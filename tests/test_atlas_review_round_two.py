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

"""TAKWERX review, round two (W240).

⚠️ **The blocker here was invisible to every test in this suite, and the
reviewer said why: the `_write_priv` double hands the file back readable.**
The real seam on a broker box is `_do_write` — `os.open` as uid 0, `fchmod`,
**no chown** — so `<home>/atlas/<slug>/.env` came out `root:root 0600`, the
console could not read its own deployment's environment file, and three
readers took `except OSError: return False`. The deploy printed a tick.

Nothing failed. `TAKMDM_ADMIN_GROUP` stayed blank, the proxy-auth secret was
never written, `TAKMDM_TRUSTED_PROXIES` kept its wide fallback. The refuse
branch added for precisely this case was unreachable, because the `OSError`
return came first.

The lesson is the one W230 and W235 already taught in different clothes: a
double that can answer a question the real console cannot ask is not a
double. These tests make the double behave like the seam.
"""

import io
import os
import pathlib
import re
import stat
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402

SOURCE = io.open(ROOT / 'modules' / 'atlas.py', encoding='utf-8').read()
CODE = re.sub(r'#[^\n]*', '', re.sub(r'"""[\s\S]*?"""', '', SOURCE))


def _body(name):
    """One function's executable source."""
    start = CODE.index('def %s(' % name)
    rest = CODE[start:]
    end = rest.index(chr(10) + 'def ', 1)
    return rest[:end]


# --------------------------------------------------------------------------- #
# 1. The blocker: the deployment's own files are written as the console
# --------------------------------------------------------------------------- #


def test_deploy_never_writes_its_own_directory_through_the_root_seam():
    """⚠️ **The blocker, as a guard.** `_write_priv` writes as root and does
    not chown, so anything it creates under the install directory is
    `root:root` and the console cannot read it back. The install directory is
    the console's own (guide §8); `_write_priv` is for `/etc` and
    `/var/lib/caddy`."""
    body = _body('deploy')
    calls = re.findall(r"_write_priv'?\]?\(\s*([^,]+),", body)

    for target in calls:
        assert 'dirpath' not in target, (
            'deploy writes %s through the root seam; it is under the '
            "console's own directory, so it comes back root-owned and "
            'unreadable. Use _write_own.' % target.strip())


def test_the_deploy_writes_the_env_file_at_0600():
    """⚠️ The helper defaults to 0644, because most files want that.
    `.env` carries the database password and the proxy-auth secret, so the
    deploy has to ask for 0600 — and asking is a separate act from the
    helper honouring it, which is why both are pinned."""
    body = _body('deploy')
    start = body.index("_write_own(os.path.join(dirpath, '.env')")
    call = body[start:body.index('_write_own(', start + 10)]

    assert '0o600' in call, call[-200:]


def test_the_console_writes_its_own_files_readably(tmp_path):
    """The positive half, against the filesystem."""
    target = tmp_path / '.env'

    atlas._write_own(str(target), 'TAKMDM_X=1' + chr(10), 0o600)

    assert target.read_text(encoding='utf-8') == 'TAKMDM_X=1' + chr(10)


@pytest.mark.skipif(os.name == 'nt', reason='POSIX modes are not meaningful here')
def test_the_env_file_is_not_world_readable(tmp_path):
    """It carries the database password and the proxy-auth secret."""
    target = tmp_path / '.env'

    atlas._write_own(str(target), 'TAKMDM_DB_PASSWORD=hunter2' + chr(10), 0o600)

    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


def test_rewriting_an_existing_file_still_tightens_the_mode(tmp_path, monkeypatch):
    """⚠️ `O_CREAT` leaves an existing file's mode alone, so a re-deploy over
    a `.env` that was somehow 0644 would have kept it. The mode is asserted
    after the write as well as on the descriptor."""
    target = tmp_path / '.env'
    target.write_text('old', encoding='utf-8')
    seen = []
    monkeypatch.setattr(atlas.os, 'chmod',
                        lambda p, m: seen.append((str(p), m)))

    atlas._write_own(str(target), 'new', 0o600)

    assert seen == [(str(target), 0o600)]


def test_an_env_the_console_cannot_rewrite_is_replaced(tmp_path, monkeypatch):
    """⚠️ **Every deployment built before this fix has a root-owned
    `.env`, and the fix alone cannot rewrite one** -- the open raises
    `PermissionError`. Without a repair the change would turn a silent
    failure into a hard one: the next update of an existing deployment stops
    dead and the operator has a stranded install.

    The console owns the *directory*, and unlink needs write on the
    directory rather than on the file, so it can clear the old one and make
    a fresh one it owns. Measured on the box before it was written.
    """
    target = tmp_path / '.env'
    target.write_text('OLD=1', encoding='utf-8')
    real_open = atlas.os.open
    refused = []

    def once(path, flags, mode=0o777):
        if str(path) == str(target) and not refused:
            refused.append(1)
            raise PermissionError(13, 'Permission denied')
        return real_open(path, flags, mode)

    monkeypatch.setattr(atlas.os, 'open', once)

    atlas._write_own(str(target), 'NEW=2', 0o600)

    assert refused, 'the test did not exercise the refusal'
    assert target.read_text(encoding='utf-8') == 'NEW=2'


def test_a_write_that_fails_for_another_reason_is_not_swallowed(tmp_path,
                                                                monkeypatch):
    """⚠️ The repair is for one specific cause. A missing directory or a
    full disk must still surface."""
    monkeypatch.setattr(atlas.os, 'open',
                        lambda *a, **k: (_ for _ in ()).throw(
                            OSError(28, 'No space left on device')))

    with pytest.raises(OSError):
        atlas._write_own(str(tmp_path / '.env'), 'x', 0o600)


@pytest.mark.parametrize('reader', ['_arm_admin_gates', '_set_trusted_proxies',
                                    '_push_email_relay'])
def test_a_reader_that_cannot_open_the_env_does_not_answer_false(reader):
    """⚠️ **`return False` is the same answer these give for "nothing needed
    changing".** So a `PermissionError` on a root-owned `.env` was reported
    as a no-op, and the deploy carried on and printed a tick. Every caller
    reaches these *after* the deploy has written the file, so an unreadable
    `.env` is a fault, not a state to live with."""
    body = _body(reader)
    head = body[:body.index('body = f.read()')]

    assert 'except OSError' not in head, (
        '%s still swallows the read; a permission error there is '
        'indistinguishable from "nothing to do"' % reader)


def test_the_gates_raise_rather_than_report_nothing_to_do(tmp_path):
    """Driven, not matched: point it at a directory with no `.env` at all."""
    with pytest.raises(OSError):
        atlas._arm_admin_gates({}, str(tmp_path), lambda _m: None,
                               inst=None, global_group=None)


def test_the_refuse_branch_is_now_reachable():
    """⚠️ The whole point. W229 added a branch that stops the deploy when
    Caddy injects the proxy-auth header and the secret cannot be read — and
    the `OSError` return sat in front of it, so it never ran on a non-root
    box. Nothing may return before the read any more."""
    body = _body('_arm_admin_gates')
    before_read = body[:body.index('body = f.read()')]

    assert 'return' not in before_read, before_read[-200:]


# --------------------------------------------------------------------------- #
# 2. Destroying one deployment asks for the password
# --------------------------------------------------------------------------- #


def test_removing_one_deployment_asks_for_the_admin_password():
    """⚠️ It destroys that agency's device CA and its database. The
    whole-module uninstall and all three CA routes ask; `login_required`
    proves a session, not intent. Every tablet enrolled against that CA needs
    a factory reset in person."""
    start = SOURCE.index('    def instance_remove_view(')
    body = SOURCE[start:SOURCE.index(chr(10) + '    def ', start + 1)]

    assert '_check_admin_password(' in body


def test_the_password_is_checked_before_anything_is_destroyed():
    """A gate after the work is not a gate."""
    start = SOURCE.index('    def instance_remove_view(')
    body = SOURCE[start:SOURCE.index(chr(10) + '    def ', start + 1)]

    assert body.index('_check_admin_password(') < body.index('_run_removal')
    assert body.index('_check_admin_password(') < body.index('Thread(')
    # ⚠️ **The call must be the whole of the assignment.** A source guard
    # that only looks for the *name* is satisfied by
    # `_pw_err = None if True else _check_admin_password(...)`, which is a
    # real way to disable a gate while leaving every grep happy — a mutation
    # doing exactly that survived the first version of this test.
    assert re.search(r"_pw_err = _check_admin_password\(ctx, _data\)" + chr(10),
                     body), 'the gate is no longer a plain call'



# --------------------------------------------------------------------------- #
# 3. A root-era console must not follow a symlink into pki/
# --------------------------------------------------------------------------- #


def test_the_root_era_key_write_refuses_a_symlink():
    """⚠️ **`pki/` is the container's, and a root-era console writes there as
    uid 0.** A compromised container planting `pki/ca.key -> /etc/<target>`
    gets root to truncate and overwrite that file on the next renewal with a
    supplied key. `O_EXCL` does not close it — the symlink is the final
    component, and without `O_NOFOLLOW` the open resolves through it."""
    body = _body('_write_root_key')

    assert 'O_NOFOLLOW' in body
    assert 'os.fchown' in body, 'the handover must be on the fd, not the path'


def test_the_privileged_read_refuses_a_symlink_and_a_fifo():
    """⚠️ Same directory, the other direction: a planted
    `pki/issuing.crt -> /etc/shadow` would be read as root and concatenated
    into the device-CA bundle, which is staged 0644 where Caddy can read it.
    The `S_ISREG` check closes the same trick through a fifo, which would
    otherwise hang the deploy."""
    body = _body('_read_maybe_priv')

    assert 'O_NOFOLLOW' in body
    assert 'S_ISREG' in body


@pytest.mark.skipif(os.name == 'nt', reason='symlinks need privilege here')
def test_a_symlinked_certificate_is_not_read(tmp_path):
    """Driven, on a real symlink."""
    secret = tmp_path / 'secret'
    secret.write_text('ROOT-ONLY', encoding='utf-8')
    planted = tmp_path / 'issuing.crt'
    planted.symlink_to(secret)

    assert atlas._read_maybe_priv(str(planted), None) is None


def test_a_real_certificate_is_still_read(tmp_path):
    """⚠️ The guard has to let the honest case through, or the trust bundle
    silently loses the intermediate it was added to carry."""
    real = tmp_path / 'issuing.crt'
    real.write_text('CERT-BODY', encoding='utf-8')

    assert atlas._read_maybe_priv(str(real), None) == 'CERT-BODY'


def test_the_nofollow_flag_is_named_once_and_degrades_visibly():
    """⚠️ Windows has no `O_NOFOLLOW`, and the test runner is Windows. The
    fallback to 0 removes a protection, so it is a named constant with a
    comment rather than an inline `getattr` a reader would skim past."""
    assert hasattr(atlas, 'O_NOFOLLOW')
    assert 'getattr(os, ' + chr(39) + 'O_NOFOLLOW' + chr(39) in SOURCE

# ------------------------------------------------------------------------- #
# The update path repairs what W240 would otherwise have stranded (W243)
# ------------------------------------------------------------------------- #


def test_an_unreadable_env_is_repaired_through_the_broker(tmp_path,
                                                          monkeypatch):
    """⚠️ **W240 turned a silent failure into a stranded deployment.**
    Every deployment built before it has a root-owned `.env`, the three
    readers now raise rather than swallow, and `_run_update` calls all
    three -- so an update of exactly the population that has the bug
    would stop dead, with a full re-deploy the only way out.

    `deploy` repairs it as a side effect because `_write_own` rewrites
    the file wholesale; an update never does, so the repair is explicit.
    """
    env = tmp_path / '.env'
    env.write_text('TAKMDM_DB_PASSWORD=keepme' + chr(10), encoding='utf-8')
    monkeypatch.setattr(atlas.os, 'access', lambda p, m: False)
    ctx = {'_read_priv': lambda p: io.open(p, encoding='utf-8').read()}
    said = []

    repaired = atlas._repair_env_ownership(str(env), ctx, said.append)

    assert repaired is True
    # ⚠️ Byte-for-byte. It carries the database password, and
    # regenerating it from the template would need every value deploy
    # had -- getting one wrong silently is worse than the bug.
    assert env.read_text(encoding='utf-8') == \
        'TAKMDM_DB_PASSWORD=keepme' + chr(10)
    assert said and '.env' in said[0]


def test_a_readable_env_is_left_alone(tmp_path):
    """⚠️ The repair unlinks and recreates. Running it on a healthy file
    would be a pointless window in which the deployment has no `.env`.

    ⚠️ The broker IS supplied here. Without it the test passes on the
    no-reader early return and says nothing about `os.access` -- which is
    how a mutant that repaired every file survived the first version.
    """
    env = tmp_path / '.env'
    env.write_text('FINE=1', encoding='utf-8')
    asked = []
    ctx = {'_read_priv': lambda p: asked.append(p) or 'REWRITTEN'}

    assert atlas._repair_env_ownership(str(env), ctx) is False

    assert env.read_text(encoding='utf-8') == 'FINE=1'
    assert asked == [], 'a readable file was read through the broker'


@pytest.mark.parametrize('ctx_kind', ['no broker', 'broker answers nothing'])
def test_an_env_that_cannot_be_recovered_is_left_for_the_reader(tmp_path,
                                                                monkeypatch,
                                                                ctx_kind):
    """⚠️ Not repairable, and not ours to guess at. Letting the reader that
    follows raise says plainly which file and why; **inventing a replacement
    would put a deployment on a database password it has never used**, and
    Postgres only honours POSTGRES_PASSWORD on an empty volume -- so that
    deployment could never authenticate again.
    """
    env = tmp_path / '.env'
    env.write_text('SECRET=1', encoding='utf-8')
    monkeypatch.setattr(atlas.os, 'access', lambda p, m: False)
    ctx = {} if ctx_kind == 'no broker' else {'_read_priv': lambda p: ''}

    assert atlas._repair_env_ownership(str(env), ctx) is False

    assert env.read_text(encoding='utf-8') == 'SECRET=1'


def test_the_repaired_env_keeps_0600(tmp_path, monkeypatch):
    """{W} It carries the database password and the proxy-auth secret. The
    helper it calls defaults to 0644, so the mode has to be asked for -- and
    asking is a separate act from the helper honouring it."""
    env = tmp_path / '.env'
    env.write_text('TAKMDM_DB_PASSWORD=x', encoding='utf-8')
    monkeypatch.setattr(atlas.os, 'access', lambda p, m: False)
    wrote = []
    monkeypatch.setattr(atlas, '_write_own',
                        lambda p, b, perm=0o644: wrote.append(perm))

    atlas._repair_env_ownership(
        str(env), {'_read_priv': lambda p: 'TAKMDM_DB_PASSWORD=x'})

    assert wrote == [0o600], wrote


def test_the_update_repairs_before_it_reads():
    """A repair after the read is no repair: the read raises first."""
    body = _body('_run_update')

    assert '_repair_env_ownership(' in body
    for reader in ('_set_trusted_proxies', '_arm_admin_gates',
                   '_push_email_relay'):
        assert body.index('_repair_env_ownership(') < body.index(reader), \
            reader
