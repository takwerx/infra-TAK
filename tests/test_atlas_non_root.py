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
"""The module never reaches for privilege it does not have (W230).

⚠️ **The guard whose absence let the whole class ship.** Upstream's review
found six separate root assumptions in one module, and every one of them was
invisible here: the tests stub `ctx`, and the box this was written on ran the
console as root. A test that stubs the privileged call can never notice that
the call is not available.

So this one reads the source instead. It is a static guard, and that is
deliberate: the dynamic question — "does a deploy succeed on a non-root box?"
— needs a non-root box, and the honest answer is that it belongs in the audit
log of a real deploy. This catches the regression before it gets that far.

⚠️ **Measured against the box, not against the guide.** The allowlist below is
what `/opt/infratak/.shims` actually contains on a converted install, read off
the filesystem on 2026-09-18. `losetup`, `umount`, `mount`, `resize2fs`,
`e2fsck`, `truncate`, `systemd-escape` and `mkfs.ext4` are **not** there.
"""

import ast
import io
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MODULE_PATH = ROOT / 'modules' / 'atlas.py'
SOURCE = io.open(MODULE_PATH, encoding='utf-8').read()
TREE = ast.parse(SOURCE)

#: Source with comments and docstrings removed. ⚠️ Every guard
#: below matches against this, never against the prose: this file's own
#: history is written in those comments, and matching them would make
#: the guards unfailable by editing a sentence.
STRIPPED = re.sub(r'"""[\s\S]*?"""', '',
                  re.sub(r'#[^\n]*', '', SOURCE))


#: Binaries the console can actually run, from `/opt/infratak/.shims` on the
#: converted box. ⚠️ Adding a name here is a claim about that directory, not a
#: preference — check it before you do.
SHIMMED = {
    'apt', 'apt-get', 'chcon', 'chmod', 'chown', 'cp',
    'debconf-set-selections', 'dnf', 'docker', 'dpkg', 'fail2ban-client',
    'fallocate', 'firewall-cmd', 'gpg', 'install', 'journalctl', 'ln',
    'loginctl', 'mkdir', 'mkswap', 'mv', 'newaliases', 'pg_createcluster',
    'postconf', 'postmap', 'restorecon', 'rm', 'rmdir', 'runuser', 'semanage',
    'semodule', 'swapoff', 'swapon', 'sysctl', 'systemctl', 'systemd-run',
    'tee', 'touch', 'ufw', 'yum',
}

#: Read-only probes the console runs as itself. They need no privilege at all,
#: so they are neither shimmed nor a problem.
UNPRIVILEGED = {'ss', 'git', 'python3', 'id', 'getent', 'uname', 'df'}

#: The binaries this work removed, named so a regression says which.
RETIRED = {
    'losetup': 'the loop store is gone; use a directory',
    'umount': 'nothing is mounted any more',
    'mount': 'nothing is mounted any more',
    'mkfs.ext4': 'the loop store is gone',
    'resize2fs': 'the loop store is gone',
    'e2fsck': 'the loop store is gone',
    'truncate': 'the loop store is gone',
    'systemd-escape': 'no .mount units are written any more',
}


def _run_root_binaries():
    """The first argv element of every literal `_run_root([...])` call."""
    found = []
    for node in ast.walk(TREE):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, 'id', None)
        if name != '_run_root' or not node.args:
            continue
        argv = node.args[0]
        if isinstance(argv, ast.List) and argv.elts:
            first = argv.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.append((first.value, node.lineno))
    return found


def test_the_extractor_finds_something():
    """⚠️ A guard that matches nothing passes forever. This one has been wrong
    that way before — a regex with a `\\b` that silently matched no lines and
    reported the page no longer called compose."""
    found = _run_root_binaries()

    assert len(found) >= 3, found


@pytest.mark.parametrize('binary,line', _run_root_binaries())
def test_every_binary_the_module_runs_is_available_to_the_console(binary, line):
    """⚠️ Not "exists on the box" — *runnable by the console*. `losetup` is
    installed on every Linux system and the console cannot execute it, which
    is exactly how six root assumptions survived a 590-test suite."""
    if binary in RETIRED:
        pytest.fail('%s:%d runs `%s`, which was retired: %s'
                    % (MODULE_PATH.name, line, binary, RETIRED[binary]))
    assert binary in SHIMMED or binary in UNPRIVILEGED, (
        '%s:%d runs `%s`, which is neither shimmed for the console nor an '
        'unprivileged probe. Either it needs adding to the broker (say so in '
        'the PR body) or the code needs another way.'
        % (MODULE_PATH.name, line, binary))


def test_no_retired_binary_is_named_anywhere_in_the_module():
    """Including in a string built at run time, which the AST walk above would
    miss. ⚠️ Comments are stripped first: this file's own history is written in
    them, and matching prose would make the guard unfailable-by-editing."""
    code = re.sub(r'#[^\n]*', '', SOURCE)
    code = re.sub(r'"""[\s\S]*?"""', '', code)

    for binary in sorted(RETIRED):
        # ⚠️ Word boundaries. Plain `in` matched `mount` inside the key
        # `'mounted'` and failed on honest code -- and a guard that cries wolf
        # is a guard somebody deletes.
        hit = re.search(r'[^A-Za-z0-9_.]' + re.escape(binary) + r'[^A-Za-z0-9_.]',
                        code)
        assert hit is None, (
            '`%s` still appears in executable code at offset %d: %s'
            % (binary, hit.start(), RETIRED[binary]))


def test_only_the_one_helper_chowns_and_it_asks_the_broker():
    """⚠️ **`os.chown` is EPERM for a non-root console**, and the recursive
    one in `deploy` was unguarded, so every deploy stopped there.

    ⚠️ It is legitimate in exactly one place: `_chown_priv` tries it first
    for a **root-era** console, where there is no broker and the direct call
    is correct, then falls back to asking the broker. Anywhere else is the
    bug this guard exists for.

    ⚠️ And the broker must be asked *directly*, not through the PATH shim:
    `/opt/infratak/.shims/chown` only routes `/etc /opt /usr /var /run /boot
    /swapfile`, so a path in the console's own home falls through to the real
    binary. Two deploys failed on that before it was measured.
    """
    code = STRIPPED

    helper = code[code.index('def _chown_priv('):]
    helper = helper[:helper.index(chr(10) + 'def ')]

    assert 'os.chown' in helper, 'the root-era path went missing'
    assert code.count('os.chown') == helper.count('os.chown'), (
        'os.chown is called outside _chown_priv')
    assert '_broker_script' in code, (
        'the non-root path must reach the broker, not the PATH shim')


def test_only_the_one_helper_deletes_and_it_asks_the_broker():
    """⚠️ **Deleting has the same problem as chowning, and it was found the
    same way: on the box, by the operator.**

    A deployment's trees are owned by its containers -- `pgdata` by uid 70,
    `artifacts`, `cache` and `pki` by the application's uid -- so the console
    can descend into them and cannot unlink their contents. Every teardown
    path therefore has to go through `_rm_priv`, which falls back to the
    broker. Two of them did not:

      rm: cannot remove '.../store/pgdata': Permission denied
      [Errno 13] Permission denied: 'pki'

    ⚠️ `shutil.rmtree` is legitimate **inside** `_rm_priv`, as the first
    attempt: it is correct for a root-era console and for anything the
    console genuinely owns. Anywhere else is this bug.
    """
    code = STRIPPED

    helper = code[code.index('def _rm_priv('):]
    helper = helper[:helper.index(chr(10) + 'def ')]

    assert 'shutil.rmtree' in helper, 'the direct attempt went missing'
    assert code.count('shutil.rmtree') == helper.count('shutil.rmtree'), (
        'shutil.rmtree is called outside _rm_priv; a tree a container owns '
        'cannot be removed by the console')


def test_the_privileged_removal_refuses_a_path_outside_its_directory():
    """⚠️ It ends in `rm -rf` as root. The paths come from `instance_paths`
    and slugs are `^[a-z]{1,32}$`, so this should be unreachable -- which is
    when a guard is worth having."""
    import modules.atlas as atlas

    assert atlas._rm_priv('/etc/passwd', '/home/takwerx/atlas') is not None
    assert atlas._rm_priv('/home/takwerx/atlas-corona',
                          '/home/takwerx/atlas') is not None, (
        'a sibling sharing a prefix must not count as inside')


def test_every_deployment_directory_is_inside_the_one_allowlisted_root():
    """⚠️ **The property the broker entry rests on (W233).**

    `MODULE_DIR_NAMES` grants one directory per add-on: `<home>/atlas/`, and
    the broker resolves the *real* path of every target against it. A
    deployment placed beside that directory rather than inside it is refused
    every write, chown and delete -- which is precisely what happened while
    they were siblings, 61 times on a single deploy, silently, because the
    broker is still PERMISSIVE and executed each one anyway.

    So the containment is asserted here rather than left to the shape of a
    `posixpath.join` somewhere. ⚠️ `startswith(root + '/')`, not
    `startswith(root)`: `<home>/atlas-corona` passes the second and is exactly
    the bug.
    """
    import modules.atlas as atlas
    from modules import atlas_instances as ai

    root = atlas.atlas_root(None)

    for inst in (None,
                 ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
                 ai.make('a', ai.MODE_FIXED, 1, 8762)):
        got = atlas.instance_paths(None, inst)
        for field in ('dir', 'store', 'artifacts', 'cache'):
            assert got[field].startswith(root + '/'), (
                '%s is %r, which is outside the directory the broker allows '
                '(%r). Every privileged operation on it will be denied.'
                % (field, got[field], root))


def test_nothing_stats_a_path_inside_the_pki_directory():
    """⚠️ **The console cannot look inside `pki/`, and False is the answer
    it gets when it tries (W235).**

    That directory is `drwx------` owned by the container's uid. Every
    `os.path.exists()` under it returns False for the console whatever is
    actually on disk, and three call sites believed it. The worst reported
    that no deployment was holding its CA root key — measured on the box
    2026-09-19 with three root keys present, `root_key_holders` returned
    `{'holders': [], 'unknown': []}`. That is the console asserting the safe
    state while the dangerous one is true, and `root_key_on_server` exists
    (SEC_AUDIT S-2) precisely to stop an operator believing it.

    ⚠️ A stat of the directory *itself* is fine and is not matched here:
    `_pki_dir` does exactly that, and it works, because the parent is the
    console's own. It is going *inside* that cannot be done.

    The answer is to ask the container, which owns the files — `_ca_status`,
    over `ca-status`, which already reports `root_key_on_server`.
    """
    code = STRIPPED

    bad = re.findall(
        r'os\.path\.(?:exists|isfile|getsize|getmtime)\([^)]*(?:pki|ca\.key|ca\.crt|issuing|retired)[^)]*\)', code)

    assert bad == [], (
        'these ask the filesystem about a path the console cannot read; the '
        'answer is always False. Ask the container instead: %s' % bad)


#: Helpers that are handed a path *inside* a deployment's `pki/`. ⚠️ They
#: take it as a plain parameter, so the guard above -- which looks for `pki`,
#: `ca.key` and friends in the expression being stat'd -- has nothing to
#: match on and sailed straight past them. `_shred` was the fifth instance
#: of this bug and the first that the guard was supposed to have caught.
#:
#: Adding a name here is a claim that the function receives a pki path.
PKI_PATH_HELPERS = ('_shred', '_write_root_key')


@pytest.mark.parametrize('helper', PKI_PATH_HELPERS)
def test_a_pki_helper_never_decides_anything_by_statting(helper):
    """⚠️ **A stat inside `pki/` is always False for the console**, and each
    of these is one `not` away from turning that into a confident lie.
    `_shred` did exactly that: `return not os.path.exists(path)` reported
    "Root key removed from the server" over a key still on disk.

    ⚠️ The **root-era** branch may stat, and must: that console owns the
    file, there is no broker, and the direct path is the correct one. So
    this checks the brokered branch only -- everything after the
    `if broker is None:` block.
    """
    code = STRIPPED
    body = code[code.index('def %s(' % helper):]
    body = body[:body.index(chr(10) + 'def ')]

    marker = 'if broker is None:'
    if marker in body:
        # Everything the non-root console actually runs.
        head, _, tail = body.partition(marker)
        rest = tail[tail.index(chr(10) + '        return'):] \
            if chr(10) + '        return' in tail else tail
        body = head + rest

    for probe in ('os.path.exists', 'os.path.isfile', 'os.path.getsize'):
        assert probe not in body, (
            '%s asks the filesystem about a path it cannot read; the answer '
            'is always False and a `not` turns that into a lie. Ask the '
            'container (`_ca_status`) or let `rm -f` be idempotent.'
            % helper)


def test_the_shred_confirms_with_the_container():
    """The positive half: a guard that only forbids is satisfied by deleting
    the check."""
    code = STRIPPED
    body = code[code.index('def _shred('):]
    body = body[:body.index(chr(10) + 'def ')]

    assert '_ca_status(' in body
    assert 'root_key_on_server' in body


def test_the_root_key_question_is_asked_of_the_container():
    """The positive half — a guard that only forbids can be satisfied by
    deleting the check altogether."""
    code = STRIPPED

    holders = code[code.index('def root_key_holders('):]
    holders = holders[:holders.index(chr(10) + 'def ')]

    assert '_ca_status(' in holders, (
        'root_key_holders must ask the deployment, not the filesystem')
    assert 'root_key_on_server' in holders


def test_nothing_writes_to_a_privileged_path_directly():
    """⚠️ `/etc/systemd/system` and `/var/lib/<anything>` are not the
    console's. The module wrote unit files there with a plain `open()`; the
    Caddy trust pool now goes through `ctx['_write_priv']`, which is the seam
    the console exposes for exactly this.
    """
    code = re.sub(r'#[^\n]*', '', SOURCE)
    code = re.sub(r'"""[\s\S]*?"""', '', code)

    # ⚠️ **Writes only.** Reading `/etc/caddy/Caddyfile` is how
    # `_caddyfile_injects_proxy_auth` checks that the vhost really injects the
    # header, and the console can read it perfectly well. Flagging that too
    # made this fail on code that is right, which is how a guard gets relaxed
    # into uselessness.
    for match in re.finditer(
            r"open\(\s*'(?:/etc/|/var/lib/)[^']*'\s*,\s*'[wa]", code):
        pytest.fail('a privileged path is opened for writing at offset %d; '
                    "use ctx['_write_priv']" % match.start())


def test_the_install_directory_is_not_hardcoded_to_root():
    """⚠️ Guide §8: a non-root console keeps its modules under its own home.
    `/root` survives only as the *probe* for a box that has not been
    converted, never as the answer."""
    code = re.sub(r'#[^\n]*', '', SOURCE)
    code = re.sub(r'"""[\s\S]*?"""', '', code)

    literals = set(re.findall(r"'(/root[^']*)'", code))

    # ⚠️ Two legitimate mentions, both **reads** of a box that has not been
    # converted: the layout probe in `install_base`, and the legacy candidate
    # list that finds a device CA in a checkout predating `install_base`.
    # Anything else is an install path being hardcoded, which is the bug.
    assert literals <= {'/root', '/root/atlas'}, literals


def test_the_store_is_a_directory_not_an_image():
    """The shape of the fix, asserted so a revert is loud."""
    import modules.atlas as atlas
    from modules import atlas_instances as ai

    paths = atlas.instance_paths(None, ai.make('x', ai.MODE_FIXED, 1, 8761))

    assert 'image' not in paths
    assert paths['store'].endswith('/store')
    assert paths['store'].startswith(paths['dir'])
