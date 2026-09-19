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
# infra-TAK module — ATLAS MDM
"""ATLAS: Android device management for ATAK tablets.

A Device Owner MDM. The console is an ordinary admin web UI; the interesting
half is the **device channel**, where enrolled tablets authenticate with client
certificates issued by ATLAS's own CA and receive a desired state to converge
on.

Three things about that shape the whole module:

* **The device channel is mutual TLS and it is not optional.** Caddy terminates
  it on its own port, verifies the client certificate against the device CA this
  deployment generated, and forwards it. Devices cannot do an interactive login,
  so Authentik is not in that path — the same split EUD Remote Assist uses.
* **The console is admin tooling**, so it sits behind Authentik on
  `atlas.<fqdn>` like every other admin surface, and is never published directly.
* **The agent package is fetched by a tablet in out-of-box setup**, before it
  has been told anything. It reaches Caddy on the well-known port, and its
  integrity comes from a signature checksum carried in the provisioning QR.

⚠️ **ATLAS never speaks ACME.** Caddy is the single ACME client on the box and
holds the certificate for `atlas.<fqdn>`; two clients contending for :80 does not
resolve in a config file, it means one of them quietly stops renewing.
"""
import json
import os
import stat
from glob import glob as _glob
# ⚠️ These are paths on the *managed box*, which is always Linux. Building
# them with `os.path.join` uses the separator of whichever machine this code
# runs on, which is invisible only because production happens to match.
import posixpath
import re
import secrets
import shutil
import subprocess
# ⚠️ Module level. `ensure_authentik_app` sleeps between attempts while it
# waits for Authentik's authorization flow; in app.py that name came from a
# module-level import, and moving the function here left it unbound. It only
# fires when the flow is not ready on the first try — a fresh box — so it
# would have waited for the worst possible moment to surface.
import time

from . import register_module, job_log, job_state, get_ctx
# ⚠️ The sizing modes live in the instance model, not here. Two copies of
# 'fixed'/'dynamic' would drift, and the one that drifted would be the one
# deciding whether an image reserves its blocks.
from . import atlas_instances
from .atlas_instances import MODE_DYNAMIC, MODE_FIXED

KEY = 'atlas'

# Source, pinned. Rule 8: a tag *and* the commit it resolved to, verified after
# fetch — a moving branch is not a pin, and a tag can be moved by whoever owns
# the repo.
# The repository is public, so there is no credential in this file and none
# needed on the box.
ATLAS_REPO_HTTPS = 'https://github.com/cfd2474/TAK-MDM.git'
# Where the update check asks what the newest release is. Unauthenticated,
# which the public repository allows and which keeps any credential out of a
# world-readable module file.
ATLAS_REPO_API = 'https://api.github.com/repos/cfd2474/TAK-MDM'

# ── Release channels (W228) ──────────────────────────────────────────────────
#
# The mirror carries two branches. A release is published to `dev`; the
# operator promotes it to `main` once tested. A box follows one of them.
#
# ⚠️ **A channel is `VERSION` at that branch tip, not "tags on that branch".**
# Every commit on the mirror is a *root* commit — one orphan per release, no
# ancestry at all — so nothing is reachable from `main` except `main` itself
# and tag reachability would resolve to nothing on either channel.
#
# ⚠️ **Only the resolution is per-channel; the fetch is not.** An update
# still fetches and checks out `v<version>`, and a tag exists whichever branch
# points at it. So the machinery every release so far has exercised is
# untouched: the channel decides which number, and nothing else.
CHANNELS = ('main', 'dev')
DEFAULT_CHANNEL = 'main'
#: Where the box's choice is kept. In `BOX_SETTINGS_KEYS`, so removing one
#: deployment cannot take the whole box's channel with it.
CHANNEL_KEY = 'atlas_channel'

#: What each channel is for, in the operator's words, on the card.
CHANNEL_BLURB = {
    'main': 'Tested releases. What a deployment should normally run.',
    'dev': 'The newest release, before it has been promoted. Expect to find '
           'the problems here.',
}
#: ⚠️ **The pin follows the `main` channel, not the newest release.** It
#: governs *fresh installs*, and a fresh install must not land on something
#: that has not been promoted: `main` is "tested releases", so pinning a
#: dev-only tag here would quietly make every new box a dev box. Updates
#: resolve the newest tag on the box's own channel themselves and are not
#: affected by this value.
#:
#: So this moves when a release is **promoted**, not when it is published.
#: v1.51.0 was published to `dev` and promoted to `main` on 2026-09-19.
ATLAS_TAG = 'v1.51.0'
# ⚠️ The **commit**, not the tag object. `v0.1.0` is an annotated tag, so
# `git rev-parse v0.1.0` returns the tag object's own SHA while a clone's HEAD
# is the commit it points at — two different hashes, and comparing them made
# every deploy refuse itself. `git rev-parse 'v0.1.0^{}'` is the one to record.
#
# ⚠️ **And it is the commit in the repository above, which is now a mirror.**
# As of v1.47.2 `cfd2474/TAK-MDM` is published from a private development
# repository — one orphan commit per release — so every release has *two*
# commits: the private one the work was done in, and the public one that
# `_verify_pin` will actually see in the clone. Recording the private SHA, which
# is exactly what the previous value here was, pins a hash the clone can never
# produce, and the deploy then refuses itself with "refusing to install a tag
# that has moved" — a message pointing at tampering rather than at bookkeeping.
# Take it from the mirror, never from the working copy you are standing in:
#
#     git ls-remote https://github.com/cfd2474/TAK-MDM.git refs/tags/v1.47.3
ATLAS_SHA = 'd2419ee63c37c48c85687b457127815312e51ff5'

# The device channel. One public port, justified: enrolled tablets cannot reach
# the console's vhost (Authentik would bounce a device that cannot log in), and
# mutual TLS needs a listener of its own.
DEVICE_PORT = 8449

# The application, on loopback. Caddy is the only thing that talks to it.
APP_PORT = 8760

# ⚠️ The container the API runs as. ATLAS's compose file pins its project name
# to `takmdm`, so the containers are `takmdm-*` no matter what directory the
# module installs into — `--project-directory` does not override an explicit
# `name:`. Guessing `atlas-api-1` from the module key made detect() report the
# module as never running, forever.
API_CONTAINER = 'takmdm-api-1'

# ⚠️ The uid the application runs as inside its image, and the host directories
# it must be able to write.
#
# ATLAS's Dockerfile drops to an unprivileged `takmdm` user pinned at uid 1000.
# These three paths are bind-mounted from the install directory, which the
# console creates as root — and Docker creates any that are still missing as
# root too. Either way the container cannot write them, and the first thing it
# tries is to generate the device CA:
#
#     PermissionError: [Errno 13] Permission denied: '/pki/ca.crt'
#
# The one-shot `init` service then exits 1, `api` never starts, and the deploy
# fails at the build step with nothing in the compose output naming a
# permission problem. So: create them, and hand them to uid 1000 first.
#: Spelled out, because an escaped backslash inside a replace() chain is
#: exactly the kind of literal that gets mis-edited later.
BACKSLASH = chr(92)

#: `O_NOFOLLOW`, or 0 where the platform has no such flag.
#:
#: ⚠️ **A box is always Linux; the test runner is not.** Windows has no
#: `O_NOFOLLOW` and no `fchown`, and referring to them directly made the
#: suite fail on the machine this is developed on rather than on any box.
#: Degrading to 0 is correct *here* and nowhere else: it removes a
#: protection, so it is named once, with this comment, instead of being an
#: inline `getattr` a reader would skim past.
O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)


def _running_as_root():
    """Is this console uid 0?

    ⚠️ **The question is the euid, not whether `ctx` carries a seam
    (W242).** `_write_root_key` used to branch on `_write_priv` being
    absent, and the console exports `_write_priv` in `_MODULE_CTX`
    *always* -- on root consoles too. So the hardened branch was
    unreachable in production and a root console still went through the
    seam's root path, which is a plain `open()` plus `chmod` followed by
    `os.chown(path, ...)`: both follow a planted symlink, which is the
    whole thing the hardening was for.

    ⚠️ Windows has no `geteuid`, and the test runner is Windows. Absent
    means "not root", which routes to the brokered path -- the safe answer
    for a platform that is never a box.
    """
    geteuid = getattr(os, 'geteuid', None)
    return geteuid is not None and geteuid() == 0

APP_UID = 1000
APP_GID = 1000

# Writable bind mounts, from ATLAS's docker-compose.yml. `pki` holds the device
# CA, `artifacts` the agent APK and generated packages, `cache` the APK
# inspector's scratch space. The read-only mounts (nginx config, acme) belong
# to ATLAS's own proxy service, which this module never starts — Caddy fronts
# the deployment instead.
WRITABLE_DIRS = ('pki', 'artifacts', 'cache')


#: What we fall back to when the Docker network does not exist yet.
#:
#: ⚠️ On a **fresh install** it always does not exist: `.env` is written before
#: `docker compose up` creates the network, so detection cannot work at that
#: point. This value keeps the install safe — it still refuses a request arriving
#: from a public address — and `_set_trusted_proxies` narrows it to the real subnet
#: once the network is there.
_TRUSTED_FALLBACK = '172.16.0.0/12,10.0.0.0/8,192.168.0.0/16,127.0.0.0/8'


# --------------------------------------------------------------------------- #
# The ATLAS store: a reserved, capped filesystem for everything ATLAS keeps
# (W205)
# --------------------------------------------------------------------------- #
#
# ⚠️ **Two requirements, and only one of them is a quota.** A storage limit
# is a cap; "designate that space as belonging to atlas so other systems don't
# take the space" is a *reservation*. A filesystem quota does the first and
# nothing for the second — it stops ATLAS exceeding N and does nothing to stop
# another module filling the disk first, after which ATLAS is under its quota
# and still out of space.
#
# So: a loopback-backed ext4 image. `fallocate` claims the blocks immediately,
# which is the reservation; the filesystem inside cannot grow past the image,
# which is the cap. One mechanism, both halves, on any filesystem, with no
# `tune2fs -O quota` and no remount of a live root.

#: The image itself. Outside the ATLAS directory on purpose: that directory is
#: a git checkout the updater rewrites, and a 40G file inside it would be one
#: `git clean` away from deletion.
#: ⚠️ Retired with the loop store (W230). Kept as a name only so that a
#: stale reference fails loudly at import rather than silently reading a
#: path nothing writes any more.
STORE_IMAGE = None

#: Where it is mounted. Inside the ATLAS directory, because the compose file's
#: bind mounts are relative to it.
STORE_DIRNAME = 'store'

#: The file ATLAS publishes its complete device-CA trust set to, inside its
#: `pki/` directory (ATLAS W234).
#:
#: ⚠️ **This name is a contract with the other repository**, and the
#: contract exists because of something this console cannot do. Caddy has to
#: verify device certificates against the root *plus every intermediate that
#: has ever signed* -- a device issued by one that has since retired chains
#: through it. That set is only knowable by listing `pki/retired/`, and `pki/`
#: is `drwx------` owned by the application's uid: the glob that used to be
#: here ran as the console, returned nothing, and said nothing. `_read_priv`
#: reads a *named* file and there is no brokered `listdir`, so ATLAS answers
#: the question instead and this reads the answer.
#:
#: If ATLAS ever renames it, this changes in the same release and ATLAS keeps
#: writing the old name until the oldest supported release writes the new one.
BUNDLE_CERT = 'device-ca-bundle.crt'

#: ⚠️ **The operator cannot reserve everything.** 85% of what is free, so a
#: box cannot be configured into having no room for its own logs, its package
#: cache, or the other modules sharing the disk.
STORE_MAX_FRACTION = 0.85

#: Below this there is no point: ATLAS ships ~570M of seed applications and
#: indexes before an operator uploads anything.
STORE_MIN_BYTES = 2 * 1024 ** 3

GIB = float(1024 ** 3)


def _disk_free(path):
    """(total, free) bytes for the filesystem holding `path`, or (0, 0).

    ⚠️ Walks up to the nearest existing directory. `statvfs` on a path that
    does not exist yet raises, and the store image's parent is created by the
    deploy that needs this number — so asking about `/var/lib/atlas` before it
    exists is the normal case, not an error.
    """
    probe = path
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    if not probe:
        # An equivalent mutant lives here, and it is kept deliberately: removing
        # this guard changes nothing observable, because `shutil.disk_usage('')`
        # raises and the handler below returns the same (0, 0). Explicit beats
        # relying on an exception to mean "nothing found", so it stays - but no
        # test can tell the two apart, and pretending otherwise would be worse
        # than saying so.
        #
        # ⚠️ The walk ran out of path without finding anything. Answering about
        # `/` instead would report a filesystem nobody asked about, and the
        # caller would size a reservation against the wrong disk. The real case
        # — `/var/lib/atlas` not existing yet — always finds `/var/lib`.
        return 0, 0
    try:
        usage = shutil.disk_usage(probe)
    except (OSError, ValueError):
        return 0, 0
    # ⚠️ `shutil.disk_usage` rather than `os.statvfs`, for two reasons and the
    # second is the one that matters. It reports `f_bavail` on POSIX — the blocks
    # a *non-root* process may use, not `f_bfree`, which includes the
    # filesystem's root reserve and must never be promised away. And it exists
    # on every platform, so this arithmetic can be tested off the box instead of
    # discovered on one: `os.statvfs` is POSIX-only and every test touching it
    # failed on the development machine with an `AttributeError`.
    return usage.total, usage.free


def store_ceiling_bytes(free_bytes, already_reserved=0):
    """The largest image this box may be asked for.

    `already_reserved` is the size of an image that exists now. Without it, a
    box that has already reserved 40G reports a ceiling computed from the free
    space *left after* that reservation — so an operator could never keep, let
    alone raise, the size they already have.
    """
    return int((max(0, free_bytes) + max(0, already_reserved)) * STORE_MAX_FRACTION)


def validate_store_size(requested_gb, free_bytes, in_use_bytes=0, already_reserved=0):
    """(bytes, error). `error` is a sentence for the operator, or None.

    ⚠️ Refuses rather than clamps. Silently handing back a different number
    than the one typed is how an operator ends up believing they reserved 200G
    on a box that gave them 40.
    """
    try:
        gb = float(requested_gb)
    except (TypeError, ValueError):
        return 0, 'Store size must be a number of gigabytes.'
    if gb != gb or gb in (float('inf'), float('-inf')):
        return 0, 'Store size must be a number of gigabytes.'

    requested = int(gb * GIB)
    if requested < STORE_MIN_BYTES:
        return 0, (f'Store size must be at least {STORE_MIN_BYTES / GIB:.0f} GB — '
                   f'ATLAS ships about 570 MB of applications and indexes before '
                   f'anything is uploaded.')

    # ⚠️ **Checked before anything else, including the short-circuit below.**
    # Shrinking under what is already stored would mean deleting data to fit a
    # number, which no setting should do quietly. The first version of this ran
    # *after* the "keeping what you have" rule, so shrinking to 20 GB with 30 GB
    # stored was allowed — the short-circuit skipped straight past it. Order is
    # the whole fix.
    if in_use_bytes and requested < in_use_bytes:
        return 0, (f'ATLAS is already storing {in_use_bytes / GIB:.1f} GB. Reserve at '
                   f'least that, or remove content first — this will not delete '
                   f'anything to fit a smaller number.')

    reserved = max(0, already_reserved)

    # ⚠️ **Shrinking the image is not supported, so asking for less is
    # refused rather than quietly ignored.** The store is a filesystem inside a
    # file; growing it is `fallocate` plus `resize2fs` online, and shrinking it
    # safely needs the stack down and `resize2fs` on an unmounted image. Until
    # that exists, a request below the current size would have been accepted and
    # then not acted on — the operator asks for 20 GB, keeps 40, and nothing
    # says so. That is the "handed back a different number" failure this module
    # refuses to commit.
    if reserved and requested < reserved:
        return 0, (f'The store is {reserved / GIB:.1f} GB and shrinking it is not '
                   f'supported yet. Ask for {reserved / GIB:.1f} GB or more.')

    # ⚠️ **Keeping exactly what is already reserved is always allowed**, and a
    # test found this the hard way. The 85% rule governs *new* claims on the
    # disk; space already reserved takes nothing further from the box. Without
    # this, a reservation made when the disk was emptier becomes impossible to
    # keep once other modules have grown — 85% of (free + reserved) falls below
    # reserved, and every re-deploy is refused with nothing the operator can do
    # about it.
    if requested == reserved:
        return requested, None

    ceiling = store_ceiling_bytes(free_bytes, already_reserved)
    if requested > ceiling:
        return 0, (f'This box can offer at most {ceiling / GIB:.1f} GB — 85% of the '
                   f'{(free_bytes + already_reserved) / GIB:.1f} GB available. '
                   f'The rest stays free for the operating system and the other '
                   f'modules on this disk.')

    return requested, None


#: How much of the image's apparent size must really be backed by blocks before
#: the reservation counts as honoured. Measured on the box: a 2 GB image built
#: correctly reports 2049 MiB of blocks against 2048 MiB apparent — slightly
#: *over*, because of ext4's own structures — while a sparse one reported 66 MiB.
#: The two cases are three orders of magnitude apart, so this only has to avoid
#: tripping over rounding.
STORE_RESERVED_FRACTION = 0.95


def allocated_bytes(path):
    """Bytes really backing `path`, or **None** when the platform cannot say.

    ⚠️ None and 0 are different answers and callers must keep them apart: 0
    means "measured, and nothing is allocated" — a sparse image — while None
    means "no `st_blocks` here", which is Windows, where these tests run.
    Treating None as 0 would make the repair below declare failure on a machine
    that merely cannot see the answer.
    """
    try:
        st = os.stat(path)
    except (OSError, ValueError):
        return None
    blocks = getattr(st, 'st_blocks', None)
    if blocks is None:
        return None
    return int(blocks) * 512


def _tree_bytes(path):
    """Bytes a directory tree really occupies, or 0.

    ⚠️ **Real blocks, not apparent sizes** — [allocated_bytes] per file, so a
    sparse file counts what it holds rather than what it claims. That was
    W213's lesson about the loop image and it applies just as well to the
    directory that replaced it.

    ⚠️ Pure Python on purpose. `du` is not on the broker's allowlist, and
    reaching for it would put a binary in the ask for a number we can count
    ourselves. A deployment is a few hundred megabytes of mostly large files;
    the walk is not the expensive part of any page that calls it.
    """
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
        for name in files:
            measured = allocated_bytes(os.path.join(root, name))
            # None is "this platform cannot say" — Windows, where the tests
            # run. Counting it as 0 is right: it is the only honest floor.
            total += measured or 0
    return total


def deliverable_free(fs_free, host_free, mode):
    """What an agency can *actually* still write — the second gauge (W216).

    ⚠️ **The number a dynamic store reports about itself is not the truth.**
    Its filesystem is a ceiling, so it will happily say "3.3 GB available" while
    the host has no blocks left to hand over. That is precisely the class of
    dishonest figure W213 existed to remove: authoritative-looking and wrong.

    Under `fixed` the two agree by construction — the blocks are already
    allocated, so the filesystem's own answer is the truth and the host's free
    space is irrelevant to it.

    Under `dynamic` the honest answer is **the smaller of the two**, because
    either can run out first: the agency can hit its own ceiling, or the box can
    run out of disk underneath it.
    """
    if mode != MODE_DYNAMIC:
        return max(0, fs_free)
    return max(0, min(fs_free, host_free))


def store_facts(ctx=None, mode=None, inst=None):
    """What the console needs to draw the size field honestly.

    Every number here is measured, never estimated: `mkfs` overhead and ext4's
    root reserve both mean usable space is less than the image, and a predicted
    figure that is wrong is worse than a real one that arrives a moment later.

    ⚠️ **`reserved_gb` is now a commitment, not a measurement (W230).** It
    was the loop image's size on disk; with the image gone it is what the
    registry records this deployment was promised. `used_gb` is still
    measured — by walking the directory — so the pair still answers "how much
    was promised, how much is in use". What it can no longer answer is "is the
    promise actually held on disk", because nothing holds it any more:
    `fully_reserved` is therefore always False and says so rather than
    claiming a guarantee that was withdrawn.
    """
    paths = instance_paths(ctx, inst)
    total, free = _disk_free(install_base(ctx))
    # The promise, from the record. `inst` is None for the plain deployment on
    # a box that predates the registry, and 0 is the honest answer there.
    reserved = int((inst or {}).get('size_gb') or 0) * GIB

    mode = mode or MODE_FIXED
    usable = used = 0
    store = paths['store']
    if os.path.isdir(store):
        used = _tree_bytes(paths['dir'])
        # ⚠️ The filesystem's free space, not a private allocation. Every
        # deployment now shares one filesystem, so "usable" is what the box
        # has left plus what this deployment already holds.
        usable = used + free

    return {
        'disk_total_gb': round(total / GIB, 1),
        'disk_free_gb': round(free / GIB, 1),
        'reserved_gb': round(reserved / GIB, 1) if reserved else 0,
        # ⚠️ Measured usage, which under a shared filesystem is the only
        # number here that is a fact about this deployment alone.
        'allocated_gb': round(used / GIB, 1) if used else 0,
        # ⚠️ **Always False, deliberately.** Nothing reserves blocks any
        # more, and a page that kept saying "fully reserved" would be
        # promising a guarantee that was removed.
        'fully_reserved': False,
        'usable_gb': round(usable / GIB, 1) if usable else 0,
        'used_gb': round(used / GIB, 1) if usable else 0,
        'mode': mode,
        # ⚠️ The second gauge. `usable_gb - used_gb` is what the agency's own
        # filesystem claims; `deliverable_gb` is what the box can actually
        # honour. They differ only under dynamic, and that difference is the
        # whole reason this field exists.
        'deliverable_gb': round(
            deliverable_free(max(0, usable - used), free, mode) / GIB, 1),
        # Named so a caller cannot mistake a ceiling for held space.
        'size_is_reserved': mode == MODE_FIXED,
        'max_gb': round(store_ceiling_bytes(free, reserved) / GIB, 1),
        'min_gb': int(STORE_MIN_BYTES / GIB),
        # ⚠️ **Always False now, and kept rather than dropped.** The page
        # reads this key; removing it would make it `undefined` in the
        # browser, which renders the same as False but for the wrong
        # reason. There is no mount: the store is a directory (W230).
        'mounted': False,
    }


def instance_paths(ctx=None, inst=None):
    """Every path one instance uses, on this box's layout.

    ⚠️ `atlas_instances.derive` decides the *names*; this decides where they
    sit, because only the module can see whether the box keeps deployments under
    `/root` or a home directory. Splitting it that way keeps the naming rules
    pure and testable while the filesystem question stays here.
    """
    d = dict(atlas_instances.derive(inst))
    # ⚠️ **Nested under one directory, not scattered beside it (W233).**
    # They used to sit side by side — `<base>/atlas`, `<base>/atlas-corona` —
    # and the broker's model is *one add-on, one directory*: it allows
    # `<home>/atlas/` and verifies by resolving the **real** path on disk
    # against that directory. `atlas-corona` is a sibling, not a child, so
    # every write, chown and delete in it was refused. 61 refusals, all of
    # them fatal the day enforcement is switched on.
    #
    # A name fragment on the allowlist cannot fix that: the check needs a
    # real directory to resolve against, and `atlas-` is not one. So the
    # directories genuinely nest.
    #
    # ⚠️ **Only the directory moves.** Compose project, volume, image
    # names, the Caddy path and the settings keys are what a *running*
    # deployment is identified by; changing any of them would strand one.
    base = posixpath.join(atlas_root(ctx), d['slug'] or PLAIN_DIRNAME)

    # ⚠️ **Transitional: a deployment already in the old sibling directory
    # keeps it.** Anything else would strand a box deployed before this
    # change — the console would look in the new place, find nothing, and
    # offer to build a second copy over the one still running. Such a
    # deployment goes on producing denials until it is removed and
    # redeployed, which is the state it is already in.
    legacy = posixpath.join(posixpath.dirname(atlas_root(ctx)), d['name'])
    if legacy != base and os.path.isdir(posixpath.join(legacy, '.git')):
        base = legacy

    d['dir'] = base
    d['store'] = posixpath.join(base, STORE_DIRNAME)
    d['artifacts'] = posixpath.join(base, 'artifacts')
    d['cache'] = posixpath.join(base, 'cache')
    return d



# --------------------------------------------------------------------------- #
# The instance list (W216)
# --------------------------------------------------------------------------- #


def load_instances(ctx):
    """Every ATLAS deployment on this box.

    ⚠️ **A deployed box predates the list, and must not read as empty.** Every
    existing installation was made before `atlas_instances` existed, so there is
    no record of it anywhere — only `atlas_enabled` and a store on disk. Returning
    `[]` there would tell the console nothing is installed, offer a *plain*
    deployment that is already deployed, and let a second one be created on top
    of the first.

    So an enabled deployment with no list is synthesised as the plain instance,
    sized from the store that is actually on disk. The synthesised record is not
    written back: it is derived on every read, so it stays true if the store is
    resized, and nothing is persisted about a deployment the operator has not
    touched since upgrading.
    """
    settings = ctx['load_settings']() if ctx else {}
    stored = settings.get(atlas_instances.INSTANCES_KEY)
    # ⚠️ **An empty list is an answer; a missing key is not.** `if stored:` made
    # them the same, so removing the *last* deployment — which leaves `[]` and
    # `atlas_enabled` still true, because the module is still installed — fell
    # through to the migration branch below and synthesised a plain deployment
    # that does not exist. The page would then list a phantom, refuse a new
    # general ATLAS as a duplicate of it, and offer to update a directory that
    # is not there.
    if stored is not None:
        return [dict(i) for i in stored]

    if not settings.get(f'{KEY}_enabled'):
        return []

    # ⚠️ **0, and it is the honest answer.** This adopts a deployment made
    # before the registry existed, and the size it was promised is not
    # recorded anywhere — it used to be read off the loop image's apparent
    # size, and there is no image now. Measuring what the directory *uses*
    # would report a different quantity under the same name.
    size_gb = 0
    return [atlas_instances.make(None, atlas_instances.MODE_FIXED,
                                 size_gb, atlas_instances.BASE_PORT)]


def save_instances(ctx, instances):
    """Persist the list. ⚠️ Replaces rather than merges, because removing an
    instance has to be expressible."""
    settings = ctx['load_settings']()
    settings[atlas_instances.INSTANCES_KEY] = [dict(i) for i in instances]
    ctx['save_settings'](settings)
    return instances


def add_instance(ctx, agency_specific, slug, mode, size_gb,
                 agency_name=''):
    """Validate and record a new deployment. `(instance, error)`.

    ⚠️ Records it **before** anything is built, so the slug is claimed and a
    second request for the same one is refused while the first is still
    deploying. A half-built instance with no record is the shape of leak W212
    was about.
    """
    instances = load_instances(ctx)

    if agency_specific:
        slug, err = atlas_instances.validate_slug(slug, instances)
        if err:
            return None, err
    else:
        if not atlas_instances.may_deploy_plain(instances):
            return None, ('This box already has a non-agency ATLAS. Further '
                          'deployments have to be agency-specific.')
        slug = None

    mode, err = atlas_instances.validate_mode(mode)
    if err:
        return None, err

    agency_name, err = atlas_instances.validate_agency_name(agency_name)
    if err:
        return None, err

    if mode == atlas_instances.MODE_DYNAMIC:
        # ⚠️ Not asked for, by design: a dynamic deployment shares whatever is
        # left rather than claiming a slice of it, so its ceiling *is* the pool.
        # Recording the figure keeps the console honest about what the
        # filesystem will report, which is a ceiling and not a reservation.
        size_gb = round(_pool_gb(ctx, instances), 1)
        if size_gb <= 0:
            return None, ('There is no space left in the ATLAS budget for '
                          'another deployment.')
    else:
        ok, err = fits_here(ctx, size_gb, instances)
        if not ok:
            return None, err

    inst = atlas_instances.make(
        slug, mode, size_gb,
        atlas_instances.next_port(instances, taken=_ports_in_use()),
        agency_name=agency_name,
    )
    save_instances(ctx, instances + [inst])
    return inst, None


def env_keys_written():
    """The `TAKMDM_*` names this module writes into a deployment's `.env`.

    Read out of the template rather than listed, so a setting added there cannot
    be forgotten here.
    """
    return sorted(set(re.findall(r'^(TAKMDM_[A-Z0-9_]+)=', _ENV_TEMPLATE,
                                 re.MULTILINE)))


def env_keys_compose_passes(dirpath):
    """The `TAKMDM_*` names the checkout's compose file actually consumes.

    None when the file cannot be read — "we could not look" is not "nothing is
    declared", and reporting the second would raise a false alarm on every
    deploy that happened to race the clone.

    ⚠️ **Two ways a variable is consumed, and only counting one raised a false
    alarm on the first run.** Most are named as keys under `environment:`, but
    `TAKMDM_DB_PASSWORD` is only ever *interpolated* — into
    `POSTGRES_PASSWORD` for the database service and into
    `TAKMDM_DATABASE_URL` for the application. Reporting it as unread would put
    a warning an operator cannot act on into every deploy log, which is how a
    warning stops being read at all.
    """
    try:
        with open(os.path.join(dirpath, 'docker-compose.yml'),
                  encoding='utf-8') as handle:
            body = handle.read()
    except OSError:
        return None
    named = re.findall(r'^\s+(TAKMDM_[A-Z0-9_]+):', body, re.MULTILINE)
    interpolated = re.findall(r'\$\{(TAKMDM_[A-Z0-9_]+)', body)
    return sorted(set(named) | set(interpolated))


def env_keys_that_reach_nothing(dirpath):
    """Settings this module writes that the release will silently ignore.

    ⚠️ **The fourth occurrence of one failure, so this is a measurement rather
    than another reminder.** ATLAS's compose file has no `env_file`, so a
    `TAKMDM_*` in `.env` reaches the container only where compose names it. It
    has now happened with `TAKMDM_INCLUDE_SERVER_CA` (provisioning went on
    pinning a CA it should not have), `TAKMDM_TRUSTED_PROXIES` (SEC_AUDIT S-1's
    mitigation shipped inert for a release), and `TAKMDM_AGENCY_NAME` — the last
    one *with* a warning comment and a test in the product repository, both of
    which were in place and neither of which could see this repository.

    The two files only exist together on the box, after the clone. That is the
    one moment the question can actually be answered, so it is answered there.
    """
    passed = env_keys_compose_passes(dirpath)
    if passed is None:
        return []
    return [key for key in env_keys_written() if key not in passed]


def _env_quote(value):
    """Make a free-text value safe to put in a compose `.env`.

    ⚠️ **Unquoted is wrong in two ways at once**, and both were measured
    against `docker compose config` on the box rather than recalled:

    - `Corona & Co #1` arrived as `Corona & Co` — compose treats an unquoted
      `#` as a comment and truncates the rest of the line.
    - `${...}` and `$NAME` are **interpolated**, so a name could expand another
      variable out of the environment into the agency's own footer.

    ⚠️ **Single quotes are literal but cannot hold an apostrophe**, and
    `'O'Brien County'` does not merely mangle the value — compose fails to
    parse the entire `.env` (*"line 1: unexpected"*) and the deploy dies. The
    shell's `'`+`"'"`+`'` trick is not honoured either. Apostrophes are
    explicitly legal in an agency name, so single quoting is not an option.

    So: **double quotes, with the three characters they give meaning to
    escaped.** Measured to round-trip apostrophes, `"`, `&`, `#`, backslashes,
    `$NAME` and `${NAME}` unchanged into the container.
    """
    text = '' if value is None else str(value)
    text = (text.replace(BACKSLASH, BACKSLASH * 2)
                .replace('"', BACKSLASH + '"')
                # ⚠️ `$$` is compose's literal-dollar escape. Doubling is what
                # stops `$HOME` in an agency's name reaching into the
                # environment of the process that rendered the file.
                .replace('$', '$$'))
    return '"' + text + '"'


def write_env_value(env_path, key, value):
    """Set one `KEY=value` line in a `.env`, adding it if it is absent.

    Returns True when the file changed.

    ⚠️ **Appends when the key is missing**, because a deployment made before
    the key existed has an `.env` without it — and `deploy` is the only thing
    that rewrites the file wholesale, so without this the only way to add a
    setting to a running deployment would be to deploy it again.

    ⚠️ Rewrites the *line*, not a substring. A value containing the key's own
    name, or a comment mentioning it, must not be what gets replaced.
    """
    # ⚠️ **Raised, not swallowed.** This returned False on any `OSError`,
    # and the route above it reported "Written to the deployment
    # configuration" either way — so a permissions problem or a missing `.env`
    # read as success, and the operator went looking for the name in a footer
    # that was never going to show it. A deployment with no `.env` is not a
    # deployment this can act on, and saying so is the whole point.
    with open(env_path, 'r', encoding='utf-8') as handle:
        body = handle.read()
    line = '%s=%s' % (key, value)
    out, replaced = [], False
    for existing in body.splitlines():
        if existing.startswith(key + '='):
            out.append(line)
            replaced = True
        else:
            out.append(existing)
    if not replaced:
        out.append(line)
    new_body = chr(10).join(out) + chr(10)
    if new_body == body:
        return False
    with open(env_path, 'w', encoding='utf-8') as handle:
        handle.write(new_body)
    return True


def set_agency_name(ctx, inst, raw_name):
    """Name a deployment that is already built. `(steps, error)`.

    ⚠️ **This exists because `deploy` is the only thing that writes `.env`.**
    `config.py` says it out loud — *"the InfraTAK module rewrites `.env` on
    deploy but not on update"* — so without this the name could only be set by
    tearing a deployment down and building it again, and the feature would ship
    unusable on every deployment that already exists.
    """
    name, err = atlas_instances.validate_agency_name(raw_name)
    if err:
        return [], err

    paths = instance_paths(ctx, inst)
    env_path = os.path.join(paths['dir'], '.env')
    if not os.path.exists(env_path):
        return [], 'That deployment has no configuration on disk yet.'

    steps = []
    remaining = []
    for other in load_instances(ctx):
        if (other.get('slug') or None) == (inst or {}).get('slug'):
            other = dict(other, agency_name=name)
        remaining.append(other)
    save_instances(ctx, remaining)
    steps.append('Recorded' if name else 'Name cleared')

    # ⚠️ The failure is reported, not stepped over. `write_env_value` used to
    # swallow `OSError` and this line claimed success regardless, so a
    # permissions problem or a missing `.env` looked exactly like a name that
    # had been applied — and the operator went looking for it in a footer that
    # was never going to show it.
    try:
        write_env_value(env_path, 'TAKMDM_AGENCY_NAME', _env_quote(name))
    except OSError as exc:
        return steps, ('Could not write %s: %s. The name is recorded but this '
                       'deployment has not been told about it.'
                       % (env_path, exc))
    steps.append('Written to the deployment configuration')

    # ⚠️ **`up -d`, not `restart`.** Measured on the box: the name was in
    # `.env`, the record and the log all said it had been applied, and
    # `printenv` inside the container showed nothing. Compose interpolates
    # `${TAKMDM_AGENCY_NAME}` when it *renders* the configuration and bakes the
    # result in at container **create** time; `restart` stops and starts the
    # same container, so a changed `.env` value never reaches it. `up -d`
    # re-renders, sees the difference and recreates.
    #
    # ⚠️ The CA ceremony's `restart api` is correct as it stands — that reloads
    # files from a volume, not an interpolated environment.
    r = _compose(ctx, 'up -d api', timeout=300, inst=inst)
    if r.returncode != 0:
        return steps, compose_error(r, 'docker compose up')
    steps.append('%s recreated — the footer shows it now'
                 % atlas_instances.derive(inst)['name'])
    return steps, None


def drop_instance(ctx, slug):
    """Forget a deployment. Returns the remaining list."""
    remaining = [i for i in load_instances(ctx)
                 if (i.get('slug') or None) != (slug or None)]
    return save_instances(ctx, remaining)


def _ports_in_use():
    """Loopback ports this box is already listening on.

    ⚠️ Best effort, and deliberately additive to the model's own list: a port
    held by something outside ATLAS is invisible to the instance model, and
    handing it out produces a deploy that fails at bind time with nothing on the
    page to explain why.
    """
    rc, out = _run_root(['ss', '-ltn'])
    if rc != 0:
        return ()
    found = set()
    for line in (out or '').splitlines():
        for field in line.split():
            if ':' in field:
                tail = field.rsplit(':', 1)[-1]
                if tail.isdigit():
                    found.add(int(tail))
    return tuple(sorted(found))


def capacity_facts(ctx, size_gb=None):
    """What the deploy screen needs to say how much room is left.

    ⚠️ **Names the binding constraint.** On the box measured, disk allowed four
    or five more instances and memory about twelve; an operator shown only the
    larger figure would plan for twice what fits.
    """
    instances = load_instances(ctx)
    total, free = _disk_free(install_base(ctx))
    floor = int(atlas_instances.DEFAULT_FLOOR_GB * atlas_instances.GIB)
    reserved = atlas_instances.committed_bytes(instances)
    # Everything on the disk that is not an ATLAS reservation.
    non_atlas = max(0, total - free - reserved)
    budget = atlas_instances.budget_bytes(total, non_atlas, floor)
    committed = atlas_instances.committed_bytes(instances)
    pool = atlas_instances.pool_bytes(budget, instances)
    dynamic = sum(1 for i in instances
                  if i.get('mode') == atlas_instances.MODE_DYNAMIC)

    # ⚠️ The real hostname, so the confirmation can name it instead of saying
    # "<your-domain>". The *rule* for where a slug goes stays in `agency_host`:
    # the template is built here and the page only substitutes, so the two
    # cannot drift into disagreeing about the shape of an agency hostname.
    plain_host = ''
    try:
        plain_host = ctx['_get_service_domain'](ctx['load_settings'](), KEY) or ''
    except (KeyError, TypeError):
        plain_host = ''

    ram_total, ram_available = _memory_bytes()
    by_ram = atlas_instances.instances_that_ram_allows(
        ram_available, 4 * atlas_instances.GIB)
    by_disk = atlas_instances.instances_that_fit(
        size_gb or 50, instances, budget) if (size_gb or 50) else 0
    which, how_many = atlas_instances.binding_constraint(by_disk, by_ram)

    gb = atlas_instances.GIB
    return {
        'instances': len(instances),
        'budget_gb': round(budget / gb, 1),
        'committed_gb': round(committed / gb, 1),
        'remaining_gb': round(max(0, budget - committed) / gb, 1),
        # What dynamic deployments share. Equal to `remaining_gb` today, and a
        # separate name because they answer different questions: one is "how
        # much is left to give away", the other "how much can this deployment
        # grow into".
        'pool_gb': round(pool / gb, 1),
        'dynamic_instances': dynamic,
        'reserved_gb': round(reserved / gb, 1),
        'floor_gb': atlas_instances.DEFAULT_FLOOR_GB,
        # ⚠️ The bounds the single-instance card used to enforce, carried
        # across rather than dropped when the two paths merged: a floor
        # because ATLAS ships ~570 MB before anything is uploaded, and the
        # 85% ceiling so a reservation cannot take the whole disk.
        'min_gb': int(STORE_MIN_BYTES / gb),
        'max_gb': round(store_ceiling_bytes(free, 0) / gb, 1),
        'disk_free_gb': round(free / gb, 1),
        'ram_total_gb': round(ram_total / gb, 1),
        'ram_available_gb': round(ram_available / gb, 1),
        'per_instance_peak_gb': round(
            atlas_instances.INSTANCE_RAM_PEAK_BYTES / gb, 2),
        'by_disk': by_disk,
        'by_ram': by_ram,
        'binding': which,
        'room_for': how_many,
        'plain_host': plain_host,
        'host_template': atlas_instances.agency_host(plain_host, '{slug}')
        if plain_host else '',
        'may_deploy_plain': atlas_instances.may_deploy_plain(instances),
        # ⚠️ So the page can refuse a duplicate slug before anything is
        # recorded. The server refuses it too — this is the courtesy, not
        # the control.
        'slugs': [i.get('slug') for i in instances if i.get('slug')],
    }


def _pool_gb(ctx, instances):
    """The pool, in GB. One place, so the screen and the validator agree."""
    total, free = _disk_free(install_base(ctx))
    floor = int(atlas_instances.DEFAULT_FLOOR_GB * atlas_instances.GIB)
    committed = atlas_instances.committed_bytes(instances)
    non_atlas = max(0, total - free - committed)
    budget = atlas_instances.budget_bytes(total, non_atlas, floor)
    return atlas_instances.pool_bytes(budget, instances) / atlas_instances.GIB


def fits_here(ctx, size_gb, instances=None):
    """`(ok, error)` for one requested size against this box's budget."""
    instances = load_instances(ctx) if instances is None else instances
    total, free = _disk_free(install_base(ctx))
    floor = int(atlas_instances.DEFAULT_FLOOR_GB * atlas_instances.GIB)
    reserved = atlas_instances.committed_bytes(instances)
    non_atlas = max(0, total - free - reserved)
    budget = atlas_instances.budget_bytes(total, non_atlas, floor)
    return atlas_instances.fits(size_gb, instances, budget)


def _memory_bytes(path='/proc/meminfo'):
    """`(total, available)` from /proc/meminfo, or `(0, 0)`.

    The path is a parameter so this can be checked against a real
    meminfo body on a machine that has none.

    ⚠️ `MemAvailable`, not `MemFree`. Free memory on a box running eight stacks
    is near zero because the page cache holds the rest, and planning against it
    would refuse every instance the box could comfortably run.
    """
    try:
        with open(path) as fh:
            fields = {}
            for line in fh:
                name, _, rest = line.partition(':')
                digits = rest.strip().split(' ')[0]
                if digits.isdigit():
                    fields[name] = int(digits) * 1024
        return fields.get('MemTotal', 0), fields.get('MemAvailable', 0)
    except (OSError, ValueError):
        return 0, 0


# --------------------------------------------------------------------------- #
# Per-instance jobs and version drift (W216)
# --------------------------------------------------------------------------- #


def instance_job_key(inst):
    """The job slot and lock for one deployment.

    ⚠️ `job_start` creates a slot lazily for any key, so instances get their own
    locks without being registered as modules — which they cannot be, because
    `register()` runs only at console import.

    ⚠️ The charset is `[a-z0-9_-]` and nothing more: the descriptor validator
    rejects anything else, so `atlas:agency-a` — the obvious first shape — would
    fail at import.
    """
    return atlas_instances.derive(inst)['job_key']


def version_drift(ctx):
    """What each deployment is running, and whether they agree.

    ⚠️ **Drift is expected here, not a fault.** Updates are deliberately manual
    (§9) and, with several agencies, will not all happen on the same day. Showing
    it is what makes a staged rollout *deliberate* rather than something
    discovered later — and it is the reason an "update all" button needs a
    per-instance result list rather than a single success flag.
    """
    projects = compose_projects_present(ctx)
    rows = [instance_status(ctx, inst, projects, probe_version=True)
            for inst in load_instances(ctx)]
    # ⚠️ Drift is measured on the *built* deployments. An unfinished one has no
    # version to disagree with, and counting its None as a version would report
    # drift on a box where every running deployment is on the same release.
    versions = sorted({r['version'] for r in rows if r['built'] and r['version']})
    return {
        'instances': rows,
        'versions': versions,
        'drifted': len(versions) > 1,
        # ⚠️ Per channel. A box following `main` must not be shown `dev`'s
        # number here, or the drift table would report every deployment as
        # behind a release its channel does not offer.
        'available': _latest_version(use_cache=True, channel=_channel_of(ctx)),
        'channel': _channel_of(ctx),
    }


def instance_status(ctx, inst, projects=None, probe_version=False):
    """Everything the console needs to say about one deployment.

    ⚠️ **`probe_version` is off by default, and that is a performance
    contract.** Asking the container its version is an HTTP round-trip with a
    five-second timeout. `detect` runs on every dashboard poll from several
    threads and must answer in under a second, so it asks only the cheap
    questions; the drift table, served by a route an operator opened
    deliberately, asks the expensive one.

    ⚠️ **`built` and `running` are different questions and both are needed.** A
    deployment that never finished has no containers and is not "stopped" — it
    is unfinished, and the action it needs is *finish*, not *start*. Collapsing
    the two is what left the operator with a claimed slug and no button.
    """
    names = atlas_instances.derive(inst)
    built = instance_is_built(ctx, inst, projects)
    # ⚠️ Asked with the same project set, so one docker call answers both.
    stranded = instance_is_stranded(ctx, inst, projects)
    running = False
    if built:
        try:
            r = ctx['probe_run'](
                ['docker', 'inspect', '--format', '{{.State.Running}}',
                 api_container(ctx, inst)],
                text=True, timeout=3,
            )
            running = (r.stdout or '').strip() == 'true'
        except Exception:
            running = False
    return {
        'slug': names['slug'],
        'name': names['name'],
        'mode': inst.get('mode'),
        'size_gb': inst.get('size_gb'),
        'port': names['port'],
        'built': built,
        'running': running,
        # ⚠️ **Containers up, files unreachable.** Without this the row reads
        # "not deployed" over a deployment that is serving, and the only
        # control offered is the one that would build a second copy of it.
        'stranded': stranded,
        # ⚠️ Both versions, when asked. They agree on a healthy deployment;
        # when they do not, the running one is the truth and the difference is a
        # rebuild that did not take.
        # ⚠️ From the record. The deployment's own `.env` has it too, but the
        # record is what the page edits and what survives a container that is
        # not running.
        'agency_name': inst.get('agency_name') or '',
        'version': _installed_version(ctx, inst),
        'running_version': (_running_version(ctx, inst)
                            if running and probe_version else None),
    }


#: Every field a deployment row carries, declared rather than implied.
#:
#: ⚠️ **A missing one is `undefined` in the browser, not an error.** JavaScript
#: renders it falsy and moves on, so the page said "stopped  version unknown"
#: over a deployment that was up — for as long as it took somebody to notice and
#: say so. A name in this list is a promise the route keeps and the page may
#: rely on; `test_atlas_route_contract.py` holds both halves to it.
INSTANCE_FIELDS = ('slug', 'name', 'mode', 'size_gb', 'port', 'built',
                   'running', 'stranded', 'version', 'running_version',
                   'agency_name', 'latest', 'update_available', 'paths')


def update_available_for(installed, latest):
    """Whether this deployment has a newer release to move to.

    ⚠️ **Computed here, not in the browser.** The comparison is on a tuple of
    integers, never on the string: `0.10.0` sorts before `0.9.0`
    alphabetically, which would stop offering updates at the tenth release of
    any series and do it silently. `_parse_version` already gets that right and
    is tested; a second implementation in JavaScript would be a second chance to
    get it wrong.

    ⚠️ **False when either version is unknown.** An unreachable GitHub leaves
    `latest` empty, and a badge is a claim — "nothing to do here" is not
    something a failed check has earned. Absence of a badge means "no newer
    release established", which is the honest reading of both cases.
    """
    here, there = _parse_version(installed), _parse_version(latest)
    return bool(here and there and there > here)


def instances_payload(ctx, size_gb=None):
    """Exactly what the deployments card needs to draw itself.

    ⚠️ **`instance_status` existed and the route did not use it.** Chunk 8 wired
    it into `detect` and `version_drift` and left `instances_view` returning the
    bare record plus `built` — so every row rendered *"stopped  version
    unknown"* over a deployment that was up, healthy and reachable. Measured on
    the box 2026-09-18: `takmdm-corona-api-1` up 8 minutes, `docker inspect`
    saying `true`, `VERSION` reading 1.47.3, and the page saying stopped.

    ⚠️ **The node harness could not catch it**, and that is the lesson. It feeds
    `renderInstances` a hand-written object carrying `running` and `version` —
    a contract the server did not keep. A harness that invents its input tests
    the page against a server that does not exist, so the guard for this is a
    test that reads the page's own property accesses and checks them against
    *this* function's output.
    """
    projects = compose_projects_present(ctx)
    # ⚠️ Asked once for the whole box, not once per deployment. It is a GitHub
    # call behind a 15-minute cache, and the allowance is 60 an hour per IP — a
    # box with five agencies polling this route would spend it on one page.
    latest = _latest_version(use_cache=True, channel=_channel_of(ctx))
    return {
        'instances': [
            dict(inst,
                 # ⚠️ No `probe_version`: this route is polled while the page is
                 # open, and an HTTP round-trip per deployment with a
                 # five-second timeout would make the card slower the more
                 # agencies a box has. The checkout's version is what the row
                 # shows; the drift table asks the containers.
                 **instance_status(ctx, inst, projects),
                 latest=latest,
                 update_available=update_available_for(
                     _installed_version(ctx, inst), latest),
                 paths={k: instance_paths(ctx, inst)[k]
                        for k in ('dir', 'vhost', 'compose_project')})
            for inst in load_instances(ctx)
        ],
        'capacity': capacity_facts(ctx, size_gb=size_gb),
        # ⚠️ **The one job an operator has, asked at box level.** While a root
        # key is on this server, anyone who reaches the machine can impersonate
        # any of that deployment's devices and the only remedy is setting every
        # tablet up again. A per-deployment banner is easy to scroll past; a
        # list is not.
        'root_keys': root_key_holders(ctx, projects),
    }


def caddy_sites(settings, plain_host):
    """One entry per deployment, for the console's Caddyfile generator (W216).

    ⚠️ **Exactly one entry on a box with a single deployment**, carrying the same
    host, upstream and CA path the generator used before this existed — so the
    emitted Caddyfile is unchanged there. That property is what makes this safe
    to land on a live box: a Caddyfile that differs by one character takes every
    vhost on the machine with it, not just ATLAS's.

    Each agency needs its own device CA path, because `client_auth` verifies
    against exactly one trust pool: pointing two agencies at one file would have
    Caddy accept either agency's devices at either agency's hostname.
    """
    ctx = {'load_settings': lambda: settings}
    sites = []
    for inst in load_instances(ctx):
        slug = (inst or {}).get('slug')
        port = (inst or {}).get('port') or atlas_instances.BASE_PORT
        sites.append({
            'slug': slug,
            'host': atlas_instances.agency_host(plain_host, slug),
            'upstream': f'127.0.0.1:{port}',
            # ⚠️ **Describes, never writes (W230).** This used to call
            # `sync_device_ca_for_caddy` here — a privileged write, from the
            # function whose job is to render a config, with a `ctx` it had
            # built itself out of nothing. When that write failed the path
            # came back None, the `:8449` block was quietly omitted, and the
            # deploy log still said "Devices: https://…:8449 (mutual TLS)".
            # Staging is now `deploy`'s job and failing is fatal there.
            'ca_path': device_ca_path(inst) if _ca_is_staged(inst) else None,
        })
    return sites


def api_container(ctx=None, inst=None):
    """The API container of one deployment.

    ⚠️ `API_CONTAINER` is the *plain* deployment's, and it was the answer
    everywhere: logs, exec, the running-version probe, the tile's liveness
    check. On a box whose only deployment is an agency, every one of those
    reports on a container that does not exist — so the console says ATLAS is
    down, shows no logs, and offers an update for a checkout it is not reading.
    """
    if not (inst or {}).get('slug'):
        return API_CONTAINER
    return '%s-api-1' % instance_paths(ctx, inst)['compose_project']


def compose_projects_present(ctx=None):
    """Compose projects that have containers on this box, running or not.

    ⚠️ **One docker call for every deployment, not one each.** This is read on
    every poll of the instances route, and a subprocess per agency would make
    the page slower the more agencies a box has — exactly backwards.
    """
    rc, out = _run_root(
        ['docker', 'ps', '-a', '--format', '{{.Label "com.docker.compose.project"}}'])
    if rc != 0:
        return set()
    return {line.strip() for line in (out or '').splitlines() if line.strip()}


def instance_is_built(ctx, inst, projects=None):
    """Whether a recorded deployment actually exists, rather than merely being
    recorded.

    ⚠️ **A directory is not a deployment.** The first version asked only whether
    the install directory existed, which is true the moment the clone succeeds —
    so a deploy that cloned and then failed at `docker compose up` reported
    itself as built, and the page offered no way to finish it. The containers are
    the thing that makes it a deployment; the checkout is a step along the way.
    """
    paths = instance_paths(ctx, inst)
    if not os.path.isdir(paths['dir']):
        return False
    known = projects if projects is not None else compose_projects_present(ctx)
    return paths['compose_project'] in known


def _store_mount(ctx, inst=None):
    return instance_paths(ctx, inst)['store']


#: The Postgres image runs as uid/gid 70 and refuses to start unless its data
#: directory is owned by that user with mode 0700. Measured on the box, not
#: assumed: `postgres:16-alpine` → `70:70`, `drwx------`.
STORE_PG_UID = 70
STORE_PG_GID = 70

#: What the compose project calls its Postgres volume. ⚠️ A Compose project
#: name prefix: the directory is `atlas` on the box but the project is `takmdm`,
#: because compose takes the name from the repository directory inside it.
STORE_PG_VOLUME = 'takmdm_pgdata'


def _broker_script():
    """The privileged broker, found the way `CONFIG_DIR` is: relative to here.

    `modules/atlas.py` sits one directory below the console, so the broker is
    `../broker/takwerx_broker.py`. Returns None on a box that has none, which
    is every root-era install.
    """
    console = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(console, 'broker', 'takwerx_broker.py')
    return path if os.path.isfile(path) else None


def _chown_priv(path, uid, gid):
    """Give `path` to `uid:gid`. Returns an error string, or None.

    ⚠️ **The PATH shim is not enough, and assuming it was cost two failed
    deploys.** `/opt/infratak/.shims/chown` only routes arguments under
    `/etc /opt /usr /var /run /boot /swapfile`; a path in the console's own
    home falls straight through to `/usr/bin/chown`, which cannot give a
    directory away. The broker itself *does* allow it — verified by calling
    it directly — so the fix is to stop going through the shim for this.

    ⚠️ **`os.chown` first, for a root-era console**, where there is no
    broker at all and the direct call is correct.

    ⚠️ There is no `ctx` seam for this yet. Upstream is already exporting
    `ctx['_proxy_auth_secret']` after the same kind of gap; this belongs on
    the same list, and the PR body asks for it.
    """
    try:
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            os.chown(path, uid, gid)
            return None
    except OSError as exc:
        return 'could not set ownership on %s: %s' % (path, exc)

    broker = _broker_script()
    if broker is None:
        return ('%s must be owned by uid %d and this console is neither root '
                'nor has a broker to ask.' % (path, uid))
    rc, out = _run_root(
        ['python3', broker, 'exec', '--', 'chown', '-R',
         '%d:%d' % (uid, gid), path], timeout=120)
    if rc != 0:
        return 'could not set ownership on %s: %s' % (path, out.strip()[:200])
    return None


def _rm_priv(path, inside):
    """Delete a tree the console may not own. Returns an error string, or None.

    ⚠️ **The containers own most of what a deployment writes.** `pgdata` is
    uid 70 and `0700`; `artifacts/` and `cache/` are the application's uid.
    The console can descend into them and cannot unlink their contents, so
    `shutil.rmtree` fails and — measured on the box — so does `rm -rf`
    through the PATH shim, which only routes `/etc /opt /usr /var /run /boot
    /swapfile` and lets a home path through to `/usr/bin/rm`.

    ⚠️ **`inside` is not decoration.** This ends in `rm -rf` as root, so
    the caller states the directory the target must live under and anything
    else is refused before the broker is asked. The paths come from
    `instance_paths` and the slug is `^[a-z]{1,32}$`, so this should be
    unreachable — which is exactly when a guard is worth having.
    """
    root = inside.rstrip('/') + '/'
    if not path.startswith(root) or '..' in path.split('/'):
        return 'refusing to delete %s: it is not inside %s' % (path, inside)
    if not os.path.isdir(path) and not os.path.isfile(path):
        return None

    try:
        shutil.rmtree(path)
        return None
    except OSError:
        pass

    broker = _broker_script()
    if broker is None:
        return ('could not remove %s and this console is neither root nor has '
                'a broker to ask.' % path)
    rc, out = _run_root(['python3', broker, 'exec', '--', 'rm', '-rf', path],
                        timeout=300)
    # ⚠️ Checked, not trusted. W205's uninstall reported success over a
    # device CA and a database it had left on disk.
    if rc != 0 or os.path.exists(path):
        return 'could not remove %s: %s' % (path, out.strip()[:200])
    return None


def _run_root(argv, timeout=120):
    """(rc, output). Runs as the console already does — root, no shell."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except Exception as exc:
        return 1, str(exc)


def ensure_store(ctx, size_bytes, plog, mode=None, inst=None):
    """Create the directories a deployment keeps its data in. Error, or None.

    ⚠️ **This was a loop-mounted ext4 image and is now four directories
    (W230).** The old version wrote `/var/lib/<name>/store.img`, ran
    `fallocate`/`truncate`, `mkfs.ext4`, `resize2fs`, `e2fsck` and `losetup`,
    and installed three systemd `.mount` units. None of that is available to
    an unprivileged console, and upstream's review named the design itself
    rather than the permissions: *"a root-mounted filesystem image whose file
    the unprivileged console can write is exactly the kind of thing the broker
    exists to prevent."* They are right — a console that can write the image
    and have root mount it can hand root a filesystem of its choosing.

    ⚠️ **So capacity is no longer enforced at runtime, and that is a real
    loss taken deliberately.** `size_gb` remains a commitment the box plans
    against — `fits_here` still refuses an over-commitment at deploy — but
    nothing now stops a deployment growing past it and crowding its
    neighbours. The alternative was asking upstream to broker the whole loop
    lifecycle, which is more privilege for a property we can get back later.

    `size_bytes` and `mode` are kept in the signature: the size is recorded
    and planned against, and callers should not have to change shape for a
    storage decision.
    """
    paths = instance_paths(ctx, inst)
    store = paths['store']

    # ⚠️ Created as the console, not as root. Everything here lives under
    # the console's own install directory, so ordinary `makedirs` is the whole
    # of it — no broker, no allowlist, no privileged path.
    wanted = [store, paths['artifacts'], paths['cache'],
              posixpath.join(store, 'pgdata')]
    for path in wanted:
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            return 'could not create %s: %s' % (path, exc)

    plog('  ✓ Store directories ready under %s' % paths['dir'])
    if mode == MODE_FIXED:
        # ⚠️ Said out loud rather than quietly dropped. An operator who chose
        # "fixed" asked for a reservation and is no longer getting one; the
        # number still governs what the box will let them commit.
        plog('  ⚠ %0.1f GB is a commitment this box plans against, not a '
             'reservation on disk.' % (size_bytes / GIB))
        plog('    Nothing stops this deployment growing past it.')

    pgdir = posixpath.join(store, 'pgdata')
    # ⚠️ **No chown at all, and the first attempt to keep one was wrong.**
    #
    # `postgres:16-alpine` runs as uid 70 and refuses to start unless it owns
    # its data directory, so this chowned `pgdata` to 70 through the shimmed
    # `chown`. That failed on the box: the shim only routes paths under
    # `/etc /opt /usr /var /run /boot /swapfile`, so a path in the console's
    # own home falls straight through to `/usr/bin/chown` and the console
    # cannot give a directory away. *"Operation not permitted"*, measured.
    #
    # Widening the shim to broker chowns anywhere under `/home` is a large
    # grant for a small need. Running the database as the console's own uid
    # instead — the same thing the api container already does — needs no
    # privilege and no broker change: the directory is owned by the only user
    # that touches it. See `_COMPOSE_OVERRIDE`.
    # ⚠️ **Not chmod'd either, and that would have failed on the *second*
    # deploy.** Postgres runs as root, chowns its data directory to uid 70 and
    # sets 0700 itself — measured: after one start the directory is
    # `drwx------ 70 70`. A `chmod` here works on a fresh deployment, where
    # the console still owns the directory, and is `EPERM` on every re-deploy
    # and every update afterwards. Creating it is the whole job.

    err = _bind_pg_volume(pgdir, plog, volume=paths['pg_volume'])
    if err:
        return err
    return None


def remove_store(ctx, plog, inst=None):
    """Undo `ensure_store`. Returns what it did, and any errors.

    ⚠️ **Most of this function was unmounting, and there is nothing left to
    unmount (W230).** It used to disable three systemd units, `umount` three
    paths (falling back to `umount -l`), delete the unit files, `losetup -d`
    the loop device and remove the image. The store is now a directory tree
    the console owns, so deleting it is deleting it.

    ⚠️ **The named volume still goes first.** It is only a pointer at
    `pgdata`, but leaving it behind makes the next deploy refuse —
    `_bind_pg_volume` rejects a volume that already exists pointing somewhere
    unexpected, which is exactly the right behaviour and exactly what a
    half-finished teardown would trigger.

    ⚠️ **Still best-effort and still idempotent.** An uninstall has to be
    re-runnable after a partial failure, and a clean box must produce no
    errors. That was W205's lesson — uninstall reported success while leaving
    the device CA and the Postgres directory behind — and it survives the
    simplification.
    """
    did, errs = [], []
    paths = instance_paths(ctx, inst)
    volume = paths['pg_volume']

    rc, out = _run_root(['docker', 'volume', 'rm', '-f', volume])
    if rc == 0:
        did.append('Docker volume %s removed' % volume)

    # ⚠️ Every one of these is owned by a container, not by the console:
    # `pgdata` by uid 70, `artifacts` and `cache` by the application's uid.
    # All three go through the same privileged removal.
    for path in (paths['store'], paths['artifacts'], paths['cache']):
        if not os.path.exists(path):
            continue
        err = _rm_priv(path, paths['dir'])
        if err:
            errs.append(err)
        else:
            did.append('%s removed' % path)

    return did, errs


def _bind_pg_volume(pgdir, plog, volume=None):
    """Back the Postgres named volume with a bind into the store.

    ⚠️ **Proven against a real Docker before it was written here.** Compose
    warns — *"volume already exists but was not created by Docker Compose"* — and
    then uses it anyway, and Postgres initialises into the bind target correctly.
    That warning appears in the deploy log and is expected; the alternative was
    editing `docker-compose.yml`, which belongs to the repository the operator
    releases rather than the one this module lives in.

    Left alone if it already points where it should: recreating a volume Postgres
    has data in would be the one genuinely destructive thing in this feature.
    """
    volume = volume or STORE_PG_VOLUME
    rc, out = _run_root(
        ['docker', 'volume', 'inspect', volume, '--format', '{{.Options.device}}'])
    if rc == 0:
        if out.strip() == pgdir:
            plog(f'  ✓ {volume} already backed by the store')
            return None
        where = out.strip() or "Docker's own directory"
        return (
            f'{volume} already exists and points at {where}. '
            f'Remove it before reserving a store — otherwise the database '
            f'would sit outside the reservation while the console reported it '
            f'inside.'
        )

    rc, out = _run_root([
        'docker', 'volume', 'create', '--driver', 'local',
        '-o', 'type=none', '-o', f'device={pgdir}', '-o', 'o=bind',
        volume,
    ])
    if rc != 0:
        return f'could not create {volume}: {out.strip()[:300]}'
    plog(f'  ✓ {volume} backed by {pgdir}')
    return None


def _bridge_gateway(project='takmdm'):
    """The address Caddy appears as from inside this deployment's container.

    Caddy runs on the host and reaches the application through Docker's bridge,
    so the peer the application sees is the network's gateway — 172.24.0.1 on the
    reference box, but the subnet is assigned by Docker and differs per host.

    ⚠️ **Falls back to the whole RFC1918 space rather than to nothing.** A wrong
    guess here locks an operator out of their own console; a broad value still
    refuses a request arriving from a public address, which is the case worth
    closing. The narrow value is an optimisation, not the control.

    ⚠️ Asked of the *network*, not of a running container: on a first install
    the network exists before the application does, and on a redeploy the
    container may be down.

    ⚠️ **Per deployment.** `takmdm_default` was hardcoded, so an agency always
    took the fallback and never narrowed — the S-1 mitigation quietly not
    applying to exactly the deployments a box gains from here on. Not a lockout,
    which is why nothing would have reported it.
    """
    network = '%s_default' % project
    try:
        r = subprocess.run(
            ['docker', 'network', 'inspect', '-f',
             '{{range .IPAM.Config}}{{.Subnet}}{{end}}', network],
            capture_output=True, text=True, timeout=30,
        )
        subnet = (r.stdout or '').strip()
        if r.returncode == 0 and '/' in subnet:
            return subnet
    except Exception:
        pass
    return _TRUSTED_FALLBACK


#: The group Authentik creates for itself, and the one the module binds the
#: ATLAS application to. ⚠️ Deliberately not an invented name: the documented
#: objection to ATLAS checking a group at all was that a required group is "a
#: bootstrap nobody could complete". That is true of `takmdm-admins`, which no
#: Authentik has, and false of this one — Authentik creates it and whoever
#: installed ATLAS is necessarily in it.
ADMIN_GROUP = 'authentik Admins'


#: What the container calls this host. Mapped to the bridge gateway by ATLAS's
#: own docker-compose; named here because this is the end that writes it.
MAIL_HOST_FROM_CONTAINER = 'host.docker.internal'

#: Prefix on every comment line this writes, so the next run takes its own
#: block out again before writing a fresh one.
MAIL_MARKER = '# W194.'


def _push_email_relay(ctx, dirpath, plog):
    """Tell ATLAS where InfraTAK's Email Relay is, and who it sends as (W194).

    ⚠️ **No credential crosses this line, and none ever should.** The relay
    is Postfix on this host with `mynetworks` covering the Docker bridge, so a
    container hands it a message and Postfix authenticates onward using the
    provider password in `/etc/postfix/sasl_passwd`. Copying that password into
    ATLAS's `.env` would put a live SMTP credential in plaintext on disk for no
    gain at all — the relay does not want it — and would undo the ATLAS audit
    finding (M-5) that sealed outbound credentials in the first place.

    ⚠️ **Cleared when the relay is gone**, not merely left behind. A stale
    from-address is what ATLAS uses to decide the relay looks configured, so
    leaving it would make the console promise a relay that has been uninstalled.
    """
    env_path = os.path.join(dirpath, '.env')
    # ⚠️ **Let it raise (W240).** This swallowed the PermissionError from
    # a root-owned `.env` and returned the same False it returns for
    # "nothing needed changing" -- so a deploy that had wired up neither the
    # admin group nor the proxy-auth secret still printed a tick. Every
    # caller reaches this *after* the deploy wrote the file, so an
    # unreadable or missing `.env` here is a fault, not a state to live with.
    with open(env_path, 'r') as f:
        body = f.read()

    relay = (ctx['load_settings']() or {}).get('email_relay') or {}
    from_addr = (relay.get('from_addr') or '').strip()

    wanted = {
        'TAKMDM_INFRATAK_MAIL_HOST': MAIL_HOST_FROM_CONTAINER if from_addr else '',
        'TAKMDM_INFRATAK_MAIL_PORT': '25' if from_addr else '',
        'TAKMDM_INFRATAK_MAIL_FROM': from_addr,
    }

    # ⚠️ The comment lines carry the marker too, so they come out with the
    # values. Without that they survived the filter and a fresh block was
    # appended beside them on every deploy and every update — an .env growing
    # four comment lines a release, and a function that never reported
    # 'nothing changed' and so restarted the api container every time. Found
    # by running it twice against a temporary file rather than by reading it.
    lines = [l for l in body.splitlines()
             if not any(l.startswith(k + '=') for k in wanted)
             and not l.startswith(MAIL_MARKER)]
    if from_addr:
        # ⚠️ Trailing blanks trimmed before the separator goes back on.
        # Filtering the block out leaves the blank line that preceded it, so
        # each run added another one — the file never settled, the function
        # reported a change every time, and the api container was restarted
        # on every update for a value that had not moved.
        while lines and not lines[-1].strip():
            lines.pop()
        lines.append('')
        lines.append(MAIL_MARKER + ' InfraTAK\'s Email Relay, for ATLAS to inherit.')
        lines.append(MAIL_MARKER + ' Postfix on this host accepts mail from the')
        lines.append(MAIL_MARKER + ' Docker bridge unauthenticated, so there is')
        lines.append(MAIL_MARKER + ' deliberately no username or password here:')
        lines.append(MAIL_MARKER + ' the provider credential stays in')
        lines.append(MAIL_MARKER + ' /etc/postfix/sasl_passwd where Postfix uses it.')
        for key, value in wanted.items():
            lines.append(key + '=' + value)

    updated = '\n'.join(lines).rstrip('\n') + '\n'
    if updated == body:
        return False
    with open(env_path, 'w') as f:
        f.write(updated)
    if from_addr:
        plog('✓ ATLAS can inherit the Email Relay (sending as %s)' % from_addr)
    else:
        plog('ℹ No Email Relay configured, so ATLAS has nothing to inherit')
    return True


def admin_groups_for(inst=None, global_group=None):
    """The groups that may administer one deployment, most specific first.

    ⚠️ **Both, and in that order.** The agency's own administrators and the
    global administrators are alternatives — never the same person — so
    requiring both would mean nobody, and requiring only the global one would
    turn every agency administrator away from the console Authentik had just
    let them into.

    ⚠️ The plain deployment gets only the global group, exactly as it has. Its
    "agency" is the box, and inventing `atlas-admins` for it would be a group
    nobody is in and a silent lockout on every deployed box.
    """
    names = []
    slug = atlas_instances.derive(inst)['slug']
    if slug:
        names.append(atlas_instances.derive(inst)['admin_group'])
    names.append(global_group or ADMIN_GROUP)
    return names


def global_admin_group(ak_url, ak_headers, plog=None):
    """Authentik's superuser group, by what it *is* rather than what it is called.

    ⚠️ **Resolved, not assumed.** `authentik Admins` is the default name and an
    operator may rename it; every deployment on the box would then require a
    group that does not exist, and the first one to notice would be an
    administrator locked out of the console they would use to fix it. Falls back
    to the name only when the question cannot be asked.
    """
    import urllib.request as _urlreq

    try:
        req = _urlreq.Request(f'{ak_url}/api/v3/core/groups/?page_size=200',
                              headers=ak_headers)
        body = json.loads(_urlreq.urlopen(req, timeout=10).read().decode())
    except Exception:
        return ADMIN_GROUP
    for group in body.get('results', []):
        if group.get('is_superuser'):
            return group.get('name') or ADMIN_GROUP
    return ADMIN_GROUP


def _global_admin_group(ctx):
    """Authentik's superuser group name, or the default when it cannot be asked.

    ⚠️ Wrapped so `deploy` and `_run_update` do not each have to assemble an
    Authentik client to ask one question — and so a box with no Authentik at all
    still gets a sensible value rather than an exception on a path that has
    nothing to do with identity.
    """
    try:
        settings = ctx['load_settings']()
        token = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not token:
            return ADMIN_GROUP
        return global_admin_group(
            ctx['_get_authentik_api_url'](settings),
            {'Authorization': 'Bearer %s' % token,
             'Content-Type': 'application/json'})
    except Exception:
        return ADMIN_GROUP


def remove_agency_admin_group(ctx, inst, plog=None):
    """Delete this deployment's admin group. Returns a note, or None.

    ⚠️ **The counterpart `ensure_agency_admin_group` never had.** Removing a
    deployment deregistered its application and provider and left
    `atlas-<slug>-admins` behind — found on the box with `atlas-testing-admins`
    still present long after that deployment was gone. An orphaned group
    grants nothing, which is precisely why nobody notices it: it accumulates
    one per teardown, and the next deployment that reuses the slug silently
    inherits whatever members the old one had.

    ⚠️ **Matched by exact name, and only for an agency.** The plain
    deployment has no group of its own — it uses the global administrators —
    so a slug-less instance returns immediately. Without that, a teardown of
    the plain deployment could delete the group every agency relies on.

    ⚠️ **Members are reported, not preserved.** The group is this
    deployment's and goes with it; saying how many people were in it is what
    lets an operator put them back somewhere if that was a mistake.
    """
    import urllib.request as _urlreq
    from urllib.parse import quote as _q

    names = atlas_instances.derive(inst)
    if not names['slug']:
        return None
    group_name = names['admin_group']

    try:
        settings = ctx['load_settings']()
        token = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not token:
            return None
        ak_url = ctx['_get_authentik_api_url'](settings)
        headers = {'Authorization': 'Bearer %s' % token,
                   'Content-Type': 'application/json'}

        def api(path, method=None):
            req = _urlreq.Request('%s/api/v3/%s' % (ak_url, path),
                                  headers=headers, method=method)
            body = _urlreq.urlopen(req, timeout=10).read().decode()
            return json.loads(body or '{}')

        found = api('core/groups/?name=%s' % _q(group_name))
        for group in found.get('results', []):
            # ⚠️ Exact match. Authentik's `?name=` is a filter, not an
            # identity, and `atlas-test-admins` must never resolve a teardown
            # of `atlas-testing-admins` — one is a prefix of the other, which
            # is the shape that has bitten this module repeatedly.
            if group.get('name') != group_name:
                continue
            members = len(group.get('users') or [])
            api('core/groups/%s/' % group.get('pk'), method='DELETE')
            note = 'Authentik group "%s" removed' % group_name
            if members:
                note += ' (it had %d member%s)' % (
                    members, '' if members == 1 else 's')
            if plog:
                plog(note)
            return note
        return None
    except Exception as exc:
        if plog:
            plog('⚠ Authentik group "%s" could not be removed: %s'
                 % (group_name, exc))
        return None


def ensure_agency_admin_group(ctx, inst, ak_url, ak_headers, plog=None):
    """Create this deployment's admin group and let it into this deployment.

    Returns the group's name, or None when there is nothing to do (the plain
    deployment) or the work failed.

    ⚠️ **Bound beside "Allow authentik Admins", never instead of it.** Measured
    on the box: the ATLAS applications run with `policy_engine_mode: any`, so
    bindings are alternatives — the global administrators keep their access and
    the agency's gain theirs. Replacing the policy binding would lock the global
    administrator out of every agency console at once.

    ⚠️ **Empty on purpose.** Nobody is put in the group here; that is the
    operator's decision and the only part of this that should be manual.
    """
    import urllib.request as _urlreq

    def log(msg):
        if plog:
            plog(msg)

    names = atlas_instances.derive(inst)
    if not names['slug']:
        return None
    group_name = names['admin_group']

    def api(path, data=None, method=None):
        req = _urlreq.Request(
            f'{ak_url}/api/v3/{path}',
            data=json.dumps(data).encode() if data is not None else None,
            headers=ak_headers, method=method)
        return json.loads(_urlreq.urlopen(req, timeout=10).read().decode() or '{}')

    # --- the group ---------------------------------------------------------- #
    group_pk = None
    try:
        from urllib.parse import quote as _q
        found = api('core/groups/?name=%s' % _q(group_name))
        for group in found.get('results', []):
            if group.get('name') == group_name:
                group_pk = group.get('pk')
                break
    except Exception as exc:
        log('  ⚠ Could not look up the agency admin group: %s' % str(exc)[:80])
        return None

    if group_pk:
        log('  ✓ Admin group "%s" already exists' % group_name)
    else:
        try:
            # ⚠️ `is_superuser` stays false. This group administers one ATLAS,
            # not Authentik — a superuser group would hand every one of its
            # members the identity provider itself.
            group_pk = api('core/groups/', {'name': group_name,
                                            'is_superuser': False},
                           method='POST').get('pk')
            log('  ✓ Admin group "%s" created — add this agency\'s '
                'administrators to it' % group_name)
        except Exception as exc:
            log('  ⚠ Could not create the agency admin group: %s' % str(exc)[:80])
            return None

    # --- and its way in ----------------------------------------------------- #
    try:
        app = api('core/applications/%s/' % names['authentik_slug'])
        target = app['pk']
        bindings = api('policies/bindings/?target=%s&page_size=100' % target)
        if any(str(b.get('group')) == str(group_pk)
               for b in bindings.get('results', [])):
            log('  ✓ "%s" already admitted to this deployment' % group_name)
            return group_name
        api('policies/bindings/', {
            'target': target, 'group': group_pk,
            # ⚠️ After the admins policy, which sits at 0. Order does not decide
            # the outcome under `any`, but it keeps the list readable in
            # Authentik's own UI.
            'order': 10, 'negate': False, 'enabled': True, 'timeout': 30,
        }, method='POST')
        log('  ✓ "%s" admitted to this deployment only' % group_name)
        return group_name
    except Exception as exc:
        log('  ⚠ Could not admit the agency admin group: %s' % str(exc)[:80])
        return None


def _arm_admin_gates(ctx, dirpath, plog, inst=None, global_group=None):
    """Turn on ATLAS's own two admin checks, once it is safe to.

    Both are fail-open in ATLAS while unset, so writing them is what arms them.

    ⚠️ **The proxy-auth secret is written only after confirming the generated
    Caddyfile actually injects the header.** Version skew — this module newer
    than the fork's app.py, or a Caddyfile not regenerated — would otherwise
    hand ATLAS a secret nothing sends, and ATLAS would refuse every admin
    request. The console is the thing an operator would use to fix that, so the
    failure locks them out of its own remedy. Core does the same verification
    for its own gate (`caddy_proxy_auth_gate_v1`); this is that pattern, reused.
    """
    env_path = os.path.join(dirpath, '.env')
    # ⚠️ **Let it raise (W240).** This swallowed the PermissionError from
    # a root-owned `.env` and returned the same False it returns for
    # "nothing needed changing" -- so a deploy that had wired up neither the
    # admin group nor the proxy-auth secret still printed a tick. Every
    # caller reaches this *after* the deploy wrote the file, so an
    # unreadable or missing `.env` here is a fault, not a state to live with.
    with open(env_path, 'r') as f:
        body = f.read()

    changed = False

    # --- H-1: ATLAS checks the group itself, not only Authentik's binding ---
    #
    # ⚠️ A *list* since W221, because an agency deployment has two ways in: its
    # own administrators and the global ones. With a single name ATLAS rejected
    # the agency's administrators with a 403 *after* Authentik had let them
    # through — the confusing half of a lockout, where the proxy says yes and
    # the application says no.
    wanted = ','.join(admin_groups_for(inst, global_group))
    if 'TAKMDM_ADMIN_GROUP=' + wanted not in body:
        lines = [l for l in body.splitlines()
                 if not l.startswith('TAKMDM_ADMIN_GROUP=')]
        lines.append('')
        lines.append('# SEC_AUDIT (ATLAS) H-1. The Authentik application binding is the')
        lines.append('# first gate; this makes ATLAS check as well, so the binding being')
        lines.append('# removed is a lockout rather than a silent promotion of everyone.')
        lines.append('#')
        lines.append('# Any one of these is sufficient (ATLAS >= 1.49.0). The agency\'s own')
        lines.append('# administrators and the global ones are alternatives, never the')
        lines.append('# same person.')
        lines.append('TAKMDM_ADMIN_GROUP=' + wanted)
        body = '\n'.join(lines) + '\n'
        changed = True
        plog('✓ ATLAS will require membership of %s'
             % ' or '.join('"%s"' % n for n in admin_groups_for(inst, global_group)))

    # --- S-1: prove the identity headers came through Caddy -----------------
    if 'TAKMDM_PROXY_AUTH_SECRET=' not in body:
        secret = _proxy_auth_secret(ctx)
        injects = _caddyfile_injects_proxy_auth()
        if secret and injects:
            body = body.rstrip('\n') + '\n\n'
            body += '# SEC_AUDIT (ATLAS) S-1. Caddy attaches this only after forward_auth\n'
            body += '# passes, so a forged X-Authentik-Username from any process on this\n'
            body += '# host is refused. The peer check cannot do this: Caddy reaches the\n'
            body += '# container through the same bridge gateway everything else does.\n'
            body += 'TAKMDM_PROXY_AUTH_SECRET=' + secret + '\n'
            changed = True
            plog('✓ Admin requests must now carry the proxy-auth header')
        elif not injects:
            # ⚠️ Reported, never armed. Arming here is the lockout.
            plog('⚠ The Caddy vhost does not inject X-Infratak-Proxy-Auth, so the')
            plog('  header check stays off. ATLAS is no worse off than before; it')
            plog('  simply cannot tell a forged identity header from a real one.')
        else:
            # ⚠️ **Caddy injects and we could not read the secret. Stop.**
            #
            # This branch did not exist, and its absence was a live hole rather
            # than an oversight: nothing was logged, `TAKMDM_PROXY_AUTH_SECRET`
            # was never written, and the vhost attached the header regardless —
            # so the deploy read as armed while ATLAS had no way to tell a
            # forged `X-Authentik-Username` from a real one. Any local process
            # could reach the container through the bridge gateway, which
            # `TAKMDM_TRUSTED_PROXIES` admits, and be an administrator.
            #
            # ⚠️ **Fatal, not a warning, and only in this exact case.** A
            # console with no proxy-auth feature at all does not inject, and is
            # handled above — so this cannot fire on a legitimately
            # secret-less install. Reaching here means the console has the
            # feature, Caddy is using it, and the module cannot find the file:
            # a misconfiguration whose only symptom would otherwise be a
            # security property silently absent.
            searched = ', '.join(_proxy_auth_secret_path(ctx))
            raise RuntimeError(
                'The Caddy vhost injects X-Infratak-Proxy-Auth but this module '
                'could not read the console\'s shared secret, so ATLAS would '
                'accept forged identity headers from any process on this host. '
                'Looked in: ' + searched + '. Refusing to continue.')

    if changed:
        with open(env_path, 'w') as f:
            f.write(body)
    return changed


def _proxy_auth_secret_path(ctx=None):
    """Where the console keeps the shared secret.

    ⚠️ **From `ctx['CONFIG_DIR']` first, because guessing got it wrong.**
    This asked `/root/infra-TAK/.config/proxy_auth.json` and the console's file
    is under `CONFIG_DIR`, which is `$CONFIG_DIR` or `<console>/.config`. On a
    standard install the guess missed, the helper returned `''`, and the gate
    it arms was never armed — see [_arm_admin_gates] for what that cost.

    The fallback is derived from **this file's own location** rather than from
    a hardcoded home. `modules/atlas.py` sits one directory below the console,
    so `../.config` is the same place `CONFIG_DIR` defaults to, whichever user
    the console runs as and wherever it is installed. `ctx` carries the key
    from v10.1.80; ours at v10.1.76 does not, so both paths are tried.
    """
    from_ctx = (ctx or {}).get('CONFIG_DIR')
    if from_ctx:
        yield os.path.join(from_ctx, 'proxy_auth.json')
    console = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    yield os.path.join(console, '.config', 'proxy_auth.json')


def _proxy_auth_secret(ctx=None):
    """The shared secret the console generates, or '' when it has none.

    ⚠️ `''` means *could not read it*, which is not the same as *this console
    has no such feature*. The caller tells them apart by asking whether the
    Caddyfile injects the header, and refuses to continue when it does.
    """
    read_priv = (ctx or {}).get('_read_priv')
    for candidate in _proxy_auth_secret_path(ctx):
        for reader in (lambda pth: open(pth).read(), read_priv):
            if reader is None:
                continue
            try:
                # ⚠️ Plain read first, brokered second. The console owns this
                # file, so the direct read is the normal path; `_read_priv`
                # covers a console whose config directory it cannot traverse
                # as itself, and costs a broker round trip only when it must.
                return (json.loads(reader(candidate)).get('secret') or '').strip()
            except Exception:
                continue
    return ''


def _caddyfile_injects_proxy_auth():
    """Does the generated vhost actually attach the header to ATLAS traffic?

    ⚠️ Checked against the **ATLAS** block, not the file as a whole. The
    console's own injection has been there for releases; matching on that would
    report success for a fork whose ATLAS vhost has no such line, which is
    exactly the version skew this exists to catch.
    """
    try:
        with open('/etc/caddy/Caddyfile') as f:
            body = f.read()
    except OSError:
        return False
    marker = 'request_header X-Infratak-Proxy-Auth'
    for block in body.split('# ATLAS MDM'):
        if 'reverse_proxy 127.0.0.1:%d' % APP_PORT in block and marker in block:
            return True
    return False


def _set_trusted_proxies(dirpath, plog, project='takmdm'):
    """Make `.env` name the addresses the admin interface answers. Returns True
    when it changed, so the caller knows the container needs recreating.

    Handles three states, and the third is the one a fresh install lands in:

    * **Absent** — a box installed before this existed. Appended. ⚠️ The update
      path does not rewrite `.env`, so without this such a box would keep
      accepting an identity header from anywhere for ever.
    * **The fallback** — written at install time, when the Docker network did not
      exist yet and the subnet could not be read. Narrowed to the real one now
      that it can.
    * **Anything else** — left alone. That is either an operator's own value or a
      subnet we already detected, and neither is ours to overwrite.
    """
    env_path = os.path.join(dirpath, '.env')
    # ⚠️ **Let it raise (W240).** This swallowed the PermissionError from
    # a root-owned `.env` and returned the same False it returns for
    # "nothing needed changing" -- so a deploy that had wired up neither the
    # admin group nor the proxy-auth secret still printed a tick. Every
    # caller reaches this *after* the deploy wrote the file, so an
    # unreadable or missing `.env` here is a fault, not a state to live with.
    with open(env_path, 'r') as f:
        body = f.read()

    detected = _bridge_gateway(project)

    if 'TAKMDM_TRUSTED_PROXIES' not in body:
        with open(env_path, 'a') as f:
            f.write('\n# Added by the ATLAS module (SEC_AUDIT.md S-1).\n')
            f.write('TAKMDM_TRUSTED_PROXIES=%s\n' % detected)
        plog('✓ Restricted the admin interface to %s' % detected)
        return True

    # ⚠️ Only ever the exact fallback string is replaced. Matching loosely — on
    # the key alone, say — would overwrite a value an operator had narrowed or
    # widened deliberately, through a deploy they ran for an unrelated reason.
    stale = 'TAKMDM_TRUSTED_PROXIES=%s' % _TRUSTED_FALLBACK
    if stale in body and detected != _TRUSTED_FALLBACK:
        body = body.replace(stale, 'TAKMDM_TRUSTED_PROXIES=%s' % detected, 1)
        with open(env_path, 'w') as f:
            f.write(body)
        plog('✓ Narrowed the admin interface to %s' % detected)
        return True

    return False


#: Settings keys recording whether Authentik still restricts the ATLAS app.
#: ⚠️ These stay the *plain* deployment's keys, unchanged, because they are what
#: every deployed box already has on disk. `access_keys` derives the rest.
ACCESS_KEY = KEY + '_access_restricted'
ACCESS_CHECKED_KEY = KEY + '_access_checked_at'


def access_keys(inst=None):
    """Where one deployment's access-control answer is recorded.

    ⚠️ **One key for N deployments would be a lie that reads as reassurance.**
    Each deployment has its own Authentik application and its own policy
    binding, so "restricted" is a per-deployment fact. Sharing the key would let
    a correctly restricted agency overwrite a *false* written moments earlier
    for another one — and the tile would go green while an MDM console stayed
    open to every authenticated user, which is exactly the failure H-1 exists
    for.
    """
    prefix = atlas_instances.derive(inst)['settings_prefix']
    return prefix + 'access_restricted', prefix + 'access_checked_at'


def access_state(ctx, settings=None):
    """The box-level answer across every deployment: True, False, or None.

    ⚠️ **Any deployment being unrestricted makes the box unrestricted.** The
    warning is about an MDM console reachable by anyone authenticated; a second,
    correctly restricted deployment does not make the first one safe.

    ⚠️ **Unknown is not restricted.** A deployment nobody has checked reports
    None, and None must not average into True — that would report an access
    control that has never been verified as verified.
    """
    s = settings if settings is not None else ctx['load_settings']()
    found = load_instances(ctx)
    if not found:
        # A box from before the instance list: the plain keys are all there is.
        return s.get(ACCESS_KEY)
    values = [s.get(access_keys(i)[0]) for i in found]
    if any(v is False for v in values):
        return False
    if values and all(v is True for v in values):
        return True
    return None


def unrestricted_deployments(ctx, settings=None):
    """The deployments known to be unrestricted, by name, for the warning.

    Named rather than counted: on a box with five agencies, "one of them is
    open" is not something an operator can act on.
    """
    s = settings if settings is not None else ctx['load_settings']()
    return [atlas_instances.derive(i)['name'] for i in load_instances(ctx)
            if s.get(access_keys(i)[0]) is False]


def _record_access_state(ctx, restricted, plog=None, inst=None):
    """Remember whether the ATLAS application is bound to an access policy.

    ⚠️ **Stored rather than probed on demand.** `detect()` runs on every dashboard
    poll, from several threads, and must answer in under a second — an Authentik
    API call there would make the whole console's tile refresh depend on
    Authentik's latency, and a slow identity provider would read as ATLAS being
    down. So the expensive check happens where there is already a job and a log:
    deploy and update.
    """
    import time as _time
    try:
        s = ctx['load_settings']()
        restricted_key, checked_key = access_keys(inst)
        s[restricted_key] = bool(restricted)
        s[checked_key] = int(_time.time())
        ctx['save_settings'](s)
    except Exception as exc:
        if plog:
            plog('  ⚠ Could not record the access-control state: %s' % str(exc)[:80])
        return restricted

    if plog:
        if restricted:
            plog('  ✓ Verified: the ATLAS application is restricted to Authentik admins')
        else:
            plog('  ✗ ATLAS IS NOT ACCESS-RESTRICTED. Every authenticated Authentik')
            plog('    user can reach the console — remote wipe, factory reset, policy')
            plog('    push. Fix: Authentik → Reconfigure, then redeploy ATLAS.')
    return restricted


def _verify_access_control(ctx, plog=None, inst=None):
    """Re-run the binding check outside a deploy. Returns True/False/None.

    None means the question could not be asked — no Authentik, no token, no
    network. ⚠️ That is deliberately not the same as False: reporting "not
    restricted" because Authentik was briefly unreachable would train an operator
    to ignore the one message that matters.
    """
    try:
        s = ctx['load_settings']()
        fqdn = ctx['_get_authentik_env_value'](s, 'AUTHENTIK_FQDN') or ''
        token = (ctx['_get_authentik_env_value'](s, 'AUTHENTIK_TOKEN') or
                 s.get('authentik_api_token') or '')
        if not fqdn or not token:
            return None
        ak_url = ctx['_get_authentik_api_url'](s)
        headers = {'Authorization': 'Bearer %s' % token,
                   'Content-Type': 'application/json'}
        app_slug = atlas_instances.authentik_names(inst)['app_slug']
        return _record_access_state(
            ctx, _restrict_to_admins(ak_url, headers, plog=plog,
                                     app_slug=app_slug),
            plog=plog, inst=inst)
    except Exception as exc:
        if plog:
            plog('  ⚠ Could not verify access control: %s' % str(exc)[:80])
        return None


def _pki_dir(ctx=None, inst=None):
    """Where one deployment keeps its PKI, or None if it is not here.

    ⚠️ **Per deployment, because the CAs are.** Every deployment issues its own
    device certificates from its own root — that is the separation the whole
    agency model rests on — and this probed `/root/atlas/pki` whatever it was
    asked about. On a box whose only deployment is an agency it answered None,
    so the console reported *"ATLAS is not installed here"* over a healthy,
    split certificate authority.

    ⚠️ The two legacy locations are still probed for the *plain* deployment: a
    checkout that predates `install_base` lives at one of them, and dropping the
    probe would strand its CA.
    """
    candidates = [posixpath.join(instance_paths(ctx, inst)['dir'], 'pki')]
    if not atlas_instances.derive(inst)['slug']:
        # ⚠️ `posixpath`, not `os.path`. These are paths on the box, and on a
        # development machine `os.path.join` produces a separator no box uses —
        # which has bitten this module before.
        candidates += [posixpath.join('/root/atlas', 'pki'),
                       posixpath.join(os.path.expanduser('~/atlas'), 'pki')]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return None


def recovery_filename(settings, inst=None):
    """What the saved root key is called on the operator's disk.

    ⚠️ **It names the deployment, and that is the whole point.** Every
    deployment on a box produced `atlas-recovery-<fqdn>.key` — the same name —
    so three agencies meant three files distinguished only by the browser's
    `(1)` and `(2)`. A mislabelled recovery file is indistinguishable from the
    right one until the day it is needed, which is five years out, during an
    outage, when `ca-verify-root` rejects it and nothing says which of the three
    it should have been.
    """
    host = (settings or {}).get('fqdn') or 'server'
    return '%s-%s.key' % (atlas_instances.derive(inst)['name'], host)


#: `ca-status` answers, by deployment name, with the time they were read.
#: ⚠️ **A `docker compose exec` per deployment on every poll is far dearer
#: than the `stat` this replaced**, and the deployments route reads it each
#: time. The TTL is short because the answer only changes when somebody runs
#: the ceremony or deletes the root key, and both of those go through this
#: console and clear the entry explicitly.
_ca_status_cache = {}
CA_STATUS_TTL = 30.0


def _forget_ca_status(inst=None):
    """Drop a cached answer, or all of them. Call after changing a CA."""
    if inst is None:
        _ca_status_cache.clear()
    else:
        _ca_status_cache.pop(atlas_instances.derive(inst)['name'], None)


def _ca_status(ctx, inst=None, use_cache=True):
    """What the deployment says about its own certificate authority, or None.

    ⚠️ **Asked of the container, because the console cannot answer it.**
    `pki/` is `drwx------` owned by the container's uid, so every
    `os.path.exists()` inside it returns False for the console while the file
    is sitting there. Three call sites believed that answer, and the worst of
    them told the operator no root key was on the server while three were.

    The container runs as the user that owns those files, so it can simply
    look. None means it could not be asked -- not running, or not answering
    -- which is a different thing from "no", and callers must keep it
    different.
    """
    name = atlas_instances.derive(inst)['name']
    now = time.time()
    if use_cache:
        hit = _ca_status_cache.get(name)
        if hit and now - hit[0] < CA_STATUS_TTL:
            return hit[1]
    raw = _compose_exec(ctx, ['python', '-m', 'app.cli', 'ca-status'], inst=inst)
    if raw is None:
        return None
    try:
        body = json.loads(raw)
    except Exception:
        return None
    _ca_status_cache[name] = (now, body)
    return body


def root_key_holders(ctx, projects=None):
    """Deployments whose CA root key is still on this server, by name.

    ⚠️ **The one job an operator has, and the one the console has to keep
    asking.** While that key is here, anyone who reaches this machine can
    impersonate any of that deployment's devices, and the only remedy is setting
    every tablet up again. With several deployments the prompt has to be a list:
    a per-deployment banner is easy to scroll past, and the box-level question —
    "is there a root key on this server at all" — is the one that matters.

    Best effort: a deployment that is not running cannot be asked, and is
    reported as unknown rather than as safe.
    """
    holders, unknown = [], []
    # ⚠️ Reuses the caller's `docker ps` when it has one. This is read on every
    # poll of the deployments route, and a second process listing per poll would
    # make the page slower the more agencies a box has.
    if projects is None:
        projects = compose_projects_present(ctx)
    for inst in load_instances(ctx):
        name = atlas_instances.derive(inst)['name']
        if not instance_is_built(ctx, inst, projects):
            continue
        # ⚠️ **Asked of the deployment, never stat'd (W235).** This read
        # `os.path.exists(pki/ca.key)` as the console, and `pki/` is
        # `drwx------` owned by the container's uid: the answer was False for
        # every deployment on a non-root box, whatever was actually there.
        # Measured on 2026-09-19 with three root keys on disk, this returned
        # `{'holders': [], 'unknown': []}` -- the console asserting the safe
        # state while the dangerous one was true, which is the one direction
        # this function must never be wrong in.
        status = _ca_status(ctx, inst=inst)
        if status is None:
            unknown.append(name)
            continue
        # ⚠️ The key file, not `is_split`. Those two come apart in exactly the
        # state this is for: an intermediate exists *and* the root is still
        # here (SEC_AUDIT S-2 / W185).
        if status.get('root_key_on_server'):
            holders.append(name)
    return {'holders': holders, 'unknown': unknown}


def _write_own(path, body, perm=0o644):
    """Write a file in the console's **own** directory. Raises on failure.

    ⚠️ **Not `_write_priv` (W240).** That seam writes as root and does not
    chown, so a file it creates under `<home>/atlas/<slug>/` comes out
    `root:root` and the console cannot read its own deployment's `.env`
    afterwards. Everything downstream then failed silently. `_write_priv`
    is for paths the console does not own -- `/etc`, `/var/lib/caddy`.

    ⚠️ The mode is set on the descriptor, not after the write, so there is
    no window where `.env` -- which carries the database password and the
    proxy-auth secret -- is readable by anyone who happens to look.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, perm)
    except PermissionError:
        # ⚠️ **Every deployment built before this fix has a root-owned
        # `.env`, and the fix alone cannot rewrite one.** Without this, the
        # change turns a silent failure into a hard one: the next update of
        # an existing deployment stops with `PermissionError` and the
        # operator has a stranded install and no obvious remedy.
        #
        # The console owns the *directory*, and unlink needs write on the
        # directory rather than on the file -- measured on the box -- so it
        # can clear the old one and create a fresh one it owns. No broker
        # needed, and nothing else in the tree is touched.
        os.unlink(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, perm)
    try:
        os.write(fd, body.encode('utf-8'))
    finally:
        os.close(fd)
    # An existing file keeps its old mode through O_CREAT, so say it again.
    os.chmod(path, perm)


def _repair_env_ownership(env_path, ctx, plog=None):
    """Give a root-owned `.env` back to the console. True if it repaired one.

    ⚠️ **Without this, W240 turned a silent failure into a stranded
    deployment.** Every deployment built before that fix has a `root:root`
    `.env`; the fix made the three readers raise instead of returning False,
    and `_run_update` calls all three. So an update of an existing
    deployment stopped dead with a `PermissionError` and the only way out
    was a full re-deploy — on the exact population that has the bug.

    `deploy` repairs it as a side effect, because `_write_own` rewrites the
    file wholesale. An update never rewrites it -- `write_env_value` edits
    single lines -- so the repair has to be explicit here.

    ⚠️ **The content is preserved exactly, through the broker.** It carries
    the database password: regenerating it from the template would need
    every value deploy had, and getting one wrong silently is worse than the
    bug. The broker can read what the console cannot, and the console owns
    the *directory*, so it can unlink and recreate.
    """
    if os.access(env_path, os.R_OK):
        return False

    reader = (ctx or {}).get('_read_priv')
    if reader is None:
        return False
    try:
        body = reader(env_path)
    except Exception:
        return False
    if not body:
        # ⚠️ Not repairable, and not ours to guess at. Let the reader that
        # follows raise, which says plainly which file and why.
        return False

    os.unlink(env_path)
    _write_own(env_path, body, 0o600)
    if plog:
        plog('  ✓ .env handed back to the console (it was root-owned by an '
             'earlier release)')
    return True


def _write_root_key(path, pem, ctx=None, inst=None):
    """Put the root key on disk for the length of one command. Error, or None.

    ⚠️ Created 0600, never world-readable for an instant — the same
    reasoning as ATLAS's own key writer. A window on *this* key is the worst
    one in the system.

    ⚠️ **It goes into `pki/`, which the console can neither write nor
    read (W235).** That directory is `drwx------` owned by the container's
    uid, so the plain `os.open` this used raised `PermissionError` and
    supplying a root key by hand could not work at all on a non-root box.

    ⚠️ **The uid claim this carried was false.** It said "the container
    now runs as this console's uid, so a file the console creates is already
    readable by the only process that needs it" — and the code rested on it.
    Measured on the box 2026-09-19: the container is uid 1000 (`APP_UID`),
    the console is 997. The ceremony reads this file *inside* the container,
    so it has to be handed over, which is why the chown is back. It is the
    brokered one, so the `EPERM` that made W230 remove it does not return.
    """
    body = pem if pem.endswith(chr(10)) else pem + chr(10)
    if _running_as_root():
        # ⚠️ **`O_NOFOLLOW`, and the chown on the fd, not the path (W240).**
        # A root-era console writes here as uid 0 into `pki/`, which the
        # *container* owns. A compromised container that plants
        # `pki/ca.key -> /etc/<target>` gets root to truncate and overwrite
        # that target on the next "renew with a supplied key". `O_EXCL`
        # alone does not close it: the symlink is the final component, and
        # without `O_NOFOLLOW` the open resolves through it.
        #
        # Broker boxes were already covered -- `_do_write` opens console-owned
        # prefixes `O_NOFOLLOW` and checks realpath containment. This is the
        # same protection for the console that has no broker.
        fd = os.open(path,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
                     0o600)
        try:
            os.write(fd, body.encode())
            # On the descriptor, so nothing can be swapped underneath between
            # the write and the handover.
            os.fchown(fd, APP_UID, APP_GID)
        finally:
            os.close(fd)
        return None

    writer = (ctx or {}).get('_write_priv')
    if writer is None:
        return ('no privileged writer available to stage the root key; this '
                'console is neither root nor has a broker.')
    try:
        # ⚠️ **`perm`, not `mode`.** The seam is
        # `_write_priv(path, content, mode='w', perm=None)`: `mode` is the
        # *open* mode and `perm` is the permission bits. W235 passed
        # `mode=0o600`, which corrupted the open mode and left `perm` unset,
        # so the broker wrote the root key at its default 0644 --
        # world-readable, and this is the one file in the system where that
        # matters most. Found on the box, on a real ceremony.
        #
        # ⚠️ The broker opens console-owned prefixes `O_NOFOLLOW` and checks
        # realpath containment, so the symlink hardening the root branch does
        # by hand is already done for us here.
        writer(path, body, perm=0o600)
    except Exception as exc:
        return 'could not stage the key: %s' % exc

    err = _chown_priv(path, APP_UID, APP_GID)
    if err:
        # ⚠️ Staged but unreadable by the process that needs it. Leaving it
        # there would be the exposure with none of the benefit.
        _shred(path, ctx, inst)
        return 'could not hand the staged key to the container: %s' % err
    return None


def _shred(path, ctx=None, inst=None):
    """Remove the root key. True only when it is really gone.

    ⚠️ **This used to end in `return not os.path.exists(path)`, and that is
    `True` for a file the console cannot see (W237).** `pki/` is `drwx------`
    owned by the container's uid, so the stat is False whatever is there, the
    negation is True, and the operator was told *"Root key removed from the
    server"* over a key still sitting on disk. Found on the box, on a real
    ceremony. It is W185 through a different door: the console asserting the
    root is gone when it is not, which is the single claim this subsystem
    exists to get right.

    So the answer comes from the deployment itself. `ca-status` reports
    `root_key_on_server`, the container can see its own files, and that is
    the only reading of "gone" worth returning.

    ⚠️ **Overwriting is not secure erasure** and is not claimed to be: on a
    journaling or copy-on-write filesystem the original blocks survive. It is
    done where it is free -- a root-era console owns the file -- and skipped
    through the broker, where it would be an extra privileged write buying
    nothing the removal does not already buy. The honest position is
    unchanged: the root key touched this machine, and the ceremony can only
    shorten that, never undo it.
    """
    broker = _broker_script()
    try:
        if broker is None:
            # Root-era: the console owns it, so overwrite and unlink directly.
            if os.path.exists(path):
                size = os.path.getsize(path)
                with open(path, 'r+b') as fh:
                    fh.write(b'\0' * size)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.unlink(path)
            return not os.path.exists(path)

        # ⚠️ `rm -f`, so there is no existence check to get wrong: it
        # succeeds on a file that was never there.
        rc, out = _run_root(['python3', broker, 'exec', '--', 'rm', '-f', path],
                            timeout=60)
        if rc != 0:
            print('[' + KEY + '] could not remove the root key: '
                  + (out or '').strip()[:200], flush=True)
            return False
    except Exception as exc:
        print('[' + KEY + '] could not remove the root key: ' + str(exc), flush=True)
        return False

    # ⚠️ **Verified by asking, never by statting.** A removal that returns 0
    # and a key that is gone are not the same claim, and this function's whole
    # job is the second one.
    status = _ca_status(ctx, inst=inst, use_cache=False)
    if status is None:
        print('[' + KEY + '] removed the root key but could not confirm it: '
              + 'the deployment did not answer', flush=True)
        return False
    return not status.get('root_key_on_server')


def _compose_exec(ctx, argv, timeout=60, stdin=None, inst=None):
    """Run a command inside the API container. Returns its output, or None.

    ⚠️ `stdin` exists so the recovery file can be checked **without ever being
    written to this host's disk**. `docker exec -i` pipes it straight into the
    process; the alternative — a temp file plus a shred afterwards — puts the
    root key on the filesystem for the length of a command, which is the exposure
    this whole feature exists to remove.
    """
    argv = list(argv)
    flags = ['-i'] if stdin is not None else []
    # ⚠️ Each deployment has its own container, named from its compose project.
    # `API_CONTAINER` is the plain one, so an agency exec would land in another
    # deployment's database — or, more often, in nothing at all.
    container = api_container(ctx, inst)
    try:
        r = subprocess.run(
            ['docker', 'exec'] + flags + [container] + argv,
            capture_output=True, text=True, timeout=timeout,
            input=stdin if stdin is not None else None,
        )
    except Exception:
        return None
    if r.returncode != 0 and not (r.stdout or '').strip():
        return None
    return (r.stdout or '') + (r.stderr or '')


def _compose_exec_rc(ctx, argv, timeout=60, stdin=None, inst=None):
    """Same, but the caller needs the exit status rather than the text.

    `_compose_exec` collapses failure into None, which suits a status read and
    not a yes/no question: `ca-verify-root` answers by exit code, and "did not
    run" must not look like "the key does not match".
    """
    argv = list(argv)
    flags = ['-i'] if stdin is not None else []
    try:
        r = subprocess.run(
            ['docker', 'exec'] + flags + [api_container(ctx, inst)] + argv,
            capture_output=True, text=True, timeout=timeout,
            input=stdin if stdin is not None else None,
        )
    except Exception as exc:
        return None, str(exc)
    return r.returncode, ((r.stdout or '') + (r.stderr or '')).strip()


# ⚠️ Imported rather than re-implemented. `modules/__init__.py` calls this "the
# 12-copy pattern, one copy" — adding a thirteenth is how a security check drifts.
# It is the module package this file lives in, not `app.py`, so rule 10 holds.
from modules import _check_admin_password  # noqa: E402


def _plog(msg):
    job_log(KEY, msg)


def install_base(ctx=None):
    """The directory ATLAS deployments live under: `/root` or the console's home.

    ⚠️ Two layouts, and the difference is not cosmetic. A console born
    unprivileged keeps modules under its own home; a box flipped from root keeps
    them at `/root`. Guessing wrong means a deploy that "succeeds" against an
    empty directory while the real install sits elsewhere.

    ⚠️ **One box, one layout — the probe is not per instance.** A new agency
    has no checkout yet, so it cannot be asked where it lives; it goes wherever
    the deployments that already exist do. Any `atlas*` checkout under `/root`
    settles it, which is why the glob is wider than the plain instance: a box
    holding only agency deployments must still resolve to `/root`.

    ⚠️ **On a converted box the probe cannot tell "empty" from "not allowed
    to look", and it must not have to.** `/root` is `drwx------`; measured as
    `takwerx`, the glob returns `[]` and `os.path.isdir('/root/atlas-corona')`
    is `False` while both deployments are up and serving. So this answers the
    home — which is right for anything *new* — and the question "is something
    already running somewhere I cannot reach" is answered separately by
    [stranded_deployments], which asks Docker instead of the filesystem.
    Without that split, a box converted from root reads as having no ATLAS at
    all and the next deploy builds a second one on top of the first.

    ⚠️ **`expanduser` reads `HOME`, not passwd, and that is what makes this
    work.** The console user's passwd home is `/nonexistent`; its *environment*
    carries `HOME=/home/takwerx`, which is also the convention every other
    module follows on disk and the one the broker allowlists.
    """
    if _glob(posixpath.join('/root', KEY + '*', '.git')):
        return '/root'
    # ⚠️ **Both layouts, because the probe outlives the move (W233).**
    # Nested checkouts are `/root/atlas/<slug>/.git`, which `atlas*/.git`
    # does not match -- it only sees the pre-nesting siblings. A box whose
    # deployments had all been redeployed into the new layout would read as
    # having no ATLAS at all and answer the home directory, and the next
    # deploy would build a second copy there.
    if _glob(posixpath.join('/root', KEY, '*', '.git')):
        return '/root'
    return os.path.expanduser('~')


def instance_is_stranded(ctx, inst, projects=None):
    """Containers running, and the console cannot reach their directory.

    ⚠️ **The signature of a box converted from root to non-root.** The
    deployment keeps serving — Docker does not care who the console is — while
    `/root/atlas-*` becomes unreadable to it. Every filesystem question then
    answers as though nothing is installed, which is the dangerous reading:
    `instance_is_built` says False, the page offers to deploy, and the deploy
    would build a second copy under the home with the same compose project,
    the same ports and the same database volume name as the one still running.

    Docker is the authority here precisely because it is the one thing the
    unprivileged console can still ask.
    """
    paths = instance_paths(ctx, inst)
    known = projects if projects is not None else compose_projects_present(ctx)
    return paths['compose_project'] in known and not os.path.isdir(paths['dir'])


def stranded_deployments(ctx):
    """Every recorded deployment whose containers we can see and files we cannot."""
    projects = compose_projects_present(ctx)
    return [inst for inst in load_instances(ctx)
            if instance_is_stranded(ctx, inst, projects)]


#: The one directory every deployment lives inside.
#:
#: ⚠️ The name matters: it is what the broker allowlists, and what its
#: real-path containment check measures against.
ATLAS_ROOT_DIRNAME = KEY

#: The plain deployment's folder inside it. A slug can never be this —
#: `validate_slug` refuses the reserved list, and a collision here would put
#: an agency on top of the plain deployment.
PLAIN_DIRNAME = 'default'


def atlas_root(ctx=None):
    """The directory holding every deployment on this box."""
    return posixpath.join(install_base(ctx), ATLAS_ROOT_DIRNAME)


def atlas_dir(ctx=None):
    """Where the **plain** ATLAS deployment is installed.

    ⚠️ **One argument, deliberately.** Every existing call site and every test
    double passes exactly one, and widening the signature broke 33 of them at a
    stroke — which was the right signal: agency paths belong in
    `instance_paths`, not here. This answers one question and keeps answering
    it the way it always has.

    ⚠️ **It is no longer `<base>/atlas` (W233).** That path is now the
    *root* holding every deployment; the plain one sits inside it like any
    other. Asking `atlas_root` for the plain deployment's files would hand
    back the directory that contains all of them — and `remove_store` would
    then delete the lot.
    """
    return posixpath.join(atlas_root(ctx), PLAIN_DIRNAME)


def _compose_argv(ctx, *action, inst=None):
    paths = instance_paths(ctx, inst)
    argv = ['docker', 'compose', '--project-directory', paths['dir']]
    if paths['slug']:
        # ⚠️ Only for agencies. The plain deployment takes its project name from
        # the compose file exactly as before, so its argv is unchanged — and an
        # unchanged argv is what keeps a running deployment running.
        argv += ['-p', paths['compose_project']]
    return argv + list(action)


def compose_error(result, what='docker compose'):
    """What a failed compose run actually said, or an honest admission.

    ⚠️ **`stderr` alone loses the error.** Measured on the box 2026-09-18: a
    deploy failed at step 4 and logged `docker compose up failed:` with nothing
    after the colon, because compose had written the reason to **stdout** and
    the message only read `stderr`. An operator was left with a failure that
    explained nothing, and so was the next person to look at the journal.

    ⚠️ The exit code is always included. When both streams are empty — compose
    killed from outside, for instance — the code is the only fact there is, and
    "said nothing" is worth saying out loud rather than rendering as a blank.
    """
    rc = getattr(result, 'returncode', None)
    # stderr first: compose puts progress on stdout and diagnostics on stderr
    # when it has both, so the diagnostic is the more useful tail.
    for stream in ((result.stderr or ''), (result.stdout or '')):
        text = stream.strip()
        if text:
            return '%s failed (exit %s):\n%s' % (what, rc, text[-1500:])
    return ('%s failed (exit %s) and wrote nothing to either stream. That '
            'usually means it was stopped from outside — check whether the '
            'deployment was removed or the console restarted while it ran.'
            % (what, rc))


def _compose(ctx, action, timeout=180, inst=None):
    """Run `docker compose <action>` in the install directory, via the broker.

    ⚠️ **`action` is a string, not argv.** `_broker_compose` does
    `shlex.split(action)` on it, so a list arrives as a file-like object and
    dies with `'list' object has no attribute 'read'` — an error that names
    neither compose nor the argument that was wrong. `control_map` is the
    opposite: the registry sudo-wraps and runs that one itself, so it takes a
    real argv list. Two neighbouring seams, two conventions.
    """
    paths = instance_paths(ctx, inst)
    if paths['slug']:
        # `-p` is a global flag, so it goes before the subcommand. The broker
        # shlex-splits `action` and appends it after `--project-directory`,
        # which is exactly where this needs to land.
        action = f"-p {paths['compose_project']} " + action
    return ctx['_broker_compose'](paths['dir'], action, timeout=timeout)


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #


def detect(ctx):
    """Whether ATLAS is installed here, and whether it is up.

    ⚠️ **Installed is a settings flag, not a directory.** The console may be
    running unprivileged and cannot read a root-owned install dir; a filesystem
    probe would report a working deployment as absent.

    ⚠️ **Running probes the API container only.** There was once a loopback port
    to curl; it is gone on purpose (it bypassed mutual TLS), and a probe against
    it would make this module report itself down forever.
    """
    s = ctx['load_settings']()
    enabled = bool(s.get(f'{KEY}_enabled'))
    # ⚠️ Every *built* deployment, not `takmdm-api-1`. A box running only an
    # agency reported ATLAS down while its console was serving, and one agency
    # stopped out of five would have reported ATLAS up.
    #
    # ⚠️ Unfinished deployments are excluded rather than counted as down. They
    # have no containers by definition, so including them would pin the tile to
    # "not running" until the operator either finished or forgot them — which is
    # a different message, and one the page already shows.
    # ⚠️ No `probe_version` here. See `instance_status`: this must answer in
    # under a second, and an HTTP round-trip per deployment would make ATLAS's
    # tile report its own containers' latency.
    statuses = [instance_status(ctx, i, compose_projects_present(ctx))
                for i in load_instances(ctx)]
    live = [st for st in statuses if st['built']]
    running = bool(live) and all(st['running'] for st in live)

    # Self-heal: the container is up but the flag was lost (a settings file
    # restored from before the install, most often). Trust the container.
    if running and not enabled:
        s = ctx['load_settings']()
        s[f'{KEY}_enabled'] = True
        ctx['save_settings'](s)
        enabled = True

    # The version comes from the checkout, so the tile cannot disagree with the
    # footer of the console it is describing.
    # ⚠️ Read from settings, never probed here. This function runs on every
    # dashboard poll from several threads and must answer in under a second; an
    # Authentik round-trip would make ATLAS's tile report Authentik's health.
    # False is only ever written by a check that actually ran (H-1).
    # ⚠️ Across every deployment, not just the plain one. A box running only
    # an agency deployment wrote its answer under `atlas_<slug>_*`, so reading
    # the plain key alone reported None — "never checked" — for a deployment
    # that had just been checked.
    restricted = access_state(ctx, s)
    open_names = unrestricted_deployments(ctx, s) if restricted is False else []

    return {'installed': enabled, 'running': running,
            'version': _installed_version(ctx) if enabled else None,
            'access_restricted': restricted,
            'warning': (None if restricted is not False else
                        'Not access-restricted: every Authentik user can reach '
                        + (', '.join(open_names) or 'this console') +
                        '. Re-run Authentik → Reconfigure, then '
                        'redeploy ATLAS.')}


# --------------------------------------------------------------------------- #
# Deploy
# --------------------------------------------------------------------------- #


def deployment_identity(ctx, inst, settings):
    """Every name and number a deploy configures itself with.

    ⚠️ **One function, because the failure mode is a deploy that half-knows
    which deployment it is.** `deploy` already resolved the instance for the
    install directory, the store and the compose project — and then wrote the
    *plain* deployment's hostname into `.env`, bound the plain deployment's
    port, recorded the plain deployment's database password, and registered the
    plain deployment's Authentik application. Each of those was a separate
    constant, so each had to be found separately; here there is one place to be
    wrong and one place to test.

    ⚠️ **The host comes from `agency_host`, the same function `caddy_sites`
    uses.** If these two ever disagreed, `.env` would carry a hostname Caddy has
    no site for — and the provisioning QR minted from it would send every
    enrolled tablet to a name that does not answer.
    """
    paths = instance_paths(ctx, inst)
    plain_host = ctx['_get_service_domain'](settings, KEY) if ctx else None
    host = atlas_instances.agency_host(plain_host, paths['slug'])
    return {
        'slug': paths['slug'],
        # ⚠️ **`_run_update` logs with this, and it was not here.** Every update
        # of every deployment raised `KeyError: 'name'` on its second log line —
        # and then again inside the `except` handler's own `plog`, so the job
        # died without even recording the failure. It had never once run since
        # chunk 8 introduced the reference.
        #
        # ⚠️ Nothing caught it. `_run_update` has no behavioural test; the
        # chunk 7 guards check that it *passes* `inst=` everywhere, which a
        # missing dict key is invisible to. `test_atlas_identity_keys` now
        # checks every `_me[...]` read against what this actually returns.
        'name': paths['name'],
        'dir': paths['dir'],
        'host': host,
        'app_port': paths['port'],
        'settings_prefix': paths['settings_prefix'],
        'compose_project': paths['compose_project'],
        # ⚠️ From the *record*, not from `derive`: this is operator text the
        # console stores, not a name the module can compute. `derive` knows
        # `atlas-corona`; only the record knows "Corona Fire Department".
        'agency_name': (inst or {}).get('agency_name') or '',
        # Empty rather than a half-formed URL: a box with no domain resolved
        # cannot enrol devices, and `https://:8449` in a QR would fail on the
        # tablet with nothing to point at.
        'console_url': f'https://{host}' if host else '',
        'device_url': f'https://{host}:{DEVICE_PORT}' if host else '',
        'apk_url': (f'http://{host}/api/v1/provisioning/agent.apk'
                    if host else ''),
        'authentik': atlas_instances.authentik_names(inst),
    }


def deploy_validate(data):
    """The repository is public and takes no credential; the store size is the
    one thing an operator can get wrong here (W205).

    ⚠️ Validated **before** the deploy starts, not inside it. A refusal
    halfway through a deploy leaves a half-built box, and the number is knowable
    from the form alone.
    """
    data = data or {}
    raw = data.get('store_gb')
    if raw in (None, ''):
        # Not supplied: an existing box keeps whatever it has, and a new one
        # gets no reservation at all rather than a size nobody chose.
        return {}, None

    # ⚠️ The sizing mode and the agency travel with the deploy, because the
    # store is built during it and cannot be changed afterwards: `resize2fs`
    # will not shrink a mounted filesystem, and a fixed store cannot become
    # sparse once its blocks are allocated. Choosing wrong here is not a setting
    # an operator can correct later.
    #
    # ⚠️ Read **before** the size is judged, because the mode decides which
    # question to ask of it.
    mode, error = atlas_instances.validate_mode(
        data.get('mode') or atlas_instances.MODE_FIXED)
    if error:
        return {}, error

    # ⚠️ No `ctx` here — the registry calls this with the form data alone —
    # so `install_base()` answers from the box's own layout.
    _, free = _disk_free(install_base())
    # ⚠️ **0, and it is the honest figure now (W230).** This was the loop
    # image's size, meaning "space ATLAS already holds, which a resize may
    # count as available". There is no image, and without `ctx` there is no
    # registry to total either. Nothing is lost: `add_instance` has already
    # bounded the request against the pool with full knowledge, which the
    # dynamic branch above says in as many words.
    reserved = 0

    if mode == atlas_instances.MODE_DYNAMIC:
        # ⚠️ **The 85% ceiling is a limit on *reservations*, and a dynamic
        # deployment reserves nothing.** Applying it here refused a dynamic
        # deployment whose ceiling was the pool — 354.6 GB against a 322.7 GB
        # reservation cap — so the deploy never started while the instance had
        # already been recorded. The ceiling asks "may ATLAS take this much disk
        # now?", which is not the question a ceiling answers.
        #
        # The pool already bounded this figure in `add_instance`; all that is
        # left is that it be a real, positive size.
        try:
            size = int(float(raw) * GIB)
        except (TypeError, ValueError):
            return {}, 'Store size must be a number of gigabytes.'
        if size <= 0:
            return {}, 'There is no space left in the ATLAS budget.'
    else:
        # ⚠️ `in_use` is not consulted here. The "already storing N GB" refusal
        # needs the store mounted to measure, and this runs before the deploy
        # that mounts it; `ensure_store` refuses a shrink against the real image
        # anyway. Asking here with a zero would have looked like a check and
        # been none.
        size, error = validate_store_size(raw, free, 0, reserved)
        if error:
            return {}, error

    return {'store_bytes': size, 'mode': mode,
            'slug': (data.get('slug') or None)}, None


def _stale_deploy_key(dirpath):
    """Paths of the key a private-repo install left behind, if still present.

    The repository is public now, so this key opens nothing. It is removed on
    deploy rather than left to rot: a credential kept past its purpose is only
    ever a liability, and nobody audits a file they have forgotten exists.
    """
    base = os.path.dirname(dirpath)
    return [p for p in (os.path.join(base, f'.{KEY}_deploy_key'),
                        os.path.join(base, f'.{KEY}_deploy_key.pub'))
            if os.path.exists(p)]



def _module_head(ctx, dirpath):
    """The commit a checkout is on, or None.

    ⚠️ Through `ctx['_module_git']`, the same seam `deploy` uses, rather
    than a bare `subprocess.run` — a checkout under the console's home is
    readable either way today, but the seam is what keeps that true.
    """
    try:
        r = ctx['_module_git'](dirpath, 'rev-parse', 'HEAD', timeout=10)
        head = (getattr(r, 'stdout', '') or '').strip()
        return head or None
    except Exception:
        return None


def _write_build_file(dirpath, plog=None):
    """Record the checked-out revision where the container can still read it.

    ⚠️ `.dockerignore` excludes `.git`, and it should — but that leaves the
    running console unable to answer "is this exactly the code I think it is".
    It reported `revision unknown` on every InfraTAK deployment while the footer
    happily showed a version, which is the worse half of both worlds: a number
    to trust and no way to check it.

    ATLAS reads this file at `app/version.py:_from_file`, which exists for
    precisely this case. Written before the image is built, so it is copied in.
    """
    try:
        r = subprocess.run(
            ['git', '-C', dirpath, 'log', '-1', '--format=%h %cs'],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return None
        revision, _, committed = r.stdout.strip().partition(' ')
        with open(os.path.join(dirpath, 'BUILD'), 'w', encoding='utf-8') as handle:
            handle.write('revision=%s\ncommitted=%s\ndirty=false\n'
                         % (revision, committed))
        if plog:
            plog('  \u2713 Build stamp written (revision %s)' % revision)
        return revision
    except (OSError, subprocess.SubprocessError):
        return None


def _verify_pin(ctx, dirpath, plog):
    """Check the checkout is the commit we meant to install.

    ⚠️ A tag is a pointer and whoever owns the repository can move it. Rule 8
    wants the SHA checked *after* the fetch, which is the only moment the
    difference is observable.

    ⚠️ `ATLAS_SHA` must be the **commit** the tag dereferences to. An annotated
    tag is itself an object with its own hash, so `git rev-parse <tag>` and the
    HEAD of a clone made from it are different strings — and comparing them
    fails every time, which reads exactly like a tag that has been tampered
    with. Record `git rev-parse '<tag>^{}'`.
    """
    r = ctx['_module_git'](dirpath, 'rev-parse', 'HEAD', timeout=10)
    head = (r.stdout or '').strip()
    if not ATLAS_SHA:
        plog(f'  ⚠ No pinned SHA recorded — installed {head[:12]} from {ATLAS_TAG}')
        return head
    if not head.startswith(ATLAS_SHA) and not ATLAS_SHA.startswith(head):
        raise RuntimeError(
            f'{ATLAS_TAG} resolved to {head[:12]}, expected {ATLAS_SHA[:12]} — '
            'refusing to install a tag that has moved'
        )
    plog(f'  ✓ Pin verified: {ATLAS_TAG} = {head[:12]}')
    return head


def deploy(ctx, job, params):
    plog = _plog
    params = params or {}
    # ⚠️ The deployment being built, which is the plain one unless a slug was
    # chosen. Resolved from the recorded list rather than from the request, so a
    # deploy cannot build a deployment nobody registered.
    #
    # ⚠️ **An unknown slug is refused, not treated as the plain deployment.**
    # `by_slug` answers None for both "no slug given" and "no such slug", and
    # every other route already tells them apart through `_requested_instance`
    # / `_addressed`. Here the second reading is the dangerous one: a deploy
    # naming a slug nobody registered would build *over the plain deployment*
    # — its directory, its port, its compose project, its database volume.
    _requested_slug = (params.get('slug') or '').strip() or None
    _known = load_instances(ctx)
    _inst = atlas_instances.by_slug(_known, _requested_slug)
    if _requested_slug and _inst is None:
        raise RuntimeError(
            'No deployment is registered with the slug "%s". Refusing to '
            'deploy: an unrecognised slug would otherwise build over the '
            'plain deployment.' % _requested_slug)

    # ⚠️ **Refusing to build a second copy of something already running.**
    # On a box converted from root to non-root the console loses access to
    # `/root/atlas-*` while those containers keep serving. Every filesystem
    # question then answers "nothing installed", so without this the deploy
    # proceeds and builds under the home with the *same* compose project, the
    # same ports and the same database volume name as the deployment still
    # running — two ATLAS instances fighting over one identity, and the
    # operator's first sign of it is whichever one loses.
    if instance_is_stranded(ctx, _inst):
        _me_name = atlas_instances.derive(_inst)['name']
        raise RuntimeError(
            '%s is already running on this box, but the console cannot reach '
            'its files — which is what a conversion from a root install to a '
            'non-root one looks like. Refusing to deploy: it would build a '
            'second copy with the same compose project, ports and database '
            'volume as the one still serving. Move the deployment under the '
            "console's home first." % _me_name)
    # ⚠️ Resolved once, before anything is written. Every value below was a
    # module constant that quietly meant "the plain deployment". A deploy that
    # builds in the right directory and then configures itself with another
    # deployment's hostname, port and settings keys is not a deployment of
    # anything — it is two half-deployments overwriting each other.
    _me = deployment_identity(ctx, _inst, ctx['load_settings']())
    dirpath = _me['dir']
    _prefix = _me['settings_prefix']
    _app_port = _me['app_port']
    try:
        settings = ctx['load_settings']()

        # ── 1/7 Docker ────────────────────────────────────────────────────────
        plog('━━━ Step 1/7: Checking Docker ━━━')
        rc, version = ctx['_docker_probe']()
        if rc != 0:
            plog('  Docker not found — installing...')
            if not ctx['_install_docker_engine'](plog):
                raise RuntimeError('Docker install failed — see log above')
            plog('✓ Docker installed')
        else:
            plog(f'✓ Docker present: {version}')

        # ── 2/7 Source ────────────────────────────────────────────────────────
        plog('')
        plog('━━━ Step 2/7: Fetching ATLAS ━━━')
        # Three ways to have a key, in order of how deliberate they are:
        # pasted into the deploy form, kept from a previous deploy, or already
        # placed on the box by an operator who would rather not paste a private
        # key into a web form at all. The last one is the reason this checks the
        # filesystem — the key never has to travel.
        # A key left over from when this repository was private opens nothing
        # now. Removed here rather than left to rot.
        for stale in _stale_deploy_key(dirpath):
            try:
                os.remove(stale)
                plog(f'  Removed the obsolete deploy key ({stale})')
            except OSError:
                pass
        repo = ATLAS_REPO_HTTPS

        if os.path.isdir(os.path.join(dirpath, '.git')):
            plog(f'  Already cloned at {dirpath} — fetching {ATLAS_TAG}')
            ctx['_module_git'](dirpath, 'checkout', '--', '.', timeout=60)
            r = subprocess.run(
                ['git', '-C', dirpath, 'fetch', '--tags', '--depth=1', 'origin', ATLAS_TAG],
                capture_output=True, text=True, timeout=300, env=None,
            )
            if r.returncode != 0:
                raise RuntimeError(f'git fetch failed: {r.stderr[-300:]}')
            ctx['_module_git'](dirpath, 'checkout', '-f', ATLAS_TAG, timeout=60)
        else:
            os.makedirs(dirpath, exist_ok=True)
            plog(f'  Cloning {repo} @ {ATLAS_TAG}')
            r = subprocess.run(
                ['git', 'clone', '--depth=1', '--branch', ATLAS_TAG, repo, dirpath],
                capture_output=True, text=True, timeout=600, env=None,
            )
            if r.returncode != 0:
                hint = ''
                if 'Permission denied' in r.stderr or 'not read from remote' in r.stderr:
                    hint = ' — the repository is private; supply a read-only deploy key'
                raise RuntimeError(f'git clone failed{hint}: {r.stderr[-300:]}')
        commit = _verify_pin(ctx, dirpath, plog)
        _write_build_file(dirpath, plog)
        plog('✓ Source in place')

        # ── 3/7 Configuration ─────────────────────────────────────────────────
        plog('')
        # ── Reserved store ───────────────────────────────────────────
        # ⚠️ **Before configuration and long before compose.** The mounts have
        # to exist before Docker creates a volume or a container writes a byte;
        # otherwise ATLAS populates the root filesystem and the reservation
        # stays an empty file that nobody notices until the disk is full.
        store_bytes = params.get('store_bytes')
        if store_bytes:
            plog('')
            # ⚠️ The prose follows the mode. It said "allocated up front so
            # nothing else on this box can claim it" for a *dynamic* deployment,
            # which claims nothing up front — an operator reading that would
            # expect `df` to move and be right to call it a bug when it did not.
            if params.get('mode') == atlas_instances.MODE_DYNAMIC:
                plog('━━━ Preparing the ATLAS store ━━━')
                plog(f'  Up to {store_bytes / GIB:.1f} GB, shared with the rest of')
                plog('  this box and taken only as it is used.')
                plog('  ⚠ `df` will not move now. It moves as this deployment')
                plog('  stores things, and moves back when they are deleted.')
            else:
                plog('━━━ Reserving the ATLAS store ━━━')
                plog(f'  {store_bytes / GIB:.1f} GB, allocated up front so nothing else')
                plog('  on this box can claim it.')
                plog('  ⚠ `df` will show this space as used from now on — that is the')
                plog('  reservation working, not a leak.')
            err = ensure_store(ctx, store_bytes, plog,
                               mode=params.get('mode'), inst=_inst)
            if err:
                raise RuntimeError(f'Reserved store: {err}')
            # ⚠️ Asked about *this* deployment. Without the instance it read
            # the plain store, which on this box does not exist — hence
            # "0 GB usable inside a 0 GB reservation" after a store had just
            # been built successfully.
            facts = store_facts(ctx, mode=params.get('mode'), inst=_inst)
            if params.get('mode') == atlas_instances.MODE_DYNAMIC:
                plog(f'  ✓ {facts["usable_gb"]} GB usable, sharing this box\'s disk')
            else:
                plog(f'  ✓ {facts["usable_gb"]} GB usable inside a '
                     f'{facts["reserved_gb"]} GB reservation')
            plog('  ⚠ Compose will warn that the Postgres volume "was not created')
            plog('  by Docker Compose". Expected: it is backed by the store.')

        plog('')
        plog('━━━ Step 3/7: Writing configuration ━━━')
        # Generated once and kept. Regenerating on a re-deploy would leave the
        # existing database unopenable by the application that owns it.
        #
        # ⚠️ Persisted *here*, before anything uses it — not with the rest of the
        # settings in step 6. Postgres applies POSTGRES_PASSWORD only when it
        # initialises an empty volume and ignores it ever after, so the moment
        # step 4 starts the database this value is baked in. A deploy that then
        # failed anywhere before step 6 left no record of it, and the next
        # attempt generated a fresh password against a volume that still held
        # the old one:
        #
        #     FATAL: password authentication failed for user "takmdm"
        #
        # — with the API sitting on "waiting for database..." forever and the
        # database permanently unopenable. Writing it first costs nothing: an
        # abandoned deploy leaves a password for a database that may not exist,
        # which is harmless, and a resumed one reuses it, which is the point.
        # ⚠️ Keyed to this deployment. Under the shared `atlas_pg_password` an
        # agency deploy overwrote the plain deployment's record, and the next
        # time anything needed it the database it belonged to was permanently
        # unopenable — the exact failure the comment above describes, caused by
        # a second deployment rather than a second attempt.
        pg_password = settings.get(f'{_prefix}pg_password')
        if not pg_password:
            pg_password = secrets.token_urlsafe(24)
            s_early = ctx['load_settings']()
            s_early[f'{_prefix}pg_password'] = pg_password
            ctx['save_settings'](s_early)
        fqdn = _me['host']

        if not fqdn:
            plog('  ⚠ No domain resolved for this box.')
            plog('    The console will still work through Caddy, but devices')
            plog('    cannot be enrolled without a hostname to put in the QR.')

        # ⚠️ **Written as the console, not through `_write_priv` (W240).**
        # The install directory is the console's own, and `_write_priv` on a
        # broker box is `_do_write`: `os.open` as uid 0, `fchmod`, **no
        # chown**. That left `<home>/atlas/<slug>/.env` `root:root 0600` on
        # every non-root install, and everything that reads it back --
        # `_arm_admin_gates`, `_set_trusted_proxies`, `_push_email_relay` --
        # took `except OSError: return False` while the deploy printed
        # "✓ ATLAS deployed".
        #
        # ⚠️ The effect was not cosmetic: `TAKMDM_ADMIN_GROUP` stayed blank,
        # `TAKMDM_PROXY_AUTH_SECRET` was never written, `TAKMDM_TRUSTED_PROXIES`
        # kept its wide fallback and the relay was never wired. The refuse
        # branch W229 added for exactly this was unreachable, because the
        # `OSError` return came first.
        #
        # Guide §8: files under the module's own directory are the console's
        # to read and write directly; `_write_priv` is for root-owned paths.
        # Compose still reads this file as root, through the broker.
        _write_own(os.path.join(dirpath, '.env'), _ENV_TEMPLATE.format(
            trusted_proxies=_bridge_gateway(_me['compose_project']),
            pg_password=pg_password,
            device_url=_me['device_url'],
            apk_url=_me['apk_url'],
            console_url=_me['console_url'],
            # ⚠️ Quoted here and nowhere else. The instance record holds
            # the plain name — it is what the console renders — and the
            # escaping belongs only where compose parses it.
            agency_name=_env_quote(_me['agency_name']),
        ), 0o600)
        # ⚠️ The allocated port, not `APP_PORT`. Two deployments both binding
        # 127.0.0.1:8760 would leave the second failing to start with a port
        # conflict that says nothing about which deployment claimed it — and
        # Caddy's upstream for the second one points at the first.
        _write_own(
            os.path.join(dirpath, 'docker-compose.override.yml'),
            _COMPOSE_OVERRIDE.format(app_port=_app_port),
        )
        plog(f'✓ .env and docker-compose.override.yml written (app on 127.0.0.1:{_app_port})')
        # ⚠️ Checked against the release that was just checked out, because a
        # setting compose does not name reaches nothing and says nothing. Not
        # fatal: the deployment works, minus whatever that setting did, and
        # failing the deploy over it would be worse than naming it.
        _inert = env_keys_that_reach_nothing(dirpath)
        if _inert:
            plog('  ⚠ This release does not read: ' + ', '.join(_inert))
            plog('    They are in .env and its docker-compose.yml does not name')
            plog('    them, so the application will never see them. Whatever')
            plog('    they configure is not configured.')

        # ⚠️ **Chowned through the broker, because the image's uid is not
        # negotiable.** Running the container as the console's uid instead was
        # tried and failed on the box: ATLAS's image is `USER takmdm` (1000)
        # and cannot fix `/pki` itself, so the init step died with
        # `PermissionError: /pki/ca.crt`. The ownership has to be right on the
        # host before the container starts.
        #
        # ⚠️ Recursive, and that matters on a re-deploy: files the previous
        # run left behind need the same owner, or the application can read its
        # own CA and not renew it.
        for name in WRITABLE_DIRS:
            path = os.path.join(dirpath, name)
            os.makedirs(path, exist_ok=True)
            err = _chown_priv(path, APP_UID, APP_GID)
            if err:
                raise RuntimeError(err)
        plog('✓ %s owned by uid %d (the container is not root)'
             % (', '.join(WRITABLE_DIRS), APP_UID))

        # ── 4/7 Start ─────────────────────────────────────────────────────────
        plog('')
        plog('━━━ Step 4/7: Starting containers ━━━')
        # `api` alone: it depends_on db and the one-shot migration step, and
        # naming it keeps ATLAS's own nginx out of a deployment where Caddy is
        # the only thing that should be terminating TLS.
        r = _compose(ctx, 'up -d --build api', timeout=1800, inst=_inst)
        if r.returncode != 0:
            raise RuntimeError(compose_error(r, 'docker compose up'))
        plog('✓ Containers built and started')

        # ⚠️ Only now can the bridge subnet be read — `docker compose up` is what
        # creates the network, and `.env` was written before it existed. So a fresh
        # install starts on the broad fallback and is narrowed here, on the same
        # deploy, rather than staying wide until somebody happens to update
        # (SEC_AUDIT.md S-1).
        if _set_trusted_proxies(dirpath, plog, _me['compose_project']):
            r2 = _compose(ctx, 'up -d api', timeout=600, inst=_inst)
            if r2.returncode != 0:
                plog('  ⚠ Could not restart with the narrowed range; it applies on '
                     'the next update')

        # ── 5/7 Firewall ──────────────────────────────────────────────────────
        plog('')
        plog('━━━ Step 5/7: Opening the device port ━━━')
        ok, detail = ctx['_fw_allow'](DEVICE_PORT, 'tcp')
        plog(f'  {"✓" if ok else "⚠"} allow {DEVICE_PORT}/tcp — {detail}')
        if not ok:
            # Not fatal: a box with no firewall installed answers "no firewall
            # present", and the port is reachable anyway. A box that *has* one
            # and refused is a problem the operator needs to see, not a reason
            # to unwind a working deployment.
            plog('    The device port may be unreachable until this is resolved.')

        # ── 6/7 Register ──────────────────────────────────────────────────────
        plog('')
        plog('━━━ Step 6/7: Registering the module ━━━')
        s = ctx['load_settings']()
        # ⚠️ `atlas_enabled` stays unprefixed on purpose: it means "the ATLAS
        # module is installed on this box", which is what `detect`, the tile and
        # `caddy_sites` ask. *Which* deployments exist is `atlas_instances`.
        # Prefixing it would have made an agency-only box report ATLAS absent
        # and emit no vhost at all.
        s[f'{KEY}_enabled'] = True
        s[f'{_prefix}pg_password'] = pg_password
        s[f'{_prefix}commit_sha'] = commit
        ctx['save_settings'](s)

        # ⚠️ **Staged before the Caddyfile is rendered, and fatal if it
        # fails (upstream review, item 1).** `caddy_sites` only emits the
        # `:8449` device listener when a trust pool is actually on disk. This
        # write used to happen *inside* that renderer, so when it failed the
        # block was silently omitted — and the deploy went on to print
        # "Devices: https://…:8449 (mutual TLS)" over a device channel that
        # did not exist. A device channel that is absent must stop the deploy,
        # not decorate it.
        staged = sync_device_ca_for_caddy(_inst, ctx)
        if not staged:
            raise RuntimeError(
                'Could not stage the device CA for Caddy at %s. The device '
                'channel on :8449 would be silently missing while the rest of '
                'the deployment looked healthy, so this stops here.'
                % device_ca_path(_inst))
        plog('✓ Device CA staged for Caddy at %s' % staged)

        ctx['generate_caddyfile'](s)
        # ⚠️ Read back. Staging the CA and rendering the listener are two
        # different questions, and on the first Rocky non-root deploy the first
        # was true while the second was false (see `_ca_is_staged`).
        if not _caddyfile_has_device_listener(_me['host']):
            raise RuntimeError(
                'The Caddyfile was rendered without the :%d device listener for %s '
                'although the device CA is staged at %s. Stopping here rather than '
                'leaving the device channel silently missing.'
                % (DEVICE_PORT, _me['host'], staged))
        plog('✓ Device listener :%d rendered for %s' % (DEVICE_PORT, _me['host']))
        if ctx['_caddy_reload'](plog):
            plog('✓ Caddy reloaded')

        # ⚠️ After generate_caddyfile above, because arming the header check
        # depends on reading the vhost it just wrote.
        # ⚠️ `inst`, or the agency's own administrators are rejected by ATLAS
        # with a 403 *after* Authentik has let them in — the confusing half of a
        # lockout, where the proxy says yes and the application says no.
        restart_api = _arm_admin_gates(ctx, dirpath, plog, inst=_inst,
                                       global_group=_global_admin_group(ctx))
        restart_api = _push_email_relay(ctx, dirpath, plog) or restart_api
        if restart_api:
            _compose(ctx, 'up -d api', timeout=300, inst=_inst)

        # ── The certificate authority is split before anyone can use it ──────
        #
        # ⚠️ Automatic, because a manual ceremony is not a control. The previous
        # design asked the operator to run five commands over SSH; SEC_AUDIT S-2
        # stayed Severe for months because nobody did, and W185 found the console
        # telling the ones who half-finished that they were done.
        #
        # This leaves the root key **on the box** — the card is what gets it off.
        # Issuing here is what makes that possible: once an intermediate signs,
        # removing the root costs nothing and breaks nothing.
        plog('')
        plog('━━━ Securing the certificate authority ━━━')
        out = _compose_exec(
            ctx, ['python', '-m', 'app.cli', 'ca-issue-intermediate'], timeout=120,
            inst=_inst,
        )
        if out and 'issuing CA' in out:
            plog('✓ Issuing certificate created — the root key is now only needed')
            plog('  to renew it, about twice a decade.')
            # ⚠️ **Re-staged, because the intermediate did not exist when the
            # bundle was written.** Step 6 stages the trust pool and this runs
            # after it, so a fresh deployment ended up with a pool holding the
            # root alone — measured on the box: one certificate,
            # `CN = TAK-MDM Device CA`, while `pki/issuing.crt` sat beside it.
            #
            # That matters exactly as the staging function's own comment says:
            # once the root is offline the devices are issued by the
            # intermediate, and Caddy cannot verify them from the root alone.
            # The failure arrives later, at a tablet, as a TLS handshake that
            # refuses — nothing in the deploy log would ever have mentioned it.
            restaged = sync_device_ca_for_caddy(_inst, ctx)
            if restaged:
                ctx['_caddy_reload']()
                plog('✓ Trust bundle re-staged with the issuing certificate')
            else:
                plog('⚠ Could not re-stage the trust bundle. Devices issued by')
                plog('  the intermediate will not be trusted until it is staged.')
            plog('⚠ The root key is still on this server. Open the ATLAS module')
            plog('  page and save your recovery file — it takes one click.')
        else:
            # Not fatal. A deployment with an unsplit CA works exactly as it
            # always did; it is simply still carrying the risk.
            plog('⚠ Could not create the issuing certificate. ATLAS works, but the')
            plog('  root key cannot be moved off this server until it exists.')

        # ── 7/7 Authentik ─────────────────────────────────────────────────────
        plog('')
        plog('━━━ Step 7/7: Administrator sign-in ━━━')
        token = (ctx['_get_authentik_env_value'](s, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](s, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if fqdn and token:
            plog('  Registering the console with Authentik...')
            # ⚠️ This is what makes the console reachable *and* restricted.
            # Without an application the outpost has nothing to authorise, so
            # Caddy's forward_auth never sets the identity headers ATLAS reads
            # and the console answers 401 to everyone, permanently.
            ensure_authentik_app(ctx, fqdn, token, plog=plog, settings=s,
                                 inst=_inst)
            # Re-emit now that the application exists: the console vhost only
            # grows its forward_auth block once Authentik is in the picture.
            ctx['generate_caddyfile'](ctx['load_settings']())
            ctx['_caddy_reload'](plog)
            plog('  ✓ Sign in with an Authentik administrator account.')
        else:
            # ⚠️ Degrading here does NOT mean an open console. ATLAS has two auth
            # modes and no middle one; without Authentik the honest answer is
            # that the console is not published, and is reached over an SSH
            # tunnel exactly as the console-by-IP row was resolved.
            plog('  ⚠ Authentik not configured — the console vhost is NOT published.')
            plog('    Reach it over an SSH tunnel:')
            plog(f'      ssh -L {_app_port}:127.0.0.1:{_app_port} <this host>')

        plog('')
        plog('✓ ATLAS deployed.')
        if fqdn:
            plog(f'  Console:  https://{fqdn}/')
            plog(f'  Devices:  https://{fqdn}:{DEVICE_PORT}/  (mutual TLS)')
        plog('')
        # The agent and the launcher ship with the source and load into the
        # library on first start, so enrolment works with no upload at all.
        # Said out loud because an operator has no other way to know the
        # library is not empty.
        plog('  Bundled and ready: ATLAS Agent (device policy controller)')
        plog('  and ATLAS Launcher. Enrollment tokens can be minted now.')
        job.update({'running': False, 'complete': True, 'error': False})
    except Exception as exc:
        plog(f'ERROR: {exc}')
        job.update({'running': False, 'complete': False, 'error': True})


# --------------------------------------------------------------------------- #
# Authentik, and the CA Caddy needs
#
# ⚠️ These live here rather than in app.py. They are ATLAS's own logic — how
# ATLAS registers itself with Authentik, how it is restricted to
# administrators, and where its device CA has to be copied for Caddy to read.
# Nothing else in infra-TAK calls them, so nothing else should carry them: the
# module adapts to the console, not the other way round.
#
# What they *do* need from the console arrives through ctx, which is the
# sanctioned direction (rule 10: a module imports nothing from app.py).
# --------------------------------------------------------------------------- #

def caddy_base():
    """Where Caddy keeps its data, as one overridable answer.

    ⚠️ **A function, so tests can redirect it.** Hardcoding `/var/lib/caddy`
    is what made three store tests create real directories under the drive
    root on Windows (upstream review, item 9) — the same trap, one directory
    over. Anything a test needs to *write* has to be reachable from a
    fixture.

    ⚠️ `pwd` is imported here, not at module scope: it is Unix-only and
    these tests run on Windows, where the import itself fails.
    """
    try:
        import pwd as _pwd
        home = _pwd.getpwnam('caddy').pw_dir
        if home and os.path.isdir(home):
            return home
    except (ImportError, KeyError, AttributeError):
        pass
    return '/var/lib/caddy'


def _read_maybe_priv(path, ctx=None):
    """Text at `path`, or None. Tries as the console, then asks the broker.

    ⚠️ **Any filesystem question about a container-owned path is
    unanswerable by the console**, and that includes `os.path.exists`. `pki/`
    is `drwx------` under the application's uid, so the console cannot even
    traverse it: `exists()` answers False about a file that is plainly there.
    Four separate failures tonight were this same shape — read, chown,
    delete, and then an existence probe standing in front of a read that had
    already been fixed.
    """
    try:
        # ⚠️ **`O_NOFOLLOW` and `S_ISREG` (W240).** A root-era console reads
        # here as uid 0, and the paths are inside `pki/`, which the container
        # owns. A planted `pki/issuing.crt -> /etc/shadow` would otherwise be
        # read by root and concatenated into the device-CA bundle, which is
        # staged `0644` where Caddy -- and anything else on the box -- can
        # read it. The `S_ISREG` check closes the same trick through a fifo,
        # which would hang the deploy instead.
        fd = os.open(path, os.O_RDONLY | O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, 'r') as handle:
                fd = None
                return handle.read().strip()
        finally:
            if fd is not None:
                os.close(fd)
    except OSError:
        pass
    reader = (ctx or {}).get('_read_priv')
    if reader is None:
        return None
    try:
        return (reader(path) or '').strip()
    except Exception:
        return None


def device_ca_path(inst=None):
    """Where Caddy reads this deployment's device CA. Pure — touches nothing.

    ⚠️ One directory per deployment. A shared `atlas/device-ca.crt` would
    have the last instance to deploy overwrite every other agency's trust
    pool, and Caddy would then verify one agency's devices against another
    agency's CA.
    """
    return posixpath.join(caddy_base(), atlas_instances.derive(inst)['name'],
                          'device-ca.crt')


def _ca_is_staged(inst=None, ctx=None):
    """Is there actually a trust pool at that path?

    ⚠️ Asked rather than assumed, because the answer decides whether the
    device listener is emitted at all. `caddy_sites` runs on every Caddyfile
    render, long after the deploy that staged it.

    ⚠️ **The direct probe is not enough (v10.1.80 T&E, Rocky non-root).**
    `/var/lib/caddy` is `drwxr-x--- caddy:caddy`. The console can traverse it
    only where something once added it to the `caddy` group (the MediaMTX
    editor setup does, on Ubuntu boxes that ran it); on a born-non-root Rocky
    box it is `takwerx wheel` and `getsize()` raised EACCES about a file the
    deploy had just staged through the broker. The listener was then left out
    of the Caddyfile while the deploy log read staged + reloaded. Same shape
    as the `pki/` lesson: a stat the console cannot make is not "absent".
    So on OSError, ask the broker, which can read that path.
    """
    path = device_ca_path(inst)
    try:
        return os.path.getsize(path) > 0
    except OSError:
        pass
    reader = ((ctx or get_ctx()) or {}).get('_read_priv')
    if reader is None:
        return False
    try:
        return bool((reader(path) or '').strip())
    except Exception:
        return False


def _caddyfile_has_device_listener(host):
    """Did the render actually emit `<host>:8449 {`? Read back, never assumed."""
    if not host:
        return True
    try:
        with open('/etc/caddy/Caddyfile') as f:
            body = f.read()
    except OSError:
        return False
    return ('%s:%d {' % (host, DEVICE_PORT)) in body


def sync_device_ca_for_caddy(inst=None, ctx=None):
    """Deploy a Caddy-readable copy of ATLAS's device CA; return its path or None.

    ATLAS issues its own client certificates to enrolled tablets, and Caddy has
    to verify them at the device listener. The CA lives in the module's install
    directory, which is root-owned — and Caddy runs as the unprivileged `caddy`
    user, so pointing `client_auth` there makes Caddy fail to start. Same
    problem, same answer, as the custom-certificate copy below.

    ⚠️ Only the *certificate* is copied. The CA private key stays where it is:
    Caddy needs to verify signatures, which takes the public half alone, and a
    copy of the key readable by a web server is a fleet's device identity one
    file-read away.
    """
    # ⚠️ The instance's own directory first, then the two historical locations
    # for the plain deployment. Dropping the legacy probe would break a box whose
    # checkout predates `install_base`, and keeping it costs two `os.path.exists`
    # calls.
    candidates = [instance_paths(None, inst)['dir']]
    if not atlas_instances.derive(inst)['slug']:
        candidates += ['/root/atlas', os.path.expanduser('~/atlas')]
    for base_dir in candidates:
        # ⚠️ Asked by *reading*, not by `os.path.exists` — see
        # [_read_maybe_priv]. The probe used to be an `exists()` that the
        # console cannot answer for a directory the application owns, so this
        # returned None about a certificate sitting right there.
        if _read_maybe_priv(os.path.join(base_dir, 'pki', 'ca.crt'), ctx):
            break
    else:
        print('[' + KEY + '] no device CA found in: '
              + ', '.join(candidates), flush=True)
        return None

    # ⚠️ Root **plus every intermediate**, not just `ca.crt` (ATLAS W172).
    #
    # Once the root is taken offline, devices are issued by an intermediate and
    # present a certificate Caddy cannot verify from the root alone. Caddy's
    # `trust_pool file` reads a bundle, so they concatenate — and retired
    # intermediates stay in it, because the certificates they signed are valid
    # until they expire and those devices chain through them.
    #
    # Only certificates. The private halves never leave the install directory:
    # verification takes the public half, and a key readable by a web server is a
    # fleet's identity one file-read away.
    pki_dir = os.path.join(base_dir, 'pki')
    bundle_parts = []
    # ⚠️ **Read through the broker when the console cannot read it itself.**
    # `pki/` is owned by the application's uid and created `drwx------`, so
    # after the host-side chown the console is locked out of the very
    # certificate it has to stage — a plain `open()` raises `PermissionError`,
    # the loop swallowed it, the bundle came back empty and the device
    # listener silently vanished. Measured: `drwx------ 1000 1000`.
    #
    # ⚠️ Certificates only, and that does not change. The private halves
    # never leave the install directory: verification takes the public half,
    # and a key readable by a web server is a fleet's identity one file-read
    # away.
    # ⚠️ **One named file, because the console cannot list a directory it
    # cannot traverse.** This used to glob `pki/retired/*.crt`. That glob runs
    # as the console; `pki/` is `drwx------` owned by the application's uid,
    # so it returned nothing -- silently -- and after the first CA renewal the
    # pool staged here would have been missing every retired intermediate.
    # A device issued by one chains through it, so all of them would have
    # stopped being trusted at the edge, with no error anywhere.
    #
    # `_read_priv` reads a *named* path and there is no brokered `listdir`, so
    # the module could not close this from its side. ATLAS closes it instead:
    # it knows the set, and since W234 it publishes it as one file.
    bundle = _read_maybe_priv(os.path.join(pki_dir, BUNDLE_CERT), ctx)
    if bundle:
        bundle_parts.append(bundle)
    else:
        # ⚠️ **The fallback is not decoration and is not safe either.** A
        # deployment on a release older than W234 publishes no bundle, and
        # this has to go on working for it -- but what it assembles is
        # `ca.crt` + `issuing.crt` and *nothing retired*, for the reason
        # above. That is correct until the deployment's first CA renewal and
        # wrong, invisibly, ever after.
        #
        # So it says so. The alternative -- failing the deploy -- would
        # strand every existing deployment on an upgrade, and the condition
        # clears itself the moment ATLAS is updated.
        print('[' + KEY + '] ' + pki_dir + ' has no ' + BUNDLE_CERT
              + ': this ATLAS predates W234, so the trust pool is being '
              + 'assembled here and CANNOT include retired intermediates. '
              + 'Update ATLAS before renewing this CA.', flush=True)
        for candidate in (os.path.join(pki_dir, 'ca.crt'),
                          os.path.join(pki_dir, 'issuing.crt')):
            text = _read_maybe_priv(candidate, ctx)
            if text and text not in bundle_parts:
                bundle_parts.append(text)
    if not bundle_parts:
        # ⚠️ Never silent. This function feeds a *fatal* check in `deploy`,
        # and it had three separate `return None` paths that said nothing —
        # so the deploy stopped with a message naming the destination and no
        # hint of which step had actually failed.
        print('[' + KEY + '] device CA at ' + pki_dir + ' could not be read',
              flush=True)
        return None
    try:
        # ⚠️ One directory per deployment. A shared `atlas/device-ca.crt`
        # would have the last instance to deploy overwrite every other
        # agency's trust pool — and Caddy would then verify one agency's
        # devices against another agency's CA.
        dest = device_ca_path(inst)
        body = chr(10).join(bundle_parts) + chr(10)
        # ⚠️ **The broker's `write` does not create parent directories, and
        # assuming it did cost a deploy.** The comment here used to say "and
        # it creates the parent" — that was never checked. Measured against
        # the live broker: a write to a missing parent returns
        # `FileNotFoundError`, and a write into an existing directory
        # succeeds. The `os.makedirs` this replaced was removed at the same
        # time as the switch to `_write_priv`, so nothing created it at all.
        #
        # `mkdir` is shimmed *and* `/var/lib/...` is one of the prefixes the
        # shim routes, so this one genuinely does reach the broker through
        # PATH — unlike a path in the console's own home.
        rc, out = _run_root(['mkdir', '-p', os.path.dirname(dest)])
        if rc != 0:
            print('[' + KEY + '] could not create ' + os.path.dirname(dest)
                  + ': ' + out.strip()[:200], flush=True)
            return None
        # ⚠️ **Through the broker (W230).** `/var/lib/caddy` is not the
        # console's to write, and the chowns to the `caddy` user were
        # `EPERM` besides. `_write_priv` is the seam the console already
        # exposes for exactly this, and it creates the parent. 0644
        # because Caddy only reads it, and it is a certificate, not a key.
        writer = (ctx or {}).get('_write_priv')
        if writer is None:
            return None
        writer(dest, body, perm=0o644)
        return dest
    except Exception as exc:
        print('[' + KEY + '] could not stage device CA for Caddy: ' + str(exc), flush=True)
        return None


def _restrict_to_admins(ak_url, ak_headers, plog=None, app_slug='atlas'):
    """Bind "Allow authentik Admins" to the ATLAS application. Returns True when
    the application is restricted, False when it is NOT.

    ⚠️ This cannot wait for the startup access-policy converge. That converge
    is default-deny and would catch ATLAS eventually — but it runs when the
    console *boots*, and a module deploy does not reboot the console. In between,
    the application exists with no binding at all, and ATLAS is configured with an
    empty admin group precisely because it trusts Authentik to decide. That
    combination is an MDM console — remote wipe, factory reset, policy push —
    reachable by every authenticated user on the box, for however long it takes
    somebody to restart the console. Observed live before this existed.

    A failure here is reported as a failure. An access control that quietly did
    not apply is worse than one never attempted, because the deploy log would
    say the console is admin-only.
    """
    import urllib.request as _urlreq
    import urllib.error

    def log(msg):
        if plog:
            plog(msg)

    def _get(path):
        req = _urlreq.Request(f'{ak_url}/api/v3/{path}', headers=ak_headers)
        return json.loads(_urlreq.urlopen(req, timeout=10).read().decode())

    policy_name = 'Allow authentik Admins'
    try:
        # ⚠️ The deployment's own application. Hardcoding `atlas` bound the
        # policy to the *plain* application and then reported success, leaving
        # the agency console — remote wipe, factory reset, policy push — bound
        # to nothing at all while the log said it was restricted.
        app_pk = _get('core/applications/%s/' % app_slug)['pk']

        policy_pk = None
        for p in _get('policies/all/?page_size=200').get('results', []):
            if p.get('name') == policy_name:
                policy_pk = p.get('pk')
                break
        if not policy_pk:
            log(f"  ✗ ATLAS is NOT restricted: no {policy_name!r} policy exists. "
                f"Run Authentik → Reconfigure, then bind it to the ATLAS MDM "
                f"application by hand.")
            return False

        bindings = _get(f'policies/bindings/?target={app_pk}&page_size=100')['results']
        if any(str(b.get('policy')) == str(policy_pk) or
               (b.get('policy_obj', {}) or {}).get('name') == policy_name
               for b in bindings):
            log("  ✓ Console restricted to Authentik administrators (already bound)")
            return True

        req = _urlreq.Request(f'{ak_url}/api/v3/policies/bindings/',
            data=json.dumps({'target': app_pk, 'policy': policy_pk,
                             'order': 0, 'negate': False, 'enabled': True,
                             'timeout': 30}).encode(),
            headers=ak_headers, method='POST')
        _urlreq.urlopen(req, timeout=10)
        log("  ✓ Console restricted to Authentik administrators")
        return True
    except Exception as e:
        log(f"  ✗ ATLAS is NOT restricted — every authenticated user can reach "
            f"the console ({str(e)[:80]}). Bind {policy_name!r} to the ATLAS MDM "
            f"application in Authentik before using this deployment.")
        return False


def ensure_authentik_app(ctx, fqdn, ak_token, plog=None, flow_pk=None, inv_flow_pk=None, settings=None, inst=None):
    """Create the ATLAS MDM proxy provider + application in Authentik.

    Same pattern as the TAK Video Restreamer: Caddy's forward_auth protects
    atlas.FQDN and the embedded outpost decides who gets in.

    ⚠️ Creating the application is what makes ATLAS admin-only. The startup
    access-policy converge is default-deny — anything not on the user-visible
    allowlist gets bound to "Allow authentik Admins" — so an MDM console that
    can factory-reset a fleet is restricted without a policy written here. A
    deployment that skipped this step would not be "open": ATLAS would answer
    401 to everyone forever, because nothing would ever set the identity
    headers it reads.
    """
    if not fqdn or not ak_token:
        return False
    def log(msg):
        if plog:
            plog(msg)
    import urllib.request as _urlreq
    import urllib.error
    import urllib.parse as _urlparse
    _ak_headers = {'Authorization': f'Bearer {ak_token}', 'Content-Type': 'application/json'}
    _ak_url = ctx['_get_authentik_api_url'](settings) if settings else 'http://127.0.0.1:9090'

    try:
        if not flow_pk or not inv_flow_pk:
            for attempt in range(36):
                try:
                    req = _urlreq.Request(f'{_ak_url}/api/v3/flows/instances/?designation=authorization&ordering=slug', headers=_ak_headers)
                    resp = _urlreq.urlopen(req, timeout=10)
                    flows = json.loads(resp.read().decode())['results']
                    flow_pk = next((f['pk'] for f in flows if 'implicit' in f.get('slug', '')), flows[0]['pk'] if flows else None)
                    if flow_pk:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/flows/instances/?designation=invalidation', headers=_ak_headers)
                        resp = _urlreq.urlopen(req, timeout=10)
                        inv_flows = json.loads(resp.read().decode())['results']
                        inv_flow_pk = next((f['pk'] for f in inv_flows if 'provider' not in f.get('slug', '')), inv_flows[0]['pk'] if inv_flows else None)
                        if inv_flow_pk:
                            break
                except Exception:
                    pass
                if attempt % 6 == 0:
                    log(f"  ⏳ Waiting for authorization flow... ({attempt * 5}s)")
                time.sleep(5)
            if not flow_pk or not inv_flow_pk:
                log("  ⚠ No authorization/invalidation flow — skipping ATLAS proxy provider")
                return False

        provider_pk = None
        # ⚠️ Built in statements, not inside an f-string. Nesting the same quote
        # character inside an f-string is Python 3.12 syntax (PEP 701) and a
        # SyntaxError on the 3.10 that Ubuntu 22.04 ships — which would stop this
        # module importing at all, taking the tile with it.
        if settings:
            _host_name = ctx['_get_service_domain'](settings, KEY)
        else:
            _host_name = 'atlas.' + fqdn
        # ⚠️ Qualified for the deployment being registered. Without this an
        # agency's provider carried the plain deployment's external_host, so
        # Authentik issued its cookie for a hostname the agency console is not
        # served at and the sign-in loop never terminated.
        _host_name = atlas_instances.agency_host(
            _host_name, (inst or {}).get('slug'))
        _atlas_host = 'https://' + _host_name
        _names = atlas_instances.authentik_names(inst)
        _cookie = f'.{fqdn.split(":")[0]}'
        try:
            req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/',
                data=json.dumps({'name': _names['provider'], 'authorization_flow': flow_pk,
                    'invalidation_flow': inv_flow_pk,
                    'external_host': _atlas_host, 'mode': 'forward_single',
                    'token_validity': 'hours=24', 'cookie_domain': _cookie}).encode(),
                headers=_ak_headers, method='POST')
            resp = _urlreq.urlopen(req, timeout=10)
            provider_pk = json.loads(resp.read().decode())['pk']
            log("  ✓ Proxy provider created")
        except Exception as e:
            if hasattr(e, 'code') and e.code == 400:
                # ⚠️ Matched by exact name, not `results[0]`. `search` is a
                # substring match, so once an agency exists a search for
                # "ATLAS MDM" returns every deployment's provider in whatever
                # order Authentik chose — and taking the first would hand one
                # deployment another's provider, then PATCH its external_host to
                # the wrong hostname.
                _q = _urlparse.quote(_names['provider'])
                req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/?search={_q}', headers=_ak_headers)
                resp = _urlreq.urlopen(req, timeout=10)
                results = [r for r in json.loads(resp.read().decode())['results']
                           if r.get('name') == _names['provider']]
                if results:
                    provider_pk = results[0]['pk']
                    try:
                        req = _urlreq.Request(f'{_ak_url}/api/v3/providers/proxy/{provider_pk}/',
                            data=json.dumps({'external_host': _atlas_host, 'cookie_domain': _cookie}).encode(),
                            headers=_ak_headers, method='PATCH')
                        _urlreq.urlopen(req, timeout=10)
                    except Exception:
                        pass
                log("  ✓ Proxy provider already exists (external_host updated)")
            else:
                log(f"  ⚠ Proxy provider error: {str(e)[:100]}")

        if provider_pk:
            try:
                req = _urlreq.Request(f'{_ak_url}/api/v3/core/applications/',
                    data=json.dumps({'name': _names['app_name'],
                        'slug': _names['app_slug'],
                        'provider': provider_pk, 'open_in_new_tab': True}).encode(),
                    headers=_ak_headers, method='POST')
                _urlreq.urlopen(req, timeout=10)
                log("  \u2713 Application '%s' created" % _names['app_name'])
            except Exception as e:
                if hasattr(e, 'code') and e.code == 400:
                    try:
                        req = _urlreq.Request(
                            '%s/api/v3/core/applications/%s/' % (_ak_url, _names['app_slug']),
                            data=json.dumps({'provider': provider_pk, 'open_in_new_tab': True}).encode(),
                            headers=_ak_headers, method='PATCH')
                        _urlreq.urlopen(req, timeout=10)
                    except Exception:
                        pass
                    log("  \u2713 Application '%s' updated" % _names['app_name'])
                else:
                    log(f"  ⚠ Application error: {str(e)[:80]}")

            # ⚠️ **Before the outpost and the policy binding**, so the
            # group exists by the time anything is bound to it — and so an
            # operator reading the deploy log finds the name they have to add
            # people to, beside everything else that deployment created.
            ensure_agency_admin_group(ctx, inst, _ak_url, _ak_headers, plog=log)
            ctx['_outpost_add_providers_safe'](_ak_url, _ak_headers, [provider_pk], plog=log)
            ctx['_authentik_application_open_in_new_tab'](
                _ak_url, _ak_headers, _names['app_slug'], plog=log)
            # ⚠️ The answer is recorded, not discarded (SEC_AUDIT.md H-1). ATLAS
            # runs with an empty admin group — it trusts Authentik to decide who is
            # an administrator — so this binding *is* the access control. It was
            # once found absent on a live box, and nothing noticed. Now the result
            # is stored where the tile and the next update can see it.
            _record_access_state(
                ctx,
                _restrict_to_admins(_ak_url, _ak_headers, plog=log,
                                    app_slug=_names['app_slug']),
                plog=log, inst=inst)
        else:
            log("  ⚠ Could not create or find the ATLAS proxy provider")
    except Exception as e:
        log(f"  ⚠ Forward auth setup error: {str(e)[:100]}")
    return True


# --------------------------------------------------------------------------- #
# Versions, and updating to a newer one
# --------------------------------------------------------------------------- #

#: ⚠️ Slot-local, deliberately NOT the registry's deploy job slot. An update
#: and a deploy must never share a lock or a log: they can be started from
#: different pages seconds apart, and interleaving their output would make both
#: unreadable at exactly the moment somebody needs to read one.
#:
#: ⚠️ **And one slot per deployment, for the same reason one layer up.** A
#: module-global slot meant updating an agency wrote into the same log as the
#: plain deployment's, and the second update of a pair was refused as "already
#: running" against the first. Keyed by the job key `derive` already owns, so
#: the slot, the lock and the directory all agree on which deployment this is.
_update_slots = {}

#: The same, for removals. ⚠️ **Not the update slot.** A removal log rendered in
#: a card labelled "update" is how an operator comes to believe a deployment was
#: updated when it was destroyed; and the two must be able to refuse each other,
#: which they cannot do through one shared `running` flag.
_removal_slots = {}


def _new_slot():
    return {'running': False, 'complete': False, 'error': False, 'log': []}

#: The sequential run over every deployment. Separate from the per-deployment
#: slots because it outlives each of them and carries a result per deployment.
_update_all_status = {'running': False, 'complete': False, 'error': False,
                      'log': [], 'results': []}


def _update_slot(inst=None):
    """This deployment's update slot, created on first use."""
    return _update_slots.setdefault(
        atlas_instances.derive(inst)['job_key'], _new_slot())


def _removal_slot(inst=None):
    """This deployment's removal slot, created on first use."""
    return _removal_slots.setdefault(
        atlas_instances.derive(inst)['job_key'], _new_slot())


def removal_refusal(inst, deploy_running=False):
    """Why this deployment must not be torn down right now, or None.

    ⚠️ **Every one of these is a job that would be fighting over the same
    containers and the same checkout.** The deploy case is not hypothetical:
    measured on the box 2026-09-18, a removal started while a deploy was at
    step 4, ran `docker compose down -v` over the containers the deploy had just
    created, and the deploy failed three seconds later — with an empty message,
    because it read only `stderr`. Two jobs each reporting honestly about a box
    they were destroying for each other.

    A function rather than four `if`s in the route, because the route needs
    Flask to exist and this needs to be provable without it.
    """
    if _removal_slot(inst)['running']:
        return 'That deployment is already being removed'
    if _update_slot(inst)['running'] or _update_all_status['running']:
        return 'An update is running — wait for it to finish'
    if deploy_running:
        # ⚠️ Any deploy, not this deployment's: the registry runs deploy under
        # the module's own job key whatever is being built, so one slot covers
        # the box. Refusing too widely here costs a wait; refusing too narrowly
        # costs a deployment.
        return ('A deployment is being built right now. Wait for it to finish '
                'or fail before removing anything.')
    return None


def _run_removal(ctx, inst):
    """Tear one deployment down, in a thread, with a log the page can read.

    ⚠️ **A job rather than a synchronous request.** `docker compose down -v`,
    three unmounts and an `rmtree` over a store take minutes; a POST that blocks
    for them times out in the browser, and the operator is left not knowing
    whether a teardown that destroys a device CA ran or not.
    """
    from datetime import datetime

    slot = _removal_slot(inst)
    label = atlas_instances.derive(inst)['name']
    log = []

    def plog(msg):
        log.append('[' + datetime.now().strftime('%H:%M:%S') + '] ' + msg)
        slot['log'] = list(log)
        print('[' + label + '] remove: ' + msg, flush=True)

    slot.update({'running': True, 'complete': False, 'error': False, 'log': []})
    try:
        plog('Removing ' + label + ' — its device CA, database and store.')
        steps, errs = remove_instance(ctx, inst, plog)
        if errs:
            for line in errs:
                plog('ERROR: ' + line)
            slot.update({'running': False, 'complete': False, 'error': True})
            return
        plog('✓ ' + label + ' removed.')
        slot.update({'running': False, 'complete': True, 'error': False})
    except Exception as exc:
        plog('ERROR: ' + str(exc))
        slot.update({'running': False, 'complete': False, 'error': True})

#: Cheap cache for the upstream version check. GitHub allows 60 unauthenticated
#: requests an hour per IP and the console polls this for a badge; without a
#: cache a busy box spends its whole allowance and the badge silently blanks.
#:
#: ⚠️ **Keyed by channel.** One shared slot would serve `dev`'s number to a
#: box that had just switched to `main` for up to the TTL — fifteen minutes of
#: an update badge offering a release that channel does not carry, which is
#: exactly the confusion the switch exists to remove.
_latest_cache = {}
_LATEST_TTL = 900


def _parse_version(text):
    """``v1.2.3`` -> ``(1, 2, 3)``. None for anything that is not three numbers.

    ⚠️ Comparison is on the tuple, never the string: ``0.10.0`` sorts before
    ``0.9.0`` alphabetically, which would quietly stop offering updates at the
    tenth release of any series.
    """
    if not text:
        return None
    parts = str(text).strip().lstrip('vV').split('.')
    if len(parts) != 3:
        return None
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _channel_of(ctx=None, settings=None):
    """The release channel this box follows. `main` unless told otherwise.

    ⚠️ **An unrecognised value reads as the default, not as itself.** The
    setting is a plain string in the box's settings file; a typo, or a channel
    a newer module knew about and this one does not, must not become a branch
    name that gets pasted into a URL. Stable is the safe reading.
    """
    if settings is None:
        if ctx is None:
            return DEFAULT_CHANNEL
        try:
            settings = ctx['load_settings']()
        except Exception:
            return DEFAULT_CHANNEL
    value = ((settings or {}).get(CHANNEL_KEY) or '').strip().lower()
    return value if value in CHANNELS else DEFAULT_CHANNEL


def _latest_version(use_cache=True, channel=None):
    """What `channel` currently offers, or None when it cannot be established.

    ⚠️ None means *unknown*, not *up to date*. A rate-limited or offline box
    must never be told it is current; it is told nothing, and the page says so.

    ⚠️ **Read from `VERSION` at the branch tip, not from the tag list.** The
    tag list is what this used to do, and it is branch-blind — every box would
    be offered the newest tag in the repository whichever channel it followed,
    so `main` would have meant nothing at all. Tag *reachability* is not an
    alternative here: the mirror publishes one orphan commit per release, so no
    tag is reachable from any branch but its own.
    """
    import urllib.request

    channel = channel if channel in CHANNELS else DEFAULT_CHANNEL
    now = time.time()
    slot = _latest_cache.setdefault(channel, {'value': None, 'at': 0.0})
    if use_cache and slot['value'] and now - slot['at'] < _LATEST_TTL:
        return slot['value']
    try:
        request = urllib.request.Request(
            ATLAS_REPO_API + '/contents/VERSION?ref=' + channel,
            headers={'Accept': 'application/vnd.github.raw+json',
                     'User-Agent': 'infra-TAK-atlas-module'},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read().decode('utf-8', 'replace')
    except Exception:
        # Including a 404, which is what a mirror with no `dev` branch yet
        # answers. Unknown, and the page says so — never "up to date".
        return slot['value']

    text = body.strip()
    if text.startswith('{'):
        # ⚠️ The raw media type is a request, not a guarantee. A proxy that
        # rewrites Accept, or an older GitHub Enterprise, answers with the JSON
        # envelope instead; decoding it here costs three lines and saves a
        # version string of "{"name":"VERSION"..." being parsed as garbage.
        try:
            import base64
            payload = json.loads(text)
            text = base64.b64decode(payload.get('content') or '').decode(
                'utf-8', 'replace').strip()
        except Exception:
            return slot['value']

    if not _parse_version(text):
        return slot['value']
    slot.update({'value': text, 'at': now})
    return text


def _running_version(ctx=None, inst=None):
    """The version this deployment's container reports, or None.

    ⚠️ This is the one that matters for "did the update work". The checkout and
    the process can disagree: `docker compose up -d` without `--build` keeps the
    old image, so `VERSION` can read 1.3.0 while the running app still serves
    1.0.0. Reading the repo alone reports a successful deploy that never
    happened.

    Loopback and unauthenticated by design — the console runs beside the
    container, not through Authentik.
    """
    import urllib.request

    # ⚠️ This deployment's port. `APP_PORT` is the plain one, so with two
    # deployments the second would report the first's version — and an update
    # that did nothing would look like it had worked.
    port = instance_paths(ctx, inst)['port'] if (inst or ctx) else APP_PORT
    try:
        with urllib.request.urlopen(
            'http://127.0.0.1:%d/version' % port, timeout=5
        ) as response:
            body = json.loads(response.read().decode())
    except Exception:
        return None
    if body.get('service') != 'atlas-mdm':
        # Something else is answering on that port; its version means nothing here.
        return None
    return (body.get('version') or '').strip().lstrip('vV') or None


def _installed_version(ctx, inst=None):
    """The version on disk, read from the checkout rather than from settings.

    ⚠️ This is the same VERSION file the running console shows in its footer,
    so the two cannot disagree. A settings value could, if a deploy half-finished
    — and an update badge that contradicts the footer is worse than no badge.

    ⚠️ Extended for instances rather than copied (W216). A second function
    reading the same file is how two readings come to disagree; the default is
    the plain instance, so every existing call site is unchanged.
    """
    try:
        path = posixpath.join(instance_paths(ctx, inst)['dir'], 'VERSION')
        with open(path, encoding='utf-8') as handle:
            return handle.read().strip().lstrip('vV') or None
    except (OSError, ValueError):
        return None


def get_version_info(ctx):
    """`{version, update_available, latest}` — the shape the console cards read.

    ⚠️ The dashboard is where an operator actually notices an update; the
    module's own page is somewhere they go only once they already suspect one.
    `get_all_module_versions()` is what fills those cards, and a module absent
    from it simply shows no badge — silently, because nothing is broken.

    ⚠️ `update_available` is true only when *both* versions parsed and upstream
    is genuinely higher. An unreachable GitHub leaves `latest` null and the flag
    false, so a rate-limited box is never told it is current — it is told
    nothing, which the card renders as no badge rather than a reassuring one.
    """
    # ⚠️ **The deployment furthest behind, not the plain one.** This badge is
    # the only place an operator passively learns an update exists, and on a box
    # with several agencies the question "is there an update" is answered by
    # whichever is oldest — reporting the newest would hide the one that needs
    # doing. On a box with a single deployment this resolves to exactly what it
    # resolved to before.
    #
    # ⚠️ Versions read from checkouts, which is a file read each; the container
    # is asked only for the one deployment being reported, so this stays at the
    # single HTTP round-trip it always cost.
    _projects = compose_projects_present(ctx)
    _built = [i for i in load_instances(ctx)
              if instance_is_built(ctx, i, _projects)]
    # ⚠️ An unreadable VERSION sorts *oldest*, not newest. The file arrived in
    # 1.0.0, so a deployment without one predates every release we can see — and
    # is precisely the deployment that most needs telling.
    _built.sort(key=lambda i: _parse_version(_installed_version(ctx, i))
                or (0, 0, 0))
    _oldest = _built[0] if _built else None

    # ⚠️ The running container first, the checkout second. They agree on a
    # healthy deployment; when they do not, the running one is the truth and the
    # difference is a rebuild that did not take.
    checked_out = _installed_version(ctx, _oldest)
    running = _running_version(ctx, _oldest)
    installed = running or checked_out
    latest = _latest_version(channel=_channel_of(ctx))
    here, there = _parse_version(installed), _parse_version(latest)

    if there and not here:
        # ⚠️ An install with no readable VERSION predates the file itself, which
        # arrived in 1.0.0 — so it is older than any release we can see, and it
        # is precisely the deployment that most needs telling. Reporting "no
        # update" here would leave the oldest boxes the quietest.
        update = bool(installed is None or not installed)
    else:
        update = bool(here and there and there > here)

    info = {'version': installed or '', 'latest': latest, 'update_available': update}
    # Surfaced rather than hidden: a checkout ahead of the process means the last
    # rebuild did not take, and an operator reading only the version would see a
    # number that is not what is serving their fleet.
    if running and checked_out and running != checked_out:
        info['stale_image'] = True
        info['checked_out'] = checked_out
    return info


def _reconcile_agency_group(ctx, inst, plog):
    """Make sure this deployment's admin group exists and is admitted.

    Best effort: a box with no Authentik has nothing to reconcile, and an
    update must not fail over it.
    """
    try:
        settings = ctx['load_settings']()
        token = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not token:
            return
        ensure_agency_admin_group(
            ctx, inst, ctx['_get_authentik_api_url'](settings),
            {'Authorization': 'Bearer %s' % token,
             'Content-Type': 'application/json'}, plog=plog)
    except Exception as exc:
        plog('  ⚠ Could not reconcile the agency admin group: %s' % str(exc)[:80])


def _run_update(ctx, inst=None):
    """Fetch the newest release and rebuild in place. Data is never touched.

    ⚠️ This is `deploy` minus everything that would destroy state: no volume
    is removed and the install directory survives, so the database, the device CA
    and every enrolled tablet come through it intact. That is the whole
    difference between updating and reinstalling.

    The applications shipped with the new release load on start, and the agent
    among them is offered to the fleet — an update that left every device on
    the previous agent would be a fleet running a build this server no longer is.
    """
    from datetime import datetime

    slot = _update_slot(inst)
    # ⚠️ The same seam `deploy` uses, spelled the same way, so the guard that
    # catches half-threading in one catches it in the other.
    _me = deployment_identity(ctx, inst, ctx['load_settings']())
    _prefix = _me['settings_prefix']
    log = []

    def plog(msg):
        log.append('[' + datetime.now().strftime('%H:%M:%S') + '] ' + msg)
        slot['log'] = list(log)
        print('[' + _me['name'] + '] update: ' + msg, flush=True)

    slot.update({'running': True, 'complete': False, 'error': False, 'log': []})
    try:
        dirpath = _me['dir']
        if not os.path.isdir(os.path.join(dirpath, '.git')):
            raise RuntimeError('ATLAS is not installed from a git checkout')

        channel = _channel_of(ctx)
        target = _latest_version(use_cache=False, channel=channel)
        if not target:
            raise RuntimeError(
                'Could not read VERSION on the ' + channel + ' branch — GitHub '
                'is unreachable, rate-limited, or that branch does not exist')
        current = _installed_version(ctx, inst)
        plog(_me['name'] + ': installed ' + (current or 'unknown') +
             ' → ' + channel + ' offers ' + target)

        here, there = _parse_version(current), _parse_version(target)
        if here and there and there < here:
            # ⚠️ **Behind, not equal — and this is a refusal, not a no-op.**
            # It happens when a box switches from `dev` to `main`, or when a
            # release is withdrawn by moving `main` back. Running older code
            # against a database a newer release has already migrated is data
            # loss, so the way back is a forward fix on the channel, never this
            # button. Said plainly, because a button that looks like it did
            # nothing is a button an operator presses again.
            plog('✗ This deployment is on ' + (current or '?') + ', which is '
                 'newer than what the ' + channel + ' channel offers (' +
                 target + ').')
            plog('  Refusing to downgrade: ' + target + ' would run against a '
                 'database ' + (current or 'a newer release') + ' has migrated.')
            plog('  Switch back to the channel it came from, or publish a '
                 'forward fix.')
            slot.update({'running': False, 'complete': True, 'error': False})
            return
        if here and there and there == here:
            plog('✓ Already on the newest release for the ' + channel +
                 ' channel — nothing to do')
            slot.update({'running': False, 'complete': True, 'error': False})
            return

        tag = 'v' + target
        plog('━━━ Step 1/3: Fetching ' + tag + ' ━━━')
        # The module rewrites .env and the compose override on every deploy, so
        # the working tree is dirty on tracked files and a plain pull aborts with
        # "local changes would be overwritten".
        ctx['_module_git'](dirpath, 'checkout', '--', '.', timeout=60)
        r = subprocess.run(
            ['git', '-C', dirpath, 'fetch', '--tags', '--depth=1', 'origin', tag],
            capture_output=True, text=True, timeout=600,
        )
        if r.returncode != 0:
            raise RuntimeError('git fetch failed: ' + (r.stderr or '')[-300:])
        ctx['_module_git'](dirpath, 'checkout', '-f', tag, timeout=60)
        _write_build_file(dirpath, plog)
        # ⚠️ **Before anything reads it (W243).** A deployment built
        # before W240 has a root-owned `.env`; the readers below now raise
        # rather than swallow, so without this an update of exactly the
        # population that has the bug would stop dead.
        _repair_env_ownership(os.path.join(dirpath, '.env'), ctx, plog)
        plog('✓ Source now at ' + tag)

        # ⚠️ Before the rebuild, or the new image starts without the setting and
        # spends a release accepting identity headers from anywhere.
        _set_trusted_proxies(dirpath, plog, _me['compose_project'])

        plog('━━━ Step 2/3: Rebuilding ━━━')
        # ⚠️ No `-v` anywhere here. `down -v` would take the database and the
        # device CA with it, and every enrolled tablet would need a factory reset.
        r = _compose(ctx, 'up -d --build api', timeout=1800, inst=inst)
        if r.returncode != 0:
            raise RuntimeError(compose_error(r, 'docker compose up'))
        plog('✓ Containers rebuilt — database and device CA untouched')
        plog('  The agent and launcher from this release load on start, and the')
        plog('  new agent is offered to the fleet on each device\'s next check-in.')

        # ⚠️ Re-asked on every update, because the binding can disappear long
        # after the deploy that made it — an Authentik restore, or somebody
        # unbinding the policy. A check that only runs at install answers a
        # question about the past (H-1).
        _verify_access_control(ctx, plog=plog, inst=inst)
        # ⚠️ Idempotent, and the only route by which a deployment made before
        # W221 gets its group and its binding at all.
        _reconcile_agency_group(ctx, inst, plog)

        # ⚠️ Re-emit the vhost. `deploy` does this and `update` did not, so a
        # change to what ATLAS's Caddy block contains reached the box and then
        # sat there: the operator updates, nothing regenerates, and the new
        # directive only appears if somebody happens to redeploy. That is how
        # the upload body limit (SEC_AUDIT M-1) would have shipped inert.
        #
        # Regenerating is what deploy already does and is idempotent — the file
        # is built from current settings either way.
        try:
            ctx['generate_caddyfile'](ctx['load_settings']())
            ctx['_caddy_reload'](plog)
            plog('✓ Caddy vhost re-emitted')
            # ⚠️ Only now, with the freshly generated vhost on disk to check.
            # An install that predates these gates picks them up here.
            # ⚠️ Reconciled on every update, which is the only way a
            # deployment made before W221 gains its agency group — `deploy` is
            # the one thing that rewrites `.env` wholesale, and an operator is
            # not going to tear a working deployment down for a setting.
            changed = _arm_admin_gates(ctx, dirpath, plog, inst=inst,
                                       global_group=_global_admin_group(ctx))
            changed = _push_email_relay(ctx, dirpath, plog) or changed
            if changed:
                _compose(ctx, 'up -d api', timeout=300, inst=inst)
        except Exception as exc:
            # Not fatal. The containers are already rebuilt and serving; a stale
            # vhost is worse reported than turned into a failed update.
            plog('⚠ Could not re-emit the Caddy vhost: ' + str(exc))

        plog('━━━ Step 3/3: Recording ━━━')
        s = ctx['load_settings']()
        s[f'{_prefix}version'] = target
        # ⚠️ **The commit too, not just the version.** This was written only
        # at deploy, so after an update the record said 1.50.0 beside the
        # commit of v1.49.0 — found on the box. Nothing reads it today, which
        # is exactly why it could drift: a provenance record that quietly
        # describes a different build is worth less than none, because it
        # will be believed. `tvr` already refreshes its own here.
        head = _module_head(ctx, dirpath)
        if head:
            s[f'{_prefix}commit_sha'] = head
        ctx['save_settings'](s)
        plog('✓ ' + _me['name'] + ' updated to v' + target)
        slot.update({'running': False, 'complete': True, 'error': False})
    except Exception as exc:
        plog('ERROR: ' + str(exc))
        slot.update({'running': False, 'complete': False, 'error': True})


def _run_update_all(ctx):
    """Update every finished deployment, in order, without stopping at a failure.

    ⚠️ **Continue on failure, with a result per deployment.** A single success
    flag would report a run where three of five agencies failed as a failure
    with no way to tell which — or, worse, as a success because the last one
    worked. Stopping at the first failure is no better: it leaves the remaining
    agencies on an old release for a reason that has nothing to do with them.

    ⚠️ **Unfinished deployments are skipped, not attempted.** They have no
    containers and no configuration; `update` would fail on the missing checkout
    and report that as an update failure, when what they need is a deploy.
    """
    from datetime import datetime

    log = []

    def plog(msg):
        log.append('[' + datetime.now().strftime('%H:%M:%S') + '] ' + msg)
        _update_all_status['log'] = list(log)
        print('[' + KEY + '] update-all: ' + msg, flush=True)

    _update_all_status.update({'running': True, 'complete': False,
                               'error': False, 'log': [], 'results': []})
    results = []
    try:
        found = load_instances(ctx)
        projects = compose_projects_present(ctx)
        plog('%d deployment(s) on this box' % len(found))
        for inst in found:
            name = atlas_instances.derive(inst)['name']
            if not instance_is_built(ctx, inst, projects):
                plog('— ' + name + ': skipped, not finished deploying')
                results.append({'name': name, 'slug': inst.get('slug'),
                                'ok': None, 'detail': 'not finished deploying'})
                _update_all_status['results'] = list(results)
                continue
            plog('━━━ ' + name + ' ━━━')
            _run_update(ctx, inst)
            slot = _update_slot(inst)
            for line in slot['log']:
                log.append('    ' + line)
            _update_all_status['log'] = list(log)
            ok = bool(slot['complete']) and not slot['error']
            results.append({
                'name': name, 'slug': inst.get('slug'), 'ok': ok,
                'detail': ('updated to ' + (_installed_version(ctx, inst) or '?')
                           if ok else 'failed — see the log above'),
            })
            _update_all_status['results'] = list(results)
        failed = [r for r in results if r['ok'] is False]
        if failed:
            plog('✗ %d of %d deployment(s) failed: %s'
                 % (len(failed), len(results),
                    ', '.join(r['name'] for r in failed)))
        else:
            plog('✓ Every finished deployment is on the newest release')
        # ⚠️ `complete` is true either way: the run finished. `error` says
        # whether any deployment failed. Conflating them would make a partial
        # success look like a run that never ended.
        _update_all_status.update({'running': False, 'complete': True,
                                   'error': bool(failed)})
    except Exception as exc:
        plog('ERROR: ' + str(exc))
        _update_all_status.update({'running': False, 'complete': False,
                                   'error': True})


# --------------------------------------------------------------------------- #
# Uninstall
# --------------------------------------------------------------------------- #


def remove_instance(ctx, inst, plog=None):
    """Remove one deployment and everything that belongs to it.

    Returns `(steps, errors)`. Best-effort and re-runnable: every step is
    idempotent, so a teardown that failed halfway can be repeated.

    ⚠️ **This destroys that deployment's device CA and database.** Every tablet
    enrolled against it is signed by that CA; once it is gone they cannot be
    re-adopted, only factory reset in person. Deployments do not share a CA —
    that is the whole point of the per-agency trust pool — so this is precisely
    one agency's fleet, and never another's.

    ⚠️ **Order is the reverse of deploy, and `remove_store` comes before the
    `rmtree`.** Three mount points live *inside* the install directory and
    `shutil.rmtree` cannot delete through a mount. W212 was exactly this, and it
    reported success.

    ⚠️ **What it must not touch:** the 8449 firewall rule and `atlas_enabled`
    are box-wide. Caddy selects the device site by SNI, so every deployment
    shares that listener; removing the rule with the first agency would take the
    device port away from every remaining one. `uninstall` handles those, once.
    """
    log = plog or (lambda _msg: None)
    steps, errs = [], []

    def note(msg):
        # ⚠️ Recorded *and* logged, together. Appending to `steps` and logging
        # separately meant `remove_store`'s own progress lines appeared twice —
        # once raw from its plog, once labelled from the returned list — and a
        # teardown log that repeats itself reads like a teardown that ran twice.
        steps.append(msg)
        log(msg)

    paths = instance_paths(ctx, inst)
    names = atlas_instances.authentik_names(inst)
    label = paths['name']
    dirpath = paths['dir']

    # Volumes go with the containers: `down -v` is the only step that removes
    # the database, and it needs the compose file, so it runs before the
    # directory does.
    if os.path.isdir(dirpath):
        _compose(ctx, 'down -v --remove-orphans', timeout=300, inst=inst)
        note(f'{label}: containers, network and database volume removed')
    else:
        note(f'{label}: no install directory — nothing to stop')

    # ⚠️ This deployment's images, named from its compose project. `takmdm-api`
    # was hardcoded, so an agency's images survived every teardown.
    if _run(ctx, ['docker', 'image', 'rm', '-f'] + list(paths['images'])):
        note(f'{label}: images removed')

    # ⚠️ A silent plog: its lines come back in `store_did` and are noted
    # below, so letting it log as well printed each of them twice.
    store_did, store_errs = remove_store(ctx, lambda *_a: None, inst)
    for line in store_did:
        note(f'{label}: {line}')
    if store_errs:
        # ⚠️ Stop here rather than attempting the rmtree. The mounts are what
        # blocks it, and deleting *around* them is how W212 came to report a
        # clean uninstall over a directory still holding the device CA.
        errs.extend(f'{label}: the reserved store could not be removed: '
                    f'{line}' for line in store_errs)
        note(f'{label}: STOPPED before deleting the install directory, '
             f'so the device CA and database are still on disk. Re-run '
             f'once the mounts are clear.')
        return steps, errs

    for stale in _stale_deploy_key(dirpath):
        try:
            os.remove(stale)
            note(f'{label}: obsolete deploy key removed')
        except OSError:
            pass

    # ⚠️ **Neither of these is the console's to delete, and both looked like
    # they were.** The install directory holds `pki/`, which the application
    # creates `drwx------` under its own uid — `shutil.rmtree` stops there
    # with `Permission denied: 'pki'`, measured on the box. Caddy's copy lives
    # under `/var/lib/caddy`, which the console cannot write at all. Both go
    # through `_rm_priv`, which falls back to the broker.
    #
    # ⚠️ Each names the directory it must be inside, because this ends in
    # `rm -rf` as root.
    for path, inside, what in (
            (dirpath, install_base(ctx),
             'install directory (device CA, artifacts, .env)'),
            (_caddy_ca_dir(inst), caddy_base(),
             "Caddy's copy of the device CA")):
        if not path or not os.path.isdir(path):
            continue
        err = _rm_priv(path, inside)
        if err:
            errs.append(f'{label}: {what} could not be removed: {err}')
        else:
            note(f'{label}: {what} removed')

    if errs:
        # ⚠️ **Nothing below this line may run.** Clearing
        # `atlas_<slug>_pg_password` while that database is still on disk is what
        # arms the *next* deploy to fail forever: it generates a fresh password,
        # Postgres keeps the old one because the data directory is not empty, and
        # the API sits on "password authentication failed" with no way back.
        # Dropping the record would be worse still — the store, the CA and the
        # database would all be on the box with nothing left that knows about
        # them.
        note(f'{label}: STOPPED — its record, settings and Authentik '
             f'application are left in place, so this can be re-run '
             f'once whatever is holding those files lets go.')
        return steps, errs

    # ⚠️ This deployment's own Authentik objects. The helper matches the
    # provider by *exact* name, so `ATLAS MDM Proxy` never resolves to
    # `ATLAS MDM Proxy (corona)` and an agency teardown cannot sign every
    # administrator out of the plain console.
    try:
        ctx['_deregister_authentik_proxy_app'](
            ctx['load_settings'](), names['app_slug'], names['provider'])
        note(f"{label}: Authentik application '{names['app_slug']}' removed")
    except Exception:
        note(f'{label}: Authentik application not present (not configured)')

    # ⚠️ **And its admin group.** Deregistering the application leaves the
    # group behind; an orphan grants nothing, so nobody notices until a slug
    # is reused and the new deployment inherits the old members.
    group_note = remove_agency_admin_group(ctx, inst)
    if group_note:
        note(f'{label}: {group_note}')

    # ⚠️ Only the keys this deployment owns. `atlas_` is a prefix of
    # `atlas_corona_`, so a `startswith` sweep while removing the *plain*
    # deployment would take every agency's database password with it.
    settings = ctx['load_settings']()
    owned = atlas_instances.owned_settings_keys(
        inst, list(settings), load_instances(ctx))
    for key in owned:
        settings.pop(key, None)
    ctx['save_settings'](settings)
    if owned:
        note(f'{label}: {len(owned)} generated setting(s) cleared')

    drop_instance(ctx, (inst or {}).get('slug'))
    note(f'{label}: removed from the deployment list')

    # ⚠️ Regenerated from the settings that are left, so this deployment's vhost
    # goes and every remaining one stays. Emitting nothing, or skipping this,
    # leaves Caddy asking for a certificate for a host with no upstream.
    try:
        ctx['generate_caddyfile'](ctx['load_settings']())
        ctx['_caddy_reload']()
        note(f'{label}: Caddy vhost removed')
    except Exception as exc:
        errs.append(f'{label}: Caddy could not be reloaded: {exc}')

    return steps, errs


def uninstall(ctx, job, params):
    """Remove ATLAS completely — every deployment on this box.

    ⚠️ **This destroys every device CA and every database, and that is
    deliberate.** Each enrolled tablet's identity is signed by its deployment's
    CA; once that is gone they cannot be re-adopted, only factory reset in
    person. The console asks for a password and says so before calling this.

    The alternative — keeping the data "just in case" — was worse in practice:
    an operator who uninstalls expects the box to be as it was, and a leftover
    database silently decided the *next* install's fate, because Postgres only
    honours POSTGRES_PASSWORD on an empty volume. Install regenerates all of it.

    ⚠️ **It used to remove only the plain deployment** — `atlas_dir(ctx)` and
    `remove_store(ctx, …, inst=None)` — so on a box running one agency and no
    plain ATLAS it reported success having removed nothing at all. That is W212
    again, multiplied by the number of agencies, and it is the reason this
    iterates.

    ⚠️ **Continue on failure, and report the failure.** One agency whose mounts
    are busy must not leave four others installed, and an uninstall that
    half-worked is not a thing to report as done.
    """
    steps, errs = [], []

    found = load_instances(ctx)
    if not found:
        steps.append('No ATLAS deployment recorded on this box')
    for inst in found:
        did, failed = remove_instance(ctx, inst)
        steps.extend(did)
        errs.extend(failed)

    if errs:
        # ⚠️ **The box-wide clear-out does not run.** A deployment whose files
        # survived is still a deployment: it needs its device port, its
        # settings and `atlas_enabled` so the console can still see it and the
        # operator can try again. Wiping those would leave a running ATLAS that
        # the console reports as absent, with a database nothing holds the
        # password for.
        #
        # Caddy *is* regenerated: the deployments that succeeded are out of the
        # list now, so this removes their vhosts and keeps the rest.
        try:
            ctx['generate_caddyfile'](ctx['load_settings']())
            ctx['_caddy_reload']()
        except Exception:
            pass
        return {
            'success': False,
            'error': '; '.join(errs),
            'steps': steps + [
                'STOPPED SHORT: the deployments above that failed still have '
                'files on disk, and their settings and records are untouched so '
                'this can be re-run. The log above names what would not go.'
            ],
        }

    # ⚠️ Only now, once every deployment is gone. Caddy selects the device site
    # by SNI so all of them share 8449, and removing the rule earlier would take
    # the device listener away from the deployments still running.
    ctx['_fw_remove'](DEVICE_PORT, 'tcp')
    steps.append(f'Firewall rule for {DEVICE_PORT}/tcp removed')

    # ⚠️ **Nesting created this directory, so nesting cleans it up (W233).**
    # Before deployments nested, every one of them *was* a top-level directory
    # and removing them left nothing behind; now they share `<base>/atlas`,
    # which would survive as an empty husk.
    #
    # ⚠️ `rmdir`, never a recursive remove. It refuses a directory that
    # still holds something -- a stranded deployment the console could not
    # reach, or anything an operator put there -- which makes "only when
    # empty" true by construction instead of by a check that could be wrong.
    # Failing is fine and is not reported: an uninstall is not incomplete
    # because a directory somebody else is using stayed.
    try:
        os.rmdir(atlas_root(ctx))
        steps.append('Empty ATLAS directory removed')
    except OSError:
        pass

    # ⚠️ Every generated value goes, agencies included. `startswith` is right
    # *here* — the point is to leave nothing — where in `remove_instance` it
    # would have taken a running agency's database password.
    s_now = ctx['load_settings']()
    for key in [k for k in list(s_now) if k.startswith(f'{KEY}_')]:
        s_now.pop(key, None)
    s_now[f'{KEY}_enabled'] = False
    ctx['save_settings'](s_now)
    ctx['generate_caddyfile'](s_now)
    ctx['_caddy_reload']()
    steps.append('Generated settings cleared and Caddy vhosts removed')

    return {'success': True, 'steps': steps}


def _caddy_ca_dir(inst=None):
    """Where a deployment's Caddy-readable device CA is staged, or None.

    Mirrors sync_device_ca_for_caddy above: Caddy runs unprivileged and cannot
    read the install directory, so the certificate is copied into its own home.
    A stale copy left behind would have Caddy verifying client certificates
    against a CA that no longer exists.

    ⚠️ **Per deployment**, matching where `sync_device_ca_for_caddy` puts it.
    Hardcoded to `atlas`, tearing down an agency would have deleted the *plain*
    deployment's trust pool — and Caddy then refuses to start, taking every
    vhost on the box with it, not only ATLAS's.
    """
    name = atlas_instances.derive(inst)['name']
    for base in ('/var/lib/caddy', os.path.expanduser('~caddy')):
        candidate = os.path.join(base, name)
        if os.path.isdir(candidate):
            return candidate
    return None


def _run(ctx, argv):
    """Best-effort root command; True when it succeeded."""
    try:
        p = subprocess.run(ctx['_sudo_wrap'](list(argv)), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=120)
        return p.returncode == 0
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Templates written into the install directory
# --------------------------------------------------------------------------- #

_ENV_TEMPLATE = """# Written by the infra-TAK ATLAS module. Edited by hand at your own risk:
# a re-deploy rewrites this file.
#
# ⚠️ Every name here must appear as ${{...}} in ATLAS's docker-compose.yml.
# There is no `env_file`, so a variable written here and not referenced there
# reaches nothing and fails silently.

# Generated once and kept. Regenerating on a re-deploy would leave the existing
# database unopenable by the application that owns it.
TAKMDM_DB_PASSWORD={pg_password}

# Caddy terminates TLS with a publicly-issued certificate, so provisioning must
# NOT tell devices to pin this deployment's own CA — they would fail the
# handshake at enrolment with nothing on the tablet to explain it.
TAKMDM_INCLUDE_SERVER_CA=0

# What a device is told to talk to: Caddy's device vhost, not the app.
TAKMDM_SERVER_URL={device_url}

# Where a tablet in out-of-box setup fetches the agent. Plain HTTP on the
# well-known port, through Caddy — an Android setup wizard follows no redirect
# and its integrity check is the signature checksum in the QR.
TAKMDM_AGENT_APK_URL={apk_url}

# The console's public origin, for the cross-origin check.
TAKMDM_CONSOLE_ORIGIN={console_url}

# Who this deployment serves, shown in the footer of every page of its console.
#
# One box can run several ATLAS deployments side by side, one per agency, and
# once you are signed in they are identical — the hostname is not on screen.
# An administrator supporting two of them needs to know which console is in
# front of them before they push a policy or wipe a tablet.
#
# Blank is the ordinary case for a single-agency box and renders nothing.
TAKMDM_AGENCY_NAME={agency_name}

# Authentik terminates administrator sign-in and forwards the identity.
TAKMDM_ADMIN_AUTH_MODE=forward_auth

# ⚠️ Deliberately empty: Authentik decides, not ATLAS.
#
# ATLAS can require a group of its own, but on infra-TAK that would mean a
# second place to manage access and a group the operator has never heard of —
# and until somebody created it and added themselves, nobody could sign in at
# all. infra-TAK's access-policy converge is default-deny: the ATLAS
# application it registers is bound to "Allow authentik Admins" because it is
# not on the user-visible allowlist. So the console is admin-only, enforced at
# the identity provider, and blank here means "whoever Authentik let through".
TAKMDM_ADMIN_GROUP=

# Where the administrative interface may be reached from (SEC_AUDIT.md S-1).
#
# ATLAS reads the administrator's identity out of the headers Caddy sets after
# forward_auth. Nothing in those headers proves they came from Caddy, so anything
# able to open a socket to this application's port is an administrator by sending
# two headers. This bounds who that can be.
#
# The value is the Docker bridge gateway: Caddy runs on the host and reaches the
# container through it, so that is the address the application actually observes.
#
# ⚠️ **This cannot tell Caddy from anything else on this host** — every host
# process arrives from the same gateway. It closes the case where the port is
# republished on 0.0.0.0 and reached from somewhere else. Host-local forgery needs
# the proxy to prove it is the proxy, which is what infra-TAK's own
# X-Infratak-Proxy-Auth secret does for the console and does not yet offer to
# module vhosts.
#
# Set it to `any` to switch the check off. ATLAS logs the address it refused and
# the ranges it allows, so a wrong value here is one log line from a fix.
TAKMDM_TRUSTED_PROXIES={trusted_proxies}
"""

_COMPOSE_OVERRIDE = """# Written by the infra-TAK ATLAS module.
#
# Caddy is the only thing that talks to this application, so it binds loopback
# and publishes nothing else. ATLAS's own nginx is simply not started — `up -d
# api` brings the database and the migration step with it and stops there.
services:
  api:
    ports:
      - "127.0.0.1:{app_port}:8000"

  # ⚠️ **No `user:` here, and that was tried.** Running the containers as
  # the console's own uid would have removed the host-side chown entirely,
  # which is why it was attempted — and both images refused. Postgres could
  # not chmod its data directory (*"initdb: could not change permissions"*)
  # and ATLAS's image is `USER takmdm`, so its init step died with
  # `PermissionError: /pki/ca.crt`. Each image expects to own what it writes.
  # The ownership is therefore fixed on the host, through the broker, before
  # anything starts.

  # No self-signed server certificate. Caddy holds a publicly-issued one, and a
  # local CA here would end up pinned in provisioning QRs that then fail.
  init:
    command: ["python", "-m", "app.cli", "init-pki"]
"""


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def register(ctx):
    from flask import jsonify, request

    def _requested_instance(default_first=False):
        """The deployment a request is about, from `?slug=` or a JSON body.

        ⚠️ **An unknown slug is refused, never silently treated as the plain
        deployment.** `by_slug` answers None for both "no slug given" and "no
        such slug", and letting the second fall through would point a restart,
        an update or a log read at whichever deployment happens to be plain.

        ⚠️ `default_first` exists for the page's single-deployment views: a box
        with only an agency has no plain deployment, and answering about nothing
        would show an empty console for a deployment that is running.
        """
        from flask import request as _rq
        raw = _rq.args.get('slug')
        if raw is None and _rq.method != 'GET':
            raw = (_rq.get_json(silent=True) or {}).get('slug')
        found = load_instances(ctx)
        if raw:
            inst = atlas_instances.by_slug(found, raw)
            if inst is None:
                return None, 'no deployment with that slug'
            return inst, None
        plain = atlas_instances.plain(found)
        if plain is not None or not default_first:
            return plain, None
        return (found[0] if found else None), None

    def logs_view():
        inst, err = _requested_instance(default_first=True)
        if err:
            return jsonify({'lines': [err]})
        try:
            r = ctx['probe_run'](
                ['docker', 'logs', '--tail', '200', api_container(ctx, inst)],
                text=True, timeout=10)
            lines = ((r.stdout or '') + (r.stderr or '')).splitlines()
        except Exception as exc:
            lines = [f'could not read logs: {exc}']
        return jsonify({'lines': lines[-200:]})

    def ca_view():
        """What one deployment's certificate authority looks like.

        ⚠️ Every deployment has its own root, its own issuing certificate and
        its own expiry. Answering for the plain one whatever was asked reported
        *"ATLAS is not running"* over a healthy, split CA on a box whose only
        deployment was an agency.
        """
        inst, err = _requested_instance(default_first=True)
        if err:
            return jsonify({'ok': False, 'error': err}), 200
        # ⚠️ Uncached: this is the panel an operator is *looking at*, and
        # they open it to see the effect of something they just did. The
        # cache exists for the box-wide banner, which is polled.
        body = _ca_status(ctx, inst=inst, use_cache=False)
        if body is None:
            return jsonify({'ok': False, 'error': 'ATLAS is not running'}), 200
        # ⚠️ Carried back so the page can label the block and the modals know
        # which deployment they are about. Without it a page showing three CAs
        # has three identical-looking panels.
        names = atlas_instances.derive(inst)
        body['slug'] = names['slug']
        body['name'] = names['name']
        return jsonify(body)

    def ca_renew_view():
        """Run the intermediate ceremony: take the root key, use it, destroy it.

        ⚠️ **This handles the most dangerous secret in the system.** The root key
        arrives in a request body, is written to disk for the length of one
        command, and is removed in a `finally`. That is a real moment of exposure
        and it is inherent to the ceremony — the alternative is an operator doing
        the same thing by hand over SSH, which exposes it just as much and has no
        guarantee the cleanup happens at all.
        """
        data = request.get_json(silent=True) or {}
        err = _check_admin_password(ctx, data)
        if err:
            return jsonify({'success': False, 'error': err}), 403

        inst, bad = _requested_instance(default_first=True)
        if bad:
            return jsonify({'success': False, 'error': bad}), 404

        key_pem = (data.get('root_key') or '').strip()
        days = data.get('days') or 1825
        try:
            days = int(days)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'days must be a number'}), 400
        if days < 1 or days > 7300:
            return jsonify({'success': False, 'error': 'days must be 1-7300'}), 400

        pki = _pki_dir(ctx, inst)
        if pki is None:
            return jsonify({'success': False,
                            'error': 'That deployment is not installed here'}), 404
        key_path = os.path.join(pki, 'ca.key')

        # ⚠️ A root key already present is the legacy state, not an error — the
        # ceremony is exactly how it stops being present. But it must not be
        # silently replaced by whatever was pasted: that would be a way to swap the
        # CA of a running fleet through a web form.
        # ⚠️ **Ask the deployment, do not stat (W235).** This probed
        # `os.path.exists(key_path)` as the console. `pki/` is `drwx------`
        # owned by the container's uid, so the answer was False whatever was
        # on disk: with the root key sitting right there, the empty-field
        # path refused with "no root key on the server and none supplied"
        # and the supplied-key path tried to write into a directory the
        # console cannot write. Renewal was impossible on a non-root box by
        # either route. Found by the operator, on the box.
        status = _ca_status(ctx, inst=inst, use_cache=False)
        if status is None:
            return jsonify({'success': False,
                            'error': 'ATLAS is not running'}), 409
        on_server = bool(status.get('root_key_on_server'))

        supplied = False
        if key_pem:
            if on_server:
                return jsonify({
                    'success': False,
                    'error': 'a root key is already on the server; leave the field '
                             'empty to use it, or remove it first',
                }), 409
            if 'PRIVATE KEY' not in key_pem:
                return jsonify({'success': False, 'error': 'that is not a PEM private key'}), 400
            try:
                staging_err = _write_root_key(key_path, key_pem, ctx, inst)
            except Exception as exc:
                staging_err = 'could not stage the key: %s' % exc
            if staging_err:
                return jsonify({'success': False, 'error': staging_err}), 500
            supplied = True
        elif not on_server:
            return jsonify({
                'success': False,
                'error': 'no root key on the server and none supplied',
            }), 400

        steps = []
        try:
            out = _compose_exec(
                ctx,
                ['python', '-m', 'app.cli', 'ca-issue-intermediate', '--days', str(days)],
                timeout=120, inst=inst,
            )
            if out is None:
                return jsonify({'success': False, 'error': 'ATLAS is not running'}), 409
            # ⚠️ Never echo the command's whole output back without looking: it is
            # written for a terminal and names file paths, which is fine, but the
            # key must never appear. It does not — the CLI prints paths, not
            # contents — and this is the line that has to stay true.
            steps.append(out.strip())
            issued = 'issuing CA' in out
        finally:
            # ⚠️ Always, on every path, including the failure ones. An operator who
            # supplied a root key and got an error must not be left with it sitting
            # on the server — that is precisely the state the whole exercise exists
            # to avoid, reached by trying to fix it.
            if supplied:
                removed = _shred(key_path, ctx, inst)
                steps.append('Root key removed from the server' if removed
                             else '⚠ COULD NOT REMOVE %s — delete it by hand NOW' % key_path)

        if not issued:
            return jsonify({'success': False, 'error': 'the command did not issue a '
                                                       'certificate', 'steps': steps}), 500

        # The new trust bundle has to reach Caddy or devices fail at the edge.
        # ⚠️ *This* deployment's bundle, into *this* deployment's Caddy
        # directory. Staging the plain one would leave the renewed agency
        # verifying devices against the certificate it just replaced.
        # ⚠️ The CA just changed, so the cached `ca-status` is stale and the
        # banner would go on reporting the pre-ceremony answer for up to the
        # TTL -- including "the root key is still here" after a delete.
        _forget_ca_status(inst)

        staged = sync_device_ca_for_caddy(inst, ctx)
        steps.append('Trust bundle staged for Caddy' if staged
                     else '⚠ Could not stage the trust bundle for Caddy')
        ctx['_caddy_reload']()

        r = _compose(ctx, 'restart api', timeout=180, inst=inst)
        steps.append('%s restarted' % atlas_instances.derive(inst)['name']
                     if r.returncode == 0 else '⚠ Restart failed')
        return jsonify({'success': True, 'steps': steps})

    def ca_recovery_view():
        """Hand the root key to the operator, once, to save.

        ⚠️ **POST with the console password, not a GET.** `login_required`
        already gates it, but the most dangerous secret in the system should not
        be one URL away from an open tab — and a GET would land in browser
        history, in the access log, and in anything that prefetches links. The
        key goes in a JSON body the page turns into a download client-side.
        """
        data = request.get_json(silent=True) or {}
        err = _check_admin_password(ctx, data)
        if err:
            return jsonify({'success': False, 'error': err}), 403

        inst, bad = _requested_instance(default_first=True)
        if bad:
            return jsonify({'success': False, 'error': bad}), 404

        rc, out = _compose_exec_rc(
            ctx, ['python', '-m', 'app.cli', 'ca-export-root'], inst=inst)
        if rc is None:
            return jsonify({'success': False, 'error': 'ATLAS is not running'}), 409
        if rc != 0:
            return jsonify({'success': False, 'error': out or 'no root key on this server'}), 409
        if 'PRIVATE KEY' not in out:
            return jsonify({'success': False, 'error': 'that did not look like a key'}), 500

        return jsonify({
            'success': True,
            'key_pem': out,
            'filename': recovery_filename(ctx['load_settings'](), inst),
        })

    def ca_recovery_confirm_view():
        """Check the operator really has the file, then remove it from the box.

        ⚠️ **Verify and delete are one call on purpose.** Two endpoints would
        allow a verified-but-not-deleted state, which is exactly the half-finished
        ceremony W185 found the console misreporting. Either the customer proves
        they hold the recovery file and the root goes, or nothing changes.
        """
        data = request.get_json(silent=True) or {}
        err = _check_admin_password(ctx, data)
        if err:
            return jsonify({'success': False, 'error': err}), 403

        inst, bad = _requested_instance(default_first=True)
        if bad:
            return jsonify({'success': False, 'error': bad}), 404

        key_pem = (data.get('root_key') or '').strip()
        if not key_pem:
            return jsonify({'success': False, 'error': 'upload your recovery file first'}), 400

        steps = []
        rc, out = _compose_exec_rc(
            ctx, ['python', '-m', 'app.cli', 'ca-verify-root'],
            stdin=key_pem if key_pem.endswith('\n') else key_pem + '\n',
            inst=inst,
        )
        if rc is None:
            return jsonify({'success': False, 'error': 'ATLAS is not running'}), 409
        if rc != 0:
            # ⚠️ The root is untouched on this path, and that is the point. A
            # customer who uploads the wrong file must end up exactly where they
            # started, with a message that says which mistake they made.
            return jsonify({'success': False, 'error': out or 'that file does not match'}), 400
        # ⚠️ Names the deployment. An operator holding three recovery
        # files needs to be told which one this matched, not that 'a'
        # file matched.
        steps.append('✓ Recovery file checked against %s\'s certificate authority'
                     % atlas_instances.derive(inst)['name'])

        # "Check my recovery file", years later, when the root is long gone.
        # ⚠️ Stops here deliberately. Running the delete would be a no-op and
        # would report a removal that did not happen in this call.
        if data.get('verify_only'):
            steps.append('This file can still renew your certificate authority.')
            steps.append('Nothing was changed.')
            return jsonify({'success': True, 'steps': steps})

        rc, out = _compose_exec_rc(
            ctx, ['python', '-m', 'app.cli', 'ca-delete-root'], timeout=60,
            inst=inst,
        )
        if rc is None:
            return jsonify({'success': False, 'error': 'ATLAS stopped responding',
                            'steps': steps}), 409
        if rc != 0:
            return jsonify({'success': False, 'error': out or 'could not remove the key',
                            'steps': steps}), 500
        _forget_ca_status(inst)
        steps.append('✓ Root key removed from this server')
        steps.append('Nothing on any device changes. Keep the file somewhere safe —')
        steps.append('you will need it to renew, in about five years.')
        return jsonify({'success': True, 'steps': steps})

    def instances_view():
        """The deployments on this box, and how much room is left for more.

        ⚠️ A live route, not a value baked into the page, for the same reason
        `store_view` is: free space and memory move as the other modules grow,
        and a figure rendered once at load would offer room that has since gone.
        """
        try:
            from flask import request as _rq
            return jsonify(instances_payload(
                ctx, size_gb=_rq.args.get('size_gb', type=float)))
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    def instance_create_view():
        """Record a new deployment. Does not build it — that is the deploy job.

        ⚠️ **`agency_specific` is sent explicitly rather than inferred from the
        slug.** "No slug" and "the operator left the slug blank" are different
        answers, and guessing between them would let an empty box silently
        receive a plain deployment when an agency one was intended.
        """
        from flask import request as _rq
        data = _rq.get_json(silent=True) or {}
        inst, err = add_instance(
            ctx,
            bool(data.get('agency_specific')),
            data.get('slug'),
            data.get('mode'),
            data.get('size_gb'),
            data.get('agency_name'),
        )
        if err:
            return jsonify({'success': False, 'error': err}), 400
        return jsonify({'success': True, 'instance': inst})

    def instance_forget_view(slug):
        """Forget a deployment that was recorded but never built.

        ⚠️ **Only when nothing was built.** The record is written before the
        deploy so the slug and port are claimed while it runs; if the deploy is
        then refused, that record is the only trace and it would block a retry
        with the same name. This removes it — and refuses if the deployment has
        a directory on disk, because then it is not a stray record, it is an
        installed deployment and forgetting it would orphan a store.
        """
        found = atlas_instances.by_slug(load_instances(ctx), slug)
        if found is None:
            return jsonify({'success': True})
        if os.path.isdir(instance_paths(ctx, found)['dir']):
            return jsonify({
                'success': False,
                'error': ('That deployment exists on disk. Uninstall it rather '
                          'than forgetting it, or its store would be orphaned.'),
            }), 409
        drop_instance(ctx, slug)
        return jsonify({'success': True})

    def store_view():
        """What the box can offer, and what the reservation is doing (W205).

        ⚠️ A live route rather than a value baked into the page. Free space
        changes as other modules grow, and a ceiling rendered once at page load
        would tell an operator they can reserve space that has since gone — they
        would then be refused by a validator quoting a different number than the
        page beside it.
        """
        try:
            return jsonify(store_facts(ctx))
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    def version_view():
        """What is installed, what is available, and whether that is a newer one.

        ⚠️ `update_available` is only ever True when *both* versions parsed and
        the upstream one is genuinely higher. An unknown latest (offline, or
        GitHub's 60/hour spent) leaves it False and `latest` null, so the page
        can say "could not check" instead of claiming the box is current.
        """
        info = get_version_info(ctx)
        # The page distinguishes "no version" from an empty string; the cards
        # want a string. One source of truth, one conversion.
        return jsonify({
            'version': info['version'] or None,
            'latest': info['latest'],
            'update_available': info['update_available'],
        })

    def update_view():
        import threading
        inst, err = _requested_instance(default_first=True)
        if err:
            return jsonify({'success': False, 'error': err}), 404
        slot = _update_slot(inst)
        if slot['running']:
            return jsonify({'success': False,
                            'error': 'An update is already running for '
                                     + atlas_instances.derive(inst)['name']})
        # ⚠️ Refused while an update-all is in flight. The two would fight over
        # the same checkout and the same containers, and the sequential run's
        # result list would record whichever finished last.
        if _update_all_status['running']:
            return jsonify({'success': False,
                            'error': 'An update of every deployment is already '
                                     'running'})
        threading.Thread(target=_run_update, args=(ctx, inst),
                         daemon=True).start()
        return jsonify({'success': True})

    def update_status_view():
        inst, err = _requested_instance(default_first=True)
        if err:
            return jsonify({'error': err}), 404
        slot = _update_slot(inst)
        return jsonify({
            'running': slot['running'],
            'complete': slot['complete'],
            'error': slot['error'],
            'entries': list(slot['log']),
        })

    def update_all_view():
        import threading
        if _update_all_status['running']:
            return jsonify({'success': False,
                            'error': 'An update of every deployment is already '
                                     'running'})
        busy = [k for k, v in _update_slots.items() if v['running']]
        if busy:
            return jsonify({'success': False,
                            'error': 'An update is already running for '
                                     + ', '.join(sorted(busy))})
        threading.Thread(target=_run_update_all, args=(ctx,),
                         daemon=True).start()
        return jsonify({'success': True})

    def update_all_status_view():
        return jsonify({
            'running': _update_all_status['running'],
            'complete': _update_all_status['complete'],
            'error': _update_all_status['error'],
            'entries': list(_update_all_status['log']),
            'results': list(_update_all_status['results']),
        })

    def _addressed(slug):
        """The deployment a `<slug>` path segment names, or None.

        ⚠️ The plain deployment is addressed as `atlas`, which is in
        RESERVED_SLUGS — so no agency can ever claim that URL, and there is no
        empty path segment to special-case.
        """
        found = load_instances(ctx)
        return (atlas_instances.plain(found) if slug == 'atlas'
                else atlas_instances.by_slug(found, slug))

    def instance_remove_view(slug):
        """Destroy one deployment.

        ⚠️ **The confirmation is the page's job and this route's too.** The body
        must repeat the deployment's own name back; a bare POST to a URL is one
        mis-click or one stale tab away from destroying an agency's fleet, and
        the device CA cannot be recovered — every tablet enrolled against it
        needs a factory reset in person.
        """
        import threading
        from flask import request as _rq

        # ⚠️ **The password, as well as the typed slug (W240).** This
        # destroys one agency's device CA and its database, which is the same
        # class of act as the whole-module uninstall and the three CA routes
        # -- and all four of those ask. `login_required` proves a session;
        # it does not prove the person at the keyboard meant to destroy a
        # fleet's identity. Every tablet enrolled against that CA needs a
        # factory reset in person.
        _data = _rq.get_json(silent=True) or {}
        _pw_err = _check_admin_password(ctx, _data)
        if _pw_err:
            return jsonify({'success': False, 'error': _pw_err}), 403

        inst = _addressed(slug)
        if inst is None:
            return jsonify({'success': False,
                            'error': 'no deployment with that slug'}), 404
        confirm = _data.get('confirm')
        expected = inst.get('slug') or 'general'
        if (confirm or '').strip() != expected:
            return jsonify({
                'success': False,
                'error': 'Type %r to confirm removing this deployment.'
                         % expected,
            }), 400
        refusal = removal_refusal(inst, job_state(KEY).get('running'))
        if refusal:
            return jsonify({'success': False, 'error': refusal}), 409
        threading.Thread(target=_run_removal, args=(ctx, inst),
                         daemon=True).start()
        return jsonify({'success': True})

    def instance_remove_status_view(slug):
        """The removal log, keyed by the slug rather than by the record.

        ⚠️ **`remove_instance` drops the record as its last step**, so a status
        read that resolved the deployment first would lose the whole log on the
        very poll that reports success — and the operator would be left with
        "that deployment is gone" where the list of what was destroyed had been.

        ⚠️ Looked up, never created. `setdefault` here would let any slug
        typed into the URL add an entry to a module-level dict, and would answer
        "not running, not complete" forever — leaving the page polling.
        """
        key = atlas_instances.derive(
            {'slug': None if slug == 'atlas' else slug})['job_key']
        slot = _removal_slots.get(key)
        if slot is None:
            gone = _addressed(slug) is None
            return jsonify({
                'running': False, 'complete': gone, 'error': False,
                'entries': ['That deployment is gone.'] if gone else [],
            })
        return jsonify({
            'running': slot['running'],
            'complete': slot['complete'],
            'error': slot['error'],
            'entries': list(slot['log']),
        })

    def instance_name_view(slug):
        """Name a deployment that already exists, or clear its name."""
        from flask import request as _rq

        inst = _addressed(slug)
        if inst is None:
            return jsonify({'success': False,
                            'error': 'no deployment with that slug'}), 404
        data = _rq.get_json(silent=True) or {}
        steps, err = set_agency_name(ctx, inst, data.get('agency_name'))
        if err:
            return jsonify({'success': False, 'error': err,
                            'steps': steps}), 400
        return jsonify({'success': True, 'steps': steps})

    def instance_control_view(slug):
        """Start, stop or restart one deployment.

        ⚠️ The registry's `control_map` takes only `ctx`, so it can only ever
        act on the plain deployment. This is the same actions, addressed.
        """
        from flask import request as _rq
        action = (_rq.get_json(silent=True) or {}).get('action')
        argv = {'start': 'up -d api', 'stop': 'stop',
                'restart': 'restart'}.get(action)
        if not argv:
            return jsonify({'success': False, 'error': 'unknown action'}), 400
        inst = _addressed(slug)
        if inst is None:
            return jsonify({'success': False,
                            'error': 'no deployment with that slug'}), 404
        r = _compose(ctx, argv, timeout=300, inst=inst)
        if r.returncode != 0:
            return jsonify({'success': False,
                            'error': (r.stderr or '')[-300:]}), 500
        return jsonify({'success': True})

    def _channel_payload():
        """What the channel card renders. Both channels, and the risk.

        ⚠️ **Both channels are resolved, not just the selected one.** An
        operator deciding whether to switch needs to see what the other one
        offers *before* switching; a card that showed only the current channel
        would make them flip the switch to find out, which on a box mid-rollout
        is a question they cannot un-ask.
        """
        settings = ctx['load_settings']()
        current = _channel_of(ctx, settings)
        offers = {c: _latest_version(use_cache=True, channel=c) for c in CHANNELS}

        # Deployments already newer than what a channel offers. Switching to it
        # will not move them: `_run_update` refuses to go backwards, because
        # older code against a migrated database is data loss.
        deployed = []
        for inst in load_instances(ctx):
            version = _installed_version(ctx, inst)
            if version:
                deployed.append(
                    {'name': deployment_identity(ctx, inst, settings)['name'],
                     'version': version})

        def _ahead_of(channel):
            there = _parse_version(offers.get(channel))
            if not there:
                return []
            return [d for d in deployed
                    if (_parse_version(d['version']) or (0, 0, 0)) > there]

        return {
            'success': True,
            'channel': current,
            # ⚠️ Fresh installs land here whichever channel is selected — the
            # pin is a verified commit and the channel is a branch that moves.
            # Said on the card, so a dev-channel operator is not surprised when
            # a new agency deploys at the stable release and is immediately
            # offered an update.
            'install_tag': ATLAS_TAG,
            'channels': [
                {'key': c,
                 'label': c.capitalize(),
                 'blurb': CHANNEL_BLURB.get(c, ''),
                 'version': offers.get(c),
                 'ahead': [d['name'] for d in _ahead_of(c)]}
                for c in CHANNELS
            ],
            'deployed': deployed,
        }

    def channel_view():
        """Which release channel this box follows, and what each one offers."""
        return jsonify(_channel_payload())

    def channel_set_view():
        """Follow a different release channel.

        ⚠️ **Changes nothing on disk and starts nothing.** It decides which
        version the *next* update targets. An operator still presses Update,
        and still watches the log — a switch that silently began rebuilding
        every deployment on the box would be a very surprising toggle.
        """
        from flask import request as _rq

        wanted = ((_rq.get_json(silent=True) or {}).get('channel') or '').strip().lower()
        if wanted not in CHANNELS:
            return jsonify({
                'success': False,
                'error': 'unknown channel; expected one of ' + ', '.join(CHANNELS),
            }), 400

        settings = ctx['load_settings']()
        settings[CHANNEL_KEY] = wanted
        ctx['save_settings'](settings)
        # ⚠️ Dropped, not left to expire. The cache is per channel so the new
        # one is correct already, but a 15-minute-stale entry for the channel
        # just switched *to* would show a number from before the switch and
        # read as the switch not having worked.
        _latest_cache.pop(wanted, None)
        return jsonify(_channel_payload())

    register_module({
        'key': KEY,
        'name': 'ATLAS MDM',
        'description': 'Android device management for ATAK tablets — policies, apps, enrolment',
        'icon': '\U0001F4F1',  # 📱 as an escape: a literal surrogate pair corrupts on edit
        # ATLAS's own banner, the one its web UI wears. The console and
        # marketplace tiles hide the module name when a logo is present, so
        # this is the wordmark artwork rather than the bare mark.
        'icon_url': '/static/logos/atlas-banner.png',
        'route': '/atlas',
        'template': 'atlas.html',
        'priority': 16,
        'detect': detect,
        'deploy': deploy,
        'deploy_validate': deploy_validate,
        'uninstall': uninstall,
        'control_map': {
            'start':   lambda c: _compose_argv(c, 'up', '-d', 'api'),
            'stop':    lambda c: _compose_argv(c, 'stop'),
            'restart': lambda c: _compose_argv(c, 'restart'),
        },
        'extra_routes': [
            {'url': f'/api/{KEY}/logs', 'methods': ['GET'],
             'endpoint': f'{KEY}_logs', 'view': logs_view},
            {'url': f'/api/{KEY}/version', 'methods': ['GET'],
             'endpoint': f'{KEY}_version', 'view': version_view},
            {'url': f'/api/{KEY}/instances', 'methods': ['GET'],
             'endpoint': f'{KEY}_instances', 'view': instances_view},
            {'url': f'/api/{KEY}/instances', 'methods': ['POST'],
             'endpoint': f'{KEY}_instance_create', 'view': instance_create_view},
            {'url': f'/api/{KEY}/instances/<slug>/forget', 'methods': ['POST'],
             'endpoint': f'{KEY}_instance_forget', 'view': instance_forget_view},
            {'url': f'/api/{KEY}/store', 'methods': ['GET'],
             'endpoint': f'{KEY}_store', 'view': store_view},
            {'url': f'/api/{KEY}/channel', 'methods': ['GET'],
             'endpoint': f'{KEY}_channel', 'view': channel_view},
            {'url': f'/api/{KEY}/channel', 'methods': ['POST'],
             'endpoint': f'{KEY}_channel_set', 'view': channel_set_view},
            {'url': f'/api/{KEY}/update', 'methods': ['POST'],
             'endpoint': f'{KEY}_update', 'view': update_view},
            {'url': f'/api/{KEY}/update-all', 'methods': ['POST'],
             'endpoint': f'{KEY}_update_all', 'view': update_all_view},
            {'url': f'/api/{KEY}/update-all-status', 'methods': ['GET'],
             'endpoint': f'{KEY}_update_all_status', 'view': update_all_status_view},
            {'url': f'/api/{KEY}/instances/<slug>/control', 'methods': ['POST'],
             'endpoint': f'{KEY}_instance_control', 'view': instance_control_view},
            {'url': f'/api/{KEY}/instances/<slug>/name', 'methods': ['POST'],
             'endpoint': f'{KEY}_instance_name', 'view': instance_name_view},
            {'url': f'/api/{KEY}/instances/<slug>/remove', 'methods': ['POST'],
             'endpoint': f'{KEY}_instance_remove', 'view': instance_remove_view},
            {'url': f'/api/{KEY}/instances/<slug>/remove-status', 'methods': ['GET'],
             'endpoint': f'{KEY}_instance_remove_status',
             'view': instance_remove_status_view},
            {'url': f'/api/{KEY}/drift', 'methods': ['GET'],
             'endpoint': f'{KEY}_drift', 'view': lambda: jsonify(version_drift(ctx))},
            {'url': f'/api/{KEY}/update-status', 'methods': ['GET'],
             'endpoint': f'{KEY}_update_status', 'view': update_status_view},
            {'url': f'/api/{KEY}/ca', 'methods': ['GET'],
             'endpoint': f'{KEY}_ca', 'view': ca_view},
            {'url': f'/api/{KEY}/ca/renew', 'methods': ['POST'],
             'endpoint': f'{KEY}_ca_renew', 'view': ca_renew_view},
            # ⚠️ POST, both of them. See ca_recovery_view for why the download
            # is not a GET.
            {'url': f'/api/{KEY}/ca/recovery', 'methods': ['POST'],
             'endpoint': f'{KEY}_ca_recovery', 'view': ca_recovery_view},
            {'url': f'/api/{KEY}/ca/recovery/confirm', 'methods': ['POST'],
             'endpoint': f'{KEY}_ca_recovery_confirm', 'view': ca_recovery_confirm_view},
        ],
        # One public port. The console is Caddy-only on 443, the agent package is
        # a Caddy path route on the well-known port, and the database never
        # leaves the container bridge.
        'ports': [f'{DEVICE_PORT}/tcp'],
        'service_units': [],
        'settings_keys': [
            ACCESS_KEY, ACCESS_CHECKED_KEY,
            f'{KEY}_enabled', f'{KEY}_pg_password', f'{KEY}_commit_sha',
            f'{KEY}_version', f'{KEY}_domain',
        ],
    })
