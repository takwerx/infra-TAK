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
# infra-TAK — the ATLAS instance model (W216)
"""Several ATLAS deployments on one box, one per agency.

⚠️ **Pure by design, and that is the point.** Every name a deployment needs —
directory, image, mount points, unit names, compose project, volume, vhost,
device hostname, Caddy CA directory, Authentik slug, settings prefix, internal
port — is derived in one place, :func:`derive`. W212 was a teardown that missed
*one* path on a single instance; N instances multiply that risk by N, and the
only defence that scales is having one function to be wrong in.

Nothing here touches a disk, a container or the network, so it is all decidable
without a box and testable on the development machine.

⚠️ **The slug is four identifiers at once.** It becomes a DNS label, part of a
systemd unit name, a Docker Compose project name and a Docker volume name, so it
has to satisfy the intersection of all four rather than merely look tidy.
"""
import re

#: The console settings key holding the instance list.
INSTANCES_KEY = 'atlas_instances'

MODE_FIXED = 'fixed'
MODE_DYNAMIC = 'dynamic'
MODES = (MODE_FIXED, MODE_DYNAMIC)

#: 32 keeps `atlas.<slug>.<fqdn>` inside the 63-character DNS label limit with
#: room to spare, and keeps systemd unit names readable.
SLUG_MAX = 32

#: ⚠️ **Lowercase letters only** — no digits, no hyphens, no dots (operator
#: decision, 2026-09-17: *"only accept lowercase letters, no spaces or
#: symbols"*).
#:
#: Narrower than a DNS label allows, deliberately. The slug is four identifiers
#: at once — a hostname label, part of a systemd unit name, a Compose project
#: and a Docker volume — and the intersection of what each accepts is wider than
#: what is *safe* in all of them. `a-b` is a legal hostname and a legal volume
#: name, but it also collides with the separator this module uses to build
#: `atlas-<slug>`, so `atlas-a-b` cannot be parsed back apart. Letters cannot.
_SLUG_RE = re.compile(r'^[a-z]{1,%d}$' % SLUG_MAX)

#: ⚠️ Not decoration. The settings prefix for a slug is `atlas_<slug>_`, so a
#: slug of `pg` would produce `atlas_pg_password` — **the plain instance's own
#: database password key**. Any slug whose prefix can collide with an existing
#: `atlas_*` key is refused; the rest are reserved because they make confusing
#: hostnames.
RESERVED_SLUGS = frozenset({
    # Would collide with the plain instance's settings keys.
    'pg', 'commit', 'access', 'enabled', 'instances',
    # Confusing as `atlas.<slug>.<fqdn>`.
    'atlas', 'admin', 'api', 'www', 'device', 'devices',
    # ⚠️ The plain deployment's own folder inside `<base>/atlas/`
    # (W233). Deployments nest now, so a slug of 'default' would put an
    # agency directly on top of it -- same directory, same store, same
    # pki -- while every *name* stayed distinct and nothing complained.
    'default',
})

#: Internal loopback port for the api container. The plain instance already uses
#: 8760 on the live box, so the range starts there and the plain instance keeps
#: it.
BASE_PORT = 8760

#: Ports other things on the box are known to hold. Callers should pass any
#: they observe as well — this is a floor, not an inventory.
KNOWN_TAKEN_PORTS = frozenset({5000, 5080, 5090, 8080, 8443, 8449, 9443, 3100, 8888})


# --------------------------------------------------------------------------- #
# The record
# --------------------------------------------------------------------------- #


#: The longest agency name that still reads as one in a footer.
#:
#: ⚠️ Not a database limit — the footer is. A 400-character "name" would wrap
#: across the bottom of every page and push the version off screen, which is the
#: one thing the footer had to keep saying.
AGENCY_NAME_MAX = 60


def validate_agency_name(raw):
    """`(name, error)`. The name shown in the deployment's own footer.

    ⚠️ **Free text on purpose.** This is *"Corona Fire Department"*, not a slug:
    spaces, capitals, ampersands and apostrophes are all ordinary in the name of
    an agency, and forcing it through the slug rules would produce something
    nobody calls themselves.

    ⚠️ **Control characters are refused rather than stripped.** A name that
    silently loses a character is a name the operator will not recognise, and
    anything that arrives here containing a newline came from something other
    than the field — which is worth refusing loudly.
    """
    name = (raw or '').strip()
    if not name:
        return '', None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        return None, 'An agency name cannot contain line breaks or control characters.'
    if len(name) > AGENCY_NAME_MAX:
        return None, ('An agency name can be at most %d characters — this one '
                      'is %d.' % (AGENCY_NAME_MAX, len(name)))
    return name, None


def make(slug, mode, size_gb, port, agency_name=''):
    """One instance record. `slug` is None for the non-agency deployment.

    ⚠️ `agency_name` defaults to empty and is *not* derived from the slug. The
    whole reason the field exists is that `corona` is not
    "Corona Fire Department".
    """
    return {'slug': slug, 'mode': mode, 'size_gb': size_gb, 'port': port,
            'agency_name': agency_name or ''}


def plain(instances):
    """The slug-less instance, or None."""
    for inst in instances or ():
        if not inst.get('slug'):
            return inst
    return None


def by_slug(instances, slug):
    for inst in instances or ():
        if (inst.get('slug') or None) == (slug or None):
            return inst
    return None


def size_label(mode):
    """What the size field *means*, which differs by mode.

    ⚠️ One field, two meanings, so the label is not cosmetic: under `fixed` the
    number is space taken from the box up front and held; under `dynamic` it is
    only a ceiling, and the space is not held at all.
    """
    return 'reserved' if mode == MODE_FIXED else 'maximum'


# --------------------------------------------------------------------------- #
# The rule the operator stated
# --------------------------------------------------------------------------- #


def may_deploy_plain(instances):
    """Whether a non-agency-specific ATLAS may be deployed.

    ⚠️ **Derived from current state, never latched.** The operator's rule is
    *"this behavior exists for as long as a non-agency atlas (no slug) is
    deployed"* — so uninstalling the plain instance makes it deployable again,
    and the setup question comes back with it. A flag set once at first deploy
    would answer "no" for ever and quietly strand the box.

    The console asks *"is this agency-specific?"* exactly when this is true; when
    it is false the question has only one possible answer, so it is not asked.
    Both behaviours come from this one predicate rather than from two that could
    drift apart.
    """
    return plain(instances) is None


# --------------------------------------------------------------------------- #
# Slugs
# --------------------------------------------------------------------------- #


def validate_slug(raw, instances=()):
    """`(slug, error)`. `error` is a sentence for the operator, or None.

    ⚠️ **Case is forced, everything else is refused** (operator decision,
    2026-09-17). `Agency-A` becomes `agency-a` rather than being rejected: the
    slug is a DNS label, a systemd unit name, a Compose project and a volume
    name, none of which agree about case, and there is exactly one sensible
    interpretation of a capital letter. There is no such single interpretation
    of a space or an underscore, so those still refuse.

    **The normalised slug is what gets stored and used**, so the console must
    show the operator what it settled on — `atlas.agency-a.<fqdn>`, not the
    string they typed. Returning it here is what makes that possible.

    Uniqueness therefore becomes case-insensitive for free: `Agency-A` collides
    with an existing `agency-a`, which is the right answer, because they would
    resolve to the same hostname.
    """
    if raw is None or not str(raw).strip():
        return None, 'An agency slug is required for an agency-specific deployment.'

    slug = str(raw).strip().lower()
    if len(slug) > SLUG_MAX:
        return None, f'Keep the slug to {SLUG_MAX} characters or fewer.'
    if '.' in slug:
        return None, ('A slug is one label, not a domain — it sits inside '
                      'atlas.<slug>.<your-domain>, so it cannot contain a dot.')
    if not _SLUG_RE.match(slug):
        return None, 'Use lowercase letters only — no spaces, digits or symbols.'
    if slug in RESERVED_SLUGS:
        return None, f'{slug!r} is reserved — please pick another.'
    if by_slug(instances, slug) is not None:
        return None, f'There is already an ATLAS deployment for {slug!r}.'
    return slug, None


def validate_mode(mode):
    """`(mode, error)`."""
    if mode in MODES:
        return mode, None
    return None, (f'Choose a sizing mode: {MODE_FIXED} reserves the space up '
                  f'front, {MODE_DYNAMIC} shares it and grows as needed.')


# --------------------------------------------------------------------------- #
# Ports
# --------------------------------------------------------------------------- #


def next_port(instances=(), taken=()):
    """The next free loopback port for an api container.

    Deterministic, so the same box produces the same answer twice, and skipping
    anything already spoken for — `taken` is for ports observed on the box,
    because this module cannot see them.
    """
    used = {inst.get('port') for inst in instances or ()}
    used |= set(KNOWN_TAKEN_PORTS)
    used |= set(taken or ())
    port = BASE_PORT
    while port in used:
        port += 1
    return port


# --------------------------------------------------------------------------- #
# Every name in one place
# --------------------------------------------------------------------------- #


def derive(instance, fqdn=None):
    """Every name this instance uses. One function, so there is one place to be
    wrong.

    ⚠️ **The plain instance must derive exactly what is already deployed.**
    compose project `takmdm`, volume `takmdm_pgdata`, `/var/lib/caddy/atlas`
    and settings keyed `atlas_*`. A refactor that quietly moved any of those
    would strand a running deployment, so the slug-less branch reproduces them
    and a test pins it.

    ⚠️ **`store` is a plain directory, and there is no image (W230).** It
    was a loop-mounted ext4 file under `/var/lib/<name>/store.img`, which an
    unprivileged console can neither create nor mount — and which upstream
    rightly called *"exactly the kind of thing the broker exists to prevent"*:
    a filesystem image the console can write, mounted by root, is an
    escalation primitive. The key is named `store` rather than `mount` because
    it is no longer a mount point, and a key that lies about that is how the
    next reader loses an afternoon.

    ⚠️ **No directories (W233).** This used to return `dir`, `store`,
    `artifacts` and `cache` built from a hardcoded `/root/<name>`, and
    `instance_paths` overwrote all four on its first line -- so the layout was
    written down twice and only one copy was ever read. When deployments
    nested, the dead copy went stale silently and the only thing that noticed
    was a test asserting on it. Naming is this function's job; *where things
    sit* is `atlas.instance_paths`, which is the one that can see whether the
    box keeps deployments under `/root` or a home directory.
    """
    slug = (instance or {}).get('slug') or None
    name = 'atlas' if slug is None else f'atlas-{slug}'
    host = 'atlas' if slug is None else f'atlas.{slug}'

    return {
        'slug': slug,
        'name': name,
        # The job slot and lock. ⚠️ `[a-z0-9_-]` only — the descriptor validator
        # rejects anything else, and a colon here would fail at import.
        'job_key': name,
        # ⚠️ Compose takes the project name from `-p`, which outranks the
        # `name:` in the released compose file, so ATLAS itself needs no change.
        'compose_project': 'takmdm' if slug is None else f'takmdm-{slug}',
        # ⚠️ Compose names a built image `<project>-<service>`, so these follow
        # the project. `takmdm-api` and `takmdm-init` were hardcoded in
        # `uninstall`, which meant an agency's two images survived every
        # teardown and accumulated a release's worth of layers each time.
        'images': (['takmdm-api', 'takmdm-init'] if slug is None else
                   [f'takmdm-{slug}-api', f'takmdm-{slug}-init']),
        'pg_volume': 'takmdm_pgdata' if slug is None else f'takmdm-{slug}_pgdata',
        'port': (instance or {}).get('port') or BASE_PORT,
        'caddy_ca_dir': f'/var/lib/caddy/{name}',
        'authentik_slug': name,
        'admin_group': f'{name}-admins',
        # ⚠️ `atlas_` for the plain instance, because those keys already exist on
        # every deployed box. See RESERVED_SLUGS for why a slug cannot collide.
        'settings_prefix': 'atlas_' if slug is None else f'atlas_{slug}_',
        'vhost': f'{host}.{fqdn}' if fqdn else None,
        'device_host': f'{host}.{fqdn}' if fqdn else None,
        'mode': (instance or {}).get('mode') or MODE_FIXED,
        'size_gb': (instance or {}).get('size_gb'),
    }


def agency_host(plain_host, slug):
    """`atlas.example.com` + `agency-a` -> `atlas.agency-a.example.com`.

    ⚠️ The slug is inserted after the *first* label rather than prepended to the
    whole name, so a box whose console is at `mdm.example.com` gets
    `mdm.agency-a.example.com` and not `agency-a.mdm.example.com`. The first
    label is the service; the agency qualifies it.

    ⚠️ A third-level label needs its own DNS record and its own certificate.
    There is no wildcard in this deployment — 13 named per-host certificates —
    and `tiles.map.<fqdn>` already proves the shape works here.
    """
    if not plain_host or not slug:
        return plain_host
    head, dot, rest = plain_host.partition('.')
    if not dot:
        return f'{head}.{slug}'
    return f'{head}.{slug}.{rest}'


#: Settings that describe the *box*, not any one deployment.
#:
#: ⚠️ **`atlas_domain` is the operator's service-domain override**, and it is the
#: input `agency_host` builds every agency hostname from. Removing it with the
#: plain deployment would move every remaining agency to a different name — new
#: certificates, and every enrolled tablet pointing at a host that no longer
#: answers. It is cleared by the whole-module uninstall, which is a different
#: question, asked once everything is gone.
#:
#: ⚠️ `atlas_enabled` means "the module is installed here" and `atlas_instances`
#: is the registry itself. Taking either with one deployment would make the
#: remaining ones invisible.
#:
#: ⚠️ `atlas_channel` is the box's release channel (W228). Removing one
#: deployment must not take it: the remaining ones would silently fall back
#: to `main` and stop being offered the release they are actually running,
#: which reads as "no update available" on a box that is mid-rollout.
BOX_SETTINGS_KEYS = frozenset({
    'atlas_enabled', 'atlas_domain', 'atlas_channel', INSTANCES_KEY})


def owned_settings_keys(instance, keys, instances=()):
    """The settings keys belonging to `instance` alone.

    ⚠️ **`atlas_` is a prefix of `atlas_corona_`.** The existing teardown swept
    `startswith('atlas_')`, which for the *plain* deployment would have taken
    every agency's keys with it — database passwords included, and Postgres only
    honours `POSTGRES_PASSWORD` on an empty volume, so each of those databases
    would have become permanently unopenable by a deployment still running.

    The rule is "mine, unless a longer prefix claims it": the plain deployment's
    `atlas_` yields to `atlas_corona_`, and `atlas_corona_` does not yield to
    the shorter `atlas_`. ⚠️ Slugs are lowercase letters only, so no two agency
    prefixes can overlap — `atlas_pd_` and `atlas_pdx_` are distinct because of
    the trailing underscore. `validate_slug` is what keeps that true.
    """
    mine = derive(instance)['settings_prefix']
    slug = (instance or {}).get('slug') or None
    longer = [p for p in
              (derive(i)['settings_prefix'] for i in instances or ()
               if ((i or {}).get('slug') or None) != slug)
              if len(p) > len(mine)]
    owned = []
    for key in keys or ():
        if key in BOX_SETTINGS_KEYS:
            continue
        if not key.startswith(mine):
            continue
        if any(key.startswith(other) for other in longer):
            continue
        owned.append(key)
    return sorted(owned)


def authentik_names(instance):
    """The Authentik objects this deployment owns, and nobody else's.

    ⚠️ **Sharing these is a tenancy break, not a cosmetic one.** The provider
    name, the application slug and the policy binding were all constants —
    `ATLAS MDM Proxy`, `atlas`, `ATLAS MDM`. Deploying an agency would therefore
    have *repointed the existing deployment's application* at the agency's
    hostname, signing every plain-deployment administrator into the agency
    console and nobody into their own.

    ⚠️ **The plain deployment keeps the exact strings already in Authentik on
    every deployed box.** A rename here would orphan the live application: the
    deploy would create a second one, the outpost would hold both, and the
    policy binding would follow the new one while Caddy's forward_auth still
    pointed at the old.
    """
    slug = (instance or {}).get('slug') or None
    if slug is None:
        return {
            'provider': 'ATLAS MDM Proxy',
            'app_slug': 'atlas',
            'app_name': 'ATLAS MDM',
        }
    return {
        'provider': f'ATLAS MDM Proxy ({slug})',
        # ⚠️ `derive` owns this name, because the Caddy CA directory and the
        # install directory use the same one. Two places to be wrong is one too
        # many.
        'app_slug': derive(instance)['authentik_slug'],
        'app_name': f'ATLAS MDM ({slug})',
    }


# --------------------------------------------------------------------------- #
# Capacity: what this box can still take
# --------------------------------------------------------------------------- #

GIB = 1024 ** 3

#: Measured on the development box (2026-09-17): an idle instance with no devices
#: enrolled held 846 MiB and **peaked at 1.27 GiB** while the repository indexes
#: were parsed.
#:
#: ⚠️ Planning uses the peak, not the steady state. N instances restarting
#: together spike together, and the steady figure would promise room that a
#: simultaneous restart would not find. Devices add on top of both, so this is a
#: floor.
INSTANCE_RAM_PEAK_BYTES = int(1.27 * GIB)

#: The protected floor: disk that never belongs to ATLAS, for the other InfraTAK
#: modules to grow into. Operator decision, 2026-09-17.
#:
#: ⚠️ This sizes **module data growth**, which measured ~3.5 GB in total on the
#: box. It cannot bound image and build-cache accumulation — 42 GB in
#: `/var/lib/containerd`, which grows with every release build — because a
#: reservation cannot bound something unbounded. That needs a prune policy, not
#: a bigger floor.
DEFAULT_FLOOR_GB = 25


def budget_bytes(disk_total, non_atlas_used, floor_bytes):
    """The most ATLAS may ever hold on this box, all instances together."""
    return max(0, disk_total - non_atlas_used - floor_bytes)


def committed_bytes(instances):
    """Space the existing deployments have actually taken — fixed ones only.

    ⚠️ **This counted both modes until the operator settled the design**
    (2026-09-17). Their rule is that dynamic deployments *share* the available
    space and are not asked for a size at all, so a dynamic ceiling is not a
    commitment against the budget — it is a ceiling on a pool everything
    dynamic draws from.

    Counting them would have exhausted the budget the moment one dynamic
    deployment existed, because its ceiling is the whole remaining pool.

    ⚠️ The consequence is deliberate over-commitment: several dynamic
    deployments can each be capped at the whole pool, so their ceilings sum to
    more than the disk holds. That is what "share the same available space"
    means, and the cost is a correlated failure if they all fill at once —
    which is why `deliverable_free` exists and why a dynamic store mounts
    `errors=remount-ro`.
    """
    return sum(int((i.get('size_gb') or 0) * GIB)
               for i in instances or () if i.get('mode') == MODE_FIXED)


def pool_bytes(budget, instances):
    """What the dynamic deployments share, and what a new fixed one may take.

    The budget less the space fixed deployments have already claimed. Never
    negative: a box over its budget has no pool, not a negative one.
    """
    return max(0, budget - committed_bytes(instances))


def fits(requested_gb, instances, budget):
    """`(ok, error)` — whether another instance of this size may be created."""
    requested = int((requested_gb or 0) * GIB)
    if requested <= 0:
        return False, 'Choose a size for this deployment.'
    used = committed_bytes(instances)
    if used + requested > budget:
        spare = max(0, budget - used)
        return False, (
            f'That would take ATLAS past its budget. '
            f'{spare / GIB:.0f} GB of {budget / GIB:.0f} GB is still uncommitted.'
        )
    return True, None


def instances_that_fit(size_gb, instances, budget):
    """How many more of this size the budget allows. For the deploy screen."""
    each = int((size_gb or 0) * GIB)
    if each <= 0:
        return 0
    return max(0, (budget - committed_bytes(instances)) // each)


def instances_that_ram_allows(ram_available, reserve_bytes, per_instance=None):
    """How many more instances memory allows, at the measured peak."""
    each = per_instance or INSTANCE_RAM_PEAK_BYTES
    return max(0, (max(0, ram_available - reserve_bytes)) // each)


def binding_constraint(by_disk, by_ram):
    """Which limit bites first, and how many more instances that allows.

    ⚠️ Returned as a pair so the page can *name* it. On the box measured, disk
    allowed four or five more and memory about twelve — and an operator reading
    only the larger number would plan for twice what fits. Naming the binding
    constraint is the difference between a dashboard and a number.
    """
    if by_disk <= by_ram:
        return 'disk', by_disk
    return 'memory', by_ram
