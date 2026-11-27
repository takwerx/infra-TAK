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
"""ATLAS standard admins: the Authentik group and the read-only roster account.

An agency ATLAS today has one kind of administrator: everyone in
`atlas-<slug>-admins` can do everything. ATLAS is adding a second role, the
**standard admin**, whom the agency's super admin limits to some devices and
some actions. Authentik says *who* is a standard admin; ATLAS keeps *what* each
one may reach.

This module is the InfraTAK half. For each deployment it makes:

* **The group `atlas-<slug>-standard-admins`** (`atlas-standard-admins` for the
  plain deployment). Empty, not a superuser group.
* **Its way into the deployment's Authentik application, only once the ATLAS
  on disk and the ATLAS running are both 2.3.0 or newer** (`MIN_ATLAS`,
  `admit`). The group is one more name in the application's access policy
  (`atlas_access`), never a binding of its own: the Hardened posture runs the
  application in `policy_engine_mode: all`, where a binding is a requirement.
  ⚠️ An older ATLAS does not know the role. It refuses anyone outside
  `TAKMDM_ADMIN_GROUP` with a 403, but a deployment whose `TAKMDM_ADMIN_GROUP`
  is blank (the plain deployment, on purpose; W240 left it blank on every
  non-root install for a while) admits everyone Authentik admits as a full
  administrator. 2.3.0 resolves the standard group *before* that blank-group
  rule, so its members stay standard admins there. Checked on every update,
  after the rebuild and the `api` restart, so the same press that installs
  2.3.0 also admits the group, and a press that leaves an older ATLAS running
  takes it out again.
* **A read-only roster account `atlas-roster-<slug>`** (`atlas-roster` for the
  plain deployment). A service account with one role of the same name, which
  may only *view* this deployment's groups (`authentik_core.view_group` as an
  object permission on each): the agency's admin group and its standard group,
  or for the plain deployment the standard group alone. ⚠️ Never
  `authentik Admins`: the plain deployment's super admins are the box's
  Authentik administrators, and the roster has no business listing them. ATLAS
  uses the token to list who is in the groups, so the super admin can see and
  set up each person before their first sign-in. The roster never grants
  access: ATLAS still decides every request from the groups Authentik sends
  with it.

⚠️ **Measured on a live box (Authentik 2026.5.6) before this was written**, with
a temporary account set up exactly like this one: the token lists only the two
groups, with their members; another group by pk answers 404; the user list
answers 403. What a leaked token exposes is therefore the two groups' members:
username, name, email, last login and their Authentik `attributes`.

⚠️ **The token is stable, not rotated on every update** (unlike
`atlas_renewal`). ATLAS reads it from `.env` at start; rotating it and deleting
the old one would break the roster until the next restart. It is low power, so
it is kept, and re-created only when it is missing.

Nothing here is fatal. A deployment without the roster works exactly as before.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from . import atlas_access
from . import atlas_instances

#: Authentik's own home for service accounts, so the account lists with the
#: outposts rather than among people (the same path `atlas_renewal` uses).
SERVICE_ACCOUNT_PATH = 'goauthentik.io/service-accounts'

#: Read by ATLAS. Today's ATLAS ignores all three (its settings ignore unknown
#: keys), so they can be written before ATLAS uses them.
ENV_GROUP = 'TAKMDM_STANDARD_ADMIN_GROUP'
ENV_TOKEN = 'TAKMDM_AUTHENTIK_ROSTER_TOKEN'
ENV_URL = 'TAKMDM_AUTHENTIK_URL'

VIEW_GROUP = 'authentik_core.view_group'
GROUP_MODEL = 'authentik_core.group'

#: The first ATLAS that knows the standard role (W495). Older releases would
#: treat the group's members as full administrators on a box whose
#: `TAKMDM_ADMIN_GROUP` is blank, so the group is not admitted before it.
MIN_ATLAS = (2, 3, 0)



def names(inst):
    """Every name this deployment's roster uses.

    ⚠️ **The plain deployment has no `admin_group` (None).** Its super admins
    are the box's Authentik administrators, which the roster must not read.

    A slug is lowercase letters only (`atlas_instances._SLUG_RE`), so
    `atlas-<slug>-standard-admins` can never equal another agency's
    `atlas-<other>-admins`. The plain deployment's `atlas-standard-admins`
    would equal the admin group of an agency named 'standard', so that slug is
    reserved, and `_clashes` guards a box that already has one.
    """
    derived = atlas_instances.derive(inst)
    slug = derived['slug']
    account = 'atlas-roster-%s' % slug if slug else 'atlas-roster'
    return {
        'admin_group': derived['admin_group'] if slug else None,
        'standard_group': ('atlas-%s-standard-admins' % slug if slug
                           else 'atlas-standard-admins'),
        'username': account,
        'role': account,
        'token': account + '-api',
        'application': derived['authentik_slug'],
    }


#: The application an agency named 'standard' would have (see `names`).
_CLASHING_APPLICATION = atlas_instances.derive({'slug': 'standard'})['authentik_slug']


def _clashes(api, n):
    """True when the plain deployment's group is another deployment's admin group.

    ⚠️ Only possible on a box that deployed an agency named 'standard' before
    the slug was reserved. Setting up, or removing, `atlas-standard-admins`
    there would act on that agency's administrators.
    """
    if n['admin_group'] is not None:
        return False
    try:
        api.call('core/applications/%s/' % _CLASHING_APPLICATION)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise
    return True


def admits_role(installed):
    """Does this installed ATLAS version know the standard role?

    ⚠️ Unknown or unreadable means no: binding too early makes the group's
    members full administrators on a box with a blank admin group, while
    binding a press late only delays their first sign-in.
    """
    parts = str(installed or '').strip().lstrip('vV').split('.')
    if len(parts) != 3:
        return False
    try:
        return tuple(int(p) for p in parts) >= MIN_ATLAS
    except ValueError:
        return False


class AuthentikAdmin:
    """The few Authentik API calls this needs, as the administrator token."""

    def __init__(self, api_url, token, opener=None):
        self.base = api_url.rstrip('/') + '/api/v3/'
        self.headers = {'Authorization': 'Bearer %s' % token,
                        'Content-Type': 'application/json'}
        self.opener = opener or urllib.request.urlopen

    def call(self, path, data=None, method=None):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers=self.headers, method=method)
        body = self.opener(req, timeout=15).read().decode()
        return json.loads(body) if body else {}

    def results(self, path):
        return self.call(path).get('results', [])


def _find(api, path, field, value):
    """The row whose `field` is exactly `value`. Authentik's filters are not
    identities (`atlas-test-admins` must never match `atlas-testing-admins`)."""
    for row in api.results('%s?%s=%s' % (path, field, urllib.parse.quote(value))):
        if row.get(field) == value:
            return row
    return None


def _is_ours(user):
    """An account this module made: a service account, never a person's."""
    return user.get('type') == 'service_account'


def ensure_group(api, name):
    """The standard-admin group, made if missing. Returns (group, note).

    ⚠️ A superuser flag is taken off again: members of this group must never be
    Authentik superusers, and nobody should have to notice that by hand.
    """
    group = _find(api, 'core/groups/', 'name', name)
    if group is None:
        return api.call('core/groups/', {'name': name, 'is_superuser': False},
                        method='POST'), 'created'
    if group.get('is_superuser'):
        api.call('core/groups/%s/' % group['pk'], {'is_superuser': False}, method='PATCH')
        return group, 'superuser flag removed'
    return group, 'present'


def ensure_account(api, n):
    """The roster service account, made or re-activated. Returns its row."""
    user = _find(api, 'core/users/', 'username', n['username'])
    if user is not None and not _is_ours(user):
        # ⚠️ Somebody's own account with our name. Giving it the role would
        # hand whoever knows its password the roster (ops #510, same shape).
        raise RuntimeError("an Authentik user named %s exists and is not a service "
                           "account; rename it, then update ATLAS" % n['username'])
    if user is None:
        return api.call('core/users/', {
            'username': n['username'],
            'name': 'ATLAS admin roster (read-only)',
            'type': 'service_account',
            'path': SERVICE_ACCOUNT_PATH,
            'is_active': True,
        }, method='POST')
    if not user.get('is_active', True):
        api.call('core/users/%s/' % user['pk'], {'is_active': True}, method='PATCH')
    return user


def ensure_role(api, n, user, groups):
    """The role: view these groups only, given to the account directly.

    ⚠️ **Never call `assign` without an `object_pk` that exists.** Authentik's
    `PermissionAssignSerializer` looks the object up and, when it finds
    nothing, assigns the permission **globally**: the token would then see
    every group on the box, the superuser group included. Every pk here comes
    from a group row just read, and `_no_global_grant` checks afterwards.
    """
    role = _find(api, 'rbac/roles/', 'name', n['role'])
    if role is None:
        role = api.call('rbac/roles/', {'name': n['role']}, method='POST')
    for group in groups:
        if not group.get('pk'):
            raise RuntimeError('a group without a pk cannot be scoped')
        api.call('rbac/permissions/assigned_by_roles/%s/assign/' % role['pk'], {
            'permissions': [VIEW_GROUP],
            'model': GROUP_MODEL,
            'object_pk': str(group['pk']),
        }, method='POST')
    _no_global_grant(api, role)
    api.call('rbac/roles/%s/add_user/' % role['pk'], {'pk': user['pk']}, method='POST')
    return role


def admitted(installed, running):
    """Both the checkout and the running container know the standard role.

    ⚠️ **Both, not either** (Security read, ops #978). The file alone can be
    ahead of the process: an update whose rebuild failed leaves 2.3.0 on disk
    and 2.2.x serving, and Deploy run again can check out an older tag. An
    unknown version on either side means no.
    """
    return admits_role(installed) and admits_role(running)


def ensure_access(api, n, installed, running, plog, blocker=None,
                  admin_group=None, include_global=True):
    """Put the standard group in, or take it out of, the application's access policy.

    ⚠️ **One expression policy, not a binding of its own** (`atlas_access`).
    The Hardened posture runs every login application in `policy_engine_mode:
    all`, where a separate group binding is one more requirement: binding the
    standard group beside the others locked every administrator out (test6,
    ops #919). Inside the policy it is one more name in the "or".

    ⚠️ **Taken out again** when either version is below 2.3.0 or unknown: an
    older ATLAS on a blank-admin-group deployment would make its members full
    administrators. A direct binding left by older code goes too.

    Returns ``(mark, note)`` for the log line.
    """
    group = n['standard_group']
    if blocker is None and admitted(installed, running):
        result = atlas_access.ensure(api, n['application'], add=[group], plog=plog,
                                     admin_group=admin_group,
                                     include_global=include_global)
        if result['status'] == 'failed':
            return '⚠', 'not admitted to ATLAS: %s' % result['detail']
        return '✓', 'admitted to ATLAS (%s)' % (installed,)
    why = ('ATLAS %s predates the standard role (%s)'
           % (installed or '(version unknown)', '.'.join(map(str, MIN_ATLAS))))
    if admits_role(installed) and not admits_role(running):
        why = ('the running ATLAS reports %s, not %s yet'
               % (running or 'no version', installed))
    if blocker is not None:
        why = blocker
    if atlas_access.revoke(api, n['application'], group, plog=plog,
                            admin_group=admin_group, include_global=include_global):
        return '✓', 'taken out of ATLAS access: %s' % why
    return '·', 'not admitted to ATLAS: %s' % why


def _no_global_grant(api, role):
    """Refuse a role that can view groups model-wide, and take that grant away."""
    for row in api.results('rbac/permissions/assigned_by_roles/?model=%s'
                           % urllib.parse.quote(GROUP_MODEL)):
        if str(row.get('role_pk')) != str(role['pk']):
            continue
        wide = [p.get('codename') for p in row.get('model_permissions') or []]
        if wide:
            api.call('rbac/permissions/assigned_by_roles/%s/unassign/' % role['pk'],
                     {'permissions': ['authentik_core.%s' % c for c in wide]},
                     method='PATCH')
            raise RuntimeError('the roster role had a permission on every group (%s); '
                               'it was removed' % ', '.join(wide))


def ensure_token(api, n, user):
    """The account's one API token, made if missing. Returns its key."""
    ident = n['token']
    existing = [t for t in api.results('core/tokens/?user__username=%s&intent=api'
                                       % urllib.parse.quote(n['username']))
                # ⚠️ The owner is checked too: Authentik ignores `?user=` and
                # can list other accounts' tokens (atlas_renewal, test12).
                if t.get('identifier') == ident and t.get('user') == user['pk']]
    if not existing:
        api.call('core/tokens/', {
            'identifier': ident,
            'intent': 'api',
            'user': user['pk'],
            'expiring': False,
            'description': 'ATLAS admin roster: reads this agency\'s two admin groups',
        }, method='POST')
    return api.call('core/tokens/%s/view_key/' % urllib.parse.quote(ident))['key']


def ensure(ctx, inst, dirpath, write_env_value, plog, opener=None):
    """Set the standard group and the roster up for one deployment.

    Returns ``{'env_changed': bool}``; the caller restarts `api` when it is
    true, and only then calls `admit`. Called after the agency admin group is
    reconciled, on deploy and on every update. Never raises.

    ⚠️ **Admits nobody.** The group is let into ATLAS by `admit`, after the
    restart, so ATLAS already knows the group's name when its first member
    signs in (Security read, ops #978: until then a 2.3.0 ATLAS with a blank
    admin group would take a standard member for a super admin).
    """
    nothing = {'env_changed': False}
    n = names(inst)
    try:
        settings = ctx['load_settings']()
        admin = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not admin:
            plog('  ⚠ Standard admins not set up: Authentik is not configured.')
            return nothing
        public = authentik_public_url(ctx, settings)
        if not public:
            plog("  ⚠ Standard admins not set up: Authentik's public name is unknown.")
            return nothing
        api = AuthentikAdmin(ctx['_get_authentik_api_url'](settings), admin, opener)
        if _clashes(api, n):
            plog('  ⚠ Standard admins not set up: "%s" is the admin group of the '
                 'agency deployment "standard".' % n['standard_group'])
            return nothing

        scoped = []
        if n['admin_group'] is not None:
            admins = _find(api, 'core/groups/', 'name', n['admin_group'])
            if admins is None:
                # The agency group is reconciled just before this; if it is
                # still missing, that step already said why. Never scope a role
                # to a group that is not there (see `ensure_role`).
                plog('  ⚠ Standard admins not set up: the group "%s" is missing.'
                     % n['admin_group'])
                return nothing
            scoped.append(admins)
        standard, group_note = ensure_group(api, n['standard_group'])
        user = ensure_account(api, n)
        ensure_role(api, n, user, scoped + [standard])
        key = ensure_token(api, n, user)

        env = os.path.join(dirpath, '.env')
        changed = write_env_value(env, ENV_GROUP, n['standard_group'])
        changed = write_env_value(env, ENV_URL, public) or changed
        changed = write_env_value(env, ENV_TOKEN, key) or changed
        readable = 'it and "%s"' % n['admin_group'] if n['admin_group'] else 'it'
        plog('  ✓ Standard admin group "%s" %s; roster account %s can read %s'
             % (n['standard_group'], group_note, n['username'], readable))
        return {'env_changed': changed}
    except Exception as exc:
        # Never the token: the message comes from urllib or the filesystem.
        plog('  ⚠ Standard admins not set up: %s' % str(exc)[:120])
        return nothing


def _env_value(dirpath, key):
    """The value of `KEY=` in this deployment's `.env`, or None."""
    try:
        with open(os.path.join(dirpath, '.env'), encoding='utf-8') as handle:
            for line in handle.read().splitlines():
                if line.startswith(key + '='):
                    return line[len(key) + 1:].strip().strip('"')
    except OSError:
        return None
    return None


def admit(ctx, inst, dirpath, installed, running, plog, restarted=True, opener=None,
          container_group=None, admin_group=None):
    """Let the standard group into ATLAS, or keep it out. Never raises.

    Called after `ensure` and after the `api` restart it asked for.
    `installed` is the version on disk and `running` the one the container
    reports; both must be 2.3.0 or newer (`admitted`). `restarted` is False
    when the restart `ensure` asked for failed: the running ATLAS may not have
    the group's name, so the group stays out.

    ⚠️ Also kept out while `.env` does not name the group: a 2.3.0 ATLAS
    without `TAKMDM_STANDARD_ADMIN_GROUP` and with a blank admin group takes
    every member for a super admin.

    ⚠️ **And while the running container does not** (Security read, ops #978).
    `container_group` is `TAKMDM_STANDARD_ADMIN_GROUP` as the `api` container
    has it (`printenv`), or None when it could not be read. `restarted` only
    knows about this run: a restart that failed on an earlier update leaves the
    name in `.env` with nothing left to restart, and the next update would let
    the group in. The container's own value is the one ATLAS acts on, so it
    must equal the group's name; anything else, unreadable included, is out.
    """
    n = names(inst)
    try:
        settings = ctx['load_settings']()
        admin = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not admin:
            return
        api = AuthentikAdmin(ctx['_get_authentik_api_url'](settings), admin, opener)
        if _clashes(api, n):
            return
        blocker = None
        if not restarted:
            blocker = 'ATLAS could not be restarted with the group\'s name'
        elif _env_value(dirpath, ENV_GROUP) != n['standard_group']:
            blocker = 'the deployment\'s .env does not name the group yet'
        elif (admitted(installed, running) and
              (container_group or '').strip() != n['standard_group']):
            # Only asked of an ATLAS that could take the group at all, so an
            # older one still logs "predates the standard role".
            blocker = ('the running ATLAS does not have the group\'s name '
                       '(restart ATLAS, then run Update)')
        # ⚠️ Whether the global administrators are in the policy right now
        # (ops #1416): this call rewrites the same policy, and must not put
        # back a group the operator switched off.
        mark, note = ensure_access(
            api, n, installed, running, plog, blocker=blocker, admin_group=admin_group,
            include_global=atlas_access.global_admins_in_force(settings, inst))
        plog('  %s "%s" %s' % (mark, n['standard_group'], note))
    except Exception as exc:
        plog('  ⚠ "%s" access not checked: %s' % (n['standard_group'], str(exc)[:120]))


def authentik_public_url(ctx, settings):
    """`https://<Authentik's public host>[:port]`, as the console builds it.

    ⚠️ The public name, not `_get_authentik_api_url`: that answers the host's
    loopback, which inside ATLAS's container is the container itself. Same
    rule and same reason as `atlas_renewal.authentik_public_url`.
    """
    from . import atlas_renewal
    return atlas_renewal.authentik_public_url(ctx, settings)


def remove(ctx, inst, opener=None):
    """Delete this deployment's token, account, role and group. A note, or None.

    ⚠️ Exact names, and a person who happens to have the account's name is
    never deleted. The group's members are counted in the note, so a mistaken
    teardown can be put right.
    """
    n = names(inst)
    try:
        settings = ctx['load_settings']()
        admin = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not admin:
            return None
        api = AuthentikAdmin(ctx['_get_authentik_api_url'](settings), admin, opener)
        if _clashes(api, n):
            return ('standard admins not removed: "%s" is the admin group of the '
                    'agency deployment "standard"' % n['standard_group'])
        gone = []
        user = _find(api, 'core/users/', 'username', n['username'])
        if user is not None and _is_ours(user):
            for t in api.results('core/tokens/?user__username=%s&intent=api'
                                 % urllib.parse.quote(n['username'])):
                if t.get('user') == user['pk']:
                    api.call('core/tokens/%s/' % urllib.parse.quote(t['identifier']),
                             method='DELETE')
            api.call('core/users/%s/' % user['pk'], method='DELETE')
            gone.append("account '%s'" % n['username'])
        role = _find(api, 'rbac/roles/', 'name', n['role'])
        if role is not None:
            api.call('rbac/roles/%s/' % role['pk'], method='DELETE')
            gone.append("role '%s'" % n['role'])
        # ⚠️ The access policy too, which may name the standard group. The
        # agency teardown removes its own earlier (`remove_agency_admin_group`);
        # the plain deployment has no agency group, so this is its only way
        # out. Runs after the application is deregistered (`remove_instance`).
        # ⚠️ Kept while the application is still there (`atlas_access.remove`);
        # the rest of the teardown goes on, and the note says why it stayed.
        kept = None
        try:
            if atlas_access.remove(api, n['application']):
                gone.append('access policy "%s"' % atlas_access.policy_name(n['application']))
        except Exception as exc:
            kept = 'access policy kept: %s' % str(exc)[:100]
        group = _find(api, 'core/groups/', 'name', n['standard_group'])
        if group is not None:
            members = len(group.get('users') or [])
            api.call('core/groups/%s/' % group['pk'], method='DELETE')
            gone.append('group "%s"%s' % (n['standard_group'], ' (it had %d member%s)' % (
                members, '' if members == 1 else 's') if members else ''))
        parts = ['%s removed' % ', '.join(gone)] if gone else []
        if kept:
            parts.append(kept)
        return 'standard admins: %s' % '; '.join(parts) if parts else None
    except Exception as exc:
        return 'standard admins not removed: %s' % str(exc)[:80]
