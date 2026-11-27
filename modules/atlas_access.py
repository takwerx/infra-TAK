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
# infra-TAK — who may open an ATLAS application in Authentik (ops #979)
"""One access policy per ATLAS application: global admins OR the deployment's groups.

⚠️ **Why one policy and not one binding per group.** Authentik decides access
from the bindings on an application and its `policy_engine_mode`. With `any`,
each binding is another way in. With `all`, each binding is another thing a user
must pass. The Hardened posture sets `all` on every login application (its MFA
step, `_w1_apply_mfa` in app.py), because the MFA binding has to be required
beside the group check. Separate group bindings (`authentik Admins`,
`atlas-<slug>-admins`) then became a requirement to be in *both* groups: an
agency administrator who is not also an Authentik administrator got Authentik's
"Permission denied" (measured on test6, ops #979).

One expression policy holds the whole "or" inside itself, so the application has
one access binding that means the same thing under `any` and under `all`. The
MFA binding stays a separate binding and stays required under `all`.

⚠️ **Lockout-safe order.** The policy is bound and read back *before* the
bindings it replaces are removed. A crash in between leaves the old bindings as
well: under `all` that is the old behaviour (too strict), never a wider door.
An application is never left with no binding at all, because Authentik shows an
unbound application to every signed-in user.

Pure on purpose: every call goes through `api`, an object with
``call(path, data=None, method=None)`` and ``results(path)``, so all of it is
testable without Authentik.
"""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from . import atlas_instances

#: Every access policy this module makes starts with this, followed by the
#: application slug. app.py's boot converge (`_ensure_app_access_policies`) reads
#: it to know such an application is already restricted, and must not add
#: "Allow authentik Admins" beside it (that would be one more requirement under
#: `all`, which is the bug).
POLICY_PREFIX = 'ATLAS access: '

#: Authentik's own administrators. Always in the policy: they were let in by the
#: "Allow authentik Admins" binding this replaces, and still are.
ADMIN_GROUP = 'authentik Admins'

#: The policy "Allow authentik Admins" that app.py binds to every admin-only
#: application. Removed from an application once this policy covers it.
ALLOW_ADMINS_POLICY = 'Allow authentik Admins'

#: Order of our binding. After nothing and before the MFA binding (10).
BINDING_ORDER = 0

_NAME_RE = re.compile(r'name=("(?:[^"\\]|\\.)*")')


class Api:
    """The Authentik calls this needs, with the administrator token.

    ⚠️ `urllib.request.urlopen` is looked up at call time, not bound at import,
    so a test (or anything else) that replaces it is honoured.
    """

    def __init__(self, api_url, headers):
        self.base = api_url.rstrip('/') + '/api/v3/'
        self.headers = headers

    def call(self, path, data=None, method=None):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers=self.headers, method=method)
        body = urllib.request.urlopen(req, timeout=15).read().decode()
        return json.loads(body) if body else {}

    def results(self, path):
        return self.call(path).get('results', [])


def policy_name(app_slug):
    return POLICY_PREFIX + app_slug


def build_expression(groups):
    """`return ak_is_group_member(...) or ...` for these group names, in order."""
    return 'return ' + ' or '.join(
        'ak_is_group_member(request.user, name=%s)' % json.dumps(g)
        for g in groups)


def parse_groups(expression):
    """The group names an expression made by `build_expression` admits."""
    found = []
    for quoted in _NAME_RE.findall(expression or ''):
        try:
            found.append(json.loads(quoted))
        except ValueError:
            continue
    return found


def is_ours(expression):
    """True when `expression` is exactly what `build_expression` writes.

    ⚠️ Only then may `ensure` rewrite it. `parse_groups` reads the names out of
    any text, so "rebuild from what it parsed" would turn a hand-written
    `return in_group_a and before_5pm` into `return in_group_a`.
    """
    expression = expression or ''
    return expression == build_expression(parse_groups(expression))


def is_access_binding(binding):
    """True for an enabled, not-negated binding of one of our policies."""
    name = (binding.get('policy_obj') or {}).get('name') or ''
    return (name.startswith(POLICY_PREFIX)
            and binding.get('enabled', True) and not binding.get('negate'))


#: Key in a deployment's record. Absent means on: Authentik's superuser group is
#: an ATLAS administrator group (ops #1416, TAK-MDM issue 14). Only an operator's
#: explicit "off" writes it, so a box that never touched the switch holds nothing.
OFF_KEY = 'authentik_admins_off'


def global_admins_wanted(inst):
    """The operator's choice: are Authentik's administrators also ATLAS's? Default yes."""
    return not (inst or {}).get(OFF_KEY)


def state_key(inst_prefix):
    """Where the last answer of the lockout guard is recorded (per deployment)."""
    return inst_prefix + 'authentik_admins_state'


def global_admins_in_force(settings, inst):
    """Whether the global administrators are in the access policy and on the admin line now.

    ⚠️ **The switch is the wish; this is what is true.** Off holds only while the
    lockout guard passed the last time it ran (`guard`). Every writer of the
    policy or the admin line reads this one answer, so they cannot disagree.
    A switch that was never turned off, or whose guard never ran, is in force.
    """
    if global_admins_wanted(inst):
        return True
    state = (settings or {}).get(state_key(_prefix_of(inst)))
    if isinstance(state, dict) and state.get('global_in') is False:
        return False
    return True


def _prefix_of(inst):
    return atlas_instances.derive(inst)['settings_prefix']


def _find(api, path, field, value):
    """The row whose `field` is exactly `value` (Authentik's filters are not identities)."""
    for row in api.results('%s?%s=%s' % (path, field, urllib.parse.quote(value))):
        if row.get(field) == value:
            return row
    return None


def _has_member(row):
    """True when this group row lists at least one enabled user.

    ⚠️ Authentik lists a group's users on the group row (`users_obj` with
    `is_active`; `users` holds the keys). A group whose only member was
    disabled admits nobody who can sign in, so it does not count.
    """
    objs = row.get('users_obj')
    if isinstance(objs, list):
        return any(u.get('is_active', True) for u in objs)
    return bool(row.get('users'))


def guard(api, policy_groups, env_groups, admin_group=None):
    """May the global administrators be taken out? ``(ok, why)``.

    ⚠️ **The lockout guard (ops #1416).** Taking `authentik Admins` out of both
    gates is safe only when somebody else can still get in. One group must be in
    **both** gates, the access policy (`policy_groups`) *and* the ATLAS admin
    line (`env_groups`), must exist in Authentik, and must hold at least one
    enabled user. A group in only one gate lets people through Authentik for
    ATLAS to turn away (or the reverse), which is the same lockout.

    Pure on purpose, and a question that cannot be asked is a no, never a yes:
    an Authentik that did not answer must not read as "your group has members".
    """
    skip = {admin_group or ADMIN_GROUP, ADMIN_GROUP}
    both = [g for g in policy_groups if g in env_groups and g not in skip]
    if not both:
        return False, ('none of your own groups is in both ATLAS\'s admin line and '
                       'Authentik\'s access policy for ATLAS')
    for group in both:
        try:
            row = _find(api, 'core/groups/', 'name', group)
        except Exception as exc:
            return False, 'could not ask Authentik about "%s": %s' % (group, str(exc)[:60])
        if row is not None and _has_member(row):
            return True, 'group "%s" exists and has a member' % group
    return False, ('%s %s in Authentik, or has no enabled member'
                   % (' and '.join('"%s"' % g for g in both),
                      'is missing' if len(both) == 1 else 'are missing'))


def _outcome(status, detail=''):
    return {'status': status, 'detail': detail}


def ensure(api, app_slug, add=(), remove=(), plog=None, admin_group=None,
           include_global=True):
    """Make the application's one access policy admit global admins plus `add`.

    The policy keeps whatever groups it already holds (so the agency's admin
    group and a later standard group are each added by their own caller without
    undoing the other), minus `remove`. The global administrators are in unless
    the operator turned that off for this deployment (`include_global=False`,
    ops #1416): then neither Authentik's superuser group nor the default name is
    in the policy, and it admits only the other groups.

    ⚠️ **A policy with no group is refused, not written.** With the global
    administrators out and nothing else to admit, the expression would be empty
    (invalid in Authentik) and the only honest reading is "nobody", which is the
    lockout the guard exists to prevent. Nothing is changed in that case.

    ⚠️ **`admin_group` is the superuser group as Authentik has it now** (ops
    #1289), from `atlas.global_admin_group`. `authentik Admins` is only the
    default name: an operator who renamed the group was locked out of ATLAS,
    because this policy kept naming the old one. None means the default name.
    The old default name is dropped from the policy once that group is gone, so
    a group made later under that name does not inherit ATLAS administration.

    Returns ``{'status', 'detail'}``: ``present`` (nothing changed), ``created``
    (something was written) or ``failed`` (``detail`` says what). Never raises.

    ⚠️ A binding of ours that somebody disabled or negated in Authentik is
    reported and left alone, and nothing it would replace is removed: that is
    their decision to undo, and removing the old bindings would then lock
    everybody out.
    """
    def log(msg):
        if plog:
            plog(msg)

    name = policy_name(app_slug)
    try:
        app = api.call('core/applications/%s/' % app_slug)
        pol = _find(api, 'policies/expression/', 'name', name)
        if pol is not None and not is_ours(pol.get('expression')):
            # ⚠️ Security read, ops #978: somebody wrote this expression by
            # hand (a time check, a second condition). Rewriting it from the
            # names `parse_groups` finds would silently drop their condition,
            # and could widen who gets in. Reported and left as it is.
            detail = ('the access policy "%s" was changed by hand in Authentik '
                      'and is left as it is; make it a plain list of groups '
                      'again, or delete it, and run Update' % name)
            log('  ⚠ ' + detail)
            return _outcome('failed', detail)
        current = parse_groups(pol.get('expression')) if pol else []
        admin_group = admin_group or ADMIN_GROUP
        if (admin_group != ADMIN_GROUP and ADMIN_GROUP in current
                and ADMIN_GROUP not in add
                and _find(api, 'core/groups/', 'name', ADMIN_GROUP) is None):
            # The default-named group no longer exists (it was renamed): its
            # name in the policy admits nobody now, and would admit whoever
            # makes a group with that name later.
            current = [g for g in current if g != ADMIN_GROUP]
            log('  ✓ The old group name "%s" is no longer in the access policy '
                '(Authentik has no such group)' % ADMIN_GROUP)
        if include_global:
            wanted = [admin_group]
            skip = set()
        else:
            wanted = []
            skip = {admin_group, ADMIN_GROUP}
        for group in list(current) + list(add):
            if group not in wanted and group not in remove and group not in skip:
                wanted.append(group)
        if not wanted:
            detail = ('the access policy "%s" would admit nobody: the Authentik '
                      'administrators are switched off for ATLAS and no other '
                      'group is in it' % name)
            log('  ⚠ ' + detail)
            return _outcome('failed', detail)
        expression = build_expression(wanted)
        changed = False

        if pol is None:
            pol = api.call('policies/expression/', {
                'name': name, 'expression': expression,
                'execution_logging': False}, method='POST')
            changed = True
            log('  ✓ Access policy "%s" created' % name)
        elif (pol.get('expression') or '') != expression:
            api.call('policies/expression/%s/' % pol['pk'],
                     {'expression': expression}, method='PATCH')
            changed = True
            log('  ✓ Access policy "%s" updated' % name)
        else:
            log('  ✓ Access policy "%s" already in place' % name)

        bindings = api.results('policies/bindings/?target=%s&page_size=100'
                               % app['pk'])
        ours = [b for b in bindings if str(b.get('policy')) == str(pol['pk'])]
        if ours and not any(b.get('enabled', True) and not b.get('negate')
                            for b in ours):
            detail = ('the access policy "%s" is bound to this deployment, but '
                      'the binding is disabled or negated in Authentik; its '
                      'administrators are turned away until it is re-enabled '
                      'there' % name)
            log('  ⚠ ' + detail)
            return _outcome('failed', detail)
        if not ours:
            api.call('policies/bindings/', {
                'target': app['pk'], 'policy': pol['pk'],
                'order': BINDING_ORDER, 'negate': False, 'enabled': True,
                'timeout': 30}, method='POST')
            changed = True
            # ⚠️ Read back before anything is removed. A bind that did not land
            # must leave the old bindings where they are.
            again = api.results('policies/bindings/?target=%s&page_size=100'
                                % app['pk'])
            if not any(str(b.get('policy')) == str(pol['pk'])
                       and b.get('enabled', True) and not b.get('negate')
                       for b in again):
                detail = ('the access policy "%s" was not found on the '
                          'application after binding it' % name)
                log('  ⚠ ' + detail)
                return _outcome('failed', detail)
            bindings = again
            log('  ✓ Access policy bound to this deployment')

        if _supersede(api, bindings, wanted, log, admin_group):
            changed = True
        return _outcome('created' if changed else 'present')
    except Exception as exc:
        detail = 'could not set the access policy: %s' % str(exc)[:100]
        log('  ⚠ ' + detail)
        return _outcome('failed', detail)


def _supersede(api, bindings, groups, log, admin_group=ADMIN_GROUP):
    """Remove the bindings our policy now covers. True when any was removed.

    Only an enabled, not-negated "Allow authentik Admins" binding, and only an
    enabled, not-negated direct binding of one of `groups`. Anything else on the
    application is the operator's and is left alone.
    """
    pks = set()
    for group in groups:
        if group == admin_group:
            continue
        row = _find(api, 'core/groups/', 'name', group)
        if row and row.get('pk'):
            pks.add(str(row['pk']))
    removed = False
    for b in bindings:
        if not b.get('enabled', True) or b.get('negate'):
            continue
        policy = (b.get('policy_obj') or {}).get('name')
        if policy == ALLOW_ADMINS_POLICY:
            what = 'the "%s" binding' % ALLOW_ADMINS_POLICY
        elif b.get('group') and str(b['group']) in pks:
            what = 'the separate group binding'
        else:
            continue
        api.call('policies/bindings/%s/' % b['pk'], method='DELETE')
        log('  ✓ Removed %s (the access policy covers it)' % what)
        removed = True
    return removed


def revoke(api, app_slug, group, plog=None, admin_group=None, include_global=True):
    """Take `group` out of this application's way in. True when anything changed.

    ⚠️ Two places can hold it: our policy (one name in the "or") and a direct
    group binding made by older code (PR 596's first form bound the ATLAS
    standard group directly). Both go: under `policy_engine_mode: any` a stale
    direct binding is a door of its own.

    ⚠️ **No policy is made here.** An application that has none (a plain
    deployment still on the "Allow authentik Admins" binding) is left as it
    is: there is nothing in it to take the group out of. Raises on an
    Authentik error; the caller logs it.
    """
    def log(msg):
        if plog:
            plog(msg)

    changed = False
    pol = _find(api, 'policies/expression/', 'name', policy_name(app_slug))
    if pol is not None and group in parse_groups(pol.get('expression')):
        result = ensure(api, app_slug, remove=[group], plog=plog,
                        admin_group=admin_group, include_global=include_global)
        if result['status'] == 'failed':
            raise RuntimeError(result['detail'])
        changed = True
    row = _find(api, 'core/groups/', 'name', group)
    if row and row.get('pk'):
        app = api.call('core/applications/%s/' % app_slug)
        bindings = api.results('policies/bindings/?target=%s&page_size=100'
                               % app['pk'])
        direct = [b for b in bindings if str(b.get('group')) == str(row['pk'])]
        rest = [b for b in bindings if b not in direct]
        # ⚠️ Never the last way in. Authentik shows an application with no
        # binding to every signed-in user, so a direct binding that is all the
        # application has stays, and the operator is told.
        if direct and not any(
                b.get('enabled', True) and not b.get('negate') and (
                    is_access_binding(b) or
                    (b.get('policy_obj') or {}).get('name') == ALLOW_ADMINS_POLICY)
                for b in rest):
            raise RuntimeError('"%s" is bound directly and nothing else restricts '
                               'this application; left in place' % group)
        for b in direct:
            api.call('policies/bindings/%s/' % b['pk'], method='DELETE')
            log('  ✓ Removed the direct binding of "%s"' % group)
            changed = True
    return changed


def remove(api, app_slug):
    """Delete this application's access policy. True when one was deleted.

    ⚠️ On removal of a deployment, so a later deployment that reuses the slug
    starts from the administrators alone rather than inheriting stale groups.

    ⚠️ **Only once the application is gone** (Security read, ops #978): the
    lookup must answer 404. Deleting the policy deletes its binding, and an
    application left with no binding is open to every signed-in user, so an
    application that is still there (its deregistration failed), or a lookup
    that failed for another reason, keeps its policy. Raises then; the caller
    logs it.
    """
    pol = _find(api, 'policies/expression/', 'name', policy_name(app_slug))
    if pol is None:
        return False
    try:
        api.call('core/applications/%s/' % app_slug)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    else:
        raise RuntimeError('the application "%s" is still in Authentik; its '
                           'access policy is kept' % app_slug)
    api.call('policies/expression/%s/' % pol['pk'], method='DELETE')
    return True
