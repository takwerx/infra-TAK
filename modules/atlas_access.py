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
import urllib.parse
import urllib.request

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


def is_access_binding(binding):
    """True for an enabled, not-negated binding of one of our policies."""
    name = (binding.get('policy_obj') or {}).get('name') or ''
    return (name.startswith(POLICY_PREFIX)
            and binding.get('enabled', True) and not binding.get('negate'))


def _find(api, path, field, value):
    """The row whose `field` is exactly `value` (Authentik's filters are not identities)."""
    for row in api.results('%s?%s=%s' % (path, field, urllib.parse.quote(value))):
        if row.get(field) == value:
            return row
    return None


def _outcome(status, detail=''):
    return {'status': status, 'detail': detail}


def ensure(api, app_slug, add=(), remove=(), plog=None):
    """Make the application's one access policy admit global admins plus `add`.

    The policy keeps whatever groups it already holds (so the agency's admin
    group and a later standard group are each added by their own caller without
    undoing the other), minus `remove`. The global administrators are always in.

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
        current = parse_groups(pol.get('expression')) if pol else []
        wanted = [ADMIN_GROUP]
        for group in list(current) + list(add):
            if group not in wanted and group not in remove:
                wanted.append(group)
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

        if _supersede(api, bindings, wanted, log):
            changed = True
        return _outcome('created' if changed else 'present')
    except Exception as exc:
        detail = 'could not set the access policy: %s' % str(exc)[:100]
        log('  ⚠ ' + detail)
        return _outcome('failed', detail)


def _supersede(api, bindings, groups, log):
    """Remove the bindings our policy now covers. True when any was removed.

    Only an enabled, not-negated "Allow authentik Admins" binding, and only an
    enabled, not-negated direct binding of one of `groups`. Anything else on the
    application is the operator's and is left alone.
    """
    pks = set()
    for group in groups:
        if group == ADMIN_GROUP:
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


def revoke(api, app_slug, group, plog=None):
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
        result = ensure(api, app_slug, remove=[group], plog=plog)
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
    """
    pol = _find(api, 'policies/expression/', 'name', policy_name(app_slug))
    if pol is None:
        return False
    api.call('policies/expression/%s/' % pol['pk'], method='DELETE')
    return True
