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
"""ATLAS reads its administrator from Authentik's signed token.

ATLAS 2.10.0 can take the administrator's name and groups from
`X-Authentik-Jwt`, the token Authentik's outpost sends, instead of the plain
identity headers (`TAKMDM_ADMIN_IDENTITY_SOURCE=jwt`). The token is signed, and
its groups are a list, so ATLAS no longer has to trust headers it cannot check.

This module is the InfraTAK half, per deployment:

1. **A signing key of the provider's own** (`ATLAS token signing — <provider>`).
   A proxy provider has none by default, and then Authentik signs with the
   provider's client secret (HS256), which ATLAS refuses on purpose.
2. **The key on the provider**, through `providers/oauth2/<pk>/`. ⚠️ The proxy
   provider API has no `signing_key` field; a proxy provider is an OAuth2
   provider underneath, and the OAuth2 endpoint lists every one of them.
3. **Proof before the switch:** the provider's JWKS must publish a key, and
   the generated Caddyfile must copy `X-Authentik-Jwt` into this deployment's
   vhost. Only then does `.env` say `jwt`, with the audience (the provider's
   client ID) and the key address.

⚠️ **Anything short of that writes `headers`.** `jwt` with no key, or with a
Caddy that does not pass the token, refuses every administrator, and the
console is what they would use to fix it.

The key address is Authentik's **public** URL (`atlas_roster.authentik_public_url`):
`_get_authentik_api_url` answers the host's loopback, which inside ATLAS's
container is the container itself.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request

from . import atlas_instances

ENV_SOURCE = 'TAKMDM_ADMIN_IDENTITY_SOURCE'
ENV_AUDIENCE = 'TAKMDM_ADMIN_JWT_AUDIENCE'
ENV_JWKS = 'TAKMDM_ADMIN_JWT_JWKS_URL'

#: Long, because nothing checks a signing key's certificate dates: the token
#: is verified with the public key alone. Ten years keeps the console from
#: showing an "expired" certificate it does not need.
KEY_VALIDITY_DAYS = 3650

TOKEN_HEADER = 'X-Authentik-Jwt'


def key_name(provider_name):
    return 'ATLAS token signing — %s' % provider_name


def jwks_url(public_url, app_slug):
    """📖 Authentik serves a provider's keys at `/application/o/<slug>/jwks/`."""
    return '%s/application/o/%s/jwks/' % (public_url.rstrip('/'), app_slug)


def caddy_copies_token(caddyfile, host):
    """Does the vhost for `host` copy `X-Authentik-Jwt` from forward_auth?

    ⚠️ Checked in **that** vhost. TAK Portal's vhost copies the token too, and
    matching the file as a whole would call a Caddyfile ready whose ATLAS block
    does not pass it.
    """
    if not caddyfile or not host:
        return False
    start = re.search(r'(?m)^%s \{\s*$' % re.escape(host), caddyfile)
    if not start:
        return False
    end = re.search(r'(?m)^\}\s*$', caddyfile[start.end():])
    block = caddyfile[start.end(): start.end() + end.start()] if end else caddyfile[start.end():]
    for line in block.splitlines():
        words = line.split()
        if words[:1] == ['copy_headers'] and TOKEN_HEADER in words[1:]:
            return True
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
    """The row whose `field` is exactly `value` (Authentik filters are substrings)."""
    for row in api.results('%s?%s=%s' % (path, field, urllib.parse.quote(value))):
        if row.get(field) == value:
            return row
    return None


def find_provider(api, name):
    """The deployment's proxy provider, by exact name, or None."""
    return _find(api, 'providers/proxy/', 'name', name)


def ensure_signing_key(api, name):
    """The provider's own key pair, made if missing. Returns (row, note)."""
    row = _find(api, 'crypto/certificatekeypairs/', 'name', name)
    if row is not None:
        return row, 'present'
    made = api.call('crypto/certificatekeypairs/generate/', {
        'common_name': name,
        'subject_alt_name': '',
        'validity_days': KEY_VALIDITY_DAYS,
    }, method='POST')
    return made, 'created'


def ensure_key_on_provider(api, provider_pk, key_pk):
    """Put the key on the provider. Returns 'present' or 'set'."""
    current = api.call('providers/oauth2/%s/' % provider_pk)
    if str(current.get('signing_key') or '') == str(key_pk):
        return 'present'
    api.call('providers/oauth2/%s/' % provider_pk, {'signing_key': str(key_pk)},
             method='PATCH')
    return 'set'


def refresh_outposts(api, provider_pk):
    """Tell Authentik's sign-in service to read this provider again, now.
    Returns how many outposts were told. (ops #1151)

    ⚠️ **Without this, nobody can sign in to ATLAS for up to five minutes
    after the key is set.** The key goes on through `providers/oauth2/<pk>/`,
    and Authentik tells its outposts about a change only when the proxy
    provider or the outpost itself is saved. The outpost goes on checking
    sign-ins with the old key (the client secret) until its own five-minute
    refresh, and every sign-in ends in a redirect loop.
    ✅ Seen on a box, Nov 24, 2026 (Rocky 9, Authentik 2026.8.5): key set at
    08:36:18, sign-in failed 132 times until the outpost's refresh at 08:40:53.

    A save of the outpost with the name it already has is the smallest write
    that makes Authentik send the update. ✅ Same box: HTTP 200, the outpost
    logged "received update trigger" one second later, a new sign-in worked
    seven seconds later, the provider list and the signing key did not change.
    ⚠️ Never a save of the proxy provider: that takes the key off (`key_lost`).
    """
    told = 0
    for outpost in api.results('outposts/instances/'):
        if outpost.get('type') != 'proxy' or not outpost.get('pk'):
            continue
        if str(provider_pk) not in [str(pk) for pk in (outpost.get('providers') or [])]:
            continue
        api.call('outposts/instances/%s/' % outpost['pk'],
                 {'name': outpost.get('name') or ''}, method='PATCH')
        told += 1
    return told


def jwks_has_key(url, opener=None):
    """Does the provider's JWKS publish at least one key?"""
    open_ = opener or urllib.request.urlopen
    body = json.loads(open_(urllib.request.Request(url), timeout=15).read().decode() or '{}')
    return bool(body.get('keys'))


def _read_caddyfile(path='/etc/caddy/Caddyfile'):
    try:
        with open(path, encoding='utf-8') as handle:
            return handle.read()
    except OSError:
        return ''


def ensure(ctx, inst, dirpath, write_env_value, plog, host, opener=None,
           jwks_opener=None, caddyfile=None, compose_passes=None):
    """Switch one deployment to the signed token, or keep it on headers.

    `host` is the console's host name as Caddy serves it. `caddyfile` is the
    generated file's text (read from disk when None). `compose_passes(dirpath)`
    returns the `TAKMDM_*` names the checked-out ATLAS compose file passes to
    the container, or None when it cannot be read; only a release that passes
    `TAKMDM_ADMIN_IDENTITY_SOURCE` (ATLAS 2.10.0 and newer) is switched. Returns
    ``{'env_changed': bool, 'source': 'jwt' | 'headers'}``; the caller
    restarts `api` when `env_changed`. Never raises.

    ``source`` is 'unchanged' when an unexpected error stopped the checks;
    `.env` is then not touched.
    """
    env = os.path.join(dirpath, '.env')

    def keep_headers(why):
        plog('  ⚠ Administrator sign-in stays on the identity headers: %s' % why)
        try:
            changed = write_env_value(env, ENV_SOURCE, 'headers')
        except Exception as exc:
            plog('  ⚠ Could not write %s: %s' % (ENV_SOURCE, str(exc)[:80]))
            changed = False
        return {'env_changed': changed, 'source': 'headers'}

    try:
        passed = compose_passes(dirpath) if compose_passes else None
        if passed is None or ENV_SOURCE not in passed:
            # ⚠️ Before any Authentik change: an older ATLAS cannot use the
            # key, and its compose file would drop the setting anyway.
            return keep_headers('this ATLAS release does not read %s (2.10.0 '
                                'or newer does)' % ENV_SOURCE)
        settings = ctx['load_settings']()
        admin = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not admin:
            return keep_headers('Authentik is not configured')
        from . import atlas_roster
        public = atlas_roster.authentik_public_url(ctx, settings)
        if not public:
            return keep_headers("Authentik's public name is unknown")
        names = atlas_instances.authentik_names(inst)
        api = AuthentikAdmin(ctx['_get_authentik_api_url'](settings), admin, opener)

        provider = find_provider(api, names['provider'])
        if provider is None or not provider.get('client_id'):
            return keep_headers('Authentik has no provider "%s"' % names['provider'])
        key, key_note = ensure_signing_key(api, key_name(names['provider']))
        if not key.get('pk'):
            return keep_headers('the signing key was not made')
        on_provider = ensure_key_on_provider(api, provider['pk'], key['pk'])
        if on_provider == 'set':
            # ops #1151: or every sign-in fails until the outpost's own
            # five-minute refresh. Not fatal: that refresh still comes.
            try:
                if not refresh_outposts(api, provider['pk']):
                    plog('  ⚠ No Authentik outpost serves this provider yet; a new '
                         'sign-in can fail for up to five minutes')
            except Exception as exc:
                plog("  ⚠ Authentik's sign-in service was not told about the new "
                     'key (%s); a new sign-in can fail for up to five minutes'
                     % str(exc)[:80])

        url = jwks_url(public, names['app_slug'])
        if not jwks_has_key(url, jwks_opener):
            return keep_headers('the provider publishes no key at %s yet' % url)
        text =_read_caddyfile() if caddyfile is None else caddyfile
        if not caddy_copies_token(text, host):
            return keep_headers('Caddy does not pass %s to %s yet' % (TOKEN_HEADER, host))

        changed = write_env_value(env, ENV_AUDIENCE, provider['client_id'])
        changed = write_env_value(env, ENV_JWKS, url) or changed
        # ⚠️ Last, after the two values it depends on are in place.
        changed = write_env_value(env, ENV_SOURCE, 'jwt') or changed
        plog('  ✓ Administrator sign-in uses the signed token (key %s, %s on the '
             'provider)' % (key_note, on_provider))
        return {'env_changed': changed, 'source': 'jwt'}
    except Exception as exc:
        # ⚠️ **Left as it was, not switched back to headers.** A timeout during
        # one update says nothing about the key or the Caddyfile; dropping a
        # working deployment to headers over it would quietly undo the switch.
        # The checks above that *do* say something (no key published, Caddy
        # not passing the token) write headers themselves.
        # Never a secret: the message comes from urllib or the filesystem.
        plog('  ⚠ Administrator sign-in not checked, left as it was: %s'
             % str(exc)[:120])
        return {'env_changed': False, 'source': 'unchanged'}


def env_source(dirpath):
    """What the deployment's `.env` says today: 'jwt', 'headers', or '' when
    the line or the file is not there. Never raises."""
    try:
        with open(os.path.join(dirpath, '.env'), encoding='utf-8') as handle:
            for line in handle.read().splitlines():
                if line.startswith(ENV_SOURCE + '='):
                    return line.split('=', 1)[1].strip()
    except OSError:
        pass
    return ''


#: Written to `.env` by the module only when the Caddy vhost attaches the
#: proxy-auth header, which Caddy does only behind Authentik's forward_auth.
ENV_PROXY_AUTH = 'TAKMDM_PROXY_AUTH_SECRET'


def card_note(dirpath, compose_passes):
    """What the ATLAS card says about administrator sign-in, or None (ops #1151).

    ⚠️ **On the row, not only in the update log.** A deployment that stays on
    the plain identity headers is the case the signed token exists to end:
    ATLAS cannot check those headers. The reason used to be one `⚠` line in a
    log that otherwise read as success.

    None when the deployment reads the signed token, when Authentik is not in
    front of it (no proxy-auth secret in `.env`), and when the files cannot be
    read: "could not look" is not a warning. Two file reads, no network call:
    the page polls this. Never raises.
    """
    try:
        with open(os.path.join(dirpath, '.env'), encoding='utf-8') as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    try:
        values = dict(line.split('=', 1) for line in lines
                      if '=' in line and not line.lstrip().startswith('#'))
        if values.get(ENV_SOURCE, '').strip() == 'jwt':
            return None
        if not values.get(ENV_PROXY_AUTH, '').strip():
            return None
        passed = compose_passes(dirpath)
        if passed is None:
            return None
        if ENV_SOURCE not in passed:
            return ('Administrator sign-in still reads the plain identity headers. '
                    'ATLAS 2.10.0 or newer reads Authentik\'s signed token instead. '
                    'Press Update when that release is offered.')
        return ('Administrator sign-in is still on the plain identity headers. '
                'Press Update to move it to Authentik\'s signed token. The update '
                'log says what is missing.')
    except Exception:
        return None


def key_lost(ctx, inst, opener=None):
    """Is this deployment's provider without its signing key? (ops #1151)

    📖 Authentik sets `signing_key` to None on **every** save through the proxy
    provider API: `ProxyProviderSerializer.create` and `.update` call
    `ProxyProvider.set_oauth_defaults()`, which has the line
    `self.signing_key = None` (authentik/providers/proxy/api.py and models.py,
    read at tag version/2026.8.5). A PATCH of `cookie_domain` or
    `external_host`, and a save of the provider in Authentik's own admin page,
    all take the key off. Authentik then signs with the client secret (HS256)
    again, and ATLAS on `jwt` answers 401 to every administrator.

    True only when Authentik answered and the key is not on the provider.
    Never raises: "could not look" is False, so a timeout changes nothing.
    """
    try:
        settings = ctx['load_settings']()
        admin = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not admin:
            return False
        api = AuthentikAdmin(ctx['_get_authentik_api_url'](settings), admin, opener)
        names = atlas_instances.authentik_names(inst)
        provider = find_provider(api, names['provider'])
        if provider is None:
            return False
        key = _find(api, 'crypto/certificatekeypairs/', 'name', key_name(names['provider']))
        if key is None or not key.get('pk'):
            return True
        current = api.call('providers/oauth2/%s/' % provider['pk'])
        return str(current.get('signing_key') or '') != str(key['pk'])
    except Exception:
        return False


def remove(ctx, inst, opener=None):
    """Delete the deployment's signing key. Returns a note, or '' when nothing
    was there. Never raises.

    ⚠️ Only the key this module named for this provider; never one by pk.
    """
    try:
        settings = ctx['load_settings']()
        admin = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not admin:
            return ''
        api = AuthentikAdmin(ctx['_get_authentik_api_url'](settings), admin, opener)
        name = key_name(atlas_instances.authentik_names(inst)['provider'])
        row = _find(api, 'crypto/certificatekeypairs/', 'name', name)
        if row is None:
            return ''
        api.call('crypto/certificatekeypairs/%s/' % row['pk'], method='DELETE')
        return 'signing key "%s" deleted' % name
    except Exception as exc:
        return 'signing key not deleted: %s' % str(exc)[:80]
