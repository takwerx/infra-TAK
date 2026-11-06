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
"""ATLAS certificate renewal: the Authentik account and the files it needs.

A TAK client certificate expires (728 days on a stock TAK Server), and a CA can
be retired. A device enrolled from a TAK Portal QR code then needs a new one, and
TAK Server signs one only for a username and password on 8446. TAK Portal's QR
password is an Authentik app password, so ATLAS makes the same kind of token —
five minutes long, for the user named in that connection's own certificate — and
the ATLAS plugin enrolls at once. Nobody scans a QR code again.

⚠️ **The account is a superuser, and that is not a choice.** Authentik's
`TokenViewSet.perform_create` replaces the token's owner with the caller unless
the caller is a superuser (read in 2026.5.6 on the box). A role that "only makes
tokens" for other users cannot exist.

So the power is fenced in another way:

* **Only ATLAS's `renewal` container holds the token.** It is written to
  `<atlas dir>/secrets/renewal/authentik.token`, mode 0400, which only that
  container mounts. ATLAS's console and API never see it.
* **That container makes a token only against proof.** The device signs a
  challenge with the connection's private key, and the certificate must chain
  to the TAK root CA written beside the token. A compromised ATLAS cannot get a
  login for a user whose key it does not hold.
* **A new token on every deploy and update**, and the old ones deleted after
  the new one is on disk, so there is no moment without a working token.

* **Never for a revoked certificate (ATLAS W461).** TAK Server's enrollment
  does not look at the certificate a device holds, so renewal must. TAK Server
  records a revocation in its `certificate` table (what its own login check
  reads) and in the issuing CA's CRL. Both are copied beside the token every
  five minutes, and the container refuses renewal when the copy is missing or
  an hour old: a gap here is never a way through.

Nothing here is fatal. A deployment without renewal works exactly as before; the
console says renewal is not set up.

**It can be turned off per deployment** (`renewal_disabled` in the deployment's
record, set from the ATLAS page). Off stops the container, deletes the token
file and deletes the account, and every later deploy and update keeps it that
way instead of re-creating the account.
"""

import json
import os
import re
import secrets
import time
import urllib.parse
import urllib.request

from . import atlas_instances

#: Shared by every deployment's account. A superuser group, because a superuser
#: is the only caller Authentik lets make a token for someone else.
GROUP_NAME = 'ATLAS certificate renewal'

#: Authentik's own home for service accounts, so the account lists with the
#: outposts rather than among people.
SERVICE_ACCOUNT_PATH = 'goauthentik.io/service-accounts'

#: The TAK Server root on an InfraTAK box. Public; world-readable. A rotated
#: intermediate still chains to it, which is the whole point.
TAK_ROOT_CA = '/opt/tak/certs/files/root-ca.pem'

#: Relative to the deployment directory. Untracked, so neither `git checkout -f`
#: nor `git checkout -- .` in the updater touches it.
SECRETS_DIR = os.path.join('secrets', 'renewal')

TOKEN_FILE = 'authentik.token'
URL_FILE = 'authentik.url'
CA_FILE = 'tak-ca.pem'
CLIENT_KEY_FILE = 'client.key'

#: Named in ATLAS's `docker-compose.yml`. The client key is what ATLAS's API
#: presents to the renewal container; the uid is who that container runs as,
#: so it can read files this console wrote with mode 0400.
ENV_CLIENT_KEY = 'TAKMDM_RENEWAL_CLIENT_KEY'
ENV_UID = 'TAKMDM_RENEWAL_UID'

#: The image's own user. A root console hands its files to this uid instead of
#: running the container as root.
IMAGE_UID = 1000

_RENEWAL_SERVICE = re.compile(r'^  renewal:\s*$', re.MULTILINE)


def enabled(inst):
    """Whether renewal is on for this deployment. On unless an operator said off."""
    return not (inst or {}).get('renewal_disabled')


def names(inst):
    """The account's username and its tokens' identifier prefix."""
    slug = atlas_instances.derive(inst)['slug']
    username = 'atlas-renewal' if slug is None else 'atlas-renewal-%s' % slug
    return {'username': username, 'token_prefix': username + '-api-'}


def compose_has_renewal(dirpath):
    """Whether this ATLAS release ships the `renewal` container.

    ⚠️ Asked first, so a box on an older ATLAS gets no superuser account that
    nothing would use.
    """
    try:
        with open(os.path.join(dirpath, 'docker-compose.yml'), encoding='utf-8') as fh:
            return bool(_RENEWAL_SERVICE.search(fh.read()))
    except OSError:
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
    for row in api.results('%s?%s=%s' % (path, field, urllib.parse.quote(value))):
        if row.get(field) == value:
            return row
    return None


def ensure_account(api, inst, now=time.time):
    """Make or repair the account, issue a fresh token, retire the old ones.

    Returns the new token's key. The old tokens are deleted only after the
    caller has the new one, by `retire_old_tokens`.
    """
    n = names(inst)
    group = _find(api, 'core/groups/', 'name', GROUP_NAME)
    if group is None:
        group = api.call('core/groups/', {'name': GROUP_NAME, 'is_superuser': True},
                         method='POST')
    elif not group.get('is_superuser'):
        # Somebody unticked it, and every renewal would fail with a 403 that
        # reads like a broken token.
        api.call('core/groups/%s/' % group['pk'], {'is_superuser': True}, method='PATCH')

    user = _find(api, 'core/users/', 'username', n['username'])
    if user is not None and not _is_ours(user):
        # ⚠️ Somebody's account with our name, made in Authentik or TAK Portal
        # before this ran. Adding it to a superuser group would hand whoever
        # knows its password the whole of Authentik (ops #510).
        raise RuntimeError("an Authentik user named %s exists and is not a service "
                           "account; rename it, then update ATLAS" % n['username'])
    if user is None:
        user = api.call('core/users/', {
            'username': n['username'],
            'name': 'ATLAS certificate renewal',
            'type': 'service_account',
            'path': SERVICE_ACCOUNT_PATH,
            'is_active': True,
        }, method='POST')
    elif not user.get('is_active', True):
        api.call('core/users/%s/' % user['pk'], {'is_active': True}, method='PATCH')
    api.call('core/groups/%s/add_user/' % group['pk'], {'pk': user['pk']}, method='POST')

    identifier = '%s%d' % (n['token_prefix'], int(now()))
    api.call('core/tokens/', {
        'identifier': identifier,
        'intent': 'api',
        'user': user['pk'],
        'expiring': False,
        'description': 'ATLAS certificate renewal (rotated on every ATLAS update)',
    }, method='POST')
    key = api.call('core/tokens/%s/view_key/' % urllib.parse.quote(identifier))['key']
    return key, identifier, user['pk']


def _is_ours(user):
    """An account this module made: a service account, never a person's."""
    return user.get('type') == 'service_account'


def retire_old_tokens(api, inst, user_pk, keep):
    """Delete this account's other API tokens. Returns how many went.

    ⚠️ `user__username`, not `user`: Authentik ignores `?user=` and lists
    every API token on the box (seen on test12, 2026.5.6), so the owner is
    checked here as well as the prefix.
    """
    n = names(inst)
    prefix = n['token_prefix']
    gone = 0
    for token in api.results('core/tokens/?user__username=%s&intent=api&page_size=100'
                             % urllib.parse.quote(n['username'])):
        ident = token.get('identifier') or ''
        if token.get('user') == user_pk and ident.startswith(prefix) and ident != keep:
            api.call('core/tokens/%s/' % urllib.parse.quote(ident), method='DELETE')
            gone += 1
    return gone


def remove_account(api, inst):
    """Delete the account and its tokens. The shared group goes when empty."""
    n = names(inst)
    user = _find(api, 'core/users/', 'username', n['username'])
    if user is None or not _is_ours(user):
        # Never delete a person who happens to have the account's name.
        return False
    retire_old_tokens(api, inst, user['pk'], keep=None)
    api.call('core/users/%s/' % user['pk'], method='DELETE')
    group = _find(api, 'core/groups/', 'name', GROUP_NAME)
    if group is not None and not group.get('users'):
        api.call('core/groups/%s/' % group['pk'], method='DELETE')
    return True


def _write_secret(path, body, uid):
    """Write via a temporary file and rename, mode 0400, owned by `uid`."""
    tmp = path + '.tmp'
    if os.path.exists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        os.write(fd, body.encode('utf-8'))
    finally:
        os.close(fd)
    if uid is not None:
        os.chown(tmp, uid, uid)
    try:
        os.replace(tmp, path)
    except PermissionError:
        # Windows will not replace a read-only file; POSIX never gets here.
        os.chmod(path, 0o600)
        os.replace(tmp, path)


def _uid():
    getuid = getattr(os, 'getuid', None)
    return getuid() if getuid else None


def container_uid():
    """Who the renewal container runs as: this console, unless that is root."""
    me = _uid()
    return IMAGE_UID if me in (0, None) else me


def client_key(dirpath):
    """The key ATLAS's API presents to the renewal container, made once."""
    path = os.path.join(dirpath, SECRETS_DIR, CLIENT_KEY_FILE)
    try:
        with open(path, encoding='utf-8') as fh:
            existing = fh.read().strip()
        if existing:
            return existing
    except OSError:
        pass
    return secrets.token_urlsafe(32)


def write_files(dirpath, token, authentik_url, ca_pem, key, uid):
    """Everything the renewal container reads, in its own 0700 directory."""
    sdir = os.path.join(dirpath, SECRETS_DIR)
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    os.chmod(sdir, 0o700)
    chown = uid if _uid() == 0 else None
    if chown is not None:
        os.chown(os.path.dirname(sdir), chown, chown)
        os.chown(sdir, chown, chown)
    # The token last: the container treats its presence as "configured".
    _write_secret(os.path.join(sdir, URL_FILE), authentik_url, chown)
    _write_secret(os.path.join(sdir, CA_FILE), ca_pem, chown)
    _write_secret(os.path.join(sdir, CLIENT_KEY_FILE), key, chown)
    _write_secret(os.path.join(sdir, TOKEN_FILE), token, chown)


#: ATLAS W461: what the container reads to refuse revoked certificates
#: (`app/renewal/revocation.py` in ATLAS).
REVOKED_FILE = 'revoked.txt'
CRL_FILE = 'tak-crls.pem'
TAK_CERT_DIR = os.path.dirname(TAK_ROOT_CA)

#: TAK Server's own record: `CertManagerAdminApi` sets it, `X509Authenticator`
#: reads it. `hash` is the SHA-256 fingerprint, upper case, colon-separated.
REVOKED_SQL = ('SELECT hash FROM certificate WHERE revocation_date IS NOT NULL '
               'ORDER BY hash')
_FINGERPRINT = re.compile(r'^[0-9A-F]{2}(?::[0-9A-F]{2}){31}$')
_CRL_BLOCK = re.compile(r'-----BEGIN X509 CRL-----\r?\n[A-Za-z0-9+/=\r\n]+?-----END X509 CRL-----')

#: How often the copy is refreshed. The container refuses one older than an hour.
REVOCATION_INTERVAL_S = 300


def revoked_fingerprints(ctx):
    """Every revoked certificate's fingerprint, or None when TAK Server's
    database could not be read, or answered with something that is not one."""
    settings = ctx['load_settings']()
    ok, out = ctx['_cotdb_psql'](ctx['_get_tak_deployment_config'](settings), REVOKED_SQL)
    if not ok:
        return None
    found = []
    for line in (out or '').splitlines():
        line = line.strip().upper()
        if not line:
            continue
        if not _FINGERPRINT.match(line):
            return None
        found.append(line)
    return found


def tak_crls(cert_dir=TAK_CERT_DIR):
    """Every CA's CRL from TAK Server's certificate folder, PEM. Public data."""
    blocks = []
    try:
        names = sorted(n for n in os.listdir(cert_dir) if n.endswith('.crl'))
    except OSError:
        return ''
    for name in names:
        try:
            with open(os.path.join(cert_dir, name), encoding='ascii', errors='replace') as fh:
                blocks.extend(b.replace('\r\n', '\n') for b in _CRL_BLOCK.findall(fh.read()))
        except OSError:
            continue
    return '\n'.join(dict.fromkeys(blocks)) + '\n' if blocks else ''


def write_revocations(dirpath, fingerprints, crls_pem, uid, now=time.time):
    """The CRLs, then the list with the time it was taken: the list is what the
    container checks for freshness, so it goes last."""
    sdir = os.path.join(dirpath, SECRETS_DIR)
    chown = uid if _uid() == 0 else None
    stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now()))
    _write_secret(os.path.join(sdir, CRL_FILE), crls_pem, chown)
    _write_secret(os.path.join(sdir, REVOKED_FILE),
                  '\n'.join(['written=' + stamp] + list(fingerprints)) + '\n', chown)


def refresh_revocations(ctx, inst, dirpath, plog, cert_dir=TAK_CERT_DIR):
    """Copy TAK Server's revocations for one deployment. True when written.

    ⚠️ When the database cannot be read, nothing is written: the old copy ages
    out and the container refuses renewal, which is the safe way to fail.
    """
    try:
        if not enabled(inst) or not os.path.isdir(os.path.join(dirpath, SECRETS_DIR)):
            return False
        prints = revoked_fingerprints(ctx)
        if prints is None:
            plog("  ⚠ Could not read TAK Server's revoked certificates; certificate "
                 'renewal stops within an hour until it can.')
            return False
        write_revocations(dirpath, prints, tak_crls(cert_dir), container_uid())
        return True
    except Exception as exc:
        plog("  ⚠ Could not copy TAK Server's revoked certificates: %s" % str(exc)[:120])
        return False


def _read_ca(path=TAK_ROOT_CA):
    try:
        with open(path, encoding='utf-8') as fh:
            pem = fh.read()
    except OSError:
        return None
    return pem if 'BEGIN CERTIFICATE' in pem else None


def ensure(ctx, inst, dirpath, write_env_value, plog, opener=None, ca_path=TAK_ROOT_CA):
    """Set renewal up for one deployment.

    Returns ``{'env_changed': bool, 'ready': bool}``. ``ready`` means the files
    are in place and the caller should start the container
    (``up -d --build renewal``).

    ⚠️ **The container is started by name, after this, and never as a
    dependency of `api`.** Docker creates a missing bind-mount source as an
    empty root-owned directory; had `api` pulled the container up before these
    files existed, this console could never write into that directory again.

    Called by deploy and by update. Never raises: renewal is an addition, and a
    failure here must not turn a working update into a failed one.
    """
    nothing = {'env_changed': False, 'ready': False}
    try:
        if not compose_has_renewal(dirpath):
            return nothing
        if not enabled(inst):
            # Kept off on every update, not only when the switch was flipped:
            # an account restored from an Authentik backup goes again here.
            _delete_token_file(dirpath)
            note = remove(ctx, inst, opener)
            plog('  Certificate renewal is off for this deployment%s.'
                 % ('; ' + note if note else ''))
            return nothing
        settings = ctx['load_settings']()
        admin = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        public = authentik_public_url(ctx, settings)
        if not admin:
            plog('  ⚠ Certificate renewal not set up: Authentik is not configured.')
            return nothing
        if not public:
            plog("  ⚠ Certificate renewal not set up: Authentik's public name is unknown "
                 "(no FQDN in the settings).")
            return nothing
        ca_pem = _read_ca(ca_path)
        if ca_pem is None:
            plog('  ⚠ Certificate renewal not set up: no TAK Server root CA at %s.' % ca_path)
            return nothing

        api = AuthentikAdmin(ctx['_get_authentik_api_url'](settings), admin, opener)
        token, identifier, user_pk = ensure_account(api, inst)
        uid = container_uid()
        key = client_key(dirpath)
        # ⚠️ The public name, not `_get_authentik_api_url`: that answers the
        # host's loopback, which inside a container is the container itself.
        write_files(dirpath, token, public, ca_pem, key, uid)
        # ATLAS W461: at once, not only at the next tick, or renewal is refused
        # for the first minutes after every deploy and update.
        refresh_revocations(ctx, inst, dirpath, plog)
        retired = retire_old_tokens(api, inst, user_pk, keep=identifier)

        env = os.path.join(dirpath, '.env')
        changed = write_env_value(env, ENV_CLIENT_KEY, key)
        changed = write_env_value(env, ENV_UID, str(uid)) or changed
        plog('  ✓ Certificate renewal: account %s, new token%s' % (
            names(inst)['username'],
            ' (%d old one%s deleted)' % (retired, '' if retired == 1 else 's') if retired else ''))
        return {'env_changed': changed, 'ready': True}
    except Exception as exc:
        # Never the token: the message comes from urllib or the filesystem.
        plog('  ⚠ Certificate renewal not set up: %s' % str(exc)[:120])
        return nothing


def start(compose, plog):
    """Start or rebuild the renewal container. Never raises."""
    try:
        r = compose('up -d --build renewal')
        if r.returncode == 0:
            plog('  ✓ Certificate renewal container running')
        else:
            plog('  ⚠ Certificate renewal container did not start: %s'
                 % ((r.stderr or '')[-160:].strip() or 'no output'))
    except Exception as exc:
        plog('  ⚠ Certificate renewal container did not start: %s' % str(exc)[:120])


def authentik_public_url(ctx, settings):
    """`https://<Authentik's public host>[:port]`, the way the console builds it.

    ⚠️ **Not `AUTHENTIK_FQDN` from Authentik's `.env`.** That key is not there
    on an InfraTAK box, and the first box update stopped with "Authentik is not
    configured" while Authentik was working. The console names Authentik with
    `_get_service_domain` (a custom `authentik_domain`, else `authentik.<fqdn>`)
    and `_pub_hostport` (Caddy may listen on a port other than 443).
    """
    domain = ctx['_get_service_domain'](settings, 'authentik') if '_get_service_domain' in ctx else ''
    if not domain:
        domain = ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_FQDN') or ''
    if not domain:
        return ''
    if '_pub_hostport' in ctx:
        domain = ctx['_pub_hostport'](domain, settings)
    return 'https://%s' % domain


def _delete_token_file(dirpath):
    path = os.path.join(dirpath, SECRETS_DIR, TOKEN_FILE)
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    except PermissionError:
        # Windows will not delete a read-only file; POSIX never gets here.
        os.chmod(path, 0o600)
        os.unlink(path)
    return True


def disable(ctx, inst, dirpath, compose, plog, opener=None):
    """Turn renewal off now: stop the container, then delete the token and the
    account. Never raises; each step says what happened."""
    try:
        r = compose('rm -s -f renewal')
        plog('Renewal container stopped' if r.returncode == 0 else
             'Renewal container not stopped: %s'
             % ((r.stderr or '')[-160:].strip() or 'no output'))
    except Exception as exc:
        plog('Renewal container not stopped: %s' % str(exc)[:120])
    try:
        if _delete_token_file(dirpath):
            plog('Token file deleted')
    except OSError as exc:
        plog('Token file not deleted: %s' % str(exc)[:120])
    note = remove(ctx, inst, opener)
    plog(note[0].upper() + note[1:] if note else 'No renewal account to remove')


def remove(ctx, inst, opener=None):
    """Delete this deployment's account. Returns a note, or None."""
    try:
        settings = ctx['load_settings']()
        admin = (ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_TOKEN') or
                 ctx['_get_authentik_env_value'](settings, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if not admin:
            return None
        api = AuthentikAdmin(ctx['_get_authentik_api_url'](settings), admin, opener)
        if remove_account(api, inst):
            return "renewal account '%s' removed" % names(inst)['username']
        return None
    except Exception as exc:
        return 'renewal account not removed: %s' % str(exc)[:80]
