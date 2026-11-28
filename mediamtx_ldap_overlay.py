# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
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
"""MediaMTX LDAP Overlay — Authentik-aware auth + Stream Access user management.

Applied by infra-TAK at deploy time when Authentik/LDAP is detected.
Patches the vanilla MediaMTX config editor Flask app to:
  1. Auto-authenticate via Authentik forward_auth headers (no local login page)
  2. Map vid_* LDAP groups to admin/viewer roles
  3. Viewers (vid_public, vid_private): only see Active Streams page at /viewer — same idea as TAK Portal regular user page
  4. Admins (vid_admin, authentik Admins): full config editor + Stream Access at /stream-access
  5. Future: filter streams in /viewer by path-to-group mapping (vid_public vs vid_private determines which streams each user sees)
"""

import base64
import hashlib
import hmac
import io
import os
import re
import json
import math
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from html import escape as _html_escape
from flask import session, request, redirect, jsonify, Response

AK_URL = os.environ.get('AUTHENTIK_API_URL', 'http://127.0.0.1:9090')
AK_TOKEN = os.environ.get('AUTHENTIK_TOKEN', '')

# Peers whose X-Authentik-* headers we will believe (v10.1.48 W1/W2).
#
# `_authentik_auto_auth()` below turns the VALUE of a request header into an admin
# session. That is only safe if the peer that sent it cannot be anyone — a reverse
# proxy in front is a deployment fact, not a code control. This is the same defect
# that made X-Authentik-Username a CRITICAL in the console in v10.1.0; the console's
# fix (v10.1.1) was a loopback check plus an HMAC'd proxy secret, and this file never
# got the equivalent because nothing had ever scanned it.
#
# Single-box: the editor is bound to 127.0.0.1 and reached only through local Caddy,
# so the default below is already correct and nothing needs to be set.
# Split-box: the editor binds 0.0.0.0 so Caddy on the CONSOLE box can reach it, and
# the console's IP is passed in here (as well as being UFW source-scoped). The
# firewall rule stops being the only thing standing between a same-subnet peer and
# an admin session.
#
# Unset -> loopback only. infra-TAK writes this into the unit on every path that
# ships this file (deploy, "Patch web editor", and the startup converge), so a
# split box gets its console IP before it ever gets this code.
_DEFAULT_TRUSTED = '127.0.0.1,::1'
TRUSTED_PROXIES = frozenset(
    p.strip() for p in os.environ.get('INFRATAK_TRUSTED_PROXIES', _DEFAULT_TRUSTED).split(',')
    if p.strip()
) or frozenset(_DEFAULT_TRUSTED.split(','))
VID_GROUPS = ('vid_private', 'vid_public')
ADMIN_GROUPS = frozenset({'authentik Admins'})
VIEWER_GROUPS = frozenset({'vid_private', 'vid_public'})
# The longest a link made by a viewer lasts (seconds). Admins may make links that never end.
SHARE_LINK_VIEWER_MAX_SECONDS = 86400
# Links made before this update that never end end 24 hours after the first start on it. Same
# files and same rule as the editor's own cap (mediamtx-installer), so whichever starts first
# does it and the other finds the marker.
SHARE_LINK_LEGACY_CAP_SECONDS = 86400

VISIBILITY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stream_visibility.json')
SHARE_LINKS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'share_links.json')
SHARE_LINKS_CAP_MARKER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'share_links_capped.json')


def _cap_log(text):
    """One line to the editor's log (the journal). A log line must never stop the cap or the editor."""
    try:
        print(text, flush=True)
    except Exception:
        pass


def _cap_read_links():
    """Read the links file for the cap. Returns (links, problem, empty).
    problem is None when the file is fine or missing, else a short plain reason (links is {} then).
    empty is True when the file holds nothing at all: no old link can be in it. Writes nothing."""
    try:
        with open(SHARE_LINKS_FILE, 'rb') as f:
            raw = f.read()
    except FileNotFoundError:
        return {}, None, False
    except (IOError, OSError) as e:
        return {}, 'cannot be read (%s)' % (e.strerror or e), False
    if not raw.strip():
        return {}, 'is empty', True
    try:
        links = json.loads(raw.decode('utf-8'))
    except ValueError:
        return {}, 'is cut off or not valid JSON', False
    if not isinstance(links, dict):
        return {}, 'is not a list of links (the top level is not an object)', False
    return links, None, False


def _is_share_link(info):
    """A real link has a text `stream`. Other entries (a number, an object with no stream, data a
    newer version keeps in this file) are not ours to change. Same test as the editor's."""
    return isinstance(info, dict) and isinstance(info.get('stream'), str) and bool(info['stream'])


def cap_never_ending_share_links(now=None):
    """Once per box: give every share link that never ends an end time 24 hours from now.
    Same rules as the editor's own copy (mediamtx-installer PR 84, ops #1323; this copy ops #1363):
    - a link with `limits_version` (stamped by an editor that has the viewer limits) is never
      touched, so a link made on purpose stays, whatever happened to the marker file;
    - only real links are touched (see _is_share_link);
    - an empty file holds no old link, so the marker is made and a link made later is kept
      (editor v2.1.17, the pin in infra-TAK 10.4.9, does not stamp, so the marker is what protects it);
    - a cut-off or unreadable file is never written over: one log line says why, nothing is
      changed and the cap tries again at the next start.
    A link an admin makes later that never ends is kept, because the marker says this ran.
    Returns how many were capped, or None when it could not run."""
    if os.path.exists(SHARE_LINKS_CAP_MARKER_FILE):
        return 0
    now = time.time() if now is None else now
    links, problem, empty = _cap_read_links()
    if problem and not empty:
        _cap_log("Warning: old share links not capped: %s %s. The cap tries again at the next start."
                 % (os.path.basename(SHARE_LINKS_FILE), problem))
        return None
    if empty:
        _cap_log("%s is empty: no old share links to cap." % os.path.basename(SHARE_LINKS_FILE))
    capped = 0
    for info in links.values():
        if _is_share_link(info) and not info.get('expires') and 'limits_version' not in info:
            info['expires'] = now + SHARE_LINK_LEGACY_CAP_SECONDS
            info['ttl_label'] = '24 hours (set by the update)'
            capped += 1
    try:
        if capped:
            with open(SHARE_LINKS_FILE, 'w') as f:
                json.dump(links, f, indent=2)
        with open(SHARE_LINKS_CAP_MARKER_FILE, 'w') as f:
            json.dump({'capped': capped, 'at': int(now)}, f)
    except (IOError, OSError) as e:
        _cap_log("Warning: old share links not capped: could not write (%s). The cap tries again at the next start."
                 % (e.strerror or e))
        return None
    return capped

# Which groups a signed-in person is in (ops #1082).
#
# Roles here come from group NAMES, so the names must be exact. The X-Authentik-Groups
# header cannot give that: the outpost joins the names with "|" into one value, and an
# Authentik group name is free text that may hold "|" itself, so splitting the header
# does not give back the list that went in. The list is read from Authentik's user API
# instead (a JSON list, one entry per group), with the token this editor already uses
# for the Stream Access page. It is also the live answer: a person taken out of a group
# loses the role within GROUPS_RECHECK_SECONDS, not at their next sign-in.
#
# No answer from Authentik (restarting, token unusable) never gives a role: the last
# answer is kept for GROUPS_UNCONFIRMED_MAX_SECONDS, after that the person has no groups
# (a viewer of public streams) until Authentik answers again.
#
# Header format: https://docs.goauthentik.io/add-secure-apps/providers/proxy/
# ("X-authentik-groups ... separated by a pipe"). The header and the API's groups_obj
# are the same list, the person's own groups: blueprints/system/providers-oauth2.yaml
# (profile scope, request.user.groups) and authentik/core/api/users.py (instance.groups),
# read at version/2026.8.5.
GROUPS_RECHECK_SECONDS = 60            # ask Authentik again at most this often per user
GROUPS_UNKNOWN_RETRY_SECONDS = 20      # after no answer, wait this long before the next try
GROUPS_UNCONFIRMED_MAX_SECONDS = 900   # how long the last answer stands with no new one
GROUPS_LOOKUP_TIMEOUT_SECONDS = 4      # one API call
GROUPS_LOOKUP_WAIT_SECONDS = 9         # a request never waits longer than this (two calls)

_groups_lock = threading.Lock()
_groups_cache = {}      # username -> (tuple of names, or None for no answer; time checked)
_groups_last = {}       # username -> (tuple of names, time of the last real answer)
_groups_inflight = {}   # username -> Thread
_groups_warned = {}     # username -> time of the last "no answer" log line


def _authentik_groups_lookup(username):
    """The exact names of the groups `username` is in, asked from Authentik now.
    A tuple (empty for an unknown or deactivated account), or None for no usable answer.
    Never raises."""
    try:
        if not AK_TOKEN:
            return None

        def _get(path):
            r = urllib.request.Request(f'{AK_URL}/api/v3/{path}', headers=_ak_headers())
            return json.loads(urllib.request.urlopen(
                r, timeout=GROUPS_LOOKUP_TIMEOUT_SECONDS).read().decode())

        # `username=` is an exact match; the row is still compared, because Authentik
        # ignores a filter it does not know and would then return every user.
        data = _get('core/users/?username=%s&include_groups=true'
                    % urllib.parse.quote(username, safe=''))
        results = data.get('results') if isinstance(data, dict) else None
        if not isinstance(results, list):
            return None
        user = next((u for u in results
                     if isinstance(u, dict) and u.get('username') == username), None)
        if user is None or user.get('is_active') is not True:
            return ()
        groups = user.get('groups_obj')
        if not isinstance(groups, list):
            full = _get('core/users/%d/' % int(user['pk']))
            groups = full.get('groups_obj') if isinstance(full, dict) else None
            if not isinstance(groups, list):
                return None
        return tuple(g['name'] for g in groups
                     if isinstance(g, dict) and isinstance(g.get('name'), str) and g['name'])
    except Exception:
        return None


def _authentik_groups(username):
    """Cached _authentik_groups_lookup(): the exact group names as a list, or None when
    Authentik gave no answer and the last one is older than
    GROUPS_UNCONFIRMED_MAX_SECONDS. One lookup per user at a time."""
    if not username:
        return None
    started = time.time()

    def _run():
        names = _authentik_groups_lookup(username)
        with _groups_lock:
            if len(_groups_cache) > 2048:
                _groups_cache.clear()
                _groups_last.clear()
                _groups_warned.clear()
            _groups_cache[username] = (names, time.time())
            if names is not None:
                _groups_last[username] = (names, time.time())
            _groups_inflight.pop(username, None)

    def _answer(hit):
        if hit[0] is not None:
            return list(hit[0])
        last = _groups_last.get(username)
        if last and 0 <= time.time() - last[1] <= GROUPS_UNCONFIRMED_MAX_SECONDS:
            return list(last[0])
        return None

    with _groups_lock:
        hit = _groups_cache.get(username)
        if hit:
            ttl = GROUPS_UNKNOWN_RETRY_SECONDS if hit[0] is None else GROUPS_RECHECK_SECONDS
            if 0 <= started - hit[1] < ttl:
                return _answer(hit)
        t = _groups_inflight.get(username)
        if t is None:
            t = threading.Thread(target=_run, daemon=True, name='authentik-groups-lookup')
            _groups_inflight[username] = t
            t.start()
    t.join(GROUPS_LOOKUP_WAIT_SECONDS)
    with _groups_lock:
        hit = _groups_cache.get(username)
        if hit and hit[1] >= started:
            return _answer(hit)
        return _answer((None, started))


# Who the signed-in person is (ops #1153).
#
# Authentik's outpost sends the name twice: as plain text (X-Authentik-Username) and inside
# the token Authentik signed for this sign-in (X-Authentik-Jwt). Only the token proves the
# name, so when the proxy in front passes it, the name is read from the token and from
# nothing else. Caddy says that it passes the token with IDENTITY_MARKER_HEADER, written
# in the same vhost block as the copy of X-Authentik-Jwt (app.py, _emit_mediamtx_site), so
# the two always arrive together. Without that line (a Caddyfile from before this change)
# the plain name header is used as before.
#
# The token is checked with this site's own key: Authentik signs a proxy provider's tokens
# with HS256 and the provider's client secret (authentik/providers/oauth2/models.py,
# OAuth2Provider.jwt_key; authentik/providers/proxy/models.py, set_oauth_defaults, read at
# version/2026.8.6). The outpost passes that token as X-authentik-jwt
# (internal/outpost/proxyv2/application/mode_common.go). The secret is read from
# Authentik's API with the token this editor already holds, for the provider of the
# application STREAM_APP_SLUG and no other, so a token made for another application is
# refused. Standard library only: the editor's venv gets no new package.
# https://docs.goauthentik.io/add-secure-apps/providers/proxy/header_authentication/
IDENTITY_MARKER_HEADER = 'X-Infratak-Identity'
IDENTITY_MARKER_SIGNED = 'signed'
STREAM_APP_SLUG = 'stream'
TOKEN_KEY_RECHECK_SECONDS = 300        # read the key from Authentik again at most this often
TOKEN_KEY_RETRY_SECONDS = 20           # after no answer, or a token the key does not fit
TOKEN_KEY_TIMEOUT_SECONDS = 4          # one API call
TOKEN_CLOCK_LEEWAY_SECONDS = 60
TOKEN_MAX_BYTES = 16384
# The stream vhost's paths outside the login (app.py, MEDIAMTX_OPEN_PATHS; a test keeps the two
# equal). Only there does a request come without a token from a Caddyfile that passes it.
OPEN_PATH_PREFIXES = ('/watch/', '/shared/', '/shared-hls/')
_IDENTITY_SESSION_KEYS = ('username', 'logged_in', 'role', 'ldap_groups', 'ldap_mode',
                          'identity_source')

_token_key_lock = threading.Lock()
_token_key = {'key': None, 'checked': 0.0, 'tried': 0.0}   # key: (client_id, secret bytes)
_token_warned = {}      # reason -> time of the last log line


def _stream_token_key_lookup():
    """(client_id, secret as bytes) of this site's Authentik provider, asked from Authentik
    now, or None for no usable answer. Never raises."""
    try:
        if not AK_TOKEN:
            return None

        def _get(path):
            r = urllib.request.Request(f'{AK_URL}/api/v3/{path}', headers=_ak_headers())
            return json.loads(urllib.request.urlopen(
                r, timeout=TOKEN_KEY_TIMEOUT_SECONDS).read().decode())

        app = _get('core/applications/%s/' % urllib.parse.quote(STREAM_APP_SLUG, safe=''))
        if not isinstance(app, dict) or app.get('slug') != STREAM_APP_SLUG:
            return None
        pk = app.get('provider')
        if not isinstance(pk, int) or isinstance(pk, bool):
            return None
        prov = _get('providers/oauth2/%d/' % pk)
        if not isinstance(prov, dict) or prov.get('pk') != pk:
            return None
        if prov.get('signing_key'):
            return None     # not HS256 then; this check knows HS256 only
        client_id, secret = prov.get('client_id'), prov.get('client_secret')
        if not (isinstance(client_id, str) and client_id
                and isinstance(secret, str) and len(secret) >= 16):
            return None
        return client_id, secret.encode('utf-8')
    except Exception:
        return None


def _stream_token_key(refresh=False):
    """Cached _stream_token_key_lookup(). The last good key stays in use while Authentik
    gives no answer. `refresh` asks again now (at most once per TOKEN_KEY_RETRY_SECONDS),
    for a token the cached key does not fit: the secret may have been changed."""
    now = time.time()
    with _token_key_lock:
        key = _token_key['key']
        age = now - _token_key['checked']
        since_try = now - _token_key['tried']
        if key is not None and not refresh and 0 <= age < TOKEN_KEY_RECHECK_SECONDS:
            return key
        if 0 <= since_try < TOKEN_KEY_RETRY_SECONDS:
            return key
        _token_key['tried'] = now
        if key is None:
            # No key yet: the other requests wait here for this one answer.
            fresh = _stream_token_key_lookup()
            if fresh is not None:
                _token_key['key'] = fresh
                _token_key['checked'] = now
            return fresh
    # A key is in use: ask again without holding the others up (video segments come
    # through here too). They keep the key they have until this answer is in.
    fresh = _stream_token_key_lookup()
    with _token_key_lock:
        if fresh is not None:
            _token_key['key'] = fresh
            _token_key['checked'] = time.time()
        return _token_key['key']


def _b64url_bytes(text):
    """The bytes of one base64url part of a token (no padding in a token). Raises on
    anything that is not base64url."""
    if not re.fullmatch(r'[A-Za-z0-9_-]+', text):
        raise ValueError('not base64url')
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _token_fits(token_parts, key):
    """True when the signature of the token is the HS256 of its first two parts with
    `key` and its audience is this site's provider. Returns (fits, claims)."""
    client_id, secret = key
    signed = (token_parts[0] + '.' + token_parts[1]).encode('ascii')
    want = hmac.new(secret, signed, hashlib.sha256).digest()
    if not hmac.compare_digest(want, _b64url_bytes(token_parts[2])):
        return False, None
    claims = json.loads(_b64url_bytes(token_parts[1]).decode('utf-8'))
    if not isinstance(claims, dict):
        return False, None
    aud = claims.get('aud')
    if not (aud == client_id or (isinstance(aud, list) and client_id in aud)):
        return False, None
    return True, claims


def _signed_username(token):
    """The username inside Authentik's signed token, or (None, reason) when the token does
    not prove one. Returns (username, None) for a good token. Never raises."""
    try:
        if not token:
            return None, 'no-token'
        if len(token) > TOKEN_MAX_BYTES:
            return None, 'too-long'
        parts = token.split('.')
        if len(parts) != 3:
            return None, 'not-a-token'
        head = json.loads(_b64url_bytes(parts[0]).decode('utf-8'))
        # One algorithm, named here: a token never picks how it is checked.
        if not isinstance(head, dict) or head.get('alg') != 'HS256':
            return None, 'algorithm'
        key = _stream_token_key()
        if key is None:
            return None, 'no-key'
        fits, claims = _token_fits(parts, key)
        if not fits:
            newer = _stream_token_key(refresh=True)
            if newer is None or newer == key:
                return None, 'signature'
            fits, claims = _token_fits(parts, newer)
            if not fits:
                return None, 'signature'
        now = time.time()
        exp = claims.get('exp')
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
            return None, 'expired'
        if exp + TOKEN_CLOCK_LEEWAY_SECONDS < now:
            return None, 'expired'
        nbf = claims.get('nbf')
        if (isinstance(nbf, (int, float)) and not isinstance(nbf, bool)
                and nbf - TOKEN_CLOCK_LEEWAY_SECONDS > now):
            return None, 'expired'
        name = claims.get('preferred_username')
        if not isinstance(name, str) or not name:
            return None, 'no-name'
        return name, None
    except Exception:
        return None, 'not-a-token'


_TOKEN_REASONS = {
    'no-token': 'the proxy sent no signed token for this sign-in',
    'not-a-token': 'the signed token could not be read',
    'too-long': 'the signed token is longer than %d bytes' % TOKEN_MAX_BYTES,
    'algorithm': 'the signed token is not HS256',
    'no-key': ('Authentik did not give the key to check it (API %s, application "%s"). '
               'Check AUTHENTIK_TOKEN in the editor env file and that Authentik is up'
               % (AK_URL, STREAM_APP_SLUG)),
    'signature': 'the signature or the audience of the token is not this site\'s',
    'expired': 'the token is past its end time',
    'no-name': 'the token names no user',
}

# v10.2.4 (GH #82): MediaMTX stream paths may be nested — OBS and DJI publish to
# rtmp://host/live/<name>. One path segment: MediaMTX's path-name characters (plus ':').
_PATH_SEGMENT_RE = re.compile(r'^[A-Za-z0-9_.~:-]+$')


def _valid_path(path):
    """True when every '/'-separated segment is a plain path segment. Empty, '.' and
    '..' segments are refused: the visibility lookup uses the name literally, so a name
    some other layer would normalise (live/pub/../secret) must never reach it. Also the
    guard for names written into the watch page's HTML and JS."""
    segs = (path or '').split('/')
    return all(_PATH_SEGMENT_RE.match(s) and s not in ('.', '..') for s in segs)


def _yaml_scalar_text(raw):
    """The string a YAML scalar holds. The editor saves passwords as `pass: "..."`;
    returning the raw text sent the quotes to MediaMTX as part of the password, which
    it refuses for every viewer outside the box (on-box requests pass as the loopback
    `any` user, which is why this hid in testing)."""
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ('"', "'"):
        inner = raw[1:-1]
        if raw[0] == '"':
            return inner.replace('\\"', '"').replace('\\\\', '\\')
        return inner.replace("''", "'")
    return raw


def _load_visibility():
    try:
        with open(VISIBILITY_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_visibility(data):
    with open(VISIBILITY_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def _ak_headers():
    return {'Authorization': f'Bearer {AK_TOKEN}', 'Content-Type': 'application/json'}


def _ak_get(path):
    r = urllib.request.Request(f'{AK_URL}/api/v3/{path}', headers=_ak_headers())
    return json.loads(urllib.request.urlopen(r, timeout=15).read().decode())


def _ak_post(path, body=None):
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(f'{AK_URL}/api/v3/{path}', data=data, headers=_ak_headers(), method='POST')
    raw = urllib.request.urlopen(r, timeout=15).read().decode()
    return json.loads(raw) if raw.strip() else {}


def _ak_patch(path, body):
    data = json.dumps(body).encode()
    r = urllib.request.Request(f'{AK_URL}/api/v3/{path}', data=data, headers=_ak_headers(), method='PATCH')
    raw = urllib.request.urlopen(r, timeout=15).read().decode()
    return json.loads(raw) if raw.strip() else {}


def _ak_delete(path):
    r = urllib.request.Request(f'{AK_URL}/api/v3/{path}', headers=_ak_headers(), method='DELETE')
    urllib.request.urlopen(r, timeout=15)


# ── TLS on the editor's own port (ops #1149) ─────────────────────────────────────────────
# On a remote MediaMTX host, Caddy on the console reaches this editor over the network. The
# stream certificate is on such a host already (RTSPS and HLS use it), so the editor takes
# TLS with it on its one port and still takes plain http there. Caddy of a console that does
# not know about this (an older release, a rollback) keeps working, and the console changes
# its Caddy to https only after it saw this port answer TLS. The first byte of a connection
# tells the two apart: 0x16 is a TLS handshake record, and no HTTP request starts with it.
EDITOR_TLS_CERT = os.environ.get('INFRATAK_EDITOR_TLS_CERT', '/etc/mediamtx/certs/stream.crt')
EDITOR_TLS_KEY = os.environ.get('INFRATAK_EDITOR_TLS_KEY', '/etc/mediamtx/certs/stream.key')
EDITOR_TLS_HANDSHAKE_SECONDS = 20
_editor_tls_lock = threading.Lock()
_editor_tls_state = {'stamp': None, 'ctx': None}


def _editor_tls_context():
    """The TLS context for the two files above, or None when there is no usable pair. The
    files are read again when one of them changes (a renewed certificate needs no restart)."""
    try:
        stamp = tuple((st.st_mtime_ns, st.st_size, st.st_ino)
                      for st in (os.stat(EDITOR_TLS_CERT), os.stat(EDITOR_TLS_KEY)))
    except OSError:
        return None
    with _editor_tls_lock:
        if _editor_tls_state['stamp'] != stamp:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(EDITOR_TLS_CERT, EDITOR_TLS_KEY)
            except Exception:
                ctx = None
            _editor_tls_state.update(stamp=stamp, ctx=ctx)
        return _editor_tls_state['ctx']


def _editor_tls_handler(base):
    """A request handler like `base` (werkzeug's) that takes TLS or plain http on one port.
    All of it runs in the connection's own thread: a slow peer holds up nobody else."""

    class TlsOrPlainHandler(base):
        _tls_sock = None
        _dropped = False

        def setup(self):
            sock = self.request
            if isinstance(sock, ssl.SSLSocket):   # a server that does TLS itself: nothing to tell apart
                super().setup()
                return
            try:
                if sock.recv(1, socket.MSG_PEEK) == b'\x16':
                    ctx = _editor_tls_context()
                    if ctx is None:
                        self._dropped = True      # TLS asked for and no certificate: no answer
                    else:
                        sock.settimeout(EDITOR_TLS_HANDSHAKE_SECONDS)
                        self._tls_sock = ctx.wrap_socket(sock, server_side=True)
                        self._tls_sock.settimeout(None)
                        self.request = self._tls_sock
            except Exception:
                self._dropped = True
            if self._dropped:
                # wrap_socket has taken the socket away on a failed handshake: nothing to read
                self.connection = self.request
                self.rfile, self.wfile = io.BytesIO(), io.BytesIO()
                return
            try:
                super().setup()
            except Exception:
                if self._tls_sock is not None:
                    self._tls_sock.close()
                raise

        def handle(self):
            if not self._dropped:
                super().handle()

        def finish(self):
            try:
                super().finish()
            finally:
                if self._tls_sock is not None:
                    try:
                        self._tls_sock.close()
                    except OSError:
                        pass

    return TlsOrPlainHandler


def _editor_tls_install(app):
    """Make app.run() serve TLS and plain http on its port. Never raises: an editor that
    cannot do this starts as before, on plain http."""
    try:
        from werkzeug.serving import WSGIRequestHandler
        handler = _editor_tls_handler(WSGIRequestHandler)
        run = app.run

        def run_tls_or_plain(*args, **kwargs):
            if not kwargs.get('ssl_context'):     # an editor that does TLS itself keeps its own way
                kwargs.setdefault('request_handler', handler)
            return run(*args, **kwargs)

        app.run = run_tls_or_plain
    except Exception:
        pass


def apply_ldap_overlay(app):
    """Patch the Flask app for Authentik/LDAP mode."""
    _editor_tls_install(app)
    try:
        cap_never_ending_share_links()
    except Exception:
        pass  # never stop the editor from starting over this

    VIEWER_ALLOWED =('/viewer', '/api/viewer/streams', '/api/share-links/generate', '/api/theme/logo')
    VIEWER_PREFIXES = ('/watch/', '/hls-proxy/', '/shared/', '/shared-hls/')

    _untrusted_seen = set()

    def _forget_identity():
        """Drop a sign-in that came from Authentik. A sign-in through the editor's own
        login page (no ldap_mode) is not this code's to end."""
        if session.get('ldap_mode'):
            for key in _IDENTITY_SESSION_KEYS:
                session.pop(key, None)

    @app.before_request
    def _authentik_auto_auth():
        ak_user = request.headers.get('X-Authentik-Username', '')
        ak_token = request.headers.get('X-Authentik-Jwt', '')
        marker = request.headers.get(IDENTITY_MARKER_HEADER, '')
        if not (ak_user or ak_token or marker):
            return
        # Peer pin (v10.1.48). Believe identity headers only from a peer that is
        # supposed to be able to set them. Anyone else is treated as if they sent
        # no headers at all — they fall through to the editor's own login rather
        # than being locked out, so a mis-set TRUSTED_PROXIES degrades to "you must
        # log in", never to "nobody can get in".
        peer = request.remote_addr or ''
        if peer not in TRUSTED_PROXIES:
            if peer not in _untrusted_seen:
                _untrusted_seen.add(peer)
                print('[infratak-overlay] ignoring X-Authentik-* headers from untrusted '
                      'peer %s (trusted: %s). If this is the console/proxy address, set '
                      'INFRATAK_TRUSTED_PROXIES in mediamtx-webeditor.service.'
                      % (peer or '<unknown>', ','.join(sorted(TRUSTED_PROXIES))), flush=True)
            return
        # ops #1153: the proxy passes Authentik's signed token (see IDENTITY_MARKER_HEADER).
        # The name is then the one in the token; the plain name header proves nothing and
        # is not read. A sign-in kept from before the token was checked is not kept.
        signed_mode = marker == IDENTITY_MARKER_SIGNED
        if signed_mode:
            if session.get('identity_source') != IDENTITY_MARKER_SIGNED:
                _forget_identity()
            # Outside the login (share link, watch page) Caddy sends no identity: the
            # sign-in from the request before stands. Every other path came through
            # forward_auth, so a request there with no good token is nobody's sign-in,
            # whatever the session held before.
            if not (ak_user or ak_token) and request.path.startswith(OPEN_PATH_PREFIXES):
                return
            ak_user, why = _signed_username(ak_token)
            if ak_user is None:
                _forget_identity()
                now = time.time()
                if now - _token_warned.get(why, 0) > 300:
                    _token_warned[why] = now
                    print('[infratak-overlay] a sign-in through Authentik was not accepted: '
                          '%s. This person is not signed in to the stream site.'
                          % _TOKEN_REASONS.get(why, why), flush=True)
                return
        elif not ak_user:
            return
        # ops #1082: the groups come from Authentik's own list, never from the groups
        # header (see _authentik_groups). No answer means no groups and no admin role.
        groups = _authentik_groups(ak_user)
        if groups is None:
            groups = []
            now = time.time()
            if now - _groups_warned.get(ak_user, 0) > 300:
                _groups_warned[ak_user] = now
                print('[infratak-overlay] Authentik did not say which groups %r is in '
                      '(API %s). Until it does, this person is a viewer of public streams '
                      'only. Check AUTHENTIK_TOKEN in the editor env file and that '
                      'Authentik is up.' % (ak_user, AK_URL), flush=True)
        role = 'admin' if any(g in ADMIN_GROUPS for g in groups) else 'viewer'
        session['username'] = ak_user
        session['logged_in'] = True
        session['role'] = role
        session['ldap_groups'] = groups
        session['ldap_mode'] = True
        session['identity_source'] = IDENTITY_MARKER_SIGNED if signed_mode else 'header'
        # Redirect away from standalone auth pages
        if request.path in ('/login', '/register', '/forgot-password', '/reset-password'):
            return redirect('/')
        # Viewers (vid_public, vid_private) only see Active Streams — redirect to viewer page, block full editor
        if role == 'viewer':
            p = request.path
            if p not in VIEWER_ALLOWED and not p.startswith('/static') and not any(p.startswith(px) for px in VIEWER_PREFIXES):
                return redirect('/viewer')

    # ── Share links made by viewers ─────────────────────────────────────
    # A viewer makes a link only for a stream they may watch themselves, and the
    # link ends within a day. Only an admin lists links or makes one that never ends.

    @app.before_request
    def _viewer_share_link_policy():
        if session.get('role') != 'viewer':
            return
        if request.path == '/api/share-links':
            return jsonify({'error': 'Only an administrator can list share links'}), 403
        if request.path != '/api/share-links/generate' or request.method != 'POST':
            return
        groups = set(session.get('ldap_groups') or [])
        if not (groups & VIEWER_GROUPS):
            return jsonify({'error': 'No video access. Contact your administrator.'}), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({'error': 'Stream name required'}), 400
        stream = str(data.get('stream') or '').strip()
        if not _valid_path(stream):
            return jsonify({'error': 'Invalid stream name'}), 400
        # Same lookup as /hls-proxy/: a private parent path makes the stream private.
        names = {stream, stream.rsplit('/', 1)[0]} if '/' in stream else {stream}
        vis = _load_visibility()
        if any(vis.get(n, 'public') == 'private' for n in names) and 'vid_private' not in groups:
            return jsonify({'error': 'You do not have access to this stream'}), 403
        ttl = data.get('ttl')
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not (1 <= ttl <= SHARE_LINK_VIEWER_MAX_SECONDS):
            return jsonify({'error': 'A link you make lasts at most 24 hours'}), 400

    # ── HLS helpers ─────────────────────────────────────────────────────

    CONFIG_FILE = os.environ.get('MEDIAMTX_CONFIG', '/usr/local/etc/mediamtx.yml')

    def _get_hlsviewer_credential():
        try:
            with open(CONFIG_FILE, 'r') as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                if 'user: hlsviewer' in line:
                    for j in range(i + 1, min(i + 10, len(lines))):
                        if 'pass:' in lines[j]:
                            pw = _yaml_scalar_text(lines[j].strip().split(':', 1)[1])
                            if pw:
                                return {'username': 'hlsviewer', 'password': pw}
                    break
        except Exception:
            pass
        return None

    def _get_streaming_domain():
        import re as _re
        try:
            with open(CONFIG_FILE, 'r') as f:
                lines = f.readlines()
            hls_enc = False
            domain = None
            for i, line in enumerate(lines):
                s = line.strip()
                if s.startswith('hlsEncryption:'):
                    if s.split(':', 1)[1].strip().lower() in ('yes', 'true'):
                        hls_enc = True
                if 'hlsServerCert:' in line:
                    cert = line.split(':', 1)[1].strip() if ':' in line else ''
                    if not cert and i + 1 < len(lines):
                        nxt = lines[i + 1].strip()
                        if nxt and not nxt.startswith('#'):
                            cert = nxt
                    if cert:
                        m = _re.search(r'/([a-z0-9.-]+\.[a-z]{2,})/\1\.crt', cert)
                        if m:
                            domain = m.group(1)
            # ops #1110: the protocol is MediaMTX's own hlsEncryption, with or without a
            # domain in the certificate path. A remote host keeps its certificate at
            # /etc/mediamtx/certs/stream.crt (no domain in the path), and plain http to a
            # TLS listener is answered 400: no video through /hls-proxy/ there.
            return {'domain': domain, 'protocol': 'https' if hls_enc else 'http'}
        except Exception:
            pass
        return {'domain': None, 'protocol': 'http'}

    # ── HLS proxy (routes HLS through Caddy/Flask so port 8888 isn't needed) ──

    @app.route('/hls-proxy/<path:subpath>')
    def hls_proxy(subpath):
        # Which stream is this? The first segment alone made live/<name> look up "live",
        # which has no visibility entry and so defaulted to public — a private stream
        # served to anyone (GH #82). MediaMTX reads <stream>/<file> for playlists and
        # segments but <stream>/ for its player page, so the stream is either everything
        # before the last segment or the whole path. Both are checked; either one being
        # private makes the request private.
        sub = subpath[:-1] if subpath.endswith('/') else subpath
        if not _valid_path(sub):
            return 'Not found', 404
        names = {sub, sub.rsplit('/', 1)[0]} if '/' in sub else {sub}
        vis = _load_visibility()
        level = 'private' if any(vis.get(n, 'public') == 'private' for n in names) else 'public'
        if level == 'private':
            role = session.get('role')
            if role not in ('viewer', 'admin'):
                return 'Unauthorized', 403
            if role == 'viewer':
                user_groups = set(session.get('ldap_groups') or [])
                if not (user_groups & {'vid_private'}):
                    return 'Unauthorized', 403
        try:
            upstream = _hls_open(subpath, request.query_string)
        except Exception as e:
            return str(e)[:200], 502
        ct = upstream.headers.get('Content-Type', 'application/octet-stream')

        # v10.2.6: since this became the stream domain's only HLS path, segments are
        # streamed through rather than read whole into memory per viewer.
        def body():
            try:
                while True:
                    chunk = upstream.read(65536)
                    if not chunk:
                        break
                    yield chunk
            finally:
                upstream.close()
        r = Response(body(), content_type=ct)
        if upstream.headers.get('Content-Length'):
            r.headers['Content-Length'] = upstream.headers['Content-Length']
        # Playlists change every segment; segments never change once written.
        if 'mpegurl' in ct.lower():
            r.headers['Cache-Control'] = 'no-cache'
        return r

    # ── Shared stream links (token-based, no login required) ────────────

    def _hls_open(subpath, query=b''):
        """Internal: open HLS content on MediaMTX with credentials. Caller closes.

        The query string goes through (v10.2.6). MediaMTX >= 1.18 puts ?session=<id> on
        every variant playlist and segment URL and answers 401 to the same URL without
        it — measured on test6 (v1.20.0), so dropping the query left this proxy able to
        serve the first playlist and nothing after it. LL-HLS _HLS_msn/_HLS_part ride
        the query too."""
        import base64, ssl
        cred = _get_hlsviewer_credential()
        streaming = _get_streaming_domain()
        proto = streaming['protocol']
        url = f'{proto}://127.0.0.1:8888/{subpath}'
        if isinstance(query, bytes):
            query = query.decode('latin-1')
        if query:
            url = f'{url}?{query}'
        headers = {'Accept': '*/*'}
        if cred:
            auth = base64.b64encode(f"{cred['username']}:{cred['password']}".encode()).decode()
            headers['Authorization'] = f'Basic {auth}'
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return urllib.request.urlopen(req, timeout=10, context=ctx)

    @app.route('/watch/<path:stream_name>')
    def watch_stream_visibility(stream_name):
        """Public streams: serve HLS player. Private streams: reject unless logged in with vid_private."""
        # Nested names (live/<name>) are valid streams. The name is also written into
        # this page's <title> and a JS string unescaped, so only plain path segments
        # get through — before v10.2.4 a quote in the URL ran script (GH #82).
        if not _valid_path(stream_name):
            return 'Stream not found', 404
        vis = _load_visibility()
        level = vis.get(stream_name, 'public')
        if level == 'private':
            role = session.get('role')
            if role == 'admin':
                pass
            elif role == 'viewer':
                user_groups = set(session.get('ldap_groups') or [])
                if not (user_groups & {'vid_private'}):
                    return Response(WATCH_PRIVATE_HTML, content_type='text/html', status=403)
            else:
                return Response(WATCH_PRIVATE_HTML, content_type='text/html', status=403)
        # ops #900: the player must start INSIDE the playlist. The box's MediaMTX keeps
        # hlsSegmentCount: 3 (app.py), and MediaMTX drops the oldest listed segment about
        # one segment after it listed it. hls.js with liveSyncDurationCount >= 3 starts at
        # that oldest segment, so a viewer on a slow link got 404 on it, no video, and
        # Stream Offline. liveSyncDurationCount 2 starts one segment in; a network error
        # that is not fatal restarts the load, as CloudTAK's player does. The same two
        # values are in the Watch popup (watchStream) below.
        hls_url = f'/hls-proxy/{stream_name}/index.m3u8'
        title = f'{stream_name} - Live'
        html = f'''<!DOCTYPE html>
<html><head><title>{title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<style>*{{margin:0;padding:0}}body{{background:#000;overflow:hidden;font-family:sans-serif}}
#v{{width:100vw;height:100vh;object-fit:contain}}
#err{{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.95);
z-index:100;justify-content:center;align-items:center;flex-direction:column;text-align:center;color:#fff}}
#err h2{{font-size:1.4rem;margin-bottom:8px}}#err p{{color:#999;font-size:.9rem}}</style>
<script src="/static/hls.min.js"></script></head><body>
<video id="v" controls autoplay muted playsinline></video>
<div id="err"><h2>Stream Offline</h2><p>Waiting for stream\u2026 auto-reconnecting.</p></div>
<script>
var video=document.getElementById("v"),err=document.getElementById("err"),url="{hls_url}";
function start(){{
if(Hls.isSupported()){{var hls=new Hls({{enableWorker:true,lowLatencyMode:false,maxBufferLength:30,maxMaxBufferLength:60,liveSyncDurationCount:2,liveMaxLatencyDurationCount:7}});
hls.loadSource(url);hls.attachMedia(video);
hls.on(Hls.Events.MANIFEST_PARSED,function(){{err.style.display="none";video.play().catch(function(){{}});}});
hls.on(Hls.Events.ERROR,function(ev,data){{if(!data.fatal&&data.type===Hls.ErrorTypes.NETWORK_ERROR){{hls.startLoad();}}if(data.fatal){{err.style.display="flex";setTimeout(function(){{hls.destroy();start();}},5000);}}}});
}}else if(video.canPlayType("application/vnd.apple.mpegurl")){{video.src=url;video.addEventListener("loadedmetadata",function(){{video.play().catch(function(){{}});}});}}
}}
start();
</script></body></html>'''
        return Response(html, content_type='text/html')

    # Share links (/shared/<token>, /shared-hls/, /api/share-links*) are provided by core; overlay only allows paths for viewers.

    # ── Active Streams viewer page (vid_public / vid_private) ────────────

    THEME_FILE = '/opt/mediamtx-webeditor/theme_config.json'
    LOGO_PATH  = '/opt/mediamtx-webeditor/agency_logo'
    _THEME_DEFAULTS = {
        'headerColor': '#1e3a8a', 'headerColorEnd': '#1e293b',
        'accentColor': '#3b82f6',
        'headerTitle': 'MediaMTX Configuration Editor',
        'subtitle': 'Brought to you by TAKWERX',
    }

    # A CSS colour as the theme editor saves it (#hex), or a colour name / rgb() / hsl() form.
    _THEME_COLOUR_RE = re.compile(r'^(#[0-9A-Fa-f]{3,8}|[A-Za-z]{3,30}|(?:rgb|hsl)a?\([0-9.,%/ a-z-]{1,60}\))$')

    def _load_theme():
        try:
            with open(THEME_FILE, 'r') as f:
                t = json.load(f)
                m = dict(_THEME_DEFAULTS)
                m.update(t)
                return m
        except Exception:
            return dict(_THEME_DEFAULTS)

    def _logo_exists():
        import glob as _glob
        return bool(_glob.glob(LOGO_PATH + '.*'))

    @app.route('/viewer')
    def viewer_page():
        if session.get('role') != 'viewer':
            return redirect('/')
        theme = _load_theme()
        logo = _logo_exists()
        # ops #897: every value is written into the page as text. The title and subtitle are
        # the admin's, the username is the Authentik one (X-Authentik-Username), and the editor's
        # own pages already show the title and subtitle as text (Jinja autoescape). A colour
        # that is not a plain CSS colour falls back to the default, because it lands in <style>.
        # The username goes in last so that no text in it is read as a placeholder.
        def _text(v):
            return _html_escape(str(v if v is not None else ''), quote=True)

        def _colour(key):
            v = str(theme.get(key) or '').strip()
            return v if _THEME_COLOUR_RE.match(v) else _THEME_DEFAULTS[key]

        html = ACTIVE_STREAMS_VIEWER_HTML
        html = html.replace('{{HEADER_COLOR}}', _colour('headerColor'))
        html = html.replace('{{HEADER_COLOR_END}}', _colour('headerColorEnd'))
        html = html.replace('{{ACCENT_COLOR}}', _colour('accentColor'))
        html = html.replace('{{LOGO_DISPLAY}}', 'block' if logo else 'none')
        sub = theme.get('subtitle', 'Brought to you by TAKWERX')
        if sub:
            html = html.replace('{{SUBTITLE}}', _text(sub))
        else:
            html = html.replace('<div class="subtitle">{{SUBTITLE}}</div>', '')
        html = html.replace('{{HEADER_TITLE}}', _text(theme.get('headerTitle', 'MediaMTX Configuration Editor')))
        html = html.replace('{{USERNAME}}', _text(session.get('username', '')))
        return Response(html, content_type='text/html')

    # v10.2.6: /api/viewer/hlscred is gone. It handed the hlsviewer credential — read on
    # EVERY path, private included — to any viewer session, vid_public too, and nothing
    # used it: the viewer page plays through /hls-proxy/, which holds the credential
    # server-side. Admins' editor pages get it from the core's own login-gated route.

    @app.route('/api/viewer/streams')
    def api_viewer_streams():
        if session.get('role') != 'viewer':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            user_groups = set(session.get('ldap_groups') or [])
            can_see_private = bool(user_groups & {'vid_private'})

            api_url = os.environ.get('MEDIAMTX_API_URL', 'http://127.0.0.1:9898')
            req = urllib.request.Request(f'{api_url.rstrip("/")}/v3/paths/list', headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            items = data.get('items') or []
            vis = _load_visibility()
            streams = []
            for p in items:
                name = p.get('name') or p.get('confName') or ''
                if not name:
                    continue
                ready = p.get('ready', False)
                available = p.get('available', True)
                level = vis.get(name, 'public')
                if level == 'private' and not can_see_private:
                    continue
                streams.append({
                    'name': name,
                    'ready': ready,
                    'available': available,
                    'visibility': level,
                    # Same-origin, through the overlay — not :8888, which is loopback-only.
                    'hls_url': f"/hls-proxy/{name}/index.m3u8",
                })
            return jsonify({'streams': streams})
        except Exception as e:
            return jsonify({'error': str(e)[:200], 'streams': []}), 500

    # ── Stream Access page (vid_admin only) ──────────────────────────────

    @app.route('/stream-access')
    def stream_access_page():
        if session.get('role') != 'admin':
            return redirect('/viewer')
        return Response(STREAM_ACCESS_HTML, content_type='text/html')

    # ── Stream Visibility API ────────────────────────────────────────────

    @app.route('/api/stream-visibility')
    def api_stream_visibility_get():
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        return jsonify(_load_visibility())

    @app.route('/api/stream-visibility', methods=['POST'])
    def api_stream_visibility_set():
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            data = request.get_json()
            stream = data.get('stream', '').strip()
            level = data.get('level', 'public').strip().lower()
            if not stream:
                return jsonify({'error': 'Stream name required'}), 400
            if level not in ('public', 'private'):
                return jsonify({'error': 'Level must be public or private'}), 400
            vis = _load_visibility()
            vis[stream] = level
            _save_visibility(vis)
            return jsonify({'ok': True, 'stream': stream, 'level': level})
        except Exception as e:
            return jsonify({'error': str(e)[:200]}), 500

    # ── Stream Access API ───────────────────────────────────────────────

    @app.route('/api/stream-access/users')
    def api_stream_users():
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            ALL_TRACKED = list(VID_GROUPS) + ['authentik Admins']
            group_map = {}
            for gname in ALL_TRACKED:
                try:
                    result = _ak_get(f'core/groups/?search={urllib.request.quote(gname)}')
                    for g in result.get('results', []):
                        if g['name'] == gname:
                            group_map[gname] = g['pk']
                except Exception:
                    pass

            admin_group_pk = group_map.get('authentik Admins')
            HIDDEN_PREFIXES = ('ak-', 'adm_', 'nodered-')
            HIDDEN_EXACT = {'akadmin'}
            users = []
            page = 1
            while True:
                result = _ak_get(f'core/users/?page={page}&page_size=100&ordering=username')
                for u in result.get('results', []):
                    uname = u.get('username', '')
                    if uname in HIDDEN_EXACT or any(uname.startswith(p) for p in HIDDEN_PREFIXES):
                        continue
                    user_groups = []
                    is_admin = False
                    for g in (u.get('groups_obj') or []):
                        gn = g.get('name', '')
                        if gn in group_map:
                            user_groups.append(gn)
                        if gn == 'authentik Admins':
                            is_admin = True
                    users.append({
                        'pk': u['pk'],
                        'username': uname,
                        'name': u.get('name', ''),
                        'email': u.get('email', ''),
                        'groups': user_groups,
                        'role': 'admin' if is_admin else 'viewer',
                        'is_active': u.get('is_active', True),
                    })
                pagination = result.get('pagination', {})
                if not pagination.get('next'):
                    break
                page += 1

            return jsonify({
                'users': users,
                'available_groups': list(VID_GROUPS),
                'group_pks': group_map,
                'admin_group_pk': admin_group_pk,
            })
        except Exception as e:
            return jsonify({'error': str(e)[:200]}), 500

    @app.route('/api/stream-access/toggle-group', methods=['POST'])
    def api_toggle_group():
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            data = request.get_json()
            raw_pk = data['user_pk']
            user_pk = int(raw_pk) if str(raw_pk).isdigit() else raw_pk
            group_pk = data['group_pk']
            action = data['action']
            if action == 'add':
                _ak_post(f'core/groups/{group_pk}/add_user/', {'pk': user_pk})
            elif action == 'remove':
                _ak_post(f'core/groups/{group_pk}/remove_user/', {'pk': user_pk})
            else:
                return jsonify({'error': 'Invalid action'}), 400
            return jsonify({'ok': True})
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode()[:300]
            except Exception:
                pass
            return jsonify({'error': f'Authentik API {e.code}: {body}'}), 502
        except Exception as e:
            return jsonify({'error': str(e)[:200]}), 500

    @app.route('/api/stream-access/edit-user', methods=['POST'])
    def api_edit_user():
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            data = request.get_json()
            raw_pk = data['user_pk']
            user_pk = int(raw_pk) if str(raw_pk).isdigit() else raw_pk
            payload = {}
            if 'name' in data:
                payload['name'] = data['name']
            if 'email' in data:
                payload['email'] = data['email']
            if not payload:
                return jsonify({'error': 'Nothing to update'}), 400
            _ak_patch(f'core/users/{user_pk}/', payload)
            return jsonify({'ok': True})
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode()[:300]
            except Exception:
                pass
            return jsonify({'error': f'Authentik API {e.code}: {body}'}), 502
        except Exception as e:
            return jsonify({'error': str(e)[:200]}), 500

    @app.route('/api/stream-access/toggle-active', methods=['POST'])
    def api_toggle_active():
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            data = request.get_json()
            raw_pk = data['user_pk']
            user_pk = int(raw_pk) if str(raw_pk).isdigit() else raw_pk
            is_active = data['is_active']
            _ak_patch(f'core/users/{user_pk}/', {'is_active': is_active})
            return jsonify({'ok': True})
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode()[:300]
            except Exception:
                pass
            return jsonify({'error': f'Authentik API {e.code}: {body}'}), 502
        except Exception as e:
            return jsonify({'error': str(e)[:200]}), 500

    @app.route('/api/stream-access/delete-user', methods=['POST'])
    def api_delete_user():
        if session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            data = request.get_json()
            raw_pk = data['user_pk']
            user_pk = int(raw_pk) if str(raw_pk).isdigit() else raw_pk
            _ak_delete(f'core/users/{user_pk}/')
            return jsonify({'ok': True})
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode()[:300]
            except Exception:
                pass
            return jsonify({'error': f'Authentik API {e.code}: {body}'}), 502
        except Exception as e:
            return jsonify({'error': str(e)[:200]}), 500

    # ── Sidebar injection ───────────────────────────────────────────────
    # Rename "Stream Access" to "Web Users" and hide Account.

    @app.after_request
    def _inject_ldap_sidebar(response):
        if not (response.content_type and 'text/html' in response.content_type):
            return response
        if not session.get('ldap_mode'):
            return response
        if session.get('role') != 'admin':
            return response
        try:
            html = response.get_data(as_text=True)
            if '</body>' not in html:
                return response
            script = (
                '<script>'
                'document.addEventListener("DOMContentLoaded",function(){'
                'document.querySelectorAll(".sidebar-item").forEach(function(b){'
                'var t=b.textContent||"";'
                'if(t.indexOf("Web Users")!==-1){'
                'b.onclick=function(e){'
                'e.preventDefault();'
                'if(typeof showTab==="function")showTab("webusers",e);'
                'var tabs=document.querySelectorAll("[id]");'
                'tabs.forEach(function(el){'
                'if(el.id==="webusers"||el.id==="tab-webusers"||el.getAttribute("data-tab")==="webusers"){'
                'el.innerHTML=\'<iframe src="/stream-access" style="width:100%;height:calc(100vh - 60px);border:none;"></iframe>\';'
                '}'
                '});'
                '};'
                '}'
                'if(t.indexOf("Account")!==-1){b.style.display="none"}'
                '});'
                'var lo=document.querySelectorAll("a,button");'
                'var akHost=window.location.hostname.replace(/^[^.]+/,"authentik");'
                'var returnUrl=encodeURIComponent(window.location.origin+"/");'
                'var logoutUrl="https://"+akHost+"/if/flow/default-invalidation-flow/?next="+returnUrl;'
                'lo.forEach(function(el){'
                'var tx=(el.textContent||"").trim().toLowerCase();'
                'if(tx==="logout"||tx==="log out"||tx==="sign out"){'
                'el.onclick=function(e){e.preventDefault();window.location.href=logoutUrl};'
                'el.setAttribute("href",logoutUrl);'
                '}'
                '});'
                '});'
                '</script>'
            )
            idx = html.rfind('</body>')
            if idx == -1:
                return response
            html = html[:idx] + script + html[idx:]
            response.set_data(html)
            response.headers['Content-Length'] = len(response.get_data())
        except Exception:
            pass
        return response

    print("[LDAP Overlay] Authentik/LDAP mode active — auto-auth via headers, Stream Access at /stream-access")


# ════════════════════════════════════════════════════════════════════════
# Shared link expired/revoked page
# ════════════════════════════════════════════════════════════════════════

WATCH_PRIVATE_HTML = '''<!DOCTYPE html>
<html><head><title>Private Stream</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#121212;color:#e0e0e0;font-family:'Segoe UI',system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;text-align:center}
.box{max-width:400px;padding:40px}.icon{font-size:48px;margin-bottom:16px}h1{font-size:22px;margin-bottom:8px}p{color:#888;font-size:14px;line-height:1.6}</style></head>
<body><div class="box"><div class="icon">&#x1F6E1;</div><h1>Private Stream</h1><p>This stream is restricted. You need a share link from an authorized user, or log in with the appropriate access level.</p></div></body></html>'''

# ════════════════════════════════════════════════════════════════════════
# Active Streams viewer page (vid_public / vid_private — regular users)
# ════════════════════════════════════════════════════════════════════════

ACTIVE_STREAMS_VIEWER_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{HEADER_TITLE}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#121212;color:#e0e0e0;min-height:100vh;line-height:1.5}
.header{background:linear-gradient(135deg,{{HEADER_COLOR}} 0%,{{HEADER_COLOR_END}} 100%);color:#fff;padding:20px 24px;display:flex;justify-content:space-between;align-items:center;position:relative}
.header-left{display:flex;align-items:center;gap:16px}
.header-logo img{max-height:50px;max-width:100px;border-radius:6px}
.header h1{font-size:20px;font-weight:600}
.header .subtitle{color:rgba(255,255,255,.7);font-size:13px;margin-top:2px}
.header-right{display:flex;align-items:center;gap:12px}
.header-user{color:rgba(255,255,255,.7);font-size:13px}
.btn-logout{background:rgba(255,255,255,.15);color:#fff;border:1px solid rgba(255,255,255,.25);border-radius:4px;padding:6px 14px;font-size:13px;cursor:pointer;transition:all .15s}
.btn-logout:hover{background:rgba(255,255,255,.25)}
.container{max-width:960px;margin:0 auto;padding:24px}
table{width:100%;border-collapse:collapse;background:#1e1e1e;border-radius:8px;overflow:hidden}
th{background:#2a2a2a;text-align:left;padding:12px;font-size:13px;color:#888;font-weight:600;text-transform:uppercase;letter-spacing:.5px}
td{padding:12px;border-top:1px solid #333}
.stream-name{font-weight:500;font-family:monospace;font-size:14px}
.badge-live{display:inline-block;background:#22c55e;color:#fff;font-size:10px;padding:2px 8px;border-radius:3px;font-weight:700;text-transform:uppercase;vertical-align:middle;margin-left:8px}
.badge-private{display:inline-block;background:rgba(59,130,246,.15);color:#3b82f6;font-size:10px;padding:2px 8px;border-radius:3px;font-weight:700;vertical-align:middle;margin-left:4px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border:none;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;transition:background .15s}
.btn-watch{background:#4CAF50;color:#fff}
.btn-watch:hover{background:#43a047}
.btn-share{background:#2563eb;color:#fff;margin-left:6px}
.btn-share:hover{background:#1d4ed8}
.loading{text-align:center;padding:48px 20px;color:#888}
.spinner{width:32px;height:32px;border:3px solid #333;border-top-color:{{ACCENT_COLOR}};border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.empty{text-align:center;padding:48px 20px;color:#888}
.empty p{margin-top:8px}
@media(max-width:640px){
  .header{flex-direction:column;gap:12px;text-align:center}
  .header-left{flex-direction:column;gap:8px}
  table,thead,tbody,th,td,tr{display:block}
  thead{display:none}
  tr{margin-bottom:12px;background:#1e1e1e;border-radius:8px;border:1px solid #333;padding:12px}
  td{border:none;padding:6px 0}
  td:last-child{margin-top:10px;display:flex;gap:8px}
  .btn{flex:1;justify-content:center;padding:12px}
}
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <div class="header-logo"><img src="/api/theme/logo" alt="" style="display:{{LOGO_DISPLAY}}" onerror="this.style.display='none'"></div>
    <div><h1>{{HEADER_TITLE}}</h1><div class="subtitle">{{SUBTITLE}}</div></div>
  </div>
  <div class="header-right">
    <span class="header-user">{{USERNAME}}</span>
    <button class="btn-logout" onclick="var h=window.location.hostname.replace(/^[^.]+/,'authentik');window.location.href='https://'+h+'/if/flow/default-invalidation-flow/?next='+encodeURIComponent(window.location.origin+'/')">Logout</button>
  </div>
</div>
<div class="container">
  <div id="content">
    <div class="loading"><div class="spinner"></div><div>Loading streams...</div></div>
  </div>
</div>
<script>
/* ops #897: escapes & < > " ' so the result is safe in text and in a quoted attribute */
function escapeHtml(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
/* ops #897: a value for an inline handler, e.g. onclick="watchStream(' + jsArg(name) + ')". JSON makes
   it a JavaScript string, escapeHtml() then makes that string safe inside the quoted attribute. */
function jsArg(v){return escapeHtml(JSON.stringify(v==null?'':String(v)));}

function streamPath(name){return name.split('/').map(encodeURIComponent).join('/');}

function watchStream(name){
  var hlsUrl='/hls-proxy/'+streamPath(name)+'/index.m3u8';
  var w=1280,h=720,l=(screen.width-w)/2,t=(screen.height-h)/2;
  var popup=window.open('','streamViewer_'+name,
    'width='+w+',height='+h+',left='+l+',top='+t+',toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=no,resizable=yes');
  if(!popup){window.open('/watch/'+streamPath(name),'_blank');return;}
  var title=escapeHtml(name)+' - Live';
  popup.document.write('<!DOCTYPE html><html><head><title>'+title+'</title>'
    +'<style>*{margin:0;padding:0}body{background:#000;overflow:hidden}'
    +'#v{width:100vw;height:100vh;object-fit:contain}'
    +'#err{display:none;position:fixed;top:0;left:0;width:100%;height:100%;'
    +'background:rgba(0,0,0,.95);z-index:100;justify-content:center;align-items:center;'
    +'flex-direction:column;text-align:center;color:#fff;font-family:sans-serif}'
    +'#err h2{font-size:1.4rem;margin-bottom:8px}#err p{color:#999;font-size:.9rem}</style>'
    +'<script src="/static/hls.min.js"><\/script></head><body>'
    +'<video id="v" controls autoplay muted playsinline></video>'
    +'<div id="err"><h2>Stream Offline</h2><p>Waiting for stream\u2026 auto-reconnecting.</p></div>'
    +'<script>'
    +'var video=document.getElementById("v"),err=document.getElementById("err");'
    +'var url="'+hlsUrl+'";'
    +'function start(){'
    +'if(Hls.isSupported()){'
    +'var hls=new Hls({enableWorker:true,lowLatencyMode:false,maxBufferLength:30,maxMaxBufferLength:60,liveSyncDurationCount:2,liveMaxLatencyDurationCount:7});'
    +'hls.loadSource(url);hls.attachMedia(video);'
    +'hls.on(Hls.Events.MANIFEST_PARSED,function(){err.style.display="none";video.play().catch(function(){})});'
    +'hls.on(Hls.Events.ERROR,function(ev,data){if(!data.fatal&&data.type===Hls.ErrorTypes.NETWORK_ERROR){hls.startLoad()}if(data.fatal){err.style.display="flex";setTimeout(function(){hls.destroy();start()},5000)}});'
    +'}else if(video.canPlayType("application/vnd.apple.mpegurl")){'
    +'video.src=url;video.addEventListener("loadedmetadata",function(){video.play().catch(function(){})});'
    +'}}'
    +'start();'
    +'<\/script></body></html>');
  popup.document.close();
}

function shareStream(name,vis,btn){
  btn.disabled=true;btn.style.opacity='0.6';
  if(vis==='public'){
    var url=window.location.origin+'/watch/'+encodeURIComponent(name);
    navigator.clipboard.writeText(url).then(function(){}).catch(function(){
      var inp=document.createElement('input');inp.value=url;document.body.appendChild(inp);inp.select();document.execCommand('copy');document.body.removeChild(inp);
    });
    btn.textContent='\u2705 Link Copied!';btn.style.background='#16a34a';
    setTimeout(function(){btn.innerHTML='&#x1F517; Share';btn.style.background='#2563eb';btn.disabled=false;btn.style.opacity='1'},3000);
    return;
  }
  btn.textContent='Generating...';
  fetch('/api/share-links/generate',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({stream:name,ttl:14400})})
  .then(function(r){return r.json()}).then(function(d){
    if(d.ok&&d.url){
      navigator.clipboard.writeText(d.url).then(function(){}).catch(function(){
        var inp=document.createElement('input');inp.value=d.url;document.body.appendChild(inp);inp.select();document.execCommand('copy');document.body.removeChild(inp);
      });
      btn.textContent='\u2705 Link Copied! (4h)';btn.style.background='#16a34a';
      setTimeout(function(){btn.innerHTML='&#x1F517; Share';btn.style.background='#2563eb';btn.disabled=false;btn.style.opacity='1'},3000);
    }else{
      btn.textContent='Error';btn.style.background='#dc2626';
      setTimeout(function(){btn.innerHTML='&#x1F517; Share';btn.style.background='#2563eb';btn.disabled=false;btn.style.opacity='1'},2000);
    }
  }).catch(function(){
    btn.textContent='Error';btn.style.background='#dc2626';
    setTimeout(function(){btn.innerHTML='&#x1F517; Share';btn.style.background='#2563eb';btn.disabled=false;btn.style.opacity='1'},2000);
  });
}

(async function(){
  var content=document.getElementById('content');
  try{
    var r=await fetch('/api/viewer/streams');
    var data=await r.json();
    if(!r.ok)throw new Error(data.error||'Failed to load streams');
    var streams=(data.streams||[]).filter(function(s){return s.ready||s.available});
    if(streams.length===0){
      content.innerHTML='<div class="empty"><p style="font-size:42px;color:#555">&#x1F4F9;</p><p>No active streams right now.</p><p style="font-size:13px">When someone publishes a stream, it will appear here.</p></div>';
      return;
    }
    var html='<table><thead><tr><th>Stream</th><th style="text-align:center">Viewers</th><th style="text-align:center">Actions</th></tr></thead><tbody>';
    for(var i=0;i<streams.length;i++){
      var s=streams[i];
      var name=s.name||'';
      var vis=s.visibility||'public';
      html+='<tr>';
      html+='<td><span class="stream-name">'+escapeHtml(name)+'</span><span class="badge-live">Live</span>';
      if(vis==='private')html+='<span class="badge-private">Private</span>';
      html+='</td>';
      html+='<td style="text-align:center;color:#888">—</td>';
      html+='<td style="text-align:center;white-space:nowrap">';
      html+='<button class="btn btn-watch" onclick="watchStream('+jsArg(name)+')"><span style="font-size:16px">&#x25B6;&#xFE0F;</span> Watch</button>';
      html+='<button class="btn btn-share" onclick="shareStream('+jsArg(name)+','+jsArg(vis)+',this)">&#x1F517; Share</button>';
      html+='</td></tr>';
    }
    html+='</tbody></table>';
    content.innerHTML=html;
  }catch(err){
    content.innerHTML='<div class="empty"><p>'+escapeHtml(err.message)+'</p></div>';
  }
})();
</script>
</body>
</html>
'''

# ════════════════════════════════════════════════════════════════════════
# Stream Access HTML — standalone page (vid_admin only)
# ════════════════════════════════════════════════════════════════════════

STREAM_ACCESS_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Web Users — MediaMTX</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#121212;--surface:#1e1e1e;--surface2:#2a2a2a;--border:#333;
  --text:#e0e0e0;--text-dim:#888;--text-faint:#555;
  --accent:#00bcd4;--accent-hover:#00acc1;
  --admin:#f59e0b;--private:#3b82f6;--public:#22c55e;
  --danger:#ef4444;--success:#22c55e;--warning:#f59e0b;
}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header-left h1{font-size:20px;font-weight:600;letter-spacing:-0.3px}
.header-left .subtitle{color:var(--text-dim);font-size:13px}
.back-link{color:var(--accent);text-decoration:none;font-size:13px;display:flex;align-items:center;gap:4px;padding:6px 12px;border-radius:6px;transition:background .15s}
.back-link:hover{background:rgba(0,188,212,.1)}
.container{max-width:100%;margin:0 auto;padding:24px}
.in-iframe .header{display:none}
.in-iframe .container{padding:16px}
.info-box{background:rgba(0,188,212,.08);border:1px solid rgba(0,188,212,.25);border-radius:8px;padding:16px 20px;margin-bottom:20px;font-size:13px;line-height:1.7}
.info-box strong{color:var(--accent)}
.search-row{display:flex;gap:12px;margin-bottom:20px;align-items:center;flex-wrap:wrap}
.search-bar{position:relative;flex:1;min-width:240px}
.search-bar input{width:100%;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 14px 10px 40px;color:var(--text);font-size:13px;outline:none;transition:border-color .15s}
.search-bar input:focus{border-color:var(--accent)}
.search-bar input::placeholder{color:var(--text-faint)}
.search-bar .si{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text-faint);font-size:20px}
.page-info{font-size:12px;color:var(--text-dim)}
.page-info em{color:var(--success);font-style:normal}

/* Table */
table{width:100%;border-collapse:collapse}
thead th{text-align:left;padding:10px 12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--text-dim);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover{color:var(--text)}
thead th .sort{font-size:12px;margin-left:2px}
tbody tr{transition:background .1s}
tbody tr:hover{background:var(--surface)}
tbody td{padding:12px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle;font-size:13px}
.user-inactive td{opacity:.5}

/* Action buttons */
.actions{display:flex;gap:6px;flex-wrap:wrap}
.btn{padding:5px 12px;border-radius:4px;font-size:11px;font-weight:600;cursor:pointer;border:none;transition:filter .15s;color:#fff}
.btn:hover{filter:brightness(1.2)}
.btn-edit{background:#3b82f6}
.btn-disable{background:#a855f7}
.btn-enable{background:#22c55e}
.btn-delete{background:#ef4444}
.btn-sm{padding:3px 8px;font-size:10px}

/* Role badge */
.role-badge{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:4px;font-size:11px;font-weight:600;cursor:pointer;transition:all .15s}
.role-admin{background:rgba(0,188,212,.15);color:var(--accent)}
.role-viewer{background:rgba(136,136,136,.15);color:var(--text-dim)}
.role-badge:hover{filter:brightness(1.3)}

/* Status */
.status-enabled{color:var(--success);font-weight:500;font-size:12px}
.status-disabled{color:var(--danger);font-weight:500;font-size:12px}

/* Stream group badges */
.groups-cell{display:flex;gap:4px;flex-wrap:wrap}
.gbadge{padding:3px 8px;border-radius:12px;font-size:10px;font-weight:600;cursor:pointer;transition:all .15s;user-select:none;border:1.5px solid transparent;display:inline-flex;align-items:center;gap:3px}
.gbadge .material-symbols-outlined{font-size:12px}
.gbadge.on.vid_admin{background:rgba(245,158,11,.15);color:var(--admin);border-color:rgba(245,158,11,.35)}
.gbadge.on.vid_private{background:rgba(59,130,246,.15);color:var(--private);border-color:rgba(59,130,246,.35)}
.gbadge.on.vid_public{background:rgba(34,197,94,.15);color:var(--public);border-color:rgba(34,197,94,.35)}
.gbadge.off{background:transparent;color:var(--text-faint);border-color:var(--border)}
.gbadge.off:hover{border-color:var(--text-dim);color:var(--text-dim)}
.gbadge.on:hover{filter:brightness(1.2)}

/* Modal */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;display:none;align-items:center;justify-content:center}
.modal-bg.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;width:420px;max-width:90vw}
.modal h3{font-size:16px;font-weight:600;margin-bottom:16px}
.modal label{display:block;font-size:12px;font-weight:600;color:var(--text-dim);margin-bottom:4px;margin-top:12px;text-transform:uppercase;letter-spacing:.5px}
.modal input{width:100%;background:#0e0e0e;border:1px solid var(--border);border-radius:6px;padding:9px 12px;color:var(--text);font-size:13px;outline:none}
.modal input:focus{border-color:var(--accent)}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}
.mbtn{padding:8px 18px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:none;color:#fff}
.mbtn-cancel{background:var(--surface2);color:var(--text-dim)}
.mbtn-save{background:var(--accent)}
.mbtn-delete{background:var(--danger)}
.mbtn:hover{filter:brightness(1.15)}

/* Toast */
.toast{position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:8px;font-size:13px;z-index:300;transform:translateY(100px);opacity:0;transition:all .3s ease}
.toast.show{transform:translateY(0);opacity:1}
.toast.success{background:#16a34a;color:#fff}
.toast.error{background:#dc2626;color:#fff}

/* Loading */
.loading-overlay{display:flex;align-items:center;justify-content:center;min-height:300px;flex-direction:column;gap:12px;color:var(--text-dim)}
.spinner{width:32px;height:32px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.empty-state{text-align:center;padding:60px 20px;color:var(--text-dim)}
.empty-state .material-symbols-outlined{font-size:48px;margin-bottom:12px;color:var(--text-faint)}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <div>
      <h1>Web Users</h1>
      <div class="subtitle">Manage who can access this configuration editor</div>
    </div>
  </div>
  <a href="/" class="back-link"><span class="material-symbols-outlined" style="font-size:18px">arrow_back</span> Back to Editor</a>
</div>

<div class="container">
  <div class="info-box">
    <strong>User Roles:</strong><br>
    <strong>Admin:</strong> Full access to all settings and configuration<br>
    <strong>Viewer:</strong> Can only view Active Streams tab
  </div>

  <div class="search-row">
    <div class="search-bar">
      <span class="material-symbols-outlined si">search</span>
      <input type="text" id="search" placeholder="Search username, email, or name..." oninput="filterUsers()">
    </div>
    <div class="page-info" id="page-info"></div>
  </div>

  <div id="content">
    <div class="loading-overlay"><div class="spinner"></div><div>Loading users from Authentik...</div></div>
  </div>
</div>

<div class="modal-bg" id="edit-modal">
  <div class="modal">
    <h3>Edit User</h3>
    <label>Username</label>
    <input type="text" id="edit-username" disabled style="opacity:.5">
    <label>Name</label>
    <input type="text" id="edit-name">
    <label>Email</label>
    <input type="email" id="edit-email">
    <input type="hidden" id="edit-pk">
    <div class="modal-actions">
      <button class="mbtn mbtn-cancel" onclick="closeModal('edit-modal')">Cancel</button>
      <button class="mbtn mbtn-save" onclick="saveUser()">Save</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="delete-modal">
  <div class="modal">
    <h3 style="color:var(--danger)">Delete User</h3>
    <p style="font-size:13px;color:var(--text-dim);margin-bottom:8px">Are you sure you want to delete <strong id="delete-name" style="color:var(--text)"></strong>?</p>
    <p style="font-size:12px;color:var(--text-faint)">This will permanently remove the user from Authentik. They will lose access to all services.</p>
    <input type="hidden" id="delete-pk">
    <div class="modal-actions">
      <button class="mbtn mbtn-cancel" onclick="closeModal('delete-modal')">Cancel</button>
      <button class="mbtn mbtn-delete" onclick="confirmDelete()">Delete</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
if (window.self !== window.top) document.body.classList.add('in-iframe');
let allUsers = [];
let groupPks = {};
let availableGroups = [];
let adminGroupPk = null;
let sortCol = 'username';
let sortAsc = true;

async function loadUsers() {
  try {
    const resp = await fetch('/api/stream-access/users');
    if (!resp.ok) throw new Error('API error ' + resp.status);
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    allUsers = data.users;
    groupPks = data.group_pks;
    availableGroups = data.available_groups;
    adminGroupPk = data.admin_group_pk || null;
    renderTable();
  } catch (err) {
    document.getElementById('content').innerHTML = '<div class="empty-state"><span class="material-symbols-outlined">error</span><p>Failed to load users: ' + esc(err.message) + '</p></div>';
  }
}

function sortBy(col) {
  if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
  renderTable();
}

function getFiltered() {
  const q = (document.getElementById('search').value || '').toLowerCase();
  let list = allUsers;
  if (q) list = list.filter(u => u.username.toLowerCase().includes(q) || (u.name||'').toLowerCase().includes(q) || (u.email||'').toLowerCase().includes(q));
  list.sort((a,b) => {
    let va = (a[sortCol]||'').toString().toLowerCase(), vb = (b[sortCol]||'').toString().toLowerCase();
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });
  return list;
}

function renderTable() {
  const filtered = getFiltered();
  const total = allUsers.length;
  document.getElementById('page-info').innerHTML = '<em>Showing ' + filtered.length + ' of ' + total + ' user(s).</em>';
  if (filtered.length === 0) {
    document.getElementById('content').innerHTML = '<div class="empty-state"><span class="material-symbols-outlined">person_off</span><p>No users found.</p></div>';
    return;
  }
  const arrow = function(col) { return sortCol === col ? (sortAsc ? ' \u25B2' : ' \u25BC') : ''; };
  let h = '<table><thead><tr>';
  h += '<th onclick="sortBy(\'username\')">Username<span class="sort">' + arrow('username') + '</span></th>';
  h += '<th onclick="sortBy(\'name\')">Name<span class="sort">' + arrow('name') + '</span></th>';
  h += '<th onclick="sortBy(\'email\')">Email<span class="sort">' + arrow('email') + '</span></th>';
  h += '<th onclick="sortBy(\'role\')">Role<span class="sort">' + arrow('role') + '</span></th>';
  h += '<th>Status</th>';
  h += '<th>Stream Groups</th>';
  h += '<th>Actions</th>';
  h += '</tr></thead><tbody>';
  for (const u of filtered) {
    const rc = u.is_active ? '' : ' class="user-inactive"';
    h += '<tr' + rc + '>';
    h += '<td><strong>' + esc(u.username) + '</strong></td>';
    h += '<td>' + esc(u.name || '\u2014') + '</td>';
    h += '<td style="color:var(--text-dim)">' + esc(u.email || '\u2014') + '</td>';
    const isAdmin = u.role === 'admin';
    h += '<td><span class="role-badge ' + (isAdmin ? 'role-admin' : 'role-viewer') + '"' + (adminGroupPk ? ' onclick="toggleRole(this,' + jsArg(u.pk) + ',' + (isAdmin ? 'true' : 'false') + ')"' : '') + '>' + (isAdmin ? 'Admin' : 'Viewer') + '</span></td>';
    h += '<td><span class="' + (u.is_active ? 'status-enabled' : 'status-disabled') + '">' + (u.is_active ? 'Enabled' : 'Disabled') + '</span></td>';
    h += '<td><div class="groups-cell">';
    for (const g of availableGroups) {
      const on = u.groups.includes(g);
      h += '<span class="gbadge ' + (on ? 'on' : 'off') + ' ' + esc(g) + '" onclick="toggleGroup(this,' + jsArg(u.pk) + ',' + jsArg(g) + ',' + (on ? 'true' : 'false') + ')">';
      h += '<span class="material-symbols-outlined">' + (on ? 'check_circle' : 'add_circle_outline') + '</span>' + esc(g.replace('vid_',''));
      h += '</span>';
    }
    h += '</div></td>';
    h += '<td><div class="actions">';
    h += '<button class="btn btn-edit" onclick="openEdit(' + jsArg(u.pk) + ')">Edit</button>';
    if (u.is_active) {
      h += '<button class="btn btn-disable" onclick="toggleActive(' + jsArg(u.pk) + ',false)">Disable</button>';
    } else {
      h += '<button class="btn btn-enable" onclick="toggleActive(' + jsArg(u.pk) + ',true)">Enable</button>';
    }
    h += '<button class="btn btn-delete" onclick="openDelete(' + jsArg(u.pk) + ')">Delete</button>';
    h += '</div></td></tr>';
  }
  h += '</tbody></table>';
  document.getElementById('content').innerHTML = h;
}

function filterUsers() { renderTable(); }

/* ── Role toggle ── */
async function toggleRole(el, userPk, currentlyAdmin) {
  if (!adminGroupPk) { toast('authentik Admins group not found','error'); return; }
  try {
    const resp = await fetch('/api/stream-access/toggle-group', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({user_pk:userPk, group_pk:adminGroupPk, action:currentlyAdmin?'remove':'add'})
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error||'API error');
    const u = allUsers.find(x => x.pk == userPk);
    if (u) { u.role = currentlyAdmin ? 'viewer' : 'admin'; }
    renderTable();
    toast(currentlyAdmin ? 'Changed to Viewer' : 'Promoted to Admin', 'success');
  } catch (err) { toast('Failed: '+err.message,'error'); }
}

/* ── Group toggle ── */
async function toggleGroup(el, userPk, groupName, on) {
  const gPk = groupPks[groupName];
  if (!gPk) { toast('Group not found','error'); return; }
  try {
    const resp = await fetch('/api/stream-access/toggle-group', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({user_pk:userPk, group_pk:gPk, action:on?'remove':'add'})
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error||'API error');
    const u = allUsers.find(x => x.pk == userPk);
    if (u) { if (on) u.groups = u.groups.filter(g=>g!==groupName); else u.groups.push(groupName); }
    renderTable();
    toast((on?'Removed from ':'Added to ')+groupName,'success');
  } catch (err) { toast('Failed: '+err.message,'error'); }
}

/* ── Edit ── */
function openEdit(pk) {
  const u = allUsers.find(x => x.pk == pk);
  if (!u) return;
  document.getElementById('edit-pk').value = u.pk;
  document.getElementById('edit-username').value = u.username;
  document.getElementById('edit-name').value = u.name || '';
  document.getElementById('edit-email').value = u.email || '';
  document.getElementById('edit-modal').classList.add('open');
}
async function saveUser() {
  const pk = document.getElementById('edit-pk').value;
  const name = document.getElementById('edit-name').value;
  const email = document.getElementById('edit-email').value;
  try {
    const resp = await fetch('/api/stream-access/edit-user', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({user_pk:pk, name:name, email:email})
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error||'API error');
    const u = allUsers.find(x => x.pk == pk);
    if (u) { u.name = name; u.email = email; }
    closeModal('edit-modal');
    renderTable();
    toast('User updated','success');
  } catch (err) { toast('Failed: '+err.message,'error'); }
}

/* ── Disable / Enable ── */
async function toggleActive(pk, activate) {
  try {
    const resp = await fetch('/api/stream-access/toggle-active', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({user_pk:pk, is_active:activate})
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error||'API error');
    const u = allUsers.find(x => x.pk == pk);
    if (u) u.is_active = activate;
    renderTable();
    toast(activate ? 'User enabled' : 'User disabled', 'success');
  } catch (err) { toast('Failed: '+err.message,'error'); }
}

/* ── Delete ── */
function openDelete(pk) {
  const u = allUsers.find(x => x.pk == pk);
  if (!u) return;
  document.getElementById('delete-pk').value = u.pk;
  document.getElementById('delete-name').textContent = u.username;
  document.getElementById('delete-modal').classList.add('open');
}
async function confirmDelete() {
  const pk = document.getElementById('delete-pk').value;
  try {
    const resp = await fetch('/api/stream-access/delete-user', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({user_pk:pk})
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error||'API error');
    allUsers = allUsers.filter(u => u.pk != pk);
    closeModal('delete-modal');
    renderTable();
    toast('User deleted','success');
  } catch (err) { toast('Failed: '+err.message,'error'); }
}

/* ── Helpers ── */
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function toast(msg,type) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'toast ' + type + ' show';
  setTimeout(()=>t.classList.remove('show'), 3000);
}
/* ops #897: escapes & < > " ' so the result is safe in text and in a quoted attribute */
function esc(s) { return String(s==null?'':s).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
/* ops #897: a value for an inline handler: a JavaScript string, made safe for the quoted attribute */
function jsArg(v) { return esc(JSON.stringify(v==null?'':String(v))); }

loadUsers();
</script>
</body>
</html>
'''
