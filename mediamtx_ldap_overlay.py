"""MediaMTX LDAP Overlay — Authentik-aware auth + Stream Access user management.

Applied by infra-TAK at deploy time when Authentik/LDAP is detected.
Patches the vanilla MediaMTX config editor Flask app to:
  1. Auto-authenticate via Authentik forward_auth headers (no local login page)
  2. Map vid_* LDAP groups to admin/viewer roles
  3. Viewers (vid_public, vid_private): only see Active Streams page at /viewer — same idea as TAK Portal regular user page
  4. Admins (vid_admin, authentik Admins): full config editor + Stream Access at /stream-access
  5. Future: filter streams in /viewer by path-to-group mapping (vid_public vs vid_private determines which streams each user sees)
"""

import os
import json
import urllib.request
import urllib.error
from flask import session, request, redirect, jsonify, Response

AK_URL = os.environ.get('AUTHENTIK_API_URL', 'http://127.0.0.1:9090')
AK_TOKEN = os.environ.get('AUTHENTIK_TOKEN', '')
VID_GROUPS = ('vid_private', 'vid_public')
ADMIN_GROUPS = frozenset({'authentik Admins'})
VIEWER_GROUPS = frozenset({'vid_private', 'vid_public'})

VISIBILITY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stream_visibility.json')


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


def apply_ldap_overlay(app):
    """Patch the Flask app for Authentik/LDAP mode."""

    VIEWER_ALLOWED = ('/viewer', '/api/viewer/streams', '/api/viewer/hlscred', '/api/share-links', '/api/share-links/generate', '/api/theme/logo')
    VIEWER_PREFIXES = ('/watch/', '/hls-proxy/', '/shared/', '/shared-hls/')

    @app.before_request
    def _authentik_auto_auth():
        ak_user = request.headers.get('X-Authentik-Username', '')
        ak_groups_raw = request.headers.get('X-Authentik-Groups', '')
        if not ak_user:
            return
        groups = [g.strip() for g in ak_groups_raw.split('|') if g.strip()]
        role = 'admin' if any(g in ADMIN_GROUPS for g in groups) else 'viewer'
        session['username'] = ak_user
        session['logged_in'] = True
        session['role'] = role
        session['ldap_groups'] = groups
        session['ldap_mode'] = True
        # Redirect away from standalone auth pages
        if request.path in ('/login', '/register', '/forgot-password', '/reset-password'):
            return redirect('/')
        # Viewers (vid_public, vid_private) only see Active Streams — redirect to viewer page, block full editor
        if role == 'viewer':
            p = request.path
            if p not in VIEWER_ALLOWED and not p.startswith('/static') and not any(p.startswith(px) for px in VIEWER_PREFIXES):
                return redirect('/viewer')

    # v10.1.34 (security review): registered AFTER _authentik_auto_auth on purpose.
    # Flask runs before_request hooks in registration order, and this one returns a
    # terminal 409 — registering it first meant an unauthenticated POST short-circuited
    # authentication entirely and still learned the pinned version. It performs no
    # action either way, but auth must be evaluated first.
    # ── v10.1.34: intercept the editor's own MediaMTX binary upgrade ──────────
    # Two independent problems with the vendored editor's `POST
    # /api/mediamtx/version/upgrade`, both live on every non-root box:
    #
    #  1. It cannot work. It backs the binary up to
    #     /usr/local/bin/mediamtx.backup_<ts> before swapping. The editor runs as
    #     takwerx and /usr/local/bin is root:root 0755, so it dies with
    #     "[Errno 13] Permission denied" — confirmed on test8 (Ubuntu x86) and
    #     aws-arm (ARM64) 2026-08-14. We do NOT fix this by widening
    #     /usr/local/bin: that directory holds binaries root executes, so making
    #     it takwerx-writable is the root-equivalence already rejected for this
    #     module ([[mediamtx-editor-upgrade-broker-not-sudoers]]). The .33 trick
    #     of widening the directory was safe for /usr/local/etc (MediaMTX files
    #     only) and is NOT safe here.
    #
    #  2. It resolves bluenviron/mediamtx releases/latest on its own, so it would
    #     push a box to an unvetted upstream build in one click — straight past
    #     MEDIAMTX_VETTED_RELEASE. That is precisely how 10.1.33's MoQ crash-loop
    #     would have reached a customer.
    #
    # So the button is answered here with the truth instead of a permission error,
    # and the actual upgrade is left to the console's deploy path, which installs
    # the pinned version with the right privileges. Lives in the overlay rather
    # than as a source patch because the editor is cloned from `main` UNPINNED
    # ([[mediamtx-editor-ref-unpinned]]) — a source edit is clobbered on re-pull,
    # this module is re-copied by our deploy every time.
    # Implemented as a before_request intercept rather than a competing @app.route:
    # the editor registers the same rule itself, and which duplicate wins depends on
    # werkzeug's map ordering and on where the overlay happens to be injected. A
    # before_request hook runs first regardless, so this cannot silently stop working
    # because an upstream re-pull moved a line.
    _VETTED = os.environ.get('INFRATAK_MEDIAMTX_VETTED', '').strip()
    _PINNED_PATHS = ('/api/mediamtx/version/upgrade',)

    @app.before_request
    def _infratak_block_unpinned_upgrade():
        if request.method != 'POST' or request.path not in _PINNED_PATHS:
            return
        pinned = f' (v{_VETTED})' if _VETTED else ''
        return jsonify({
            'success': False,
            'error': (
                f'MediaMTX is pinned by infra-TAK{pinned}. Upgrading from here is '
                'disabled so a box cannot be moved to an untested build. Update '
                'MediaMTX from the infra-TAK console (MediaMTX module → Update), '
                'which installs the vetted version.'),
            'pinned_version': _VETTED or None,
            'infratak_pinned': True,
        }), 409

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
                            pw = lines[j].strip().split(':', 1)[1].strip()
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
            if domain:
                return {'domain': domain, 'protocol': 'https' if hls_enc else 'http'}
        except Exception:
            pass
        return {'domain': None, 'protocol': 'http'}

    # ── HLS proxy (routes HLS through Caddy/Flask so port 8888 isn't needed) ──

    @app.route('/hls-proxy/<path:subpath>')
    def hls_proxy(subpath):
        stream_name = subpath.split('/')[0] if '/' in subpath else subpath
        vis = _load_visibility()
        level = vis.get(stream_name, 'public')
        if level == 'private':
            role = session.get('role')
            if role not in ('viewer', 'admin'):
                return 'Unauthorized', 403
            if role == 'viewer':
                user_groups = set(session.get('ldap_groups') or [])
                if not (user_groups & {'vid_private'}):
                    return 'Unauthorized', 403
        try:
            data, ct = _hls_fetch(subpath)
            r = Response(data, content_type=ct)
            r.headers['Cache-Control'] = 'no-cache'
            return r
        except Exception as e:
            return str(e)[:200], 502

    # ── Shared stream links (token-based, no login required) ────────────

    def _hls_fetch(subpath):
        """Internal: fetch HLS content from MediaMTX with credentials."""
        import base64, ssl
        cred = _get_hlsviewer_credential()
        streaming = _get_streaming_domain()
        proto = streaming['protocol']
        url = f'{proto}://127.0.0.1:8888/{subpath}'
        headers = {'Accept': '*/*'}
        if cred:
            auth = base64.b64encode(f"{cred['username']}:{cred['password']}".encode()).decode()
            headers['Authorization'] = f'Basic {auth}'
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return resp.read(), resp.headers.get('Content-Type', 'application/octet-stream')

    @app.route('/watch/<stream_name>')
    def watch_stream_visibility(stream_name):
        """Public streams: serve HLS player. Private streams: reject unless logged in with vid_private."""
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
if(Hls.isSupported()){{var hls=new Hls({{enableWorker:true,lowLatencyMode:false,maxBufferLength:30,maxMaxBufferLength:60,liveSyncDurationCount:4,liveMaxLatencyDurationCount:7}});
hls.loadSource(url);hls.attachMedia(video);
hls.on(Hls.Events.MANIFEST_PARSED,function(){{err.style.display="none";video.play().catch(function(){{}});}});
hls.on(Hls.Events.ERROR,function(ev,data){{if(data.fatal){{err.style.display="flex";setTimeout(function(){{hls.destroy();start();}},5000);}}}});
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
        html = ACTIVE_STREAMS_VIEWER_HTML
        html = html.replace('{{HEADER_COLOR}}', theme.get('headerColor', '#1e3a8a'))
        html = html.replace('{{HEADER_COLOR_END}}', theme.get('headerColorEnd', '#1e293b'))
        html = html.replace('{{ACCENT_COLOR}}', theme.get('accentColor', '#3b82f6'))
        html = html.replace('{{HEADER_TITLE}}', theme.get('headerTitle', 'MediaMTX Configuration Editor'))
        sub = theme.get('subtitle', 'Brought to you by TAKWERX')
        if sub:
            html = html.replace('{{SUBTITLE}}', sub)
        else:
            html = html.replace('<div class="subtitle">{{SUBTITLE}}</div>', '')
        html = html.replace('{{LOGO_DISPLAY}}', 'block' if logo else 'none')
        html = html.replace('{{USERNAME}}', session.get('username', ''))
        return Response(html, content_type='text/html')

    @app.route('/api/viewer/hlscred')
    def api_viewer_hlscred():
        if session.get('role') not in ('viewer', 'admin'):
            return jsonify({'error': 'Unauthorized'}), 403
        cred = _get_hlsviewer_credential()
        if cred:
            return jsonify(cred)
        return jsonify({'error': 'hlsviewer credential not found'}), 404

    @app.route('/api/viewer/streams')
    def api_viewer_streams():
        if session.get('role') != 'viewer':
            return jsonify({'error': 'Unauthorized'}), 403
        try:
            user_groups = set(session.get('ldap_groups') or [])
            can_see_private = bool(user_groups & {'vid_private'})

            streaming = _get_streaming_domain()
            if streaming['domain']:
                hls_base = f"{streaming['protocol']}://{streaming['domain']}:8888"
            else:
                host = request.host.split(':')[0]
                hls_base = f"http://{host}:8888"

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
                    'hls_url': f"{hls_base}/{name}/index.m3u8",
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
function escapeHtml(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML;}

function watchStream(name){
  var hlsUrl='/hls-proxy/'+encodeURIComponent(name)+'/index.m3u8';
  var w=1280,h=720,l=(screen.width-w)/2,t=(screen.height-h)/2;
  var popup=window.open('','streamViewer_'+name,
    'width='+w+',height='+h+',left='+l+',top='+t+',toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=no,resizable=yes');
  if(!popup){window.open('/watch/'+encodeURIComponent(name),'_blank');return;}
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
    +'var hls=new Hls({enableWorker:true,lowLatencyMode:false,maxBufferLength:30,maxMaxBufferLength:60,liveSyncDurationCount:4,liveMaxLatencyDurationCount:7});'
    +'hls.loadSource(url);hls.attachMedia(video);'
    +'hls.on(Hls.Events.MANIFEST_PARSED,function(){err.style.display="none";video.play().catch(function(){})});'
    +'hls.on(Hls.Events.ERROR,function(ev,data){if(data.fatal){err.style.display="flex";setTimeout(function(){hls.destroy();start()},5000)}});'
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
      html+='<button class="btn btn-watch" onclick="watchStream(\''+escapeHtml(name).replace(/'/g,"\\'")+'\')"><span style="font-size:16px">&#x25B6;&#xFE0F;</span> Watch</button>';
      html+='<button class="btn btn-share" onclick="shareStream(\''+escapeHtml(name).replace(/'/g,"\\'")+'\',\''+vis+'\',this)">&#x1F517; Share</button>';
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
    h += '<td><span class="role-badge ' + (isAdmin ? 'role-admin' : 'role-viewer') + '"' + (adminGroupPk ? ' onclick="toggleRole(this,\'' + u.pk + '\',' + isAdmin + ')"' : '') + '>' + (isAdmin ? 'Admin' : 'Viewer') + '</span></td>';
    h += '<td><span class="' + (u.is_active ? 'status-enabled' : 'status-disabled') + '">' + (u.is_active ? 'Enabled' : 'Disabled') + '</span></td>';
    h += '<td><div class="groups-cell">';
    for (const g of availableGroups) {
      const on = u.groups.includes(g);
      h += '<span class="gbadge ' + (on ? 'on' : 'off') + ' ' + g + '" onclick="toggleGroup(this,\'' + u.pk + '\',\'' + g + '\',' + on + ')">';
      h += '<span class="material-symbols-outlined">' + (on ? 'check_circle' : 'add_circle_outline') + '</span>' + g.replace('vid_','');
      h += '</span>';
    }
    h += '</div></td>';
    h += '<td><div class="actions">';
    h += '<button class="btn btn-edit" onclick="openEdit(\'' + u.pk + '\')">Edit</button>';
    if (u.is_active) {
      h += '<button class="btn btn-disable" onclick="toggleActive(\'' + u.pk + '\',false)">Disable</button>';
    } else {
      h += '<button class="btn btn-enable" onclick="toggleActive(\'' + u.pk + '\',true)">Enable</button>';
    }
    h += '<button class="btn btn-delete" onclick="openDelete(\'' + u.pk + '\')">Delete</button>';
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
function esc(s) { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

loadUsers();
</script>
</body>
</html>
'''
