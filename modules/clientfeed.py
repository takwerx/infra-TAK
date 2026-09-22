"""TAK Client Feed — publish connected TAK clients to outside consumers.

PLAN v10.1.77. infra-TAK hosts a read-only map feed of the ATAK/iTAK/WinTAK clients
connected to this TAK Server, so an outside agency can pull TAK situational awareness
onto its own map. Each consumer gets its OWN token, scoped to the TAK channels the
operator picks, revocable without touching any other consumer.

Two representations off one URL:
  * **ArcGIS REST FeatureServer** (`f=json`) — what Esri-spec consumers speak. Despite
    the name that is not an Esri-only club: Tablet Command, Intterra, First Due,
    WebEOC, QGIS and ArcGIS Pro all consume it.
  * **GeoJSON** (`f=geojson`) — for everything else: Leaflet, Mapbox, OpenLayers, or
    anything that can parse a FeatureCollection.

The module is deliberately NOT named after either protocol or any vendor. It is named
for what it publishes, so adding a third representation later does not make the name
a lie.

This is the mirror of the inbound integration the Node-RED Configurator already
ships: it polls Tablet Command's tokenized feature service
(`https://api.tabletcommand.com/esri/tc-file/<TOKEN>/FeatureServer`) and turns it
into CoT. Here we are the other end of the same pattern.

No Esri account is required anywhere in the chain — not ours, not the agency's.
Publishing into a customer's ArcGIS Online org is deliberately NOT a thing we do
(PLAN §5.0/§6): it would force every agency onto a paid AGOL org + OAuth app with
their credentials on our box, and round-trip unit positions through Esri's cloud
on CJIS-class deployments. A department that wants the layer inside their own org
adds our URL as a *referenced* item themselves — identical service, zero work here.

Data model (verified live on test6/test12 2026-09-16, PLAN §3.3):
  - `cot_router.groups` is a bit varying(32768); `public.groups` maps name -> bitpos.
    Channel scoping is ONE predicate: get_bit(groups, 32767 - bitpos) = 1.
    The bits are stored high-end first — Postgres get_bit() counts from the left
    and TAK's bitpos does not. Do not "simplify" this to get_bit(groups, bitpos).
  - A TAK client is cot_type 'a-f-G-U-C*' AND carries a <takv …> element in detail
    (platform / device / version — every TAK app stamps it: ATAK, iTAK, WinTAK,
    OpenTAK Tracker, TAK Aware, TAK Tracker, whatever comes next). The AVL/ADS-B/TFR
    feeds we INGEST land in cot_router too (a-f-G-E-S / u-d-f / t-x-d-d) and carry no
    takv — without the gate we would export Tablet Command's own engines straight back
    to Tablet Command. v10.1.79 (operator rule 2026-09-18): the gate is takv PRESENCE,
    not an allowlist of app names — the allowlist silently dropped every tracker.
    Surveyed test6/test12 (30 d) + CORAZ (90 min): zero a-f-G-U-C rows without takv.

This file imports NOTHING from app.py — every seam arrives through the ctx dict.
The PUBLIC token-authed route is NOT registered here: init_registry() wraps every
registry view in login_required with no opt-out (a deliberate v10.1.22 acceptance
check), so the public route lives in app.py behind @esri_token_required. Only the
authenticated admin CRUD is registered here.
"""
import os
import re
import json
import hmac
import hashlib
import secrets
import binascii
import threading
import math
from datetime import datetime, timezone

from . import register_module

STORE_NAME = 'clientfeed.json'

# Fleet-uniform constants — no per-customer knobs (CLAUDE.md fleet-uniform config).
DEFAULT_STALE_MINUTES = 5          # matches Tablet Command's own AVL stale concept
# The service name in the Esri layout (/feed/<token>/rest/services/<name>/FeatureServer).
# ArcGIS Online classifies a service from its URL before reading the payload and rejects the
# short /feed/<token>/FeatureServer form with 'This service type is not supported'
# (2026-09-17 on test6, 2026-09-18 on CORAZ with the URL the console itself handed out).
# Any name works server-side; this one is what AGOL shows as the layer name.
ESRI_SERVICE_NAME = 'TAKClients'
MAX_STALE_MINUTES = 60
SNAPSHOT_CACHE_TTL = 15            # seconds; N tokens on one channel set = 1 query
MAX_RECORD_COUNT = 2000
GROUPS_BITMAP_LEN = 32768          # TAK's cot_router.groups width

# Any TAK client on the channel is exported — the test is the <takv> element every TAK
# app stamps into its position report, NOT a list of app names. v10.1.77 shipped an
# ATAK/iTAK/WinTAK prefix allowlist that silently dropped every tracker: CORAZ had 5
# devices reporting platform="OpenTAK-Tracker-Android" (cot_type a-f-G-U-C, same as
# ATAK) and 3 ATAK-CIV, and ArcGIS showed 3 (2026-09-18). TAK Aware on test6/test12 was
# dropped the same way. Operator rule: "if it's a TAK client it shows up."
#
# The ONE exclusion is our own synthetic traffic: the TAK Simulator stamps
# <takv platform="infra-TAK" device="TAK Simulator"> on its simulated people so they look
# like clients to TAK Server — which is its job — but a training scenario must never land
# on a partner agency's map. Exact match on the platform string, upper-cased.
SYNTHETIC_PLATFORMS = ('INFRA-TAK',)

# CoT writes 9999999.0 into hae/ce/le when the value is UNKNOWN — it is a sentinel,
# not a measurement. Passing it through put a unit at 9,999,999 m in ArcGIS (observed
# 2026-09-17). Anything at or beyond this is "no altitude fix", which is null, not a
# number. Also guards the plain-wrong: Earth's deepest point is about -11 km and no
# EUD is above low orbit.
COT_UNKNOWN = 9999999.0
ALT_MIN_M = -12000.0
ALT_MAX_M = 100000.0

# Degenerate extents break client zoom: a single client (or several at one spot) makes
# xmin == xmax, and ArcGIS cannot zoom to a zero-area box. Pad it to something a map
# can actually frame — ~550 m at the equator.
EXTENT_PAD_DEG = 0.005

# Channels never offered in the picker — TAK internals, not operational channels.
HIDDEN_CHANNELS = ('ROLE_ADMIN', '__ANON__')

_snapshot_cache = {}   # (bitpos tuple, stale_minutes) -> (epoch, [features])

# EVERY mutation of the token store goes through this lock. A full-file
# read-modify-write is destructive (CLAUDE.md, the TAK Portal settings.json saga):
# a pull landing mid-mint would drop the new token on the floor. gunicorn runs one
# worker with four threads, so a process-level lock covers every writer there is.
_STORE_LOCK = threading.Lock()
_pull_stats = {}        # token id -> {'ts','ip','count'} — flushed, not written per-pull
_last_stat_flush = [0.0]
PULL_STAT_FLUSH_SECS = 60


# ── token store ───────────────────────────────────────────────────────────────

def _store_path(ctx):
    return os.path.join(ctx['CONFIG_DIR'], STORE_NAME)


def _blank_store():
    return {'version': 1, 'salt': secrets.token_hex(32), 'tokens': []}


def _load_store(ctx):
    p = _store_path(ctx)
    if not os.path.exists(p):
        return _blank_store()
    try:
        with open(p) as f:
            s = json.load(f)
    except Exception:
        return _blank_store()
    if not isinstance(s, dict) or not isinstance(s.get('tokens'), list):
        return _blank_store()
    s.setdefault('salt', secrets.token_hex(32))
    return s


def _save_store(ctx, store):
    p = _store_path(ctx)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(store, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def _hash_token(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def mint_token(ctx, label, channels, stale_minutes=DEFAULT_STALE_MINUTES):
    """Create a token. Returns (entry, secret) — the secret is shown ONCE and is
    never recoverable afterwards (only its SHA-256 is stored)."""
    secret = secrets.token_urlsafe(32)
    entry = {
        'id': 'tok_' + secrets.token_hex(4),
        'label': (label or '').strip()[:120] or 'Unnamed',
        'token_hash': _hash_token(secret),
        'channels': list(channels or []),
        'stale_minutes': max(1, min(int(stale_minutes or DEFAULT_STALE_MINUTES),
                                    MAX_STALE_MINUTES)),
        'created_ts': _now_iso(),
        'enabled': True,
        'last_pull_ts': None,
        'last_pull_ip': None,
        'pull_count': 0,
        'allow_ips': [],          # reserved (PLAN §4-W8); unset in v10.1.76
    }
    with _STORE_LOCK:
        store = _load_store(ctx)
        store['tokens'].append(entry)
        _save_store(ctx, store)
    return entry, secret


def revoke_token(ctx, token_id):
    with _STORE_LOCK:
        store = _load_store(ctx)
        before = len(store['tokens'])
        store['tokens'] = [t for t in store['tokens'] if t.get('id') != token_id]
        if len(store['tokens']) == before:
            return False
        _save_store(ctx, store)
    _pull_stats.pop(token_id, None)
    return True


def set_token_enabled(ctx, token_id, enabled):
    with _STORE_LOCK:
        store = _load_store(ctx)
        for t in store['tokens']:
            if t.get('id') == token_id:
                t['enabled'] = bool(enabled)
                _save_store(ctx, store)
                return True
    return False


def update_token(ctx, token_id, label=None, channels=None, stale_minutes=None):
    with _STORE_LOCK:
        store = _load_store(ctx)
        for t in store['tokens']:
            if t.get('id') != token_id:
                continue
            if label is not None:
                t['label'] = str(label).strip()[:120] or t['label']
            if channels is not None:
                t['channels'] = list(channels)
            if stale_minutes is not None:
                t['stale_minutes'] = max(1, min(int(stale_minutes), MAX_STALE_MINUTES))
            _save_store(ctx, store)
            return True
    return False


def rotate_token(ctx, token_id):
    """Issue a NEW secret for an existing token, keeping its label, channels and
    settings. Returns (entry, secret) or (None, None).

    This exists because the alternative — revoke and re-mint — loses the agency's
    label, channel scoping and stale window, and makes the operator rebuild a
    consumer that was only ever asking for a fresh credential. Rotation is the
    normal lifecycle event (a leaked URL, a staff change, a policy interval); a
    teardown should not be the only way to get one.

    The OLD secret stops working the instant this returns: its hash is replaced,
    and resolve_token() compares against hashes only.
    """
    secret = secrets.token_urlsafe(32)
    with _STORE_LOCK:
        store = _load_store(ctx)
        for t in store['tokens']:
            if t.get('id') != token_id:
                continue
            t['token_hash'] = _hash_token(secret)
            t['rotated_ts'] = _now_iso()
            t['rotations'] = int(t.get('rotations') or 0) + 1
            _save_store(ctx, store)
            return t, secret
    return None, None


def resolve_token(ctx, presented):
    """Presented secret -> token entry, or None. Constant-time compare against
    every stored hash (no early return on the first mismatch)."""
    if not presented or len(presented) > 200:
        return None
    want = _hash_token(presented)
    found = None
    for t in _load_store(ctx)['tokens']:
        if hmac.compare_digest(str(t.get('token_hash') or ''), want):
            found = t
    if found is None or not found.get('enabled', True):
        return None
    return found


def record_pull(ctx, token_id, ip):
    """Pull accounting for the UI. Counts live in memory and are flushed to the
    store at most once a minute — a consumer polling every 60s must not rewrite the
    token store on every request, and must never race a mint or a revoke. Never
    raises: accounting is never worth failing a customer's feed over."""
    try:
        st = _pull_stats.setdefault(token_id, {'ts': None, 'ip': None, 'count': 0})
        st['ts'] = _now_iso()
        st['ip'] = (ip or '')[:64]
        st['count'] += 1

        now = datetime.now(timezone.utc).timestamp()
        if (now - _last_stat_flush[0]) < PULL_STAT_FLUSH_SECS:
            return
        _last_stat_flush[0] = now
        _flush_pull_stats(ctx)
    except Exception:
        pass


def _flush_pull_stats(ctx):
    """Fold the in-memory counters into the store under the lock. Never raises."""
    try:
        with _STORE_LOCK:
            store = _load_store(ctx)
            dirty = False
            for t in store['tokens']:
                st = _pull_stats.get(t.get('id'))
                if not st or not st['count']:
                    continue
                t['last_pull_ts'] = st['ts']
                t['last_pull_ip'] = st['ip']
                t['pull_count'] = int(t.get('pull_count') or 0) + st['count']
                st['count'] = 0
                dirty = True
            if dirty:
                _save_store(ctx, store)
    except Exception:
        pass


def merge_pull_stats(entry):
    """Stored counters + the unflushed in-memory delta, for the UI. A feed that
    was pulled 20 seconds ago must show that, not 'never'."""
    st = _pull_stats.get(entry.get('id'))
    if not st:
        return entry.get('last_pull_ts'), entry.get('last_pull_ip'), int(entry.get('pull_count') or 0)
    return (st['ts'] or entry.get('last_pull_ts'),
            st['ip'] or entry.get('last_pull_ip'),
            int(entry.get('pull_count') or 0) + int(st['count'] or 0))


def _client_id(store, uid):
    """Opaque, stable per-install device id. Per-INSTALL salt (not per-token) so
    mutual-aid partners pulling two feeds still see one unit as one unit."""
    return hmac.new(store['salt'].encode(), uid.encode(), hashlib.sha256).hexdigest()[:16]


def _objectid(client_id):
    """Esri clients key feature identity on OBJECTID, so it must be STABLE across
    polls — never a per-snapshot row number."""
    return binascii.crc32(client_id.encode()) & 0x7FFFFFFF


# ── TAK channel resolution ────────────────────────────────────────────────────

def list_channels(ctx):
    """[{name, bitpos}] from TAK's groups table. Fixed SQL, no interpolation.

    Raises RuntimeError when the database cannot be queried. v10.1.77 returned []
    on any failure, so a split box or a managed-DB box (RDS / Azure) rendered
    "No TAK channels found - is TAK Server running?" while TAK Server was up and
    serving from a database this module simply could not reach (CORAZ, 2026-09-18).
    An empty list now means exactly one thing: the groups table has no channels."""
    r = ctx['_cot_pg_exec'](['psql', 'cot', '-tAF', '\t', '-c',
                             "SELECT name, bitpos FROM groups WHERE type = 1 ORDER BY name;"],
                            timeout=15)
    if r.returncode != 0:
        raise RuntimeError(((r.stderr or r.stdout or '').strip()
                            or 'psql exited %s' % r.returncode)[:300])
    out = []
    for line in (r.stdout or '').strip().splitlines():
        if '\t' not in line:
            continue
        name, _, bp = line.partition('\t')
        try:
            bitpos = int(bp)
        except ValueError:
            continue
        if name.strip().upper() in HIDDEN_CHANNELS:
            continue
        out.append({'name': name.strip(), 'bitpos': bitpos})
    return out


def _resolve_bitpos(ctx, channel_names):
    """Channel NAMES -> integer bit positions. Names that no longer resolve are
    returned separately so the UI can show the token amber — a vanished channel
    must never silently widen a token's scope."""
    have = {c['name']: c['bitpos'] for c in list_channels(ctx)}
    bits, missing = [], []
    for n in channel_names or []:
        if n in have:
            bits.append(int(have[n]))
        else:
            missing.append(n)
    return bits, missing


# ── snapshot ──────────────────────────────────────────────────────────────────

_RE_GROUP = re.compile(r'<__group\b[^>]*\bname="([^"]*)"', re.I)
_RE_ROLE = re.compile(r'<__group\b[^>]*\brole="([^"]*)"', re.I)
_RE_BATTERY = re.compile(r'<status\b[^>]*\bbattery="(\d+)"', re.I)
_RE_PLATFORM = re.compile(r'<takv\b[^>]*\bplatform="([^"]*)"', re.I)
_RE_DEVICE = re.compile(r'<takv\b[^>]*\bdevice="([^"]*)"', re.I)
_RE_VERSION = re.compile(r'<takv\b[^>]*\bversion="([^"]*)"', re.I)
_RE_CALLSIGN = re.compile(r'<contact\b[^>]*\bcallsign="([^"]*)"', re.I)


def _clean_alt(hae):
    """CoT altitude -> metres, or None when it is the unknown sentinel or absurd."""
    try:
        v = float(hae)
    except (TypeError, ValueError):
        return None
    if abs(v) >= COT_UNKNOWN or not (ALT_MIN_M <= v <= ALT_MAX_M):
        return None
    return round(v, 1)


_RE_TAKV = re.compile(r'<takv\b', re.I)


def _is_tak_client(detail, platform):
    """True for anything that is a TAK client: the position report carries a <takv>
    element. No app-name allowlist (see SYNTHETIC_PLATFORMS for why, and for the one
    exclusion). A feed we ingest has no takv and fails here."""
    if not _RE_TAKV.search(detail or ''):
        return False
    return (platform or '').upper().strip() not in SYNTHETIC_PLATFORMS


def snapshot(ctx, bitpos_list, stale_minutes, channel_names=None):
    """Latest position per connected ATAK client in the given channels.

    SECURITY: _cot_pg_exec's invariant is that no attacker-controlled SQL reaches it.
    Everything interpolated below is an int() we produced — bit positions read
    from TAK's own groups table, and a clamped stale window. Channel NAMES are
    resolved to integers in Python and never touch the SQL string.
    """
    bits = sorted({int(b) for b in bitpos_list})
    mins = max(1, min(int(stale_minutes), MAX_STALE_MINUTES))
    if not bits:
        return []

    key = (tuple(bits), mins)
    now = datetime.now(timezone.utc).timestamp()
    hit = _snapshot_cache.get(key)
    if hit and (now - hit[0]) < SNAPSHOT_CACHE_TTL:
        rows = hit[1]
    else:
        # get_bit() counts from the LEFT; TAK's bitpos does not. See module header.
        pred = ' OR '.join('get_bit(groups, %d) = 1' % (GROUPS_BITMAP_LEN - 1 - b)
                           for b in bits)
        sql = (
            "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)::text FROM ("
            "  SELECT DISTINCT ON (uid) uid, cot_type,"
            "         extract(epoch FROM servertime)::bigint AS ts,"
            "         ST_Y(event_pt) AS lat, ST_X(event_pt) AS lon,"
            "         point_hae AS hae, detail"
            "  FROM cot_router"
            "  WHERE cot_type LIKE 'a-f-G-U-C%%'"
            "    AND event_pt IS NOT NULL"
            "    AND servertime > now() - interval '%d minutes'"
            "    AND (%s)"
            "  ORDER BY uid, servertime DESC"
            ") t;" % (mins, pred)
        )
        r = ctx['_cot_pg_exec'](['psql', 'cot', '-tA', '-c', sql], timeout=20)
        if r.returncode != 0:
            raise RuntimeError(((r.stderr or r.stdout or '').strip()
                                or 'psql exited %s' % r.returncode)[:300])
        try:
            rows = json.loads((r.stdout or '').strip() or '[]')
        except Exception:
            return []
        _snapshot_cache[key] = (now, rows)

    store = _load_store(ctx)
    chan_label = ', '.join(channel_names or [])
    feats = []
    for row in rows:
        detail = row.get('detail') or ''
        m = _RE_PLATFORM.search(detail)
        platform = m.group(1) if m else ''
        if not _is_tak_client(detail, platform):
            continue     # feeds/services/simulator are never exported (see header)
        uid = row.get('uid') or ''
        cid = _client_id(store, uid)
        m = _RE_CALLSIGN.search(detail)
        callsign = m.group(1) if m else uid[:32]
        m = _RE_GROUP.search(detail)
        team = m.group(1) if m else ''
        m = _RE_ROLE.search(detail)
        role = m.group(1) if m else ''
        m = _RE_BATTERY.search(detail)
        battery = int(m.group(1)) if m else None
        m = _RE_DEVICE.search(detail)
        device = m.group(1) if m else ''
        m = _RE_VERSION.search(detail)
        version = m.group(1) if m else ''
        ts = int(row.get('ts') or 0)
        feats.append({
            'OBJECTID': _objectid(cid),
            'client_id': cid,
            'callsign': callsign,
            'radioName': callsign,          # Tablet Command vocabulary (PLAN §5.0)
            'team': team,
            'role': role,
            'cot_type': row.get('cot_type') or '',
            'platform': platform,
            'deviceType': device or platform,   # Tablet Command vocabulary
            'takVersion': version,
            'battery': battery,
            'altitude': _clean_alt(row.get('hae')),
            'channel': chan_label,
            'last_update': ts * 1000,       # Esri dates are epoch MILLISECONDS
            'age_seconds': max(0, int(now) - ts),
            '_lat': row.get('lat'),
            '_lon': row.get('lon'),
        })
    return feats


# ── ArcGIS REST shapes ────────────────────────────────────────────────────────

FIELDS = [
    ('OBJECTID',    'esriFieldTypeOID',     'OBJECTID',     None),
    ('client_id',   'esriFieldTypeString',  'Client ID',    64),
    ('callsign',    'esriFieldTypeString',  'Callsign',     128),
    ('radioName',   'esriFieldTypeString',  'Radio Name',   128),
    ('team',        'esriFieldTypeString',  'Team',         32),
    ('role',        'esriFieldTypeString',  'Role',         64),
    ('cot_type',    'esriFieldTypeString',  'CoT Type',     32),
    ('platform',    'esriFieldTypeString',  'Platform',     32),
    ('deviceType',  'esriFieldTypeString',  'Device Type',  64),
    ('takVersion',  'esriFieldTypeString',  'TAK Version',  64),
    ('battery',     'esriFieldTypeInteger', 'Battery %',    None),
    ('altitude',    'esriFieldTypeDouble',  'Altitude (m)', None),
    ('channel',     'esriFieldTypeString',  'TAK Channel',  255),
    ('last_update', 'esriFieldTypeDate',    'Last Update',  None),
    ('age_seconds', 'esriFieldTypeInteger', 'Age (s)',      None),
]

SR = {'wkid': 4326, 'latestWkid': 4326}
SR_WEBMERC = {'wkid': 102100, 'latestWkid': 3857}

# ArcGIS map clients ask for geometry in the MAP's spatial reference via outSR, and
# ArcGIS Online's viewer asks for Web Mercator. We were ignoring outSR and always
# answering in degrees while telling the client it was getting what it asked for — so
# AGOL plotted -117.57, 33.84 as METRES and put the unit on Null Island (observed
# 2026-09-17). Honour the two references that matter; anything else gets 4326, which is
# what we actually have, declared honestly.
WEBMERC_R = 20037508.342789244
WEBMERC_LAT_LIMIT = 85.05112878


def _webmerc(lon, lat):
    """EPSG:4326 -> EPSG:3857/102100. Latitude clamps at the Mercator pole limit."""
    lat = max(min(float(lat), WEBMERC_LAT_LIMIT), -WEBMERC_LAT_LIMIT)
    x = float(lon) * WEBMERC_R / 180.0
    y = math.log(math.tan((90.0 + lat) * math.pi / 360.0)) / (math.pi / 180.0)
    return round(x, 3), round(y * WEBMERC_R / 180.0, 3)


def _resolve_out_sr(params):
    """(spatialReference dict, project?) for the requested outSR.

    outSR arrives either bare ('102100') or as JSON ({"wkid":102100}), depending on
    the client."""
    raw = str(params.get('outSR') or '').strip()
    if not raw:
        return SR, False
    wkid = None
    if raw.startswith('{'):
        try:
            wkid = (json.loads(raw) or {}).get('latestWkid') or (json.loads(raw) or {}).get('wkid')
        except Exception:
            wkid = None
    else:
        try:
            wkid = int(raw)
        except ValueError:
            wkid = None
    if wkid in (102100, 3857, 900913, 102113):
        return SR_WEBMERC, True
    return SR, False


def _fields_json():
    out = []
    for name, ftype, alias, length in FIELDS:
        f = {'name': name, 'type': ftype, 'alias': alias,
             'nullable': name != 'OBJECTID', 'editable': False,
             'domain': None, 'defaultValue': None}
        if length:
            f['length'] = length
        out.append(f)
    return out


def _extent(feats=None):
    """Bounding box of the current clients, padded so it is never zero-area.

    A feed with one client — the normal case for a small agency — produced
    xmin == xmax == the unit's longitude, and ArcGIS cannot frame a box with no area.
    Falls back to the whole world only when there is genuinely nothing to show."""
    pts = [(f['_lon'], f['_lat']) for f in (feats or [])
           if f.get('_lat') is not None and f.get('_lon') is not None]
    if not pts:
        return {'xmin': -180, 'ymin': -90, 'xmax': 180, 'ymax': 90, 'spatialReference': SR}
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    xmin, xmax, ymin, ymax = min(xs), max(xs), min(ys), max(ys)
    if xmax - xmin < EXTENT_PAD_DEG:
        xmin, xmax = xmin - EXTENT_PAD_DEG, xmax + EXTENT_PAD_DEG
    if ymax - ymin < EXTENT_PAD_DEG:
        ymin, ymax = ymin - EXTENT_PAD_DEG, ymax + EXTENT_PAD_DEG
    return {'xmin': round(xmin, 6), 'ymin': round(ymin, 6),
            'xmax': round(xmax, 6), 'ymax': round(ymax, 6), 'spatialReference': SR}


def service_json(entry, feats=None):
    return {
        'currentVersion': 11.2,
        'serviceDescription': 'Connected TAK clients published by infra-TAK',
        'hasVersionedData': False,
        'supportsDisconnectedEditing': False,
        'hasStaticData': False,
        'maxRecordCount': MAX_RECORD_COUNT,
        'supportedQueryFormats': 'JSON',
        'capabilities': 'Query',
        'description': 'Read-only live positions of TAK clients (%s).'
                       % (', '.join(entry.get('channels') or []) or 'no channels'),
        'copyrightText': '',
        'spatialReference': SR,
        'initialExtent': _extent(feats),
        'fullExtent': _extent(feats),
        'allowGeometryUpdates': False,
        'units': 'esriDecimalDegrees',
        'syncEnabled': False,
        'layers': [{'id': 0, 'name': 'TAK Clients', 'parentLayerId': -1,
                    'defaultVisibility': True, 'subLayerIds': None,
                    'minScale': 0, 'maxScale': 0,
                    'type': 'Feature Layer', 'geometryType': 'esriGeometryPoint'}],
        'tables': [],
    }


def layer_json(entry, feats=None):
    return {
        'currentVersion': 11.2,
        'id': 0,
        'name': 'TAK Clients',
        'type': 'Feature Layer',
        'description': 'Live positions of ATAK/iTAK/WinTAK clients connected to TAK Server.',
        'geometryType': 'esriGeometryPoint',
        'sourceSpatialReference': SR,
        'copyrightText': '',
        'defaultVisibility': True,
        'isDataVersioned': False,
        'hasContingentValuesDefinition': False,
        'supportsAppend': False,
        'supportsCalculate': False,
        'supportsRollbackOnFailureParameter': False,
        'hasGeometryProperties': True,
        'hasAttachments': False,
        'htmlPopupType': 'esriServerHTMLPopupTypeNone',
        'displayField': 'callsign',
        'typeIdField': None,
        'fields': _fields_json(),
        'objectIdField': 'OBJECTID',
        'uniqueIdField': {'name': 'OBJECTID', 'isSystemMaintained': True},
        'globalIdField': '',
        'types': [],
        'templates': [],
        'capabilities': 'Query',
        'maxRecordCount': MAX_RECORD_COUNT,
        'standardMaxRecordCount': MAX_RECORD_COUNT,
        'tileMaxRecordCount': MAX_RECORD_COUNT,
        'maxRecordCountFactor': 1,
        'supportedQueryFormats': 'JSON, geoJSON',
        'minScale': 0,
        'maxScale': 0,
        'extent': _extent(feats),
        'drawingInfo': {
            'renderer': {
                'type': 'simple',
                'symbol': {'type': 'esriSMS', 'style': 'esriSMSCircle',
                           'color': [46, 196, 182, 255], 'size': 8,
                           'outline': {'color': [255, 255, 255, 255], 'width': 1}},
                'label': '', 'description': '',
            },
            'transparency': 0,
            'labelingInfo': None,
        },
    }


def _wanted_fields(out_fields):
    names = [f[0] for f in FIELDS]
    if not out_fields or out_fields.strip() in ('*', ''):
        return names
    want = [s.strip() for s in out_fields.split(',') if s.strip()]
    keep = [n for n in names if n in want or n == 'OBJECTID']
    return keep or names


def query_json(entry, feats, params):
    """ArcGIS /query response.

    `where` is parsed only to be IGNORED. The answer is always exactly the
    token's own scope — a client-supplied predicate can never widen it, and no
    request string ever reaches SQL. That is deliberate: it removes the injection
    surface instead of trying to sanitize it (PLAN §4-W4).
    """
    if str(params.get('returnCountOnly', '')).lower() in ('true', '1'):
        return {'count': len(feats)}

    keep = _wanted_fields(params.get('outFields') or '*')
    want_geom = str(params.get('returnGeometry', 'true')).lower() not in ('false', '0')
    try:
        limit = int(params.get('resultRecordCount') or MAX_RECORD_COUNT)
    except (TypeError, ValueError):
        limit = MAX_RECORD_COUNT
    limit = max(1, min(limit, MAX_RECORD_COUNT))

    out_sr, project = _resolve_out_sr(params)
    out = []
    for f in feats[:limit]:
        item = {'attributes': {k: f.get(k) for k in keep}}
        if want_geom and f.get('_lat') is not None and f.get('_lon') is not None:
            if project:
                x, y = _webmerc(f['_lon'], f['_lat'])
            else:
                x, y = f['_lon'], f['_lat']
            item['geometry'] = {'x': x, 'y': y, 'spatialReference': out_sr}
        out.append(item)

    return {
        'objectIdFieldName': 'OBJECTID',
        'uniqueIdField': {'name': 'OBJECTID', 'isSystemMaintained': True},
        'globalIdFieldName': '',
        'geometryType': 'esriGeometryPoint',
        'spatialReference': out_sr,
        'hasZ': False,
        'hasM': False,
        'fields': [f for f in _fields_json() if f['name'] in keep],
        'features': out,
        'exceededTransferLimit': len(feats) > limit,
    }


def geojson_response(entry, feats, params):
    """RFC 7946 FeatureCollection — the representation for consumers that do not
    speak the ArcGIS REST spec (Leaflet, Mapbox, OpenLayers, plain HTTP clients).

    RFC 7946 mandates WGS84, so outSR is deliberately NOT honoured here: reprojecting
    would produce a GeoJSON document that lies about its own coordinates."""
    keep = _wanted_fields(params.get('outFields') or '*')
    want_geom = str(params.get('returnGeometry', 'true')).lower() not in ('false', '0')
    try:
        limit = int(params.get('resultRecordCount') or MAX_RECORD_COUNT)
    except (TypeError, ValueError):
        limit = MAX_RECORD_COUNT
    limit = max(1, min(limit, MAX_RECORD_COUNT))

    out = []
    for f in feats[:limit]:
        geom = None
        if want_geom and f.get('_lat') is not None and f.get('_lon') is not None:
            geom = {'type': 'Point', 'coordinates': [f['_lon'], f['_lat']]}
        out.append({'type': 'Feature', 'id': f.get('OBJECTID'),
                    'geometry': geom,
                    'properties': {k: f.get(k) for k in keep if k != 'OBJECTID'}})
    return {'type': 'FeatureCollection', 'features': out}


def query_response(entry, feats, params):
    """Dispatch on `f`. Esri JSON is the default because that is what the spec-
    compliant consumers request by name; geojson is opt-in."""
    fmt = str(params.get('f') or 'json').strip().lower()
    if fmt == 'geojson':
        return geojson_response(entry, feats, params)
    return query_json(entry, feats, params)


def esri_error(code, message, details=''):
    return {'error': {'code': code, 'message': message,
                      'details': [details] if details else []}}


# ── lifecycle ─────────────────────────────────────────────────────────────────

def detect(ctx):
    """Installed once the token store exists. 'running' means the feed can
    actually answer — TAK Server present and the cot DB reachable."""
    installed = os.path.exists(_store_path(ctx))
    running = False
    tokens = 0
    if installed:
        try:
            tokens = len(_load_store(ctx)['tokens'])
        except Exception:
            tokens = 0
        try:
            r = ctx['_cot_pg_exec'](['psql', 'cot', '-tAc', 'SELECT 1'], timeout=8)
            running = (r.returncode == 0)
        except Exception:
            running = False
    return {'installed': installed, 'running': running, 'tokens': tokens}


def deploy(ctx, job, params):
    from . import job_log
    key = 'clientfeed'

    def plog(m):
        job_log(key, m)

    try:
        plog('Enabling TAK Client Feed…')
        if not os.path.isdir('/opt/tak') and not os.path.exists('/opt/tak'):
            plog('⚠ TAK Server not detected on this host — the feed will return '
                 'no features until TAK Server is installed.')
        # v10.1.85: a split / managed-DB console has no local postgres and, unless
        # something unrelated installed one, no psql client either (NC TAK, 2026-09-21).
        # Put it on the box here, in the deploy log, instead of failing at the first mint.
        try:
            if ctx['_tak_db_topology']()[0] == 'remote':
                if not ctx['_ensure_psql_client'](log_fn=plog, timeout=600):
                    plog('   ⚠ remote cot database and no PostgreSQL client could be installed — '
                         'channels will not resolve until one is present')
        except Exception as e:
            plog('   ⚠ psql client check failed: %s' % str(e)[:160])
        r = ctx['_cot_pg_exec'](['psql', 'cot', '-tAc', 'SELECT count(*) FROM groups'], timeout=10)
        if r.returncode == 0:
            plog('   ✓ cot DB reachable — %s channels visible' % (r.stdout or '').strip())
        else:
            plog('   ⚠ cot DB not reachable yet: %s'
                 % ((r.stderr or '')[:160] or 'unknown error'))

        if not os.path.exists(_store_path(ctx)):
            _save_store(ctx, _blank_store())
            plog('   ✓ token store created (0600)')
        else:
            plog('   ✓ token store already present — left untouched')

        plog('Regenerating Caddy config so /feed/* is reachable on 443…')
        try:
            ctx['generate_caddyfile']()
            ctx['_caddy_reload']()
            plog('   ✓ Caddy reloaded')
        except Exception as e:
            plog('   ⚠ Caddy regen/reload failed: %s' % str(e)[:160])

        plog('Arming the fail2ban jail for rejected tokens…')
        try:
            ok, msg = ctx['_f2b_arm_clientfeed_jail'](plog)
            plog(('   ✓ ' if ok else '   ⚠ ') + msg)
        except Exception as e:
            plog('   ⚠ jail setup error: %s' % str(e)[:160])

        plog('')
        plog('✅ TAK Client Feed ready. Mint a token to hand an agency a URL.')
        plog('   No new port was opened — the feed rides the existing Caddy 443 listener.')
        return True
    except Exception as e:
        plog('❌ Deploy failed: %s' % str(e)[:300])
        return False


def uninstall(ctx, job, params):
    from . import job_log
    key = 'clientfeed'

    def plog(m):
        job_log(key, m)

    try:
        plog('Removing TAK Client Feed…')
        p = _store_path(ctx)
        if os.path.exists(p):
            n = len(_load_store(ctx)['tokens'])
            os.remove(p)
            plog('   ✓ token store removed — %d token(s) revoked' % n)
        else:
            plog('   • no token store present')
        _snapshot_cache.clear()
        _pull_stats.clear()
        try:
            ok, msg = ctx['_f2b_disarm_clientfeed_jail']()
            plog(('   ✓ ' if ok else '   ⚠ ') + msg)
        except Exception as e:
            plog('   ⚠ jail removal error: %s' % str(e)[:160])
        try:
            ctx['generate_caddyfile']()
            ctx['_caddy_reload']()
            plog('   ✓ Caddy regenerated — /feed/* no longer served')
        except Exception as e:
            plog('   ⚠ Caddy regen failed: %s' % str(e)[:160])
        plog('✅ TAK Client Feed removed.')
        return True
    except Exception as e:
        plog('❌ Uninstall failed: %s' % str(e)[:300])
        return False


# ── registration ──────────────────────────────────────────────────────────────

def register(ctx):
    from flask import request, jsonify

    def channels_view():
        try:
            return jsonify({'success': True, 'channels': list_channels(ctx)})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)[:200], 'channels': []})

    def tokens_view():
        store = _load_store(ctx)
        try:
            known = {c['name'] for c in list_channels(ctx)}
        except RuntimeError:
            known = None    # DB unreachable: unknown is not the same as vanished
        out = []
        for t in store['tokens']:
            missing = [c for c in (t.get('channels') or [])
                       if known is not None and c not in known]
            _lp_ts, _lp_ip, _lp_n = merge_pull_stats(t)
            out.append({
                'id': t.get('id'), 'label': t.get('label'),
                'channels': t.get('channels') or [],
                'missing_channels': missing,
                'stale_minutes': t.get('stale_minutes'),
                'created_ts': t.get('created_ts'), 'enabled': t.get('enabled', True),
                'last_pull_ts': _lp_ts, 'last_pull_ip': _lp_ip,
                'pull_count': _lp_n,
                'rotated_ts': t.get('rotated_ts'),
                'rotations': int(t.get('rotations') or 0),
            })
        return jsonify({'success': True, 'tokens': out})

    def mint_view():
        d = request.get_json(silent=True) or {}
        label = (d.get('label') or '').strip()
        channels = d.get('channels') or []
        if not label:
            return jsonify({'success': False, 'error': 'A label is required'}), 400
        if not isinstance(channels, list) or not channels:
            return jsonify({'success': False, 'error': 'Pick at least one channel'}), 400
        known = {c['name'] for c in list_channels(ctx)}
        bad = [c for c in channels if c not in known]
        if bad:
            return jsonify({'success': False,
                            'error': 'Unknown channel(s): %s' % ', '.join(bad[:5])}), 400
        entry, secret = mint_token(ctx, label, channels, d.get('stale_minutes'))
        ctx['audit']('clientfeed_token_mint',
                     'label=%s channels=%s' % (entry['label'], ','.join(channels)),
                     force=True)
        return jsonify({'success': True, 'id': entry['id'], 'token': secret,
                        'path': '/feed/%s/FeatureServer' % secret,
                        'esri_path': '/feed/%s/rest/services/%s/FeatureServer' % (secret, ESRI_SERVICE_NAME)})

    def revoke_view():
        d = request.get_json(silent=True) or {}
        tid = d.get('id')
        store = _load_store(ctx)
        label = next((t.get('label') for t in store['tokens'] if t.get('id') == tid), tid)
        if not revoke_token(ctx, tid):
            return jsonify({'success': False, 'error': 'No such token'}), 404
        ctx['audit']('clientfeed_token_revoke', 'label=%s id=%s' % (label, tid), force=True)
        return jsonify({'success': True})

    def toggle_view():
        d = request.get_json(silent=True) or {}
        tid, on = d.get('id'), bool(d.get('enabled'))
        if not set_token_enabled(ctx, tid, on):
            return jsonify({'success': False, 'error': 'No such token'}), 404
        ctx['audit']('clientfeed_token_%s' % ('enable' if on else 'disable'), 'id=%s' % tid,
                     force=True)
        return jsonify({'success': True})

    def edit_view():
        d = request.get_json(silent=True) or {}
        tid = d.get('id')
        channels = d.get('channels')
        if channels is not None:
            known = {c['name'] for c in list_channels(ctx)}
            bad = [c for c in channels if c not in known]
            if bad:
                return jsonify({'success': False,
                                'error': 'Unknown channel(s): %s' % ', '.join(bad[:5])}), 400
        if not update_token(ctx, tid, d.get('label'), channels, d.get('stale_minutes')):
            return jsonify({'success': False, 'error': 'No such token'}), 404
        ctx['audit']('clientfeed_token_edit', 'id=%s' % tid, force=True)
        return jsonify({'success': True})

    def rotate_view():
        d = request.get_json(silent=True) or {}
        tid = d.get('id')
        entry, secret = rotate_token(ctx, tid)
        if not entry:
            return jsonify({'success': False, 'error': 'No such token'}), 404
        ctx['audit']('clientfeed_token_rotate',
                     'label=%s id=%s rotations=%s' % (entry.get('label'), tid,
                                                      entry.get('rotations')),
                     force=True)
        return jsonify({'success': True, 'id': entry['id'], 'token': secret,
                        'path': '/feed/%s/FeatureServer' % secret,
                        'esri_path': '/feed/%s/rest/services/%s/FeatureServer' % (secret, ESRI_SERVICE_NAME)})

    def preview_view():
        """What a given token currently returns — so the operator can see the
        exact payload BEFORE sending the URL to an agency."""
        d = request.get_json(silent=True) or {}
        tid = d.get('id')
        entry = next((t for t in _load_store(ctx)['tokens'] if t.get('id') == tid), None)
        if not entry:
            return jsonify({'success': False, 'error': 'No such token'}), 404
        try:
            bits, missing = _resolve_bitpos(ctx, entry.get('channels'))
            feats = snapshot(ctx, bits, entry.get('stale_minutes') or DEFAULT_STALE_MINUTES,
                             entry.get('channels'))
        except RuntimeError as e:
            return jsonify({'success': False,
                            'error': 'cot database unavailable: %s' % str(e)[:200]}), 503
        return jsonify({'success': True, 'count': len(feats),
                        'missing_channels': missing,
                        'sample': query_json(entry, feats[:5], {})})

    register_module({
        'key': 'clientfeed',
        'name': 'TAK Client Feed',
        'description': 'Publish connected TAK clients to outside agencies as a map feed',
        'icon': '🛰️',
        # The ATAK team "skittle" — the circle a TAK client renders as on the map,
        # tinted Cyan, which is ATAK's own default team colour
        # (call_sign_preference.xml: locationTeam android:defaultValue="Cyan").
        # Source asset: TAK-Product-Center/atak-civ, GPL-3.0 — see static/logos/ATTRIBUTION.md.
        'icon_url': '/static/logos/tak-client-skittle.png',
        'route': '/clientfeed',
        'template': 'clientfeed.html',
        'priority': 14,
        'detect': detect,
        'deploy': deploy,
        'uninstall': uninstall,
        'control_map': {},          # nothing to start/stop — it is a route, not a service
        'extra_routes': [
            {'url': '/api/clientfeed/channels', 'methods': ['GET'],
             'endpoint': 'clientfeed_channels', 'view': channels_view},
            {'url': '/api/clientfeed/tokens', 'methods': ['GET'],
             'endpoint': 'clientfeed_tokens', 'view': tokens_view},
            {'url': '/api/clientfeed/tokens/mint', 'methods': ['POST'],
             'endpoint': 'clientfeed_mint', 'view': mint_view},
            {'url': '/api/clientfeed/tokens/revoke', 'methods': ['POST'],
             'endpoint': 'clientfeed_revoke', 'view': revoke_view},
            {'url': '/api/clientfeed/tokens/toggle', 'methods': ['POST'],
             'endpoint': 'clientfeed_toggle', 'view': toggle_view},
            {'url': '/api/clientfeed/tokens/edit', 'methods': ['POST'],
             'endpoint': 'clientfeed_edit', 'view': edit_view},
            {'url': '/api/clientfeed/tokens/rotate', 'methods': ['POST'],
             'endpoint': 'clientfeed_rotate', 'view': rotate_view},
            {'url': '/api/clientfeed/preview', 'methods': ['POST'],
             'endpoint': 'clientfeed_preview', 'view': preview_view},
        ],
        'ports': [],                # opens NO port — rides Caddy's existing 443
        'service_units': [],
        'settings_keys': [],
    })
