# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ETL Runner (v10.4.0) — pure wiring for the etl-shim in the CloudTAK compose project.

W11: infra-TAK owns ONE overlay file in ~/CloudTAK, `docker-compose.infratak-etl.yml`, rewritten
whole by the console and never hand-edited. It is listed in COMPOSE_FILE after infra-TAK's
override and BEFORE the operator's docker-compose.custom.yml (the operator still wins), and
only while it exists. The operator's file is never written (CLAUDE.md "third-party app config").

Pure functions only: no I/O beyond reading the shim source for its hash, and nothing imported
from app.py (the Dependency Rule boundary). app.py does the side effects — broker etl_setup,
image build, file writes. No register() yet: the module descriptor + UI arrive with W3/W9.
"""
import hashlib
import os

OVERLAY = 'docker-compose.infratak-etl.yml'
CA_FILE = 'etl-ca.pem'                    # the shim CA cert (public), as returned by etl_setup
CA_BUNDLE = 'etl-ca-bundle.pem'           # console.crt + shim CA -> NODE_EXTRA_CA_CERTS
SHIM_IMAGE = 'infratak-etl-shim:local'
SHIM_HASH_LABEL = 'org.infratak.etl-shim.source'
SHIM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'shim')
SHIM_SOURCES = ('Dockerfile', 'lib.mjs', 'shim.mjs')
SHIM_SERVICE = 'etl-shim'
ETL_NETWORK = 'cloudtak_etl'
ETL_BRIDGE = 'br-cloudtak-etl'            # fixed: the broker's W5 egress rules match this interface
AWS_ALIAS = 'aws-local'                   # default-network-only: Docker DNS must never answer
                                          # api/events with the shim's ETL-net address (W5)
AWS_REGION = 'us-east-1'                  # must match the broker's ETL_SQS_HOST
SQS_HOST = f'sqs.{AWS_REGION}.amazonaws.com'
HOOK_LOOPBACK_PORT = 4001                 # webhooks; Caddy proxies to it only when used (W7)
BUNDLE_IN_CONTAINER = '/etc/ssl/certs/infratak-etl-ca-bundle.pem'

# CloudTAK's AWS SDK clients honor these per-service endpoint overrides.
_API_SERVICES = ('CLOUDFORMATION', 'LAMBDA', 'ECR', 'CLOUDWATCH_LOGS', 'STS', 'SQS')
_EVENTS_SERVICES = ('LAMBDA', 'STS', 'SQS')


def shim_source_hash(shim_dir=SHIM_DIR):
    """sha256 over the files the image is built from. Stored as an image label: a different
    value means the image on the box is stale and must be rebuilt."""
    h = hashlib.sha256()
    for name in SHIM_SOURCES:
        h.update(name.encode() + b'\0')
        with open(os.path.join(shim_dir, name), 'rb') as f:
            h.update(f.read())
        h.update(b'\0')
    return h.hexdigest()


def ca_bundle(console_crt, ca_pem):
    """NODE_EXTRA_CA_CERTS takes ONE file and infra-TAK already points it at console.crt, so
    the shim CA is appended to the console cert, not swapped in for it. Either part may be
    empty (a box on the NODE_TLS_REJECT_UNAUTHORIZED fallback has no usable console cert)."""
    parts = [p.strip() + '\n' for p in (console_crt or '', ca_pem or '') if p and p.strip()]
    return ''.join(parts)


def _q(s):
    """Double-quoted YAML scalar. Every value we write is ours (constants, ints, paths
    built from constants) — this only guards the shape."""
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def overlay_yml(ct_dir, uid, gid, socket_dir, data_dir, tls_dir, hook_secret=None, webhooks_url=None):
    """The whole overlay file. `uid`/`gid` are the takwerx-etl ids etl_setup returned.
    W7: `hook_secret` goes to the shim only; `webhooks_url` (webhooks_base()) to api, so the URL
    CloudTAK shows on a layer is the working one. The file therefore holds a secret: 0600."""
    uid, gid = int(uid), int(gid)
    bundle = os.path.join(os.path.abspath(ct_dir), CA_BUNDLE)
    shim_ep = f'http://{AWS_ALIAS}:4000'

    def aws_env(services):
        lines = [f'      AWS_ENDPOINT_URL_{s}: {_q(shim_ep)}' for s in services]
        lines += [f'      AWS_REGION: {_q(AWS_REGION)}',
                  '      AWS_ACCESS_KEY_ID: "local"',
                  '      AWS_SECRET_ACCESS_KEY: "local"',
                  f'      NODE_EXTRA_CA_CERTS: {_q(BUNDLE_IN_CONTAINER)}']
        return '\n'.join(lines)

    return f"""\
# Written by infra-TAK (ETL Runner, v10.4.0) while the ETL Runner is enabled, and removed when
# it is not. Do not edit: the console rewrites it before every CloudTAK compose action. Your own
# settings go in docker-compose.custom.yml, which is loaded after this file.
services:
  api:
    networks:
      default: {{}}
      etl: {{}}
    environment:
{aws_env(_API_SERVICES)}
      ECR_TASKS_REPOSITORY_NAME: "etl-local"
{f'      WEBHOOKS_URL: {_q(webhooks_url)}' + chr(10) if webhooks_url else ''}    volumes:
      - {_q(bundle + ':' + BUNDLE_IN_CONTAINER + ':ro')}
  events:
    environment:
{aws_env(_EVENTS_SERVICES)}
    volumes:
      - {_q(bundle + ':' + BUNDLE_IN_CONTAINER + ':ro')}
  {SHIM_SERVICE}:
    image: {_q(SHIM_IMAGE)}
    pull_policy: never
    restart: always
    user: {_q(f'{uid}:{gid}')}
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks:
      default:
        aliases: [{_q(AWS_ALIAS)}, {_q(SQS_HOST)}]
      etl: {{}}
    ports:
      - {_q(f'127.0.0.1:{HOOK_LOOPBACK_PORT}:4001')}
    environment:
      SHIM_ETL_API: "http://api:5000"
      SHIM_BROKER_SOCK: "/run/etl/broker.sock"
      SHIM_STATE: "/data/stacks.json"
      SHIM_TLS_CERT: "/tls/tls.pem"
      SHIM_TLS_KEY: "/tls/tls.key"
{f'      SHIM_HOOK_SECRET: {_q(hook_secret)}' + chr(10) if hook_secret and HOOK_SECRET_RE.match(hook_secret) else ''}    volumes:
      - {_q(socket_dir + ':/run/etl')}
      - {_q(data_dir + ':/data')}
      - {_q(tls_dir + ':/tls:ro')}
networks:
  etl:
    name: {_q(ETL_NETWORK)}
    driver_opts:
      com.docker.network.bridge.name: {_q(ETL_BRIDGE)}
"""


# ── W3: the ETL catalog ──────────────────────────────────────────────────────────────────────
# catalog.json is generated by tools/etl_catalog_sync.py: every dfpc-coe/etl-* repo plus the
# community entries in community.json, each pinned to a commit SHA. The box builds an installed
# ETL from that SHA (Option A) and registers it in CloudTAK as an Integration.
import json as _json
import re as _re

CATALOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'catalog.json')
ETL_REPO = 'etl-local'                         # the "ECR repository" the shim serves
CAP_LABEL = 'com.cloudtak.capabilities'        # CloudTAK reads static capabilities from it
SHA_LABEL = 'org.infratak.etl.sha'
PREFIX_RE = _re.compile(r'^etl-[A-Za-z0-9-]{1,64}$')      # etl-AlertWest is mixed-case upstream
VERSION_RE = _re.compile(r'^\d{1,4}\.\d{1,4}\.\d{1,4}$')
SHA_RE = _re.compile(r'^[0-9a-f]{40}$')
SOURCE_RE = _re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$')


EGRESS_MAX_ALLOW = 32


def egress_allow_norm(allow):
    """The W5 allow-list rule, for the console to reject a bad list early. The broker applies
    the same rule (_etl_egress_allow_norm) and is the authority. Raises ValueError."""
    import ipaddress
    if not isinstance(allow, list) or len(allow) > EGRESS_MAX_ALLOW:
        raise ValueError(f'at most {EGRESS_MAX_ALLOW} CIDRs')
    cgnat = ipaddress.ip_network('100.64.0.0/10')
    out = set()
    for a in allow:
        try:
            n = ipaddress.ip_network(str(a), strict=False)
        except ValueError:
            raise ValueError(f'bad CIDR: {str(a)[:60]!r}')
        if n.is_loopback or n.is_link_local or n.is_multicast or n.is_unspecified or n.is_reserved \
                or (n.version == 4 and n.overlaps(ipaddress.ip_network('0.0.0.0/8'))):
            raise ValueError(f'{n} can never be allowed (loopback / link-local / multicast / reserved)')
        if n.prefixlen < (8 if n.version == 4 else 16):
            raise ValueError(f'{n} is too wide')
        if not (n.is_private or (n.version == 4 and n.subnet_of(cgnat))):
            raise ValueError(f'{n} is not a private network (public addresses are already allowed)')
        out.add(str(n))
    return sorted(out, key=lambda x: (ipaddress.ip_network(x).version, x))


# ── W7: webhooks ─────────────────────────────────────────────────────────────────────────────
HOOK_PATH = '/etl-hooks'                       # shim/lib.mjs HOOK_PREFIX
HOOK_SECRET_RE = _re.compile(r'^[A-Za-z0-9_-]{43}$')


def new_hook_secret():
    import secrets
    return secrets.token_urlsafe(32)           # 43 chars, 256 bits — lib.mjs HOOK_SECRET_RE


def webhooks_base(api_url, secret):
    """https://<CloudTAK map host>/etl-hooks/<secret> from CloudTAK's API_URL, or None when the
    map host is not a plain https name (no public route is made then)."""
    from urllib.parse import urlsplit
    try:
        u = urlsplit(str(api_url or ''))
    except ValueError:
        return None
    host = u.hostname or ''
    if (u.scheme != 'https' or not _re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host) or u.username
            or u.password or u.path not in ('', '/') or not HOOK_SECRET_RE.match(str(secret or ''))):
        return None
    return f"https://{host}{f':{u.port}' if u.port else ''}{HOOK_PATH}/{secret}"


HOOK_FALLBACK_PORT = 4009                      # Caddy's own loopback 503 site (see caddy_hook_lines)
HOOK_COOKIE = 'infratak_hook'                  # shim/lib.mjs HOOK_COOKIE
HOOK_PATH_MASK = '_'                           # what the URI carries after Caddy moves the secret


def caddy_hook_lines(port=HOOK_LOOPBACK_PORT):
    """Lines for the CloudTAK map site while at least one layer has webhooks on. The secret is
    in the public URL (CloudTAK shows WEBHOOKS_URL/<layer>), but Caddy's error logger writes the
    request URI and headers to the journal (seen live with the shim down). So Caddy moves the
    secret into a Cookie it sets itself — Caddy redacts Cookie in logs, it replaces whatever the
    client sent, and the shim never passes Cookie to an ETL — and rewrites the path segment to
    `_` before the proxy. The shim checks the secret before it reads the body."""
    return [
        "    # ETL Runner webhooks (W7): only while a layer has webhooks on.",
        f"    @etl_hooks path {HOOK_PATH}/*",
        "    handle @etl_hooks {",
        "        request_body {",
        "            max_size 1MB",
        "        }",
        "        route {",
        f"            request_header Cookie \"{HOOK_COOKIE}={{http.request.uri.path.1}}\"",
        f"            uri path_regexp ^{HOOK_PATH}/[^/]* {HOOK_PATH}/{HOOK_PATH_MASK}",
        # Fallback upstream: when the shim is down, Caddy answers from its own loopback site
        # instead of failing the proxy — a failed proxy is what Caddy's error logger writes,
        # with the ORIGINAL request URI (secret included; seen live, Caddy 2.11).
        f"            reverse_proxy 127.0.0.1:{int(port)} 127.0.0.1:{HOOK_FALLBACK_PORT} {{",
        "                lb_policy first",
        "                lb_try_duration 2s",
        "                fail_duration 10s",
        "            }",
        "        }",
        "    }",
    ]


def caddy_hook_fallback_site():
    """A loopback-only Caddy site the hook route falls back to while the shim is down."""
    return [
        "# ETL Runner webhooks (W7): fallback while the shim is down (loopback only)",
        f"http://127.0.0.1:{HOOK_FALLBACK_PORT} {{",
        "    bind 127.0.0.1",
        "    header Content-Type application/json",
        "    header X-Content-Type-Options nosniff",
        "    header Cache-Control no-store",
        "    respond `{\"message\":\"Service Unavailable\"}` 503",
        "}",
        "",
    ]


def image_tag(prefix, version):
    return f'{ETL_REPO}:{prefix}-v{version}'


def valid_entry(e):
    """Every value the console shells out with comes from the catalog, and is still checked:
    the catalog is a file a later phase fetches from GitHub."""
    return (isinstance(e, dict) and PREFIX_RE.fullmatch(str(e.get('prefix', '')))
            and VERSION_RE.fullmatch(str(e.get('version', '')))
            and SHA_RE.fullmatch(str(e.get('sha', '')))
            and SOURCE_RE.fullmatch(str(e.get('source', ''))) is not None)


# ── W3 phase 2: the signed catalog fetched from takwerx/infratak-etl-catalog ─────────────────
# The catalog decides what a box builds and runs (source + sha + reviewed), so a fetched copy is
# used only when it carries a valid Ed25519 signature from the offline key whose public half
# ships here. Any failure falls back to the bundled catalog, which is trusted like code.
CATALOG_SCHEMA = 1
CATALOG_REPO = 'takwerx/infratak-etl-catalog'
CATALOG_BRANCH = 'main'
CATALOG_FILE = 'catalog.json'
CATALOG_MAX_BYTES = 2 * 1024 * 1024
CATALOG_MAX_ENTRIES = 500
CATALOG_PUBKEY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'catalog_signing.pub')
CATALOG_CHECK_SEC = 24 * 3600
COMMIT_SHA_RE = SHA_RE


def parse_catalog(raw):
    """bytes -> dict, or ValueError. Checks shape only; the signature is checked apart."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > CATALOG_MAX_BYTES:
        raise ValueError('catalog is too large')
    try:
        d = _json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise ValueError('catalog is not JSON')
    if not isinstance(d, dict) or d.get('schema') != CATALOG_SCHEMA:
        raise ValueError('catalog schema is not supported')
    serial = d.get('serial')
    if not isinstance(serial, int) or isinstance(serial, bool) or serial <= 0:
        raise ValueError('catalog has no serial')
    ents = d.get('entries')
    if not isinstance(ents, list) or len(ents) > CATALOG_MAX_ENTRIES:
        raise ValueError('catalog entries are not a list')
    return d


def catalog_serial(d):
    s = d.get('serial') if isinstance(d, dict) else None
    return s if isinstance(s, int) and not isinstance(s, bool) and s > 0 else 0


def _pubkeys(path=CATALOG_PUBKEY):
    try:
        text = open(path).read()
    except OSError:
        return []
    return _re.findall(r'-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\s]+?-----END PUBLIC KEY-----', text)


def verify_signature(raw, sig_text, pubkey_path=CATALOG_PUBKEY, openssl='openssl'):
    """True only when `sig_text` (base64 of a 64-byte Ed25519 signature) verifies over the exact
    bytes `raw` with a pinned public key. Uses the OpenSSL 3 CLI (a start.sh dependency on both
    families), argv only, in a private temp dir."""
    import base64
    import binascii
    import shutil
    import subprocess
    import tempfile
    try:
        sig = base64.b64decode((sig_text or b'').strip(), validate=True)
    except (binascii.Error, ValueError, TypeError):
        return False
    keys = _pubkeys(pubkey_path)
    if len(sig) != 64 or not keys or not isinstance(raw, (bytes, bytearray)):
        return False
    d = tempfile.mkdtemp(prefix='etlcat-')
    try:
        paths = {}
        for name, data in (('msg', bytes(raw)), ('sig', sig)):
            paths[name] = os.path.join(d, name)
            with open(paths[name], 'wb') as f:
                f.write(data)
        for i, k in enumerate(keys):
            kp = os.path.join(d, f'k{i}.pem')
            with open(kp, 'w') as f:
                f.write(k + '\n')
            try:
                r = subprocess.run([openssl, 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', kp,
                                    '-in', paths['msg'], '-sigfile', paths['sig']],
                                   capture_output=True, text=True, timeout=20)
            except (OSError, subprocess.SubprocessError):
                return False
            if r.returncode == 0 and 'Signature Verified Successfully' in r.stdout:
                return True
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


_VERIFIED = {}          # (path, mtime_ns, size) -> parsed dict, so a load does not re-run openssl


def cached_catalog(cache_dir, pubkey_path=CATALOG_PUBKEY):
    """The fetched catalog in `cache_dir`, or None unless its signature still verifies."""
    if not cache_dir:
        return None
    cp, sp = os.path.join(cache_dir, CATALOG_FILE), os.path.join(cache_dir, CATALOG_FILE + '.sig')
    try:
        st = os.stat(cp)
        key = (cp, st.st_mtime_ns, st.st_size, os.stat(sp).st_mtime_ns)
        if key in _VERIFIED:
            return _VERIFIED[key]
        with open(cp, 'rb') as f:
            raw = f.read(CATALOG_MAX_BYTES + 1)
        with open(sp, 'rb') as f:
            sig = f.read(4096)
        d = parse_catalog(raw)
    except (OSError, ValueError):
        return None
    if not verify_signature(raw, sig, pubkey_path):
        return None
    _VERIFIED.clear()
    _VERIFIED[key] = d
    return d


def bundled_catalog(path=CATALOG):
    with open(path) as f:
        return _json.load(f)


def active_catalog(cache_dir=None, path=CATALOG, pubkey_path=CATALOG_PUBKEY):
    """(dict, source): the verified fetched catalog when its serial is newer than the bundled
    one, else the bundled catalog (on a tie the bundled file wins: it can carry local edits not
    yet published, and it needs no openssl call). source is 'fetched' or 'bundled'."""
    b = bundled_catalog(path)
    if not cache_dir or not os.path.exists(os.path.join(cache_dir, CATALOG_FILE)):
        return b, 'bundled'
    c = cached_catalog(cache_dir, pubkey_path)
    if c is not None and catalog_serial(c) > catalog_serial(b):
        return c, 'fetched'
    return b, 'bundled'


def load_catalog(path=CATALOG, cache_dir=None, pubkey_path=CATALOG_PUBKEY):
    d, _src = active_catalog(cache_dir, path, pubkey_path)
    return [e for e in d.get('entries', []) if valid_entry(e)]


def accept_fetched(raw, sig, floor, pubkey_path=CATALOG_PUBKEY):
    """(dict, '') when a fetched catalog may replace the cache, else (None, reason). `floor` is
    the highest serial this box has accepted or bundled: anything lower is a rollback."""
    try:
        d = parse_catalog(raw)
    except ValueError as e:
        return None, str(e)
    if not verify_signature(raw, sig, pubkey_path):
        return None, 'signature does not verify'
    if catalog_serial(d) < floor:
        return None, f'serial {catalog_serial(d)} is older than {floor} (rollback refused)'
    return d, ''


def installable(e, allow_unreviewed=False):
    """(ok, reason). Email ETLs need SES (parked); webhook ETLs run behind the W7 box secret; an
    unreviewed entry (new or bumped since its /module-scan) is refused unless the box opts in."""
    f = e.get('flags') or {}
    if f.get('email') and not f.get('schedule') and not f.get('webhook'):
        return False, 'Email delivery is not supported by the local runner yet'
    if not f.get('schedule') and not f.get('webhook'):
        return False, 'This ETL has no way to run on the local runner'
    if not e.get('reviewed') and not allow_unreviewed:
        return False, 'Waiting for security review'
    return True, ''


def installed_versions(image_lines):
    """`docker images etl-local --format '{{.Tag}}'` lines -> {prefix: [versions]}."""
    out = {}
    for t in image_lines:
        m = _re.fullmatch(r'(etl-[A-Za-z0-9-]+)-v(\d+\.\d+\.\d+)', t.strip())
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    for v in out.values():
        v.sort(key=lambda s: tuple(int(x) for x in s.split('.')))
    return out


def _short(text, limit=200):
    """First sentence of third-party text, one line, no control characters, at most `limit`."""
    t = ' '.join(_re.sub(r'[\x00-\x1f\x7f]', ' ', text or '').split())
    t = _re.split(r'(?<=[.!?])\s', t, maxsplit=1)[0]
    return t if len(t) <= limit else t[:limit - 1].rstrip() + '…'


def notify_items(catalog, installed, known, allow_unreviewed=False):
    """Guard Dog update-email items for the ETL catalog -> (items, known).

    * `etl:<prefix>` — an installed ETL whose catalog version is newer and installable here;
      identity is the pinned SHA, so each new commit is mailed once.
    * `etl-new:<prefix>` — an installable catalog ETL this box has not seen before.

    `known` is the set of prefixes already announced (None on the first sweep). The first
    sweep returns every current prefix as the baseline and announces nothing — a box that
    turns ETL on must not get one email per catalog entry. The caller adds the announced
    prefixes to `known` only after the email is sent."""
    def vt(v):
        return tuple(int(x) for x in v.split('.'))
    baseline = known is None
    known = set(e['prefix'] for e in catalog) if baseline else set(known)
    items = []
    for e in catalog:
        p, have = e['prefix'], installed.get(e['prefix']) or []
        can, _ = installable(e, allow_unreviewed)
        if have:
            known.add(p)       # installed before we announced it: nothing to announce
            if can and vt(e['version']) > vt(have[-1]):
                items.append({'key': f'etl:{p}', 'identity': e['sha'],
                              'label': f"CloudTAK ETL “{e['name']}”",
                              'installed': f"v{have[-1]}", 'target': f"v{e['version']}",
                              'how': 'CloudTAK page → ETL → Update.'})
        elif can and p not in known:
            items.append({'key': f'etl-new:{p}', 'identity': e['sha'], 'etl_new': True,
                          'label': f"CloudTAK ETL “{e['name']}”",
                          'installed': 'not installed', 'target': f"v{e['version']}",
                          'summary': f"New ETL available: {e['name']} v{e['version']}"
                                     + (f" (community, by {e['author']})" if e.get('community') else ''),
                          'detail': [d for d in (_short(e.get('description')),) if d],
                          'how': 'CloudTAK page → ETL → Install.'})
    return items, known
