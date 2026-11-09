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


def overlay_yml(ct_dir, uid, gid, socket_dir, data_dir, tls_dir):
    """The whole overlay file. `uid`/`gid` are the takwerx-etl ids etl_setup returned."""
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
    volumes:
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
    volumes:
      - {_q(socket_dir + ':/run/etl')}
      - {_q(data_dir + ':/data')}
      - {_q(tls_dir + ':/tls:ro')}
networks:
  etl:
    name: {_q(ETL_NETWORK)}
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


def image_tag(prefix, version):
    return f'{ETL_REPO}:{prefix}-v{version}'


def valid_entry(e):
    """Every value the console shells out with comes from the catalog, and is still checked:
    the catalog is a file a later phase fetches from GitHub."""
    return (isinstance(e, dict) and PREFIX_RE.fullmatch(str(e.get('prefix', '')))
            and VERSION_RE.fullmatch(str(e.get('version', '')))
            and SHA_RE.fullmatch(str(e.get('sha', '')))
            and SOURCE_RE.fullmatch(str(e.get('source', ''))) is not None)


def load_catalog(path=CATALOG):
    with open(path) as f:
        d = _json.load(f)
    return [e for e in d.get('entries', []) if valid_entry(e)]


def installable(e, allow_unreviewed=False):
    """(ok, reason). Email ETLs need SES (parked); webhook-only ETLs need W7; an unreviewed
    entry (new or bumped since its /module-scan) is refused unless the box opts in for testing."""
    f = e.get('flags') or {}
    if f.get('email') and not f.get('schedule') and not f.get('webhook'):
        return False, 'Email delivery is not supported by the local runner yet'
    if not f.get('schedule'):
        return False, 'Webhook-only ETLs arrive with webhook support'
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
