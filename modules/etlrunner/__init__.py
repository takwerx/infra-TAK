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
