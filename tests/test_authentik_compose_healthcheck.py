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
"""Authentik compose: a re-run of the deploy must not write a second healthcheck (v10.2.7, GH #85).

Field (GH #85, 2026-10-07): re-running the Authentik deploy logged "Added healthchecks for
server and worker" and then every docker compose call failed with
    mapping key "healthcheck" already defined at line 25
so Postgres, the server and the LDAP outpost never started.

Cause (reproduced against goauthentik.io/docker-compose.yml): deploy Step 6 injected the
healthcheck as text and recognised it only in the one-line form
`test: ["CMD", "ak", "healthcheck"]`. _ensure_authentik_compose_patches() re-dumps the file
with PyYAML, which writes that list as a block — so the next deploy no longer recognised it
and injected a second key. PyYAML's safe_load keeps the last duplicate silently, so the YAML
patcher saw nothing to change and never rewrote the file; docker compose is strict.

app.py cannot be imported in a test, so the two functions are cut out of it and run: the
code under test is the shipped text.
"""

import ast
import pathlib
import re

import pytest

yaml = pytest.importorskip('yaml')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_WANT = {'_yaml_duplicate_keys', '_ensure_authentik_compose_patches'}

# goauthentik.io/docker-compose.yml as served 2026-10-07 (2026.8.3 template): no healthcheck
# on server or worker — exactly what a fresh deploy downloads.
UPSTREAM = """services:
  postgresql:
    env_file:
    - .env
    environment:
      POSTGRES_DB: ${PG_DB:-authentik}
      POSTGRES_PASSWORD: ${PG_PASS:?database password required}
      POSTGRES_USER: ${PG_USER:-authentik}
    healthcheck:
      interval: 30s
      retries: 5
      start_period: 20s
      test:
      - CMD-SHELL
      - pg_isready -d $${POSTGRES_DB} -U $${POSTGRES_USER}
      timeout: 5s
    image: docker.io/library/postgres:16-alpine
    restart: unless-stopped
    volumes:
    - database:/var/lib/postgresql/data
  server:
    command: server
    depends_on:
      postgresql:
        condition: service_healthy
    env_file:
    - .env
    environment:
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY:?secret key required}
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.8.3}
    ports:
    - ${COMPOSE_PORT_HTTP:-9000}:9000
    - ${COMPOSE_PORT_HTTPS:-9443}:9443
    restart: unless-stopped
    volumes:
    - ./data:/data
    - ./custom-templates:/templates
  worker:
    command: worker
    depends_on:
      postgresql:
        condition: service_healthy
    env_file:
    - .env
    environment:
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY:?secret key required}
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.8.3}
    restart: unless-stopped
    user: root
    volumes:
    - ./data:/data
    - ./custom-templates:/templates
volumes:
  database:
    driver: local
"""

PG_CMD = ('postgres -c max_connections=300 -c shared_buffers=2GB -c effective_cache_size=6GB')


def _load():
    parts = []
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name in _WANT:
            parts.append(ast.get_source_segment(APP, node))
    assert len(parts) == len(_WANT), 'a function under test was renamed or removed'
    ns = {
        'os': __import__('os'),
        're': re,
        '_authentik_pg_command_for_ram': lambda ram: (PG_CMD, 'test-tier'),
        '_local_ram_mb': lambda: 16000,
        '_ensure_authentik_compose_patches_legacy': lambda *a, **k: pytest.fail('legacy patcher reached'),
    }
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


NS = _load()


class _Strict(yaml.SafeLoader):
    """What docker compose does: a duplicate key is an error, not last-wins."""


def _strict_mapping(loader, node, deep=False):
    keys = [loader.construct_object(k, deep=deep) for k, _ in node.value]
    dup = sorted({k for k in keys if keys.count(k) > 1})
    if dup:
        raise ValueError('mapping key %r already defined' % dup)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_Strict.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _strict_mapping)


def _patch(path):
    log = []
    changed = NS['_ensure_authentik_compose_patches'](str(path), log.append)
    return changed, log


def test_patcher_adds_one_healthcheck_and_rerun_is_a_noop(tmp_path):
    f = tmp_path / 'docker-compose.yml'
    f.write_text(UPSTREAM)
    changed, _ = _patch(f)
    assert changed
    first = f.read_text()
    data = yaml.load(first, Loader=_Strict)
    for svc in ('server', 'worker'):
        hc = data['services'][svc]['healthcheck']
        assert hc['test'] == ['CMD', 'ak', 'healthcheck'] and hc['start_period'] == '600s'
    # the re-dump writes the list as a block — the form the old text detector missed
    assert '- ak\n' in first and 'ak", "healthcheck' not in first
    changed, log = _patch(f)
    assert not changed and f.read_text() == first, log
    yaml.load(f.read_text(), Loader=_Strict)


def test_duplicate_healthcheck_from_the_old_deploy_is_repaired(tmp_path):
    f = tmp_path / 'docker-compose.yml'
    f.write_text(UPSTREAM)
    _patch(f)
    # Re-create the GH #85 file: a second healthcheck block right after `command: server`.
    broken = f.read_text().replace(
        '    command: server\n',
        '    command: server\n    healthcheck:\n      test: ["CMD", "ak", "healthcheck"]\n'
        '      start_period: 600s\n      interval: 30s\n      timeout: 10s\n      retries: 5\n', 1)
    f.write_text(broken)
    with pytest.raises(ValueError, match='healthcheck'):
        yaml.load(broken, Loader=_Strict)
    assert any(d.startswith('healthcheck (line ') for d in NS['_yaml_duplicate_keys'](broken, yaml))

    changed, log = _patch(f)
    assert changed
    assert any('Repaired duplicate key(s) healthcheck' in l and 'GH #85' in l for l in log), log
    data = yaml.load(f.read_text(), Loader=_Strict)
    assert data['services']['server']['healthcheck']['test'] == ['CMD', 'ak', 'healthcheck']


def test_duplicate_detector_ignores_merge_keys_and_clean_files():
    assert NS['_yaml_duplicate_keys'](UPSTREAM, yaml) == []
    merged = ('x-base: &base\n  restart: always\nservices:\n  a:\n    <<: *base\n'
              '    restart: unless-stopped\n')
    assert NS['_yaml_duplicate_keys'](merged, yaml) == []
    assert NS['_yaml_duplicate_keys']('a: [unclosed', yaml) == []


def test_deploy_no_longer_injects_healthchecks_as_text():
    # Only the legacy patcher (reached only for unparseable YAML) may still do text injection.
    assert APP.count('Added healthchecks for server and worker') == 1
    assert 'Added healthchecks for server and worker [legacy patcher]' in APP
    # the LOCAL deploy (the remote one writes a whole templated file every run — no injection)
    m = re.search(r'^def run_authentik_deploy\(', APP, re.M)
    body = APP[m.start():APP.index('\ndef ', m.end())] if m else ''
    code = re.sub(r'#.*', '', body)   # the explanatory comment quotes the old form
    assert code and 'ak", "healthcheck' not in code and 'ak healthcheck' not in code
    assert '_ensure_authentik_compose_patches(compose_path, plog)' in body
