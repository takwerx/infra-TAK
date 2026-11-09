# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ETL Runner W11 (v10.4.0): the console-owned CloudTAK overlay for the etl-shim."""
import importlib.util
import pathlib

import pytest
import yaml

SRC = pathlib.Path(__file__).resolve().parent.parent / 'modules' / 'etlrunner' / '__init__.py'


@pytest.fixture
def e():
    spec = importlib.util.spec_from_file_location('etl_wiring_test', SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _overlay(e):
    return yaml.safe_load(e.overlay_yml('/home/takwerx/CloudTAK', 997, 996, '/run/takwerx-etl',
                                        '/var/lib/takwerx-etl', '/var/lib/takwerx-etl-tls'))


def test_shim_service_is_hardened_and_never_pulled(e):
    shim = _overlay(e)['services'][e.SHIM_SERVICE]
    assert shim['image'] == e.SHIM_IMAGE and shim['pull_policy'] == 'never'
    assert 'build' not in shim                         # CloudTAK Update's build --no-cache skips it
    assert shim['user'] == '997:996' and shim['read_only'] is True
    assert shim['cap_drop'] == ['ALL'] and shim['security_opt'] == ['no-new-privileges:true']
    assert shim['ports'] == ['127.0.0.1:4001:4001']    # webhooks on loopback only; :4000/:443 unpublished
    vols = shim['volumes']
    assert not any('docker.sock' in v for v in vols)
    assert '/var/lib/takwerx-etl-tls:/tls:ro' in vols


def test_aws_alias_is_on_the_default_network_only(e):
    nets = _overlay(e)['services'][e.SHIM_SERVICE]['networks']
    assert set(nets['default']['aliases']) == {e.AWS_ALIAS, e.SQS_HOST}
    assert not (nets['etl'] or {}).get('aliases')
    assert _overlay(e)['networks']['etl']['name'] == e.ETL_NETWORK


def test_api_and_events_point_every_aws_client_at_the_shim(e):
    svc = _overlay(e)['services']
    for name, services in (('api', e._API_SERVICES), ('events', e._EVENTS_SERVICES)):
        env = svc[name]['environment']
        for s in services:
            assert env[f'AWS_ENDPOINT_URL_{s}'] == f'http://{e.AWS_ALIAS}:4000'
        assert env['AWS_REGION'] == e.AWS_REGION
        assert env['NODE_EXTRA_CA_CERTS'] == e.BUNDLE_IN_CONTAINER
        assert svc[name]['volumes'] == [f'/home/takwerx/CloudTAK/{e.CA_BUNDLE}:{e.BUNDLE_IN_CONTAINER}:ro']


def test_sqs_host_matches_the_broker_cert(e):
    broker = (pathlib.Path(__file__).resolve().parent.parent / 'broker' / 'takwerx_broker.py').read_text()
    assert f"ETL_SQS_HOST = '{e.SQS_HOST}'" in broker


def test_ca_bundle_keeps_the_console_cert(e):
    assert e.ca_bundle('CONSOLE\n', 'SHIMCA') == 'CONSOLE\nSHIMCA\n'
    assert e.ca_bundle('', 'SHIMCA\n') == 'SHIMCA\n'


def test_uid_must_be_an_int(e):
    with pytest.raises(ValueError):
        e.overlay_yml('/x', '997"\n  evil: 1', 996, '/a', '/b', '/c')


def test_source_hash_tracks_the_shim_source(e, tmp_path):
    for n in e.SHIM_SOURCES:
        (tmp_path / n).write_text(n)
    h1 = e.shim_source_hash(str(tmp_path))
    assert h1 == e.shim_source_hash(str(tmp_path))
    (tmp_path / 'shim.mjs').write_text('changed')
    assert e.shim_source_hash(str(tmp_path)) != h1


# ── W3 catalog ──────────────────────────────────────────────────────────────────────────────
def test_shipped_catalog_is_all_valid_and_unique(e):
    raw = __import__('json').load(open(e.CATALOG))['entries']
    cat = e.load_catalog()
    assert len(cat) == len(raw) >= 40                     # every entry passed valid_entry
    prefixes = [x['prefix'] for x in cat]
    assert len(prefixes) == len(set(prefixes))            # CloudTAK keys integrations by prefix
    assert 'etl-caltopo' in prefixes and 'etl-caltopo-clptak' in prefixes


def test_catalog_entries_are_pinned_to_a_commit(e):
    for x in e.load_catalog():
        assert e.SHA_RE.fullmatch(x['sha']), x['prefix']


def test_hostile_entries_are_dropped(e, tmp_path):
    good = {'prefix': 'etl-ok', 'version': '1.2.3', 'sha': 'a' * 40, 'source': 'o/r'}
    bad = [dict(good, prefix='etl-x; rm -rf /'), dict(good, sha='main'), dict(good, version='1.2'),
           dict(good, source='o/r --upload-pack=evil'), dict(good, prefix='../etl')]
    p = tmp_path / 'c.json'
    p.write_text(__import__('json').dumps({'entries': [good] + bad}))
    assert [x['prefix'] for x in e.load_catalog(str(p))] == ['etl-ok']


def test_installable_gates(e):
    sched = {'flags': {'schedule': True}, 'reviewed': {'result': 'PASS'}}
    assert e.installable(sched) == (True, '')
    assert e.installable(dict(sched, reviewed=None))[0] is False          # unscanned never installs
    assert e.installable(dict(sched, reviewed=None), allow_unreviewed=True)[0] is True
    assert e.installable({'flags': {'email': True}, 'reviewed': {}}, True)[0] is False
    assert e.installable({'flags': {'webhook': True}, 'reviewed': {}}, True)[0] is True     # W7
    assert e.installable({'flags': {'webhook': True}, 'reviewed': None})[0] is False       # still scanned first
    assert e.installable({'flags': {}, 'reviewed': {}}, True)[0] is False


def test_installed_versions_parses_docker_tags(e):
    got = e.installed_versions(['etl-geojson-v2.13.0', 'etl-geojson-v2.9.1', 'etl-AlertWest-v2.2.0', 'junk', ''])
    assert got == {'etl-geojson': ['2.9.1', '2.13.0'], 'etl-AlertWest': ['2.2.0']}
    assert e.image_tag('etl-AlertWest', '2.2.0') == 'etl-local:etl-AlertWest-v2.2.0'


def _cat(**kw):
    base = {'prefix': 'etl-a', 'name': 'A', 'version': '1.2.0', 'sha': 'a' * 40, 'author': 'COE',
            'community': False, 'reviewed': '2026-11-08', 'description': 'Pulls A. More text here.',
            'flags': {'schedule': True}}
    return {**base, **kw}


def test_first_sweep_is_a_silent_baseline(e):
    items, known = e.notify_items([_cat(), _cat(prefix='etl-b')], {}, None)
    assert items == [] and known == {'etl-a', 'etl-b'}


def test_new_catalog_etl_is_announced_once_with_a_short_description(e):
    items, known = e.notify_items([_cat(), _cat(prefix='etl-b', name='B')], {}, ['etl-a'])
    assert [i['key'] for i in items] == ['etl-new:etl-b']
    assert items[0]['detail'] == ['Pulls A.'] and items[0]['etl_new']
    assert 'etl-b' not in known      # joins only after the email goes out (caller)


def test_unreviewed_or_uninstallable_etl_is_not_announced(e):
    cat = [_cat(prefix='etl-u', reviewed=None), _cat(prefix='etl-w', flags={'webhook': True})]
    assert e.notify_items(cat, {}, [])[0] == []
    assert [i['key'] for i in e.notify_items(cat[:1], {}, [], allow_unreviewed=True)[0]] == ['etl-new:etl-u']


def test_update_for_an_installed_etl_keys_on_the_pinned_sha(e):
    items, known = e.notify_items([_cat(version='1.10.0')], {'etl-a': ['1.2.0', '1.9.0']}, [])
    assert [(i['key'], i['identity'], i['installed'], i['target']) for i in items] == \
        [('etl:etl-a', 'a' * 40, 'v1.9.0', 'v1.10.0')]
    assert 'etl-a' in known
    assert e.notify_items([_cat()], {'etl-a': ['1.2.0']}, [])[0] == []      # current: nothing


def test_unreviewed_bump_is_not_mailed(e):
    assert e.notify_items([_cat(version='2.0.0', reviewed=None)], {'etl-a': ['1.2.0']}, [])[0] == []
