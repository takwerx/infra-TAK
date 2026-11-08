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
