# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ETL Runner W2 (v10.4.0): the etl-shim's only door to Docker is the broker `etl` verb.

The spike mounted docker.sock into the shim (host root). The product shim has no socket;
these tests pin what the verb will and will not do for it:
  * a fixed schema per action — unknown fields, actions and shapes are denied;
  * only etl-local:etl-<name>-v<x.y.z> images, never a pull, never another image;
  * the hardened profile is built by the broker and cannot be overridden by the request;
  * stop/logs/inspect refuse any container the verb did not start;
  * the ETL socket admits root and the takwerx-etl uid only, and serves only `etl`.
"""
import importlib.util
import json
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parent.parent / 'broker' / 'takwerx_broker.py'


def _load():
    spec = importlib.util.spec_from_file_location('tb_etl_test', SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def m():
    return _load()


def _run(**over):
    req = {'op': 'etl', 'action': 'run', 'fn': 'test-layer-7', 'image': 'etl-local:etl-geojson-v2.13.0',
           'memory_mb': 512, 'env': {'ETL_API': 'http://api:5000', 'ETL_LAYER': '7'}}
    req.update(over)
    return req


def test_valid_requests_pass(m):
    m._check_etl(_run())
    for a in ('list', 'list-images', 'net'):
        m._check_etl({'op': 'etl', 'action': a})
    m._check_etl({'op': 'etl', 'action': 'logs', 'id': 'a' * 64, 'since': 1730000000})
    m._check_etl({'op': 'etl', 'action': 'stop', 'id': 'abcdef012345'})


@pytest.mark.parametrize('image', [
    'alpine', 'etl-local:latest', 'etl-local:etl-x', 'docker.io/etl-local:etl-x-v1.0.0',
    'etl-local:etl-x-v1.0.0@sha256:00', 'etl-local:etl-X-v1.0.0', 'etl-local:etl-x-v1.0.0 ',
    'other:etl-x-v1.0.0', 'etl-local:etl-x-v1.0.0\n', ['etl-local:etl-x-v1.0.0'],
])
def test_only_local_etl_images(m, image):
    with pytest.raises(m.Denied):
        m._check_etl(_run(image=image))


@pytest.mark.parametrize('extra', [
    {'HostConfig': {'Privileged': True}}, {'binds': ['/:/host']}, {'network': 'host'},
    {'user': '0:0'}, {'privileged': True}, {'cap_add': ['SYS_ADMIN']},
])
def test_run_rejects_any_extra_field(m, extra):
    with pytest.raises(m.Denied):
        m._check_etl(_run(**extra))


@pytest.mark.parametrize('bad', [
    {'memory_mb': 64}, {'memory_mb': 99999}, {'memory_mb': '512'}, {'memory_mb': True},
    {'fn': '../x'}, {'fn': 'a' * 129}, {'fn': ''},
    {'env': {'BAD KEY': 'x'}}, {'env': {'X': 1}}, {'env': {'X': 'a\x00b'}}, {'env': ['X=1']},
    {'env': {f'K{i}': 'v' for i in range(65)}}, {'env': {'BIG': 'x' * (64 * 1024 + 1)}},
])
def test_run_shape_denials(m, bad):
    with pytest.raises(m.Denied):
        m._check_etl(_run(**bad))


@pytest.mark.parametrize('req', [
    {'op': 'etl', 'action': 'exec'}, {'op': 'etl'}, {'op': 'etl', 'action': 'stop', 'id': 'cloudtak-api-1'},
    {'op': 'etl', 'action': 'stop', 'id': '../../x'}, {'op': 'etl', 'action': 'logs', 'id': 'a' * 12, 'since': -1},
    {'op': 'etl', 'action': 'list', 'filters': {'label': ['x']}}, {'op': 'etl', 'action': 'net', 'network': 'host'},
])
def test_other_denials(m, req):
    with pytest.raises(m.Denied):
        m._check_etl(req)


def test_hardened_profile_is_fixed(m):
    hc = m._etl_host_config(512)
    assert hc['NetworkMode'] == 'cloudtak_etl'
    assert hc['ReadonlyRootfs'] is True and hc['Privileged'] is False
    assert hc['CapDrop'] == ['ALL'] and 'no-new-privileges' in hc['SecurityOpt']
    assert hc['Binds'] == [] and hc['Mounts'] == [] and hc['Devices'] == []
    assert hc['Memory'] == hc['MemorySwap'] == 512 * 1048576
    assert hc['PidsLimit'] == 256
    assert 'size=512m' in hc['Tmpfs']['/tmp']


def test_run_sends_only_broker_built_fields(m, monkeypatch):
    calls = []

    def fake_json(method, path, body=None, ok=(200,)):
        calls.append((method, path, body))
        if path.startswith('/containers/json'):
            return []
        if path.startswith('/containers/create'):
            return {'Id': 'f' * 64}
        if path.endswith('/start'):
            return {}
        return {'NetworkSettings': {'Networks': {'cloudtak_etl': {'IPAddress': '172.30.0.9'}}}}
    monkeypatch.setattr(m, '_docker_json', fake_json)
    r = m._do_etl(_run())
    assert r == {'ok': True, 'id': 'f' * 64, 'name': r['name'], 'ip': '172.30.0.9'}
    assert r['name'].startswith('etl-run-test-layer-7-')
    create = next(c for c in calls if c[1].startswith('/containers/create'))[2]
    assert set(create) == {'Image', 'User', 'Env', 'Labels', 'NetworkDisabled', 'HostConfig'}
    assert create['Image'] == 'etl-local:etl-geojson-v2.13.0'
    assert create['User'] == '1000:1000'
    assert create['Labels'] == {'etl-shim': '1', 'etl-shim.fn': 'test-layer-7'}
    assert create['HostConfig'] == m._etl_host_config(512)
    assert 'ETL_LAYER=7' in create['Env']


def test_run_refuses_past_the_container_cap(m, monkeypatch):
    monkeypatch.setattr(m, '_etl_list', lambda: [{}] * m.ETL_MAX_CONTAINERS)
    monkeypatch.setattr(m, '_docker_json', lambda *a, **k: pytest.fail('must not create'))
    assert m._do_etl(_run())['code'] == 'LIMIT'


def test_stop_refuses_a_container_it_did_not_start(m, monkeypatch):
    monkeypatch.setattr(m, '_docker_json', lambda method, path, body=None, ok=(200,): {'Config': {'Labels': {}}})
    monkeypatch.setattr(m, '_docker_api', lambda *a, **k: pytest.fail('must not delete'))
    with pytest.raises(m.Denied):
        m._do_etl({'op': 'etl', 'action': 'stop', 'id': 'a' * 64})


def test_etl_socket_admits_only_root_and_the_etl_uid(m, monkeypatch):
    monkeypatch.setattr(m, '_etl_uid', lambda: 995)
    h = m._EtlHandler.__new__(m._EtlHandler)
    assert h._peer_ok(0) and h._peer_ok(995)
    assert not h._peer_ok(1000) and not h._peer_ok(-1)
    monkeypatch.setattr(m, '_etl_uid', lambda: None)
    assert not h._peer_ok(995) and h._peer_ok(0)
    # and the console user is not on the ETL socket (it has the main one)
    monkeypatch.setattr(m, '_allowed_peer', lambda uid: True)
    assert not h._peer_ok(1000)


def test_etl_socket_serves_only_the_etl_verb(m, monkeypatch):
    monkeypatch.setattr(m, 'audit', lambda *a, **k: None)
    for op in ('exec', 'write', 'read', 'pg_dump', 'etl_setup', 'enforce_enable', 'check', None):
        r = m._etl_dispatch({'op': op, 'argv': ['id']}, (1, 995, 995))
        assert r['ok'] is False and r['code'] == 'DENIED', op
    assert m._etl_dispatch({'op': 'ping'}, (1, 995, 995))['pong'] is True


def test_denials_are_fail_closed_even_when_permissive(m, monkeypatch):
    monkeypatch.setattr(m, 'audit', lambda *a, **k: None)
    monkeypatch.setattr(m, 'ENFORCE', False)
    monkeypatch.setattr(m, '_do_etl', lambda req: pytest.fail('must not execute'))
    r = m._dispatch(_run(image='alpine'), (1, 0, 0))
    assert r['code'] == 'DENIED'


def test_demux(m):
    frame = lambda s: b'\x01\x00\x00\x00' + len(s).to_bytes(4, 'big') + s
    assert m._etl_demux(frame(b'a\n') + frame(b'bc')) == 'a\nbc'
    assert m._etl_demux(b'\x01\x00') == ''


def test_etl_setup_takes_no_fields(m):
    assert m._evaluate({'op': 'etl_setup'})[0] == 'ALLOW'
    assert m._evaluate({'op': 'etl_setup', 'user': 'root'})[0] == 'DENY'
    with pytest.raises(m.Denied):
        m._do_etl_setup({'op': 'etl_setup', 'user': 'root'})


def test_a_refused_stop_is_audited_as_deny_only(m, monkeypatch):
    """etlspike 2026-11-05: a stop of a non-ETL container logged ALLOW, then DENY 'None'."""
    lines = []
    monkeypatch.setattr(m, 'audit', lambda peer, op, summary, verdict, detail='': lines.append((op, summary, verdict)))
    monkeypatch.setattr(m, '_docker_json', lambda method, path, body=None, ok=(200,): {'Config': {'Labels': {}}})
    r = m._etl_dispatch({'op': 'etl', 'action': 'stop', 'id': 'a' * 64}, (1, 997, 996))
    assert r['code'] == 'DENIED'
    assert lines == [('etl', 'stop id=' + 'a' * 64, 'DENY')]


def test_a_docker_failure_is_audited_once_with_the_summary(m, monkeypatch):
    lines = []
    monkeypatch.setattr(m, 'audit', lambda peer, op, summary, verdict, detail='': lines.append((summary, verdict)))

    def boom(*a, **k):
        raise RuntimeError('docker down')
    monkeypatch.setattr(m, '_etl_list', boom)
    with pytest.raises(m._EtlAudited):
        m._etl_dispatch(_run(), (1, 997, 996))
    assert lines == [('run fn=test-layer-7 image=etl-local:etl-geojson-v2.13.0 mem=512', 'ERROR')]
