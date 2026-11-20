"""ops #963 — a Docker TAK Server built from TAK's 5.8 hardened bundle keeps Java 17.0.19.

Dockerfile.hardened-takserver pins one exact Temurin build:

    ARG BASE_DEPLOY_TAG=17.0.19_10-jdk-ubi10-minimal

`docker build --pull` refreshes a mutable tag, never an exact pin, so no newer Java ever
reached a Docker TAK box (17.0.19 is April 2026; Temurin 17.0.21+9 is October 2026). _patch_tak_hardened_java_pin
moves that one line up to _TEMURIN17_FIXED_TAG on every build path. It must touch nothing else,
leave a newer pin, another major or another image alone, and be a no-op the second time.

The SHIPPED header below is the first lines of Dockerfile.hardened-takserver in
takserver-docker-hardened-5.8-RELEASE-75.zip, copied verbatim (checked 2026-11-19).
"""
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

SHIPPED = '''## Environment variables outside image context
ARG BASE_REGISTRY=docker.io
ARG BASE_DEPLOY_IMAGE=library/eclipse-temurin
ARG BASE_DEPLOY_TAG=17.0.19_10-jdk-ubi10-minimal

####################################################################################################

## Base deploy image
FROM ${BASE_REGISTRY}/${BASE_DEPLOY_IMAGE}:${BASE_DEPLOY_TAG} AS deploy_container

USER root
RUN microdnf update -y --disableplugin=subscription-manager --nodocs
'''

DF = 'docker/Dockerfile.hardened-takserver'


def _grab(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, name + ' is not defined in app.py'
    return m.group(0)


def _consts():
    ns = {'re': re}
    for name in ('_TEMURIN17_FIXED_TAG', '_TEMURIN_JDK_TAG_RE', '_TEMURIN_PIN_LINE_RE'):
        m = re.search(r'^%s = .*?(?=^\S)' % name, APP, re.S | re.M)
        assert m, name + ' is not defined in app.py'
        exec(compile(m.group(0), 'app.py', 'exec'), ns)
    return ns


def _patcher():
    import os
    ns = {'os': os, 're': re, 'print': lambda *a, **k: None, **_consts()}
    exec(compile(_grab('_temurin_tag_key'), 'app.py', 'exec'), ns)
    exec(compile(_grab('_patch_tak_hardened_java_pin'), 'app.py', 'exec'), ns)
    return ns['_patch_tak_hardened_java_pin'], ns


def _ctx(tmp_path, text=SHIPPED):
    d = tmp_path / 'docker'
    d.mkdir()
    (d / 'Dockerfile.hardened-takserver').write_text(text)
    return str(tmp_path)


def _read(tmp_path):
    return (tmp_path / DF).read_text()


def test_shipped_pin_moves_to_the_fixed_build_and_nothing_else_changes(tmp_path):
    patch, ns = _patcher()
    logs = []
    assert patch(_ctx(tmp_path), DF, logs.append) is True
    out = _read(tmp_path)
    fixed = ns['_TEMURIN17_FIXED_TAG']
    assert 'ARG BASE_DEPLOY_TAG=' + fixed + '\n' in out
    assert '17.0.19_10' not in out
    assert out.replace(fixed, '17.0.19_10-jdk-ubi10-minimal', 1) == SHIPPED
    assert logs and '17.0.19_10-jdk-ubi10-minimal' in logs[0] and fixed in logs[0]


def test_second_run_is_a_noop(tmp_path):
    patch, _ = _patcher()
    ctx = _ctx(tmp_path)
    assert patch(ctx, DF) is True
    once = _read(tmp_path)
    assert patch(ctx, DF) is False
    assert _read(tmp_path) == once


def test_fixed_tag_is_the_newest_known_build_and_newer_than_shipped():
    ns = _consts()
    key = _patcher()[1]['_temurin_tag_key']
    # Bump with the one constant when Docker Hub lists 17.0.21.1_2-jdk-ubi10-minimal (Adoptium's Nov 18 build).
    assert ns['_TEMURIN17_FIXED_TAG'] == '17.0.21_9-jdk-ubi10-minimal'
    assert key(ns['_TEMURIN17_FIXED_TAG']) > key('17.0.20.1_1-jdk-ubi10-minimal') > key('17.0.19_10-jdk-ubi10-minimal')


def test_tag_order_reads_update_numbers_not_text():
    key = _patcher()[1]['_temurin_tag_key']
    assert key('17.0.9_9-jdk-ubi10-minimal') < key('17.0.19_10-jdk-ubi10-minimal')
    assert key('17.0.20_8-jdk-ubi10-minimal') < key('17.0.20.1_1-jdk-ubi10-minimal')
    assert key('17.0.21_9-jdk-ubi10-minimal') > key('17.0.21_2-jdk-ubi10-minimal')
    assert key('17.0.21_9-jre-ubi10-minimal') is None and key('latest') is None and key(None) is None


def test_a_newer_pin_is_left_alone(tmp_path):
    patch, _ = _patcher()
    text = SHIPPED.replace('17.0.19_10', '17.0.22_6')
    assert patch(_ctx(tmp_path, text), DF) is False
    assert _read(tmp_path) == text


def test_the_fixed_pin_itself_is_left_alone(tmp_path):
    patch, ns = _patcher()
    text = SHIPPED.replace('17.0.19_10-jdk-ubi10-minimal', ns['_TEMURIN17_FIXED_TAG'])
    assert patch(_ctx(tmp_path, text), DF) is False
    assert _read(tmp_path) == text


def test_other_majors_images_and_shapes_are_left_alone(tmp_path):
    patch, _ = _patcher()
    for pin in ('21.0.4_7-jdk-ubi10-minimal',        # another Java major: never moved to 17
                '17.0.19_10-jre-ubi10-minimal',      # a JRE tag is not this pin
                '17.0.19_10-jdk-jammy',              # not the UBI 10 minimal image
                '17.0.19_10-jdk-ubi10-minimal-x',    # a tag we do not recognise
                'latest',
                '${SOMETHING}'):
        text = SHIPPED.replace('17.0.19_10-jdk-ubi10-minimal', pin)
        d = tmp_path / pin.replace('$', '_').replace('{', '_').replace('}', '_')
        d.mkdir()
        assert patch(_ctx(d, text), DF) is False, pin
        assert _read(d) == text, pin


def test_an_operator_who_set_another_registry_or_image_keeps_it(tmp_path):
    patch, _ = _patcher()
    text = SHIPPED.replace('ARG BASE_REGISTRY=docker.io', 'ARG BASE_REGISTRY=registry1.dso.mil')
    # the registry/image lines are never touched; only the tag line can change
    assert patch(_ctx(tmp_path, text), DF) is True
    out = _read(tmp_path)
    assert 'ARG BASE_REGISTRY=registry1.dso.mil\n' in out
    assert 'ARG BASE_DEPLOY_IMAGE=library/eclipse-temurin\n' in out


def test_missing_or_unreadable_dockerfile_builds_as_shipped(tmp_path):
    patch, _ = _patcher()
    logs = []
    assert patch(str(tmp_path), DF, logs.append) is False        # file absent
    assert patch(str(tmp_path), None, logs.append) is False      # no app Dockerfile resolved
    assert patch(_ctx(tmp_path, 'FROM postgres:15.1\n'), DF, logs.append) is False  # no pin line
    assert _read(tmp_path) == 'FROM postgres:15.1\n'


def test_both_docker_build_paths_run_the_patch_before_the_app_image_build():
    calls = [m.start() for m in re.finditer(r'_patch_tak_hardened_java_pin\((new_ctx|build_ctx), _app_df, (ulog|log_step)\)', APP)]
    builds = [m.start() for m in re.finditer(r"docker build --pull -t \{TAK_CONTAINER\} -f \{shlex\.quote\(_app_df\)\}", APP)]
    assert len(calls) == 2 and len(builds) == 2
    for c, b in zip(sorted(calls), sorted(builds)):
        assert c < b < c + 2500, 'the pin is patched just before the takserver image is built'
