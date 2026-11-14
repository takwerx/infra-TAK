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
"""Broker rulebook: every spelling of a refused flag is refused (ops #645, Security review).

GNU getopt_long accepts any unique prefix of a long option (`--mo=4755` is
`--mode=4755`), and getopt takes short flags with the value attached (`-m4755`,
`-f/x`) or bundled after other flags (`-Dm4755`, `-qAtf x`). A gate that checks a
flag by its exact spelling misses all of these. For each refused flag below, every
prefix, attached and bundled form must be refused too.

Each row has a CONTROL: the same command without the refused flag, which must be
ALLOWED. So a row cannot pass only because the whole command is refused for some
other reason.

Nothing is executed: the rulebook is called directly.
"""

import importlib.util
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
H = '/home/takwerx'


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_spell', REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()

PSQL = ['runuser', '-u', 'postgres', '--', 'psql']

# name: (head, tail, bundle letters the console really uses, long flags [(name, value)],
#        short flags [(letter, value)])
# The command is head + <flag words> + tail; the control is head + tail.
ROWS = {
    'install': (['install'], ['-m', '0644', H + '/x', '/var/lib/takguard/b'], 'D',
                [('mode', '4755'), ('owner', 'takwerx'), ('group', 'takwerx'),
                 ('strip-program', '/var/lib/takguard/x'), ('strip', None),
                 ('target-directory', '/etc/sudoers.d'), ('suffix', 'x'), ('backup', None),
                 ('compare', None), ('preserve-context', None), ('context', 'x')],
                [('m', '4755'), ('m', '2755'), ('o', 'takwerx'), ('g', 'takwerx'),
                 ('t', '/etc/sudoers.d'), ('S', 'x'), ('s', None), ('b', None), ('C', None)]),
    'psql': (PSQL, ['-c', 'SELECT 1'], 'qAt',
             [('file', '/tmp/x.sql'), ('output', '/tmp/o'), ('log-file', '/tmp/l'),
              ('set', 'X=1'), ('variable', 'X=1'), ('host', '/tmp'), ('username', 'x'),
              ('dbname', 'postgresql:///cot?options=-c%20x'), ('command', 'SELECT 1'),
              ('single-step', None), ('echo-all', None)],
             [('f', '/tmp/x.sql'), ('o', '/tmp/o'), ('L', '/tmp/l'), ('v', 'X=1'),
              ('h', '/tmp'), ('U', 'x'), ('s', None), ('a', None)]),
    'chmod': (['chmod'], ['644', '/var/lib/takguard/x'], 'R',
              [('reference', '/etc/shadow')], []),
    'chown': (['chown'], ['root:root', '/var/lib/takguard/x'], 'R',
              [('reference', '/etc/shadow')], []),
    'mv': (['mv'], ['/var/log/a', '/var/log/b'], 'f',
           [('target-directory', '/etc/sudoers.d'), ('suffix', 'x'), ('backup', 'simple')],
           [('t', '/etc/sudoers.d'), ('S', 'x'), ('b', None)]),
    'cp': (['cp'], ['/var/lib/caddy/x', '/var/lib/caddy/y'], 'p',
           [('target-directory', '/etc/sudoers.d'), ('link', None), ('symbolic-link', None),
            ('suffix', 'x'), ('backup', 'simple'), ('copy-contents', None)],
           [('t', '/etc/sudoers.d'), ('l', None), ('s', None), ('S', 'x'), ('b', None)]),
    'ln': (['ln'], ['-sfn', H + '/tak-docker/tak', '/opt/tak'], 'f',
           [('target-directory', '/etc/sudoers.d'), ('suffix', 'x'), ('backup', 'simple')],
           [('t', '/etc/sudoers.d'), ('S', 'x'), ('b', None)]),
    'touch': (['touch'], ['/var/lib/takguard/disk_alert_sent'], 'c',
              [('reference', '/etc/shadow'), ('date', 'now')],
              [('r', '/etc/shadow'), ('d', 'now')]),
    'rm': (['rm'], ['-f', '/var/lib/takguard/x'], 'f',
           [('no-preserve-root', None), ('one-file-system', None)], []),
    'mkdir': (['mkdir'], ['-p', '/etc/fail2ban/filter.d'], 'p',
              [('context', 'x')], [('Z', None)]),
    'dnf': (['dnf'], ['install', '-y', 'caddy'], 'y',
            [('setopt', 'pluginpath=/tmp'), ('config', '/tmp/x'), ('installroot', '/tmp'),
             ('repofrompath', 'x,/tmp'), ('nogpgcheck', None)],
            [('c', '/tmp/x')]),
    'apt-get': (['apt-get'], ['install', '-y', 'caddy'], 'q',
                [('option', 'APT::Update::Pre-Invoke::=id'), ('config-file', '/tmp/x'),
                 ('allow-unauthenticated', None)],
                [('o', 'APT::Update::Pre-Invoke::=id'), ('c', '/tmp/x')]),
    'sysctl': (['sysctl'], ['-w', 'vm.swappiness=10'], 'q',
               [('load', '/tmp/x'), ('system', None)],
               [('p', '/tmp/x'), ('f', '/tmp/x')]),
    # argparse: unique prefixes, attached values, and the LAST -t wins
    'semanage': (['semanage', 'fcontext', '-a'], ['-t', 'httpd_sys_content_t', '/var/lib/cesium-tiles(/.*)?'],
                 'a',
                 [('type', 'shadow_t'), ('seuser', 'root'), ('range', 's0'), ('ftype', 'a'),
                  ('equal', '/etc')],
                 [('t', 'shadow_t'), ('s', 'root'), ('r', 's0'), ('f', 'a'), ('e', '/etc')]),
}


def _long_forms(name, value):
    """Every unique-prefix spelling, with the value after = and as the next word."""
    out = []
    for n in range(1, len(name) + 1):
        flag = '--' + name[:n]
        out.append([flag + '=' + value] if value is not None else [flag])
        if value is not None:
            out.append([flag, value])
    return out


def _short_forms(letter, value, bundle):
    out = []
    pres = [''] + [bundle[:k] for k in range(1, len(bundle) + 1)]
    for pre in pres:
        if value is None:
            out.append(['-' + pre + letter])
        else:
            out.append(['-' + pre + letter, value])
            out.append(['-' + pre + letter + value])
    return out


# A prefix that is itself an allowed flag of that tool is that flag, not the longer
# one (an exact match wins in getopt_long), so it is not an escape.
REAL_FLAGS = {'apt-get': {'--all'}}


def _cases():
    for name, (head, tail, bundle, longs, shorts) in ROWS.items():
        for lname, lval in longs:
            for words in _long_forms(lname, lval):
                if words[0] in REAL_FLAGS.get(name, ()):
                    continue
                yield pytest.param(head, tail, words, id=f'{name}:{" ".join(words)}')
        for letter, sval in shorts:
            for words in _short_forms(letter, sval, bundle):
                yield pytest.param(head, tail, words, id=f'{name}:{" ".join(words)}')


@pytest.mark.parametrize('name', sorted(ROWS))
def test_control_shape_is_allowed(name):
    head, tail = ROWS[name][0], ROWS[name][1]
    B.check_exec(head + tail)


@pytest.mark.parametrize('head,tail,words', list(_cases()))
def test_every_spelling_of_a_refused_flag_is_refused(head, tail, words):
    with pytest.raises(B.Denied):
        B.check_exec(head + words + tail)


# --- the exact shapes the Security review found (all ALLOWED before the fix) ----------

@pytest.mark.parametrize('argv', [
    ['install', '--mo=4755', '/bin/bash', '/var/lib/takguard/b'],
    ['install', '-Dm4755', '/bin/bash', '/var/lib/takguard/b'],
    ['install', '--own=takwerx', '-m', '0755', H + '/x', '/opt/tak-guarddog/x'],
    ['install', '-s', '--strip-p=/var/lib/takguard/x', '/tmp/a', '/var/lib/takguard/b'],
    ['install', '--tar=/etc/sudoers.d', '/var/lib/takguard/x'],
    PSQL + ['-f/tmp/x.sql'],
    PSQL + ['--fil=/tmp/x.sql'],
    PSQL + ['-qAtf', '/tmp/x.sql'],
    PSQL + ['-c', '\\o |id'],
    PSQL + ['-c', '  \\copy x to /tmp/y'],
    PSQL + ['-d', 'dbname=cot options=-cx', '-c', 'SELECT 1'],
    PSQL + ['postgresql:///cot', '-c', 'SELECT 1'],
    ['dnf', '--setop=pluginpath=/tmp', 'install', '-y', 'caddy'],
    ['dnf', '--setop=clean_requirements_on_remove=True', 'remove', '-y', 'takserver'],
    # same family, found while converting the rest: argparse in semanage
    ['semanage', 'fcontext', '-a', '-t', 'httpd_sys_content_t', '--typ=shadow_t', '/etc/x'],
    ['semanage', 'fcontext', '-a', '-t', 'httpd_sys_content_t', '-tshadow_t', '/etc/x'],
    ['semanage', 'fcontext', '-a', '--ty', 'httpd_sys_content_t', '-t', 'shadow_t', '/etc/x'],
    ['semanage', 'port', '-a', '-t', 'ssh_port_t', '-p', 'tcp', '5001'],
])
def test_security_review_shapes_are_refused(argv):
    with pytest.raises(B.Denied):
        B.check_exec(argv)


# --- Security re-review: `$` matches before a trailing newline, and fcontext paths ----

# Each pair: (allowed control, same command with a trailing newline in one checked word).
NEWLINE_PAIRS = [
    (['install', '-m', '0755', H + '/x', '/usr/bin/caddy'],
     ['install', '-m', '0755\n', H + '/x', '/usr/bin/caddy']),
    (['install', '-m0755', H + '/x', '/usr/bin/caddy'],
     ['install', '-m0755\n', H + '/x', '/usr/bin/caddy']),
    (PSQL + ['-d', 'postgres', '-c', 'SELECT 1'],
     PSQL + ['-d', 'postgres\n', '-c', 'SELECT 1']),
    (PSQL + ['cot', '-c', 'SELECT 1'],
     PSQL + ['cot\n', '-c', 'SELECT 1']),
    (['dnf', 'install', '-y', '--enablerepo=epel', 'caddy'],
     ['dnf', 'install', '-y', '--enablerepo=epel\n', 'caddy']),
    (['fail2ban-client', 'status', 'sshd'],
     ['fail2ban-client', 'status', 'sshd\n']),
]


@pytest.mark.parametrize('control,bad', NEWLINE_PAIRS, ids=lambda a: ' '.join(a).replace('\n', '\\n'))
def test_trailing_newline_in_a_checked_word_is_refused(control, bad):
    B.check_exec(control)
    with pytest.raises(B.Denied):
        B.check_exec(bad)


def test_no_gate_regex_uses_match_with_a_dollar_anchor():
    """`re.match(r'^x$', 'x\\n')` matches. Every `$`-anchored gate pattern must be
    used with fullmatch, so one missed call cannot reopen the gap."""
    import re as _re
    src = (REPO / 'broker' / 'takwerx_broker.py').read_text()
    dollar_names = {m.group(1) for m in _re.finditer(
        r"^(_[A-Z0-9_]+)\s*=\s*re\.compile\(r?'[^']*\$'", src, _re.M)}
    assert dollar_names, 'expected the module-level gate patterns'
    bad = [n for n in dollar_names if _re.search(_re.escape(n) + r'\.match\(', src)]
    bad += _re.findall(r"re\.match\(r?'\^[^']*\$'", src)
    assert not bad, f'use fullmatch, not match, with a $-anchored pattern: {bad}'


@pytest.mark.parametrize('path', [
    '/etc/shadow', '/.*', '/', '/etc(/.*)?', '/var/lib/cesium-tiles', '/var/lib/cesium-tiles/x',
    '/var/lib/cesium-tiles(/.*)?/x', '/var/lib/cesium-tiles(/.*)?\n', '/root/cesium-tiles(/.*)?',
])
def test_semanage_fcontext_takes_only_the_cesium_dir(path):
    with pytest.raises(B.Denied):
        B.check_exec(['semanage', 'fcontext', '-a', '-t', 'httpd_sys_content_t', path])


@pytest.mark.parametrize('typ', sorted(B.SELINUX_SAFE_TYPES - {'httpd_sys_content_t'}))
def test_semanage_fcontext_takes_only_httpd_sys_content_t(typ):
    with pytest.raises(B.Denied):
        B.check_exec(['semanage', 'fcontext', '-a', '-t', typ, '/var/lib/cesium-tiles(/.*)?'])


@pytest.mark.parametrize('argv', [
    # every install shape in the console code and the test6/test12 audit logs
    ['install', '-m', '0755', H + '/x', '/usr/bin/caddy'],
    ['install', '-m', '644', '/tmp/nr_ctx_global.json', '/opt/tak/nodered-ctx-backup.json'],
    ['install', '-D', '-m', '600', '-o', 'root', '-g', 'root', '/tmp/x', '/etc/wireguard/wg0.conf'],
    ['install', '-o', 'tak', '-g', 'tak', '-m', '640', '/tmp/takserver-le.jks',
     '/opt/tak/certs/files/takserver-le.jks'],
    # every psql shape (_pg_exec / _cot_pg_exec call sites, audit logs)
    PSQL + ['-tAc', "SELECT pg_database_size('cot')"],
    PSQL + ['cot', '-tAc', 'SELECT 1'],
    PSQL + ['cot', '-tAF', '\t', '-c', 'SELECT 1'],
    PSQL + ['cot', '-tA', '-c', 'SELECT 1'],
    PSQL + ['-t', '-A', '-d', 'cot', '-c', 'SELECT 1'],
    PSQL + ['-t', '-A', '-c', "SELECT COALESCE(pg_database_size('cot'), 0);"],
    PSQL + ['-tAX', '-d', 'postgres', '-p', '5432', '-c', 'SHOW data_directory;'],
    PSQL + ['-tAX', '-d', 'postgres', '-c', 'SHOW server_version_num;'],
    PSQL + ['-q', '-d', 'postgres', '-c', 'SELECT 1'],
    PSQL + ['-d', 'cot', '-c', 'VACUUM ANALYZE cot_router'],
    PSQL + ['-X', '-q', '-tA', '-F', '|', '-c', 'SELECT 1'],
    ['dnf', '--setopt=clean_requirements_on_remove=True', 'remove', '-y', 'takserver'],
    # every semanage shape in the console code
    ['semanage', 'port', '-l'],
    ['semanage', 'port', '-a', '-t', 'http_port_t', '-p', 'tcp', '8443'],
    ['semanage', 'port', '-m', '-t', 'http_port_t', '-p', 'udp', '8443'],
    ['semanage', 'fcontext', '-a', '-t', 'httpd_sys_content_t', '/var/lib/cesium-tiles(/.*)?'],
])
def test_console_shapes_still_allowed(argv):
    B.check_exec(argv)


@pytest.mark.parametrize('spec', ['5000/tcp\n', '5000/udp\n'])
def test_mediamtx_port_spec_with_trailing_newline_is_refused(spec):
    """The MediaMTX profile's port check is $-anchored too (fullmatch, not match)."""
    B._mtx_port_ok(spec.rstrip('\n'))
    with pytest.raises(B.Denied):
        B._mtx_port_ok(spec)


def test_mediamtx_backup_name_with_trailing_newline_is_not_its_own_path():
    assert B._mtx_own_path('/usr/local/etc/mediamtx.yml.bak1')
    assert not B._mtx_own_path('/usr/local/etc/mediamtx.yml.bak1\n')
