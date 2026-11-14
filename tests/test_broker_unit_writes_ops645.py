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
"""Root-run destinations have a class, and unit files are checked (ops #645 W2 part 1).

systemd runs every unit in /etc/systemd/system as root, and the console could write
any of them: a new unit, or its own unit with User= removed, was root. Now:
- every writable broker path has a class (data / validated / asset);
- a unit write must be a unit infra-TAK owns, and root may run only infra-TAK's own
  scripts from it; a non-root unit cannot be turned into root;
- no exec route (cp, mv, install, tee, ln, chown, chmod) gets around that check;
- coreutils take only the flags the console uses (a dash mode or a --reference /
  --target-directory flag carried a path past the check).
"""

import ast
import base64
import importlib.util
import pathlib
import re
import shlex

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops645_w2',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()
APP = (REPO / 'app.py').read_text()
CONSOLE_SRC = APP + (REPO / 'start.sh').read_text()


def write(rel, text, mode='w'):
    return B._evaluate({'op': 'write', 'path': f'{B.UNIT_DIR}/{rel}', 'mode': mode,
                        'content_b64': base64.b64encode(text.encode()).decode()})


def ok(rel, text):
    v = write(rel, text)
    assert v[0] == 'ALLOW', v


def refused(rel, text, why=''):
    v = write(rel, text)
    assert v[0] == 'DENY', f'{rel} was allowed'
    assert why in v[1], v[1]


def exec_verdict(argv):
    try:
        B.check_exec(argv)
        return 'ALLOW'
    except B.Denied as e:
        return f'DENY {e}'


GUARD = ('[Unit]\nDescription=TAK Disk Space Monitor\n\n[Service]\nType=oneshot\n'
         'ExecStart=/opt/tak-guarddog/tak-disk-watch.sh\n')
CONSOLE = ('[Unit]\nDescription=infra-TAK\nAfter=network.target\n\n[Service]\nType=simple\n'
           'User=takwerx\nGroup=takwerx\nWorkingDirectory=/opt/infratak\n'
           'Environment=CONFIG_DIR=/opt/infratak/.config\n'
           'ExecStartPre=-/opt/infratak/.venv/bin/python3 /opt/infratak/selfheal_ip.py\n'
           'ExecStart=/opt/infratak/.venv/bin/gunicorn --bind 0.0.0.0:5001 --workers 1 app:app\n'
           'Restart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n')


# --- every destination has a class ------------------------------------------------------

def test_every_writable_path_has_a_class():
    entries = set(B.PATH_ALLOW) | set(B.PATH_ALLOW_EXACT)
    missing = sorted(e for e in entries if e not in B.PATH_CLASS)
    assert not missing, f'give these a class in PATH_CLASS: {missing}'
    assert not set(B.PATH_CLASS) - entries, 'PATH_CLASS has entries the broker does not allow'
    assert set(B.PATH_CLASS.values()) <= {B.DEST_DATA, B.DEST_VALIDATED, B.DEST_ASSET}
    for p, part in B.PATH_CLASS_PENDING.items():
        assert p in B.PATH_CLASS and re.fullmatch(r'W2 part [0-9][a-z]?', part), (p, part)
    assert B._dest_class('/etc/systemd/system/x.service') == B.DEST_VALIDATED
    assert B._dest_class('/opt/tak-guarddog/tak-disk-watch.sh') == B.DEST_ASSET
    assert B._dest_class('/etc/docker/daemon.json') == B.DEST_VALIDATED      # exact wins
    assert '/etc/systemd/system/' not in B.PATH_CLASS_PENDING                 # enforced now


def test_os_release_is_read_only():
    assert B._evaluate({'op': 'read', 'path': '/etc/os-release'})[0] == 'ALLOW'
    v = B._evaluate({'op': 'write', 'path': '/etc/os-release', 'content_b64': ''})
    assert v[0] == 'DENY', 'root scripts source /etc/os-release'


# --- unit names: generated from the console code ----------------------------------------

_NOT_THROUGH_BROKER = {
    'takwerx-broker.service',                              # the broker's own, deny-listed
    'takserver-snapshot.service', 'takserver-snapshot.timer',   # legacy, only removed
    'tak-db-health.service',                               # Server One, over SSH
}


def _console_unit_names():
    names = set(re.findall(r'/etc/systemd/system/([A-Za-z0-9@_.-]+(?:/[A-Za-z0-9@_.-]+)?)', CONSOLE_SRC))
    names |= set(re.findall(r"\(\s*'([a-z0-9@_.-]+\.(?:service|timer))',\s*f?'\[Unit\]", APP))
    return {n for n in names if not n.endswith('.d')}


def test_every_unit_the_console_writes_is_allowed():
    names = _console_unit_names()
    assert len(names) > 60, 'the code scan found too few units; fix the regex'
    bad = sorted(n for n in names - _NOT_THROUGH_BROKER if not B._unit_name_ok(n))
    assert not bad, f'the console writes these units; add them to UNIT_FILES: {bad}'
    for n in _NOT_THROUGH_BROKER - {'takwerx-broker.service'}:
        assert not B._unit_name_ok(n), n


def test_no_stale_unit_names():
    for n in B.UNIT_FILES:
        assert n.split('/')[-1] in CONSOLE_SRC, f'{n} is allowed but no console code writes it'


def test_console_unit_texts_from_app_py_pass():
    """Every (name, '[Unit]...') constant in app.py passes the checker as written."""
    seen = 0
    for node in ast.walk(ast.parse(APP)):
        if (isinstance(node, ast.Tuple) and len(node.elts) == 2
                and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts)
                and re.fullmatch(r'[a-z0-9@_.-]+\.(service|timer)', node.elts[0].value)
                and '[Unit]' in node.elts[1].value):
            ok(node.elts[0].value, node.elts[1].value)
            seen += 1
    assert seen >= 40, seen


def test_authentik_forwarder_matches_app_py():
    const = next(n.value for n in ast.walk(ast.parse(APP))
                 if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', '') == '_AK_FORWARDER_EXEC')
    value = ''.join(c.value for c in const.elts) if isinstance(const, ast.Tuple) else ast.literal_eval(const)
    toks = shlex.split(value.split('=', 1)[1])
    assert toks[:2] == ['/bin/bash', '-c'] and toks[2] == B._AK_FORWARDER_SCRIPT
    ok('authentik-log-forwarder.service',
       '[Unit]\nDescription=f\nAfter=docker.service\n\n[Service]\nType=simple\n' + value
       + 'Restart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n')
    refused('authentik-log-forwarder.service',
            '[Service]\nExecStart=/bin/bash -c \'docker logs -f authentik-server-1; id\'\n', 'inline')


def _stagger(steps):
    exec_cmd = ' && \\\n  '.join(steps)
    return ('[Unit]\nDescription=Stagger\nAfter=docker.service\nRequires=docker.service\n\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            f"ExecStart=/bin/bash -c '\\\n  docker stop a b 2>/dev/null; true && \\\n  {exec_cmd}'\n\n"
            '[Install]\nWantedBy=multi-user.target\n')


def test_docker_stagger_shape_from_app_py_passes_and_extra_commands_do_not():
    good = ['echo "Starting Authentik DB..." && docker start authentik-postgresql-1', 'sleep 5',
            'echo "Starting TAK Portal..." && ((cd /home/takwerx/TAK-Portal && docker compose up -d) '
            '|| docker start tak-portal)', 'echo "All containers started"']
    assert "f\"ExecStart=/bin/bash -c '\\\\\\n  {stop_cmd} && \\\\\\n  {exec_cmd}'\\n\\n\"" in APP
    ok('docker-stagger.service', _stagger(good))
    refused('docker-stagger.service', _stagger(good + ['cp /bin/bash /tmp/x']), 'step not allowed')
    refused('docker-stagger.service', _stagger(['docker start a; id']), 'step not allowed')
    refused('docker-stagger.service',
            _stagger(['((cd /etc && docker compose up -d) || docker start a)']), 'module dir')


def test_real_units_pass():
    ok('takdiskguard.service', GUARD)
    ok('takwerx-console.service', CONSOLE)
    ok('takserver.service.d/soft-start.conf',
       '[Unit]\nAfter=network-online.target postgresql.service\nWants=network-online.target\n\n'
       '[Service]\nTimeoutStartSec=300\nExecStartPre=+-/opt/tak-guarddog/tak-boot-sequencer.sh\n')
    ok('takserver.service.d/jvm-pin.conf',
       '[Service]\nEnvironment=JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64\n'
       'Environment=PATH=/usr/lib/jvm/java-17-openjdk-amd64/bin:/usr/local/sbin:/usr/local/bin'
       ':/usr/sbin:/usr/bin:/sbin:/bin\n')
    ok('caddy.service.d/10-takwerx-acme-eab.conf',
       '[Service]\nEnvironment="TAKWERX_ACME_EAB_KID=abc"\nEnvironment="TAKWERX_ACME_EAB_MAC=xyz"\n')
    ok('mediamtx-webeditor.service.d/20-infratak-home.conf', '[Service]\nEnvironment=HOME=/home/takwerx\n')
    ok('mediamtx-webeditor.service.d/10-infratak-journal.conf', '[Service]\nSupplementaryGroups=systemd-journal\n')
    ok('mediamtx.service', '[Unit]\nDescription=MediaMTX\n\n[Service]\nUser=takwerx\n'
       'SupplementaryGroups=caddy\nExecStart=/usr/local/bin/mediamtx /usr/local/etc/mediamtx.yml\n'
       'Restart=always\n\n[Install]\nWantedBy=multi-user.target\n')
    ok('tak-health.service', '[Service]\nExecStart=/usr/bin/python3 /opt/tak-guarddog/tak-health-endpoint.py\n')
    ok('takdiskguard.timer', '[Unit]\nDescription=t\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\n'
       'Unit=takdiskguard.service\n\n[Install]\nWantedBy=timers.target\n')
    ok('takserver-cert-renewal.service',
       '[Service]\nType=oneshot\nExecStart=/usr/local/sbin/takserver-renew-letsencrypt.sh\n')


# --- proof: the escapes are refused -----------------------------------------------------

@pytest.mark.parametrize('rel,text,why', [
    ('evil.service', GUARD, 'not a unit file'),
    ('takwerx-broker.service.d/x.conf', '[Service]\nEnvironment=TAKWERX_BROKER_ENFORCE=0\n', 'deny'),
    ('x.socket', '', 'not a unit file'),
    ('takwerx-console.service', CONSOLE.replace('User=takwerx\n', ''), 'non-root'),
    ('takwerx-console.service', CONSOLE.replace('User=takwerx', 'User=root'), 'non-root'),
    ('mediamtx.service', '[Service]\nUser=tak\nExecStart=/usr/local/bin/mediamtx\n', 'User=tak'),
    ('takdiskguard.service', GUARD.replace('/opt/tak-guarddog/tak-disk-watch.sh', '/home/takwerx/x.sh'), 'only infra-TAK'),
    ('takdiskguard.service', GUARD.replace('/opt/tak-guarddog/tak-disk-watch.sh', '/opt/infratak/x.sh'), 'only infra-TAK'),
    ('takdiskguard.service', GUARD.replace('/opt/tak-guarddog/tak-disk-watch.sh', '/opt/tak/renew-letsencrypt.sh'), 'only infra-TAK'),
    ('takdiskguard.service', GUARD.replace('/opt/tak-guarddog/tak-disk-watch.sh', '/usr/bin/docker run --privileged x'), 'only infra-TAK'),
    ('takdiskguard.service', GUARD.replace('/opt/tak-guarddog/tak-disk-watch.sh', '/bin/bash -c id'), 'inline'),
    ('takdiskguard.service', GUARD.replace('/opt/tak-guarddog/tak-disk-watch.sh', '/usr/bin/python3 -c 1'), 'python'),
    ('takdiskguard.service', GUARD.replace('/opt/tak-guarddog/tak-disk-watch.sh', '/usr/bin/env sh'), 'only infra-TAK'),
    ('takdiskguard.service', GUARD.replace('ExecStart=/', 'ExecStart=|/'), 'shell'),
    ('takwerx-console.service', CONSOLE.replace('ExecStartPre=-', 'ExecStartPre=+'), 'only infra-TAK'),
    ('takwerx-console.service', CONSOLE.replace('ExecStartPre=-', 'ExecStartPre=!'), 'only infra-TAK'),
    ('takwerx-console.service', CONSOLE + '[Service]\nStandardOutput=file:/etc/sudoers.d/x\n', 'StandardOutput'),
    ('takwerx-console.service', CONSOLE + '[Service]\nBindPaths=/home/takwerx/s:/etc/sudoers\n', 'BindPaths'),
    ('takwerx-console.service', CONSOLE + '[Service]\nAmbientCapabilities=CAP_SYS_ADMIN\n', 'AmbientCapabilities'),
    ('takwerx-console.service', CONSOLE + '[Service]\nLoadCredential=x:/etc/shadow\n', 'LoadCredential'),
    ('takwerx-console.service', CONSOLE + '[Service]\nSupplementaryGroups=docker\n', 'docker'),
    ('takwerx-console.service', CONSOLE + '[Install]\nAlias=sshd.service\n', 'Alias'),
    ('takdiskguard.service', GUARD + 'Environment=LD_PRELOAD=/home/takwerx/x.so\n', 'LD_PRELOAD'),
    ('takdiskguard.service', GUARD + 'Environment=BASH_ENV=/home/takwerx/x\n', 'BASH_ENV'),
    ('takdiskguard.service', GUARD + 'Environment=PATH=/home/takwerx/bin:/usr/bin\n', 'PATH'),
    ('takdiskguard.service', GUARD + 'Environment=JAVA_HOME=/home/takwerx/jdk\n', 'console-writable'),
    ('takdiskguard.service', GUARD + 'EnvironmentFile=/home/takwerx/env\n', 'EnvironmentFile'),
    ('takdiskguard.service', GUARD + 'EnvironmentFile=-/var/log/env\n', 'EnvironmentFile'),
    ('takdiskguard.service', GUARD.replace('[Service]', '[Socket]'), 'section'),
    ('takdiskguard.timer', '[Timer]\nOnBootSec=1\nUnit=evil.service\n', 'Unit=evil'),
    ('takserver.service.d/soft-start.conf', '[Service]\nExecStartPre=+/home/takwerx/x\n', 'only infra-TAK'),
    ('takserver.service.d/soft-start.conf', '[Service]\nUser=root\n', 'drop-in may not set User'),
    ('caddy.service.d/10-takwerx-boot.conf', '[Service]\nExecStartPre=/opt/infratak/x\n', 'only infra-TAK'),
    ('mediamtx-webeditor.service.d/20-infratak-home.conf', '[Service]\nUser=root\n', 'drop-in may not set User'),
])
def test_unit_escape_is_refused(rel, text, why):
    refused(rel, text, why)


def test_append_to_a_unit_is_refused():
    v = write('takdiskguard.service', 'ExecStartPost=/home/takwerx/x\n', mode='a')
    assert v[0] == 'DENY' and 'append' in v[1]


@pytest.mark.parametrize('argv', [
    ['tee', '/etc/systemd/system/evil.service'],
    ['cp', '/tmp/evil.service', '/etc/systemd/system/takdiskguard.service'],
    ['cp', '-r', '/var/lib/infratak-backups/x', '/etc/systemd/system'],
    ['mv', '/var/log/x', '/etc/systemd/system/takdiskguard.service'],
    ['install', '-m', '0644', '/tmp/x', '/etc/systemd/system/x.service'],
    ['ln', '-s', '/etc/systemd/system', '/var/log/units'],
    ['ln', '/etc/systemd/system/takdiskguard.service', '/var/log/x'],          # hard link
    ['ln', '-s', '../../../etc/systemd/system', '/var/log/a/units'],
    ['ln', '-s', '/var/log/x', '/opt/tak-guarddog/tak-disk-watch.sh'],
    ['cp', '-l', '/etc/systemd/system/takdiskguard.service', '/var/log/x'],
    ['cp', '-s', '/etc/systemd/system/takdiskguard.service', '/var/log/x'],
    ['chown', 'takwerx', '/etc/systemd/system'],
    ['chown', '-R', 'takwerx:takwerx', '/opt/tak-guarddog'],
    ['chmod', '777', '/etc/systemd/system'],
    ['chmod', 'o+w', '/etc/systemd/system/takdiskguard.service'],
    ['chmod', 'g+w', '/opt/tak-guarddog/tak-disk-watch.sh'],
    ['install', '-o', 'takwerx', '-m', '0755', '/tmp/x', '/opt/tak-guarddog/tak-disk-watch.sh'],
    # flags that carried a path past the check (one command to root on W1 and dev)
    ['chmod', '-w,o+w', '/etc/passwd'],
    ['chmod', '--', '-w,o+w', '/etc/passwd'],
    ['chown', '--reference=/home/takwerx/node-red/f', '/etc/passwd'],
    ['mv', '--target-directory=/etc/sudoers.d', '/var/log/x'],
    ['ln', '--target-directory=/etc/sudoers.d', '/var/log/x'],
    ['cp', '-t', '/etc/sudoers.d', '/var/log/x'],
    ['cp', '--target-directory=/etc/sudoers.d', '/var/log/x'],
    ['install', '-t', '/etc/sudoers.d', '/var/log/x'],
    ['install', '-Dt', '/etc/sudoers.d', '/var/log/x'],
    ['touch', '--reference=/etc/shadow', '/var/log/x'],
])
def test_exec_route_around_the_unit_check_is_refused(argv):
    assert exec_verdict(argv).startswith('DENY'), argv


@pytest.mark.parametrize('argv', [
    # shapes from the test6/test12 broker audit logs and the console code
    ['chmod', '755', '/opt/tak-guarddog/tak-disk-watch.sh'],
    ['chmod', '600', '/opt/tak-guarddog/known_hosts'],
    ['chmod', '-R', '755', '/var/lib/cesium-tiles'],
    ['chown', 'root:root', '/opt/tak-guarddog/known_hosts'],
    ['chown', '-R', 'takwerx:takwerx', '/var/lib/takwerx-console'],
    ['chown', '-R', '-h', '--from=root:root', 'takwerx:takwerx', '/var/lib/takwerx-console'],
    ['mkdir', '-p', '/etc/systemd/system/takserver.service.d'],
    ['mkdir', '-p', '/etc/fail2ban/filter.d'],
    ['touch', '/var/lib/takguard/disk_alert_sent'],
    ['touch', '/etc/systemd/system/caddy.service.d/10-takwerx-acme-eab.conf'],
    ['chmod', '600', '/etc/systemd/system/caddy.service.d/10-takwerx-acme-eab.conf'],
    ['rm', '-f', '/etc/systemd/system/mediamtx-webeditor.service.d/20-infratak-home.conf'],
    ['rm', '-rf', '/var/lib/takguard/x'],
    ['cp', '-p', '/opt/tak/certs/files/a.p12', '/opt/tak/certs/files/b.p12'],
    ['cp', '-rp', '/opt/tak/certs/files', '/opt/tak/certs/files2'],
    ['cp', '-a', '/var/lib/caddy/x', '/var/lib/caddy/y'],
    ['install', '-D', '-m', '0644', '/tmp/x', '/usr/local/etc/mediamtx.yml'],
    ['install', '-m', '0755', '/tmp/caddy', '/usr/bin/caddy'],
    ['install', '-o', 'root', '-g', 'root', '-m', '0644', '/tmp/x', '/etc/caddy/Caddyfile'],
    ['mv', '-f', '/var/log/a', '/var/log/b'],
    ['ln', '-sfn', B.TAK_BUNDLE_DIR + '/tak', '/opt/tak'],
])
def test_console_exec_shapes_still_pass(argv):
    assert exec_verdict(argv) == 'ALLOW', exec_verdict(argv)


def test_security_level_raised_and_parseable():
    """W2 is a broker security fix, so the level went up (root refuses to install a
    lower level), and root must be able to read the line from a candidate commit."""
    src = (REPO / 'broker' / 'takwerx_broker.py').read_text()
    m = re.search(r'^BROKER_SECURITY_LEVEL = (\d+)\s*$', src, re.M)
    assert m and int(m.group(1)) == B.BROKER_SECURITY_LEVEL >= 2


# --- Security review: a lone `;` word starts a second command -------------------------
# systemd runs `ExecStartPre=/opt/tak-guarddog/tak-disk-watch.sh ; /tmp/evil.sh` as two
# commands. Each one is checked, with its own prefixes.

_ASSET = '/opt/tak-guarddog/tak-disk-watch.sh'


@pytest.mark.parametrize('key', ['ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop'])
@pytest.mark.parametrize('second', ['/tmp/evil.sh', '-/tmp/evil.sh', '/bin/sh -c id',
                                    '/usr/bin/python3 -c 1', '@/tmp/evil.sh evil'])
def test_second_command_after_semicolon_is_checked(key, second):
    text = GUARD + f'{key}={_ASSET} ; {second}\n'
    if key == 'ExecStart':
        text = GUARD.replace(f'ExecStart={_ASSET}', f'ExecStart={_ASSET} ; {second}')
    refused('takdiskguard.service', text)


@pytest.mark.parametrize('line', [
    f'ExecStartPre={_ASSET} ; +/tmp/evil.sh',        # + runs it as root in a non-root unit
    f'ExecStartPre={_ASSET} ; !/tmp/evil.sh',
    f'ExecStartPost=/opt/infratak/.venv/bin/python3 /opt/infratak/selfheal_ip.py ; +/tmp/x',
])
def test_privileged_prefix_on_a_later_command_is_checked(line):
    refused('takwerx-console.service', CONSOLE.replace('Restart=always\n', line + '\nRestart=always\n'))


@pytest.mark.parametrize('line', [
    f'ExecStartPre={_ASSET} \\; /tmp/evil.sh',     # escaped: one literal argument
    f'ExecStartPre={_ASSET} ";" /tmp/evil.sh',      # quoted: one literal argument
    f"ExecStartPre={_ASSET} ';' /tmp/evil.sh",
    f'ExecStartPre={_ASSET} ;',                      # empty command
    f'ExecStartPre=; {_ASSET}',
    f'ExecStartPre={_ASSET} ; ; {_ASSET}',
    f'ExecStartPre={_ASSET} ; -',
])
def test_odd_semicolons_are_refused(line):
    refused('takdiskguard.service', GUARD + line + '\n')


def test_two_infra_tak_commands_still_pass():
    ok('takdiskguard.service', GUARD + f'ExecStartPre={_ASSET} ; -{_ASSET}\n')
    # a `;` inside a word is a literal argument, not a separator
    ok('takdiskguard.service', GUARD + f'ExecStartPre={_ASSET} a;b\n')
    # non-root unit: a later command without + or ! runs as the unit's user
    ok('takwerx-console.service', CONSOLE.replace(
        'Restart=always\n', 'ExecStartPost=/opt/infratak/.venv/bin/python3 /opt/infratak/selfheal_ip.py'
        ' ; /opt/infratak/.venv/bin/python3 /opt/infratak/selfheal_ip.py\nRestart=always\n'))


# --- Security re-review: read the lines the way systemd does, or refuse the shape ------
# systemd.syntax: "When a comment line or lines follow a line ending with a backslash,
# the comment block is ignored, so the continued line is concatenated with whatever
# follows the comment block." So systemd reads the shapes below as ONE Exec line whose
# second command (`+/tmp/evil.sh`) runs as root. A checker that ends the line at the
# comment never looks at it. All were ALLOWED on 5633722.
# https://www.freedesktop.org/software/systemd/man/latest/systemd.syntax.html

_CONT_KEYS = ['ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop']
_COMMENT_BLOCKS = {
    'hash': ['# c'],
    'semi': ['; c'],
    'indented': ['   # c'],
    'two': ['# a', '; b'],
    'hash-blank': ['# c', ''],
    'blank-hash': ['', '# c'],
    'blank': [''],
}


def _continued(key, block, tail='RestartSec=5 ; +/tmp/evil.sh'):
    body = '\n'.join([f'{key}={_ASSET} \\'] + block + [tail]) + '\n'
    if key == 'ExecStart':
        return GUARD.replace(f'ExecStart={_ASSET}\n', body)
    return GUARD + body


@pytest.mark.parametrize('key', _CONT_KEYS)
@pytest.mark.parametrize('block', sorted(_COMMENT_BLOCKS))
def test_comment_or_blank_line_inside_a_continuation_is_refused(key, block):
    refused('takdiskguard.service', _continued(key, _COMMENT_BLOCKS[block]), 'inside a line continuation')


def test_security_review_shape_exactly():
    text = ('[Service]\nType=oneshot\nExecStart=/opt/tak-guarddog/tak-disk-watch.sh \\\n'
            '# c\nRestartSec=5 ; +/tmp/evil.sh\n')
    refused('takdiskguard.service', text)


@pytest.mark.parametrize('ch', ['\r', '\x0b', '\x0c', '\x85', '\u2028', '\u2029', '\x1c', '\x1e',
                                '\x1b', '\ufeff', '\x7f'])
@pytest.mark.parametrize('where', ['keyline', 'crlf', 'in-value'])
def test_control_and_line_separator_characters_are_refused(ch, where):
    if where == 'keyline':
        text = GUARD + f'{ch}ExecStartPre=+/tmp/evil.sh\n'
    elif where == 'crlf':
        text = GUARD.replace('\n', ch + '\n')
    else:
        text = GUARD + f'Description=a{ch}b\n'
    refused('takdiskguard.service', text)


# systemd counts escapes and does not strip trailing spaces first: a line ending in `\\`
# or in `\` + spaces is NOT a continuation to it. A checker that strips first, or only
# looks at the last character, joins the next line in and never checks it as its own.
@pytest.mark.parametrize('first', [f'ExecStart={_ASSET} a\\\\', f'ExecStart={_ASSET} a\\\\\\',
                                   f'ExecStart={_ASSET} \\ ', f'ExecStart={_ASSET} \\\t'])
def test_backslash_endings_systemd_reads_differently_are_refused(first):
    text = GUARD.replace(f'ExecStart={_ASSET}\n', first + '\nExecStartPre=+/tmp/evil.sh\n')
    refused('takdiskguard.service', text)


def test_comment_line_ending_in_a_backslash_is_refused():
    # systemd >= 235 skips it; older systemd joined the next line into the comment
    refused('takdiskguard.service', GUARD + '# note \\\nExecStartPre=/tmp/evil.sh\n')


@pytest.mark.parametrize('line', [
    'RestartSec=5 \\\n  ; +/tmp/evil.sh',
    'Description=a \\\n  b',
    'Environment=A=1 \\\n  B=2',
    'Type=oneshot \\\n  ',
])
def test_continuation_outside_exec_lines_is_refused(line):
    refused('takdiskguard.service', GUARD + line + '\n')


def test_continuation_in_a_section_header_is_refused():
    refused('takdiskguard.service', GUARD.replace('[Service]', '[Serv\\\nice]'))


@pytest.mark.parametrize('k', ['LD_PRELOAD\n', 'A B', 'A-B', '1A', 'A.B', ''])
def test_odd_environment_names_are_refused_for_root(k):
    import shlex
    refused('takdiskguard.service', GUARD + f'Environment={shlex.quote(k + "=x")}\n')


def test_unit_name_with_a_trailing_newline_is_refused():
    assert B._unit_name_ok('takdiskguard.service')
    assert not B._unit_name_ok('takdiskguard.service\n')


def test_plain_continuations_in_exec_lines_still_pass():
    ok('takdiskguard.service', GUARD.replace(
        f'ExecStart={_ASSET}\n', f'ExecStart={_ASSET} \\\n    --quiet\n'))
    ok('takdiskguard.service', GUARD + f'ExecStartPre={_ASSET} ; \\\n  -{_ASSET}\n')
    # a continued line that starts with `;` is a comment to systemd too: refused
    refused('takdiskguard.service', GUARD + f'ExecStartPre={_ASSET} \\\n  ; -{_ASSET}\n')
    # tabs are fine
    ok('takdiskguard.service', GUARD.replace('Type=oneshot', 'Type=\toneshot'))


def test_broker_source_has_no_raw_control_or_line_separator_characters():
    """A raw U+2028 in the source is a line break to str.splitlines() but not to the
    Python parser, so line-based tools (redteam-selfaudit) read the wrong lines."""
    src = (REPO / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')
    bad = re.findall('[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\ufeff]', src)
    assert not bad, f'write these as escapes: {sorted(set(bad))!r}'


# --- Security re-review #2: systemd decodes escapes and specifiers, the checker did not ---
# `ExecStart=/opt/tak-guarddog/..\x2f..\x2ftmp/evil.sh` was ALLOW: shlex drops the `\`,
# systemd 255 turns `\x2f` into `/` and runs /tmp/evil.sh as root (systemd-analyze
# verify). Same with `\057`, quoted or not, and with specifiers (`%T` is /tmp). Every
# `\` and `%` in a unit value is refused now; root paths are plain and normalised.
# The Exec shapes were also read by a real systemd: ops645 evidence `sdparse-escapes.sh`.

_ESC = '/opt/tak-guarddog/..\\x2f..\\x2ftmp/evil.sh'
_OCT = '/opt/tak-guarddog/..\\057..\\057tmp/evil.sh'


@pytest.mark.parametrize('key', ['ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop'])
@pytest.mark.parametrize('cmd', [
    _ESC, _OCT, f"'{_ESC}'", f'"{_ESC}"', f"'{_OCT}'", f'"{_OCT}"',
    '/opt/tak-guarddog/\\x2e\\x2e/\\x2e\\x2e/tmp/evil.sh',
    f'/usr/bin/python3 {_ESC}', f'/usr/bin/python3 -I "{_OCT}"', f'/bin/bash {_ESC}',
    '/%T/evil.sh', '/opt/tak-guarddog/%h', '%t/evil.sh', '/opt/tak-guarddog/tak-disk-watch.sh %h',
    # `..` or `.` written plainly, and `$VAR` words, in the binary or the script word
    '/opt/tak-guarddog/../../tmp/evil.sh', '/opt/tak-guarddog/./tak-disk-watch.sh',
    '/usr/bin/python3 /opt/tak-guarddog/../../tmp/x.py',
    '/usr/bin/python3 /opt/tak-guarddog/${X}/${X}/tmp/x.py', '/bin/bash /opt/tak-guarddog/$X',
    '/bin/bash /opt/tak-guarddog//tak-disk-watch.sh',
])
def test_escaped_or_unnormalised_root_paths_are_refused(key, cmd):
    refused('takdiskguard.service', GUARD + f'Environment=X=..\n{key}={cmd}\n')


@pytest.mark.parametrize('cmd', [f'+{_ESC}', f'+"{_OCT}"', '+/%T/evil.sh', '!/opt/tak-guarddog/..\\x2fx'])
def test_escaped_privileged_command_in_a_non_root_unit_is_refused(cmd):
    refused('takwerx-console.service', CONSOLE.replace('ExecStartPre=-', f'ExecStartPre={cmd} ; -'))


@pytest.mark.parametrize('line', [
    'Environment=\\x4cD_PRELOAD=/usr/bin\\x2f..\\x2f..\\x2ftmp\\x2fx.so',
    'Environment="\\x4cD_PRELOAD=/opt/tak-guarddog/x.so"',
    'Environment=JAVA_HOME=/usr/bin\\x2f..\\x2f..\\x2ftmp',
    "Environment='JAVA_HOME=/usr/bin\\057..\\057..\\057tmp'",
    'Environment=JAVA_HOME=%h/jdk', 'Environment=JAVA_HOME=/%T/jdk', 'Environment=A=%t',
    'EnvironmentFile=-/usr/bin\\x2f..\\x2f..\\x2ftmp\\x2fenv',
    'EnvironmentFile=/usr/bin\\057..\\057..\\057tmp\\057env',
    'EnvironmentFile=/%T/env', 'EnvironmentFile=-/%h/env', 'EnvironmentFile=/%t/env',
    'EnvironmentFile=/usr/bin/../../tmp/env', 'EnvironmentFile=-/etc/./default/takserver',
    'EnvironmentFile=/etc/default/take"r"', "EnvironmentFile='/etc/default/takserver'",
])
def test_escaped_environment_lines_are_refused_for_root(line):
    refused('takdiskguard.service', GUARD + line + '\n')


@pytest.mark.parametrize('line', [
    'Description=90% full', 'Description=a\\x20b', 'User=\\x74akwerx', 'User=%u',
    'WorkingDirectory=%h', 'ReadOnlyPaths=/opt/tak-guarddog/%n',
])
def test_escapes_and_specifiers_are_refused_in_every_key(line):
    refused('takwerx-console.service', CONSOLE.replace('[Service]\n', f'[Service]\n{line}\n'), 'specifier')


def test_plain_root_paths_still_pass():
    ok('takdiskguard.service', GUARD + 'EnvironmentFile=-/etc/environment\n')
    ok('takdiskguard.service', GUARD + 'ExecStartPost=/usr/bin/python3 -I /opt/tak-guarddog/tak-health-endpoint.py\n')
    ok('takdiskguard.service', GUARD + 'ExecStartPost=/bin/bash /opt/tak-guarddog/tak-disk-watch.sh --quiet\n')
    ok('takclientgate.service', '[Unit]\nDescription=g\n\n[Service]\nType=oneshot\n'
       'ExecStart=/opt/tak-guarddog/tak-client-gate.sh release\n')
