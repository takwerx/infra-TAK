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
"""ops #645 W2.5: Docker routes around the broker's root-run rules.

Each of these was ALLOWED in ENFORCE on dev de59e37 (rulebook dry run):
  1. `docker cp <c>:/x /etc/systemd/system/evil.service` and into /opt/tak-guarddog:
     root wrote the file directly, past the unit checker and the Guard Dog lock.
  2. `docker run -v /var:/v …`, `-v /opt:/o …`: the bind deny list missed /var, /opt,
     /srv and /mnt.
  3. A named volume with a host path (the ATLAS pgdata volume) was checked only when
     it was made. The console owns the folders above it, so it could swap `pgdata`
     for a link and the next container start mounted the link target as root.
  4. `docker build -t x /root`, `docker load -i /root/x.tar`: root read any host path.

Nothing is executed: the rulebook is called directly, and the Docker API answers
are stubbed.
"""

import importlib.util
import os
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_w25',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()
HOME = B._NONROOT_HOME


def _denied(argv, cwd=None):
    with pytest.raises(B.Denied):
        B.check_exec(argv, cwd)


def _allowed(argv, cwd=None):
    B.check_exec(argv, cwd)


# ---------------------------------------------------------------------------
# 1. docker cp into a unit, a validated file or a root-run script: never by root
# ---------------------------------------------------------------------------
ROOT_RUN_DESTS = [
    '/etc/systemd/system/evil.service',
    '/etc/systemd/system/',
    '/etc/systemd/system/takserver.service.d/x.conf',
    '/opt/tak-guarddog/tak-health.sh',
    '/opt/tak-guarddog/',
    '/usr/local/sbin/tak-console-restart.sh',
    '/etc/fail2ban/action.d/x.conf',
    '/etc/sysctl.d/99-x.conf',
    '/etc/docker/daemon.json',
    '/var/lib/takguard/state',
]


@pytest.mark.parametrize('dest', ROOT_RUN_DESTS)
def test_docker_cp_into_a_root_run_place_goes_through_the_console_user(dest):
    argv = ['docker', 'cp', 'authentik-worker-1:/tmp/x', dest]
    _allowed(argv)                                  # not refused: staged instead
    assert B._docker_cp_needs_stage(argv) is True, dest
    argv = ['docker', 'container', 'cp', 'c:/x', dest]
    assert B._docker_cp_needs_stage(argv) is True, dest


@pytest.mark.parametrize('dest', [
    '/var/lib/infratak-backups/2026/tak-db.dump',   # app.py: TAK DB dump to the backup dir
    HOME + '/CloudTAK/x.json',
    '-',
])
def test_docker_cp_to_a_data_place_is_still_direct(dest):
    assert B._docker_cp_needs_stage(['docker', 'cp', 'c:/x', dest]) is False


def test_docker_cp_reading_from_the_host_is_unchanged():
    # host -> container reads; the TAK Portal settings push copies a tmp file in
    assert B._docker_cp_needs_stage(['docker', 'cp', '/etc/caddy/Caddyfile', 'c:/x']) is False


# ---------------------------------------------------------------------------
# 2. bind mounts: an allow list
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('src', [
    '/var', '/var/spool/cron', '/var/lib/dpkg/info', '/var/lib/takwerx-broker',
    '/opt', '/opt/tak-guarddog', '/opt/infratak', '/srv', '/mnt', '/media',
    '/var/lib/docker', '/usr/local/lib/infratak-broker', '/tmp', '/tmp/sub/x',
    '/etc/ssl/certs/ca-certificates.crt',          # allowed only read-only
])
@pytest.mark.parametrize('form', ['run', 'create', 'container run', 'compose run'])
def test_bind_outside_the_module_folders_is_refused(src, form):
    if form == 'compose run' and (src == '/tmp' or src.startswith('/tmp/')):
        pytest.skip('compose run keeps /tmp (CloudTAK build step) until W3')
    head = ['docker'] + form.split()
    if form == 'compose run':
        argv = head + ['-v', src + ':/v', 'svc', 'sh']
    else:
        argv = head + ['-v', src + ':/v', 'alpine', 'sh']
    _denied(argv)
    if form != 'compose run':
        _denied(head + ['--mount', 'type=bind,source=%s,target=/v' % src, 'alpine'])


def test_tmp_bind_needs_an_existing_plain_file(tmp_path):
    # /tmp/<name> only; a missing file or a folder is refused
    _denied(['docker', 'run', '--rm', '-v', '/tmp/ops645-w25-missing.yml:/x', 'node:22-alpine'])


def test_cloudtak_marketplace_align_binds_still_pass(tmp_path):
    """The docker run the CloudTAK Marketplace step sends (audit logs, test6 and test12)."""
    names = []
    for n in ('ctak-marketplace-align-w25.cjs', 'ctak-overlay.w25.yml', 'ctak-base.w25.yml'):
        p = '/tmp/' + n
        with open(p, 'w') as fh:
            fh.write('x')
        names.append(p)
    try:
        _allowed(['docker', 'run', '--rm', '-u', '0',
                  '-v', names[0] + ':/align.cjs:ro', '-v', names[1] + ':/overlay.yml',
                  '-v', names[2] + ':/base.yml:ro', 'node:22-alpine', 'node', '/align.cjs',
                  '--fix-compose'])
    finally:
        for p in names:
            os.unlink(p)


def test_tmp_link_is_refused():
    link = '/tmp/ops645-w25-link.yml'
    if os.path.lexists(link):
        os.unlink(link)
    os.symlink('/etc/hosts', link)
    try:
        _denied(['docker', 'run', '-v', link + ':/x', 'alpine'])
    finally:
        os.unlink(link)


def test_bundle_binds_still_pass():
    # the TAK Docker runs in app.py bind realpath('/opt/tak'), inside the bundle
    _allowed(['docker', 'run', '--rm', '-v', B.TAK_BUNDLE_DIR + '/tak:/opt/tak:z',
              '--entrypoint', 'bash', 'takserver', '-c', 'true'])


@pytest.mark.parametrize('src', [HOME + '/CloudTAK/api', HOME + '/atlas/agency/store',
                                 '/root/webodm/media'])
def test_module_dirs_stay_refused_for_docker_run(src):
    # refused before W2.5 too (/home and /root were on the old deny list); not widened
    _denied(['docker', 'run', '--rm', '-v', src + ':/x', 'alpine'])


@pytest.mark.skipif(os.path.islink('/tmp'), reason='/tmp is a link on macOS; CI is Linux')
def test_compose_run_home_and_tmp_still_pass():
    # CloudTAK's build step mounts the console home and /tmp
    _allowed(['docker', 'compose', 'run', '--rm', '-v', HOME + ':/h', '-v', '/tmp:/t', 'api', 'sh'])


def test_named_volumes_still_pass():
    # app.py: the 5.8 rollback copy binds two NAMED volumes
    _allowed(['docker', 'run', '--rm', '--user', '0', '-v', 'takserver_pgsql:/from',
              '-v', 'takserver_pgsql_rollback:/to', '--entrypoint', 'sh', 'takserver',
              '-c', 'cp -a /from/. /to/'])


@pytest.mark.parametrize('spec', ['/opt/tak/certs/files:/certs:ro', '/opt/tak:/opt/tak',
                                  '/opt/tak/certs/files/admin.key:/k:ro'])
def test_native_tak_folder_is_refused(spec):
    # native TAK keeps its CA keys here, readable only by `tak`; allowed before W2.5
    _denied(['docker', 'run', '-v', spec, 'alpine'])


def test_bind_sources_are_rewritten_to_the_checked_realpath(tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    link = tmp_path / 'link'
    link.symlink_to(real)
    rp = os.path.realpath(str(real))
    out = B._docker_bind_realpaths(['docker', 'run', '-v', f'{link}:/d:ro', '--name', 'n',
                                    '--mount', f'type=bind,src={link},dst=/e', 'img', '-v', 'x'])
    assert out == ['docker', 'run', '-v', f'{rp}:/d:ro', '--name', 'n',
                   '--mount', f'type=bind,src={rp},dst=/e', 'img', '-v', 'x']
    out = B._docker_bind_realpaths(['docker', 'container', 'create', f'--volume={link}:/d', 'img'])
    assert out == ['docker', 'container', 'create', f'--volume={rp}:/d', 'img']
    same = ['docker', 'exec', 'c', 'ls', str(link)]
    assert B._docker_bind_realpaths(same) == same
    named = ['docker', 'run', '-v', 'vol:/d', 'img']
    assert B._docker_bind_realpaths(named) == named


# ---------------------------------------------------------------------------
# 3. a host-path volume is checked again at every start (Security review 1)
# ---------------------------------------------------------------------------
@pytest.fixture
def atlas(tmp_path, monkeypatch):
    """A fake ATLAS module dir under tmp, a volume made by the console, and a stubbed
    Docker API that answers with it."""
    root = tmp_path / 'atlas'
    pg = root / 'agency' / 'store' / 'pgdata'
    pg.mkdir(parents=True)
    rootp = str(root) + '/'
    monkeypatch.setattr(B, '_ATLAS_VOLUME_ROOTS', (rootp,))

    def path_allowed(p, readonly=False):
        if not B._within_realpath(p, str(root)):
            raise B.Denied('symlink escape from console-owned dir: ' + p)
        return p
    monkeypatch.setattr(B, '_path_allowed', path_allowed)
    vol = {'Name': 'takmdm-agency_pgdata', 'Driver': 'local',
           'Options': {'type': 'none', 'o': 'bind', 'device': str(pg)}}
    plain = {'Name': 'authentik_database', 'Driver': 'local', 'Options': None}
    answers = {
        '/volumes/takmdm-agency_pgdata': vol,
        '/volumes/authentik_database': plain,
        '/volumes': {'Volumes': [plain, vol]},
        '/containers/takmdm-agency-db-1/json': {
            'Mounts': [{'Type': 'volume', 'Name': 'takmdm-agency_pgdata'}]},
        '/containers/authentik-postgresql-1/json': {
            'Mounts': [{'Type': 'volume', 'Name': 'authentik_database'}]},
    }
    monkeypatch.setattr(B, '_docker_get', lambda path: answers.get(path), raising=False)
    return {'root': root, 'pg': pg, 'vol': vol}


START_CMDS = [
    ['docker', 'start', 'takmdm-agency-db-1'],
    ['docker', 'restart', '-t', '5', 'takmdm-agency-db-1'],
    ['docker', 'container', 'start', 'takmdm-agency-db-1'],
    ['docker', 'run', '-d', '-v', 'takmdm-agency_pgdata:/var/lib/postgresql/data', 'postgres'],
    ['docker', 'run', '-d', '--mount', 'source=takmdm-agency_pgdata,target=/d', 'postgres'],
    ['docker', 'compose', '-p', 'takmdm-agency', 'up', '-d'],
    ['docker', 'compose', '-f', 'docker-compose.yml', 'restart'],
]


@pytest.mark.parametrize('argv', START_CMDS)
def test_volume_start_passes_while_the_folder_is_real(atlas, argv):
    _allowed(argv)


@pytest.mark.parametrize('argv', START_CMDS)
def test_volume_start_refused_after_pgdata_becomes_a_link(atlas, argv, tmp_path):
    pg = atlas['pg']
    pg.rename(pg.parent / 'pgdata.moved')
    os.symlink('/etc', str(pg))
    _denied(argv)


@pytest.mark.parametrize('argv', START_CMDS)
def test_volume_start_refused_after_a_parent_becomes_a_link(atlas, argv, tmp_path):
    store = atlas['pg'].parent
    elsewhere = tmp_path / 'elsewhere' / 'store'
    (elsewhere / 'pgdata').mkdir(parents=True)
    store.rename(store.parent / 'store.moved')
    os.symlink(str(elsewhere), str(store))
    _denied(argv)


def test_volume_with_other_options_is_refused(atlas):
    atlas['vol']['Options'] = {'type': 'none', 'o': 'bind,suid', 'device': str(atlas['pg'])}
    _denied(['docker', 'start', 'takmdm-agency-db-1'])
    atlas['vol']['Options'] = {'type': 'tmpfs', 'device': 'tmpfs'}
    _denied(['docker', 'compose', 'up', '-d'])


def test_other_containers_and_commands_unaffected(atlas):
    pg = atlas['pg']
    pg.rename(pg.parent / 'pgdata.moved')
    os.symlink('/etc', str(pg))
    # a start that does not use the bad volume, and commands that start nothing
    _allowed(['docker', 'start', 'authentik-postgresql-1'])
    _allowed(['docker', 'stop', 'takmdm-agency-db-1'])
    _allowed(['docker', 'compose', 'ps'])
    _allowed(['docker', 'compose', 'down'])


# ---------------------------------------------------------------------------
# 4. docker build / load read host paths as root
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('argv,cwd', [
    (['docker', 'build', '-t', 'x', '/root'], None),
    (['docker', 'build', '-t', 'x', '/etc'], None),
    (['docker', 'build', '-t', 'x', '.'], None),                     # cwd / by default
    (['docker', 'build', '-t', 'x', '.'], '/etc'),
    (['docker', 'build', '-t', 'x', '-f', '/etc/shadow', HOME + '/CloudTAK'], None),
    (['docker', 'build', '-t', 'x', '--file=/root/Dockerfile', HOME + '/CloudTAK'], None),
    (['docker', 'build', '-t', 'x', '-f', '../../etc/shadow', '.'], HOME + '/CloudTAK'),
    (['docker', 'image', 'build', '-t', 'x', '/root'], None),
    (['docker', 'buildx', 'build', '-t', 'x', '/root'], None),
    (['docker', 'build', '--secret', 'id=s,src=/etc/shadow', '-t', 'x', HOME + '/CloudTAK'], None),
    (['docker', 'build', '--build-context', 'r=/root', '-t', 'x', HOME + '/CloudTAK'], None),
    (['docker', 'build', '--ssh', 'default=/root/.ssh/id_ed25519', HOME + '/CloudTAK'], None),
    (['docker', 'load', '-i', '/root/x.tar'], None),
    (['docker', 'load', '--input=/var/lib/takwerx-broker/x.tar'], None),
    (['docker', 'image', 'load', '-i', '/etc/x.tar'], None),
])
def test_build_and_load_outside_the_console_folders_refused(argv, cwd):
    _denied(argv, cwd)


@pytest.mark.parametrize('argv,cwd', [
    # app.py call sites (and the test6/test12 audit logs)
    (['docker', 'build', '--label', 'infratak.shim=abc', '-t', 'infratak-etl-shim:local',
      B.CONSOLE_REPO_DIR + '/modules/etlrunner/shim'], None),
    (['docker', 'build', '--network', 'cloudtak_etl', '--force-rm',
      '--label', 'infratak.caps={"name": "ADS-B Exchange", "x": 1}', '--label', 'infratak.sha=1',
      '-t', 'etl:1', HOME + '/.cache/infratak-etl-src/adsb'], None),
    (['docker', 'build', '--no-cache', '--pull', '-t', 'takserver-db:refresh',
      '-f', 'docker/Dockerfile.takserver-db.refresh', '.'], B.TAK_BUNDLE_DIR + '/v5'),
    (['docker', 'build', '--pull', '-t', 'takserver', '-f', 'docker/Dockerfile.takserver', '.'],
     B.TAK_BUNDLE_DIR),
    (['docker', 'build', '-t', 'ghcr.io/dfpc-coe/media-infra:v1', HOME + '/CloudTAK/media-infra-src'],
     None),
    (['docker', 'build', '-t', 'x', '-'], None),
    (['docker', 'build', '-t', 'x', 'https://github.com/dfpc-coe/media-infra.git#v1'], None),
    (['docker', 'load'], None),
    (['docker', 'load', '-i', HOME + '/tak-docker/takserver.tar'], None),
    (['docker', 'buildx', 'ls'], None),
])
def test_build_and_load_call_sites_still_pass(argv, cwd, monkeypatch):
    # on a box these folders exist; here they do not, so take the cwd as given
    monkeypatch.setattr(B, '_effective_cwd', lambda c: c or '/', raising=False)
    _allowed(argv, cwd)


def test_build_with_a_missing_cwd_is_checked_against_slash():
    # _do_exec drops a cwd that is not a folder and runs in /, so the check does too
    _denied(['docker', 'build', '-t', 'x', '.'], HOME + '/CloudTAK/no-such-folder-w25')


def test_build_paths_are_rewritten_to_the_checked_realpath(tmp_path):
    real = tmp_path / 'ctx'
    (real / 'docker').mkdir(parents=True)
    link = tmp_path / 'link'
    link.symlink_to(real)
    rp = os.path.realpath(str(real))
    out = B._docker_build_realpaths(
        ['docker', 'build', '--label', 'a=b c', '-t', 'x', '-f', 'docker/Dockerfile', '.'], str(link))
    assert out == ['docker', 'build', '--label', 'a=b c', '-t', 'x',
                   '-f', rp + '/docker/Dockerfile', rp]
    out = B._docker_build_realpaths(['docker', 'image', 'build', '--file=' + str(link) + '/D',
                                     str(link)], None)
    assert out == ['docker', 'image', 'build', '--file=' + rp + '/D', rp]
    out = B._docker_build_realpaths(['docker', 'load', '-i', str(link) + '/i.tar'], None)
    assert out == ['docker', 'load', '-i', rp + '/i.tar']
    same = ['docker', 'build', '-t', 'x', '-']
    assert B._docker_build_realpaths(same, None) == same
    same = ['docker', 'build', '-t', 'x', 'https://github.com/a/b.git#v1']
    assert B._docker_build_realpaths(same, None) == same
    same = ['docker', 'ps']
    assert B._docker_build_realpaths(same, None) == same


# ---------------------------------------------------------------------------
# 5. no setuid in the console's folders (Security review 5)
# ---------------------------------------------------------------------------
MOUNTINFO = (
    '22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw,discard\n'
    '25 22 0:22 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw\n'
    '40 22 0:40 / /tmp rw,relatime shared:9 - tmpfs tmpfs rw\n'
    '41 22 252:2 / /home rw,relatime shared:10 - ext4 /dev/vg/home rw\n'
)


def test_nosuid_plan_binds_folders_that_are_not_mount_points():
    mounts = B._mountinfo(MOUNTINFO)
    plan = B._nosuid_plan(['/home/takwerx', '/opt/infratak', '/tmp', '/var/tmp', '/dev/shm'],
                          mounts)
    assert plan == [
        ['mount', '--rbind', '/home/takwerx', '/home/takwerx'],
        ['mount', '-o', 'remount,bind,nosuid,nodev', '/home/takwerx'],
        ['mount', '--rbind', '/opt/infratak', '/opt/infratak'],
        ['mount', '-o', 'remount,bind,nosuid,nodev', '/opt/infratak'],
        ['mount', '-o', 'remount,bind,nosuid,nodev', '/tmp'],          # own mount: remount only
        ['mount', '--rbind', '/var/tmp', '/var/tmp'],
        ['mount', '-o', 'remount,bind,nosuid,nodev', '/var/tmp'],
    ]                                                                   # /dev/shm already done


def test_nosuid_plan_is_idempotent():
    done = MOUNTINFO + ''.join(
        '9%d 22 252:1 /x %s rw,nosuid,nodev,relatime shared:1 - ext4 /dev/vda1 rw\n' % (n, d)
        for n, d in enumerate(['/home/takwerx', '/opt/infratak', '/tmp', '/var/tmp']))
    assert B._nosuid_plan(['/home/takwerx', '/opt/infratak', '/tmp', '/var/tmp', '/dev/shm'],
                          B._mountinfo(done)) == []


def test_mountinfo_decodes_spaces():
    m = B._mountinfo('50 22 0:1 / /home/a\\040b rw,nosuid,nodev - ext4 x rw\n')
    assert m == {'/home/a b': {'rw', 'nosuid', 'nodev'}}


def test_nosuid_targets_cover_home_repo_and_temp(monkeypatch, tmp_path):
    home = tmp_path / 'home' / 'takwerx'
    (home / 'infra-TAK').mkdir(parents=True)
    repo = tmp_path / 'opt' / 'infratak'
    repo.mkdir(parents=True)
    monkeypatch.setattr(B, '_HOME_ROOTS', (str(home),))
    monkeypatch.setattr(B, 'CONSOLE_REPO_DIR', str(repo))
    t = B._nosuid_targets()
    assert str(home) in t and str(repo) in t
    assert '/' not in t
    # a repo inside the home is covered by the home's rbind
    monkeypatch.setattr(B, 'CONSOLE_REPO_DIR', str(home / 'infra-TAK'))
    assert str(home / 'infra-TAK') not in B._nosuid_targets()
    # a home that is a link is never bound (realpath could be anywhere)
    link = tmp_path / 'homelink'
    link.symlink_to(home)
    monkeypatch.setattr(B, '_HOME_ROOTS', (str(link),))
    assert str(link) not in B._nosuid_targets()


def test_nosuid_unit_runs_before_docker_and_the_console():
    t = B.NOSUID_UNIT_TEXT
    assert 'Before=docker.service containerd.service takwerx-console.service' in t
    assert 'DefaultDependencies=no' in t and 'Type=oneshot' in t and 'RemainAfterExit=yes' in t
    assert ('ExecStart=/usr/bin/python3 -I /usr/local/lib/infratak-broker/current/broker/'
            'takwerx_broker.py nosuid') in t
    assert 'WantedBy=sysinit.target' in t


@pytest.mark.parametrize('path', ['/etc/systemd/system/infratak-nosuid.service',
                                  '/etc/systemd/system/infratak-nosuid.service.d/10-x.conf'])
def test_console_cannot_write_the_nosuid_unit(path):
    with pytest.raises(B.Denied):
        B._path_allowed(path)


@pytest.mark.parametrize('argv', [
    ['systemctl', 'disable', 'infratak-nosuid.service'],
    ['systemctl', 'mask', 'infratak-nosuid'],
    ['systemctl', '--runtime', 'mask', 'infratak-nosuid.service'],
    ['systemctl', 'stop', 'infratak-nosuid'],
    ['systemctl', 'disable', '--now', 'docker', 'infratak-nosuid.service'],
    ['systemctl', 'mask', 'infratak-*'],
    ['systemctl', 'disable', '/etc/systemd/system/infratak-nosuid.service'],
])
def test_console_cannot_switch_the_nosuid_unit_off(argv):
    _denied(argv)


@pytest.mark.parametrize('argv', [
    ['systemctl', 'status', 'infratak-nosuid'],
    ['systemctl', 'restart', 'infratak-nosuid.service'],
    ['systemctl', 'disable', 'infratak-kernel-patch.service'],
    ['systemctl', 'stop', 'docker'],
])
def test_other_systemctl_calls_unchanged(argv):
    _allowed(argv)


def test_fold_home_lifts_the_bind_before_unmounting(monkeypatch):
    calls = []
    monkeypatch.setattr(B, '_nosuid_targets', lambda: ['/home/takwerx', '/opt/infratak', '/tmp'])
    monkeypatch.setattr(B, '_mountinfo', lambda text=None: {'/home/takwerx': {'nosuid'},
                                                              '/opt/infratak': {'nosuid'}})
    B._nosuid_release_under('/home', [], run=lambda cmd, **kw: calls.append(cmd) or
                            type('R', (), {'returncode': 0})())
    assert [c[1:] for c in calls] == [['-R', '/home/takwerx']]
