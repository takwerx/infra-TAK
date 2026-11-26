"""ops #1266 part B: re-home ATLAS when a box is flipped from root to non-root.

The startup re-home list in app.py moved TAK Portal, CloudTAK, NetBird, Node-RED,
Remote Assist and Authentik, and not ATLAS. On CORAZ the three ATLAS containers
kept serving from /root/atlas/default while the non-root console could not enter
it, so it could not update, restart or read logs for them.

These tests run the shipped `rehome_root_era` against a small model of Docker and
the broker. The model is what makes the interesting cases testable: the database
volume is a *bind* volume (`-o device=<deployment>/store/pgdata`), so a move that
does not re-point it leaves Postgres starting on a directory that is not there.
Real Docker is exercised on a box (ops #1266); this holds the order of steps and
every refusal.
"""
import ast
import os
import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import modules.atlas as atlas  # noqa: E402

APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _real_rewrite():
    """The shipped `_rehome_rewrite_paths`, cut out of app.py (it cannot be
    imported in a test), so the module is tested with the helper it really gets."""
    def node(cls, name):
        return next(n for n in TREE.body if isinstance(n, cls) and (
            n.name == name if cls is ast.FunctionDef else
            any(isinstance(t, ast.Name) and t.id == name for t in n.targets)))
    ns = {'os': os, 're': re}
    src = '\n\n'.join(ast.get_source_segment(APP, node(c, n)) for c, n in (
        (ast.Assign, '_REHOME_COMPOSE_FILE_RE'),
        (ast.FunctionDef, '_rehome_rewrite_paths')))
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns['_rehome_rewrite_paths']


class R:
    def __init__(self, rc=0, out=''):
        self.returncode, self.stdout, self.stderr = rc, out, ''


class World:
    """Docker + the broker, enough to tell a working move from a broken one."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.root = tmp_path / 'root' / 'atlas'
        self.home = tmp_path / 'home'
        self.home.mkdir()
        self.root.mkdir(parents=True)
        self.containers = {}   # name -> {'project','workdir','running'}
        self.volumes = {}      # name -> device ('' = Docker-managed)
        self.anon = {}         # project -> anonymous volume name
        self.names = {}        # directory basename -> project
        self.calls = []        # ordered record of what was done
        self.stubborn = set()  # projects whose `stop` does nothing
        self.fail_up_from = set()
        self.compose_up_log = []
        self.started_proxy = False

    # ---- building a box ----
    def deployment(self, slug, project, pg='bind', up=True, files=True):
        d = self.root / slug
        (d / 'store' / 'pgdata').mkdir(parents=True)
        (d / 'store' / 'pgdata' / 'PG_VERSION').write_text('16')
        (d / 'pki').mkdir()
        (d / 'pki' / 'ca.crt').write_text('CA')
        if files:
            (d / 'docker-compose.yml').write_text('services: {}\n')
            (d / '.env').write_text('ATLAS_DIR=%s\nOTHER=%s-x\n' % (d, d))
        self.names[slug] = project
        for kind in ('api', 'db', 'renewal'):
            self.containers['%s-%s-1' % (project, kind)] = {
                'project': project, 'workdir': str(d), 'running': up,
                'service': kind}
        vol = '%s_pgdata' % project
        self.volumes[vol] = str(d / 'store' / 'pgdata') if pg == 'bind' else (
            '' if pg == 'managed' else pg)
        return d

    # ---- Docker, as `_run_root` sees it ----
    def run_root(self, argv, timeout=120):
        assert argv[0] == 'docker', argv
        sub = argv[1:]
        if sub[:2] == ['ps', '-a'] and '--filter' not in sub:
            seen = sorted({(c['project'], c['workdir'])
                           for c in self.containers.values()})
            return 0, '\n'.join('%s\t%s' % pw for pw in seen)
        if sub[0] == 'ps':
            project = [a for a in sub if a.startswith('label=')][0].split('=', 2)[2]
            pick = [(n, c) for n, c in sorted(self.containers.items())
                    if c['project'] == project and (c['running'] or '-a' in sub)]
            if 'compose.service' in sub[-1]:
                return 0, '\n'.join(c['service'] for _, c in pick)
            return 0, '\n'.join(n for n, _ in pick)
        if sub[0] == 'inspect':
            c = self.containers[sub[-1]]
            lines = ['volume %s_pgdata' % c['project'], 'bind ']
            if c['project'] in self.anon:
                lines.append('volume %s' % self.anon[c['project']])
            return 0, '\n'.join(lines)
        if sub[:2] == ['volume', 'inspect']:
            name = sub[2]
            if name not in self.volumes:
                return 1, 'no such volume'
            return 0, self.volumes[name] or '<no value>'
        if sub[:2] == ['volume', 'rm']:
            name = sub[2]
            self.calls.append(('volume rm', name))
            if any(name.startswith(c['project'] + '_') for c in self.containers.values()):
                return 1, 'volume is in use'
            self.volumes.pop(name, None)
            return 0, name
        if sub[:2] == ['volume', 'create']:
            device = [a for a in sub if a.startswith('device=')][0][7:]
            name = sub[-1]
            self.volumes[name] = device
            self.calls.append(('volume create', name, device))
            return 0, name
        raise AssertionError('unmodelled docker call: %r' % (argv,))

    # ---- docker compose, as `_broker_compose` runs it ----
    def compose(self, where, action, timeout=300):
        project = self.names[os.path.basename(where)]
        self.calls.append(('compose', action, where))
        mine = [n for n, c in self.containers.items() if c['project'] == project]
        if action == 'stop':
            if project not in self.stubborn:
                for n in mine:
                    self.containers[n]['running'] = False
        elif action == 'rm -f':
            for n in mine:
                if not self.containers[n]['running']:
                    del self.containers[n]
        elif action.startswith('up -d'):
            self.compose_up_log.append((where, action))
            wanted = action.split()[2:] or ['api', 'db', 'renewal', 'proxy']
            # ⚠️ ATLAS's compose also defines `proxy` (nginx on port 80). It must
            # never be started: Caddy owns 80, and where it is free it would
            # open a second public listener.
            if 'proxy' in wanted:
                self.started_proxy = True
            vol = '%s_pgdata' % project
            device = self.volumes.get(vol)
            self.volumes.setdefault(vol, '')
            # Postgres on a bind volume needs the directory to exist; the API
            # needs the working directory to exist.
            db_ok = (not device) or os.path.isdir(device)
            ok = os.path.isdir(where) and db_ok and where not in self.fail_up_from
            for kind in [w for w in wanted if w != 'proxy']:
                n = '%s-%s-1' % (project, kind)
                self.containers[n] = {'project': project, 'workdir': where,
                                      'running': ok, 'service': kind}
        return R()

    # ---- the broker's mv / test / chown, on the real temp tree ----
    def sudo(self, argv):
        self.calls.append(('priv',) + tuple(argv[:1]))
        if argv[0] in ('chown', 'restorecon'):
            self.calls.append(('priv', argv[0], tuple(argv[1:])))
            return ['true']
        return argv


@pytest.fixture
def world(tmp_path, monkeypatch):
    w = World(tmp_path)
    monkeypatch.setenv('HOME', str(w.home))
    monkeypatch.setattr(atlas, '_run_root', w.run_root)
    monkeypatch.setattr(atlas, '_ROOT_ERA_UNIT',
                        re.compile(r'^%s/([a-z]{1,32})$' % re.escape(str(w.root))))
    monkeypatch.setattr(atlas, 'ROOT_ERA_DIR', str(w.root))
    monkeypatch.setattr(atlas.os, 'getuid', lambda: 1000)
    monkeypatch.setattr(atlas, '_mounted_under', lambda p, f='': False)
    w.ctx = {'_sudo_wrap': w.sudo, '_broker_compose': w.compose,
             '_rehome_rewrite_paths': _real_rewrite(),
             'os_type': lambda: 'debian'}
    return w


def run(w, **kw):
    out = atlas.rehome_root_era(w.ctx, log=lambda m: None, wait_healthy=9,
                                sleep=lambda s: None, **kw)
    return dict(out)


# --------------------------------------------------------------------------- #
# The move
# --------------------------------------------------------------------------- #


def test_a_stranded_deployment_moves_home_and_comes_back_up(world):
    d = world.deployment('default', 'takmdm')

    out = run(world)

    home = world.home / 'atlas' / 'default'
    assert out[str(d)].startswith('moved')
    assert not d.exists()
    assert (home / 'store' / 'pgdata' / 'PG_VERSION').read_text() == '16'
    assert (home / 'pki' / 'ca.crt').read_text() == 'CA'
    up = {n for n, c in world.containers.items() if c['running']}
    assert up == {'takmdm-api-1', 'takmdm-db-1', 'takmdm-renewal-1'}
    assert {c['workdir'] for c in world.containers.values()} == {str(home)}


def test_the_bind_volume_follows_the_data(world):
    """⚠️ **The reason this is not the other modules' re-home.** Without it the
    volume still names /root/atlas/default/store/pgdata, which no longer exists,
    and Postgres starts on nothing."""
    world.deployment('default', 'takmdm')

    run(world)

    assert world.volumes['takmdm_pgdata'] == str(
        world.home / 'atlas' / 'default' / 'store' / 'pgdata')


def test_the_database_is_not_started_before_the_volume_points_at_it(world):
    """Order, not just outcome: stop, free the volume, move, re-point, up."""
    d = world.deployment('default', 'takmdm')

    run(world)

    kinds = [c[:2] for c in world.calls
             if c[0] in ('compose', 'volume rm', 'volume create')]
    assert kinds == [('compose', 'stop'), ('compose', 'rm -f'),
                     ('volume rm', 'takmdm_pgdata'),
                     ('volume create', 'takmdm_pgdata'),
                     ('compose', 'up -d api db renewal')]
    assert ('compose', 'up -d api db renewal',
            str(world.home / 'atlas' / 'default')) in world.calls
    assert not any(c[0] == 'compose' and c[1].startswith('up') and c[2] == str(d)
                   for c in world.calls)


def test_stop_is_used_never_down(world):
    """ops #346: `down` orphaned an anonymous volume and CloudTAK lost its data."""
    world.deployment('default', 'takmdm')

    run(world)

    assert not any(c[0] == 'compose' and 'down' in c[1] for c in world.calls)


def test_only_the_services_that_were_up_are_started_never_the_nginx_proxy(world):
    """⚠️ **Found on nuc (ops #1266).** A bare `compose up -d` also starts ATLAS's
    own `proxy` (nginx on port 80). It failed there only because Caddy held the
    port; on a box where 80 is free it would open a second public listener.
    The module has always started `up -d api`; the re-home starts what ran."""
    world.deployment('default', 'takmdm')
    world.deployment('corona', 'takmdm-corona')

    run(world)

    assert world.started_proxy is False
    assert world.compose_up_log
    assert all(cmd == 'up -d api db renewal' for _, cmd in world.compose_up_log)


def test_a_docker_managed_database_volume_is_left_alone(world):
    """Boxes whose volume has no bind (older deployments): nothing to re-point,
    and the containers are never removed."""
    world.deployment('default', 'takmdm', pg='managed')

    out = run(world)

    assert list(out.values())[0].startswith('moved')
    assert world.volumes['takmdm_pgdata'] == ''
    assert not any(c[0] in ('volume rm', 'volume create') for c in world.calls)
    assert not any(c[:2] == ('compose', 'rm -f') for c in world.calls)


def test_every_deployment_is_moved_not_only_the_plain_one(world):
    """⚠️ The nested layout holds one stack per agency, each with its own project."""
    world.deployment('default', 'takmdm')
    world.deployment('corona', 'takmdm-corona')

    out = run(world)

    assert all(v.startswith('moved') for v in out.values()) and len(out) == 2
    assert world.volumes['takmdm-corona_pgdata'] == str(
        world.home / 'atlas' / 'corona' / 'store' / 'pgdata')
    assert all(c['running'] for c in world.containers.values())


def test_absolute_paths_in_env_follow_the_directory(world):
    d = world.deployment('default', 'takmdm')

    run(world)

    env = (world.home / 'atlas' / 'default' / '.env').read_text()
    home = str(world.home / 'atlas' / 'default')
    assert env == 'ATLAS_DIR=%s\nOTHER=%s-x\n' % (home, d)  # `-x` is another name


def test_ownership_is_handed_over_only_where_root_made_it(world):
    """uid 70 owns pgdata and uid 1000 owns pki: a blanket chown breaks both."""
    world.deployment('default', 'takmdm')

    run(world)

    chowns = [c for c in world.calls if c[:2] == ('priv', 'chown') and len(c) == 3]
    assert chowns and '--from=root:root' in chowns[0][2]


def test_an_empty_root_directory_is_tidied_after_the_last_move(world):
    world.deployment('default', 'takmdm')

    run(world)

    assert ('priv', 'rmdir') in world.calls


# --------------------------------------------------------------------------- #
# Idempotence and refusals
# --------------------------------------------------------------------------- #


def test_a_second_run_changes_nothing(world):
    world.deployment('default', 'takmdm')
    run(world)
    world.calls.clear()

    assert run(world) == {}
    assert not any(c[0] == 'compose' for c in world.calls)


def test_a_root_console_does_nothing(world, monkeypatch):
    world.deployment('default', 'takmdm')
    monkeypatch.setattr(atlas.os, 'getuid', lambda: 0)

    assert run(world) == {}
    assert not world.calls


def test_a_deployment_already_in_the_home_is_left_alone(world):
    """A new agency was deployed to the home before the re-home ran: do not
    overwrite it."""
    d = world.deployment('default', 'takmdm')
    (world.home / 'atlas' / 'default').mkdir(parents=True)

    out = run(world)

    assert out[str(d)].startswith('left alone')
    assert d.exists() and not any(c[0] == 'compose' for c in world.calls)


def test_an_anonymous_volume_stops_the_move(world):
    """⚠️ Removing the container would orphan it and the next up would make a
    new empty one."""
    d = world.deployment('default', 'takmdm')
    world.anon['takmdm'] = 'a' * 64

    out = run(world)

    assert 'anonymous volume' in out[str(d)]
    assert d.exists() and not any(c[0] == 'compose' for c in world.calls)


def test_a_volume_bound_somewhere_else_is_not_touched(world):
    d = world.deployment('default', 'takmdm', pg='/var/lib/atlas/store/pgdata')

    out = run(world)

    assert 'bound to /var/lib/atlas' in out[str(d)]
    assert d.exists()
    assert world.volumes['takmdm_pgdata'] == '/var/lib/atlas/store/pgdata'


def test_a_mount_inside_the_directory_stops_the_move(world, monkeypatch):
    d = world.deployment('default', 'takmdm')
    monkeypatch.setattr(atlas, '_mounted_under', lambda p, f='': True)

    out = run(world)

    assert 'mounted' in out[str(d)]
    assert d.exists()


def test_a_directory_with_no_compose_file_is_not_a_deployment(world):
    d = world.deployment('default', 'takmdm', files=False)

    assert 'no compose file' in run(world)[str(d)]
    assert d.exists()


def test_a_stack_that_will_not_stop_is_put_back_and_not_moved(world):
    d = world.deployment('default', 'takmdm')
    world.stubborn.add('takmdm')

    out = run(world)

    assert 'would not stop' in out[str(d)]
    assert d.exists()
    assert all(c['running'] for c in world.containers.values())
    assert 'takmdm_pgdata' in world.volumes


def test_a_stopped_deployment_is_moved_and_stays_stopped(world):
    """Moving must not start what an operator had stopped."""
    world.deployment('default', 'takmdm', up=False)

    out = run(world)

    assert list(out.values())[0].startswith('moved')
    assert not any(c[0] == 'compose' and c[1].startswith('up') for c in world.calls)
    assert world.volumes['takmdm_pgdata'] == str(
        world.home / 'atlas' / 'default' / 'store' / 'pgdata')


def test_the_older_sibling_layout_is_not_matched():
    """The broker allowlists /root/atlas/ only; /root/atlas-corona cannot move."""
    assert atlas._ROOT_ERA_UNIT.match('/root/atlas/default')
    assert atlas._ROOT_ERA_UNIT.match('/root/atlas/corona')
    assert not atlas._ROOT_ERA_UNIT.match('/root/atlas-corona')
    assert not atlas._ROOT_ERA_UNIT.match('/root/atlas')
    assert not atlas._ROOT_ERA_UNIT.match('/root/atlas/a/b')
    assert not atlas._ROOT_ERA_UNIT.match('/root/atlas/../etc')


# --------------------------------------------------------------------------- #
# Undo
# --------------------------------------------------------------------------- #


def test_if_it_does_not_come_back_the_move_is_undone(world):
    """⚠️ The promise of the whole re-home: never leave the module down."""
    d = world.deployment('default', 'takmdm')
    world.fail_up_from.add(str(world.home / 'atlas' / 'default'))

    out = run(world)

    assert out[str(d)].startswith('rolled back')
    assert (d / 'store' / 'pgdata' / 'PG_VERSION').read_text() == '16'
    assert not (world.home / 'atlas' / 'default').exists()
    assert world.volumes['takmdm_pgdata'] == str(d / 'store' / 'pgdata')
    assert all(c['running'] for c in world.containers.values())
    assert {c['workdir'] for c in world.containers.values()} == {str(d)}
    assert (d / '.env').read_text() == 'ATLAS_DIR=%s\nOTHER=%s-x\n' % (d, d)


def test_a_failed_volume_release_puts_the_stack_back(world):
    """If the volume cannot be released nothing has moved yet."""
    d = world.deployment('default', 'takmdm')
    real = world.run_root

    def refuse(argv, timeout=120):
        if argv[1:3] == ['volume', 'rm']:
            return 1, 'busy'
        return real(argv, timeout)

    atlas._run_root = refuse
    try:
        out = run(world)
    finally:
        atlas._run_root = real

    assert 'could not release' in out[str(d)]
    assert d.exists() and all(c['running'] for c in world.containers.values())


def test_one_failure_does_not_stop_the_next_deployment(world):
    a = world.deployment('default', 'takmdm')
    b = world.deployment('corona', 'takmdm-corona')
    world.fail_up_from.add(str(world.home / 'atlas' / 'corona'))

    out = run(world)

    assert out[str(a)].startswith('moved')
    assert out[str(b)].startswith('rolled back')


# --------------------------------------------------------------------------- #
# Pieces
# --------------------------------------------------------------------------- #


def test_units_come_from_docker_not_from_the_filesystem(world):
    """The console cannot list /root; Docker still names the working directory."""
    world.deployment('default', 'takmdm')

    assert atlas.root_era_units() == [('takmdm', str(world.root / 'default'))]


def test_a_mount_inside_is_read_from_the_mount_table(tmp_path):
    mounts = tmp_path / 'mounts'
    mounts.write_text('/dev/loop3 /root/atlas/default/store ext4 rw 0 0\n'
                      '/dev/sda1 / ext4 rw 0 0\n')
    assert atlas._mounted_under('/root/atlas/default', str(mounts))
    assert not atlas._mounted_under('/root/atlas/corona', str(mounts))
    assert not atlas._mounted_under('/root/atlas/def', str(mounts))


def test_app_hands_the_module_its_path_rewrite_and_runs_the_rehome():
    """The seams in app.py: the ctx key the module reads, and the call itself."""
    assert "'_rehome_rewrite_paths': _rehome_rewrite_paths," in APP
    assert 'mod_registry.atlas.rehome_root_era(_MODULE_CTX)' in APP
    # After the registry, which is what gives the ctx its meaning.
    assert (APP.index('mod_registry.init_registry(app, _MODULE_CTX')
            < APP.index('mod_registry.atlas.rehome_root_era(_MODULE_CTX)'))
