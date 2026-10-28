"""GH #330 (second cause): the MediaMTX web editor crash-looped on `No module named 'flask'`
while infra-TAK's own check said its packages were fine.

The check imported Flask in the CONSOLE's context; the editor runs as takwerx with the HOME
systemd gives it. Two ways those differ in the field:
  - non-root console migrated from root: start.sh's `usermod -d /home/takwerx … || true`
    fails while mediamtx runs as takwerx, so the passwd home stays /nonexistent. The console
    (HOME=/home/takwerx) pip --user installs there; the editor never looks there.
  - root console: a Flask in /root/.local satisfies both pip and root's import check.
Patch web editor never touched the packages at all, so it restarted the editor into the
same crash.
"""
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

DROPIN = '/etc/systemd/system/mediamtx-webeditor.service.d/20-infratak-home.conf'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


class FakePwd:
    def __init__(self, me='takwerx', takwerx_home='/nonexistent'):
        self.me, self.home = me, takwerx_home

    def getpwnam(self, name):
        if name != 'takwerx' or self.home is None:
            raise KeyError(name)
        return types.SimpleNamespace(pw_dir=self.home)

    def getpwuid(self, uid):
        return types.SimpleNamespace(pw_name=self.me)


class Box:
    """Runs the real helpers against a fake host."""

    def __init__(self, monkeypatch, euid=999, me='takwerx', passwd_home='/nonexistent',
                 console_home='/home/takwerx', files=None, import_ok=lambda argv, env: True,
                 pip_rc=0):
        self.files = dict(files or {})
        self.runs, self.writes = [], []
        monkeypatch.setitem(__import__('sys').modules, 'pwd', FakePwd(me, passwd_home))
        box = self

        def run(argv, **kw):
            box.runs.append((argv, kw.get('env')))
            if '-c' in argv:
                return types.SimpleNamespace(returncode=0 if import_ok(argv, kw.get('env') or {}) else 1,
                                             stdout='', stderr='')
            if argv[:2] == ['pip3', 'install']:
                return types.SimpleNamespace(returncode=pip_rc, stdout='Successfully installed Flask\n'
                                             if pip_rc == 0 else 'ERROR: network unreachable\n')
            return types.SimpleNamespace(returncode=0, stdout='', stderr='')

        def write(path, content, **kw):
            box.writes.append((path, content))
            box.files[path] = content

        fake_os = types.SimpleNamespace(
            geteuid=lambda: euid,
            environ={'HOME': console_home, 'PATH': '/opt/infratak/.venv/bin:/usr/bin'},
            path=types.SimpleNamespace(exists=lambda p: p in box.files,
                                       isdir=lambda p: p == console_home,
                                       dirname=lambda p: p.rsplit('/', 1)[0]))
        self.ns = {
            'os': fake_os, 're': re, 'subprocess': types.SimpleNamespace(run=run, PIPE=-1, STDOUT=-2),
            '_read_priv': lambda p: box.files.get(p), '_write_priv': write, '_sudo_wrap': lambda c: c,
            'print': lambda *a, **k: None,
            '_MEDIAMTX_EDITOR_USER': 'takwerx', '_MEDIAMTX_EDITOR_HOME_DROPIN': DROPIN,
            '_MEDIAMTX_EDITOR_PY_PKGS': ('Flask', 'ruamel.yaml', 'requests', 'psutil'),
            '_MEDIAMTX_EDITOR_PY_IMPORTS': 'import flask, ruamel.yaml, requests, psutil',
        }
        for name in ('_mediamtx_editor_home', '_mediamtx_editor_python_ok', '_mediamtx_editor_pin_home',
                     '_mediamtx_editor_install_py_deps', '_mediamtx_editor_ensure_py_deps'):
            exec(compile(_fn(name), 'app.py', 'exec'), self.ns)

    def __getattr__(self, name):
        return self.ns['_mediamtx_editor_' + name]

    def import_checks(self):
        return [(a, e) for a, e in self.runs if '-c' in a]

    def pips(self):
        return [(a, e) for a, e in self.runs if a[:1] == ['pip3']]


# --- the check runs as the editor runs ----------------------------------------------------

def test_root_console_checks_as_takwerx_with_its_passwd_home(monkeypatch):
    b = Box(monkeypatch, euid=0, me='root', passwd_home='/nonexistent')
    assert b.python_ok() is True
    argv, env = b.import_checks()[0]
    assert argv[:6] == ['runuser', '-u', 'takwerx', '--', 'env', 'HOME=/nonexistent']
    assert argv[6:8] == ['/usr/bin/python3', '-c']
    assert env == {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/nonexistent'}   # nothing of root's


def test_nonroot_console_checks_with_the_editors_home_not_its_own(monkeypatch):
    """The field case: console HOME=/home/takwerx, takwerx's passwd home /nonexistent."""
    b = Box(monkeypatch, passwd_home='/nonexistent',
            import_ok=lambda argv, env: env.get('HOME') == '/home/takwerx')
    assert b.python_ok() is False                    # the old check (console's HOME) said True
    argv, env = b.import_checks()[0]
    assert argv[0] == '/usr/bin/python3' and env['HOME'] == '/nonexistent'


def test_the_home_dropin_is_what_the_editor_sees(monkeypatch):
    b = Box(monkeypatch, files={DROPIN: '# x\n[Service]\nEnvironment=HOME=/home/takwerx\n'})
    assert b.home() == '/home/takwerx'
    b.python_ok()
    assert b.import_checks()[0][1]['HOME'] == '/home/takwerx'


def test_unknown_editor_user_is_never_healed_on_a_guess(monkeypatch):
    b = Box(monkeypatch, euid=0, me='root', passwd_home=None, import_ok=lambda a, e: False)
    assert b.python_ok() is True and b.import_checks() == []


# --- pinning the editor's HOME (non-root only) --------------------------------------------

def test_pin_home_writes_the_dropin_when_passwd_home_differs(monkeypatch):
    b = Box(monkeypatch, passwd_home='/nonexistent', console_home='/home/takwerx')
    assert b.pin_home() is True
    assert b.writes == [(DROPIN, "# infra-TAK GH #330: the editor imports Flask from the console's "
                                 "pip --user site.\n[Service]\nEnvironment=HOME=/home/takwerx\n")]
    assert ['systemctl', 'daemon-reload'] in [a for a, _ in b.runs]


def test_pin_home_is_a_no_op_when_homes_match_or_as_root(monkeypatch):
    b = Box(monkeypatch, passwd_home='/home/takwerx')
    assert b.pin_home() is False and b.writes == []
    b = Box(monkeypatch, euid=0, me='root')
    assert b.pin_home() is False and b.writes == []
    b = Box(monkeypatch, me='someoneelse')
    assert b.pin_home() is False and b.writes == []


def test_pin_home_never_writes_a_home_that_could_add_a_unit_line(monkeypatch):
    bad = '/home/takwerx\nExecStartPre=/bin/sh'
    b = Box(monkeypatch, console_home=bad)
    b.ns['os'].path.isdir = lambda p: True
    assert b.pin_home() is False and b.writes == []


# --- install: root's ~/.local must not satisfy pip -----------------------------------------

def test_root_install_ignores_roots_user_site(monkeypatch):
    b = Box(monkeypatch, euid=0, me='root')
    assert b.install_py_deps()[0] is True
    for argv, env in b.pips():
        assert env['PYTHONNOUSERSITE'] == '1', argv
    assert [a for a, _ in b.pips()][-1][:4] == ['pip3', 'install', '-U', 'certifi']


def test_nonroot_install_keeps_the_user_site(monkeypatch):
    b = Box(monkeypatch)
    b.install_py_deps()
    assert all('PYTHONNOUSERSITE' not in env for _, env in b.pips())


# --- ensure: cheapest fix first, verified as the editor -----------------------------------

def test_ensure_does_nothing_when_the_editor_already_imports(monkeypatch):
    b = Box(monkeypatch, passwd_home='/home/takwerx')
    assert b.ensure_py_deps() == (True, 'already importable')
    assert b.pips() == [] and b.writes == []


def test_ensure_fixes_the_migrated_box_with_the_dropin_alone(monkeypatch):
    b = Box(monkeypatch, passwd_home='/nonexistent',
            import_ok=lambda argv, env: env.get('HOME') == '/home/takwerx')
    ok, detail = b.ensure_py_deps()
    assert ok is True and 'HOME' in detail
    assert b.pips() == [] and b.writes and b.writes[0][0] == DROPIN


def test_ensure_reinstalls_when_the_packages_are_really_gone(monkeypatch):
    state = {'installed': False}
    b = Box(monkeypatch, euid=0, me='root', import_ok=lambda a, e: state['installed'])
    orig = b.ns['subprocess'].run

    def run(argv, **kw):
        r = orig(argv, **kw)
        if argv[:2] == ['pip3', 'install']:
            state['installed'] = True
        return r
    b.ns['subprocess'].run = run
    assert b.ensure_py_deps() == (True, 'packages reinstalled')


def test_ensure_reports_pips_error_when_install_fails(monkeypatch):
    b = Box(monkeypatch, euid=0, me='root', import_ok=lambda a, e: False, pip_rc=1)
    assert b.ensure_py_deps() == (False, 'ERROR: network unreachable')


# --- wiring --------------------------------------------------------------------------------

def test_patch_web_editor_installs_packages_before_the_restart():
    body = _fn('mediamtx_recovery')
    i_deps = body.index('_mediamtx_editor_ensure_py_deps()')
    assert body.index('_mediamtx_editor_remote_py_deps(deploy_cfg)') < body.index("'systemctl daemon-reload")
    assert i_deps < body.index("'systemctl daemon-reload")
    assert 'could not be installed: {deps_detail}' in body


def test_deploy_and_heal_verify_as_the_editor():
    assert '_mediamtx_editor_ensure_py_deps()' in _fn('_startup_heal_mediamtx_editor_python')
    i = APP.index('\ndef run_mediamtx_deploy():')       # _fn() stops at its first f-string block
    assert '_mediamtx_editor_ensure_py_deps()' in APP[i:APP.index('\ndef ', i + 1)]
    remote = _fn('_run_mediamtx_deploy_remote')
    assert remote.index('_ensure_takwerx_system_user_remote(') < remote.index('_mediamtx_editor_remote_py_deps(')


def test_remote_check_imports_as_takwerx():
    assert ("_MEDIAMTX_EDITOR_REMOTE_IMPORT_CHECK = (f'runuser -u {_MEDIAMTX_EDITOR_USER} -- /usr/bin/python3 -c '"
            in APP)
    body = _fn('_mediamtx_editor_remote_py_deps')
    assert '_MEDIAMTX_EDITOR_REMOTE_IMPORT_CHECK' in body
