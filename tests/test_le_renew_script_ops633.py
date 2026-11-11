"""ops #633: where the daily LE renewal script lives.

takserver-cert-renewal.service runs the LE renewal script every day. It lived at
/opt/tak/renew-letsencrypt.sh, 0755, and it holds the keystore password. Now it is
written 0700 to LE_RENEW_SCRIPT, and
_startup_move_le_renewal_script() moves it on existing boxes without breaking renewal.
The first three tests fail on dev d67aa04.
"""
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER = (REPO / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')

NEW = '/usr/local/sbin/takserver-renew-letsencrypt.sh'
OLD = '/opt/tak/renew-letsencrypt.sh'
UNIT = '/etc/systemd/system/takserver-cert-renewal.service'
SCRIPT = '#!/bin/bash\nset -euo pipefail\necho renew\n'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, name
    return m.group(0)


def test_no_writer_puts_the_renewal_script_in_opt_tak():
    assert "_write_priv('/opt/tak/renew-letsencrypt.sh'" not in APP
    assert 'ExecStart=/opt/tak/renew-letsencrypt.sh' not in APP


def test_the_new_path_is_root_owned_and_broker_allowed():
    m = re.search(r"^LE_RENEW_SCRIPT = '([^']+)'", APP, re.M)
    assert m and m.group(1) == NEW
    assert not NEW.startswith('/opt/tak/')
    exact = BROKER[BROKER.index('PATH_ALLOW_EXACT = ('):]
    exact = exact[:exact.index('\n)\n')]
    assert f"'{NEW}'" in exact


def test_broker_allows_exactly_the_new_path_and_still_denies_its_folder():
    """The non-root console writes, reads and removes through the broker."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops633',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    assert b._path_allowed(NEW) == NEW
    assert b._path_allowed(NEW, readonly=True) == NEW
    assert b._path_allowed(OLD) == OLD               # the `rm -f` of the old copy
    try:
        b._path_allowed('/usr/local/sbin/anything-else.sh')
    except b.Denied:
        pass
    else:
        raise AssertionError('/usr/local/sbin/ must stay denied apart from exact paths')


def test_both_writers_use_the_0700_helper():
    assert APP.count('_le_renew_write(renewal)') == 1
    assert APP.count('_le_renew_write(renewal_script)') == 1


class Box:
    def __init__(self, files, verify_ok=True):
        self.files = dict(files)
        self.perms = {}
        self.verify_ok = verify_ok
        self.cmds = []
        self.log = []

    def ns(self):
        box = self

        def read(p):
            if p == NEW and not box.verify_ok:
                return 'garbled'
            return box.files.get(p)

        def write(p, content, mode='w', perm=None):
            box.files[p] = content
            if perm is not None:
                box.perms.setdefault(p, []).append((content, perm))

        def run(cmd, **kw):
            box.cmds.append(cmd)
            if cmd[-3:-1] == ['rm', '-f']:
                box.files.pop(cmd[-1], None)
            return types.SimpleNamespace(returncode=0, stdout='', stderr='')

        fake_os = types.SimpleNamespace(path=types.SimpleNamespace(
            exists=lambda p: p in box.files, lexists=lambda p: p in box.files))
        ns = {'os': fake_os, 'subprocess': types.SimpleNamespace(run=run),
              '_read_priv': read, '_write_priv': write,
              '_sudo_wrap': lambda c: ['sudo', '-n'] + c,
              'print': lambda *a, **k: box.log.append(' '.join(map(str, a))),
              'LE_RENEW_SCRIPT': NEW, 'LE_RENEW_SCRIPT_OLD': OLD, 'LE_RENEW_UNIT': UNIT}
        for name in ('_le_renew_write', '_le_renew_drop_old', '_startup_move_le_renewal_script'):
            exec(compile(_fn(name), 'app.py', 'exec'), ns)
        return ns


def _unit(path):
    return f'[Unit]\nDescription=x\n\n[Service]\nType=oneshot\nExecStart={path}\n'


def test_existing_box_is_moved_and_the_unit_repointed():
    box = Box({UNIT: _unit(OLD), OLD: SCRIPT})
    box.ns()['_startup_move_le_renewal_script']()
    assert box.files[NEW] == SCRIPT
    assert box.files[UNIT] == _unit(NEW)
    assert OLD not in box.files
    # created empty at 0700 BEFORE the password-bearing content goes in
    assert box.perms[NEW][0] == ('', 0o700)
    assert box.perms[NEW][-1] == (SCRIPT, 0o700)
    assert ['sudo', '-n', 'systemctl', 'daemon-reload'] in box.cmds


def test_a_copy_that_does_not_verify_leaves_renewal_as_it_was():
    box = Box({UNIT: _unit(OLD), OLD: SCRIPT}, verify_ok=False)
    box.ns()['_startup_move_le_renewal_script']()
    assert box.files[UNIT] == _unit(OLD)
    assert box.files[OLD] == SCRIPT


def test_missing_old_script_leaves_the_unit_for_the_le_self_heal():
    box = Box({UNIT: _unit(OLD)})
    box.ns()['_startup_move_le_renewal_script']()
    assert box.files[UNIT] == _unit(OLD)
    assert NEW not in box.files


def test_already_moved_box_only_drops_a_leftover_old_copy():
    box = Box({UNIT: _unit(NEW), NEW: SCRIPT, OLD: SCRIPT})
    box.ns()['_startup_move_le_renewal_script']()
    assert OLD not in box.files
    assert box.files[UNIT] == _unit(NEW) and box.files[NEW] == SCRIPT
    assert ['sudo', '-n', 'systemctl', 'daemon-reload'] not in box.cmds


def test_box_without_le_on_8446_is_untouched():
    box = Box({})
    box.ns()['_startup_move_le_renewal_script']()
    assert box.files == {} and box.cmds == []


def test_move_runs_before_the_in_place_heal():
    i_move = APP.index('            _startup_move_le_renewal_script()')
    i_heal = APP.index('            _startup_heal_le_renewal_script()')
    assert i_move < i_heal
