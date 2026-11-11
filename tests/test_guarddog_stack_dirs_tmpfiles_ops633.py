"""ops #633: Guard Dog stack lookup and temp files.

1. gd_find_stack_dir() searches /home/*/<stack>. A stack dir is now used only when it
   and its compose file belong to root or the console account, are not symlinks, and are
   not writable by other users.
2. The alert scripts wrote the SMS body to a fixed /tmp/gd-sms-$$.txt (and a few other
   fixed /tmp names). Every one now uses mktemp.

Both parts fail on dev d67aa04.
"""
import os
import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GD = ROOT / 'scripts' / 'guarddog'
LIB = (GD / '_gd-tak-lib.sh').read_text()

DOCKER_STUB = '#!/bin/sh\nexit 1\n'          # no container: the search list decides


@pytest.fixture
def find(tmp_path):
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    for name, body in (('docker', DOCKER_STUB), ('logger', '#!/bin/sh\nexit 0\n')):
        (stubs / name).write_text(body)
        (stubs / name).chmod(0o755)
    homes = tmp_path / 'home'
    homes.mkdir()
    lib = tmp_path / 'lib.sh'
    lib.write_text(LIB.replace('/home/*/', str(homes) + '/*/')
                      .replace('/root/', str(tmp_path / 'noroot') + '/'))

    def make_stack(user, stack='authentik'):
        d = homes / user / stack
        d.mkdir(parents=True)
        (d / 'docker-compose.yml').write_text('services: {}\n')
        return d

    def run(owner, stack='authentik'):
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs, 'GD_STACK_OWNER': owner}
        r = subprocess.run(['bash', '-c', '. "$1"; gd_find_stack_dir "$2" authentik-server-1',
                            'x', str(lib), stack], capture_output=True, text=True, env=env,
                           timeout=30)
        return r.stdout if r.returncode == 0 else None

    run.make_stack = make_stack
    return run


def _not_me():
    """A trusted-owner setting that is neither root nor the test user (root only)."""
    return 'no-such-account-ops633'


@pytest.mark.skipif(os.getuid() == 0, reason='as root every test file is root-owned')
def test_a_stack_owned_by_another_user_is_not_used(find):
    find.make_stack('other')
    assert find(_not_me()) is None


def test_the_console_accounts_own_stack_is_used(find):
    d = find.make_stack('takwerx')
    assert find(str(os.getuid())) == str(d)


def test_a_world_writable_stack_dir_is_not_used(find):
    d = find.make_stack('takwerx')
    d.chmod(0o777)
    assert find(str(os.getuid())) is None


def test_a_world_writable_compose_file_is_not_used(find):
    d = find.make_stack('takwerx')
    (d / 'docker-compose.yml').chmod(0o666)
    assert find(str(os.getuid())) is None


def test_a_symlinked_compose_file_is_not_used(find, tmp_path):
    d = find.make_stack('takwerx')
    real = tmp_path / 'elsewhere.yml'
    real.write_text('services: {}\n')
    (d / 'docker-compose.yml').unlink()
    (d / 'docker-compose.yml').symlink_to(real)
    assert find(str(os.getuid())) is None


def test_a_symlinked_stack_dir_is_judged_by_its_target(find):
    """Non-root boxes keep /root/<stack> -> /home/takwerx/<stack> (test12). Seen from the
    /home/* glob here: a link to a trusted dir is used, a link to a writable one is not."""
    real = find.make_stack('takwerx', 'node-red')
    link = real.parent.parent / 'ops' / 'authentik'
    link.parent.mkdir()
    link.symlink_to(real)
    assert find(str(os.getuid())) == str(link)
    real.chmod(0o777)
    assert find(str(os.getuid())) is None


def test_an_untrusted_stack_does_not_shadow_the_real_one(find):
    """'other' sorts before takwerx in the /home/* glob; its copy must be skipped, not win."""
    find.make_stack('other')
    d = find.make_stack('takwerx')
    me = str(os.getuid())
    # Same owner here (the test user), so make the other one world-writable to stand in for "not trusted".
    (d.parent.parent / 'other' / 'authentik').chmod(0o777)
    assert find(me) == str(d)


# ── 2. No fixed /tmp names ───────────────────────────────────────────────────────
FIXED_TMP = re.compile(r'''["'](/tmp/[^"'$]*\$\$[^"']*)["']''')


def test_no_guarddog_script_writes_a_fixed_tmp_name():
    hits = []
    for f in sorted(GD.glob('*.sh')):
        for n, line in enumerate(f.read_text().splitlines(), 1):
            if line.lstrip().startswith('#'):
                continue
            if FIXED_TMP.search(line):
                hits.append(f'{f.name}:{n}: {line.strip()}')
    assert not hits, 'fixed /tmp names (use mktemp):\n' + '\n'.join(hits)


@pytest.mark.parametrize('pat', [
    r'of=/tmp/\.gd_diskio',                 # disk-speed probe file
    r'TEMP_CERT="/tmp/takserver-le-temp\.pem"',
    r'--pid-file=/tmp/',
])
def test_other_fixed_tmp_writes_are_gone(pat):
    for f in GD.glob('*.sh'):
        assert not re.search(pat, f.read_text()), f'{f.name}: {pat}'


def test_setup_ap_writes_its_configs_exclusively():
    src = (GD / 'tak-setup-ap.sh').read_text()
    i = src.index('cat > "$HOSTAPD_CONF"')
    before = src[max(0, i - 900):i]
    assert 'rm -f "$HOSTAPD_CONF" "$DNSMASQ_CONF"' in before
    assert 'set -C' in before and 'umask 077' in before


def test_console_spiral_sms_uses_mkstemp():
    src = (ROOT / 'app.py').read_text()
    assert "f'/tmp/gd-spiral-sms-{os.getpid()}.txt'" not in src
    assert "tempfile.mkstemp(prefix='gd-spiral-sms.'" in src


def test_mktemp_sms_file_works_end_to_end(tmp_path):
    """The rewritten pattern still hands sms_send.sh a readable file with the body."""
    snippet = ('TMPF="$(mktemp "$1/gd-sms.XXXXXX")"\n'
               'printf "%s" "$2" > "$TMPF"\n'
               'cat "$TMPF"; rm -f "$TMPF"\n')
    r = subprocess.run(['bash', '-c', snippet, 'x', str(tmp_path), 'hello body'],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 0 and r.stdout == 'hello body'
    assert not list(tmp_path.iterdir())


def test_scripts_still_parse():
    for f in sorted(GD.glob('*.sh')):
        r = subprocess.run(['bash', '-n', str(f)], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, f'{f.name}: {r.stderr}'
