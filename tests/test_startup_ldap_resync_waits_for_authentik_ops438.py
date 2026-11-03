"""ops #438: the boot-time LDAP service-account heal waits for Authentik before it judges the bind.

Field, Nov 2 (24.04 reboot): the console started at 18:15:31, the heal ran at 18:16:05 while
Authentik still answered its LDAP outpost with 502/503, and it logged "LDAP service account
resync incomplete — LDAP flow fix failed: [Errno 104] Connection reset by peer". At boot a
failing bind means Authentik is starting, not drift. The heal now waits for Authentik to answer,
retries once on a transient error, and the 5-min watchdog doesn't heal alongside it.
"""
import pathlib
import re
import threading
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


_c = re.search(r'^_STARTUP_LDAP_AK_WAIT_S = .*?(?=\n\n\ndef _startup_resync_ldap_service_account)', APP, re.S | re.M)
# Without the fix there are no constants; the defaults let the tests show the old behavior.
CONSTS = _c.group(0) if _c else ("_STARTUP_LDAP_AK_WAIT_S = 600\n_STARTUP_LDAP_TRANSIENT = ()\n"
                                 "_startup_ldap_resync_done = threading.Event()\n")
FIELD_ERR = 'LDAP flow fix failed: [Errno 104] Connection reset by peer'


class Boot:
    """Runs _startup_resync_ldap_service_account against a fake box. `ak` is the sequence of
    Authentik answers (True = answers); the last one repeats."""

    def __init__(self, ak=(True,), verdicts=('ok',), resync=((True, 'ok'),), compose=True):
        self.ak = list(ak)
        self.verdicts = list(verdicts)
        self.resync = list(resync)
        self.events = []
        self.slept = 0
        clock = [0.0]

        def sleep(n):
            self.slept += n
            clock[0] += n

        def ak_ok():
            a = self.ak.pop(0) if len(self.ak) > 1 else self.ak[0]
            self.events.append(('ak', a))
            return a

        def verdict(dn, pw):
            v = self.verdicts.pop(0) if len(self.verdicts) > 1 else self.verdicts[0]
            self.events.append(('probe', v))
            return v

        def ensure():
            r = self.resync.pop(0) if len(self.resync) > 1 else self.resync[0]
            self.events.append(('resync', r[0]))
            return r

        self.out = []
        os_ns = types.SimpleNamespace(path=types.SimpleNamespace(
            isdir=lambda p: True, expanduser=lambda p: p,
            exists=lambda p: compose if p.endswith('docker-compose.yml') else True))
        self.ns = {
            'os': os_ns, 'threading': threading,
            'time': types.SimpleNamespace(time=lambda: clock[0], sleep=sleep),
            'print': lambda *a, **k: self.out.append(' '.join(str(x) for x in a)),
            '_coreconfig_has_ldap': lambda: True,
            'load_settings': lambda: {},
            '_get_authentik_env_value': lambda s, k: 'pw',
            '_authentik_busy_reason': lambda: '',
            '_local_authentik_http_ok': ak_ok,
            '_test_ldap_bind_dn_verdict': verdict,
            '_ensure_authentik_ldap_service_account': ensure,
            '_resync_ldap_credential_to_coreconfig': lambda: (False, ''),
            '_tak_recycle_after_ldap_outage': lambda *a, **k: self.events.append(('recycle',)),
        }
        exec(compile(CONSTS + '\n' + _fn('_startup_resync_ldap_service_account'),
                     'app.py:_startup_resync_ldap_service_account', 'exec'), self.ns)

    def go(self):
        self.ns['_startup_resync_ldap_service_account']()
        return self


def test_boot_heal_probes_the_bind_only_after_authentik_answers_ops438():
    # The old code probed at once, while Authentik was still starting.
    b = Boot(ak=(False, False, False, True)).go()
    first_probe = b.events.index(('probe', 'ok'))
    assert ('ak', True) in b.events[:first_probe]
    assert not any(e[0] == 'resync' for e in b.events)
    assert b.ns['_startup_ldap_resync_done'].is_set()


def test_boot_heal_retries_once_when_authentik_resets_the_connection_ops438():
    # The field error, then Authentik answers: the second try heals.
    b = Boot(verdicts=('fail', 'ok'), resync=((False, FIELD_ERR), (True, 'password set'))).go()
    assert [e for e in b.events if e[0] == 'resync'] == [('resync', False), ('resync', True)]
    assert any('resync OK' in line for line in b.out)
    assert not any('resync incomplete' in line for line in b.out)


def test_boot_heal_does_not_retry_a_real_failure_ops438():
    b = Boot(verdicts=('fail',), resync=((False, 'adm_ldapservice not found'),)).go()
    assert [e for e in b.events if e[0] == 'resync'] == [('resync', False)]
    assert any('resync incomplete' in line for line in b.out)


def test_boot_heal_leaves_it_to_the_watchdog_when_authentik_never_answers_ops438():
    b = Boot(ak=(False,)).go()
    assert not any(e[0] in ('probe', 'resync') for e in b.events)
    assert b.slept >= b.ns['_STARTUP_LDAP_AK_WAIT_S']
    assert any('5-min watchdog' in line for line in b.out)
    assert b.ns['_startup_ldap_resync_done'].is_set()


def test_boot_heal_skips_the_wait_for_remote_authentik_ops438():
    b = Boot(ak=(False,), compose=False).go()
    assert ('ak', False) not in b.events and b.events[0] == ('probe', 'ok')


def test_watchdog_waits_for_the_boot_heal_before_its_first_tick_ops438():
    body = _fn('_authentik_ldap_sa_bind_watchdog_loop')
    code = re.sub(r'#.*', '', body)
    assert code.index('_startup_ldap_resync_done') < code.index('while True:')
    assert '.wait(timeout=' in code
