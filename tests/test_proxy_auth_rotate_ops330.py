"""ops #330: rotate the X-Infratak-Proxy-Auth secret from the console.

Runs the real `_rotate_proxy_auth_secret` and `_apply_authentik_session` against a fake host,
plus the ATLAS half (`rotate_proxy_auth_secret`) against a temp `.env`.

What must hold:
  - success: new secret in the Caddyfile, Caddy reloaded WITHOUT the restart fallback, ATLAS
    switched, `previous` dropped, old value no longer accepted;
  - every failure (Caddy rejects the file, reload refused, running config not updated, ATLAS
    fails) puts the secret file and the Caddyfile back, and the old value still works;
  - while a rotation runs, the console accepts old AND new (Caddy is still sending the old one
    until its reload lands); an empty secret never authenticates.
"""
import hmac
import json
import pathlib
import re
import sys
import threading
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
APP = (REPO / 'app.py').read_text(encoding='utf-8')

OLD = 'a' * 64
CF_PATH = '/etc/caddy/Caddyfile'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _caddyfile(secret):
    return ('infratak.example.com {\n'
            '    request_header -X-Infratak-Proxy-Auth\n'
            '    forward_auth @needs_sso authentik:9000 {\n    }\n'
            '    request_header @needs_sso X-Infratak-Proxy-Auth %s\n}\n' % secret)


class Host:
    def __init__(self, tmp_path, monkeypatch, *, fqdn='infratak.example.com', validate_rejects=False,
                 reload_ok=True, running_has_new=True, atlas=None, atlas_enabled=False, caddyfile_has_old=True):
        self.state = {'secret': OLD, 'enforce': True}
        self.files = {CF_PATH: _caddyfile(OLD) if caddyfile_has_old else 'x {\n}\n'}
        self.saved_states, self.reloads, self.audits, self.atlas_calls = [], [], [], []
        self.priv_writes = []
        host = self
        self.atlas = atlas or (lambda ctx, secret, plog=None: (1, []))

        def save_state(st):
            host.state = dict(st)
            host.saved_states.append(dict(st))

        def generate(settings=None):
            sec = host.state['secret']
            if validate_rejects:
                return  # generate_caddyfile restored the old file itself
            host.files[CF_PATH] = _caddyfile(sec)

        def write_priv(path, content, **kw):
            host.files[path] = content
            host.priv_writes.append((path, content))

        def reload(plog=None, timeout=None, restart_on_error=True):
            host.reloads.append({'restart_on_error': restart_on_error, 'file': host.files[CF_PATH]})
            return (reload_ok, '' if reload_ok else 'rc=1 bad config')

        os_ns = types.SimpleNamespace(
            makedirs=lambda *a, **k: None, O_WRONLY=1, O_CREAT=2, O_TRUNC=4,
            open=lambda p, flags, mode: p,
            fdopen=lambda p, m: _W(host, p),
            path=types.SimpleNamespace(join=lambda *a: '/'.join(a), dirname=lambda p: p.rsplit('/', 1)[0]))
        atlas_mod = types.SimpleNamespace(
            rotate_proxy_auth_secret=lambda ctx, secret, plog=None: (host.atlas_calls.append(secret),
                                                                      host.atlas(ctx, secret, plog))[1])
        self.ns = {
            'os': os_ns, 'json': json, 'secrets': __import__('secrets'), 'time': __import__('time'),
            'threading': threading, 'print': lambda *a, **k: None,
            'CONFIG_DIR': '/cfg', 'CADDYFILE_PATH': CF_PATH,
            '_proxy_auth_state': lambda create=False: dict(host.state),
            '_save_proxy_auth_state': save_state,
            'load_settings': lambda: {'fqdn': fqdn, 'atlas_enabled': atlas_enabled},
            '_read_priv': lambda p: host.files.get(p), '_write_priv': write_priv,
            'generate_caddyfile': generate,
            '_caddy_reload_if_changed': reload,
            '_caddy_last_validate_error': {'err': 'bad directive'},
            '_caddy_running_config_has': lambda needle: (
                None if running_has_new is None else (needle in host.files[CF_PATH] and running_has_new
                                                      and host.reloads[-1]['file'] == host.files[CF_PATH])),
            'audit': lambda ev, detail='', force=False: host.audits.append(ev),
            'mod_registry': types.SimpleNamespace(atlas=atlas_mod, get_ctx=lambda: {}),
            '_write_private_file': lambda path, content: host.files.__setitem__(path, content),
        }
        exec(compile("_PROXY_AUTH_BACKUP_FILE = '/cfg/proxy_auth.pre-rotate.json'\n"
                     "_PROXY_AUTH_CADDYFILE_BACKUP = '/cfg/Caddyfile.pre-rotate'\n"
                     "_proxy_auth_rotate_lock = threading.Lock()\n", 'x', 'exec'), self.ns)
        for name in ('_proxy_auth_atlas_apply', '_rotate_proxy_auth_secret'):
            exec(compile(_fn(name), 'app.py', 'exec'), self.ns)

    def rotate(self):
        return self.ns['_rotate_proxy_auth_secret']()


class _W:
    def __init__(self, host, p):
        self.host, self.p = host, p

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def write(self, s):
        self.host.files[self.p] = s


@pytest.fixture
def host(tmp_path, monkeypatch):
    return Host(tmp_path, monkeypatch)


# --- success -----------------------------------------------------------------------------

def test_success_swaps_the_secret_everywhere_and_drops_the_old_one(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, atlas_enabled=True)
    res = h.rotate()
    assert res['success'], res
    new = h.state['secret']
    assert new != OLD and re.fullmatch(r'[0-9a-f]{64}', new)
    assert 'previous' not in h.state and h.state['enforce'] is True and h.state['rotated_at']
    cf = h.files[CF_PATH]
    assert new in cf and OLD not in cf
    assert h.atlas_calls == [new]
    assert 'proxy-auth:rotated' in h.audits
    assert 'ATLAS updated to the new value' in res['steps']


def test_the_new_value_is_never_in_the_result_or_the_steps(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, atlas_enabled=True)
    res = h.rotate()
    blob = json.dumps(res)
    assert h.state['secret'] not in blob and OLD not in blob


def test_backup_is_taken_before_anything_changes(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch)
    h.rotate()
    assert json.loads(h.files['/cfg/proxy_auth.pre-rotate.json'])['secret'] == OLD
    assert OLD in h.files['/cfg/Caddyfile.pre-rotate']


def test_reload_never_falls_back_to_a_restart(tmp_path, monkeypatch):
    """A refused config must keep serving the old one; a restart would read the same bad file."""
    h = Host(tmp_path, monkeypatch)
    h.rotate()
    assert h.reloads and all(r['restart_on_error'] is False for r in h.reloads)


def test_both_values_are_accepted_while_caddy_catches_up(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch)
    seen = []
    orig = h.ns['_save_proxy_auth_state']
    h.ns['_save_proxy_auth_state'] = lambda st: (seen.append(dict(st)), orig(st))[1]
    h.rotate()
    mid = seen[0]
    assert mid['previous'] == OLD and mid['secret'] != OLD     # step 2 state
    assert 'previous' not in seen[-1]                          # finished state


# --- failures roll everything back ---------------------------------------------------------

def _assert_rolled_back(h, res):
    assert res['success'] is False
    assert h.state == {'secret': OLD, 'enforce': True}
    assert h.files[CF_PATH] == _caddyfile(OLD)
    assert 'proxy-auth:rotate-failed' in h.audits


def test_caddy_rejecting_the_new_file_changes_nothing(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, validate_rejects=True)
    res = h.rotate()
    _assert_rolled_back(h, res)
    assert 'bad directive' in res['error']
    assert res['rolled_back'] is True


def test_a_refused_reload_puts_the_old_file_and_secret_back(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, reload_ok=False)
    res = h.rotate()
    _assert_rolled_back(h, res)
    assert 'did not reload' in res['error']


def test_running_config_without_the_new_value_is_a_failure(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, running_has_new=False)
    res = h.rotate()
    _assert_rolled_back(h, res)
    assert 'not running the new value' in res['error']


def test_unreachable_admin_api_is_not_a_failure(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, running_has_new=None)
    assert h.rotate()['success'] is True


def test_atlas_failure_rolls_back_and_hands_atlas_the_old_value_again(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, atlas_enabled=True,
             atlas=lambda ctx, secret, plog=None: (0, ['takmdm: compose failed']) if secret != OLD else (1, []))
    res = h.rotate()
    _assert_rolled_back(h, res)
    assert 'ATLAS did not take the new value' in res['error']
    assert h.atlas_calls[-1] == OLD and len(h.atlas_calls) == 2


def test_incomplete_rollback_is_reported_not_hidden(tmp_path, monkeypatch):
    # reload fails both times (new, then the restore)
    h = Host(tmp_path, monkeypatch, reload_ok=False)
    res = h.rotate()
    assert res['success'] is False and res['rolled_back'] is False
    assert 'Rollback was incomplete' in res['error']
    # the files are back even though Caddy would not reload; Caddy never took the new config
    assert h.state['secret'] == OLD and h.files[CF_PATH] == _caddyfile(OLD)


def test_no_atlas_install_means_no_atlas_calls(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, atlas_enabled=False)
    h.rotate()
    assert h.atlas_calls == []


# --- refusals before anything is touched -------------------------------------------------------

def test_no_domain_means_nothing_to_rotate(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, fqdn='')
    res = h.rotate()
    assert res['success'] is False and h.saved_states == [] and h.reloads == []


def test_caddy_not_sending_the_value_changes_nothing(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch, caddyfile_has_old=False)
    res = h.rotate()
    assert res['success'] is False and h.saved_states == [] and h.reloads == []
    assert h.state['secret'] == OLD


def test_a_second_rotation_at_the_same_time_is_refused(tmp_path, monkeypatch):
    h = Host(tmp_path, monkeypatch)
    h.ns['_proxy_auth_rotate_lock'].acquire()
    res = h.rotate()
    assert res['success'] is False and 'already running' in res['error']
    assert h.saved_states == []


# --- the console side: old+new while rotating, never empty ---------------------------------------

class _Req:
    def __init__(self, headers):
        self.remote_addr = '127.0.0.1'
        self.headers = headers


def _apply(state, headers):
    session = {}
    ns = {'request': _Req(headers), 'session': session, 'hmac': hmac, 'time': __import__('time'),
          '_proxy_auth_state': lambda create=False: state}
    exec(compile(_fn('_apply_authentik_session'), 'app.py', 'exec'), ns)
    return ns['_apply_authentik_session'](), session


def test_console_accepts_new_and_previous_during_rotation_and_nothing_else():
    st = {'enforce': True, 'secret': 'n' * 64, 'previous': 'o' * 64}
    h = {'X-Authentik-Username': 'bob'}
    assert _apply(st, dict(h, **{'X-Infratak-Proxy-Auth': 'n' * 64}))[0] is True
    assert _apply(st, dict(h, **{'X-Infratak-Proxy-Auth': 'o' * 64}))[0] is True
    assert _apply(st, dict(h, **{'X-Infratak-Proxy-Auth': 'x' * 64}))[0] is False
    assert _apply(st, h)[0] is False


def test_after_rotation_the_old_value_is_dead():
    st = {'enforce': True, 'secret': 'n' * 64}
    h = {'X-Authentik-Username': 'bob'}
    assert _apply(st, dict(h, **{'X-Infratak-Proxy-Auth': 'o' * 64}))[0] is False
    assert _apply(st, dict(h, **{'X-Infratak-Proxy-Auth': 'n' * 64}))[0] is True


def test_empty_values_never_authenticate_even_with_an_empty_previous():
    st = {'enforce': True, 'secret': 'n' * 64, 'previous': ''}
    assert _apply(st, {'X-Authentik-Username': 'bob', 'X-Infratak-Proxy-Auth': ''})[0] is False
    st = {'enforce': True, 'secret': '', 'previous': ''}
    assert _apply(st, {'X-Authentik-Username': 'bob', 'X-Infratak-Proxy-Auth': ''})[0] is False


# --- ATLAS: its own copy of the secret --------------------------------------------------------

@pytest.fixture
def atlas(tmp_path, monkeypatch):
    from modules import atlas as atlas_mod
    env = tmp_path / '.env'
    env.write_text('A=1\nTAKMDM_PROXY_AUTH_SECRET=' + OLD + '\nB=2\n')
    calls = []
    monkeypatch.setattr(atlas_mod, 'load_instances', lambda ctx: [{'slug': ''}])
    monkeypatch.setattr(atlas_mod, 'instance_is_built', lambda ctx, inst, projects=None: True)
    monkeypatch.setattr(atlas_mod, 'instance_paths', lambda ctx=None, inst=None: {'dir': str(tmp_path)})
    monkeypatch.setattr(atlas_mod, '_repair_env_ownership', lambda *a, **k: False)
    rc = {'code': 0}
    monkeypatch.setattr(atlas_mod, '_compose', lambda ctx, action, timeout=180, inst=None: (
        calls.append(action), types.SimpleNamespace(returncode=rc['code'], stdout='', stderr='boom'))[1])
    return atlas_mod, env, calls, rc


def test_atlas_env_line_is_replaced_and_the_api_container_recreated(atlas):
    mod, env, calls, _ = atlas
    touched, errors = mod.rotate_proxy_auth_secret({}, 'b' * 64)
    assert (touched, errors) == (1, [])
    assert env.read_text() == 'A=1\nTAKMDM_PROXY_AUTH_SECRET=' + 'b' * 64 + '\nB=2\n'
    assert calls == ['up -d api']          # `up -d`, never `restart` (a restart keeps the old env)


def test_atlas_without_the_line_is_left_alone(atlas):
    mod, env, calls, _ = atlas
    env.write_text('A=1\n')
    assert mod.rotate_proxy_auth_secret({}, 'b' * 64) == (0, [])
    assert env.read_text() == 'A=1\n' and calls == []


def test_atlas_compose_failure_is_reported(atlas):
    mod, env, calls, rc = atlas
    rc['code'] = 1
    touched, errors = mod.rotate_proxy_auth_secret({}, 'b' * 64)
    assert touched == 0 and len(errors) == 1 and 'docker compose up' in errors[0]
    # `.env` goes back to what the still-running container has, and compose gets one more go
    assert env.read_text() == 'A=1\nTAKMDM_PROXY_AUTH_SECRET=' + OLD + '\nB=2\n'
    assert calls == ['up -d api', 'up -d api']
    # so the console's rollback (same call with the old value) finds nothing left to do
    calls.clear()
    assert mod.rotate_proxy_auth_secret({}, OLD) == (1, []) and calls == []


def test_atlas_already_on_the_value_does_not_recreate_the_container(atlas):
    mod, env, calls, _ = atlas
    assert mod.rotate_proxy_auth_secret({}, OLD) == (1, [])
    assert calls == []
