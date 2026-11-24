"""The per-username sign-in limit on Authentik's ldap-authentication-flow.

TAK Server (8446/8089 passwords) and every other LDAP client sign in through that flow.
The limit is Authentik's ReputationPolicy `infratak-brute-force`: a failed sign-in lowers
the score of that username, and at the threshold the name is refused until the score
recovers.

Where the policy is bound decides whose score it reads. FakeAuthentik below follows
Authentik's own rules (read from the 2026.8.6 source, see the comment above
_AK_LDAP_FLOW_SLUG in app.py):
  - a policy on the flow is evaluated when the flow is planned, before any name is given;
  - a policy on a stage binding (re_evaluate_policies) is evaluated when the stage is
    reached, with the name the identification stage accepted; not passing REMOVES the stage;
  - a binding with no policy passes for everyone;
  - a deny stage ends the flow.

So the tests sign in against the fake the way the LDAP outpost does and look at the result
a customer would see, and they check the flow after every single API call the console
makes: a half-built limit must never refuse a good sign-in or skip the password.
"""
import io
import json
import pathlib
import re
import types
import urllib.error
import urllib.parse
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

SA = 'adm_ldapservice'
IDENT = 'authentik_stages_identification.identificationstage'
PASSWORD = 'authentik_stages_password.passwordstage'
LOGIN = 'authentik_stages_user_login.userloginstage'
DENY = 'authentik_stages_deny.denystage'
NO_PASSWORD = 'SIGNED IN WITHOUT A PASSWORD CHECK'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _helpers():
    """The constants and helpers of the limit. Empty when app.py has none (the base branch):
    the sign-in tests then still run against whatever the setup function builds."""
    m = re.search(r'^_AK_LDAP_FLOW_SLUG = .*?(?=^def _authentik_setup_reputation_policy\()', APP, re.S | re.M)
    return m.group(0) if m else ''


class Resp:
    def __init__(self, body):
        self._b = b'' if body is None else json.dumps(body).encode()

    def read(self):
        return self._b


def http_error(code, body='boom'):
    return urllib.error.HTTPError('http://ak', code, 'err', {}, io.BytesIO(body.encode()))


class FakeAuthentik:
    """Authentik's API for flows, stages, bindings and policies, plus a sign-in."""

    def __init__(self, ident_order=10, password_order=15):
        self.n = 0
        self.flows = {}          # pk -> {pk, slug, policybindingmodel_ptr_id}
        self.stages = {}         # pk -> {pk, name, model}
        self.fsbs = {}           # pk -> flow stage binding
        self.policies = {}       # pk -> {pk, name, kind, ...}
        self.pbindings = {}      # pk -> policy binding
        self.scores = {}         # username -> score
        self.calls = []          # (method, path) of every write
        self.fail_write = None   # index of the write that answers HTTP 500
        self.after_write = None  # callback after every write
        flow = self._add_flow('ldap-authentication-flow')
        for model, order in ((IDENT, ident_order), (PASSWORD, password_order), (LOGIN, 20)):
            st = self._add_stage(model.split('.')[-1], model)
            self._add_fsb(flow['pk'], st['pk'], order)
        self.ldap_flow = flow

    # ------------------------------------------------------------ objects
    def _id(self, prefix):
        self.n += 1
        return f'{prefix}-{self.n}'

    def _add_flow(self, slug):
        pk = self._id('flow')
        self.flows[pk] = {'pk': pk, 'slug': slug, 'policybindingmodel_ptr_id': 'pbm-' + pk}
        return self.flows[pk]

    def _add_stage(self, name, model):
        pk = self._id('stage')
        self.stages[pk] = {'pk': pk, 'name': name, 'model': model}
        return self.stages[pk]

    def _add_fsb(self, target, stage, order, evaluate_on_plan=False, re_evaluate_policies=True):
        pk = self._id('fsb')
        self.fsbs[pk] = {'pk': pk, 'policybindingmodel_ptr_id': 'pbm-' + pk, 'target': target,
                         'stage': stage, 'order': order, 'evaluate_on_plan': evaluate_on_plan,
                         're_evaluate_policies': re_evaluate_policies}
        return self.fsbs[pk]

    def add_policy(self, kind, **attrs):
        pk = self._id('policy')
        self.policies[pk] = dict(attrs, pk=pk, kind=kind)
        return self.policies[pk]

    def add_pbinding(self, policy, target, negate=False, failure_result=False, enabled=True, order=0):
        pk = self._id('pb')
        self.pbindings[pk] = {'pk': pk, 'policy': policy, 'target': target, 'negate': negate,
                              'failure_result': failure_result, 'enabled': enabled, 'order': order,
                              'timeout': 30}
        return self.pbindings[pk]

    def _pbm_ids(self):
        return ({f['policybindingmodel_ptr_id'] for f in self.flows.values()}
                | {f['policybindingmodel_ptr_id'] for f in self.fsbs.values()})

    def _drop_fsb(self, pk):
        fsb = self.fsbs.pop(pk)
        for b in [b for b in self.pbindings.values() if b['target'] == fsb['policybindingmodel_ptr_id']]:
            del self.pbindings[b['pk']]

    def _fsb_json(self, fsb):
        st = self.stages[fsb['stage']]
        return dict(fsb, stage_obj={'pk': st['pk'], 'name': st['name'], 'meta_model_name': st['model']})

    # ------------------------------------------------------------ policy engine
    def _policy_passes(self, policy, username):
        if policy['kind'] == 'reputation':
            return self.scores.get(username, 0) <= policy['threshold']
        body = 'def _expr(request, ak_call_policy):\n' + ''.join(
            '    ' + line + '\n' for line in policy['expression'].splitlines())
        ns = {}
        exec(body, ns)  # the text the console shipped, run as Authentik runs it

        def ak_call_policy(name):
            pol = next((p for p in self.policies.values() if p['name'] == name), None)
            if not pol:
                raise ValueError(f"Policy '{name}' not found.")
            return types.SimpleNamespace(passing=self._policy_passes(pol, username))

        request = types.SimpleNamespace(user=types.SimpleNamespace(username=username))
        return bool(ns['_expr'](request, ak_call_policy))

    def _target_passes(self, target, username):
        bindings = [b for b in self.pbindings.values() if b['target'] == target and b['enabled']]
        if not bindings:
            return True                      # Authentik: nothing bound = pass
        results = []
        for b in bindings:
            try:
                r = self._policy_passes(self.policies[b['policy']], username)
                if b['negate']:
                    r = not r
            except Exception:
                r = b['failure_result']
            results.append(r)
        return any(results)                  # policy_engine_mode: any

    def sign_in(self, username, good_password, keep_score=True):
        """One LDAP bind. Returns ok, invalid (wrong password), denied or NO_PASSWORD."""
        flow = self.ldap_flow
        if not self._target_passes(flow['policybindingmodel_ptr_id'], ''):   # no name yet
            return 'denied'
        pending, checked = None, False
        for fsb in sorted((f for f in self.fsbs.values() if f['target'] == flow['pk']),
                          key=lambda f: f['order']):
            model = self.stages[fsb['stage']]['model']
            if model == IDENT:
                pending = username
                continue
            if fsb['re_evaluate_policies'] and not self._target_passes(
                    fsb['policybindingmodel_ptr_id'], pending):
                continue                     # the stage is removed from the plan
            if model == DENY:
                return 'denied'
            if model == PASSWORD:
                if not good_password:
                    if keep_score:
                        self.scores[username] = max(-5, self.scores.get(username, 0) - 1)
                    return 'invalid'
                checked = True
            if model == LOGIN:
                if not checked:
                    return NO_PASSWORD
                if keep_score:
                    self.scores[username] = min(5, self.scores.get(username, 0) + 1)
                return 'ok'
        return 'no login stage'

    # ------------------------------------------------------------ API
    def urlopen(self, req, timeout=None):
        method = req.get_method()
        path = req.full_url.split('/api/v3/', 1)[1]
        body = json.loads(req.data.decode()) if req.data else None
        if method != 'GET':
            idx = len(self.calls)
            self.calls.append((method, path))
            if self.fail_write == idx:
                raise http_error(500)
        out = self._route(method, path, body)
        if method != 'GET' and self.after_write:
            self.after_write(method, path)
        return Resp(out)

    def _route(self, method, path, body):
        base, _, query = path.partition('?')
        q = dict(urllib.parse.parse_qsl(query))
        parts = [p for p in base.split('/') if p]
        coll, ident = '/'.join(parts[:2]), (parts[2] if len(parts) > 2 else None)

        if coll == 'core/users':
            return {'results': []}

        if base.startswith('policies/reputation/scores/'):
            if method == 'GET':
                return {'results': [{'pk': 'score-' + name, 'identifier': name, 'score': score}
                                    for name, score in self.scores.items()
                                    if q.get('identifier', name) == name]}
            if method == 'DELETE':
                del self.scores[parts[3][len('score-'):]]
                return None

        if coll in ('policies/reputation', 'policies/expression'):
            kind = parts[1]
            if method == 'GET':
                return {'results': [p for p in self.policies.values()
                                    if p['kind'] == kind and q.get('search', '') in p['name']]}
            if method == 'POST':
                return self.add_policy(kind, **body)
            if method == 'PATCH':
                self.policies[ident].update(body)
                return self.policies[ident]
            if method == 'DELETE':
                del self.policies[ident]
                for b in [b for b in self.pbindings.values() if b['policy'] == ident]:
                    del self.pbindings[b['pk']]
                return None

        if coll == 'flows/instances':
            if method == 'GET':
                return {'results': [f for f in self.flows.values() if f['slug'] == q.get('slug')]}
            if method == 'POST':
                return self._add_flow(body['slug'])
            if method == 'DELETE':               # addressed by slug
                flow = next(f for f in self.flows.values() if f['slug'] == ident)
                for fsb in [f for f in self.fsbs.values() if f['target'] == flow['pk']]:
                    self._drop_fsb(fsb['pk'])
                del self.flows[flow['pk']]
                return None

        if coll == 'stages/deny':
            if method == 'GET':
                return {'results': [s for s in self.stages.values()
                                    if s['model'] == DENY and q.get('search', '') in s['name']]}
            if method == 'POST':
                return self._add_stage(body['name'], DENY)
            if method == 'DELETE':
                for fsb in [f for f in self.fsbs.values() if f['stage'] == ident]:
                    self._drop_fsb(fsb['pk'])
                del self.stages[ident]
                return None

        if coll == 'flows/bindings':
            if method == 'GET':
                rows = [f for f in self.fsbs.values()
                        if q.get('target', f['target']) == f['target']
                        and q.get('stage', f['stage']) == f['stage']]
                return {'results': [self._fsb_json(f) for f in sorted(rows, key=lambda f: f['order'])]}
            if method == 'POST':
                if body['target'] not in self.flows or body['stage'] not in self.stages:
                    raise http_error(400, 'Select a valid choice')
                if not body.get('evaluate_on_plan', False) and not body.get('re_evaluate_policies', True):
                    raise http_error(400, 'Either evaluation on plan or evaluation on run must be enabled')
                return self._fsb_json(self._add_fsb(
                    body['target'], body['stage'], body['order'],
                    body.get('evaluate_on_plan', False), body.get('re_evaluate_policies', True)))
            if method == 'PATCH':
                if 'target' in body and body['target'] not in self.flows:
                    raise http_error(400, 'Select a valid choice')
                self.fsbs[ident].update(body)
                return self._fsb_json(self.fsbs[ident])
            if method == 'DELETE':
                self._drop_fsb(ident)
                return None

        if coll == 'policies/bindings':
            if method == 'GET':
                return {'results': [b for b in self.pbindings.values()
                                    if q.get('target', b['target']) == b['target']
                                    and q.get('policy', b['policy']) == b['policy']]}
            if method == 'POST':
                # The target is a policybindingmodel_ptr_id; a flow's or binding's own pk is refused.
                if body['target'] not in self._pbm_ids() or body['policy'] not in self.policies:
                    raise http_error(400, 'Select a valid choice')
                return self.add_pbinding(body['policy'], body['target'], body.get('negate', False),
                                         body.get('failure_result', False), body.get('enabled', True),
                                         body.get('order', 0))
            if method == 'DELETE':
                del self.pbindings[ident]
                return None

        raise AssertionError(f'FakeAuthentik: unexpected {method} {path}')

    # ------------------------------------------------------------ shortcuts
    def old_layout(self, negate=True):
        """What the console built before: the policy bound to the flow itself."""
        pol = self.add_policy('reputation', name='infratak-brute-force', threshold=-5,
                              check_ip=False, check_username=True)
        self.add_pbinding(pol['pk'], self.ldap_flow['policybindingmodel_ptr_id'],
                          negate=negate, failure_result=True)
        return pol

    def limit_bindings(self):
        """(stage binding, its policy bindings) for every deny stage on the LDAP flow."""
        out = []
        for fsb in self.fsbs.values():
            if fsb['target'] == self.ldap_flow['pk'] and self.stages[fsb['stage']]['model'] == DENY:
                out.append((fsb, [b for b in self.pbindings.values()
                                  if b['target'] == fsb['policybindingmodel_ptr_id']]))
        return out


class Console:
    """The console functions under test, wired to a FakeAuthentik."""

    def __init__(self, ak, monkeypatch, settings=None):
        self.ak = ak
        self.settings = settings if settings is not None else {}
        self.log = []
        fake_os = types.SimpleNamespace(path=types.SimpleNamespace(
            exists=lambda p: True, isdir=lambda p: True, expanduser=lambda p: p))
        import datetime as _dt
        self.ns = {
            'json': json, 'os': fake_os, 'datetime': _dt.datetime,
            'load_settings': lambda: json.loads(json.dumps(self.settings)),
            'save_settings': self._save,
            '_get_authentik_env_value': lambda s, k: 'tok',
            '_get_authentik_api_url': lambda s: 'http://ak',
            'print': lambda *a, **k: self.log.append(' '.join(str(x) for x in a)),
        }
        exec(_helpers(), self.ns)
        exec(_fn('_authentik_setup_reputation_policy'), self.ns)
        exec(_fn('_startup_fix_reputation_policy_drift'), self.ns)
        monkeypatch.setattr(urllib.request, 'urlopen', ak.urlopen)

    def _save(self, s):
        self.settings.clear()
        self.settings.update(s)

    def setup(self):
        return self.ns['_authentik_setup_reputation_policy'](self.log.append)

    def startup_fix(self):
        return self.ns['_startup_fix_reputation_policy_drift']()


def _guess(ak, username, times):
    return [ak.sign_in(username, good_password=False) for _ in range(times)]


# --------------------------------------------------------------------------- the proof

def test_wrong_passwords_for_a_known_name_are_limited(monkeypatch):
    """Proof test. Five wrong passwords for alice, then the limit holds even for the right
    password, and for nobody else."""
    ak = FakeAuthentik()
    Console(ak, monkeypatch).setup()
    assert ak.sign_in('alice', good_password=True) == 'ok'
    ak.scores.clear()

    assert _guess(ak, 'alice', 5) == ['invalid'] * 5
    assert ak.sign_in('alice', good_password=True) == 'denied', \
        'alice is not held at the limit after five wrong passwords'
    assert ak.sign_in('alice', good_password=False) == 'denied'
    # Nobody else is touched.
    assert ak.sign_in('bob', good_password=True) == 'ok'


def test_limit_also_holds_on_a_box_that_had_the_old_layout(monkeypatch):
    ak = FakeAuthentik()
    ak.old_layout()
    Console(ak, monkeypatch, {'authentik_reputation_policy': {'last_outcome': 'applied'}}).setup()
    _guess(ak, 'alice', 5)
    assert ak.sign_in('alice', good_password=True) == 'denied'
    flow_target = ak.ldap_flow['policybindingmodel_ptr_id']
    assert not [b for b in ak.pbindings.values() if b['target'] == flow_target], \
        'the flow-level binding is still there'


def test_service_account_is_never_locked_out(monkeypatch):
    """TAK Server binds as adm_ldapservice for every lookup, so failed binds for that
    name must never stop it."""
    ak = FakeAuthentik()
    Console(ak, monkeypatch).setup()
    assert _guess(ak, SA, 20) == ['invalid'] * 20
    assert ak.scores[SA] <= -5
    assert ak.sign_in(SA, good_password=True) == 'ok'


def test_score_recovery_lets_the_name_in_again(monkeypatch):
    """Clear scores on the Authentik page (or Authentik's own expiry) ends the lockout."""
    ak = FakeAuthentik()
    Console(ak, monkeypatch).setup()
    _guess(ak, 'alice', 5)
    assert ak.sign_in('alice', good_password=True) == 'denied'
    ak.scores.clear()
    assert ak.sign_in('alice', good_password=True) == 'ok'


# --------------------------------------------------------------------------- never break sign-in

def _watch_every_write(ak):
    """After every write the console makes, a good sign-in must work and no sign-in may
    skip the password check."""
    seen = []

    def check(method, path):
        for name in ('carol', SA):
            got = ak.sign_in(name, good_password=True, keep_score=False)
            assert got == 'ok', f'after {method} {path}: {name} with the right password got {got!r}'
            got = ak.sign_in(name, good_password=False, keep_score=False)
            assert got == 'invalid', f'after {method} {path}: {name} with a wrong password got {got!r}'
        seen.append((method, path))

    ak.after_write = check
    return seen


@pytest.mark.parametrize('start', ['fresh', 'old'])
def test_no_api_call_leaves_good_sign_ins_refused(monkeypatch, start):
    ak = FakeAuthentik()
    if start == 'old':
        ak.old_layout()
    seen = _watch_every_write(ak)
    Console(ak, monkeypatch).setup()
    assert seen, 'the setup made no API writes'
    assert len(ak.limit_bindings()) == 1


def test_limit_is_a_deny_stage_between_name_and_password(monkeypatch):
    """A policy on the password stage's own binding would DROP the password stage for a
    name over the limit and sign it in with no password. The limit has its own stage."""
    ak = FakeAuthentik()
    Console(ak, monkeypatch).setup()
    (fsb, bindings), = ak.limit_bindings()
    assert 10 < fsb['order'] < 15
    assert fsb['evaluate_on_plan'] is False and fsb['re_evaluate_policies'] is True
    assert len(bindings) == 1
    b = bindings[0]
    assert (b['negate'], b['failure_result'], b['enabled']) == (False, False, True)
    for other in ak.fsbs.values():
        if ak.stages[other['stage']]['model'] != DENY:
            assert not [x for x in ak.pbindings.values()
                        if x['target'] == other['policybindingmodel_ptr_id']], \
                'a policy is bound to a stage that is not the deny stage'
    _guess(ak, 'alice', 5)
    assert ak.sign_in('alice', good_password=True) != NO_PASSWORD


def test_second_run_changes_nothing(monkeypatch):
    ak = FakeAuthentik()
    con = Console(ak, monkeypatch)
    con.setup()
    first = len(ak.calls)
    con.setup()
    con.startup_fix()
    assert ak.calls[first:] == [], f'a second run wrote again: {ak.calls[first:]}'


def test_any_failed_api_call_leaves_sign_in_working_and_the_next_run_finishes(monkeypatch):
    """Authentik answers 500 on each write in turn. Good sign-ins keep working after the
    failed run, and a clean run afterwards ends with the limit in place."""
    probe = FakeAuthentik()
    probe.old_layout()
    Console(probe, monkeypatch).setup()
    writes = len(probe.calls)
    assert writes >= 5
    for i in range(writes):
        ak = FakeAuthentik()
        ak.old_layout()
        con = Console(ak, monkeypatch)
        ak.fail_write = i
        con.setup()
        for name in ('carol', SA):
            assert ak.sign_in(name, good_password=True, keep_score=False) == 'ok', \
                f'write {i} ({probe.calls[i]}) failed and {name} can no longer sign in'
        ak.fail_write = None
        con.setup()
        assert len(ak.limit_bindings()) == 1, f'no limit after recovering from failed write {i}'
        _guess(ak, 'alice', 5)
        assert ak.sign_in('alice', good_password=True) == 'denied'
        assert not [f for f in ak.flows.values() if f['slug'] != 'ldap-authentication-flow'], \
            f'the scratch flow was left behind after failed write {i}'


def test_flow_without_room_is_left_alone(monkeypatch):
    """An operator's own flow layout with no free order between the two stages: do not
    guess. The limit is not installed and sign-ins work."""
    ak = FakeAuthentik(ident_order=10, password_order=11)
    seen = _watch_every_write(ak)
    con = Console(ak, monkeypatch)
    con.setup()
    assert ak.limit_bindings() == []
    assert any('NOT installed' in line for line in con.log)
    assert seen is not None


# --------------------------------------------------------------------------- repair and startup

def test_startup_repairs_a_limit_stage_that_lost_its_policy(monkeypatch):
    """A deny-stage binding with no policy refuses every LDAP sign-in. The startup check
    repairs it and says so (the caller then also heals TAK Server's LDAP connections)."""
    ak = FakeAuthentik()
    con = Console(ak, monkeypatch)
    con.setup()
    (fsb, bindings), = ak.limit_bindings()
    del ak.pbindings[bindings[0]['pk']]
    assert ak.sign_in('carol', good_password=True, keep_score=False) == 'denied'

    assert con.startup_fix() is True
    assert ak.sign_in('carol', good_password=True, keep_score=False) == 'ok'
    assert ak.sign_in(SA, good_password=True, keep_score=False) == 'ok'
    _guess(ak, 'alice', 5)
    assert ak.sign_in('alice', good_password=True) == 'denied'


def test_startup_repairs_the_old_binding_without_negate(monkeypatch):
    ak = FakeAuthentik()
    ak.old_layout(negate=False)
    assert ak.sign_in('carol', good_password=True, keep_score=False) == 'denied'
    con = Console(ak, monkeypatch)
    assert con.startup_fix() is True
    assert ak.sign_in('carol', good_password=True, keep_score=False) == 'ok'


def test_startup_on_a_healthy_old_box_reports_no_repair(monkeypatch):
    """Moving a healthy box to the new layout is not a repair: reporting one would make
    the startup LDAP check restart-heal TAK Server on every box at update time."""
    ak = FakeAuthentik()
    ak.old_layout()
    seen = _watch_every_write(ak)
    con = Console(ak, monkeypatch)
    assert con.startup_fix() is False
    assert seen and len(ak.limit_bindings()) == 1


# --------------------------------------------------------------------------- Disable holds

def test_disable_on_the_authentik_page_removes_the_limit_and_holds(monkeypatch):
    ak = FakeAuthentik()
    con = Console(ak, monkeypatch)
    con.setup()
    seen = _watch_every_write(ak)
    con.settings['authentik_reputation_policy'] = {'last_outcome': 'disabled', 'threshold': -5}

    assert con.setup() is False
    assert con.startup_fix() is False
    assert seen, 'nothing was removed'
    assert ak.limit_bindings() == []
    assert not [s for s in ak.stages.values() if s['model'] == DENY]
    assert not [p for p in ak.policies.values() if p['kind'] == 'expression']
    assert con.settings['authentik_reputation_policy']['last_outcome'] == 'disabled'
    _guess(ak, 'alice', 8)
    assert ak.sign_in('alice', good_password=True) == 'ok'


def test_disable_route_takes_the_stage_binding_off_before_the_policy():
    """The route deletes the ReputationPolicy. The limit must come off first."""
    route = _fn('authentik_reputation_config_api')
    assert '_ak_ldap_gate_remove(' in route
    assert route.index('_ak_ldap_gate_remove(') < route.index("method='DELETE'")


def test_expression_is_safe_when_the_reputation_policy_is_gone(monkeypatch):
    """After a rollback the older console's Disable deletes only the ReputationPolicy.
    The limit's policy then lets everyone through instead of failing."""
    ak = FakeAuthentik()
    Console(ak, monkeypatch).setup()
    rep = next(p for p in ak.policies.values() if p['kind'] == 'reputation')
    del ak.policies[rep['pk']]
    _guess(ak, 'alice', 8)
    assert ak.sign_in('alice', good_password=True) == 'ok'
    assert ak.sign_in(SA, good_password=True) == 'ok'


def test_older_console_cannot_break_the_limit_after_a_rollback(monkeypatch):
    """The released console rewrites every binding OF infratak-brute-force to negate=True
    at startup. The limit's own binding must not be one of those, or a rollback would turn
    the deny stage on for every good name."""
    ak = FakeAuthentik()
    Console(ak, monkeypatch).setup()
    rep = next(p for p in ak.policies.values() if p['kind'] == 'reputation')
    assert not [b for b in ak.pbindings.values() if b['policy'] == rep['pk']], \
        'infratak-brute-force is bound directly; the released console would negate that binding'


# --------------------------------------------------------------------------- one name's count

def test_clear_name_forgets_only_that_name(monkeypatch):
    ak = FakeAuthentik()
    con = Console(ak, monkeypatch)
    con.setup()
    _guess(ak, 'alice', 5)
    _guess(ak, 'bob', 5)
    ak.scores['carol'] = 3
    assert con.ns['_ak_ldap_gate_clear_name']('http://ak', {}, 'alice') == 1
    assert ak.sign_in('alice', good_password=True) == 'ok'
    assert ak.sign_in('bob', good_password=True) == 'denied'
    assert ak.scores['carol'] == 3
    assert con.ns['_ak_ldap_gate_clear_name']('http://ak', {}, 'carol') == 0


def test_webadmin_sync_lifts_the_limit_before_it_would_delete_the_user():
    """Sync webadmin deletes and recreates the user when its bind is refused. A name held
    by the limit is refused with the right password, and the count is kept by name, so
    the count is cleared and the bind probed again before that path."""
    fn = _fn('_ensure_authentik_webadmin')
    clear = fn.index("_ak_ldap_gate_clear_name(url, headers, 'webadmin')")
    delete = fn.index("method='DELETE'")
    assert clear < delete
    assert "_test_ldap_bind_dn_verdict('cn=webadmin,ou=users,dc=takldap', webadmin_pass)" in fn[clear:delete]
