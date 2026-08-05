# TAKWERX Console - Module Package
"""infra-TAK module registry — SOLID Wave 3 (v10.1.22).

One descriptor per module, one generic deploy-job runner, one generic route
registrar. Module files live one-per-file in this package and receive every
app.py seam through a plain `ctx` dict — they import NOTHING from app.py
(the Dependency Rule boundary; see /pre-merge-check §3).

Deliberately plain dicts + functions: no class hierarchies, no DI framework.
Third-party imports (flask, werkzeug) are lazy so `import modules` stays clean
on a bare interpreter (smoke.py / acceptance checks run without the venv).
"""
import threading
from datetime import datetime

# key -> descriptor dict (see _validate_descriptor for the contract)
MODULES = {}

# per-module job slots — deliberately NOT the cloudtak-plugin single global slot
_JOBS = {}
_LOCKS = {}

_CTX = None

_REQUIRED_FIELDS = ('key', 'name', 'description', 'icon', 'route', 'template',
                    'priority', 'detect', 'deploy', 'uninstall', 'control_map')
_CALLABLE_FIELDS = ('detect', 'deploy', 'uninstall')


def get_ctx():
    """The ctx dict handed to load_all() by app.py (None before load_all runs)."""
    return _CTX


def _validate_descriptor(desc):
    """Fail fast at import with a clear message — a bad descriptor must never
    half-register (smoke.py py_compiles modules/*.py before any box pull)."""
    if not isinstance(desc, dict):
        raise ValueError('module descriptor must be a dict')
    key = desc.get('key')
    missing = [f for f in _REQUIRED_FIELDS if f not in desc]
    if missing:
        raise ValueError(f"module descriptor {key!r}: missing required fields {missing}")
    if not isinstance(key, str) or not key or not all(c.isalnum() or c in '-_' for c in key):
        raise ValueError(f"module descriptor: bad key {key!r} (want [a-z0-9_-]+)")
    for f in _CALLABLE_FIELDS:
        if not callable(desc[f]):
            raise ValueError(f"module descriptor {key!r}: {f} must be callable")
    if not isinstance(desc['control_map'], dict):
        raise ValueError(f"module descriptor {key!r}: control_map must be a dict verb -> argv")
    for verb, argv in desc['control_map'].items():
        # v10.1.24: values may be a static argv list OR a callable (ctx) -> argv,
        # resolved per request — for modules whose commands depend on runtime
        # state (e.g. TVR's compose dir: ~ on fresh installs, /root on flipped boxes).
        if not (callable(argv) or isinstance(argv, (list, tuple))):
            raise ValueError(f"module descriptor {key!r}: control_map[{verb!r}] must be an argv list or a callable (ctx) -> argv")
    if not isinstance(desc['priority'], int):
        raise ValueError(f"module descriptor {key!r}: priority must be an int")
    for f in ('conflicts', 'ports', 'service_units', 'settings_keys',
              'deploy_aliases', 'extra_routes'):
        if f in desc and not isinstance(desc[f], list):
            raise ValueError(f"module descriptor {key!r}: {f} must be a list")
    if 'deploy_validate' in desc and not callable(desc['deploy_validate']):
        raise ValueError(f"module descriptor {key!r}: deploy_validate must be callable")
    if key in MODULES:
        raise ValueError(f"module descriptor {key!r}: already registered")


def register_module(desc):
    """Register a module descriptor (called from each module file's register(ctx))."""
    _validate_descriptor(desc)
    MODULES[desc['key']] = desc
    _job(desc['key'])  # allocate the job slot + lock up front
    return desc


# ── Generic deploy-job runner ─────────────────────────────────────────────────

def _job(key):
    job = _JOBS.get(key)
    if job is None:
        job = {'running': False, 'complete': False, 'error': False,
               'log': [], 'action': None}
        _JOBS[key] = job
        _LOCKS[key] = threading.Lock()
    return job


def job_state(key):
    """Live job dict for a module — read-only by convention outside the runner."""
    return _job(key)


def job_log(key, msg):
    """The ONE plog: timestamped append to the module's job log (+ journal)."""
    entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    _job(key)['log'].append(entry)
    print(f"[{key}] {msg}", flush=True)
    return entry


def job_start(key, action, target, args=()):
    """Start `target(*args)` as the module's background job. Returns False when a
    job is already running (the 409-equivalent guard). The target owns its own
    complete/error updates via the job dict; this wrapper is the safety net."""
    job = _job(key)
    with _LOCKS[key]:
        if job['running']:
            return False
        job['log'].clear()
        job.update({'running': True, 'complete': False, 'error': False,
                    'action': action})

    def _runner():
        try:
            target(*args)
            if job['running']:
                # target returned cleanly without closing out — count it a success
                job.update({'complete': True, 'error': False})
        except Exception as e:
            job_log(key, f"✗ {action} failed: {str(e)[:300]}")
            job.update({'complete': False, 'error': True})
        finally:
            job['running'] = False

    threading.Thread(target=_runner, daemon=True,
                     name=f'module-{key}-{action}').start()
    return True


# ── Auth preamble (the 12-copy pattern, one copy) ─────────────────────────────

def _check_admin_password(ctx, data):
    """Admin-password gate for destructive actions. ALWAYS enforced by the
    generic uninstall view — there is deliberately no opt-out descriptor field.
    (Allowlisted by name in smoke.py AUTH_FUNCS.)"""
    from werkzeug.security import check_password_hash
    password = (data or {}).get('password', '')
    auth = ctx['load_auth']()
    if not auth.get('password_hash') or not check_password_hash(auth['password_hash'], password):
        return 'Invalid admin password'
    return None


# ── Generic route registrar ───────────────────────────────────────────────────

def _make_views(desc, ctx):
    """View functions for one module's generic route family. URL contract is
    frozen at the module's pre-registry endpoints; response shapes match the
    migrated handlers verbatim (PLAN v10.1.22 §4-W4)."""
    from flask import request, jsonify
    import subprocess
    key = desc['key']

    def deploy_view():
        job = _job(key)
        if job['running']:
            return jsonify({'success': False, 'error': 'Deployment already in progress'})
        data = request.get_json(silent=True) or {}
        validate = desc.get('deploy_validate')
        params = data
        if validate:
            params, err = validate(data)
            if err:
                return jsonify({'success': False, 'error': err})
        if not job_start(key, 'deploy', desc['deploy'], (ctx, job, params)):
            return jsonify({'success': False, 'error': 'Deployment already in progress'})
        return jsonify({'success': True})

    def log_view():
        job = _job(key)
        return jsonify({'running': job['running'], 'complete': job['complete'],
                        'error': job['error'], 'entries': list(job['log'])})

    def control_view():
        data = request.get_json(silent=True) or {}
        verb = data.get('action', '')
        argv = desc['control_map'].get(verb)
        if argv is None:
            # canonical contract: unknown verb is a client error, not a 200-false
            return jsonify({'success': False, 'error': 'Unknown action'}), 400
        if callable(argv):
            argv = argv(ctx)  # runtime argv (v10.1.24 — see _validate_descriptor)
        r = subprocess.run(ctx['_sudo_wrap'](list(argv)), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, timeout=90)
        return jsonify({'success': r.returncode == 0, 'output': (r.stdout or '').strip()})

    def uninstall_view():
        data = request.get_json(silent=True) or {}
        err = _check_admin_password(ctx, data)
        if err:
            return jsonify({'error': err}), 403
        job = _job(key)
        if job['running']:
            return jsonify({'success': False, 'error': 'A deployment is in progress'}), 409
        result = desc['uninstall'](ctx, job, data)
        job['log'].clear()
        job.update({'running': False, 'complete': False, 'error': False, 'action': None})
        return jsonify(result)

    return {'deploy': deploy_view, 'log': log_view,
            'control': control_view, 'uninstall': uninstall_view}


def init_registry(app, ctx, login_required):
    """Register every module's generic route family on the Flask app. Every view
    — generic and extra — is wrapped in the SAME login_required decorator app.py
    uses for its own routes (auth parity is a v10.1.22 acceptance check)."""
    global _CTX
    _CTX = ctx
    for key in sorted(MODULES):
        desc = MODULES[key]
        base = desc.get('api_base') or f'/api/{key}'
        views = _make_views(desc, ctx)
        app.add_url_rule(f'{base}/deploy', endpoint=f'registry_{key}_deploy',
                         view_func=login_required(views['deploy']), methods=['POST'])
        for i, alias in enumerate(desc.get('deploy_aliases') or []):
            # e.g. emailrelay /swap — a second URL onto the SAME deploy view
            app.add_url_rule(alias, endpoint=f'registry_{key}_deploy_alias{i}',
                             view_func=login_required(views['deploy']), methods=['POST'])
        app.add_url_rule(f'{base}/log', endpoint=f'registry_{key}_log',
                         view_func=login_required(views['log']), methods=['GET'])
        app.add_url_rule(f'{base}/control', endpoint=f'registry_{key}_control',
                         view_func=login_required(views['control']), methods=['POST'])
        app.add_url_rule(f'{base}/uninstall', endpoint=f'registry_{key}_uninstall',
                         view_func=login_required(views['uninstall']), methods=['POST'])
        for r in desc.get('extra_routes') or []:
            # bespoke stays bespoke, visible, and enumerable
            app.add_url_rule(r['url'], endpoint=r.get('endpoint') or f"registry_{key}_{r['url'].rsplit('/', 1)[-1]}",
                             view_func=login_required(r['view']), methods=r.get('methods') or ['GET'])


def uninstall_module(key, log_fn=None, params=None):
    """Already-authorized internal uninstall path — used by run_full_uninstall()
    so the registry copy is the ONLY copy (first drift-kill, PLAN §4-W4)."""
    desc = MODULES[key]
    job = _job(key)
    result = desc['uninstall'](_CTX, job, params or {})
    job['log'].clear()
    job.update({'running': False, 'complete': False, 'error': False, 'action': None})
    if log_fn:
        for step in (result or {}).get('steps', []):
            log_fn(f"  {step}")
    return result


def load_all(ctx):
    """Import every module file in this package (deterministic, sorted) and call
    its register(ctx). Called once from the bottom of app.py."""
    global _CTX
    _CTX = ctx
    import importlib
    import pkgutil
    loaded = []
    for _finder, name, _ispkg in sorted(pkgutil.iter_modules(__path__), key=lambda t: t[1]):
        mod = importlib.import_module(f'{__name__}.{name}')
        if hasattr(mod, 'register'):
            mod.register(ctx)
            loaded.append(name)
    return loaded
