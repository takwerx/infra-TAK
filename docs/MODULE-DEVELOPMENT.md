# infra-TAK Module Developer Guide

How to build a Marketplace module for infra-TAK: an application that an operator
deploys from the console with one click and then manages from a page of its own
(status, start/stop/restart, logs, update, remove). The reference examples are
**EUD Remote Assist** (an external Docker application with an Authentik OIDC
admin portal and a separate device-facing API) and **TAK Video Restreamer**
(an external Docker application behind Caddy with a self-update path).

This document is the contract between your module and the console. Read it end
to end before writing code. Where it says **must**, the maintainers will not
land the module without it.

Applies to infra-TAK **v10.1.22 and later** (the module registry). Current dev
line: see `VERSION` in `app.py`.

---

## 1. What a module is

From the operator's point of view a module is:

1. A **tile in the Marketplace** (`/marketplace`) while it is not installed.
2. A **Deploy** button that runs a multi-step job with a live log.
3. After deploy, a **page of its own** (`/<route>`) with status, controls, logs,
   an update badge, and a password-confirmed **Remove** button.
4. A **card on the Console dashboard** and a link in the sidebar while installed.
5. Optionally, a **subdomain** published through Caddy (`mdm.<fqdn>`), an
   **Authentik** application for single sign-on, and **firewall** rules.

From the developer's point of view a module has two halves:

| Half | What it is | Who owns it |
|---|---|---|
| **Your application** | The thing being deployed. Usually a Docker Compose stack in its own public git repository with tagged releases. | You |
| **The infra-TAK module** | One Python file under `modules/`, one Jinja template under `templates/`, and a handful of small hooks in `app.py`. It clones, configures, starts, monitors, updates, and removes your application using only the seams the console hands it. | You write it, maintainers review and land it |

The console never runs your application's code in-process. It orchestrates it
with `docker`, `systemctl`, `git`, and the host firewall through an audited
privilege broker. Everything in this guide follows from that.

---

## 2. Ground rules (hard requirements)

These are landing requirements. A module that breaks one does not ship, no
matter how small it is.

1. **Multiplatform.** Ubuntu 22.04, Rocky/RHEL 9, and ARM64 are all first-class.
   Package installs go through `ctx['_pkg_install']`, firewall changes through
   `ctx['_fw_allow']`, OS branching through `ctx['os_type']()` and
   `ctx['_host_arch']()`. Your Docker images must be published for **both**
   `linux/amd64` and `linux/arm64`, or the deploy must build from source on the box.
   "Works on my Ubuntu box" is not done.
2. **No new unauthenticated surface.** Every route the registry creates for you is
   already wrapped in the console's `login_required`. Every extra route you add
   is wrapped too. Do not register routes any other way.
3. **Anything Caddy fronts binds to `127.0.0.1`.** Publish container ports as
   `127.0.0.1:<port>:<port>` unless clients must reach the port directly (a
   device API, a streaming port). A `0.0.0.0` bind on a Caddy-fronted port is a
   review failure. firewalld does **not** protect Docker-published ports.
4. **Every public port is justified, opened through the shim, and documented**
   in the descriptor's `ports` list and in your PR.
5. **Secrets live in `.config/settings.json`** (mode 600) via
   `ctx['load_settings']()` / `ctx['save_settings']()`, or in your application's
   own volume. Never in the repo, never in a log line, never world-readable.
6. **No shell strings for privileged work.** The broker runs argv lists, not a
   shell. `bash -c`, `sh -c`, pipes, `cd && …`, `sed`, `python`, and `openssl`
   are denied through the broker. Use `--project-directory` instead of `cd`,
   `ctx['_read_priv']` / `ctx['_write_priv']` instead of `sed`, and Python
   string handling instead of `awk`.
7. **Never interpolate user or remote input into a command, a file path, or a
   compose file without validation.** Reject control characters in anything
   that lands in a config file (see the TVR password handler for the pattern).
8. **External code is pinned to a release tag plus commit SHA**, never a moving
   branch, and re-scanned on every bump. Licenses must be AGPL-3.0-or-later
   compatible (MIT, BSD, ISC, Apache-2.0 are fine; GPLv2-only is not).
9. **Fleet-uniform configuration.** Every value you write is either a constant
   every box converges to or is computed from observable signals on that box.
   Never preserve a number an operator typed during an incident.
10. **Your module file imports nothing from `app.py`.** Every capability arrives
    through the `ctx` dict. If you need something that is not in `ctx`, ask the
    maintainers to add a seam. Do not work around it.
11. **Import Flask and Werkzeug lazily** (inside `register()` or the view
    functions), so `import modules` still works on a bare interpreter. The
    maintainers' pre-pull smoke check depends on that.
12. **Security scan before it lands** (section 14). Remote control of end-user
    devices, credential handling, and new listening ports are held to the
    CJIS-class bar. A High or Critical finding is a hard fail.

---

## 3. Anatomy of a module

```
infra-TAK/
├── modules/
│   └── mdm.py                  # your module: descriptor + detect/deploy/uninstall + extra views
├── templates/
│   └── mdm.html                # your page: extends base.html
├── static/
│   └── logos/mdm-logo.png      # optional tile/sidebar logo (or use an emoji icon)
└── app.py                      # small hooks, listed in section 10
```

The module file is discovered automatically: `modules/__init__.py` imports every
`.py` in the package in sorted order and calls its `register(ctx)`. Registration
happens once, at import time, before gunicorn serves a request.

Keep the module file under 3,000 lines (the repo's per-file budget). Put large
config templates in module-level string constants, as `tvr.py` does.

Every new source file carries the SPDX header from `CONTRIBUTING.md`.

---

## 4. The descriptor

`register(ctx)` must call `register_module({...})` exactly once with a plain
dict. The registry validates it at import and refuses to start the console on a
bad descriptor, so mistakes surface immediately and loudly.

```python
from . import register_module, job_log, job_state

def register(ctx):
    register_module({
        # identity / UI
        'key':         'mdm',
        'name':        'Mobile Device Manager',
        'description': 'Enroll, locate, lock, and wipe company EUDs',
        'icon':        '\U0001F4F1',             # 📱 as an escape keeps the file ASCII-safe
        'icon_url':    '/static/logos/mdm-logo.png',   # optional
        'route':       '/mdm',
        'template':    'mdm.html',
        'priority':    16,
        'conflicts':   [],
        # lifecycle
        'detect':          detect,
        'deploy':          deploy,
        'deploy_validate': deploy_validate,          # optional
        'uninstall':       uninstall,
        'control_map': {
            'start':   lambda c: _compose_argv(c, 'up', '-d'),
            'stop':    lambda c: _compose_argv(c, 'stop'),
            'restart': lambda c: _compose_argv(c, 'restart'),
        },
        'extra_routes': [ ... ],                      # optional, section 6
        # facts
        'ports':         ['8449/tcp'],
        'service_units': [],
        'settings_keys': ['mdm_enabled', 'mdm_commit_sha', 'mdm_pg_password'],
    })
```

### 4.1 Field reference

| Field | Type | Required | Meaning |
|---|---|---|---|
| `key` | `str` matching `[A-Za-z0-9_-]+` | yes | Module identity. Used in the job slot, the log prefix, and the default API base `/api/<key>`. Must be unique across the registry. |
| `name` | `str` | yes | Display name on the tile, card, and sidebar. |
| `description` | `str` | yes | One line under the name on the tile. |
| `icon` | `str` | yes | Emoji fallback for the tile. Write it as a `\U0001F4F1`-style escape. |
| `icon_url` | `str` | no | Logo URL (local `/static/...` preferred). When set, the Marketplace card shows the logo instead of the emoji. Include the wordmark in the image, because the card hides the text name when a logo is present unless the key is on a short allow-list in `templates/marketplace.html`. |
| `route` | `str` | yes | Page path, e.g. `/mdm`. The page route itself is written in `app.py` (section 10). |
| `template` | `str` | yes | File under `templates/`. |
| `priority` | `int` | yes | Sort order on the Marketplace and dashboard. Existing modules use 0 to 15; pick 16 or higher. |
| `api_base` | `str` | no | Overrides `/api/<key>`. Only for preserving URLs of a module that predates the registry. New modules leave it unset. |
| `conflicts` | `list[str]` | no | Tile keys of modules that cannot coexist with yours (shared ports). The Marketplace shows a blocked card with the reason while the other is installed. Your `deploy()` must still refuse on its own. |
| `detect` | callable `(ctx) -> dict` | yes | Section 5.1. |
| `deploy` | callable `(ctx, job, params)` | yes | Section 5.2. |
| `deploy_validate` | callable `(data) -> (params, err)` | no | Section 5.3. |
| `deploy_aliases` | `list[str]` | no | Additional URLs bound to the same deploy view (e.g. a `/swap` alias). Rarely needed. |
| `uninstall` | callable `(ctx, job, params) -> dict` | yes | Section 5.4. |
| `control_map` | `dict[str, list | callable]` | yes | Verb to argv. Section 5.5. |
| `extra_routes` | `list[dict]` | no | Bespoke endpoints. Section 6.2. |
| `ports` | `list[str]` | no | Public ports your module opens, `'8449/tcp'` form. Documentation for reviewers today; keep it accurate. |
| `service_units` | `list[str]` | no | systemd units you install, if any. |
| `settings_keys` | `list[str]` | no | Every `settings.json` key you write. Reviewers use this to check cleanup on uninstall. |

---

## 5. Lifecycle callables

All four receive `ctx`, the seam dict described in section 7. None of them may
import from `app.py`.

### 5.1 `detect(ctx) -> {'installed': bool, 'running': bool}`

Called on **every dashboard poll and every page load**, from several threads.
It must be fast (under a second), must never raise, and must not write to disk
except for the self-heal below.

Use `ctx['probe_run']` for every probe. It defaults to an 8-second timeout,
captures output, swallows every exception, and routes `docker` / `systemctl`
through the broker on non-root boxes. A wedged probe degrades to "not running"
instead of taking the dashboard down.

**The install signal is a settings flag, not the filesystem.** The console runs
as the unprivileged `takwerx` user and cannot see into `/root`, so a path check
alone misreports modules installed before a box was migrated off root. Store
`<key>_enabled` at the end of deploy and read it here. Then **self-heal**: if
the flag is missing but your container is running, set the flag back. Both
reference modules do exactly this:

```python
def detect(ctx):
    s = ctx['load_settings']()
    enabled = bool(s.get('mdm_enabled'))
    r = ctx['probe_run'](['docker', 'inspect', '--format', '{{.State.Running}}', 'mdm-server'],
                         text=True, timeout=3)
    running = (r.stdout or '').strip() == 'true'
    if running and not enabled:
        s['mdm_enabled'] = True
        ctx['save_settings'](s)
        enabled = True
    return {'installed': enabled, 'running': running}
```

### 5.2 `deploy(ctx, job, params)`

Runs in a **background thread** started by the registry after the HTTP request
returns. There is no time limit, so long Docker builds are fine, but every
`subprocess.run` you make must carry its own `timeout=`.

- `job` is the module's job dict: `{'running', 'complete', 'error', 'log', 'action'}`.
  The log list is what the page polls.
- `params` is whatever `deploy_validate` returned, or the raw JSON body when
  there is no validator.
- Log with `job_log('<key>', msg)` (imported from the package). It timestamps
  the line, appends it to the job log, and prints it to the console journal.
  Log a numbered step header before each phase, a `✓` line after it, and a
  `✗` line with the last few hundred bytes of output on failure. Operators read
  this log live.
- **Finish by setting the job state yourself**:
  `job.update({'running': False, 'complete': True, 'error': False})` on success,
  `job.update({'running': False, 'error': True})` on failure, then `return`.
  If you return without touching the job, the registry counts it a success. If
  you raise, the registry logs the exception and marks the job failed. Prefer
  explicit failure logging over raising, so the operator sees *why*.
- The registry refuses a second deploy while one is running.

A typical deploy has six steps. This is the shape both reference modules use:

```python
def deploy(ctx, job, params):
    import secrets
    plog = lambda m: job_log('mdm', m)
    try:
        s = ctx['load_settings']()
        fqdn = (s.get('fqdn') or '').strip()

        plog('━━━ Step 1/6: Checking Docker ━━━')
        rc, ver = ctx['_docker_probe']()
        if rc != 0 and not ctx['_install_docker_engine'](plog):
            raise RuntimeError('Docker install failed')

        plog('━━━ Step 2/6: Fetching application ━━━')
        # git clone --depth=1 --branch <PINNED_TAG> <repo> <install_dir>
        # then verify `git rev-parse HEAD` equals the pinned SHA. Abort if not.

        plog('━━━ Step 3/6: Writing configuration ━━━')
        pg_pass = s.get('mdm_pg_password') or secrets.token_hex(24)
        # write .env / docker-compose.override.yml with 127.0.0.1 binds

        plog('━━━ Step 4/6: Starting containers ━━━')
        r = ctx['_broker_compose'](MDM_DIR, 'up -d --build', timeout=900)
        if r.returncode != 0:
            raise RuntimeError(f'compose up failed: {r.stderr[-400:]}')

        plog('━━━ Step 5/6: Firewall ━━━')
        ok, msg = ctx['_fw_allow'](8449, 'tcp')          # device API only; portal rides Caddy 443
        plog(f'  {"✓" if ok else "⚠"} {msg}')

        plog('━━━ Step 6/6: Registering module ━━━')
        s = ctx['load_settings']()
        s['mdm_enabled'] = True
        s['mdm_pg_password'] = pg_pass
        s['mdm_commit_sha'] = sha
        ctx['save_settings'](s)
        ctx['generate_caddyfile'](s)
        if ctx['_caddy_reload'](plog):
            plog('✓ Caddy reloaded')

        plog(f'✓ Deployed. Portal: https://mdm.{fqdn}')
        job.update({'running': False, 'complete': True, 'error': False})
    except Exception as e:
        plog(f'✗ Deploy failed: {e}')
        job.update({'running': False, 'error': True})
```

Rules inside deploy:

- **Re-read settings before you write them** (`load_settings()` again right
  before `save_settings()`). Other threads write the same file.
- **Generate secrets once and persist them.** Re-deploys and updates must reuse
  the stored password, or you lock the operator out of their own data.
- **Refuse conflicts explicitly** with a clear log line before doing anything.
- **Never `git pull` a moving branch.** Clone the pinned tag, verify the SHA.
- **ARM64.** If the upstream Dockerfile hardcodes an `amd64` download, patch it
  before the build when `ctx['_host_arch']() == 'arm64'`, and log that you did.
  See the TVR module for the pattern.
- **RHEL.** No `ufw`. The firewall shim handles it; do not call `ufw` directly.

### 5.3 `deploy_validate(data) -> (params, err)`

Optional. Runs **in the HTTP request**, before the job starts. `data` is the
parsed JSON body. Return `(params_dict, None)` on success or `(None, 'message')`
to reject with `{'success': False, 'error': message}`. Do all input validation
here so the background job only ever sees clean values.

### 5.4 `uninstall(ctx, job, params) -> {'success': bool, 'steps': [str, ...]}`

Runs **synchronously in the HTTP request**, after the registry has already
verified the admin password (you cannot opt out of that gate) and confirmed no
deploy is running. It is also what the console's **full uninstall** calls, so it
must be idempotent and must not assume the page is watching.

Do, in order: stop and remove containers (`compose down`), remove firewall
rules you opened (`ctx['_fw_remove']`), clear your settings keys (or set
`<key>_enabled` false), regenerate and reload Caddy, deregister your Authentik
application. Return one human-readable string per step; the full-uninstall log
prints them.

Decide deliberately what happens to **operator data** (a device inventory, a
database volume). TVR keeps its data directory; Email Relay purges its
credentials. Say which you chose in the PR and in the Remove dialog text.

### 5.5 `control_map`

A dict of verb to argv. `start`, `stop`, `restart` are the conventional verbs
the page buttons send. Each value is either a static list or a callable
`(ctx) -> list` resolved per request, for commands that depend on runtime state
(the install directory of a module that was deployed before a root-to-non-root
migration lives in `/root`, not `~`).

The registry runs the argv through `_sudo_wrap` with a 90-second timeout and
returns `{'success': rc == 0, 'output': ...}`. An unknown verb is a 400. Verbs
are the only thing the client can choose; it cannot pass arguments.

---

## 6. HTTP API

### 6.1 Generated routes

The registry creates these four for every module at `<api_base>` (default
`/api/<key>`). All are `login_required`. Unauthenticated `/api/*` calls get
`401 {"error": "Unauthorized", "login_required": true}`.

| Method | Path | Request body | Response |
|---|---|---|---|
| `POST` | `/api/<key>/deploy` | JSON, passed to `deploy_validate` | `200 {"success": true}` when the job started. `200 {"success": false, "error": "..."}` on validation failure or when a deploy is already running. |
| `GET` | `/api/<key>/log` | none | `200 {"running": bool, "complete": bool, "error": bool, "entries": [str, ...]}`. Poll this every ~800 ms while `running`. |
| `POST` | `/api/<key>/control` | `{"action": "start" \| "stop" \| "restart"}` | `200 {"success": bool, "output": str}`. Unknown verb: `400 {"success": false, "error": "Unknown action"}`. |
| `POST` | `/api/<key>/uninstall` | `{"password": "<admin password>"}` plus anything your `uninstall` reads | `403 {"error": "Invalid admin password"}`, `409` while a deploy runs, otherwise whatever `uninstall()` returned (convention `{"success": true, "steps": [...]}`). |

### 6.2 Extra routes

Anything else your page needs (container logs, a version check, an update
trigger, a settings change) goes in `extra_routes`. Each entry:

```python
{'url': '/api/mdm/logs', 'methods': ['GET'], 'endpoint': 'mdm_logs', 'view': logs_view}
```

`view` is a plain Flask view function closed over `ctx`; the registry wraps it
in `login_required`. Give every entry a unique `endpoint`. Import `request` and
`jsonify` inside `register()`.

Conventions the existing pages follow, so operators get the same behavior on
every module:

| Purpose | Path | Shape |
|---|---|---|
| Container logs | `GET /api/<key>/logs` | `{"lines": [str, ...]}` (last 200 lines of `docker logs`) |
| Version | `GET /api/<key>/version` | `{"version": str, "latest": str \| null, "update_available": bool}` |
| Start update | `POST /api/<key>/update` | `{"started": true}` or `{"started": false, "error": "..."}` |
| Update progress | `GET /api/<key>/update-status` | `{"running", "complete", "error", "log": [...]}` |

Any route that **destroys or overwrites** something must re-check the admin
password. Registry uninstall does it for you; for an extra route, accept a
`password` field and validate it the way the registry does (ask the maintainers
for the `_check_admin_password` seam if you need it, or keep destructive
actions inside `uninstall`).

---

## 7. The `ctx` seam dict

`ctx` is the **only** way your module reaches the console. It is a plain dict
built at the bottom of `app.py` and handed to `register(ctx)`; the same object is
passed to every lifecycle callable. Names keep their `app.py` spelling, including
leading underscores.

### 7.1 State

| Seam | Signature | Notes |
|---|---|---|
| `load_settings` | `() -> dict` | Reads `.config/settings.json`. Cheap. Call it fresh before every write. |
| `save_settings` | `(dict) -> None` | Atomic write, mode 600. Write only your own `settings_keys`. |
| `load_auth` | `() -> dict` | Admin password hash. You should not need it. |
| `detect_modules` | `() -> dict[tile_key, {...}]` | Every module's live state. Use it to check conflicts and whether Authentik / Caddy are installed. |

Well-known settings you may **read**: `fqdn`, `server_ip`, `ssl_mode`,
`update_channel` (`'dev'` or `'main'`), `<key>_domain` (operator override of your
subdomain; read it through `_get_service_domain`, never directly). Never write
any key you do not own.

### 7.2 Privileged execution

| Seam | Signature | Notes |
|---|---|---|
| `_sudo_wrap` | `(argv) -> argv` | Prefixes an argv list so `subprocess.run` executes it with privilege (root directly, or through the broker on a non-root console). Wrap every `docker`, `systemctl`, `chmod`, etc. Never pass a shell string. |
| `probe_run` | `(*args, **kw) -> CompletedProcess` | Never raises. Default `timeout=8`, `capture_output=True`. For `detect()` and any status read. |
| `run_cmd` | `(cmd, desc=None, check=True, quiet=False, log=None) -> ...` | Step-logging runner used by the TAK Server deploy. Pass `log=job['log']` to route its output into your job log. |
| `_read_priv` | `(path) -> str` | Read a root-owned file through the broker. |
| `_write_priv` | `(path, content, mode='w', perm=None) -> None` | Write a root-owned file through the broker; `perm` is an octal int applied after the write. Paths must be on the broker allow-list (section 8). |
| `_broker_compose` | `(dirpath, action: str, timeout=300) -> CompletedProcess` | `docker compose --project-directory <dir> <action>` without a shell. `action` is split with `shlex`, e.g. `'up -d --build'`. Use it for every compose call. |
| `_module_git` | `(repo_dir, *git_args, timeout=60) -> CompletedProcess` | `git -C <dir> ...`. Runs as the console user for home-resident repos and through the broker for `/root/…` repos. |
| `_docker_probe` | `() -> (rc, version_str)` | `docker --version`, never raises; a missing binary is `rc=127`. |
| `_install_docker_engine` | `(plog=None) -> bool` | Installs Docker Engine on either OS family, non-root safe. 15-minute internal timeout. |

### 7.3 Platform shims

| Seam | Signature | Notes |
|---|---|---|
| `os_type` | `() -> 'debian' \| 'rhel'` | Package-manager family. Branch on this, never on `/etc/os-release` text. |
| `_host_arch` | `() -> 'amd64' \| 'arm64'` | |
| `_pkg_install` | `(pkgs, repo=None, log_fn=None, timeout=1800) -> (ok, output)` | `apt-get install -y` or `dnf install -y`. `pkgs` is a name, a list, a local package path, or a URL. Confirm the package name exists on both families. |
| `_pkg_remove` | `(pkgs, purge=False, timeout=600) -> (ok, output)` | |
| `_fw_allow` | `(port, proto='tcp') -> (ok, msg)` | ufw or firewalld, chosen per box. `ok=True` with a message when no firewall is present. |
| `_fw_remove` | `(port, proto='tcp') -> (ok, msg)` | |
| `wait_for_apt_lock` | `(plog, log_list)` | Debian only. Call before `_pkg_install` if another install may be running. |

### 7.4 Edge and identity

| Seam | Signature | Notes |
|---|---|---|
| `generate_caddyfile` | `(settings) -> None` | Rewrites the whole Caddyfile from current module state. Call after you flip `<key>_enabled`. Your vhost block lives in `app.py` (section 10). |
| `_caddy_reload` | `(plog=None) -> bool` | The **only** sanctioned way to reload Caddy. Never raises, never hangs, restarts Caddy if the reload fails. A raw `systemctl reload caddy` fails the self-audit scanner. |
| `_get_authentik_env_value` | `(settings, key) -> str \| None` | Reads a key from Authentik's `.env`, e.g. `AUTHENTIK_TOKEN` or `AUTHENTIK_BOOTSTRAP_TOKEN`. `None` means Authentik is not installed or not configured; degrade gracefully. |
| `_deregister_authentik_proxy_app` | `(settings, app_slug, provider_name, plog=None)` | Remove your Authentik application and **proxy** provider on uninstall (it looks the provider up under `/providers/proxy/`). Idempotent, non-fatal. An OIDC provider needs its own cleanup against `/providers/oauth2/`; see how the Remote Assist uninstall in `app.py` does it. |
| `_ensure_authentik_tvr_app` | TVR-specific | Provisioning helpers are per-module today. Your module needs its own; see section 9. |
| `_ssh_probe` | `(host_cfg, cmd, timeout=15) -> (ok, output)` | Only for split-server deploys. Most modules never need it. |
| `_get_module_deployment_config` | `(settings, key) -> dict` | Same. |
| `_takportal_push_settings`, `_configure_authentik_smtp_and_recovery*` | Email Relay specific | Ignore. |

If a seam you need is missing, name it in the PR description. The maintainers
add it to `_MODULE_CTX` in `app.py`; you never import around it.

---

## 8. The privilege model

The console process runs as user **`takwerx`**, not root. Privileged commands go
through a root **broker** (`broker/takwerx_broker.py`) that enforces an allow-list
and writes an audit log. `_sudo_wrap` and the `_priv` helpers hide this from you,
but the allow-list shapes what a module can do:

**Binaries the broker will run** (partial): `docker`, `systemctl` (verbs gated to
start/stop/restart/enable/disable/is-active and friends), `journalctl`, `ufw`,
`firewall-cmd`, `apt-get`/`dnf` (install/remove only, no hook options), `git`
(only for `/root/<module>` repos), `postconf`/`postmap`, `tee`/`cat`/`cp`/`mv`/
`rm`/`mkdir`/`chmod`/`chown`/`ln`/`install` (path-checked), `test`, `stat`,
`ss`, `ip`, `getent`, `restorecon`/`semanage`/`chcon` (gated).

**Never through the broker:** any shell (`sh`, `bash`), `sudo`, `su`, `env`,
`xargs`, `timeout`, `perl`, `python`, `awk`, `sed`, `dd`, `psql`, `openssl`,
`passwd`, `useradd`, `visudo`.

**Privileged paths you may read and write:** `/etc/systemd/system/`, `/etc/caddy/`,
`/etc/docker/`, `/etc/firewalld/`, `/etc/ufw/`, `/etc/sysctl.d/`, `/etc/apt/`,
`/var/log/`, `/opt/tak/`, and the recognized module directories under `~` and
`/root`. Not `/usr/local/bin`, not `/usr/sbin`, not `/root/.ssh` for writes.

Practical consequences:

- **Install under the console user's home**, `os.path.expanduser('~/<key>')`.
  Files there are yours to read and write directly, no broker needed. Only
  reach for `_read_priv` / `_write_priv` on root-owned paths.
- **`docker` is effectively root.** The broker refuses `--privileged`, host
  namespaces, and mounting the Docker socket. Do not design your application
  to need them.
- **A new binary or path you need means a broker rulebook change.** That is a
  maintainer change with its own review. Ask early, in the design issue, not
  after the module is written.
- **Docker Hub anonymous pulls are rate-limited per IP.** Prefer GHCR or a
  build-from-source fallback; at minimum, log a clear line on a 429.

---

## 9. Networking, SSL, and single sign-on

### 9.1 Subdomain and Caddy

Every module with a web UI gets a subdomain under the box's FQDN. Register a
default label in `SERVICE_DOMAIN_DEFAULTS` in `app.py` (`'mdm': 'mdm'` gives
`mdm.<fqdn>`). Operators can override it per box with an `mdm_domain` setting,
which is why you always resolve it with `_get_service_domain(settings, 'mdm')`
in `app.py` code and never build the hostname yourself.

Your vhost is a block inside `generate_caddyfile()`, emitted only when
`detect_modules()['mdm']['installed']` is true. Pattern (TVR):

```
mdm.<fqdn> {
    reverse_proxy 127.0.0.1:8760
}
```

For a **device-facing API** that must not sit behind SSO, EUD Remote Assist
uses a second vhost on its own TLS port and blocks the device paths on 443:

```
remote.<fqdn> {
    @device path /api/v1/* /ws/device /health /version
    respond @device 404
    reverse_proxy 127.0.0.1:8767
}
remote.<fqdn>:8448 {
    @device path /api/v1/* /ws/device /health /version
    handle @device { reverse_proxy 127.0.0.1:8767 }
    respond 404
}
```

Caddy terminates TLS with the box's Let's Encrypt or custom certificate, so your
application speaks plain HTTP on loopback. Long-lived WebSockets need
`flush_interval -1` and raised `read_timeout` / `write_timeout` on the
`reverse_proxy`. If your app upgrades to HTTPS upstream, pass the Host header
through explicitly; Caddy's TLS transport rewrites it otherwise.

Port tiers, from the README:

| Tier | Meaning | Your module |
|---|---|---|
| Public | open in the firewall, reachable from the internet | device API port, streaming ports. Open with `_fw_allow`, list in `ports`. |
| Caddy-loopback | bound to `127.0.0.1`, reached only through Caddy on 443 | admin UI, web API |
| Docker-internal | no host port at all | database, cache, queues |

Pick a host port that is not already taken. In use today (partial): 5001
console, 8089/8443/8446 TAK Server, 9000/9090 Authentik, 3000 TAK Portal, 3100
TVR, 8767 and 8448 EUD Remote Assist, 8554/8555/8888/8889/8890/1935 media,
1880 Node-RED, 3478/3479 TURN, 51820 WireGuard, 8080 Guard Dog agent.

### 9.2 Single sign-on with Authentik

Two patterns exist. Choose based on whether your application can do OIDC itself.

**Pattern A: your app is an OIDC client (EUD Remote Assist).** The module creates
an OAuth2/OpenID provider and application in Authentik through its REST API
(`/api/v3/providers/oauth2/`, `/api/v3/core/applications/`) using the token
from `_get_authentik_env_value`, writes the client ID into your app's `.env`, and
your app validates ID tokens against Authentik's JWKS. Use PKCE and set
`grant_types` explicitly to `['authorization_code', 'refresh_token']` (an empty
grant list silently breaks login). Redirect URIs use `matching_mode: strict`.

**Pattern B: your app has no auth of its own (TVR, WebODM, Node-RED).** The module
creates a **proxy provider** in Authentik, adds it to the embedded outpost, and
the Caddy vhost gets a `forward_auth` block. Users hit Authentik first; your app
trusts the resulting identity headers **only** because Caddy strips any
client-supplied copies. Never trust an `X-Authentik-*` header on a path a client
can reach directly.

Both patterns:

- Provisioning lives in an `app.py` helper today (`_ensure_authentik_remote_assist_app`,
  `_ensure_authentik_tvr_app`). Write yours next to them and ask for it to be
  added to `ctx`. Make it idempotent: look up by slug, create only when missing,
  and retry the flow lookups a few times because Authentik may still be
  starting.
- Decide **who may log in**. Admin tooling (an MDM console is admin tooling) is
  restricted to the *authentik Admins* group by adding your slug to the
  `admin_only_slugs` list in `_ensure_app_access_policies()`. Everything not on
  the user-visible allow-list there is admin-only by default.
- Deregister on uninstall. Pattern B uses `_deregister_authentik_proxy_app`
  (slug-scoped). Pattern A deletes the application by slug and the OAuth2
  provider by name, the way the Remote Assist uninstall in `app.py` does.
- **Degrade when Authentik is absent.** No token means no SSO; log that and
  either fall back to your app's own login or refuse to deploy with a clear
  message. Do not crash.

### 9.3 Firewall

`_fw_allow(port, proto)` for every public port, in deploy. `_fw_remove` for each
in uninstall. Nothing else. Do not `ufw deny` a loopback port; a port bound to
`127.0.0.1` needs no rule, and ufw silently mishandles a deny on a port that
already has an allow.

---

## 10. Hooks in `app.py`

The registry gives you routes, jobs, and auth. A few things are still wired by
hand in `app.py`, each a five-to-fifteen-line hunk next to the equivalent hunk
for TVR or EUD Remote Assist. Grep for `tak_video_restreamer` or `remote_assist`
to find every location. Your PR will include:

| Hook | Where | What |
|---|---|---|
| **Dashboard tile** | `detect_modules()` | Pull your descriptor from `mod_registry.MODULES`, call its `detect`, and add the tile dict. Copy the TVR block. Use the **same key** for the tile as for the descriptor (TVR's differ for historical reasons; do not repeat that). |
| **Page route** | near the other module pages | `@app.route('/mdm') @login_required def mdm_page():` builds the template context and `render_template('mdm.html', ...)`. Set `Cache-Control: no-store`. |
| **Sidebar link** | `render_sidebar()` | One `link(...)` guarded by `modules.get('mdm', {}).get('installed')`. |
| **Subdomain default** | `SERVICE_DOMAIN_DEFAULTS` | `'mdm': 'mdm'`. |
| **Caddy vhost** | `generate_caddyfile()` | Your reverse-proxy block, guarded by installed state. |
| **Version badge** | `/api/modules/version` handler | `_set('mdm', lambda: mod_registry.mdm.get_version_info(mod_registry.get_ctx()))` inside the installed guard. |
| **Full uninstall** | `run_full_uninstall()` | `mod_registry.uninstall_module('mdm', log_fn=plog)` in a try/except. |
| **Authentik** | `_ensure_app_access_policies()` and a new `_ensure_authentik_mdm_app()` | Section 9.2. |
| **Guard Dog monitor** (optional) | the `service_id ==` chain in the Guard Dog health check | A liveness probe so the operator gets an alert if your container dies. |
| **Dev-channel gate** (if the maintainers ask for it) | the tile hunk in `detect_modules()` | Register the tile only when `settings.get('update_channel') == 'dev'` or the module is already installed, so stable-channel boxes do not see it until it is promoted. |

The maintainers may ask you to submit the `app.py` hunks as a separate commit
from the module file, so the review can focus on each.

---

## 11. The page template

`templates/<key>.html` extends `base.html` and fills four blocks:

```jinja
{% extends 'base.html' %}
{% block title %}Mobile Device Manager — infra-TAK{% endblock %}
{% block page_css %}<style> /* page-local rules */ </style>{% endblock %}
{% block body_attrs %}{% endblock %}
{% block content %}<div class="main"> ... </div>{% endblock %}
```

The sidebar is injected for you. The base sheet defines the theme tokens
(`--bg-card`, `--border`, `--text-primary`, `--text-dim`, `--accent`, `--green`,
`--red`, `--yellow`, `--cyan`) and the font (`JetBrains Mono`, served locally so
air-gapped and Setup-AP boxes render correctly). Use the tokens; do not bring a
CSS framework or load anything from a CDN.

Structure operators expect, in this order (see `templates/tvr.html`):

1. **Header** with logo and module name.
2. **Not installed:** a Deploy card with a short description, a warning about
   deploy time, any input fields, and the Deploy button; a hidden Deploy Log card
   that appears on click; the previous deploy log if the last attempt failed.
3. **Installed:** an update banner when `update_available`; a Status card
   (running dot, version, Start/Stop/Restart, Remove); an Access card with the
   URL and any credentials behind a show/hide toggle; a Logs card.
4. **Remove modal** that asks for the admin password and shows the steps
   returned by uninstall.

The JavaScript is plain `fetch` with `credentials: 'same-origin'`:

```js
function startDeploy(){
  fetch('/api/mdm/deploy',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({}),credentials:'same-origin'})
    .then(r=>r.json()).then(d=>{ if(!d.success){alert(d.error);return;} poll(); });
}
function poll(){
  fetch('/api/mdm/log',{credentials:'same-origin'}).then(r=>r.json()).then(d=>{
    logBox.textContent=d.entries.join('\n'); logBox.scrollTop=logBox.scrollHeight;
    if(d.running) setTimeout(poll,800);
    else if(d.complete) setTimeout(()=>location.reload(),3000);
    else if(d.error) showError();
  });
}
```

Escape everything you render from settings with `|e`. Never put a secret in a
`data-` attribute or inline script that is not already shown to the operator
on that page.

Test the page with **no** FQDN configured, with Authentik absent, and after a
failed deploy. All three are normal states on a fresh box.

---

## 12. Updates and the version badge

Operators expect an **Update Now** button when a newer release of your
application exists. Implement:

- `get_version_info(ctx) -> {'version': str, 'latest': str | None, 'update_available': bool}`.
  Compare the installed tag or SHA against the newest **release tag** upstream.
  Cache the GitHub lookup for hours (unauthenticated GitHub allows 60 requests
  an hour per IP, and this runs on every dashboard poll) and return the stale
  value on failure rather than `None`, so a rate limit does not hide an update.
- An update job in its **own** status dict and thread, never the deploy job
  slot: update and deploy must never share a lock or log.
- The update re-applies everything infra-TAK owns (compose overrides, `.env`,
  ARM64 patches) after pulling, because upstream may have touched those files.
  Discard the console-written overlay before the pull so a plain fast-forward
  cannot fail on local changes.
- Record the new SHA or tag in settings and log it.

Note the `settings_keys` you add for this (`<key>_commit_sha`).

---

## 13. Your application's contract

The module is only as deployable as the application behind it. Before writing
the module, make the application meet this list. Every point comes from a real
problem with a module that shipped.

- **Docker Compose, config through environment.** One `docker-compose.yml`
  plus a `.env` the module writes. No interactive setup, no wizard on first
  boot that the operator has to click through before the console can finish.
- **Multi-arch images**, `linux/amd64` and `linux/arm64`, or a Dockerfile that
  builds on both. Base images pinned by tag at least, by digest ideally.
- **Bind addresses are configurable** and default to loopback. EUD Remote
  Assist exposes `NGINX_BIND_ADDR`; the module writes `127.0.0.1`.
- **A health endpoint** (`GET /health` returning 200) and a **version
  endpoint or `VERSION` file**, so the module can report state honestly.
- **Tagged releases** (`vX.Y.Z`). The module pins a tag; "latest commit on
  main" is not a version.
- **OIDC support, or none at all.** Either you validate tokens properly
  (issuer, audience, JWKS, fail closed) or you rely on Caddy `forward_auth`.
  A half-implemented login is worse than none.
- **Persistent data in named volumes**, so containers can be recreated freely
  and the module's uninstall can choose to keep or remove data deliberately.
- **Runs as non-root inside the container** where possible, and never needs
  `--privileged`, host networking, or the Docker socket.
- **Secrets from the environment**, generated by the module, never defaulted in
  the image. `test_db.js` with hardcoded credentials in the repo is the kind of
  thing the scan flags.
- **Lockfile-honoring installs** (`npm ci`, `pip install -r` with hashes, and no
  `|| npm install` fallback).
- **Logs to stdout** so `docker logs` is the log.
- **A license** compatible with AGPL-3.0-or-later, stated in the repository.

For an **MDM specifically**, the reviewers will also look for: device
enrollment gated by a revocable token; a per-device credential after
enrollment, hashed at rest; the device API binding every action to the
authenticated device's own identity (the EUD scan found a cross-device WebRTC
signaling injection exactly here); an admin command set that is a fixed
allow-list; audit records for lock, wipe, and remote-control actions; and
device inventory stored in the application's own volume, never in
`settings.json`.

---

## 14. Security review

Every new module is scanned **twice**: before it lands on `dev`, and again on
the full diff before it is promoted to `main`. External application code is
scanned as a whole tree at the pinned tag, not just the integration glue, and
re-scanned on every version bump. The bar is the console's own CJIS-class
hardening bar. The checklist, verbatim from the maintainers' gate:

- **AuthN/AuthZ.** Every route is `login_required`; nothing bypasses Authentik
  forward_auth or SSO+MFA; no anonymous admin surface; nothing trusts an
  `X-Authentik-*` or other identity header on a client-reachable path.
- **Secrets and certificates.** No hardcoded credentials, tokens, or keys;
  secrets read from `.config/` and never logged; no weakened TLS (no disabled
  verification, no `checkServerIdentity` no-op, no expired-cert acceptance).
- **Injection.** Every `subprocess` call is an argv list or strictly sanitized;
  no user or remote input reaches a shell, SQL, or a file path.
- **Network exposure.** Every new port justified, opened through the shim,
  bound to the right interface; Caddy-fronted ports on `127.0.0.1`.
- **Supply chain.** External repos pinned to tag plus SHA; dependencies checked
  against known CVEs; no `curl | bash` of unpinned remote code.
- **Audit.** Security-relevant actions are logged and forwardable; auth and
  error events are not swallowed.
- **Data handling.** No CJI or PII to world-readable paths, logs, or the public
  repository.
- **Multiplatform.** Package and firewall shims used, OS branching not hardcoded.

Output is a severity-ranked findings list. **Any High or Critical finding is a
hard fail**: the module is fixed or formally parked. Accepted residual risk is
recorded in the maintainers' private notes. A green scan is a precondition to
merge, not a promise of a ship date.

Do a first pass yourself against this list before opening the PR. It saves a
round trip.

---

## 15. Testing before you open a PR

There is no unit-test suite for the console. What exists:

1. **Compile and import check** on your machine:
   ```bash
   python3 -m py_compile modules/mdm.py
   python3 -c "import modules"          # must succeed on a bare interpreter, no venv
   python3 -c "import ast; ast.parse(open('app.py').read())"
   ```
2. **Template sanity:** the file decodes as strict UTF-8 and contains no lone
   surrogate escapes (write emoji as `\U…` escapes in Python, or as literal
   characters in HTML, never as `\ud83d`-style halves).
3. **A real box.** Deploy from the Marketplace on a **fresh** Ubuntu 22.04 box
   with a configured FQDN and Authentik, and again on a Rocky 9 box. If you
   have ARM64 hardware or a Graviton instance, use it. Exercise: deploy,
   reload the page mid-deploy, start/stop/restart, Update Now, uninstall,
   re-deploy (credentials reused), full console uninstall.
4. **Deploy with things missing.** No FQDN. No Authentik. Docker not yet
   installed. Each must fail or degrade with a readable log line, never a
   traceback in the browser.
5. **Check the console did not regress.** `journalctl -u takwerx-console` is
   clean after restart; the dashboard still polls; other module pages render.

The maintainers then run their own pre-pull smoke check (compile, surrogate
scan, duplicate-route detection, and a ratchet that fails if the count of bare
`apt-get`/`ufw` calls, shell f-strings, or inline password checks goes up), the
security scan, and a fleet soak of at least 30 minutes on three or more boxes
across both OS families before anything reaches `main`.

---

## 16. Submitting

1. **Open an issue first** describing the module: what it deploys, which ports,
   which subdomain, how it authenticates, which upstream repo and tag, and any
   seam or broker change you expect to need. Design questions are cheapest here.
2. Fork, branch from `dev`, build against `dev`. `main` is the release branch
   and is always behind.
3. One PR to `dev` containing `modules/<key>.py`, `templates/<key>.html`, static
   assets, and the `app.py` hooks from section 10. Sign every commit
   (`git commit -s`) to accept `CLA.md`. SPDX headers on new files.
4. In the PR description: the section 13 checklist for the application, the
   section 14 self-review, the boxes you tested on, the pinned tag and SHA, the
   license of the upstream code, and the `settings_keys` and `ports` you add.
5. Expect the module to land **dev-channel only** first. Promotion to the
   stable channel is a separate decision after the second scan and a release
   cycle of field exposure.

---

## 17. Minimal complete example

A module for a hypothetical MDM stack: a single compose project under
`~/mdm`, admin UI on loopback `8760` behind Caddy at `mdm.<fqdn>`, device API
on public `8449`, Postgres in a Docker-internal network, OIDC via Authentik.

```python
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# (full AGPL header as in CONTRIBUTING.md)
"""Mobile Device Manager — infra-TAK Marketplace module.

Imports NOTHING from app.py; every seam arrives through ctx.
"""
import os
import subprocess

from . import register_module, job_log, job_state

MDM_REPO = 'https://github.com/example/mdm-server.git'
MDM_TAG = 'v1.4.2'
MDM_SHA = '0123456789abcdef0123456789abcdef01234567'
MDM_DIR = os.path.expanduser('~/mdm')
MDM_UI_PORT = 8760        # loopback, Caddy-fronted
MDM_DEVICE_PORT = 8449    # public, device API

COMPOSE_OVERRIDE = '''\
services:
  web:
    ports:
      - "127.0.0.1:{ui}:8080"
      - "0.0.0.0:{dev}:8443"
  db:
    ports: []
'''


def _plog(msg):
    return job_log('mdm', msg)


def _compose_argv(ctx, *action):
    return ['docker', 'compose', '--project-directory', MDM_DIR] + list(action)


def detect(ctx):
    s = ctx['load_settings']()
    enabled = bool(s.get('mdm_enabled'))
    r = ctx['probe_run'](['docker', 'inspect', '--format', '{{.State.Running}}', 'mdm-web'],
                         text=True, timeout=3)
    running = (r.stdout or '').strip() == 'true'
    if running and not enabled:
        s['mdm_enabled'] = True
        ctx['save_settings'](s)
        enabled = True
    return {'installed': enabled, 'running': running}


def deploy(ctx, job, params):
    import secrets
    plog = _plog
    try:
        s = ctx['load_settings']()
        fqdn = (s.get('fqdn') or '').strip()
        if not fqdn:
            plog('✗ A domain (FQDN) must be configured in Caddy SSL before deploying MDM.')
            job.update({'running': False, 'error': True})
            return

        plog('━━━ Step 1/6: Checking Docker ━━━')
        rc, ver = ctx['_docker_probe']()
        if rc != 0:
            if not ctx['_install_docker_engine'](plog):
                raise RuntimeError('Docker install failed')
        plog(f'✓ Docker present: {ver or "installed"}')

        plog(f'━━━ Step 2/6: Fetching MDM {MDM_TAG} ━━━')
        if not os.path.isdir(os.path.join(MDM_DIR, '.git')):
            r = subprocess.run(['git', 'clone', '--depth=1', '--branch', MDM_TAG, MDM_REPO, MDM_DIR],
                               capture_output=True, text=True, timeout=180)
            if r.returncode != 0:
                raise RuntimeError(f'git clone failed: {r.stderr[-300:]}')
        else:
            ctx['_module_git'](MDM_DIR, 'fetch', '--depth=1', 'origin', 'tag', MDM_TAG, timeout=120)
            ctx['_module_git'](MDM_DIR, 'checkout', '--force', MDM_TAG, timeout=60)
        head = ctx['_module_git'](MDM_DIR, 'rev-parse', 'HEAD', timeout=10).stdout.strip()
        if head != MDM_SHA:
            raise RuntimeError(f'pinned SHA mismatch: expected {MDM_SHA[:7]}, got {head[:7]}')
        plog(f'✓ At {MDM_TAG} ({head[:7]})')

        plog('━━━ Step 3/6: Writing configuration ━━━')
        pg_pass = s.get('mdm_pg_password') or secrets.token_hex(24)
        app_secret = s.get('mdm_app_secret') or secrets.token_hex(32)
        with open(os.path.join(MDM_DIR, 'docker-compose.override.yml'), 'w') as f:
            f.write(COMPOSE_OVERRIDE.format(ui=MDM_UI_PORT, dev=MDM_DEVICE_PORT))
        with open(os.path.join(MDM_DIR, '.env'), 'w') as f:
            f.write(f'PUBLIC_URL=https://mdm.{fqdn}\n'
                    f'POSTGRES_PASSWORD={pg_pass}\n'
                    f'APP_SECRET={app_secret}\n')
        os.chmod(os.path.join(MDM_DIR, '.env'), 0o600)
        plog('✓ .env and compose override written (UI on loopback)')

        plog('━━━ Step 4/6: Starting containers (first build may take several minutes) ━━━')
        r = ctx['_broker_compose'](MDM_DIR, 'up -d --build', timeout=900)
        if r.returncode != 0:
            raise RuntimeError(f'docker compose up failed: {r.stderr[-400:]}')
        plog('✓ Containers running')

        plog('━━━ Step 5/6: Firewall ━━━')
        ok, msg = ctx['_fw_allow'](MDM_DEVICE_PORT, 'tcp')
        plog(f'  {"✓" if ok else "⚠"} device API {MDM_DEVICE_PORT}/tcp: {msg}')

        plog('━━━ Step 6/6: Registering module ━━━')
        s = ctx['load_settings']()
        s['mdm_enabled'] = True
        s['mdm_pg_password'] = pg_pass
        s['mdm_app_secret'] = app_secret
        s['mdm_version'] = MDM_TAG
        ctx['save_settings'](s)
        ctx['generate_caddyfile'](s)
        if ctx['_caddy_reload'](plog):
            plog('✓ Caddy reloaded')

        plog('')
        plog(f'✓ MDM deployed. Admin portal: https://mdm.{fqdn}')
        job.update({'running': False, 'complete': True, 'error': False})
    except Exception as e:
        plog(f'✗ Deploy failed: {e}')
        job.update({'running': False, 'error': True})


def uninstall(ctx, job, params):
    steps = []
    if os.path.exists(os.path.join(MDM_DIR, 'docker-compose.yml')):
        ctx['_broker_compose'](MDM_DIR, 'down', timeout=120)
        steps.append('Containers stopped and removed (data volume kept)')
    ctx['_fw_remove'](MDM_DEVICE_PORT, 'tcp')
    steps.append(f'Firewall rule for {MDM_DEVICE_PORT}/tcp removed')
    s = ctx['load_settings']()
    s['mdm_enabled'] = False
    ctx['save_settings'](s)
    ctx['generate_caddyfile'](s)
    ctx['_caddy_reload']()
    steps.append('Caddy subdomain removed')
    # OIDC cleanup: delete the Authentik application (slug 'mdm') and its OAuth2
    # provider through the REST API, as the Remote Assist uninstall does. For a
    # proxy-provider module this is one call to ctx['_deregister_authentik_proxy_app'].
    steps.append('Authentik application deregistered')
    return {'success': True, 'steps': steps}


def get_version_info(ctx):
    s = ctx['load_settings']()
    return {'version': s.get('mdm_version', ''), 'latest': None, 'update_available': False}


def register(ctx):
    from flask import jsonify

    def logs_view():
        r = subprocess.run(ctx['_sudo_wrap'](['docker', 'logs', '--tail', '200', 'mdm-web']),
                           capture_output=True, text=True, timeout=15)
        return jsonify({'lines': (r.stdout + r.stderr).splitlines()[-200:]})

    def version_view():
        return jsonify(get_version_info(ctx))

    register_module({
        'key': 'mdm',
        'name': 'Mobile Device Manager',
        'description': 'Enroll, locate, lock, and wipe company Android EUDs',
        'icon': '\U0001F4F1',
        'route': '/mdm',
        'template': 'mdm.html',
        'priority': 16,
        'detect': detect,
        'deploy': deploy,
        'uninstall': uninstall,
        'control_map': {
            'start':   lambda c: _compose_argv(c, 'up', '-d'),
            'stop':    lambda c: _compose_argv(c, 'stop'),
            'restart': lambda c: _compose_argv(c, 'restart'),
        },
        'extra_routes': [
            {'url': '/api/mdm/logs', 'methods': ['GET'], 'endpoint': 'mdm_logs', 'view': logs_view},
            {'url': '/api/mdm/version', 'methods': ['GET'], 'endpoint': 'mdm_version', 'view': version_view},
        ],
        'ports': [f'{MDM_DEVICE_PORT}/tcp'],
        'service_units': [],
        'settings_keys': ['mdm_enabled', 'mdm_pg_password', 'mdm_app_secret', 'mdm_version'],
    })
```

What this example deliberately leaves to you: the Authentik OIDC provisioning
helper (section 9.2), the update path (section 12), the `app.py` hooks
(section 10), and the page (section 11). Copy the equivalent pieces from
`modules/tvr.py`, `templates/tvr.html`, and the `remote_assist` code in
`app.py`, which are the current reference implementations.

---

## 18. Where to look in the codebase

| Question | Look at |
|---|---|
| The registry itself: validation, job runner, generated views | `modules/__init__.py` |
| Simplest complete module (system package, no Docker) | `modules/emailrelay.py`, `templates/email_relay.html` |
| Docker Compose module with Caddy, Authentik proxy, self-update, ARM64 patch | `modules/tvr.py`, `templates/tvr.html` |
| External app with OIDC admin portal plus separate device API on its own TLS port | `remote_assist` code in `app.py` (grep `REMOTE_ASSIST`), `templates/remote_assist.html` |
| The `ctx` dict, exactly what is exposed | `_MODULE_CTX` at the bottom of `app.py` |
| The broker allow-list | `EXEC_ALLOW`, `EXEC_DENY`, `PATH_ALLOW` in `broker/takwerx_broker.py` |
| Codebase map and the seams table | `ARCHITECTURE.md` |
| Contribution rules, license header, CLA | `CONTRIBUTING.md`, `CLA.md` |
| Ports already in use | `README.md`, "Ports" section |
