# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> The sections below the `---` divider are **process rules** (git stops, plan-first, handoff, scoping, T&E). They are hard requirements — read them. The sections above the divider are the **codebase map** so you don't re-explore every session.

## What this is

infra-TAK is a single-clone, single-password web console (`https://<host>:5001`) that deploys and manages the whole TAK ecosystem on one Ubuntu VPS: TAK Server, Federation Hub, Authentik (SSO/LDAP), TAK Portal, Caddy (SSL), CloudTAK, MediaMTX / TAK Video Restreamer, Node-RED, Email Relay, and Guard Dog (health monitoring). "No more SSH" — everything is driven from the browser. Current release line: see the top of `README.md` (e.g. `v0.9.41-alpha`); `dev` is ahead of `main`.

## Architecture (the big picture)

**It is a Flask monolith.** `app.py` is **~54,000 lines / ~200k tokens** and holds essentially the entire backend: ~322 `@app.route` handlers plus their helpers. There is no blueprint/package split — `modules/` is an empty stub. **NEVER read `app.py` whole** (see token rules below); grep for the route or function and read only the 50–200 lines you need.

- **Entry / process model:** `start.sh` (run as root) installs deps into `.venv`, hashes the admin password, generates a self-signed cert, and writes the `takwerx-console.service` systemd unit that runs `gunicorn ... app:app` on port 5001 (1 worker, 4 threads). It does NOT use `python app.py` directly in production.
- **State lives in `.config/`** (gitignored, mode 600), not a database: `auth.json` (password hash), `settings.json` (`ssl_mode`, `fqdn`, `server_ip`, `os_type`, `console_port`, `install_dir`, …), `ssl/`. Read/write it via `load_settings()` / `save_settings()` / `load_auth()` (`app.py:750`+). `CONFIG_DIR` env var points at it.
- **Managed services are Docker containers / system packages** the console shells out to (TAK Server `.deb`, Authentik via compose in `~/authentik`, CloudTAK, MediaMTX, etc.). The console orchestrates them over the host's docker/systemctl/openssl/ssh — there is no ORM and few in-process libraries.
- **Routes are grouped by module via URL prefix.** To find a feature's backend, grep the prefix. Approx counts: `/api/takserver` (77), `/api/fail2ban` (26), `/api/authentik` (24), `/api/guarddog` (22), `/api/cloudtak` (19), `/api/fedhub` (15), `/api/caddy` (10), plus `webodm`, `tak-video-restreamer`, `nodered`, `emailrelay`, `cesium-tiles`, `takportal`, `mediamtx`, `firewall`, `console`, `update`, `customization`. Routes use a `@login_required` decorator.
- **Frontend** is server-rendered templates + `static/`; there is no separate SPA build for the console itself.

### CloudTAK plugins (current active work — TAK CAD)

CloudTAK plugins live in `cloudtak-plugins/<name>/` and are **registered in the `CLOUDTAK_PLUGINS` catalog list in `app.py` (~line 15283)**. Each entry has a `key`, `install_dir`, and either:
- `repo` (public git URL — cloned at install), or
- `local_path` (absolute path to source in *this* repo — **copied** into `~/CloudTAK/api/web/plugins/<install_dir>/` at install; Vite auto-discovers it via `import.meta.glob` and bundles on the next API rebuild), and optionally
- `server_path` — CloudTAK API route files copied into CloudTAK's `api/routes/` so the browser plugin can reach TAK Server's `/Marti/api/plugins/<key>/*` through CloudTAK's cert auth (CloudTAK has no generic Marti passthrough — this server-side proxy is required).

Install/detect/rebuild logic: `_detect_cloudtak_plugins()` (`app.py:16052`), `_run_cloudtak_plugin_action()` (`app.py:16091`), routes `/api/cloudtak/plugins/{list,action,log}` (`app.py:16233`+). **TAK CAD** = `cloudtak-plugins/takcad/`: Vue plugin under `plugin/` (`index.ts`, `components/`, `lib/takcad-client.ts`), server proxy under `server/plugin-takcad.ts`. Plugin client auth goes through CloudTAK's `std()` helper (not raw fetch) — raw fetch gave `401 No Auth Present`. See memory `cloudtak-plugin-authoring.md` for the gotchas (`disable()` must not `removeRoute`; copy-not-symlink; ESLint single-quotes; the service-worker cache masks rebuilds). It ships **dev-only** until the TAK-CAD *server* plugin is public.

TAK Server plugin management (the `.jar`/`.yaml` side, distinct from CloudTAK browser plugins) is `/api/takserver/plugins/*` at `app.py:43556`+.

## Commands

This is a Flask app run under gunicorn + systemd; there is **no test suite, no linter, no build step** for `app.py` (the framework's own checklists are manual — see T&E below). The CloudTAK plugins are TypeScript/Vue and are linted/built by CloudTAK's own toolchain when CloudTAK rebuilds.

```bash
# Run / manage the console (on a host)
sudo ./start.sh                              # first install or re-run (idempotent)
sudo systemctl restart takwerx-console       # restart after a code change (operator does this on test boxes)
journalctl -u takwerx-console -f             # tail logs
grep '^VERSION' app.py                        # confirm running version

# Navigate app.py WITHOUT reading it whole
grep -nE "@app\.route\('/api/<prefix>" app.py        # find a feature's routes
grep -n "def <function_name>" app.py                  # jump to a handler/helper

# Recovery on a VPS (wrong version / failed Update Now) — see README "Universal recovery"
git fetch https://github.com/takwerx/infra-TAK.git main && git checkout --force -B main FETCH_HEAD

# CloudTAK plugin local-dev cycle: edit cloudtak-plugins/takcad/, then re-run the
# plugin install action from the console (copies source) and rebuild CloudTAK's API.
# Hard-refresh the browser — CloudTAK's service worker caches the old bundle.
```

`scripts/` holds standalone operator fixes (e.g. `ldap-diagnose-and-fix.sh`, `nodered-egress-firewall.sh`); `nodered/` has the Node-RED flow build (`deploy.sh`, `build-flows.js` — never raw `docker cp flows.json`). Memory/context for the project lives in `memory-bank/` (`activeContext.md`, `progress.md`) and `docs/` (`RELEASE-*`, `PLAN-*`, `HANDOFF-*` files).

> **`docs/` and `memory-bank/` now live in the PRIVATE sibling repo `infra-TAK-notes`** (`takwerx/infra-TAK-notes`), not in this public repo. On the dev Mac they sit at `../infra-TAK-notes/docs/` and `../infra-TAK-notes/memory-bank/` — open `~/GitHub/infra-TAK.code-workspace` to get both repos in one window. **Every `docs/…` and `memory-bank/…` path in the process rules below resolves to that private repo** (read/write HANDOFFs, PLANs, and memory-bank there; commit/push them to `infra-TAK-notes`, never to public `infra-TAK`).

---

# infra-TAK — Claude Code guidance (process rules)

## Git & release rules (hard stops)

The following git operations require **explicit, unambiguous authorization** from the operator before running. Stop and ask every time — even if a prior turn felt like authorization:

1. `git merge` any branch into `main`
2. `git push origin main`
3. `git tag` (any version tag)
4. `git push origin <tag>` or `git push --tags`
5. `gh release create`

**Phrases that do NOT count as permission:** "do the best thing", "let's ship it", "go for it", "send it", "ok let's do this", general approval of a plan.

**Phrases that DO count:** "ship to main", "merge to main and tag v0.X.Y", "tag it and push", "selective merge to main, tag it", "release vX.Y.Z" (when context clearly means publish).

Before any main-merge/tag/release, send this prompt and wait for a yes/no:

> Ready to ship vX.Y-alpha to `main`:
> - dev branch tip: `<sha>` (`<commit subject>`)
> - field validation: `<one-line summary>`
> - this will: squash-merge dev → main, tag `vX.Y-alpha`, push both
>
> **Ship it?**

Free actions (no permission needed): `git push origin dev`, migrations/soak on dev boxes, drafting release notes on dev.

**Why:** On 2026-05-17 the agent autonomously squash-merged dev→main after reading "im tired of fucking around" as authorization. That was wrong. Releases are operator decisions.

### Release procedure — run ALL of this once the operator authorizes the ship

When the operator gives an unambiguous ship instruction ("ship to main", "selective merge to main, tag it", "release vX.Y.Z"), execute this full sequence — don't stop after the tag. The version is already bumped on dev (`VERSION` in `app.py`); the code is the T&E-validated dev tip.

1. **README on dev** — bump `**Current release:**` and add a `## Changelog` entry (product-focused headline, dated). Link both to the GitHub Release URL `https://github.com/takwerx/infra-TAK/releases/tag/vX.Y.Z-alpha` (NOT `docs/RELEASE-*.md` — those live in the private notes repo and are dead links in the public repo). Commit + `git push origin dev`. README/changelog is non-functional, so it doesn't invalidate the soak — note the validated code SHA in the commit.
2. **Selective merge dev → main** — `git checkout -B main origin/main` then `git checkout dev -- <changed files>` so main's tree is byte-identical to dev. **Verify `git diff dev main` is empty before committing.** Do NOT `git merge` dev — dev/main histories are rewrite-diverged (see `[[pending-history-rewrite-v0944]]`); only the tree matters, and a real merge drags 300+ rewritten commits. Commit on main as the release commit.
3. **Tag + push** — annotated `git tag -a vX.Y.Z-alpha`, then `git push origin main` and `git push origin vX.Y.Z-alpha`.
4. **GitHub Release** — `gh release create vX.Y.Z-alpha --title "…" --latest --notes "…"`. **Mark it `--latest`.** Body is **product-focused** (root cause + fix + upgrade note) — NO internal box names, T&E metrics, soak data, or infra details (public repo is product-only).
5. **Private full notes** — write/finish `docs/RELEASE-vX.Y.Z-alpha.md` in the **private** `infra-TAK-notes` repo (root cause, full T&E results, soak data, known limitations), commit + push that repo.
6. **Return to dev** (`git checkout dev`) and confirm `main` tree == `dev` tree.

Public vs private split is the rule: GitHub Release + public README = product-only; the private notes repo holds the full engineering record.

---

## Node-RED config persistence is SACRED (hard stop)

Configurator configs (`arcgis_configs`, `tc_configs`, `pp_configs`, `tak_settings`, `ipaws_config`) live **only** in Node-RED's volatile global context — **not** in `flows.json`, **not** in git, **not** reconstructable from engine tabs (a tab looks its config up *by name*: `if(!cfg) return null`). Lose context without a fresh backup and the configs are **gone forever**. This has wiped real users (Charles on v0.9.49; Joe's "Red Flag" on test12). It must never happen again.

**Before ANY change to the persistence path** — `nodered/deploy.sh`, `CFG_BACKUP_SNIPPET`, `fn_save`/`fn_saveall`/`fn_*_delete`/`fn_cfg_restore`/`fn_deploy_restore`, the `contextStorage`/`settings.js` logic, or the configurator save/restore JS:
1. Pull live configs off-box first (`docker exec nodered curl -s localhost:1880/context/global`) and confirm non-empty.
2. Treat every restore/deploy as **DESTRUCTIVE until proven otherwise**.
3. Validate on a real box: add a throwaway config → run the change (deploy **and** restart) → confirm it survived. Never ship a persistence change without this.

**Code invariants — no exceptions:**
- A restore/deploy MUST NEVER shrink the live config set by replacing it with a smaller/older snapshot. If a candidate has fewer configs than another available source, **union by `configName`** (keep both) — older/smaller never silently wins. Both live context and `latest.json` honor deletes, so unioning *them* never resurrects a deleted config; the stale `/opt/tak` persistent snapshot is last-resort fallback only, never part of the union.
- Back up on **SAVE and DELETE**, not just on deploy (`CFG_BACKUP_SNIPPET` writes `latest.json` synchronously — every save/delete handler must run it).
- Verify `contextStorage:localfilesystem` is present in the file the **container** reads (derive the path from the `docker inspect` bind-mount source, not `$HOME`), with a canary — never assume a patch landed.
- A restore that yields **0 configs, or fewer than live, is a FAILURE to surface** in the UI/logs, not a success.

See memory `nodered-config-persistence-sacred.md`. The v0.9.50 shields: save/delete→`latest.json`, settings.js real-path + canary, deploy.sh live∪`latest.json` union, `fn_deploy_restore` never-drop-live merge, hardened `fn_cfg_restore` (strip `default`, report counts).

---

## Plan-first build workflow

Name the scenario at the start of every chat.

### Scenario A — New feature or idea
1. **Planning chat** — produce `docs/PLAN-v[X.Y.Z].md`. One chat, one doc.
2. **Build chat** (new chat) — first message: "Read `docs/PLAN-vX.Y.Z.md`. Implement it exactly as specced. Start with [section]." No re-explaining.

### Scenario B — Bug found
**B1 — Hot fix:** scope in 2–3 sentences (function name, what's wrong, what the fix is), build it, version-bump, ship. Keep this chat SHORT — fix the critical thing only.

**B2 — Cascade planning (after hot fix ships):** write `docs/PLAN-v[next].md` for everything the bug revealed. Never fold cascade items into the hot fix chat.

### PLAN doc must contain
1. Headline — one sentence: what ships and why
2. Scope discipline — what is explicitly NOT in this release
3. The bug/need — full description with exact log evidence
4. The fix — function names, approximate line anchors
5. Acceptance test — exact shell commands
6. What this does NOT ship — every parked item named explicitly

If scope creep appears during a build chat, STOP — update the PLAN first, then continue.

---

## Session handoff

Reading 50 lines of a HANDOFF costs ~150 tokens. Reconstructing lost context from scratch costs ~8,000 tokens. Write the HANDOFF.

**Starting a session:** Read `docs/HANDOFF-<latest-date>.md` before opening any code file. Anchor: "Per the HANDOFF, picking up from [X]. Today's task: [Y]." Open only files mentioned in the handoff.

**Ending any chat longer than 10 turns:** Write or update `docs/HANDOFF-<YYYY-MM-DD>.md`:

```
## Status
[Done / In progress / Blocked]

## What was done
- [function/route changed] — [why]

## Current state
[Does it work? What's confirmed broken? What's unknown?]

## Exact next step
[Single action: "Fix the X in function_name() around line NNNN"]

## Files touched
- app.py (lines ~XXXX–YYYY)
```

If a bug takes >2 chats to resolve, add a `## Known context` section with what's been ruled out, exact error messages, and which approaches failed and why.

---

## Task scoping — pre-flight for app.py work

Answer all three before writing a single line of code:

1. **Which route or function?** (e.g. `/api/nodered/deploy`, `deploy_nodered()`)
2. **What exactly needs to change?** (1–2 sentences)
3. **Approximate line range?** (grep to anchor before reading)

If you cannot answer all three → grep first. Do NOT start with open-ended exploration.

If the task touches >3 functions, split it into sub-tasks and write a brief plan.

**Prefer grep over open-ended reads:**
- ❌ "find where Node-RED context backup happens" (reads many chunks)
- ✅ `grep "nodered_context_backup" app.py` (immediate)

**When reporting a bug:**
- ❌ "The deploy is broken"
- ✅ "Deploy fails at the context backup step — log shows `FileNotFoundError` on `/opt/tak/nodered-ctx-backup.json`"

---

## Context discipline

**`app.py` is large (~54,000 lines / ~200k tokens). Never load it whole.**
- Grep or search first to find the exact function/route
- Read only the 50–200 line range needed
- Anchor the agent before it starts: "In `deploy_nodered()` around line ~4200, fix X"

**Cap chat length at ~15 turns.** After ~15 back-and-forths, write a HANDOFF note and start a fresh chat.

**Give the agent a line number or function name to anchor on.** A vague question = broad search = many file reads.

---

## Consult upstream documentation first

When debugging, optimizing, or configuring any third-party software (Authentik, Caddy, TAK Server, Node-RED, Postgres, Docker, etc.), **read the official documentation BEFORE chasing symptoms or building workarounds.**

Required workflow:
1. Find the project's official docs and read the relevant subsystem page first
2. Find the project's verification command (e.g. `ak dump_config`, `caddy adapt`, `docker inspect`, `psql -c "SHOW ALL"`)
3. **Never trust the input config to mean the runtime is using it.** Always confirm with the upstream's verification command
4. Cite the doc URL in commit messages and HANDOFF notes

**Cautionary tale (April 2026):** `AUTHENTIK_WEB_WORKERS=4` was silently ignored for 5 releases because the correct env var is `AUTHENTIK_WEB__WORKERS=4` (double underscore). Only caught when the operator asked "is there any info on the internet about optimizing authentik?"

Anti-patterns to avoid:
- ❌ Building a recreate/restart workaround before checking upstream config docs
- ❌ Setting an env var and assuming it works because the process started
- ❌ Citing GitHub issues/blog posts as the only source when the project has official docs

---

## Fleet-uniform configuration

infra-TAK ships to many customers. Config MUST produce the same operational state on every box — either a fleet-uniform constant OR a value computed from observable signals on that box (deterministic auto-tune). **Never preserve a number an operator typed during a fire and let it silently outlive the incident.**

**Anti-patterns:**
```python
# ❌ Operator override silently outlives the incident
new_default = max(cur_default, target_default)

# ❌ Per-customer tiers (same trap)
new_default = SIZES[settings.get('install_tier', 'small')]
```

**Approved patterns:**
```python
# ✅ Fleet constant — every box converges to the same value
DEFAULT_POOL_SIZE = 250  # field-validated under Channels-class load
target_default = DEFAULT_POOL_SIZE  # always write target, no max(cur, target)

# ✅ Deterministic auto-tune — same logic on every box
peak = read_observed_peak_from(pgbouncer_show_pools, pg_stat_activity)
target_ceiling = max(MIN_CEILING, peak * SAFETY_FACTOR)
target_default = target_ceiling * 5 // 6
# always write target, no max(cur, target)
```

**Pre-merge checklist:**
- [ ] No `max(cur, target)` or equivalent override-preservation in any config migration
- [ ] Every config knob has either a fleet constant or an autotune output backing it
- [ ] ≥3 test boxes pulled the release from dev and ran ≥60 min stable WITHOUT manual config edits
- [ ] Operator overrides on test boxes are explicitly cleared before validation
- [ ] Release notes name the validation boxes, soak window, and absence of overrides

**Never validate a release on an operator-tuned box.** Validating on a box with manual overrides proves the override works — not that the codified default works.

**Why:** In v0.9.26, `max(cur, target)` caused tak-10 (manually tuned to 250/50) to stay at 250/50 while test8 was set to 75/15. The release was validated on tak-10 and shipped — test8 became unhealthy in ~5 min.

---

## Test & Evaluation (T&E) procedure

When the operator says "perform T&E", "run T&E", "soak it", "validate dev", or "ready to ship?" → read `docs/TEST-AND-EVALUATION-PROCEDURE.md` end-to-end and execute it step-by-step. Do not re-derive the steps.

**Role split — agent does NOT pull on test boxes:**
- **Operator does:** `git fetch origin dev` / `git checkout -B dev origin/dev` / `sudo systemctl restart takwerx-console` on every test box
- **Agent does:** Step 0 (pick candidate), Steps 1–2 (read-only pre-flight and verification), Step 3 (soak wait), Step 4 (health-check matrix), Step 5 (release-specific checks), Step 6 (PASS/FAIL gate and ship prompt)

**The agent must NEVER `git pull`, `git checkout`, or `systemctl restart takwerx-console` on a test box on its own initiative.**

**Hard invariants:**
1. ≥3 dev boxes from the active fleet (currently `test6`/`test8`/`test12`)
2. No operator overrides on validation boxes
3. Operator does the pull + restart on every box
4. ≥60 min soak per box on the candidate SHA; clock resets if a new commit lands mid-soak
5. All boxes on the same SHA at end of soak
6. `ak dump_config` mandatory on any release touching Authentik env vars
7. T&E green = present the ship prompt and STOP. T&E green ≠ permission to ship

T&E output is the Step 6 PASS/FAIL checklist, filled in, plus either the ship prompt (all green) or forensics + next debug step on dev (any red).
