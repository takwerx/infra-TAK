# infra-TAK — Claude Code guidance

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

**`app.py` is large (~120k tokens). Never load it whole.**
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
