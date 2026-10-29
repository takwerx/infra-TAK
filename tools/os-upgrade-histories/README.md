# Box-history matrix for one-way, in-place upgrades (ops #285)

**Why.** The Ubuntu 22.04 → 24.04 upgrade in v10.3.0 was only ever tested on boxes that had one PostgreSQL cluster. Real boxes that took the TAK 5.7 → 5.8 update keep PostgreSQL 15 stopped on 5433 next to PostgreSQL 18 on 5432. The upgrade stopped those boxes halfway (infra-TAK #316, #318). A test that builds the *end state by hand* cannot find that; a box that lived the *real history* can.

**The rule.** Any release test for the OS upgrade (or another one-way, in-place upgrade: database server, remote hosts, a future Rocky 9 → 10) runs this matrix against the candidate. `tools/pick-tests.py` lists it as **Tier 6** whenever a change touches that code.

## The matrix

| Cell | History (replayed from released versions, never hand-built) | Must end |
|---|---|---|
| `h1-fresh-single:a-bare` | 22.04, infra-TAK v10.2.30, TAK 5.8 only | `done`, PG 18 on 5432 |
| `h1-fresh-single:b-authentik` | same + Authentik | `done`, Authentik container back |
| `h1-fresh-single:c-docker-tak` | same, Docker (hardened) TAK Server | `done`, `takserver` container back |
| `h1-fresh-single:d-full` | same + Authentik + broker + Docker modules | `done`, all back |
| `h2-57-to-58-then-os` | infra-TAK v10.1.85, TAK **5.7** / PG 15, console Update Now to v10.2.30, the console's **5.8 update** (PG 15 stopped on 5433 + PG 18 on 5432), Authentik + broker + Docker modules | `done`, **both** clusters as they were, log says the stopped 15 was kept |
| `h3-old-pg-left-online` | h2, then PG 15 started again | **refused before any change**, names `pg_ctlcluster 15 main stop` |
| `h4-stuck-reassert` | h2, then the *released v10.3.0* OS upgrade, which stops at `failed:reassert` | Update Now to the candidate finishes it by itself: `done`, no reboot asked |
| `h6-58-r92-then-os` | h2, then the console's plain TAK Server update to **5.8 RELEASE92** (the headline release), then the OS upgrade | `done`, both clusters as they were, TAK Server still RELEASE92 |
| `h5-two-server` | core + database server (test8 style), TAK 5.8 | core `done`, then the database server `done` from the core console |

Add a cell by adding it to `scenarios.json`; `tests/test_os_upgrade_histories_ops285.py` checks the file and this table agree.

## How it works

1. **Build a history once.** `python3 histories.py plan CELL` prints the steps. Replay them on a lane Azure VM (`box.sh create`), through the console, exactly as a customer would, and after each step run `box.sh note-step VM STEP-LABEL`. The labels are the proof the history was lived, not painted on.
2. **Check it is a real history.** `box.sh facts VM`, then `histories.py judge CELL facts.json --stage start`. A snapshot without the recorded steps in order, or with the wrong clusters, is refused.
3. **Snapshot it.** `box.sh snapshot VM snap-hN --cell CELL`. The VM is stopped, the OS disk is snapshotted (incremental), tagged `owner` + `expires` (45 days). Derived cells (h3, h4) are built from a restore of h2's snapshot.
4. **Run it.** `run-scenario.sh CELL --candidate SHA` restores the snapshot to a *new* VM, drives the console (`drive.py`: preflight, Start, or Update Now), waits through the reboot, collects facts, judges, and deletes the run box. The snapshot is never touched, so a one-way upgrade never uses up the only box in that state. For two-server cells, snapshot the database box as `snap-h5-db`.
5. **Release note.** `histories.py release-line --all-cells RESULT.json…` prints `Tested on box histories: …`. **Any release note that adds an in-place upgrade must carry that line**, and a cell with no result prints `NOT RUN`.

## Pass rule

Per cell the judge checks: upgrade status `done`; the log has no `failed` (edit `log_allow` in `scenarios.json` for a known-harmless line, with a reason); `lsb_release` 24.04; the PostgreSQL clusters on the expected ports; TAK Server + console (+ Authentik where the history has it) up and every service and container from before the upgrade back; the box runs the candidate SHA; the client check passes. An **unsafe** cell passes only if the console refused before any change: preflight red on the named check, the next step named, Start answered 409, no job, still 22.04, clusters / packages / boot id unchanged, no upgrade drop-ins left, the box still serving.

## Cloud rules (OPS-WORKER.md, Oct 27, 2026)

Everything lives in resource group `rg-tak-hist` of the lane's Azure subscription, named in `HIST_AZURE_SUBSCRIPTION` (the id is not kept in this repo; `box.sh` refuses any other subscription before every command). Each VM gets Azure auto-shutdown (3 hours after it is created; `HIST_SHUTDOWN_HOURS` can say 1 to 4, never more) the moment it exists, before anything is installed, and is deleted again if that fails. Every resource carries `owner=claude-lane` and `expires=`. SSH and the console are open only to the address of the machine that created the box. `run-scenario.sh` stays in the foreground until the cell has a verdict. Start every session with `box.sh sweep` (`--delete-expired` removes only expired lane resources).

## What you need

- `az login`, and `HIST_AZURE_SUBSCRIPTION` set to the lane subscription id; an SSH key at `~/.ssh/id_ed25519_infratak` (or `HIST_SSH_KEY`).
- The TAK Server 5.7 and 5.8 packages from tak.gov (uploaded through the console, as customers do). They are not in this repo.
- `INFRATAK_CONSOLE_PASSWORD_FILE`: a mode-600 file with the console password of the history boxes. Never put it on a command line or in a report.
- `CLIENT_CHECK_CMD`: command that takes the box IP and runs the client check (see `run-scenario.sh`). Without it the client check is reported as **skipped: needs device** (a cloud box has no enrolled phone client): the cell can pass, and the result and the release line say the client check was skipped. A command that runs and fails still fails the cell.

## Not automated yet (be honest in reports)

- Step 1 (replaying the released path through the console) is done by hand following `plan`; only the proof (`note-step`) and the checks are scripted.
- The client check against a *cloud* box needs a client enrolled to that box (the tak-dev emulator); no such tool exists yet, so cloud cells report it as skipped, needs device. Set `CLIENT_CHECK_CMD` once there is one.
- The two-server database box's own `status` file is read from the same path as the core's; confirm on the first real h5 run.
