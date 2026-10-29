# CloudTAK plugins nightly (ops #301)

Every night `.github/workflows/cloudtak-plugins-nightly.yml` builds CloudTAK (the newest release and `main`) with every
plugin takwerx ships, then opens the built web app and looks for each plugin's menu entry. It exists because CloudTAK
13.102.0 moved its web folder, our Dispatcher installer kept copying into the old one, said "installed", and nobody looked
at the finished app (ops #297).

## What a run contains

| Job | What it proves |
|---|---|
| all plugins, latest release / main | infra-TAK's install + its pre-build step (`_cloudtak_shield_foreign_plugins` in `app.py`, taken from the file as written) put every plugin in the build. Also runs the console's own in-container look (`_CT_IN_APP_SH`) in the built image. |
| Dispatcher install.sh (main / dev) | The Dispatcher's own installer, as people without infra-TAK run it. `main` is what users get today, `dev` is what ships next. |
| canary: old Dispatcher install.sh | Must come out red inside the check (the job is green when it does). Proves the check still catches the 13.102 folder bug. |
| canary: main without infra-TAK build step | Same for CloudTAK main's `.dockerignore` change: without our pre-build step the plugins must be missing. |

Each plugin's expected menu entry is read from the plugin's own `menu.add({key, label, ...})`, so renaming a menu entry
needs no edit here. A plugin whose `menu.add` can't be read is a failure, not a skip.

## Adding or removing a plugin

Edit `manifest.json`. `tests/test_cloudtak_plugin_nightly_ops301.py` fails a PR if a plugin in `CLOUDTAK_PLUGINS`
(`app.py`) is missing from it, or if `in_catalog` disagrees with `app.py`.

## Reading a red run

The step "Check each plugin's menu entry is in the built app" lists one `ok`/`FAIL` line per plugin. A FAIL means the
plugin was installed but is not in the built web app (what a user sees: no menu item). Check, in order: where the
installer put the folder (CloudTAK's web app is `app/`), whether `.dockerignore` leaves it out of the build, whether the
build output changed. Run locally: `python3 -I .github/ci/cloudtak_plugins/bundle_check.py --help`.

Not covered: seeing the icon in a logged-in browser (needs a TAK Server login). This proves the plugin's code and its
menu registration are in the bundle, not that the panel works.
