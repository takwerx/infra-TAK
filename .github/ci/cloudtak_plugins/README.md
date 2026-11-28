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

**Does the plugin's action still have a route? (ops #1414)** A menu entry in the bundle proves the plugin loaded, not that
clicking it works. CloudTAK 14.0.0 removed routes and changed chat and location sharing, and a plugin that calls a route
that is gone still shows its menu. The step "Check each plugin's CloudTAK API calls still have a route" reads every CloudTAK
call the plugin's browser code makes (`std('/api/...', {method})`, the typed `server.GET('/api/...')`, or a plain `fetch` on
the server address) and checks that CloudTAK's own source, plus the routes the plugin ships in `server/`, still defines it
with that method. It needs no TAK Server and no login. Reading the result:

- `ok` all calls have a route. `FAIL` a call has no route (the line names the plugin, the call, the file and line).
- `note` a call passes a variable instead of a literal path, so it was not compared. It is shown, never skipped silently.
- `known` a route the plugin knows is gone and copes with. It is listed in `manifest.json` under `allow_missing`, with a
  required `why`. A NEW missing route next to it is still `FAIL`.
- `skip` a private plugin (see below).
- A path the plugin builds at run time (`${BASE}${path}`) is checked as a prefix: CloudTAK must have routes under it.
- A canary step adds a route that cannot exist and requires the check to go red, so the check cannot go blind unseen.

**Private plugins (HazCmdr, RapidSOS).** A GitHub-hosted run cannot read their repos, so the nightly lists them as `skip`
(never silently). They are checked on the Studio against the local checkouts, against any CloudTAK tag or `main`:

```
python3 -I .github/ci/cloudtak_plugins/bundle_check.py routes-local --ct <CloudTAK checkout> \
    --plugin ~/GitHub/cloudtak-hazcmdr-plugin --plugin ~/GitHub/cloudtak-rapidsos-plugin
```

Each `--plugin` folder has `plugin/` (browser code) and `server/` (its own routes). Exit 1 means a route is gone. Giving the
nightly a read token for the two private repos would let it build and check them too: that is the Plugins lead's call.

Not covered (still true): the plugin's request and response shapes, chat and location behaviour, and a click in a logged-in
CloudTAK with a TAK Server. This check says a route is gone, not that a route that is still there answers the way the plugin expects.

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
