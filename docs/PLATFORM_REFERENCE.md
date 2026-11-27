# Platform reference: what infra-TAK depends on outside its own code

Each entry says where the fact comes from. `✅ verified <date> on <box>` means we saw it happen on a real box. Where the official docs and what we saw disagree, both are kept. Observations are never deleted, only added to.

## TAK Server: LDAP username lookup

**Source (official):** TAK Server open source, `src/takserver-core/src/main/java/com/bbn/marti/groups/LdapAuthenticator.java` (https://github.com/TAK-Product-Center/Server). Public source ends at 5.7-RELEASE-14; the code below is identical on `main`.

- TAK Server builds the user's LDAP name with a plain string replace: `userString.replace("{username}", username)`. Nothing is escaped (no RFC 4514 escaping).
- It binds with that name (as a connection property, so any character survives), then reads the user's groups with JNDI `ctx.lookup(userBindDn)` and a base-object search.
- `Context.lookup(String)` parses its argument as a **composite name**, where `/` separates components (https://docs.oracle.com/en/java/javase/21/docs/api/java.naming/javax/naming/CompositeName.html). So `cn=a/b,ou=users,dc=takldap` is read as `cn=a` plus `b,ou=users,dc=takldap`, and the lookup goes to `cn=a`.
- The `userstring` is configurable (`<ldap userstring="cn={username},ou=users,dc=takldap">`) but there is no setting to escape or encode the username.

**What happens per character** (✅ verified 2026-10-30 on test12, TAK Server 5.8-RELEASE92, Authentik 2026.8.5; users created in Authentik, logged in through the 8446 basic-auth enrollment API, watched in the `authentik-ldap-1` log):

| Character in the username | Result |
|---|---|
| `/` | Bind works, login works. TAK Server then searches `cn=<text before the slash>` only, which does not exist, so the user gets **no groups** and no channels. Silent. |
| `\` `,` `+` `"` `<` `>` `;` | Authentik's LDAP outpost cannot read the name TAK Server sends ("No provider found for request" or "failed to execute flow"). **Login fails** (HTTP 401). |
| `=` `#` `*` `(` `)` `.` `@`, space, accented letters | Work. TAK Server asks for the full name and the groups come back. |

**Newer TAK Server versions:** not checked past 5.8 (no public source for 5.8 or later).

**What infra-TAK does:** nothing. A warning on the TAK Server page was added and then removed (AJ, Fri Oct 30, 2026): these names come from TAK Portal, so the fix belongs there. Reported upstream as ValleyTacticalSolutions/TAK-Portal#82.

## TAK Portal: usernames

- TAK Portal creates the user in Authentik as typed. It does not reject or warn about `/ \ , + " < > ;` (reported in TAK Portal#82). The name TAK Portal accepts is the name TAK Server later puts into an LDAP lookup, so see the table above.

## Authentik LDAP outpost: new users appear late

**Source (official):** https://docs.goauthentik.io/add-secure-apps/providers/ldap/. Search mode "Cached" keeps users and groups in the outpost's memory and refreshes them periodically, so it "can return stale data". The docs do not say how often.

- infra-TAK's blueprint sets `search_mode: cached` and `bind_mode: cached` (fleet constant).
- ✅ verified 2026-10-30 on test12 (Authentik 2026.8.5): a user created in Authentik can bind straight away, but the outpost's search returns no entry or no groups for it, with the log line `User with pk is not in local cache`. In two clean runs the user and groups showed up on their own after about 2 minutes and about 4 minutes 20 seconds. No restart was needed.
- A restart of `authentik-ldap-1` forces the refresh but drops LDAP for 10-30 seconds, so infra-TAK does not do it for this.

## Authentik: updates across release families (the upgrade step)

**Source (official):** upstream `lifecycle/migrate.py` (`ensure_allowed_version`, `VERSION_FAMILY_PREVIOUS`): 2026.8 starts only on a database from 2026.8 or 2026.5. Release notes per patch: https://docs.goauthentik.io/releases/2026.5#fixed-in-202659 (the 2026.5.9 release is a same-minor patch). A box on 2026.2.x or older therefore stops at `AUTHENTIK_UPGRADE_STEPS` first and takes the pin on its second Update press.

- The step must be at or above the security floor of its own family (`AUTHENTIK_SECURITY_FLOOR` in `tests/test_authentik_2026_8_promotion.py`): the box waits there until the customer presses Update again. Raise the step in the same PR that raises the floor.
- ✅ verified 2026-11-26: upstream compare `version/2026.5.7...version/2026.5.9` touches no migrations file (only `blueprints/schema.json` among schema files), so the step moves inside the 2026.5 family without a database change.
- ✅ verified 2026-11-26 on fresh-install boxes (ubuntu-22.04, rocky-9, ubuntu-22.04-arm64): a console on this code with Authentik 2026.2.7 (and 2026.2.1 on ARM) takes the Authentik page's Update to 2026.5.9 in about 75 seconds, and a second press to 2026.8.7 in about 100 to 120 seconds. After each press: sign-in, LDAP groups on TAK Server clients and QR enrollment (HTTP 200, wrong password 401) work. A hand re-pin 2026.5.9 to 2026.5.7 inside the family works and the next Update goes straight to 2026.8.7.
- ✅ verified 2026-11-26: on Authentik 2026.2.x the embedded outpost loads a new proxy application only at its 5 minute refresh (log line `Loaded application` at 5 minute steps). A TAK Portal deployed on such a box answers Authentik's 404 page for up to 5 minutes, then redirects to sign-in. Authentik 2026.8.7 was not measured the same way.

## Redis (Authentik's legacy `redis` service): no downgrade over a newer dump

**Source (official):** https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/ (RDB snapshots; with save points set, Redis also saves on shutdown). Authentik stopped using Redis in 2025.10: https://docs.goauthentik.io/releases/2025.10/. The official image sets `REDIS_VERSION` in its environment, so `docker inspect` tells which Redis a floating tag really is.

- ✅ verified 2026-11-26 on nuc (Rocky 9, non-root console, Authentik compose `--save 60 1`): Redis 8.12.0 saves an 89-byte RDB v17 `dump.rdb` on stop even with no keys. Redis 8.10.3 started on that volume exits at once with `Can't handle RDB format version 17` and restarts in a loop. Moving `dump.rdb` aside starts 8.10.3 empty and healthy. Authentik server, worker and LDAP stay healthy the whole time.
- ✅ verified 2026-11-26 on nuc: with a file other than `dump.rdb` in `/data`, the image's entrypoint logs `Unknown file ... found in data dir. Permissions will not be modified.` Redis starts normally.
- So infra-TAK never pins a floating Redis tag to a version older than the one the box ran (ops #1306, infra-TAK #759).

## CloudTAK: documentation site

**Source (official):** https://docs.cloudtak.io/ ("Get started with CloudTAK | CloudTAK Documentation"). The same site holds the integrations (ETL) pages at https://docs.cloudtak.io/integrations/, which the CloudTAK page already links.

- infra-TAK links the docs home page from the header of the CloudTAK page (`templates/cloudtak.html`, `id="ct-docs-link"`), opening in a new tab.
- ✅ verified 2026-11-20 from the Studio: both URLs return HTTP 200 with the titles above. Not checked: whether every page of the site stays at the same path in later CloudTAK releases.

## Customer states: what Update does to a box that is not "the last release, built by us"

Written for the stack audit (ops #1311, after the 10.4.8 redis crash loop, infra-TAK #759). The rule (maintainer rule, Thu Nov 26, 2026): before a change ships, list the customer states it can meet and prove each on a box that really has that state, with data written by the NEWEST upstream version. This table is the list. The T&E and the update-path matrix (ops #1309, ops #1308) copy rows from it.

**Rule for every Update, heal and startup step.** A step that finds data it cannot read, or a version newer than ours, stops and says in plain words what to do. It never half-breaks the box. A floating tag (`latest`, `alpine`, a bare major) is judged by the version Docker really ran, never by the tag text (model: `_authentik_redis_target_image`, PR 762).

**Proof status, Thu Nov 26, 2026, 8:40 PM PT: read only, except the cells that name a box.** Every cell below comes from reading the code (app.py at dev `26d8328`, 10.4.9-alpha) and from the unit tests named, except the cells that name a fresh-install box (Authentik core local, TAK Server Docker Update, WebODM): those were run on a real box, with the data written by the newest version that exists (Authentik 2026.11.0-rc2, WebODM 3.3.1 on PostgreSQL 9.5, TAK Server 5.8-105). Box proof follows, one state per run, on cheap boxes first (test12, nuc, aws-arm) and throwaway cloud boxes when a state needs a fresh install. Cells with "read only" are the list of what is still unproven. Use `fix #N` for "the code breaks this state, bug open", `safe` for "the code handles it, with the evidence in the row note", `unclear` for "the code does not settle it, a box test must", `n/a` for a state that cannot occur.

States (columns): **Old** = box several releases or a whole family behind. **1 behind** = one release behind. **Floating** = floating tag from before the pins. **Newer** = box runs a newer version or format than our pin. **Interrupted** = update cut off half-way (console restart, pull cut off, disk full). **Old plugins** = CloudTAK Marketplace plugins older than the newest (CloudTAK rows only).

| Service (saved data) | Old | 1 behind | Floating | Newer | Interrupted | Old plugins |
|---|---|---|---|---|---|---|
| Authentik core, local (Postgres, secret key) | safe, box: fresh-install ubuntu-22.04, rocky-9, arm64, 2026.2.x to 2026.8.7 in two presses, 2026-11-26 (above); 2025.x unclear | safe | family tag `2026.8` on the same build: safe, box fi-20261127-031943 (data written by 2026.8.7), 2026-11-26. Floating label on a NEWER build: fix ops #1331, box fi-20261127-031943 (data written by 2026.11.0-rc2): no refusal, Update pulls the vetted tag, server will not start, rollback recovers in about 3 minutes | explicit newer tag: safe (409 "Refusing to downgrade"), box fi-20261127-031943 (rc2 data), 2026-11-26. Floating label and stopped stack: fix ops #1331 (remote: ops #1322) | stopped stack with a newer pin in `.env`: fix ops #1331, box fi-20261127-031943 (rc2 data): no refusal, pin overwritten, rollback refused for a pre-release tag, box left down until the pin is put back by hand | n/a |
| Authentik redis (RDB file) | safe | safe | fix PR 762 | fix PR 762 | unclear (rollback restore when the tag text did not change; check PR 762) | n/a |
| Authentik Postgres 16 (database) | safe | safe | safe (minor only) | safe (never lowers) | safe (failed pull changes nothing) | n/a |
| Authentik pgbouncer (none) | safe | safe | safe | safe | safe (pull first, rollback) | n/a |
| Authentik `.env` (secrets) | safe | safe | n/a | n/a | fix ops #1332 (disk full leaves it truncated) | n/a |
| Authentik LDAP outpost, blueprints, app policies (none, API objects) | safe | safe | safe | safe | safe | n/a |
| TAK Portal (Postgres, settings.json) | safe | safe | fix ops #1333 (box on `main`) | fix ops #1333 | fix ops #1333 | n/a |
| CloudTAK app update (CloudTAK Postgres) | safe (hop rule MinIO to Garage; tests) | safe | safe (judged by the running container) | safe (guard ~62758) | fix ops #1325 | safe (stops and tells; tests) |
| CloudTAK object store, MinIO to Garage (files) | fix ops #1334 | fix ops #1334 | unclear (Garage image is upstream's, not pinned) | safe (`copy --update`, never overwrites newer) | fix ops #1334 | n/a |
| CloudTAK PostGIS pin (CloudTAK Postgres) | safe (extension upgrade is check-first) | safe | safe (minor floats, major 17) | fix ops #1335 | unclear (remote `up -d` 120 s limit) | n/a |
| CloudTAK media-infra (none) | safe | safe | safe | safe (pin replaces newer, no data) | safe | n/a |
| CloudTAK ETL Runner (`stacks.json`) | safe | safe | safe (digest and SHA pins) | fix ops #1335 | safe (visible, plain words) | n/a |
| CloudTAK Deploy button (whole tree) | fix ops #1334 | fix ops #1334 | n/a | fix ops #1334 | fix ops #1334 | n/a |
| TAK Server native .deb, Ubuntu (database, CoreConfig, certs) | safe (5.7 to 5.8 migration, verified backup) | safe | n/a (packages pinned) | partly safe (cross-minor refused; same-minor downgrade unclear, ops #1337) | unclear (half-configured heal, ops #1337) | n/a |
| TAK Server RHEL and two-server (database on Server One) | fix ops #1336 | fix ops #1336 | n/a | fix ops #1336 | fix ops #1336 | n/a |
| TAK Server Docker, Update button (database volume, certs, snapshots) | fix ops #1326 (read only) | fix ops #1326 (read only) | n/a | fix ops #1326, box fi-20261127-041640 (ARM, 5.8-105 data), 2026-11-26: an older zip (104) is accepted with no version check | fix ops #1326, same box: a failed build leaves TAK down, old folder deleted, snapshots and `setenv.sh` lost, and pressing Update again cannot retry (routes to the 5.8 migration, which stops) | n/a |
| TAK Server Docker database image refresh (database) | unclear (5.7 refresh then Update goes back to the bundle image) | safe | n/a | safe (major compared) | unclear | n/a |
| TAK Server rollback (certs, database) | fix ops #1337 | fix ops #1337 | n/a | fix ops #1337 | fix ops #1337 | n/a |
| TAK Server Java pin, Temurin 17 (none) | safe | safe | safe | safe (edits only an older tag) | safe | n/a |
| TAK Server database package pins, PGDG gis (none) | safe | safe | safe (priority 600, never downgrades) | safe | safe | n/a |
| Remote DB restart, Guard Dog watcher (database) | fix ops #1338 | fix ops #1338 | n/a | fix ops #1338 | n/a | n/a |
| Federation Hub (CA, keystores, Mongo) | fix ops #1339 | fix ops #1339 | n/a | safe (apt refuses downgrade) | safe (idempotent) except the CA case, fix ops #1339 | n/a |
| NetBird server and dashboard (`store.db`, `idp.db`) | safe forward (0.80 to 0.82 had T&E evidence); no backup, fix ops #1327 | safe forward | fix ops #1327 | fix ops #1307, ops #1327 | fix ops #1327 | n/a |
| CoTURN (none) | safe | safe | safe (pinned) | safe | safe (old file restored on failure) | n/a |
| MediaMTX binary (editor owns it) | safe (console never moves it) | safe | safe | safe | safe | n/a |
| MediaMTX web editor, Patch button (users.json, share links) | safe | safe | safe | fix ops #1341 | fix ops #1341 | n/a |
| TVR (data/) | safe | safe | safe | unclear (ops #1341) | fix ops #1341 | n/a |
| WebODM (Postgres 9.5 to 18) | Reapply on a 3.3.1 box: data safe (upstream keeps `db/backup-9.5` and retries), fix ops #1328 for the missing room check; box fi-20261127-031943 (data written by 3.3.1), 2026-11-26; remote host read only | fix ops #1328 (read only) | fix ops #1307 (PR 763) | fix ops #1307 (PR 763), ops #1328 | Reapply with 110 MB free disk: fix ops #1328, same box: upgrade fails, WebODM down, console says "deployed successfully"; recovers by itself after the disk is freed, data intact | n/a |
| Node-RED image (saved configs) | safe (configs are unioned, never shrunk) | safe | fix ops #1307 (PR 763) | fix ops #1307 (PR 763) | safe | n/a |
| Node-RED saved configs (global context, `latest.json`) | safe | safe | safe | safe | safe (deploy aborts if no source has configs) | n/a |
| ATLAS (Postgres, signed identity) | safe | safe | safe (signed tags) | safe (refuses newer, test) | fix ops #1340 | n/a |
| Remote Assist (Postgres) | safe | safe | safe | safe (refuses newer) | safe (a re-run works) | n/a |
| Caddy (certs, ACME account) | safe | safe | safe | safe (never lowers) | safe (validates before reload) | n/a |
| Caddyfile regenerate (operator edits above the marker) | low, ops #1343 | low, ops #1343 | n/a | n/a | safe | n/a |
| Email Relay and Postfix (mail queue) | low, ops #1343 | safe | n/a | n/a | safe | n/a |
| Guard Dog scripts and state (`metrics.db`, takguard files) | safe (additive schema) | safe | n/a | low, ops #1343 (older console overwrites newer scripts) | safe | n/a |
| fail2ban and ufw (ban database) | safe | safe | n/a | n/a | fix ops #1342 | n/a |
| Console Update Now (code tree, venv) | fix ops #1329 (no version floor, libraries) | fix ops #1329 | n/a | fix ops #1329, ops #1330 | fix ops #1329 | n/a |
| Console Rollback and post-update (settings.json) | unclear (settings key shape changes) | safe | n/a | fix ops #1330 | fix ops #1330 | n/a |
| Full-stack backup and restore (`.config`, dumps) | low, ops #1343 | low, ops #1343 | n/a | low, ops #1343 | safe (verifies first) | n/a |
| Broker and non-root migration (root-owned code) | safe | safe | n/a | unclear (rollback across a security level) | safe (rollback in the script) | n/a |

**Not box-tested yet:** every cell with `fix`, `unclear` or `low` that does not name a box, and every `safe` cell except the Authentik core Old cell and the Authentik rows above. CloudTAK Update (ops #1325) is being box-tested by its own worker. The cells where the code alone cannot decide are the `unclear` ones: Authentik 2025.x family hop, redis rollback restore, CloudTAK object-store image drift, CloudTAK PostGIS major in 14.x, TAK Server half-configured heal, TAK Docker database refresh then Update on 5.7, NetBird 0.82 on a 0.83 store, TVR after a console rollback, broker rollback across a security level.

**Marketplace plugins.** CloudTAK Update runs `_cloudtak_shield_foreign_plugins`, `_cloudtak_api_plugin_preflight` and a 2-minute API watch; an old plugin that fails lint, type check or an API import stops the Update with the old build still running (tests: `test_cloudtak_marketplace_plugins_ops216.py`, `test_cloudtak_update_plugin_api_ops1262.py`, `test_marketplace_plugin_updates_ops1253.py`). A plugin that only fails in the browser at run time is seen by no check. A watch failure rolls back, and that rollback is the ops #1325 case.

## Inventory: every place infra-TAK changes an existing box

Line numbers are `app.py` at dev `26d8328` unless a file is named. "Runs" is when: **boot** = every console start (`_startup_migrations` ~123701 and the other start-up threads), **post-update** = once after the version changed (`_post_update_auto_deploy` ~125899), **button** = a console button. `security/inventory.json` named in the audit request does not exist in the repo; this list is built from the code.

**Console itself.** `update_apply` ~12382 (button: fetch, `checkout --force`, restart), `update_check` ~12058, `set_update_channel` ~11890, `_fetch_latest_tag_name` ~12242, `_ensure_gunicorn_upgrade` ~1528, `_detached_console_restart` ~772, `console_rollback_api` ~13130, `_post_update_auto_deploy` ~125899, `_startup_migrations` ~123701 (about 100 converge steps, state based, no per-release order), `load_settings` ~2360 and `save_settings` ~2387, `_repo_ownership_selfheal` ~12270, `_startup_repo_ownership_heal` ~117227, `console_migrate_nonroot_api` ~13027, broker converge `_startup_broker_converge` ~128112, `_broker_converge_root_commit` ~128011, `_broker_converge_running_source` ~128047, `_startup_pin_console_service_home` ~116561, stack backup and restore ~103168 and ~103799, patch-now reader ~31862 to 32110.

**Authentik.** Local Update `authentik_control` ~71836; remote Update ~71735; target `_get_authentik_target_release` ~46736 and `_ak_upgrade_hop` ~46782 (`AUTHENTIK_UPGRADE_STEPS` ~1758); version read `_get_authentik_version_info` ~46937; pin `_ak_env_pin_tag` ~46858; Deploy and Reconfigure `run_authentik_deploy` ~87187 (tag pin ~87796 to 87870); remote Deploy `_run_authentik_deploy_remote` ~73870; redis `_authentik_redis_image_target` ~74843, `_ensure_authentik_compose_patches` ~75103, `AUTHENTIK_REDIS_IMAGE` ~1905; Postgres `_postgres_compose_converge` ~31373; pgbouncer `_ensure_authentik_pgbouncer_image` ~80056 (`_AUTHENTIK_PGBOUNCER_IMAGE` ~78160); compose heal `_self_heal_authentik_compose` ~90773, `authentik_compose_heal` ~72314; `.env` writers through `_open_secret_w` ~1148 (about 22 sites, e.g. ~78105, ~86124); migration lock `_clear_stale_authentik_migration_lock` ~77500; converges `_startup_authentik_idle_load_converge` ~121480, `_authentik_docker_socket_converge` ~85892, `_startup_app_access_policy_converge` ~121792; LDAP heals `_tak_heal_ldap_sessions` ~80794, `_authentik_reconfigure_heal_tak_clients` ~81782.

**TAK Portal.** `_takportal_update_git` ~48458, `_takportal_run_update` ~50057, `_takportal_release_tag_strict` ~48322, Deploy `_takportal_checkout_existing` ~19898, settings `_takportal_merged_settings_json` ~48831, `_takportal_write_settings_json` ~48946, `_takportal_get_existing_settings` ~48212, guardrail `_takportal_admin_guardrail` ~85101, token heal `_heal_takportal_authentik_token` ~49030, SSH key heal `_heal_takportal_ssh_key` ~49562.

**CloudTAK.** `run_cloudtak_update` ~62679, deploy ~60495 (lookup fallback `CLOUDTAK_VETTED_RELEASE`), remote re-clone ~58454, rollback `_cloudtak_rollback_after_failed_up` ~62460 with `_cloudtak_snapshot_images` ~62383 and `_cloudtak_drop_rollback_pins` ~62427, Garage move `_cloudtak_migrate_minio_to_garage` ~58543, `_cloudtak_garage_converge` ~58629, remote `_cloudtak_remote_garage_sh` ~59460, PostGIS `POSTGIS_IMAGE` ~55790 and `_cloudtak_build_override_yml` ~55974, extensions `_cloudtak_postgis_extensions_upgrade` ~61904, media `MEDIA_INFRA_IMAGE` ~55767 and `_cloudtak_media_hls_heal` ~56485, heals `_cloudtak_upload_limit_heal` ~56659, `_cloudtak_etl_layer_heal` ~56937, `_cloudtak_print_converge` ~58380, `_cloudtak_tak_cert_heal` ~54373, `_cloudtak_heal_after_ca_change` ~54549, `_selfheal_cloudtak_corrupt_icons` ~128562, `_cloudtak_heal_dockerignore_at_start` ~58981, start-up recreate `_cloudtak_recreate_and_heal` ~120142, plugins `_run_cloudtak_plugin_action` ~55319, `_cloudtak_shield_foreign_plugins` ~59110, `_cloudtak_carry_plugins` ~59310, `_cloudtak_api_plugin_preflight` ~62227, ETL Runner `_etlrunner_net_migrate` ~57621, `_etlrunner_hooks_converge` ~57682, `_etlrunner_startup_converge` ~57720.

**TAK Server.** Native Update `run_takserver_upgrade` ~104491 and `takserver_update` ~101575, RHEL `run_takserver_upgrade_rhel` ~104605, container `run_takserver_upgrade_container` ~104717, two-server `run_takserver_upgrade_two_server` ~105321 (rhel ~105517), 5.8 migrations `run_takserver_58_migration` ~100967, `run_takserver_58_container_migration` ~100591, `run_takserver_58_two_server_migration` ~105097, downgrade guards `_tak_package_downgrade` ~101493, `_tak_cross_minor_downgrade_message` ~101516, rollback `_tak_rollback` ~102708, package pins `takserver_pin_packages` ~16390, `_pgdg_gis_pin_ensure` ~106763, Java `_patch_tak_hardened_java_pin` ~3737 (`_TEMURIN17_FIXED_TAG` ~3709), `_pin_takserver_jvm` ~115908, database image refresh `run_tak_db_refresh` ~31602, CoreConfig heals `_coreconfig_db_tls_converge` ~15027, `_heal_coreconfig_updateinterval_ms` ~89256, `_heal_coreconfig_ldap_connection_pool` ~89313, `_heal_takserver_coreconfig_step8` ~122767, `_startup_heal_coreconfig_owner` ~45863, half-configured heal `_selfheal_takserver_half_configured` ~122545, LE heals `_selfheal_takserver_le_cert` ~45904, `_startup_heal_le_renewal_script` ~122854, `_startup_heal_missing_le_keystore` ~122920, split-DB `_migrate_split_db_tls` ~15520, `_migrate_split_db_keepalives` ~15663, health agent `_deploy_health_agent_to_server_one` ~21345, Federation Hub update `fedhub_update_api` ~35039 and `_fedhub_run_remote_package_install` ~34521.

**NetBird, CoTURN, Remote Assist.** NetBird `_get_netbird_target_images` ~1919, `_heal_netbird_pinned_image` ~67887, `_netbird_sync_compose_image_tags` ~67638, `_heal_netbird_orphaned_store` ~67771, `_netbird_finalize_account_store` ~68010, `_heal_netbird_ca_trust` ~68424, Update `netbird_control_api` ~16939, deploy `_run_netbird_deploy` ~68461; CoTURN `COTURN_IMAGE` ~20431, `_coturn_converge_override_locked` ~20604, `_startup_converge_coturn` ~20661; Remote Assist `_remote_assist_checkout_release` ~19231, `_run_remote_assist_update` ~20287 (`REMOTE_ASSIST_SHA` ~1850).

**MediaMTX, TVR, WebODM, Node-RED, ATLAS.** MediaMTX `mediamtx_recovery` ~51218, `mediamtx_deploy_api` ~51137, overlay `_startup_converge_mediamtx_overlay` ~118468, converges `_startup_converge_mediamtx_*` ~117979 to 119718, `MEDIAMTX_EDITOR_SHA` ~1935; TVR `modules/tvr.py` `_run_update` ~654, `checkout_pin` ~325; WebODM `WEBODM_IMAGES` ~63863, `_webodm_pin_images` ~63877, `_run_webodm_update` ~64865, `_run_webodm_deploy` ~64464, remote ~64255; Node-RED `NODERED_IMAGE` ~69573, `_auto_nodered` ~126480, `_auto_nodered_flows` ~127029, `_auto_nodered_settings` ~126901, `nodered/deploy.sh`; ATLAS `modules/atlas.py` `_run_update` ~5828, `deploy` ~3994, `refresh_database` ~6177, `_atlas_signed_identity_converge` ~68750.

**Caddy, fail2ban, firewall, mail, Guard Dog.** Caddy `_caddy_lift_to_secure_floor` ~42505, `caddy_update` ~38197, `_caddy_apt_repo_heal` ~37901, `generate_caddyfile` ~44138 and the `_startup_caddy_*_converge` group ~42753 to 43519; fail2ban `_f2b_selfheal_*` ~23868 to 25430, `_startup_f2b_ufw_lock_switch` ~128143; firewall `_ufw_ipv4_parity_heal` ~23719, remote firewall converges ~118319; Email Relay `modules/emailrelay.py` `deploy` ~379, `sync_root_alias` ~198; Guard Dog `_auto_update_guarddog` ~116283, `_gd_install_script` ~1024, scripts under `scripts/guarddog`.

**Not covered in this first pass:** the Cesium rehome (`_startup_rehome_cesium` ~117694, low), the Simulator panel, the ETL catalog publish tools, and remote-host code beyond what the rows above name. Each helper read its rows once; the rows marked "Verified" in the bug issues are the ones re-read by hand.
