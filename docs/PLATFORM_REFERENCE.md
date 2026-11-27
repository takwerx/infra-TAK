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

## TAK Server Docker bundle: database volume layout and the update order (ops #1326)

**Source (official):** the TAK Server docker bundle itself: `docker/Dockerfile.hardened-takserver-db` (5.8: `postgresql18-server`, `VOLUME /var/lib/postgresql/data`, `ENV PGDATA=/var/lib/postgresql/data`) and the older `docker/Dockerfile.takserver-db` (`FROM postgres:15.1`, cluster under `/var/lib/postgresql/<N>/data`).

- ✅ verified 2026-11-26 on fresh-install ubuntu-22.04-arm64 (TAK Server 5.8 R104 and R105 hardened bundles, non-root console): the `takserver_pgsql` volume holds `PG_VERSION` (value 18) at the volume ROOT, read with `docker run --rm --user 0 -v takserver_pgsql:/from --entrypoint sh takserver -c 'cat /from/PG_VERSION'` through the console's broker. A 5.7-era image mounts the volume one level higher and looks for `<volume>/15/data`, so it finds nothing in that volume and starts an EMPTY cluster. The update reads the volume in the layout of the NEW zip and refuses when the data is not there.
- ✅ verified 2026-11-26 on the same box: the new images build while the old containers keep running; `docker tag` of the old image under a spare tag and a retag back put the old version in place again after a failed start (failed on purpose by holding host port 8446).
- ✅ verified 2026-11-26: `pg_dump` of the `cot` database as `martiuser` refuses (`permission denied for table`) when a table in it belongs to `postgres`; the update treats a failed dump as a stop before any change.
- Not verified on a box: the 5.7 layout (`<volume>/15/data`): no 5.7 Docker bundle is in our files folder. It is read from the Dockerfile only.

## CloudTAK: documentation site

**Source (official):** https://docs.cloudtak.io/ ("Get started with CloudTAK | CloudTAK Documentation"). The same site holds the integrations (ETL) pages at https://docs.cloudtak.io/integrations/, which the CloudTAK page already links.

- infra-TAK links the docs home page from the header of the CloudTAK page (`templates/cloudtak.html`, `id="ct-docs-link"`), opening in a new tab.
- ✅ verified 2026-11-20 from the Studio: both URLs return HTTP 200 with the titles above. Not checked: whether every page of the site stays at the same path in later CloudTAK releases.
