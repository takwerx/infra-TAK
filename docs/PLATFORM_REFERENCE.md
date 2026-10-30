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

**What infra-TAK does:** the TAK Server page shows a warning listing existing Authentik users whose names contain `/ \ , + " < > ;` (`/api/takserver/ldap-username-check`). Fix is to rename the user and enroll again. Reported upstream to TAK Portal as ValleyTacticalSolutions/TAK-Portal#82.

## TAK Portal: usernames

- TAK Portal creates the user in Authentik as typed. It does not reject or warn about `/ \ , + " < > ;` (reported in TAK Portal#82). The name TAK Portal accepts is the name TAK Server later puts into an LDAP lookup, so see the table above.

## Authentik LDAP outpost: new users appear late

**Source (official):** https://docs.goauthentik.io/add-secure-apps/providers/ldap/. Search mode "Cached" keeps users and groups in the outpost's memory and refreshes them periodically, so it "can return stale data". The docs do not say how often.

- infra-TAK's blueprint sets `search_mode: cached` and `bind_mode: cached` (fleet constant).
- ✅ verified 2026-10-30 on test12 (Authentik 2026.8.5): a user created in Authentik can bind straight away, but the outpost's search returns no entry or no groups for it, with the log line `User with pk is not in local cache`. In two clean runs the user and groups showed up on their own after about 2 minutes and about 4 minutes 20 seconds. No restart was needed.
- A restart of `authentik-ldap-1` forces the refresh but drops LDAP for 10-30 seconds, so infra-TAK does not do it for this.
