# Actions reference (Sync, Update Config, Resync)

Back to the [README](../README.md).

Each page has buttons that do specific things. Here's what they do and when to use them.

## TAK Server Page

| Button | What it does | When to use it |
|--------|-------------|----------------|
| **Update Config** | Regenerates Caddyfile, reloads Caddy, installs Let's Encrypt cert on 8446, restarts TAK Server | After changing the TAK Server domain/FQDN in Caddy settings |
| **Connect TAK Server to LDAP** | Full LDAP setup: repairs Authentik blueprint, ensures service account + webadmin, writes LDAP auth block into CoreConfig.xml (without flat-file), restarts TAK Server | After deploying Authentik (if TAK Server was deployed first), or if LDAP auth stops working |
| **Resync LDAP to TAK Server** | Same as Connect LDAP — full re-run of the LDAP fix flow | If QR registration fails, if 8446 login stops working, after pulling console updates |
| **Sync webadmin to Authentik** | Pushes the 8446 webadmin password from settings into Authentik (no TAK Server restart) | After changing the webadmin password |
| **Disable/Enable flat-file auth** | Adds or removes `UserAuthenticationFile.xml` from the CoreConfig auth block, restarts TAK Server | When you want LDAP-only auth (disable) or need local password fallback (enable) |
| **Set JVM Heap** | Writes `-Xms`/`-Xmx` to `/opt/tak/setenv.sh`, restarts TAK Server | TAK Server running out of memory (OutOfMemoryError in logs) |

## TAK Portal Page

| Button | What it does | When to use it |
|--------|-------------|----------------|
| **Sync TAK Server to TAK Portal** | Forces TAK Portal to re-read the TAK Server connection (IP, certs, API URL) | If TAK Portal dashboard doesn't show TAK Server uptime/disk usage |
| **Update Config** | Rewrites TAK Portal's `settings.json` with current Authentik + TAK Server URLs, restarts the container | After changing FQDN, after Authentik redeploy, if TAK Portal can't reach TAK Server or Authentik |
| **Sync TAK Server CA** | Copies the current `tak-ca.pem` into the TAK Portal container | After CA rotation — TAK Portal needs the new CA to generate valid client certs |

## Authentik Page

| Button | What it does | When to use it |
|--------|-------------|----------------|
| **Update Config & Reconnect** | Patches docker-compose.yml (PostgreSQL tuning, blueprint mounts), ensures all forward auth apps exist (infra-TAK, TAK Portal, Node-RED, etc.), repairs embedded outpost, updates LDAP CoreConfig, reloads Caddy | After pulling console updates, if forward auth breaks, if apps disappear from Authentik, if LDAP stops working |
| **Fix LDAP Token** | Re-fetches the LDAP outpost token from Authentik API and injects it into docker-compose.yml, restarts the LDAP container | If LDAP container shows "unhealthy" or "403 Forbidden" in logs |

## Email Relay Page

| Button | What it does | When to use it |
|--------|-------------|----------------|
| **Switch Provider** | Reconfigures Postfix with new SMTP credentials/host, restarts Postfix | Changing email provider or From address |
| **Configure Authentik** | Pushes relay settings (localhost:25, From address) into Authentik so password recovery emails work | After deploying or switching Email Relay provider |

## CloudTAK: keeping your own source patches (pre-build hooks)

CloudTAK **Update** checks out a clean release, so any edit you made to `~/CloudTAK`'s source is wiped before the rebuild. To have it put back every time, put a script in `.config/cloudtak-hooks/pre-build.d/` inside the infra-TAK folder. Executable files there run in name order (`10-…`, `20-…`) right before every CloudTAK build: on Update, on a plugin install/update/remove, and on the tree a failed update rolls back to. They run as the console user, with `~/CloudTAK` as the working directory and `INFRATAK_HOOK_PHASE` (`update` / `plugin` / `revert`), `INFRATAK_CLOUDTAK_DIR`, `INFRATAK_CLOUDTAK_TAG` and `INFRATAK_CLOUDTAK_PREV_SHA` set. If a hook exits non-zero or runs over 5 minutes, the build does not start: the update rolls back and CloudTAK keeps running, and the log names the hook and shows its output. Hooks must be safe to run twice and should fail loudly when the code they patch has moved. The folders and scripts must be owned by the console user and not writable by anyone else, or nothing runs; `chmod -x` a script to turn it off. On a non-root console, anything a hook runs or reads (a script in another user's home, a patch file) must be readable by the console user too, or the hook fails with `Permission denied`. Hooks run only for a CloudTAK on the same server as the console, not for a remote CloudTAK host or a fresh Deploy.

## Caddy: your own lines inside a generated site

infra-TAK rewrites `/etc/caddy/Caddyfile` on every deploy, domain change and Update, so a line you add inside a generated site block is lost. New sites go below the `# --- User-added blocks (do not remove) ---` line at the bottom. For lines that must sit inside a generated site (an extra route on the CloudTAK map host, for example), use the include folders, which infra-TAK never writes:

- `/etc/caddy/sites.d/<host>/*.caddy` is imported as the first line of that host's site block. `<host>` is the site address exactly as the Caddyfile shows it, e.g. `/etc/caddy/sites.d/map.example.com/10-print.caddy`.
- `/etc/caddy/snippets.d/*.caddy` is imported at the top of the file, right after the global options, for named snippets you use from a site file.

Only files ending in `.caddy` are read, so a `.bak` copy is ignored. Files must be readable by caddy (`0644`). Press **Reload** on the Caddy page to apply them; the page lists the files in use. If an include makes the Caddyfile invalid, infra-TAK writes it without any includes so every site keeps working, and the Caddy page names the files and Caddy's error. Fix the file and press **Reload** again.

## General Rules

- **Deploy order matters:** Caddy → Authentik → Email Relay → TAK Server → TAK Portal → everything else
- **After pulling console updates:** Hit "Update Config" on Authentik, then optionally on TAK Server if you changed FQDN
- **If TAK Portal can't reach TAK Server:** Hit "Sync TAK Server to TAK Portal" on the TAK Portal page
- **If LDAP auth breaks:** Hit "Connect TAK Server to LDAP" on the TAK Server page
- **If forward auth breaks (502/blank on FQDN URLs):** Hit "Update Config" on the Authentik page
- **After CA rotation:** Hit "Sync TAK Server CA" on the TAK Portal page, then have users re-enroll
