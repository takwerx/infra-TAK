# infra-TAK platform reference

What infra-TAK depends on that it does not control: other products, package repositories, distros and cloud APIs. Each entry says what the outside thing does, where the official statement of it lives, and how sure we are.

Read the entry before you change code that talks to the thing. Platforms often fail vaguely on purpose (a generic login or certificate error can be a deliberate security choice), so read the contract before reasoning from the symptom. [ARCHITECTURE.md](ARCHITECTURE.md) covers our own code; this file covers everything outside it.

**How sure we are**

| Mark | Meaning |
|---|---|
| ✅ verified `<date>`, `<box>` | We reproduced or observed it on a real machine and wrote down which. |
| 👁 observed `<date>` | Seen in a field report or a test run. Not reproduced since. |
| 📖 documented | Stated by the official source. Not proven on one of our machines. |

When the official docs and what we saw disagree, keep both and say so. Never delete an observation. No passwords, tokens, customer data or private box addresses in this file.

---

## Ubuntu, apt and Ubuntu Pro

Official: [Ubuntu Pro client](https://documentation.ubuntu.com/pro-client/), [apt_preferences(5)](https://manpages.ubuntu.com/manpages/noble/man5/apt_preferences.5.html)

- **Stock Ubuntu 24.04 cloud images carry Ubuntu Pro pin files even when Pro is off.** `ubuntu-pro-client` writes `/etc/apt/preferences.d/ubuntu-pro-esm-apps` and `ubuntu-pro-esm-infra` (priority 510) whether or not the machine is attached. ✅ verified 2026-10-30, Azure Ubuntu 24.04.
  - Do not judge "is Pro on" from those files. Ask the client: `pro status --format json` and read `attached`. A `+esm` suffix on a version in apt output also means Pro is on. `_ubuntu_pro_security_covered()` in `app.py` does it this way and treats any doubt as "not covered".
- **A priority of 510 beats the default 500.** apt picks the highest-priority candidate before it looks at version numbers. On a box with Pro attached, an ESM copy of a package therefore beats a newer PGDG copy of the same package. 📖 apt_preferences(5).
- **PGDG's PostGIS and Ubuntu's ESM GDAL cannot be installed together.** The TAK Server `.deb` pulls PostGIS from PGDG, which links PGDG's own newer GDAL, GEOS and PROJ. With Pro's pin in play apt takes `gdal-data` from ESM and the install stops with `libgdal39 : Depends: gdal-data (>= …pgdg…) but …+esm1 is to be installed`. 👁 observed 2026-10-29 (GH #352); the ESM pin can be modelled without a Pro token in a fresh Ubuntu container with `Pin: release o=Ubuntu` at 510.
  - Our fix pins the GIS packages plus `postgresql-common`, `postgresql-client-common` and `libpq5` to `o=apt.postgresql.org` at 600. 600 is above ESM's 510 and below 1000, so nothing is ever downgraded. It lives in `_PGDG_GIS_PIN_BODY`.
  - A plain box is unaffected: PGDG already wins on version.
- `apt-cache pkgnames libgdal` is a prefix match. It also lists `-dbgsym` and `-dev` packages. Filter with `^libgdal\d+[a-z0-9]*$` when you want the runtime library.
- **One apt repository configured two ways breaks every apt command on the box.** If the same URL appears in two `sources.list.d` files with different `Signed-By` keyrings, apt normalises the URLs, sees a conflict and refuses to read any source. Use one filename and one keyring for PGDG everywhere, and skip adding it when the box already has it. 👁 observed (see the comment above `_PGDG_LIST` in `app.py`).
- The apt codename comes from `/etc/os-release`, not `lsb_release`. A minimal 24.04 image can lack `lsb_release`, and an empty codename writes `apt -pgdg main`, which apt rejects for every source. 👁 observed, v10.3.0.
- To model apt behaviour without a Pro token or a new VM, use a fresh `ubuntu` container and write the pin file by hand.

## PGDG (PostgreSQL package repositories)

Official: [apt](https://wiki.postgresql.org/wiki/Apt), [yum/dnf](https://www.postgresql.org/download/linux/redhat/)

- Debian family: `https://apt.postgresql.org/pub/repos/apt <codename>-pgdg main`, signed by the key at `postgresql.org/media/keys/ACCC4CF8.asc`.
- Rocky/RHEL: install `pgdg-redhat-repo-latest.noarch.rpm` for the right `EL-<major>-<arch>`. The repo paths use the **minor** release (`$releasever_minor`), and PGDG only publishes paths for current minors. On an old Rocky minor (9.3 was tried) `pgdg-common` answers 404 and the install fails. A current image works (9.8 tried). 👁 observed 2026-10-30. Rule for tests: use the newest Rocky 9 image, never an old pinned minor.
- The TAK Server 5.8 upgrade can leave the old PostgreSQL 15 cluster behind. infra-TAK offers to remove it (Guard Dog, v10.2.30). 👁 observed.

## Rocky / RHEL 9 (dnf)

Official: [dnf docs](https://dnf.readthedocs.io/), [RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9)

- Always go through `_pkg_install` / `_pkg_remove` and the firewall seams (`firewalld` here, `ufw` on Ubuntu). See [ARCHITECTURE.md](ARCHITECTURE.md), "The seams".
- The Rocky cloud image on Azure needs marketplace terms accepted by a person. For a throwaway Rocky 9 test, run the official `rockylinux/rockylinux:9` container instead. 👁 observed 2026-10-30.
- A born-non-root console cannot `sudo`; privileged work goes through the broker (`broker/`). Probing such a box as any other user, with the broker shims on `PATH`, answers "service inactive" or "file missing" when the truth is "wrong user".

## TAK Server

Official: TAK Server Configuration Guide and release notes at [tak.gov](https://tak.gov) (account required); [TAK Product Center on GitHub](https://github.com/TAK-Product-Center/Server)

- Ports we rely on: 8089 (streaming, mutual TLS), 8443 (admin/API, mutual TLS), 8446 (certificate enrollment and the username/password web login). 📖
- **Usernames are pasted into an LDAP DN without escaping.** A user whose name contains `/` can log in but receives no groups. A name containing any of `\ , + " < > ;` cannot log in at all. No setting changes this; the user has to be renamed. 👁 observed 2026-10-30 (infra-TAK warns about these names). The vague failure is why this is easy to misread as an Authentik or LDAP bug.
- **CoreConfig `<ldap updateinterval>` is in milliseconds.** The Configuration Guide (5.7 and 5.8) says "Frequency (in milliseconds) at which the server refreshes group memberships from LDAP" and its example is `60000`. infra-TAK wrote `30` for a long time, which expired the cache on every check and sent every lookup live to LDAP. It now writes `TAK_LDAP_UPDATE_INTERVAL_MS = '30000'`. 📖 Configuration Guide 5.7/5.8. ⚠ Disagreement: older private notes describe the value as "30 seconds"; the guide and the code comment are the authority.
- **Channels come from a group cache, not a live lookup.** Login does a live LDAP bind; the channel list comes from the cached user-to-groups map. A user created seconds ago can connect and see no channels until the cache refreshes. Only LDAP groups whose `cn` starts with `tak_` become channels. 👁 observed.
- **A failed LDAP group lookup for a certificate login silently means "no groups".** In TAK Server 5.8, `X509Authenticator` calls `LdapAuthenticator.getGroupInfoBySearch`, which catches every LDAP error, logs it only at DEBUG and returns an empty map. Nothing shows in the normal logs. ✅ verified 2026-10-30, TAK Server 5.8 jar on an Ubuntu dev box (decompiled).
- **After Authentik's server and worker restart and the LDAP outpost is recreated under a running TAK Server, the 8443 side can give fresh certificate logins no groups for minutes.** Measured 75 s to about 5.5 min on a busy box (CloudTAK, Node-RED, ATAK clients connected); it recovers by itself, no TAK restart needed. Connected 8089 clients keep their groups. During the gap TAK sends no LDAP lookup at all for the affected user (packet capture on the outpost port) while it keeps looking up others, and no thread is waiting in LDAP code. A plain outpost recreate, without the server/worker restart, recovered in about 12 s. ✅ verified 2026-10-30, Ubuntu dev box, TAK Server 5.8, Authentik 2026.8.5. Not known: where TAK holds the empty result; it is longer than `updateinterval` (30 s) and was not found in the decompiled classes.
- `x509useGroupCacheRequiresExtKeyUsage="false"` in `<auth>` lets certificates made by `makeCert.sh` (no extended key usage) use channels. 📖 notes, carried from the field.
- Mission API quirks (📖 from our notes, not re-proven): `PUT /Marti/api/missions/{name}/subscription?uid=X` assigns `defaultRole` even to an admin, so follow it with a role `PUT`. `PUT .../contents` needs the UID in the CoT cache first. `PUT .../role` needs the `group` to match the mission's group or TAK answers `FORBIDDEN: Illegal attempt to change Mission groups!`.
- A user named `webadmin` in the flat-file `UserAuthenticationFile.xml` shadows an LDAP user of the same name. Do not create one in Authentik.
- A Java heap that is too small can show up as HTTP 500 on CloudTAK sign-in. 👁 observed.

## Authentik and the LDAP outpost

Official: [docs.goauthentik.io](https://docs.goauthentik.io/), [LDAP provider](https://docs.goauthentik.io/add-secure-apps/providers/ldap/), [configuration](https://docs.goauthentik.io/install-config/configuration/)

- Verify config with Authentik's own command, never by the fact that the process started: `ak dump_config` inside the server container. Environment variables use a **double underscore** between sections (`AUTHENTIK_WEB__WORKERS`, not `AUTHENTIK_WEB_WORKERS`). The single-underscore form was silently ignored for five releases. 📖 configuration docs; 👁 observed April 2026.
- **A new Authentik user is missing from LDAP search for about 2–4 minutes.** Wait. Do not restart `authentik-ldap-1` to "fix" it. 👁 observed 2026-10-30.
- The outpost caches the directory (`bind_mode` and `search_mode` cached), so a group change in Authentik reaches TAK Server after the cache time plus TAK's own refresh. 📖
- TAK Server binds as the service account `adm_ldapservice`. Besides that service account, the `tak_ROLE_ADMIN` group and the `webadmin` user are the only group and user infra-TAK creates itself. Every other `tak_*` group comes from TAK Portal.
- After restarting `authentik-worker`, blueprints have to re-apply before LDAP queries work.
- Two things at once on one box can starve it. A first-time Authentik deploy next to a TAK Server, Node-RED and MediaMTX deploy has produced `127.0.0.1:9090: connection refused` (502) from Caddy. Space deploys out. 👁 observed.

## TAK Portal

Official: [ValleyTacticalSolutions/TAK-Portal](https://github.com/ValleyTacticalSolutions/TAK-Portal) (our `TAKPORTAL_REPO`)

- Its `settings.json` belongs to the operator. infra-TAK writes only the keys in `TAKPORTAL_AUTHORITATIVE_KEYS` (`AUTHENTIK_URL`, `AUTHENTIK_TOKEN`, and the email transport keys while Email Relay is configured) and seeds the rest once. One writer: `_takportal_merged_settings_json()` / `_takportal_write_settings_json()`. Never infer ownership from a value. See the hard stop in the project rules.
- **"Deploy To Caddy" can report failure when Caddy reloaded fine.** TAK Portal runs `bash -lc '… ; exit 0'` over SSH. The default `~/.bash_logout` on a stock account runs `clear_console -q`, which fails, so the login shell exits 1 even though the command succeeded. The fix belongs in TAK Portal (do not call `exit` in a login shell). 👁 observed 2026-10-30.
- Upstream versions can lie: the 2.0.15 tag shipped a `package.json` whose `version` still said 2.0.14 (the real number was in `beta-version`). Read the field the release actually bumps. 👁 observed 2026-10-21 (GH #214).

## CloudTAK

Official: [dfpc-coe/CloudTAK](https://github.com/dfpc-coe/CloudTAK), [dfpc-coe/node-tak](https://github.com/dfpc-coe/node-tak)

- **After a UI fix, the browser can still show the old bundle.** CloudTAK's service worker caches it. Hard-refresh before deciding a fix failed. 👁 observed.
- Plugins reach CloudTAK only when the plugin install action in the console copies their source in and CloudTAK's API is rebuilt. Editing a plugin repo alone changes nothing. Plugins are a catalog entry (`CLOUDTAK_PLUGINS`) pointing at a repo with `plugin/` and optionally `server/`.
- Cert login needs the TAK Server certificate in the browser's trust store. API calls to TAK Server use `TAKAPI.init()` with `APIAuthCertificate`. 📖 node-tak.
- `docker-compose.custom.yml` is the supported place for the operator's own CloudTAK services.
- **The `tiles` container loads every basemap from the API at `API_URL`** (`tasks/pmtiles/lib/basemap.ts`: `process.env.API_URL || 'http://localhost:5001'`), so a wrong `API_URL` makes every tile 500. 13.117.0's compose never passed it to `tiles`; 13.117.1 passes `API_URL=${API_URL}` from `.env`. infra-TAK writes that `.env` value as the public address (`https://map.<domain>`), or `http://172.20.0.1:5000` on an install with no domain. ✅ verified 2026-11-01 on test12 (Ubuntu 22.04, 13.117.1): with no override, tiles are 200 because the container can reach the public name; the same container cannot reach the Docker gateway on port 5000, because the API is published on `127.0.0.1:5000` only. So an install with no domain still needs infra-TAK's `API_URL: "http://api:5000"` override for `tiles`. Check after any update: fetch one tile from `/tiles/basemap/<id>/tiles/1/0/0?token=...` on the tiles container (200, not 500).

- **Video: how a stream gets from MediaMTX to CloudTAK's player, and what "Failed to generate proxy stream" means.** Read from CloudTAK's API source (`api/stateless/lib/control/video-service.ts`, `routes/profile-videos.ts`, `routes/video-lease.ts`, 13.116.0) 📖. Everything marked ✅ was also observed against 13.117.1.
  - A stream added to the video wall (`POST /api/profile/video {url, name}`) or opened from a marker (`POST /api/video/lease {proxy: url}`) becomes a **proxy lease**. CloudTAK's API then calls its media server (the `media::url` setting, always port **9997**, a JWT with `internal` and `access: media`) with `POST /path {name, source: url}` for `rtsp`, `rtmp` and `srt` sources; an `http(s)` source is fetched once to check it answers. ✅ verified 2026-11-03, test6 (Ubuntu 24.04, CloudTAK 13.117.1).
  - **Any failure in that block reaches the user as the same words, "Failed to generate proxy stream" (HTTP 500)**: a refused or timed-out call to port 9997, an address blocked by `isSafeUrl`, anything that is not one of CloudTAK's own errors. The words do not say which; the API container's log does. ✅ verified 2026-11-03, test6: pointing `video.<name>` at an unreachable address inside the API container (`/etc/hosts`) gives exactly this 500 on both routes, and removing the line brings video back. Seen for real on a relay/home-network box where `video.<name>:9997` could not be reached from inside the box (ops #471). 👁
  - What the player is handed is `protocols.hls.url` from `GET /api/video/lease/<id>/metadata`: `<media url>:9997/stream/<lease path>/index.m3u8` (plain, or with `{{username}}:{{password}}` placeholders on a secure lease). The lease route itself (`GET /api/video/lease/<id>`) carries no stream addresses. ✅ verified 2026-11-03, test6.
  - A working stream is proven by decoded frames from that HLS address, not by an API answer. On test6 (CloudTAK 13.117.1, media-infra v9.12.1) a stream published to MediaMTX over SRT with H.264 plus a KLV data track played as HLS whose segments decoded with both the video and the KLV track present. ✅ verified 2026-11-03, test6. The `video-check` tool in `takwerx/ops` (`fresh-install/`) does exactly this.
  - A fleet-box CloudTAK API token can be signed inside the API container with its own `SigningSecret`: payload `{access: 'admin', email: <an existing profile with a TAK certificate>}`; `access: 'user'` is refused by admin-only routes (`/api/video/service`: "User must be a System Administrator"). ✅ verified 2026-11-03, test6.
- **CloudTAK's first admin is made by its own first-time setup call, and it will not configure without one.** `PATCH /api/server` on an unconfigured CloudTAK answers 400 "Initial configuration must include valid TAK Username & Password to set System Administrator" unless `username` and `password` are in the body; with them it asks TAK Server for that user's certificate and creates the profile with `system_admin: true` before it saves the server. Sign-in is refused ("Server has not been configured") until the server is saved, and a user who signs in later gets `system_admin` false. So "set up and signed in with no admin" can only come from an admin that was later disabled or taken off, or from signing in as a different user than the one setup named. Read from CloudTAK source (`api/stateless/routes/server.ts`, `login.ts`, `lib/provider.ts`) 📖; the guard text is in the running 13.121.0 API container on test12 ✅ verified 2026-11-09, test12 (read only, no live call on an unconfigured CloudTAK). Disagrees with nothing in the official docs; the docs do not describe it.
- **Making an existing user a CloudTAK admin:** `PATCH /api/user/<username>` with `{"system_admin": true}` and an admin token (`access: admin`). The console's "Make admin" button uses it. ✅ verified 2026-11-09, test6 (CloudTAK 13.121.0, branch claude/issue-588): the admin flag was removed from the only admin in the database, the button promoted that user, the page read it back, and a second call was refused by the console because an admin existed.

## MediaMTX

Official: [bluenviron/mediamtx](https://github.com/bluenviron/mediamtx), [mediamtx.org](https://mediamtx.org/)

- We run bluenviron's binary and our own web editor ([takwerx/mediamtx-installer](https://github.com/takwerx/mediamtx-installer)) as separate services. After the editor is patched, restart `mediamtx-webeditor` as well as MediaMTX itself. 👁 observed.
- The editor decides access from LDAP groups: `vid_admin` gets the config editor, `vid_private` and `vid_public` get the streams page only.
- A MediaMTX unit written for Caddy's group fails on a box without Caddy with `216/GROUP` and crash-loops. 👁 observed (v10.3.3).

## Caddy

Official: [caddyserver.com/docs](https://caddyserver.com/docs/), [forward_auth](https://caddyserver.com/docs/caddyfile/directives/forward_auth), [reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)

- Reload (`systemctl reload caddy`) to apply a rewritten Caddyfile without dropping connections. Check a file with `caddy adapt` before reloading. 📖
- `forward_auth` is how protected sites ask Authentik first. Our notes say it must come before `reverse_proxy` in a site block; confirm the ordering against the Caddy directive-order table before relying on it. Not re-proven here.

## Node-RED

Official: [nodered.org/docs](https://nodered.org/docs)

- Function nodes cannot `require()` by default; declare modules in the node's `libs`.
- Never `docker cp` a `flows.json` into a running container (it can persist an empty global context). `nodered/deploy.sh` stops the container first. Confirm `contextStorage` is `localfilesystem` in the file the container actually reads.

## Docker

Official: [docs.docker.com](https://docs.docker.com/)

- Confirm what a container really runs with `docker inspect` (image digest, mounts, env, compose working directory label `com.docker.compose.project.working_dir`), not with the compose file. Do not guess where Authentik's compose project lives.
- Container logs fill disks; Guard Dog caps them.

## Shell scripts and systemd units that are rewritten while they run

Official: [bash manual, shell scripts](https://www.gnu.org/software/bash/manual/html_node/Shell-Scripts.html), [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)

- **bash reads a script file as it runs, not all at once.** If the file is rewritten in place (open with truncate, then write), a running script carries on from its old byte offset in the new content and ends with a syntax error or a random command, exit 2. Writing a temp file in the same directory and renaming it over the old one is safe: the running script keeps the old file. The console does this for `/opt/tak-guarddog/` and `/etc/systemd/system/` (ops #666). ✅ verified 2026-11-11, `tak-post-start.service` on an Ubuntu 22.04 dev box: console restarted while the unit ran, in-place rewrite gave `Result=exit-code`, `ExecMainStatus=2` and no "Boot sequence complete"; with the rename write the unit ended `Result=success`.
- **A rename is not always right.** It breaks a single-file bind mount into a container (the container keeps the old file) and a log file that a running process holds open. Files like those stay written in place. ⚠ not re-tested for ops #666; the bind-mount case was seen with the NetBird CA bundle (ops #433).

## Node.js in the module images

Official: [nodejs.org/en/about/previous-releases](https://nodejs.org/en/about/previous-releases)

- TAK Portal, CloudTAK, Node-RED and Remote Assist each ship their own Node. A module can be on its latest release and still run a vulnerable Node. The console checks the Node each one actually runs and flags it (v10.3.2). Update rebuilds on the newest Node 22.

## Test fleet and cloud CLIs (for people who test)

Official: [Azure CLI `az vm auto-shutdown`](https://learn.microsoft.com/cli/azure/vm/auto-shutdown), [AWS CLI](https://docs.aws.amazon.com/cli/latest/)

These are facts about the cloud tools, not about infra-TAK. 👁 observed 2026-10-30 unless noted.

- Every `aws` command needs `--profile <name>`. Without it AWS sees no login and answers with something that looks like a permission error.
- Azure `az vm auto-shutdown` fails with `InvalidScheduleLocation` when the VM is not in the resource group's region. Create the schedule yourself with `az resource create --resource-type Microsoft.DevTestLab/schedules -l <VM region>`.
- VM sizes come and go by region: `Standard_B2s` was `SkuNotAvailable` in eastus2 while `Standard_D2s_v4` worked in westus2. Check before you promise a box.
- A new Azure VM needs an auto-shutdown and `owner` and `expires` tags at creation.
- `az vm run-command invoke` returns only the last ~4 KB of output. Write to a file on the VM and read it in pieces.
- `az vm create` can fail with "The content for this response was already consumed". Re-run it with `--debug`.
- Mixed-up identities waste hours: an SSH alias, the OS hostname and the name people use for a box can all differ. Identify a box by alias plus address, and by the `fqdn` in its `settings.json`.

---

## Virtual machine CPU level (TAK Portal and CloudTAK)

Official: [sharp, installation](https://sharp.pixelplumbing.com/install) (the image library both products load)

- **TAK Portal and CloudTAK need an x86-64-v2 CPU or newer on Intel/AMD boxes.** Both use the `sharp` module, whose prebuilt Linux x64 binaries need those CPU features. Without them TAK Portal restarts in a loop with "Unsupported CPU: Prebuilt binaries for Linux x64 require v2 microarchitecture", and the CloudTAK build stops with "Could not load the sharp module". 👁 observed 2026-10-31 (reporter on TrueNAS, ops #341).
  - The usual cause is a VM set to a generic or "basic" CPU type (TrueNAS, KVM and Proxmox defaults), which hides the features the real CPU has. The fix is in the hypervisor: set the VM's CPU mode to host passthrough (or host model). No reinstall; the reporter confirmed it fixed both. 👁 observed 2026-10-31.
  - The flags the v2 level adds that we check: `popcnt`, `sse4_1`, `sse4_2` (in `/proc/cpuinfo`). ARM boxes are not affected.
  - Official docs and what we saw differ on detail: the sharp install page lists only "CPU with SSE4.2" for Linux x64 and does not mention x86-64-v2 or POPCNT, while the error text above names v2. We check the whole v2 set to be safe. The error text was seen; whether sharp enforces every v2 flag was not tested.

## Adding to this file

1. Put the fact under the product it belongs to. If the product has no section, add one with its official source.
2. Say what the outside thing does, not what we did about it. Our own fixes belong in the changelog.
3. Mark it ✅, 👁 or 📖. Use ✅ only when you proved it on a real box, and name the box type and the date.
4. If you found a disagreement with the official docs, write both sides.
5. Do not put credentials, customer names or private addresses here. The repo is public.
