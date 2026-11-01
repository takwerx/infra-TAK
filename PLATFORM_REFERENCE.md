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
