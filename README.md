# infra-TAK

Team Awareness Kit Infrastructure Management Platform.

One clone. One password. One URL. Manage everything from your browser.

**Latest release: v0.9.17-alpha** — **AUTHENTIK REDIS SELF-HEAL + CADDY UPDATE FIX.** Drop-in update — Update Now is the only step. v0.9.17 fixes two issues found during v0.9.16 follow-up: (1) Installs deployed before Redis was part of the Authentik compose template were missing the `redis:` service — the worker burned 40–65% CPU retrying `localhost:6379` on every task cycle. `_ensure_authentik_compose_patches()` now detects and injects Redis automatically on Update Now; idempotent no-op on installs that already have it. (2) The Caddy Update button (v0.9.16) issued `systemctl reload caddy` after the apt upgrade — wrong for a binary swap and could hang indefinitely mid-ACME-challenge, causing a systemd kill loop ([issue #25](https://github.com/takwerx/infra-TAK/issues/25)). Changed to `systemctl restart`. See **[docs/RELEASE-v0.9.17-alpha.md](docs/RELEASE-v0.9.17-alpha.md)** for the full notes. Prior releases: [v0.9.16](docs/RELEASE-v0.9.16-alpha.md) (Authentik worker CPU hotfix — stale Local Docker service connection; Caddy update button + Authentik update spinner), [v0.9.15](docs/RELEASE-v0.9.15-alpha.md) (TAK Portal admin-account guardrail — `akadmin`/`webadmin` hidden + action-locked), [v0.9.14](docs/RELEASE-v0.9.14-alpha.md) (Authentik admin recovery hotfix — status-read ak-shell fallback so the panel works when the bootstrap token is 403-locked), [v0.9.13](docs/RELEASE-v0.9.13-alpha.md) (Authentik admin recovery — initial feature; superseded by v0.9.14 if you hit the 403 read-path bug), [v0.9.12](docs/RELEASE-v0.9.12-alpha.md) (cyber security hardening — port-exposure lockdown + post-auth route fixes + ReputationPolicy `negate=True` fix; **important if you haven't updated past v0.9.11 yet**), [v0.9.11](docs/RELEASE-v0.9.11-alpha.md) (security hotfix — CloudTAK PG_MEM/PGMiner; **read this if you haven't updated past v0.9.10 yet**), [v0.9.10](docs/RELEASE-v0.9.10-alpha.md), [v0.9.9](docs/RELEASE-v0.9.9-alpha.md), [v0.9.8](docs/RELEASE-v0.9.8-alpha.md), [v0.9.7](docs/RELEASE-v0.9.7-alpha.md), [v0.9.6](docs/RELEASE-v0.9.6-alpha.md), [v0.9.5](docs/RELEASE-v0.9.5-alpha.md), [v0.9.4](docs/RELEASE-v0.9.4-alpha.md), [v0.9.3](docs/RELEASE-v0.9.3-alpha.md), [v0.9.2](docs/RELEASE-v0.9.2-alpha.md), [v0.9.1](docs/RELEASE-v0.9.1-alpha.md), [v0.9.0](docs/RELEASE-v0.9.0-alpha.md) — older releases on the [GitHub Releases tab](https://github.com/takwerx/infra-TAK/releases).

**Something broken?** Wrong sidebar version, **Update Now** error, merge/rebase/tag-clobber messages, or you are not sure the VPS ever pulled the real repo → go to **[Universal recovery (SSH)](#universal-recovery-ssh)** and run the one block there. **Point people at that section**; it is the single source of truth.

**Goal: universal installer.** Currently supported platform: **Ubuntu 22.04 LTS**.

## Universal recovery (SSH)

Use this on the **VPS** when anything below is true:

- **Update Now** failed (including **`would clobber existing tag`**, merge/rebase errors, or a vague git error).
- The sidebar **VERSION** does not match the **Latest release** line at the top of this README (e.g. stuck on **v0.2.4** while the README says **v0.4.5-alpha**).
- You are unsure whether **`git remote -v`** points at **`github.com/takwerx/infra-TAK`** (forks, typos, and old mirrors leave **`origin/main`** years behind — **`git fetch origin`** is not safe until **`origin` is fixed**).

This pulls **`main` from the official repo URL** (same as **Quick Start**), checks **`VERSION`**, restarts the service. Your **`.config/`** is not touched.

```bash
cd $(grep -oP 'WorkingDirectory=\K.*' /etc/systemd/system/takwerx-console.service)
git fetch https://github.com/takwerx/infra-TAK.git main
git checkout --force -B main FETCH_HEAD
grep '^VERSION' app.py
sudo systemctl restart takwerx-console
```

**Check:** The **`grep`** line should show **`VERSION = "…"`** matching the current **Latest release** at the top (without the **`v`**, e.g. **`0.6.2-alpha`**). If it still shows an old number, you are in the wrong directory (compare with **`grep WorkingDirectory /etc/systemd/system/takwerx-console.service`**) or the fetch failed (network).

**Fix `origin` once (recommended):** so future **`git fetch origin`** hits upstream:

```bash
git remote set-url origin https://github.com/takwerx/infra-TAK.git
```

**No `grep -oP`?** Run **`grep WorkingDirectory /etc/systemd/system/takwerx-console.service`**, **`cd`** to that path, then run the four lines starting with **`git fetch https://github.com/...`** (skip the **`cd`** line).

**Shallow / single-branch clone** (`fetch` errors): [docs/PULL-AND-RESTART.md](docs/PULL-AND-RESTART.md).

**After the console is up:** If **Guard Dog** is installed, open **Guard Dog** and click **↻ Update Guard Dog** once (see **Guard Dog** note under **Quick Start**).

**Why:** Older builds used **`git pull --rebase`** or bulk **`git fetch --tags`**, which break on many field installs. Current **Update Now** (v0.4.1+) is safer, but recovery over SSH must **not** trust a wrong **`origin`** — always use the **`https://github.com/takwerx/infra-TAK.git`** fetch above.

## What Is This?

A unified web console for deploying and managing TAK ecosystem infrastructure:

- **TAK Server** — Upload your .deb, configure, deploy, manage CoreConfig — all from the browser
- **Federation Hub** — Deploy and manage a TAK Server Federation Hub on this machine or a remote VPS, with Authentik SSO, certificate management, and Guard Dog monitoring
- **Authentik** — Identity provider with automated LDAP configuration for TAK Server auth
- **TAK Portal** — User and certificate management portal with auto-configured Authentik + TAK Server integration
- **Caddy SSL** — Let's Encrypt certificates and reverse proxy management
- **CloudTAK** — Browser-based TAK client
- **MediaMTX** — Video streaming server for real-time feeds
- **Node-RED** — Flow-based automation engine, protected behind Authentik forward auth
- **Email Relay** — Outbound email for notifications and alerts
- **Guard Dog** — TAK Server health monitoring and auto-recovery (port 8089, processes, OOM, PostgreSQL, CoT DB size, disk, disk I/O performance, certificates; optional monitors for Authentik, Node-RED, MediaMTX, CloudTAK, Federation Hub)

No more SSH. No more editing XML by hand. No more running scripts and hoping.

## Quick Start

```bash
git clone --depth 1 https://github.com/takwerx/infra-TAK.git
cd infra-TAK
sudo ./start.sh
```

**First boot / automatic updates:** On a new Ubuntu VPS, **`apt`** may run right after SSH is available. **`systemctl status unattended-upgrades`** often shows **active (running)** for **`unattended-upgrade-shutdown`** — that idle process is **normal** and is **not** blocking installs. If **`apt-get`** still reports **“Could not get lock”**, wait until **`sudo fuser /var/lib/dpkg/lock-frontend`** shows nothing, then run **`sudo ./start.sh`** again. **`start.sh`** waits for **real** apt/dpkg activity and for **dpkg/apt lock files** before installing packages.

**Branches:** Default clone uses **main** (stable; tagged releases). For latest features and fixes before they're merged to main, use the **dev** branch: `git clone --depth 1 -b dev https://github.com/takwerx/infra-TAK.git`. The README and changelog here reflect main; dev may include remote deployment, UI tweaks, and fixes not yet in a release.

The script will:
1. Detect your OS (**Ubuntu 22.04 only** for now; goal is a universal installer)
2. Wait if automatic updates hold **apt/dpkg**, then install Python dependencies
3. Ask you to set an admin password
4. Start the web console

Then open your browser to the URL shown and log in.

**Updating:** After `git pull` or **Update Now**, restart the console with `sudo systemctl restart takwerx-console`. Your password and config live in the install directory's `.config/`. If you run `start.sh` from a different clone or path, the service keeps using the original install directory so your password continues to work. **Node-RED / Configurator code** (`nodered/`): after pulling **dev** on the VPS, also run **`bash nodered/deploy.sh`** from that install directory (see **[docs/PULL-AND-RESTART.md](docs/PULL-AND-RESTART.md)**).

**Guard Dog — automatic since v0.4.7-alpha:** Guard Dog scripts are automatically re-deployed when the console detects a version change. No manual button press needed after upgrading. The button still exists as a fallback if you change alert email or server nickname. Set **Notifications** → alert email and use **Send test email** to verify. Details: [docs/GUARDDOG.md](docs/GUARDDOG.md).

**Testing Update Now before you ship a release:** Maintainers should follow [docs/TESTING-UPDATES.md](docs/TESTING-UPDATES.md) on a test VPS (fake low `VERSION`, click **Update Now**, then restore). Pushing a Git **tag** is what shows customers “Update Available”; test the button before pushing the tag.

**Upgrading from v0.1.x to v0.2.0:** v0.2.0 switches from Flask dev server to gunicorn (production server). The upgrade is automatic — just `git pull` and restart. On first restart, the console installs gunicorn, rewrites the systemd service, and starts the production server transparently. No manual steps needed.

**Password not working after update?** Use the **backdoor**: **https://&lt;VPS_IP&gt;:5001**. If login spins or fails, on the server run (from the directory where you do `git pull`, e.g. `/home/takwerx/infra-TAK`): **`sudo ./fix-console-after-pull.sh`** — it pins the config path in the systemd unit and prompts you to set a new password so you can log in again. Alternatively run `sudo ./reset-console-password.sh` from that same directory. After pulling, open the Caddy module and re-save your domain once so the Caddyfile (login bypass) is applied.

## Recovery / backdoor (when Authentik or Caddy is broken)

Git / version / **Update Now** issues: use **[Universal recovery (SSH)](#universal-recovery-ssh)** above, not this section.

If Authentik or Caddy is down and you can't reach **https://infratak.yourdomain.com**:

- **Backdoor:** Open **https://&lt;VPS_IP&gt;:5001** in your browser (use the server's real IP, not the domain). Log in with the **console password** you set when you ran `start.sh`. That path skips Caddy and Authentik, so you can get back into the console and fix things.

The console password is stored as a **hash** in the install directory at `.config/auth.json` (e.g. `/home/takwerx/infra-TAK/.config/auth.json`). You **cannot** recover the plaintext password from that file. If you forget it:

```bash
cd /home/takwerx/infra-TAK   # or your install path
sudo ./reset-console-password.sh
```

Enter a new password twice; the script updates `.config/auth.json` and restarts the console. Then use **https://&lt;VPS_IP&gt;:5001** with the new password. Store the console password somewhere safe (e.g. password manager); it's your only way in when the domain or Authentik is broken.

## Deployment Order

Deploy services in this order — each step auto-configures the next:

```
1. Caddy SSL         Set your FQDN, get Let's Encrypt certs (recommended first if using a domain)
         ↓
2. Authentik         Identity provider + LDAP outpost (automated deploy)
         ↓
3. Email Relay       Optional; configure SMTP for password recovery
         ↓
4. TAK Server        Upload .deb, deploy, configure ports + certs
         ↓
5. Connect LDAP      On TAK Server page — patches CoreConfig, creates webadmin in Authentik
         ↓
6. TAK Portal        User/cert management portal
         ↓
7. Anything else     CloudTAK, Node-RED, MediaMTX — any order
```

**Connect LDAP** runs after TAK Server deploy and wires LDAP auth to CoreConfig. 8446 webadmin login and QR enrollment work immediately after. **For MediaMTX-only (or standalone Authentik):** Deploy Authentik without TAK Server — it skips CoreConfig and webadmin; add TAK Server later and use Connect LDAP.

## Remote deployment and firewalls

Authentik, CloudTAK, MediaMTX, and Node-RED can be deployed to a **remote host** (separate from the infra-TAK console). You configure the target in each module's "Deployment target" (e.g. "On another server via SSH") and deploy from the console; the console SSHs to the remote and runs Docker/scripts there.

TAK Server supports a **two-server split**: Server One (PostgreSQL database) and Server Two (TAK Server core) on separate hosts. Configure both hosts in the TAK Server settings and deploy from the console.

**Firewall:** Depending on how you deploy, the infra-TAK host and remote host may need to reach each other for the automation to work. For example:

- **SSH:** The console must reach the remote on port 22 (or your SSH port) to run deploy and management commands.
- **Authentik remote:** After containers start, the console calls the remote Authentik API on port **9090** (e.g. `http://<remote>:9090`) to inject the LDAP outpost token. If the infra-TAK server and the remote are in different networks or behind firewalls, open port **9090** from the infra-TAK host to the remote so the token step can succeed; otherwise you'll see "Connection refused" in the deploy log and the LDAP container may stay unhealthy (403 token errors).
- **Two-server TAK:** Server Two (core) must reach Server One (database) on the **PostgreSQL port** (default 5432); open that port on Server One's firewall for Server Two's IP.

If a remote deploy fails at "token" or "API" steps, or a service reports unhealthy, check that the hosts can reach the required ports (SSH, 9090 for Authentik, 5432 for two-server DB, etc.).

## What Gets Automated

**Authentik Deploy (~7 minutes):**
Console ensures 4GB swap and starts PostgreSQL first, then server/worker after the DB is ready (reduces OOM and 502s on small VPS). Bootstrap credentials generated, LDAP blueprint installed, Docker Compose patched with standalone LDAP container, API polled for outpost token, CoreConfig.xml patched with LDAP auth block, TAK Server restarted.

**TAK Portal Deploy (~4 minutes):**
Repository cloned, container built, TAK Server certs (admin.p12, tak-ca.pem) copied into container, settings.json auto-configured with Authentik URL/token and TAK Server connection, forward auth configured in Caddy, 2-minute sync wait for Authentik outpost.

After deployment, create users in TAK Portal — they flow through Authentik → LDAP → TAK Server automatically.

## Requirements

- **Ubuntu 22.04 LTS** (currently the only supported platform; goal is a universal installer). Fresh installation recommended.
- **Root access**
- **RAM:** 8 GB+ recommended for TAK Server; more if you run the full stack (Authentik, TAK Portal, Node-RED, MediaMTX, CloudTAK, Guard Dog).
- **Disk:** At max deployment (all modules) you can sit around **26 GB** used. Plan for growth: CoT data, logs, and retention. **50 GB+** disk is recommended so you have headroom; TAK Server's own minimum is 40 GB per the official configuration guide. Apply Docker log limits (Guard Dog → Apply Docker log limits) to avoid containers filling the disk.
- **Disk I/O:** SSD-backed storage strongly recommended. **Test your VPS before deploying** — slow disk I/O causes Docker build timeouts, service startup failures, and unreliable boots. See [VPS disk I/O check](#vps-disk-io-check) below.
- **CPU:** Enough cores for all processes (TAK Server, PostgreSQL, Authentik, Caddy, Node-RED, etc.). TAK Server's minimum is 4 cores; more is better for the full stack.
- **Internet** connection for initial setup.
- **TAK Server .deb** package from [tak.gov](https://tak.gov).

### VPS disk I/O check

Run this on your VPS **before deploying**. Poor disk I/O is the #1 cause of slow deploys and unreliable service startups.

```bash
# Write speed (sequential, sync)
dd if=/dev/zero of=/tmp/testfile bs=1M count=1024 oflag=dsync 2>&1 | tail -1

# Read speed
dd if=/tmp/testfile of=/dev/null bs=1M 2>&1 | tail -1

# Clean up
rm -f /tmp/testfile
```

| Write speed | Assessment |
|-------------|------------|
| **400+ MB/s** | Good — SSD-backed, full stack will deploy and boot quickly |
| **200–400 MB/s** | Acceptable — deploys work, boot may be slightly slower |
| **< 200 MB/s** | Poor — expect slow Docker builds, service timeouts, longer boot sequences |
| **< 100 MB/s** | Bad — likely throttled or HDD-backed; migrate to a different node or provider |

Some VPS providers place instances on overloaded or HDD-backed storage nodes. If your write speed is consistently under 200 MB/s, contact your provider about migrating to a different node before troubleshooting service issues. The difference between a bad node and a good one can be 50 MB/s vs 500 MB/s on the same provider.

## Architecture

```
start.sh                    ← One CLI command to launch everything
├── app.py                  ← Gunicorn web application (HTTPS on :5001)
├── uploads/                ← Uploaded .deb packages
└── .config/                ← Auth + settings (gitignored)
```

## Ports

> **v0.9.12 hardening:** Every host port is classified by exposure tier. **Tier 1 (Public)** is reachable from the internet, **Tier 3 (Caddy-loopback)** binds to `127.0.0.1` and is reached only via Caddy on 443, **Tier 4 (Docker-internal)** has no host port at all, **Tier 5 (Source-scoped)** is allowed only from a specific peer IP. Full policy: [docs/PORT-EXPOSURE-POLICY.md](docs/PORT-EXPOSURE-POLICY.md).

### Tier 1 — Public (open in UFW)

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| infra-TAK Console | 5001 | HTTPS | Management web UI (backdoor: direct IP access) |
| Caddy | 80 | HTTP | Redirect to HTTPS |
| Caddy | 443 | HTTPS | Reverse proxy for all services (Let's Encrypt) |
| TAK Server | 8089 | TLS | TAK client connections (ATAK, iTAK, WinTAK) |
| TAK Server | 8443 | HTTPS | Admin WebGUI (client certificate auth) |
| TAK Server | 8446 | HTTPS | Admin WebGUI (Let's Encrypt, password/LDAP auth) |
| MediaMTX | 8554 | RTSP | Video streaming clients (publish + play) |
| MediaMTX | 8322 | RTSPS | TLS-wrapped RTSP |
| MediaMTX | 8890 | SRT | SRT streaming clients |
| MediaMTX | 8000/8001 | UDP | RTP/RTCP companion ports for RTSP |
| CloudTAK Media | 18554 | RTSP | CloudTAK video tab — RTSP clients |
| CloudTAK Media | 11935 | RTMP | CloudTAK video tab — RTMP publishers |
| CloudTAK Media | 18890 | SRT | CloudTAK video tab — SRT clients |

### Tier 3 — Caddy-loopback (bound to `127.0.0.1`, **deny in UFW**)

Reached only through Caddy on 443 via the public FQDN. Raw ports are NOT reachable from the internet. v0.9.12 enforces this via `!reset` Docker port overrides plus UFW deny rules.

| Service | Port | Description |
|---------|------|-------------|
| Authentik | 9090/9443 | Identity provider HTTP/HTTPS (Caddy proxies `https://authentik.example.com`) |
| TAK Portal | 3000 | User/cert management portal (Caddy proxies `https://portal.example.com`) |
| Node-RED | 1880 | Flow editor (Caddy proxies `https://nodered.example.com` with forward_auth) |
| MediaMTX | 8888 | HLS playback (Caddy proxies `/hls-proxy/` on the MediaMTX FQDN) |
| MediaMTX | 5080 | MediaMTX webedit (Caddy proxies the MediaMTX FQDN) |
| MediaMTX | 9898 | MediaMTX admin API (consumed by webedit on loopback) |
| CloudTAK | 5000 | CloudTAK API (Caddy proxies `https://cloudtak.example.com`) |
| CloudTAK | 5002 | CloudTAK tiles |
| CloudTAK | 18888 | CloudTAK media HLS |
| CloudTAK | 9997 | CloudTAK media admin API |
| CloudTAK | 9002 | MinIO web console (operator SSH-tunnels for bucket management) |

### Tier 4 — Docker-internal (no host port, **service reachable only on the Docker network**)

| Service | Internal endpoint | Description |
|---------|-------------------|-------------|
| Authentik PostgreSQL | `postgresql:5432` | Authentik DB |
| Authentik Redis | `redis:6379` | Authentik task queue |
| CloudTAK PostGIS | `postgis:5432` | CloudTAK DB (was Tier 1 + default creds pre-v0.9.11 — root cause of the PG_MEM incident) |
| CloudTAK MinIO S3 | `store:9000` | CloudTAK S3 storage |
| CloudTAK events | `events:5003` | CloudTAK background worker |

### Tier 5 — Source-scoped (UFW allow from specific peer IP only)

| Service | Port | Source | Description |
|---------|------|--------|-------------|
| Server One PostgreSQL | 5432 (default) | Server Two IP | Two-server TAK Server DB (was unconditional `allow 5432/tcp` pre-v0.9.12) |
| Guard Dog health agent | 8080 | Console IP (`settings.server_ip`) | Two-server DB health endpoint on Server One |
| LDAP Outpost | 389/636 | Console IP | Reachable only when Authentik is deployed remotely; consumed by TAK Server's LDAP auth block |
| Email Relay | 25 | localhost | Local Postfix relay (apps send here) |

## Actions Reference (Sync, Update Config, Resync)

Each page has buttons that do specific things. Here's what they do and when to use them.

### TAK Server Page

| Button | What it does | When to use it |
|--------|-------------|----------------|
| **Update Config** | Regenerates Caddyfile, reloads Caddy, installs Let's Encrypt cert on 8446, restarts TAK Server | After changing the TAK Server domain/FQDN in Caddy settings |
| **Connect TAK Server to LDAP** | Full LDAP setup: repairs Authentik blueprint, ensures service account + webadmin, writes LDAP auth block into CoreConfig.xml (without flat-file), restarts TAK Server | After deploying Authentik (if TAK Server was deployed first), or if LDAP auth stops working |
| **Resync LDAP to TAK Server** | Same as Connect LDAP — full re-run of the LDAP fix flow | If QR registration fails, if 8446 login stops working, after pulling console updates |
| **Sync webadmin to Authentik** | Pushes the 8446 webadmin password from settings into Authentik (no TAK Server restart) | After changing the webadmin password |
| **Disable/Enable flat-file auth** | Adds or removes `UserAuthenticationFile.xml` from the CoreConfig auth block, restarts TAK Server | When you want LDAP-only auth (disable) or need local password fallback (enable) |
| **Set JVM Heap** | Writes `-Xms`/`-Xmx` to `/opt/tak/setenv.sh`, restarts TAK Server | TAK Server running out of memory (OutOfMemoryError in logs) |

### TAK Portal Page

| Button | What it does | When to use it |
|--------|-------------|----------------|
| **Sync TAK Server to TAK Portal** | Forces TAK Portal to re-read the TAK Server connection (IP, certs, API URL) | If TAK Portal dashboard doesn't show TAK Server uptime/disk usage |
| **Update Config** | Rewrites TAK Portal's `settings.json` with current Authentik + TAK Server URLs, restarts the container | After changing FQDN, after Authentik redeploy, if TAK Portal can't reach TAK Server or Authentik |
| **Sync TAK Server CA** | Copies the current `tak-ca.pem` into the TAK Portal container | After CA rotation — TAK Portal needs the new CA to generate valid client certs |

### Authentik Page

| Button | What it does | When to use it |
|--------|-------------|----------------|
| **Update Config & Reconnect** | Patches docker-compose.yml (PostgreSQL tuning, blueprint mounts), ensures all forward auth apps exist (infra-TAK, TAK Portal, Node-RED, etc.), repairs embedded outpost, updates LDAP CoreConfig, reloads Caddy | After pulling console updates, if forward auth breaks, if apps disappear from Authentik, if LDAP stops working |
| **Fix LDAP Token** | Re-fetches the LDAP outpost token from Authentik API and injects it into docker-compose.yml, restarts the LDAP container | If LDAP container shows "unhealthy" or "403 Forbidden" in logs |

### Email Relay Page

| Button | What it does | When to use it |
|--------|-------------|----------------|
| **Switch Provider** | Reconfigures Postfix with new SMTP credentials/host, restarts Postfix | Changing email provider or From address |
| **Configure Authentik** | Pushes relay settings (localhost:25, From address) into Authentik so password recovery emails work | After deploying or switching Email Relay provider |

### General Rules

- **Deploy order matters:** Caddy → Authentik → Email Relay → TAK Server → TAK Portal → everything else
- **After pulling console updates:** Hit "Update Config" on Authentik, then optionally on TAK Server if you changed FQDN
- **If TAK Portal can't reach TAK Server:** Hit "Sync TAK Server to TAK Portal" on the TAK Portal page
- **If LDAP auth breaks:** Hit "Connect TAK Server to LDAP" on the TAK Server page
- **If forward auth breaks (502/blank on FQDN URLs):** Hit "Update Config" on the Authentik page
- **After CA rotation:** Hit "Sync TAK Server CA" on the TAK Portal page, then have users re-enroll

## Access Modes

**IP Address Mode** — Self-signed certificate, works anywhere (field deployments, no DNS needed)

**FQDN Mode** — Caddy + Let's Encrypt for proper SSL. Required for TAK client QR enrollment. Can upgrade from IP mode through the web console without SSH.

## QR Code Enrollment

| Client | Status | Notes |
|--------|--------|-------|
| ATAK (Android) | ✅ Working | Requires FQDN mode with Let's Encrypt |
| TAKAware (iOS) | ✅ Working | Works in both IP and FQDN mode |

## Security

- Password required before any access (set during `./start.sh`)
- HTTPS from the start (self-signed or Let's Encrypt)
- Session-based authentication
- All config files are 600 permissions
- Authentik bootstrap credentials auto-generated per deployment

## Design notes

- **[References](docs/REFERENCES.md)** — Canonical links (e.g. [TAK Server API](https://docs.tak.gov/api/takserver)) for development and integration.
- **[Authentik login branding](docs/AUTHENTIK-LOGIN-BRANDING.md)** — Custom CSS vs **Brand → Attributes** (`theme: dark`), black backgrounds, flow wording; links to official Authentik docs and community guides.
- **[Guard Dog](docs/GUARDDOG.md)** — How Guard Dog works: monitors, 15‑minute boot delay and cooldowns, TAK Server soft start (after PostgreSQL and network), 4GB swap on deploy for memory stability, and restart-loop protection. Apply Docker container log limits from the Guard Dog page without redeploying a module.
- **[MediaMTX access driven by TAK Portal / LDAP](docs/MEDIAMTX-TAKPORTAL-ACCESS.md)** — How stream.fqdn admin vs viewer logic can be driven from TAK Portal (one place to manage users, no separate MediaMTX or Authentik user management). **Do not configure the email/SMTP portion of MediaMTX** — request access and approval notifications are handled by TAK Portal's open request-access page and Email Relay.

---

## Changelog

### v0.9.16-alpha — 2026-05-13 — AUTHENTIK WORKER CPU HOTFIX + UI POLISH

**Headline: Authentik worker CPU drops from ~26% sustained to idle after Update Now. Drop-in — no operator pre-flight.**

- **Root cause (two-step chain).** v0.9.2-alpha (CVE-2026-31431 hardening) removed `/var/run/docker.sock` from the Authentik worker's compose volumes — correct, as the socket was never needed and gave the worker full Docker daemon access. That fix patched the compose file but never cleaned up the **"Local Docker" service connection** stored in Authentik's database by the upstream quickstart. With the socket gone, the worker's `outpost_service_connection_monitor` Dramatiq task retried the dead socket every 30 seconds indefinitely. On Authentik 2026.2.3 the retry loop is tight enough to hold the worker at ~26% CPU continuously.
- **Fix: `_auto_remove_stale_docker_service_connections()`.** New post-update migration step that runs after `_authentik_tasklog_cleanup()` in `_run_post_update()`. Uses `GET /api/v3/outposts/service_connections/docker/` to list all Docker service connections, then issues `DELETE` for any with `local: true`. Idempotent — logs "nothing to do" if no local connections exist. Non-fatal — top-level exception handler prevents it from blocking the rest of the update if Authentik is unreachable.
- **Caddy Update button.** Caddy detail page now shows the installed version (e.g. `v2.9.1`) in the status banner, a `· update available` indicator in cyan when `apt list --upgradable` detects a newer package, and an **⬆ Update** button in controls. Button runs `apt-get install --only-upgrade caddy` then `systemctl reload caddy` via new `POST /api/caddy/update` route. Consistent with the update button pattern on all other service pages (TAK Portal, CloudTAK, FedHub, Guard Dog, MediaMTX).
- **Authentik Update button spinner.** The **⬆ Update** button on the Authentik detail page now shows a spinning `↻ Updating...` label and a status line while `docker compose pull` runs (can take 2–5 min). Shows green "✓ Updated" on success, red error message on failure. Matches Caddy and TAK Portal UX — was previously silent for the full pull duration.

Full notes: [docs/RELEASE-v0.9.16-alpha.md](docs/RELEASE-v0.9.16-alpha.md).

---

### v0.9.15-alpha — 2026-05-12 — TAK PORTAL ADMIN-ACCOUNT GUARDRAIL

**Headline: `akadmin` and `webadmin` are now hidden + action-locked in TAK Portal. v0.9.13/v0.9.14 recovery panel stays as the safety net.**

- **Background.** The original v0.9.13 incident: TAK Portal user clicked **Disable** on both `akadmin` and `webadmin` from the user-management UI, locking the operator out of Authentik. v0.9.13 + v0.9.14 built the **detection + recovery** side (Protected Admin Accounts panel on `/authentik`, layered API → `ak shell` fallback). v0.9.15 closes the **prevention** side.
- **What ships.** TAK Portal already has two settings fields that exactly cover this case — `USERS_HIDDEN_PREFIXES` (hidden from user list) and `USERS_ACTIONS_HIDDEN_PREFIXES` (visible but cannot be modified). infra-TAK is already authoritative for both in TAK Portal's `settings.json`. v0.9.15 bumps the defaults:
  - `USERS_HIDDEN_PREFIXES`: `"ak-,adm_,nodered-,ma-"` → `"akadmin,webadmin,ak-,adm_,nodered-,ma-"`.
  - `USERS_ACTIONS_HIDDEN_PREFIXES`: `""` → `"akadmin,webadmin"`.
  - TAK Portal does **prefix** matching; the literal strings `akadmin` / `webadmin` match those exact users (the existing `ak-` prefix has a trailing dash and did not cover `akadmin`).
- **Self-healing migration** `_auto_harden_takportal_settings()` runs in post-update right after `_auto_harden_takportal` (port hardening). Idempotent: reads the live `settings.json` from the `tak-portal` container; if both prefixes are already in both fields, no-op. Otherwise pushes merged settings (preserving `BRAND_LOGO_URL` / SSH onboarding flags via `PRESERVE_TAKPORTAL_KEYS`) and restarts the container. Skipped when TAK Portal isn't deployed locally — remote-Portal installs apply the new defaults via TAK Portal → **Update config & reconnect** in the console UI.
- **Three-layer defense for the same incident class.** Any one layer failing doesn't break the chain:
  - **Prevent (v0.9.15)** — TAK Portal hides + action-locks the two protected admins. Operator can't click Disable on them.
  - **Detect (v0.9.13 + v0.9.14)** — Protected Admin Accounts panel on `/authentik` shows live `is_active` state. Reads survive Authentik 403s via the ak-shell fallback added in v0.9.14.
  - **Recover (v0.9.13 + v0.9.14)** — One-click **Reactivate** button. Layered API → `ak shell` so the recover path works even when the bootstrap token's owner has been disabled.
- **Recovery surface unchanged.** `_recover_authentik_user` (write), `_get_authentik_admin_accounts_status` + `_read_authentik_admin_accounts_via_ak_shell` (read), the `/api/authentik/admin-accounts` and `/api/authentik/recover-admin` endpoints, and the Protected Admin Accounts UI panel are all untouched from v0.9.14. The panel becomes a recovery feature operators see rarely instead of frequently — which is the right shape for a foot-gun guardrail.
- **Drop-in update.** No migrations to run, no operator pre-flight. Channel toggle from v0.9.12 (`main` vs `dev`) is unchanged. Update Now applies the new defaults via the post-update migration on local installs and via the next Update config & reconnect click on remote-Portal installs.

Full notes: [docs/RELEASE-v0.9.15-alpha.md](docs/RELEASE-v0.9.15-alpha.md).

---

### v0.9.14-alpha — 2026-05-12 — AUTHENTIK ADMIN RECOVERY HOTFIX

**Headline: v0.9.13's Protected Admin Accounts panel couldn't see the very state it was built to recover. v0.9.14 gives the read path the same `ak shell` fallback the write path already had.**

- **The bug.** `AUTHENTIK_BOOTSTRAP_TOKEN` (the token infra-TAK pulls out of `~/authentik/.env`) is owned by `akadmin`. Authentik's permission model checks the *token owner's* permissions on every API call. When `akadmin.is_active = false` — the exact state the panel exists to recover from — Authentik authenticates the token but returns **HTTP 403 Forbidden** on every protected endpoint, including `GET /api/v3/core/users/?search=akadmin`. v0.9.13's `_get_authentik_admin_accounts_status` only knew how to talk to the API, so on installs where the bug had already bitten the panel rendered `? Authentik API 403` for both accounts and never reached the `is_active === false` branch that draws the **Reactivate** button. v0.9.13's *write* path (`_recover_authentik_user`) already had the right `ak shell` fallback — the *read* path had just been overlooked.
- **Fix A — new helper `_read_authentik_admin_accounts_via_ak_shell()`.** Reads both protected admin users in a single `docker exec authentik-server-1 ak shell` call. Snippet is base64-encoded before being piped in (same pattern as v0.9.13's recover-path ak-shell layer — zero quoting concerns across shell / ssh / docker layers). Output is parsed line-by-line into the same dict shape the API path produces. Only the whitelisted usernames are ever interpolated into the snippet.
- **Fix B — layered read in `_get_authentik_admin_accounts_status()`.** Try the API first (normal case, fastest). If *any* API call errors with `HTTPError` / network error / 401 / 403, switch to the ak-shell fallback for *all* users so the entire panel renders from one consistent source. The response JSON gains a `source` field (`'api'` vs `'ak-shell'`); the UI shows a small dim caption when the fallback is in use so the operator knows the panel is self-healing.
- **Fix C — UI escape hatch.** The JS now also renders the **Reactivate** button when `a.error` is set (previously the button only appeared when `a.is_active === false`). The recover endpoint has its own independent ak-shell fallback that doesn't depend on the read working, so the operator always has a manual lever even if the read fails for an unanticipated reason.
- **What it looks like for the customer who hit this:**
  - Before v0.9.14: `akadmin  ? Authentik API 403 / webadmin  ? Authentik API 403` — no buttons.
  - After v0.9.14: `akadmin  ⚠ DEACTIVATED  [ Reactivate ] / webadmin  ⚠ DEACTIVATED  [ Reactivate ]` + a dim caption `status read via ak shell (Authentik API unavailable)`. Clicking Reactivate on `akadmin` recovers via the ak-shell layer (banner: `[via ak-shell]`); the API unwedges once akadmin is back to `is_active=true`; reactivating `webadmin` typically goes `[via api]` after that.
- **No migrations. No operator pre-flight.** Drop-in update from v0.9.13. Channel toggle from v0.9.12 (`main` vs `dev`) is unchanged. Update Now patches the panel automatically. No new dependencies, no new packages, no new endpoints (URLs and verbs from v0.9.13 are unchanged; the response JSON gains a `source` field but the v0.9.13 fields are kept).

Full notes: [docs/RELEASE-v0.9.14-alpha.md](docs/RELEASE-v0.9.14-alpha.md).

---

### v0.9.13-alpha — 2026-05-12 — AUTHENTIK ADMIN RECOVERY

**Headline: One-click reactivate for `akadmin` / `webadmin` when a TAK Portal user accidentally Disables them.**

- **The incident this fixes.** An operator using TAK Portal's user-management UI clicked **Disable** on both `webadmin` and `akadmin`. Authentik's "Disable" = `is_active=false` (fully reversible — user record is preserved, only login + LDAP bind are blocked), but with **both** admin accounts disabled, the operator was locked out of the Authentik UI entirely. Pre-v0.9.13 recovery required SSH to the host and either `docker exec authentik-server-1 ak shell` running a Django ORM update, or `docker exec authentik-postgresql-1 psql -c "UPDATE authentik_core_user …"`. Neither is operator-friendly.
- **New panel on `/authentik`.** A **Protected Admin Accounts** card now sits under the existing "Admin user: akadmin · Show Password" row inside the Access section. Polls on page load and on demand (Refresh button). Each row shows the account's `is_active`/`is_superuser` state:
  - Green `✓ Active · superuser` — normal.
  - Red `⚠ DEACTIVATED` with a **Reactivate** button — the recovery path.
  - Quiet `— not present in Authentik` — for installs where `webadmin` doesn't exist yet (e.g. TAK Server not deployed). No alarm.
- **Layered recovery.** `_recover_authentik_user()` tries paths in order, first success wins:
  1. **Authentik API.** `PATCH /api/v3/core/users/{pk}/ {"is_active": true, "is_superuser": true}` using the `AUTHENTIK_BOOTSTRAP_TOKEN` from `~/authentik/.env`. Banner: `[via api]`.
  2. **`ak shell` fallback.** `docker exec authentik-server-1 sh -c 'echo $b64 | base64 -d | ak shell'` runs Django ORM `User.objects.filter(username=…).save()`. The script is base64-encoded before being piped in, so there is zero quoting concern across the shell / ssh / docker layers. Bypasses API auth, broken flows, broken policies — works as long as the `authentik-server-1` container is running. Banner: `[via ak-shell]`.
  - Whitelist (`_AUTHENTIK_RECOVERABLE_USERS = ('akadmin', 'webadmin')`) is enforced server-side so the endpoint can't be used to re-enable arbitrary accounts, and the whitelist also guarantees the username interpolated into the ak-shell snippet is one of two literals.
- **Bug fix bundled.** `_ensure_authentik_webadmin()` (behind the existing **Sync webadmin to Authentik** button on the TAK Server page) was patching `is_superuser`/`path`/`groups` on an existing webadmin record but never flipping `is_active` back to `true`. So a disabled webadmin could not be recovered through that path — `set_password` succeeded but 8446 login still failed because `is_active=false` blocks LDAP bind. Added the missing one-liner (matching what `_ensure_authentik_ldap_service_account` already did for `adm_ldapservice`).
- **Out of scope.** `adm_ldapservice` is not in the panel — TAK Portal cannot disable that account and there's no plausible accidental-disable path for it through the UIs infra-TAK is responsible for. The complementary fix in TAK Portal (refuse to Disable the protected accounts, or require typed confirmation) is in the TAK Portal repo, not infra-TAK; infra-TAK's panel is the safety net for when that guardrail is bypassed or the operator uses Authentik's native UI to do the same thing.
- **No migrations. No operator pre-flight.** Drop-in update from v0.9.12 — Update Now applies the new endpoints + panel and the bundled `is_active` fix; the existing webadmin sync flow simply gains the missing recovery step. Channel toggle from v0.9.12 (`main` vs `dev`) is unchanged.

Full notes: [docs/RELEASE-v0.9.13-alpha.md](docs/RELEASE-v0.9.13-alpha.md).

---

### v0.9.12-alpha — 2026-05-11 — CYBER SECURITY HARDENING

**Headline: Comprehensive port-exposure lockdown + post-auth route fixes + self-healing migrations — follow-up to v0.9.11 audit.**

- **Operator pre-flight.** v0.9.12 introduces a `main`/`dev` **update-channel toggle** on the Console page. Before clicking **Update Now**, confirm the toggle is on **`main`** (green). Operators on the `dev` channel during the rc cycle should click `main` first; otherwise Update Now will keep tracking the moving `dev` HEAD instead of the tagged `v0.9.12-alpha` release. Full pre-flight in [docs/RELEASE-v0.9.12-alpha.md](docs/RELEASE-v0.9.12-alpha.md).
- **Background.** The v0.9.11 CloudTAK fix patched ONE upstream credential / port-exposure vulnerability. A post-incident audit found the same class of issue (publicly-bound services + lax auth boundaries) elsewhere in the stack, plus a small cluster of post-auth code bugs (SQL injection, command injection, path traversal, a hardcoded LDAP fallback password). None were live-exploited — this release is a planned hardening pass, not a fire drill. New canonical reference: [docs/PORT-EXPOSURE-POLICY.md](docs/PORT-EXPOSURE-POLICY.md).
- **Port hardening — Part A.** Generalises the v0.9.11 `!reset` override pattern to every service:
  - **CloudTAK** — `api 5000`, `tiles 5002`, `media-admin 9997`, `media HLS 18888` bound to `127.0.0.1`; `events 5003` removed entirely (Docker-internal, no host port). RTSP/RTMP/SRT streaming ports kept public. UFW denies the loopback ports belt-and-braces.
  - **TAK Portal** — `WEB_UI_PORT` (default 3000) bound to `127.0.0.1`. New `_auto_harden_takportal()` post-update step force-recreates the container if it's still on `0.0.0.0`.
  - **MediaMTX** — admin API `9898`, HLS `8888`, webedit Flask `5080` bound to `127.0.0.1` (both local and remote installs). Patches existing installs on every Update Now via new `_auto_harden_mediamtx()`. Streaming ports (RTSP 8554, RTSPS 8322, SRT 8890, RTP 8000/8001) kept public.
  - **Remote Authentik** — `9000`/`9443` bound to `127.0.0.1` (Caddy proxies). LDAP outpost `389`/`636` source-scoped to the console source IP via `settings.server_ip`. Existing remote installs patched on Update Now via new `_auto_authentik_ports_remote()`.
  - **Server One PostgreSQL** — removed the unconditional `ufw allow {db_port}/tcp` that silently overrode the source-scope rule above it; UFW now explicitly denies the port to everyone except Server Two.
  - **Server One Guard Dog health agent** — `8080/tcp` source-scoped to the console IP instead of public.
- **Route fixes — Part B.**
  - **Snapshot path traversal.** New `_validate_snapshot_label` validator wired into `/api/takserver/snapshot/<label>/download`, `/api/takserver/snapshot/<label>` DELETE, `/api/takserver/rollback`, and the underlying `_tak_rollback` helper. Was vulnerable to `..%2F..%2Fetc` payloads.
  - **External-DB SQL injection.** `/api/takserver/external-db/provision` now regex-validates identifiers (`app_user`, `db_name`, `admin_user`) against the Postgres identifier grammar and passes the password via `psql -v` substitution + `:'pw'` quoting instead of f-string concatenation.
  - **External-DB test-connection RCE.** Replaced `bash -c "</dev/tcp/HOST/PORT"` shell-out with `socket.create_connection((host, port))` and added IP/DNS validation on `db_host`.
  - **Webadmin password shell injection.** `/api/takserver/webadmin-password` POST now validates the password with `_validate_cert_password` and passes it to `UserManager.jar` via `argv` instead of `bash -c "... -p '{pw}' ..."`. Secondary call site uses `shlex.quote` for defence-in-depth.
  - **Hardcoded LDAP service password fallback.** The literal 32-char `adm_ldapservice` fallback baked into `app.py` since v0.7.x is gone. Missing `AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD` now generates a fresh `secrets.token_urlsafe(24)` and persists it to `~/authentik/.env` for future runs.
  - **SSH host/user injection.** New `_validate_ssh_target` regex-checks `host`/`ssh_user`/`ssh_port` before `_ssh_probe` and `_scp_to_host` build the ssh argv, defending against operator/API inputs that contain SSH option flags (e.g. `-oProxyCommand=...`).
- **Operator action.** Confirm the channel toggle is `main`, then click **Update Now** — the new `_auto_harden_*` post-update steps patch existing installs automatically. For installs that have been running TAK Portal or MediaMTX for a while, a one-time container recreate happens during the post-update; expect a brief downtime on those services. The remote-Authentik hardening requires `Settings → Server IP` to be filled in for LDAP source-scoping; without it the install logs a warning and leaves 389/636 publicly open (current behaviour).
- **Late-cycle fixes (B7, B8) — discovered during the test cycle on `tak-10` and `responder`, shipped in the same release.** These are documented as separate sections in the release notes:
  - **B7. `~/authentik` tilde expansion under gunicorn.** Clicking **Sync webadmin to Authentik** (and any other code path that shelled out to `cd ~/authentik …`) failed with `/bin/sh: 1: cd: can't cd to ~/authentik` because `takwerx-console.service` never pinned `Environment=HOME=`. systemd does not inherit `HOME` from login env, so `/bin/sh` couldn't expand `~`. Three-layer fix: runtime guard in `app.py` (sets `os.environ['HOME']` if unset), `start.sh create_service()` writes `Environment=HOME=$SERVICE_HOME` for fresh installs, and a new `_startup_pin_console_service_home()` migration patches existing v0.9.11 unit files on Update Now. Same class of bug fixed for `takupdatesguard.service` in v0.2.7-alpha and for `git config --global` in v0.9.2-alpha — finally closed end-to-end for the console unit.
  - **B8. Authentik ReputationPolicy binding was inverted — `negate=True` required.** Every LDAP bind for `webadmin` (and `adm_ldapservice` once its cache rebuilt) returned `Invalid credentials (49)` after the v0.9.12 `_startup_resync_ldap_service_account` migration wiped the LDAP outpost's bind cache. Authentik server log filled with `FlowNonApplicableException`. Root cause verified via `inspect.getsource(ReputationPolicy.passes)` directly inside the running `authentik-server-1` container: `passes()` returns `True` only when `score <= threshold` (i.e. only when the user has accumulated bad reputation), so with `negate=False` the binding denied **all normal users** instead of just brute-force abusers. Fix: `_authentik_setup_reputation_policy()` now POSTs new bindings with `negate=True, failure_result=True`, and a new `_startup_fix_reputation_policy_drift()` migration DELETE+POST-recreates existing bindings whose `negate` or `failure_result` fields are wrong (PATCH on `policies/bindings/` returns 405 on Authentik 2026.x — DELETE+POST is the documented workaround). This bug hid for ten releases (v0.9.2 → v0.9.12-rc) because the LDAP outpost's `bind_mode: cached` masked the misconfig — only after v0.9.12's resync cleared the cache did it surface. [`docs/HANDOFF-LDAP-AUTHENTIK.md`](docs/HANDOFF-LDAP-AUTHENTIK.md) carries the new `negate=True` rule so it can't be re-introduced without a doc trigger.
- **Self-healing startup migrations (run on every console boot, all idempotent).** `_startup_pin_console_service_home` (B7), `_auto_harden_takportal_compose_ports` / `_auto_harden_cloudtak_compose_ports` (Part A self-heal — patches existing `docker-compose.yml` files in place and force-recreates if `0.0.0.0` still in port mappings), `_startup_resync_ldap_service_account` (heals LDAP SA bind drift end-to-end including TAK Server restart on healing), `_startup_fix_reputation_policy_drift` (B8). All persist their outcome to `settings.json` so the operator can audit what ran via `journalctl -u takwerx-console`.

Full notes: [docs/RELEASE-v0.9.12-alpha.md](docs/RELEASE-v0.9.12-alpha.md).

---

### v0.9.11-alpha — 2026-05-10 — SECURITY HOTFIX

**Headline: CloudTAK upstream PostgreSQL public-exposure + default-credentials RCE — active cryptominer infection observed.**

- **Background.** `dfpc-coe/CloudTAK`'s `docker-compose.yml` (main branch) ships postgis with `5433:5432` (host `0.0.0.0:5433`) and a hardcoded `POSTGRES_PASSWORD=docker` literal, plus MinIO on `9000`/`9002`. Any public-IP CloudTAK install = open Postgres with `docker:docker` superuser creds reachable from the internet. Brute-force scanners find it within hours.
- **Live compromise observed May 8–10 2026** on infra-TAK `responder`. Attacker chain: scan → `docker:docker` succeeds → `COPY FROM PROGRAM` drops `gcmanager-1.so` into the postgis data volume → modify `postgresql.conf` `shared_preload_libraries` → reload → Monero miner runs at 1000%+ CPU. Malware family: PG_MEM / PGMiner (Aqua Nautilus, Palo Alto Unit 42). C2 over Tor SOCKS5. See [docs/SECURITY-INCIDENT-2026-05-10-PGMINER.md](docs/SECURITY-INCIDENT-2026-05-10-PGMINER.md).
- **Fix in `_cloudtak_build_override_yml()`.** Override now uses `ports: !reset []` on postgis (removes the upstream `5433:5432` mapping entirely — CloudTAK app reaches postgis over the internal Docker network, host port was never needed) and `ports: !reset` on store binding only `127.0.0.1:9002:9002` (operators can still SSH-tunnel for MinIO console access; the public `9000` S3 API mapping is removed). Postgis `POSTGRES_PASSWORD` is now substituted from `.env` via `${POSTGRES_PASSWORD:-docker}` so fresh installs init with a strong value.
- **Fix in `_cloudtak_build_env_content()`.** Accepts `postgres_pass` parameter; emits `POSTGRES_PASSWORD=<value>` + `POSTGRES=postgres://docker:<value>@postgis:5432/gis`. Fresh-install call sites generate `secrets.token_hex(24)` and save to `~/CloudTAK/.postgres-password` (chmod 600). Reconfig call sites read the existing value from `.env` (and from remote `.env` via SSH for remote deploys) so a reconfig never breaks the DB connection.
- **New: `_auto_harden_cloudtak()`** runs every Update Now after `_auto_takportal()` and `cloudtak_t.join()`. Detects compromise (`*.so` files in postgis data root + uncommented `shared_preload_libraries` in `postgresql.conf`), quarantines `.so` files to a dated subdir (preserves forensics, does not delete), comments out the malicious `shared_preload_libraries` line with `#INFRATAK_DISABLED# ` prefix. If compromised: stops all CloudTAK containers, writes `~/CloudTAK/COMPROMISE-DETECTED.txt`, prints loud red banner, leaves CloudTAK OFFLINE pending operator Remove + Reinstall. If clean: writes the hardened override, applies UFW deny rules for `5433/tcp`/`9000/tcp`/`9002/tcp` (defense in depth), force-recreates the stack.
- **Operator action required.** After updating, go to console → CloudTAK → **Remove** (wipes the data volume + any potentially compromised artifacts), then → **Install** (clean install with strong password + hardened port bindings). Reinstall is the only way to get a fresh DB; the Update Now hardening alone leaves the existing weak password in place (but locks the network so it's unreachable). See [docs/RELEASE-v0.9.11-alpha.md](docs/RELEASE-v0.9.11-alpha.md).

Full notes: [docs/RELEASE-v0.9.11-alpha.md](docs/RELEASE-v0.9.11-alpha.md).

---

### v0.9.10-alpha — 2026-05-10

**Headline: Critical hotfix — orphan-postgres killer was murdering CloudTAK PostGIS on every update.**

- **Fix: cgroup check now compares against ALL running containers, not just `authentik-postgresql-1`** — v0.9.8/v0.9.9 used `kill if cgroup doesn't contain authentik-postgresql-1 ID`, which incorrectly classified `cloudtak-postgis-1` UID-70 processes as orphans and SIGKILLed them on every update. Verified on responder and tak-10. Fix: get the set of all running container IDs via `docker ps -q --no-trunc`, kill UID-70 postgres only when its cgroup matches NO running container.

Full notes: [docs/RELEASE-v0.9.10-alpha.md](docs/RELEASE-v0.9.10-alpha.md).

---

### v0.9.9-alpha — 2026-05-10

**Headline: Hotfix — v0.9.8's orphan kill ran too early; second pass added after Authentik reconfigure.**

- **Fix: final orphan postgres kill after `_auto_authentik()`** — v0.9.8's orphan check ran at the end of `_auto_harden_containers()`, but `_auto_authentik()` runs LATER in post-update and recreates Authentik containers a second time, creating fresh orphans the first check couldn't see. Second cgroup-based kill now runs right before `auto-deploy complete` to catch these.

Full notes: [docs/RELEASE-v0.9.9-alpha.md](docs/RELEASE-v0.9.9-alpha.md).

---

### v0.9.8-alpha — 2026-05-10

**Headline: Hotfix — orphaned postgres process at 1100%+ CPU survives container recreate.**

- **Fix: cgroup-based orphan postgres kill runs on every update** — reads `/proc/<pid>/cgroup` for all UID-70 postgres processes and kills any whose cgroup does not contain the current `authentik-postgresql-1` container ID. Catches orphans from prior bad updates unconditionally.
- **Fix: `docker stop -t 30`** — extended graceful shutdown from 10s to 30s so postgres can complete its checkpoint before the container is removed, preventing new orphans from being created.

Full notes: [docs/RELEASE-v0.9.8-alpha.md](docs/RELEASE-v0.9.8-alpha.md).

---

### v0.9.7-alpha — 2026-05-10

**Headline: Hotfix — three bugs in v0.9.5/v0.9.6 Authentik Postgres cleanup left all servers still broken.**

- **Fix: `shm_size` detection anchored to postgresql service block** — v0.9.6 checked `'shm_size:' not in whole_file` which false-positives when other services (server/worker) have their own `shm_size` values. Fix: scan only the postgresql service block by anchoring on `image: docker.io/library/postgres:16-alpine`. Also decoupled the docker inspect ShmSize check from compose content — now always checks the running container regardless of what the file says.
- **Fix: DELETE SQL wrong column names** — Authentik 2026.x task table schema has `message_id` (PK) and `mtime` (timestamp), not `pk` and `finish_timestamp`. All three SQL locations fixed: `_authentik_tasklog_cleanup()`, the weekly Guard Dog timer script written to disk, and `docs/AUTHENTIK-TASK-BLOAT-FIX.md`.

Full notes: [docs/RELEASE-v0.9.7-alpha.md](docs/RELEASE-v0.9.7-alpha.md).

---

### v0.9.6-alpha — 2026-05-10

**Headline: Hotfix — Authentik Postgres `shm_size: 256m` was patched to compose file in v0.9.5 but the container was never recreated with it.**

- **Fix: Authentik `shm_size` not applied to running container** — `_auto_harden_containers()` wrote `shm_size: 256m` to `~/authentik/docker-compose.yml` but only ran `--force-recreate worker server ldap` — `postgresql` was never in the list. All v0.9.5 installs had `ShmSize: 67108864` (64 MB) in `docker inspect` regardless of the compose file. Fix: the code now inspects the running container's `HostConfig.ShmSize` at update time; if it reads 64 MB it recreates `postgresql` first (with a 5 s settle), then `worker server ldap`. Fires automatically for all v0.9.5 operators.
- **Fix: Authentik task log backlog cleared on "Update Now"** — New `_authentik_tasklog_cleanup()` runs on every update. If `authentik_tasks_tasklog` exceeds 100 MB it runs the same DELETE + `VACUUM ANALYZE` as the weekly Guard Dog timer, clearing the accumulated backlog immediately. No-op on subsequent runs once tables are small. Operators experiencing Authentik Postgres CPU spikes from bloated task tables no longer need to follow the manual runbook.

Full notes: [docs/RELEASE-v0.9.6-alpha.md](docs/RELEASE-v0.9.6-alpha.md).

---

### v0.9.5-alpha — 2026-05-10

**Headline: Snapshot upload & restore, two-server snapshot support, Authentik DB health, CloudTAK stability, and six bug fixes from field testing.**

- **Snapshot Upload & Restore (B)** — New **⬆ Upload Snapshot** button. Upload a previously downloaded `.tar.gz` back to the server; it appears in the table like a local snapshot and the existing **↩ Restore** button works without changes. Real-time progress bar shows MB transferred and percent. Use case: disaster recovery on a fresh VPS, migration between hosts, restoring a snapshot pruned by the retention policy.
- **Two-server snapshot support (A)** — On split deployments, `_tak_snapshot()` now streams `pg_dump` from Server One via SSH instead of running locally (where the DB doesn't live). `_tak_rollback()` streams the restore back. Config files and certs are unchanged — they already live on Server Two.
- **Authentik Postgres `shm_size` (C)** — Added `shm_size: 256m` to the Authentik `postgresql` service (fresh installs and "Update Now" on existing installs). Prevents `ERROR: could not resize shared memory segment` on `VACUUM ANALYZE` with parallel workers.
- **Authentik task log purge — weekly Guard Dog timer (D)** — New `takauthentiktasklogpurge.timer` (Sundays 03:00). Deletes `authentik_tasks_task` and `authentik_tasks_tasklog` rows older than 30 days, then `VACUUM ANALYZE`. Without this, these tables grow to 500–900 MB after ~1 month (88%+ of the Authentik DB), causing autovacuum lag and CPU spikes. Guard Dog page shows last-run timestamp.
- **Console Rollback → Guard Dog page (E)** — Removed the yellow rollback banner from the Console (home) page. New **Console Rollback** card on the Guard Dog page shows the previous version and "Roll Back" button. If no previous version exists, shows a greyed-out "No previous version available" state.
- **Fix: CloudTAK deploy hanging / "failed to deploy"** — Three overlapping bugs: (1) `cap_drop: ALL` in the CloudTAK override silently broke nginx workers; (2) a Caddy exception in Step 7 marked the entire deploy failed; (3) the JS polling loop stopped permanently on fetch errors, so users saw failure even when the deploy succeeded.
- **Fix: TAK Portal `cap_drop` on fresh deploy** — Fresh TAK Portal deploys were still injecting `cap_drop: ALL`, preventing Node.js from reading `tak-client.p12` (dashboard showed `--` for all stats).
- **Fix: CloudTAK Reset Config** — "Key (username)=(…) already exists" error on reconfiguration. Now uses `TRUNCATE profile CASCADE` to clear all FK-dependent tables before restarting the API container.
- **Fix: Fail2ban / Scheduler toggles double-fire (issue #21)** — Removed redundant `onclick` from all 7 `*-toggle-track` spans; disabling jails now works correctly.
- **Fix: Snapshot TAK Server version shown as `?`** — Version detection now runs in the upload endpoint and the two-server SSH path, not only in the local snapshot path.
- **Fix: TAK Server page JS syntax error** — `font-family:'JetBrains Mono'` in a JS string caused `Uncaught SyntaxError: Unexpected identifier 'JetBrains'`, breaking all card expand/collapse on the TAK Server page.

Full notes: [docs/RELEASE-v0.9.5-alpha.md](docs/RELEASE-v0.9.5-alpha.md).

---

### v0.8.9-alpha — 2026-05-01

**Headline: Authentik security — real client IP fix (fleet-wide silent bug since the Caddy→Authentik wiring shipped).**
- **THE BUG:** Every Authentik login event (successful, failed, timed-out) on every infra-TAK install has been recorded with `client_ip: "172.18.0.1"` — the Docker bridge gateway — instead of the real public IP of the user's device. Root cause: `AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS` defaults to "trust nothing" in Authentik. Caddy forwards `X-Forwarded-For` correctly but Authentik discards it. Same silent-default pattern as the v0.8.7 `AUTHENTIK_WEB__WORKERS` bug — same official docs page. Impact: audit logs wrong since the project began; Reputation policy (v0.9.0) would be useless; fail2ban would ban `172.18.0.1` (the Docker gateway) and DoS the entire stack.
- **Fix:** NEW idempotent migration `_authentik_fix_trusted_proxy_cidrs(plog)` appends `AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS=172.16.0.0/12,127.0.0.1/32,::1/128` to `~/authentik/.env`. `172.16.0.0/12` covers all Docker bridge subnets fleet-wide. Idempotent — operator-set values are never overwritten. Triggers `_recreate_authentik_server_worker` (server+worker only, LDAP outpost untouched). Wired into `_startup_migrations` AND `_post_update_auto_deploy`; runs after the v0.8.8 recursion fix to batch restarts on old boxes. Persists `last_outcome` to `settings.authentik_trusted_proxy_cidrs_fix`.
- **Verifier extended** — 4th probe reads `listen.trusted_proxy_cidrs` from `ak dump_config`, asserts `172.16.0.0/12` is present. Success log includes `trusted_proxy_cidrs=172.16.0.0/12`.
- **Migration window:** ~35-60s on first upgrade (server+worker recreate + verifier run); sub-second no-op on every subsequent restart. LDAP outpost stays up — TAK Server clients and field users unaffected.
- **Validated May 1 2026** on tak-10 and responder: `ak dump_config` confirms CIDRs loaded; `ak shell` query on `Event.objects.filter(action='login_failed')` returns real WAN IP `174.244.110.118` (not `172.18.0.1`). Overnight soak both boxes: `idempotent-noop` + verifier `pass`.
- **No UI changes.** fail2ban and Authentik Reputation policy parked to v0.9.x — this fix is a prerequisite for both.

Full notes: [docs/RELEASE-v0.8.9-alpha.md](docs/RELEASE-v0.8.9-alpha.md). Plan: [docs/PLAN-v0.8.9.md](docs/PLAN-v0.8.9.md).

---

### v0.8.8-alpha — 2026-04-30

**Headline: LDAP flow stage-binding recursion fix — latent fleet-wide bug since the LDAP feature shipped.**
- **THE BUG:** Every infra-TAK install since the LDAP feature shipped has had `evaluate_on_plan=true` AND `re_evaluate_policies=true` on all three `ldap-authentication-flow` stage bindings. That combo causes a **cascading policy re-evaluation** on every step of every authentication plan — each step re-runs all policy lookups, which re-triggers plan generation, which re-evaluates policies, ad infinitum. Authentik 2025.10+ uses Postgres for cache + channels + tasks (no Redis), and `policybindingmodel` has only the PK as an index, so each cascading lookup is a sequential scan. **Fast-disk boxes hide it** (queries complete in microseconds); **slow-disk boxes explode** under it.
- **THE SMOKING GUN:** Apr 30 2026 on a buddy's slow-disk SSDNodes box (1795 random-write 4k IOPS, 31.7 MB/s sequential write — between spinning rust and slow SATA SSD): Postgres CPU pinned at **900-1500% sustained** with five PG backends running 86-second `policybindingmodel` queries on a box doing **0.36 LDAP binds/sec**. Setting `evaluate_on_plan=false` (matches `default-authentication-flow`, which has zero recursion and works fine on every box) + `docker restart authentik-server-1` dropped Postgres CPU **~115x in 60 seconds** (~900% → ~7.8%). Zero long-running queries persisted. LDAP outpost StartedAt unchanged.
- **Fix shipped in three places.** (1) Two YAML blueprint copies in `app.py` — six occurrences of `evaluate_on_plan: true` flipped to `false` on the three `ldap-authentication-flow` stage bindings. `re_evaluate_policies: true` preserved (matches default flow, not part of the recursion combo). (2) `_ensure_ldap_flow_authentication_none()` healing function — same fix on the healing path so post-update healing doesn't re-introduce the bug. (3) NEW idempotent self-healing migration `_authentik_fix_ldap_flow_recursion(plog)` — counts bad bindings via SQL on every console startup AND post-update; if `count > 0`, runs UPDATE and restarts `authentik-server-1` ONLY (server alone — never `--no-deps server worker`, never LDAP outpost) to clear the in-memory flow plan cache.
- **Audit trail.** Persists outcome to `settings.authentik_ldap_flow_recursion_fix` (`fixed` / `idempotent-noop`) so operators can see exactly what happened. Hooked into `_startup_migrations` (every console start) and `_post_update_auto_deploy` (after every update). On a healthy/v0.8.8-clean box: one COUNT query + one settings.json write per startup (~10ms cost).
- **Cardinal rule honored.** `docker restart authentik-server-1` (server alone, ~5-10s blip) — gentler and faster than `_recreate_authentik_server_worker`'s full compose recreate. The worker container doesn't cache flow plans; only the server does. LDAP outpost (`authentik-ldap-1`) is never touched. No thundering herd.
- **No UI changes.** Same scope discipline as v0.8.7. The rollback feature originally planned for v0.8.8 is **parked to v0.9.0 or later** — Authentik stabilization is the sole priority on the v0.8.x line until the fleet is provably stable across slow disks.
- **Fleet impact.** tak-10, responder, ssdnodes-validated, Alex's R3930 — all currently on v0.8.7-alpha and **all still have this latent bug** (fast-disk masking). After they pull v0.8.8 the migration fires once on the next console startup, audit shows `last_outcome='fixed'`, `last_bad_count=3`. Their CPU samples should show measurable drops (less dramatic than ssdnodes since their disks were hiding more, but real).

Full notes: [docs/RELEASE-v0.8.8-alpha.md](docs/RELEASE-v0.8.8-alpha.md). Plan: [docs/PLAN-v0.8.8.md](docs/PLAN-v0.8.8.md). Incident writeup: [docs/HANDOFF-LDAP-AUTHENTIK.md](docs/HANDOFF-LDAP-AUTHENTIK.md) → "April 2026 — v0.8.8 LDAP FLOW STAGE-BINDING RECURSION FIX".

---

### v0.8.7-alpha — 2026-04-30

**Headline: Authentik stability — env var name fix (silent-ignore bug since v0.8.2) + official tunings + runtime-config verifier.**
- **THE BUG WE'VE BEEN CARRYING SINCE v0.8.2:** `AUTHENTIK_WEB_WORKERS=4` (single underscore) was being silently ignored by Authentik 2026.x. Per the [official Authentik docs](https://docs.goauthentik.io/install-config/configuration/), the correct name is `AUTHENTIK_WEB__WORKERS` (DOUBLE underscore — *"the double-underscores are intentional"*). On Apr 30 2026, `docker top authentik-server-1` on tak-10 showed only **2 gunicorn workers** despite our `.env` saying 4. Every box in the fleet has been running with half the workers we thought, since late April 2026. **Fix:** the new `_authentik_apply_official_tunings(plog)` removes the wrong-name line and writes the correct double-underscore form on every box. Idempotent. Only adds keys that are missing — never overwrites operator-set values.
- **Cache and log tunings (also never applied):** `ak dump_config` revealed `cache.timeout_flows=300`, `cache.timeout_policies=300`, `log_level=info` — all defaults, every box. `_authentik_apply_official_tunings` now adds `AUTHENTIK_CACHE__TIMEOUT_FLOWS=600`, `AUTHENTIK_CACHE__TIMEOUT_POLICIES=600`, `AUTHENTIK_LOG_LEVEL=warning` (only if missing). Reduces DB pressure (cached flows/policies don't re-evaluate every 5 min) and log overhead.
- **Runtime config verifier** — new `_authentik_verify_runtime_config(plog)` closes the audit loop. Runs `docker exec authentik-worker-1 ak dump_config`, parses JSON, counts actual gunicorn workers via `docker top`. Persists pass/fail to `settings.authentik_runtime_config_check`. We can never have this silent-default scenario again.
- **`_recreate_authentik_server_worker(plog, reason)`** — single source of truth for env-var-change → server recreate. Runs `docker compose up -d --force-recreate --no-deps server worker`. **Never touches `ldap`** (preserves bind cache, zero thundering-herd risk — the cardinal rule of all v0.8.x Authentik migrations). Called by `_startup_migrations` and `_post_update_auto_deploy` only when env vars actually changed. Records outcome to `settings.authentik_last_recreate`.
- **Validated tak-10 Apr 30 2026:** 4 gunicorn workers running (was 2), `ak dump_config` confirms cache=600s and log_level=warning (were defaults), 3-min CPU soak with 351 real binds → server p50 **2.1%**, postgres p50 **0.0%** (was 99%/94% on v0.8.6 under same load). ~47x reduction at p50, with zero LDAP impact.
- **Deleted before ship (band-aids built on the wrong "state drift" theory):** the daily 04:00 periodic restart, the reactive ASGI WebSocket loop trigger, and the admin-API safety gate were all built and then removed once the real env var bug was found. With 4 workers actually running and the cache tunings active, none are needed. ~200 lines of code removed in the cleanup.
- **No UI changes.** Operator was explicit: "I just want an update to work for now. No UI changes."
- **Cursor rule shipped:** [`.cursor/rules/consult-upstream-docs.mdc`](.cursor/rules/consult-upstream-docs.mdc) (alwaysApply) institutionalizes the lesson — read official docs before chasing symptoms; never trust `.env` to mean the runtime is using it; always verify with the project's introspection command (`ak dump_config`, etc.). Five releases of band-aids would have been one PR if we'd read the docs first.

Full notes: [docs/RELEASE-v0.8.7-alpha.md](docs/RELEASE-v0.8.7-alpha.md). Plan: [docs/PLAN-v0.8.7.md](docs/PLAN-v0.8.7.md). Incident writeup: [docs/HANDOFF-LDAP-AUTHENTIK.md](docs/HANDOFF-LDAP-AUTHENTIK.md) → "April 2026 — v0.8.7 SILENT-IGNORE env var name bug" and "April 2026 — v0.8.7 band-aids that were built then DELETED before ship".

---

### v0.8.6-alpha — 2026-04-29

**Headline: Azure / NAT deploy reliability — four field bugs fixed during first Azure deployment test (`tak-test-3`, D8as_v5, P10 64 GiB OS disk, ~145 MB/s sync write).**
- **Authentik containers never started on slow-disk Azure VMs.** Step 7 (`docker compose up -d`) was nested inside `elif needs_pg_update:` which is always `False` on fresh deploys — containers never launched, API poll ran 900 s, operator had to SSH and run compose manually. Fixed by un-indenting 121 lines so the bring-up runs unconditionally.
- **`start.sh` showed private IP on Azure/AWS NAT.** `hostname -I` returns `10.0.x.x` on NAT VMs. Fixed: `curl api.ipify.org` (3 s timeout, graceful fallback); when public ≠ private both are displayed; single-line output preserved on direct-IP VPS.
- **Dashboard disk I/O showed cached vmstat speed (998 MB/s) instead of real sync speed (145 MB/s).** Guard Dog's `diskio_history.csv` (already uses `oflag=dsync` every 15 min) is read first; vmstat fallback now labeled "(vmstat, cached)"; manual test switched to `oflag=dsync`.
- **LDAP SA bind check reported failure even when LDAP was working.** Two bugs: ldapsearch searched `dc=takldap` (base scope) — Authentik returns LDAP error 32 there even on success. Fixed: `ou=users,dc=takldap` one-level + `cn=adm_ldapservice`. Race: `sleep(2)` was too short on Azure; fixed: `sleep(5)`, `--since 90s`, direct Docker-log fallback.
- All four transparent on SSD Nodes / DigitalOcean / non-NAT fast-disk VPS.

Full notes: [docs/RELEASE-v0.8.6-alpha.md](docs/RELEASE-v0.8.6-alpha.md).

---

### v0.8.5-alpha — 2026-04-28

**Headline: proactive LDAP routing migration + gunicorn timeout bump + verifier hardening (responder + tak-10 field tests)**
- **Proactive routing migration** — new `_ensure_authentik_ldap_outpost_on_fqdn()` migrates the LDAP outpost from internal direct routing (`http://authentik-server-1:9000`) to FQDN routing (`https://<fqdn>`) BEFORE a spiral manifests. Gated on `/opt/tak` installed (heavy load profile) + FQDN configured + Caddy reachable. Catches the responder-class latent misroute that the reactive detector cannot see — cached service-account session masks the spiral until the first fresh bind. Runs on Authentik deploy / TAK Server deploy / every Update Now / every 10 min via spiral monitor. Idempotent; no-op on FQDN-routed and console-only boxes.
- **Gunicorn worker timeout 30s → 120s** — new `_ensure_authentik_gunicorn_timeout()` appends `GUNICORN_CMD_ARGS=--timeout=120` to `~/authentik/.env` once and recreates only the Authentik server container. Closes the SIGABRT cascade on heavy-LDAP-load boxes (tak-10: 3.5+ binds/sec) where Authentik 2026.2.2's flow planner exceeds the upstream-default 30s gunicorn timeout, gunicorn kills the worker mid-request, in-flight TCP connections drop, Caddy returns 502, outpost retries, recursion. Idempotent — never overwrites operator override; safe everywhere because timeout never fires on fast boxes. Hooked into Authentik deploy / TAK Server deploy / Update Now (NOT periodic monitor — one-shot config). Outcome persisted to `settings.authentik_gunicorn_timeout_migration`.
- **Verifier hardening** — `_test_ldap_bind_dn` now wraps tri-state `_test_ldap_bind_dn_verdict()` (`'ok' | 'fail' | 'inconclusive'`). `_ensure_authentik_webadmin` no longer triggers DELETE+POST recreate of `webadmin` on inconclusive verdicts (which was the root cause of the responder `400 username must be unique` regression). On confirmed-fail, re-queries Authentik before POSTing to confirm DELETE actually completed. Auto-installs `ldap-utils`/`openldap-clients` to make decisive verdicts the norm.
- **Dual-signal spiral detection with two-tier markers** — field testing of v0.8.4 on busy boxes (Mission API / DataSync) showed high-volume `Bind request` traffic could push spiral markers off the `--tail 200` window. v0.8.5 dev testing on tak-10 caught a second issue: treating all markers equally produced false positives from transient container restart artifacts. New `_detect_authentik_ldap_spiral()` confirms a spiral via **either** signal: ≥**1 spiral-specific marker** in last **1000** outpost log lines (`result code 50`, `nil pointer`, `exceeded stage recursion`, 502, 503 — these don't appear on healthy boxes), **or** ≥30 connections in `idle in transaction` from `application_name LIKE '%authentik%'` in Postgres. General markers (`failed to execute flow`, `EOF`) are tracked for forensics but never trip alone — they appear from user typos and normal LDAP disconnects.
- **Periodic self-healing monitor** — new `_authentik_spiral_monitor()` daemon thread runs every 10 minutes; calls the proactive routing function first, then the reactive detector + repair. Same gates, same Caddy probe, same auto-rollback. Single-instance PID-checked lock (only one gunicorn worker runs the monitor). Reactive repair rate-limited to 1 per 6 hours; attempts persisted to `settings.authentik_spiral_last_repair`. Proactive migration outcome persisted to `settings.authentik_proactive_routing_migration`.
- **Granular gate logging** — every early-return in the routing repair now logs why it skipped, under the `routing repair: ...` / `proactive routing: ...` / `gunicorn timeout: ...` prefix. Silent skips can no longer hide bugs.
- No UI changes. Pure backend self-healing.

Full notes: [docs/RELEASE-v0.8.5-alpha.md](docs/RELEASE-v0.8.5-alpha.md).

---

### v0.8.4-alpha — 2026-04-28

**Fix: reverse v0.8.0 LDAP outpost routing for boxes spiraling on direct internal URL**
- v0.8.0 switched the LDAP outpost from `https://<fqdn>` (via Caddy) to `http://authentik-server-1:9000` (direct). On busy installs, that bypassed Caddy's request shaping and exposed Authentik 2026.2.2's slow `policybindingmodel` flow evaluation, producing a Postgres query storm (200+ active queries) and outpost panic loop.
- New post-update migration `_apply_authentik_ldap_routing_repair` detects the spiral (`Result Code 50` / `nil pointer` / `EOF` / `503` markers in outpost logs), probes that the FQDN actually serves through Caddy, and reroutes the LDAP outpost back to `https://<fqdn>` + `extra_hosts:host-gateway`. Only the LDAP container is recreated; server/worker/db are untouched. Validates within 30s; auto-rolls-back on failure.
- `needs_pg_update` generalized to detect any `idle_in_transaction_session_timeout` value other than `30s` (was hardcoded list; missed manual values like `15s`).
- No-ops on healthy boxes, on already-FQDN-routed boxes, on boxes without an FQDN configured, and on boxes where Caddy isn't ready.

Full notes: [docs/RELEASE-v0.8.4-alpha.md](docs/RELEASE-v0.8.4-alpha.md).

---

### v0.8.3-alpha — 2026-04-28

**Fix: reduce `idle_in_transaction_session_timeout` to prevent Postgres exhaustion**
- Authentik's enterprise license check leaks `idle in transaction` connections; with the old 120s timeout they pile up fast enough to exhaust the Postgres connection pool and spike CPU to 500–800%.
- `idle_in_transaction_session_timeout` reduced from 120s to 30s. PostgreSQL container is auto-recreated by the migration to apply the new command-line arg.

Full notes: [docs/RELEASE-v0.8.3-alpha.md](docs/RELEASE-v0.8.3-alpha.md).

---

### v0.8.2-alpha — 2026-04-28

**Fix: auto-set `AUTHENTIK_WEB_WORKERS=4` on update**
- Post-update migration now sets `AUTHENTIK_WEB_WORKERS=4` in `~/authentik/.env` if not already at 4+, then restarts only the server container (ldap untouched, bind caches preserved).
- Prevents thundering-herd overload on active deployments after restarts.

Full notes: [docs/RELEASE-v0.8.2-alpha.md](docs/RELEASE-v0.8.2-alpha.md).

---

### v0.8.1-alpha — 2026-04-28

**Hotfix: v0.8.0 post-update migration caused CPU spike and Postgres exhaustion**
- v0.8.0's migration patched `AUTHENTIK_HOST` and restarted the LDAP outpost on all existing installs, including healthy ones. Restarting the outpost clears all cached bind sessions — with active TAK clients this triggered a thundering-herd reconnect storm, exhausting Postgres connections and pegging CPU.
- Fix: migration now checks whether the outpost is connected (websocket + no TLS errors in recent logs) before touching anything. Skipped on healthy outposts.

Full notes: [docs/RELEASE-v0.8.1-alpha.md](docs/RELEASE-v0.8.1-alpha.md).

---

### v0.8.0-alpha — 2026-04-28

**Bug fix: LDAP outpost `tls: internal error` on fresh installs**
- On new deployments with an FQDN configured, the LDAP outpost was generated with `AUTHENTIK_HOST: https://<fqdn>` instead of the internal Docker service URL. On first boot, Caddy hasn't finished its ACME challenge yet, so it sends a TLS `internal_error` alert. The LDAP outpost then enters exponential backoff (3s → 6s → 12s → … → 12+ min between retries) and never recovers on its own.
- Fix: all three code paths that generated or overwrote the LDAP outpost URL now unconditionally use `http://authentik-server-1:9000`. No `extra_hosts` entry is generated.
- Auto-heals on update: post-update migration patches any existing broken `docker-compose.yml` and restarts the `ldap` container.

Full notes: [docs/RELEASE-v0.8.0-alpha.md](docs/RELEASE-v0.8.0-alpha.md).

---

### v0.7.2-alpha — 2026-04-24

**Patch: Node-RED EACCES crash on first update from older installs**
- `docker cp` writes files as root; Node-RED runs as `node-red` → permission denied on `/data/context/global/global.json` at startup.
- Fix: `chown -R node-red:node-red /data/context` after every `docker cp` in `deploy.sh` and `app.py` migration path.

Full notes: [docs/RELEASE-v0.7.2-alpha.md](docs/RELEASE-v0.7.2-alpha.md).

---

### v0.7.1-alpha — 2026-04-24

> ⚠️ **Existing deployments:** TAK Server page → **Resync LDAP to TAK Server** after pulling.

- **Critical: Node-RED configs no longer wiped on Update Now** — older installs without `contextStorage: localfilesystem` lost all Configurator configs on any container restart. Fix: `_auto_nodered_settings()` detects missing storage, exports live in-memory context to disk via REST API before patching, then migrates to filesystem storage. `deploy.sh` also uses REST API backup first.
- **Tablet Command AVL** — stream fire/EMS vehicle positions from Tablet Command Feature Services to ATAK as live CoT events. Per-agency config cards with known-units CSV remapping table (custom callsigns + CoT type overrides). CoT type auto-detected from radio name prefix.
- **LDAP password propagation** — `ldap-authentication-login` stage `session_duration` fixed from `seconds=0` (24-hour cache) to `seconds=120`. Password changes take effect in 2 minutes. Self-healing via Resync.
- **ArcGIS save hang fixed** — `TypeError: configs.findIndex` caused save to hang indefinitely when context stored as stringified array after deploy/restore. Fixed with `_coerceArr()` in all CRUD mutators + `unwrapCtxVal` patched to prevent re-corruption.
- **External DB** — deploy TAK Server against AWS RDS, Azure Database for PostgreSQL, Google Cloud SQL, or any PostgreSQL 15 host. Test Connection button, Guard Dog cloud-aware alerts, full setup guide in `docs/EXTERNAL-DB-SETUP.md`.
- **Cert display** — cert card green at ≥30 days, red at <30 days (renewal ran and failed). No more false orange at 40 days. Guard Dog alert threshold corrected to 25 days.

Full notes: [docs/RELEASE-v0.7.1-alpha.md](docs/RELEASE-v0.7.1-alpha.md).

---

### v0.7.0-alpha — 2026-04-22

**IPAWS — timer-based KML cache, zone polygons, NAPSG icons**
- Timer-based KML cache with configurable poll interval; NWS zone polygon fetch; NAPSG Public Alert icons via CDN; Deploy/Deactivate button in Configurator.

Full notes: [docs/RELEASE-v0.7.0-alpha.md](docs/RELEASE-v0.7.0-alpha.md).

---

### v0.6.6-alpha — 2026-04-20

**Guard Dog — disk I/O alerts fixed + controls; Node-RED — safe deploy + KML polish**
- **Disk I/O watch script:** **`bc`** percentage fix — no more false **100%** “drop” when 1h and 24h averages differ slightly.
- **Guard Dog UI:** turn **disk I/O benchmark** on/off (systemd timer); turn **email/SMS for disk I/O only** on/off (other alerts unchanged). Settings sync to **`takdiskioguard.timer`** and **`/opt/tak-guarddog/diskio_email_off`**.
- **`nodered/deploy.sh`:** **stop container → write merged flows → restore Node-RED global/flow context → start** so Configurator-backed **`global.json`** is not wiped during deploy.
- **KML engine:** removes **`require()`** from the polling path (sandbox-safe **`FN_KML_CHECK_NL`** + HTTP nodes).
- **KML Configurator:** Step 3 Save toolbar matches ArcGIS; **auto-fetch on reopen**; blank defaults on fresh Fetch; **Google Earth / ArcGIS / FAA** logos on nav and source-type buttons.

Full notes: [docs/RELEASE-v0.6.6-alpha.md](docs/RELEASE-v0.6.6-alpha.md). Node-RED pointer: [nodered/CHANGELOG-nodered-v0.6.6-alpha.md](nodered/CHANGELOG-nodered-v0.6.6-alpha.md). Maintainer pre-release: [docs/TESTING-UPDATES.md](docs/TESTING-UPDATES.md); Node-RED smoke tests: [docs/TESTING-NODERED-DEPLOYS.md](docs/TESTING-NODERED-DEPLOYS.md). Selective merge + tag: [docs/COMMANDS.md](docs/COMMANDS.md) → *Merge dev → main (selective — release only)*.

---

### v0.6.5-alpha — 2026-04-17

**Node-RED Configurator — stable ID pills, compound UIDs, strict reconcile + Purge**
- **Stable-ID Step 3** is now a **multi-select pill picker** (0 / 1 / N fields): **compound UIDs** (`c` + hash) for feeds with no single stable column (NOAA FLOOD / STORM OBJECTID rotation).
- **Multi-layer feeds:** picker shows the **union of fields** across all selected layers with **`(in X/N)`** badges; partial-presence pills are dimmed so operators avoid foot-guns.
- **Strict mission ownership** (Step 5, default on for new configs) + **Purge Orphans** per config card — cleans orphan mission UIDs from past `idField` / `uidPrefix` edits; **strict is auto-disabled on multi-layer per-layer passes** so sibling layers do not delete each other.

Full notes: [docs/RELEASE-v0.6.5-alpha.md](docs/RELEASE-v0.6.5-alpha.md). Node-RED pointer: [nodered/CHANGELOG-nodered-v0.6.5-alpha.md](nodered/CHANGELOG-nodered-v0.6.5-alpha.md).

---

### v0.6.4-alpha — 2026-04-16

**Patch — VERSION / tag alignment for Update Now**
- Bumps **`VERSION`** to **`0.6.4-alpha`** so the checked-out tag and sidebar match, the update banner clears, and **post-update auto-deploy** (Guard Dog, Node-RED `deploy.sh` flow sync) runs after upgrade. No change to shipped Node-RED flows vs v0.6.3 content.

Full notes: [docs/RELEASE-v0.6.4-alpha.md](docs/RELEASE-v0.6.4-alpha.md). Node-RED pointer: [nodered/CHANGELOG-nodered-v0.6.4-alpha.md](nodered/CHANGELOG-nodered-v0.6.4-alpha.md).

---

### v0.6.3-alpha — 2026-04-17

**Node-RED Configurator — multi-layer, per-class styling, epoch-ms time**
- **Multi-layer** ArcGIS configs (one wizard, multiple layers); **multi-geometry** (point + polygon) with geometry-aware Step 4.
- **Step 3c class mapping:** per-class icons, ATAK color swatches, **no-color** option, template **label** and **remarks** with pill field toggles; **ALL CAPS** callsign option.
- **Epoch-millisecond time field** for rolling windows on numeric epoch columns (e.g. NOAA storm reports).
- **Template export/import** for reusable feed JSON.
- **Reconciliation:** global `_lastPoll`, duplicate tab dedup on deploy, stable polygon hash, `_subscribed` reset — fewer spurious ATAK notifications after deploy.
- **UI fixes:** Step 4 visible for point + class mapping; `resetForm()` on config switch so fields don’t leak between saved feeds.

Full notes: [docs/RELEASE-v0.6.3-alpha.md](docs/RELEASE-v0.6.3-alpha.md). Node-RED file list: [nodered/CHANGELOG-nodered-v0.6.3-alpha.md](nodered/CHANGELOG-nodered-v0.6.3-alpha.md).

---

### v0.6.2-alpha — 2026-04-16

**Node-RED DataSync — enterprise operator path**
- Shipped **`flows.json`** has **no** static example ArcGIS feeds (`FEEDS` empty in `build-flows.js`). Feeds are created only in the **Configurator** (dynamic tabs; `deploy.sh` merge + template sync preserves them).
- **Console** Node-RED **docker-compose** mounts **`/opt/tak/certs/files:/certs:ro`**, **`extra_hosts: host.docker.internal:host-gateway`**; **first deploy** runs **`nodered/deploy.sh --no-pull`**. **Post-update** patches existing compose if needed and syncs flows.
- **TLS:** `tls_tak` does not ship hardcoded cert paths in git; **`deploy.sh`** fills **`/certs/admin.pem`** when present on host. Operators enter the **private key passphrase** in the Node-RED editor and **Deploy**.
- **ArcGIS:** stable feature hashing (geometry + mapped fields); recommend **IncidentId** (or **GlobalID**) instead of **OBJECTID** for feeds where IDs fluctuate.
- **Configurator** copy explains TAK TLS + passphrase step.

Full notes: [docs/RELEASE-v0.6.2-alpha.md](docs/RELEASE-v0.6.2-alpha.md). Node-RED detail: [nodered/CHANGELOG-nodered-v0.6.0-alpha.md](nodered/CHANGELOG-nodered-v0.6.0-alpha.md).

---

### v0.6.1-alpha — 2026-04-16

**Patch release** — version bump to ensure all boxes (including those that fetched the original v0.6.0-alpha tag) receive the disk I/O monitor fix via Update Now. No functional changes beyond the version string.

---

### v0.6.0-alpha — 2026-04-16

**Guard Dog — Disk I/O Performance Monitor**
- Automated 15-minute `dd` benchmarks logged to CSV (30-day retention). Alerts when last-hour average drops below 50 MB/s or falls 70%+ from the 24h rolling average (noisy-neighbor detection). Email + SMS via Guard Dog alert pipeline.
- Dashboard card with color-coded stats (current, 1h avg, 24h avg, min/max), interactive sparkline chart with warning threshold line, time range dropdown (24h–30d), and CSV report download. Chart timestamps in user's local timezone.
- Auto-deploys with Guard Dog — `takdiskioguard.timer` created and enabled alongside existing monitors.

**VPS memory stability — swappiness tuning**
- Guard Dog deploy sets `vm.swappiness=10` (persistent + immediate). Prevents aggressive swapping on VPS with slow disk I/O, which was the #1 cause of "struggling" servers with plenty of free RAM.

**Postfix installation fix**
- `debconf-set-selections` preseeds `postfix/mailname` and `postfix/main_mailer_type` before install. Fixes `meter mydomain: bad parameter value: 0` failure on some systems.

**Node-RED — ArcGIS DataSync & FAA TFR Configurator (new)**
- Stream ArcGIS Feature Service data (wildfire perimeters, weather alerts, infrastructure, custom layers) and FAA Temporary Flight Restrictions into TAK Server missions as live CoT objects.
- Web-based configurator UI inside Node-RED — no flow editing required. Add feeds, pick fields, set poll intervals, click Deploy.
- Access at `https://nodered.<your-fqdn>` → Configurator tab.
- Non-destructive updates: user flows, feed configs, TLS, TCP settings, and credentials all survive `deploy.sh` runs. Template sync auto-updates function code in existing tabs.
- Ships with cold-start guards (no post-restart churn), stable ArcGIS hashing, FAA TFR ID fix, and per-feed label/capitalize options.

Full notes: [docs/RELEASE-v0.6.0-alpha.md](docs/RELEASE-v0.6.0-alpha.md).

---

### v0.5.9-alpha — 2026-04-10

**Boot sequence hardening — cold reboot to full stack in under 5 minutes**
- **Guard Dog Boot Sequencer** stops all Docker containers on boot so TAK Server gets exclusive CPU during its ~100s Java initialization. Nothing else starts until port 8089 is listening.
- **Authentik staggered start** — PostgreSQL starts first, waits for `pg_isready`, then server/worker/LDAP come up in order. Eliminates "too many clients already" connection storms.
- **PostgreSQL tuning (idempotent)** — `max_connections=300`, idle session timeouts, TCP keepalives baked into compose. New `_ensure_authentik_compose_patches()` helper runs on every deploy/reconfigure/update so tuning can never silently disappear after upgrades.
- **Priority service ordering** — TAK Server → Authentik → TAK Portal (critical trio, under 3 min). CloudTAK and Node-RED get 30s stagger delays to prevent Docker iptables churn from disrupting active TAK client connections.
- **Tested cold boot:** TAK Server ready ~100s, Authentik healthy +54s, TAK Portal +12s, full stack ~4:42. Zero PG errors, zero LDAP 502s, LDAP binds under 1ms.

Full notes: [docs/RELEASE-v0.5.9-alpha.md](docs/RELEASE-v0.5.9-alpha.md).

---

### v0.4.7-alpha — 2026-04-08

**Auto-deploy on update** — Guard Dog, Authentik, TAK Portal, and CloudTAK configs are all automatically re-deployed when a version change is detected. No manual button presses after console updates. Authentik, TAK Portal, and CloudTAK run in parallel. Console cards show "Updating config..." while each service reconfigures. TAK Server and other services stay running throughout.

**Online database repack (pg_repack)** — new weekly Guard Dog script reclaims actual disk space from the CoT database without downtime. Runs Sunday 4 AM, auto-installs pg_repack, works in both local and two-server mode.

**Boot sequencer — two-server fix** — `tak-boot-sequencer.sh` no longer hangs for 2 minutes on two-server setups trying to reach a local PostgreSQL that doesn't exist. Detects remote DB from `guarddog.conf` or `CoreConfig.xml` and checks via TCP, completing instantly.

**TAK Portal Guard Dog monitor** — new container health monitor with alert + auto-restart after 3 failures. Previously TAK Portal had no monitoring — if it crashed, nobody knew.

**Smart Guard Dog UI** — shows "up to date" when config is current; "Update Guard Dog" button only appears when settings have changed.

**CloudTAK security fix** — removed `NODE_TLS_REJECT_UNAUTHORIZED=0` from CloudTAK `.env` and `docker-compose.override.yml` (flagged by CloudTAK developer as security flaw). Applied automatically on upgrade.

**Remote DB monitor fix** — TCP+SSH monitor now correctly shows red when Server One is unreachable (was falsely showing green).

**Guard Dog config drift prevention** — `guarddog.conf` auto-syncs with settings.json on every console startup, preventing stale remote DB IPs after migration.

### v0.4.6-alpha — 2026-04-07

**Staggered boot sequencer — cold reboot to full stack healthy in ~2 minutes**
- Full boot orchestration: pre-start stops all Docker services and waits for PostgreSQL, then TAK Server starts with exclusive CPU. Post-start waits for port 8089, then brings up Authentik (waits for healthy + LDAP 389), TAK Portal, CloudTAK, Node-RED, and MediaMTX in order. Only installed services are touched.
- Auto-restarts TAK messaging if it crashes during cold boot (config ready but messaging process died).
- Tested on fresh 12-core / 48 GB VPS (316 MB/s disk): pre-start 15s, TAK Server 9s, full stack healthy in ~2 min 15s.

**Authentik deployment resilience**
- TLS cert readiness gate: waits up to 300s for Caddy to provision a valid cert on the Authentik FQDN before restarting the LDAP outpost.
- LDAP port 389 readiness gate: waits up to 180s for the LDAP container to be listening before running bind verification.
- Improved LDAP bind verification: 24 attempts / 10s delay (was 12/5s). Log parsing prioritizes success markers over stale errors.
- Docker healthcheck `start_period` extended to 600s for Authentik server and worker (accommodates slow first-run migrations).

**Guard Dog — boot-loop prevention**
- Service-age grace (10 min), daily restart cap (3/day shared counter), clean restart (stop → kill orphans → clear Ignite → start).
- Timer delays increased to 20 min after boot.

**Certificate password fix**
- Custom cert passwords now correctly applied to all JKS files during TAK Server deploy and CA rotation. `cert-metadata.sh` is patched before cert generation with the correct variable names (`CAPASS`, `PASS`).
- All `keystorePass` and `truststorePass` attributes in CoreConfig.xml are updated to match the custom password — including `<tls>` elements that previously retained the default `atakatak`, causing TAK Server to crash with a JWT RSA key NPE on startup.
- Default password (`atakatak`) deployments were never affected.

**TAK Portal — SSH auto-configuration**
- On deploy, reconfigure, or update: generates an ed25519 keypair, installs the public key in the host's `authorized_keys`, copies the keypair into the TAK Portal container, and populates all `TAK_SSH_*` settings. No manual handshake needed.
- Only runs when TAK Server is on the same box (`/opt/tak` exists). Remote TAK Server deployments are left for manual SSH config in TAK Portal's UI.
- Existing users: click **Update Config** on the TAK Portal page to enable.

**VPS disk I/O check in installer**
- `start.sh` now runs a 256 MB write test on first boot and prints a colored speed assessment (excellent / acceptable / slow) with guidance if performance is poor.

**After upgrading to v0.4.6:** Guard Dog → ↻ Update Guard Dog, then Authentik → Update Config & Reconnect, then TAK Portal → Update Config (enables SSH). Note: v0.4.7-alpha makes all of this automatic.

Full notes: [docs/RELEASE-v0.4.6-alpha.md](docs/RELEASE-v0.4.6-alpha.md).

---

### v0.2.9-alpha — 2026-03-15

**Deep security hardening**
- Comprehensive security audit and remediation: shell injection fixes (CRITICAL/HIGH), credential handling (hardcoded passwords removed, `sshpass -e`, cert password validation), session security (cookie flags, fixation prevention, POST-only logout, XFF trust), file permissions (`settings.json` 0o600, `tempfile.mkstemp()` for sensitive temp files), information disclosure (exception truncation, secret masking in logs), and input validation (FQDN, version, `StrictHostKeyChecking`). Recommended upgrade for all deployments.

Full notes: [docs/RELEASE-v0.2.9-alpha.md](docs/RELEASE-v0.2.9-alpha.md).

---

### v0.2.8-alpha — 2026-03-20

**Security hardening**
- Input validation and sanitization across console API endpoints and internal shell commands. All user-supplied and settings-derived values that reach system commands are now validated, whitelisted, or escaped. Recommended upgrade for all deployments.

**Authentik branding**
- Starter TAK logo (`tak-gov-brand.svg`) shipped with the repo and copied to the Authentik media directory on deploy. See [docs/AUTHENTIK-LOGIN-BRANDING.md](docs/AUTHENTIK-LOGIN-BRANDING.md) for CSS, theme, and flow customization.

Full notes: [docs/RELEASE-v0.2.8-alpha.md](docs/RELEASE-v0.2.8-alpha.md).

---

### v0.2.7-alpha — 2026-03-19

**Guard Dog — alert email uses Email Relay**
- All Guard Dog **email** alerts (monitors, certificate expiry, “updates available”, etc.) now go through the **console** and the same **Email Relay** path as **Send test email** on the Guard Dog page — not the system `mail` command.
- **After upgrading:** open **Guard Dog** → **↻ Update Guard Dog** once. Set **Notifications** alert email and deploy **Email Relay**; use **Send test email** to confirm.
- **Updates email:** Reads Authentik’s installed version from `docker-compose.yml` (matches the dashboard). Does not report an update when the current version is unknown. Simpler body: only lists components with pending updates. Throttle: same set of updates ≈ one email per 24 hours until the set changes.
- **Pre-ship testing:** See [docs/TESTING-UPDATES.md](docs/TESTING-UPDATES.md) before pushing a new release tag.

Full notes: [docs/RELEASE-v0.2.7-alpha.md](docs/RELEASE-v0.2.7-alpha.md).

---

### v0.2.6-alpha — 2026-03-16

**Update Now hotfix (no rebase conflicts)**
- Fixed a field-update failure where **Update Now** could trigger rebase/cherry-pick conflict errors (`could not apply ... Add files via upload`) on some customer installs.
- Update flow now uses a deterministic **fetch + force checkout** path (latest tag, fallback `origin/main`) and first clears stale in-progress git operations (rebase/merge/cherry-pick abort attempts).
- This prevents customer boxes from getting stuck mid-update due to local branch/rebase state.

---

### v0.2.5-alpha — 2026-03-16

**MediaMTX web editor — stale overlay self-heal**
- Some upgraded infra-TAK installs had an older `/opt/mediamtx-webeditor/mediamtx_ldap_overlay.py` still injecting legacy UI logic into External Sources (duplicate Private/Share controls and broken layout). **Patch web editor** now always syncs the live overlay file from the current infra-TAK repo before restarting the web editor, so existing installs converge to the same behavior as clean deploys.

**Guard Dog — Updates monitor recovery**
- **↻ Update Guard Dog** now reinstalls `takupdatesguard.service` and `takupdatesguard.timer`, runs `daemon-reload`, and enables/starts the timer. This fixes boxes where the Updates monitor stayed red because the timer unit was missing.
- Guard Dog update UX is clearer: button text is now **↻ Update Guard Dog** and the success message auto-clears after a few seconds.

---

### v0.2.4-alpha — 2026-03-16

**MediaMTX web editor — duplicate endpoint patch**
- After deploying the LDAP overlay, the web editor could crash with Flask "View function mapping is overwriting an existing endpoint" for shared and share-links routes. The console now applies an **endpoint patch** (shared_stream_page, shared_hls_proxy, api_share_links_list, api_share_links_generate, api_share_links_revoke) so the overlay and core don't conflict. Use **Patch web editor** on the MediaMTX page if the editor is in a restart loop; the same patch runs automatically on deploy and via the heal script at service start.

**Console Update Now — no more "still see update" loop**
- **Update Now** used to only run `git pull` on the current branch. If the latest release was a tag (e.g. v0.2.3-alpha) and the branch wasn't at that commit, the restarted app still showed the old version and "Update Available" stayed. Update Now now **fetches and checks out the latest release tag** after pull, so the restarted process runs the tagged version and the banner disappears after refresh.

---

### v0.2.3-alpha — 2026-03-15

**Guard Dog**
- Update check runs every **6 hours** (configurable). When the set of available updates changes, Guard Dog sends **one email** with the full list so you're notified without inbox spam.

**Ku-band (MediaMTX web editor)**
- When the console installs or updates the **web editor**, it now copies the **simulator scripts** into the editor install so the **Simulate** link works without manual copying.

---

### v0.2.2-alpha — 2026-03-14

**CSRF behind Caddy**
- Same-origin check now uses **X-Forwarded-Host** (and X-Forwarded-Port when non-standard) so the console works when accessed through Caddy or another reverse proxy. Fixes 403 "CSRF validation failed" when clicking Update CloudTAK, Apply log limits, etc. Ensure Caddy forwards Host (e.g. `header_up Host {host}`); see COMMANDS.md.

**CloudTAK deploy and update**
- **Deploy** and **Update** both use **`docker compose build --no-cache`** so the running CloudTAK version matches the tag (e.g. v12.103.0). Previously Docker could reuse cached layers and serve an older version.
- **Deploy log** ends with explicit "Deploy finished — CloudTAK is running." (and "✓ Containers built and restarted" / "✓ Restart complete.") so you can tell when the restart is done.
- **Access** links (Web UI, Tile Server, Video, Install Dir) are hidden until deploy/update is complete.

---

### v0.2.1-alpha — 2026-03-14

**Security hardening**
- Auth header trust gated to local proxy (loopback only). CloudTAK logs endpoint hardened (container name allowlist, argv-style subprocess). TAK package uploads use `secure_filename()`. CSRF baseline: same-origin validation for state-changing APIs. Rate limiting: 12 login attempts / 5 min, 240 API writes / min per IP. Security headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, CSP, HSTS on HTTPS. See [SECURITY-AUDIT-v0.2.0-alpha.md](docs/SECURITY-AUDIT-v0.2.0-alpha.md).

**Server metrics**
- Console dashboard and module detail pages show **server metrics** (CPU, RAM, disk) for the local host and for remote deployment targets. Remote metrics are fetched via SSH so you can see resource usage per server.

**TAK Server — JVM heap**
- TAK Server page shows **recommended heap** from total RAM and **current heap** (if set via systemd drop-in). You can set a custom **JVM heap** (e.g. 4G, 8G) via the Controls area; the console writes `/etc/systemd/system/takserver.service.d/heap.conf` and restarts TAK Server.

**Guard Dog — server nickname**
- In **Guard Dog → Notifications** you can set an optional **Server nickname** (e.g. Production, Staging). Alerts then include the nickname plus IP/FQDN so you can tell which server sent the alert when monitoring multiple infra-TAK hosts. **Save email & nickname** applies the nickname without redeploying.

**CA rotation and TAK Portal**
- **Rotate CA** now **replaces the server cert** with one signed by the new CA (no "keep existing server cert" option). After rotation, users re-enroll by scanning the new QR; no need to delete the server first. **Sync TAK Server CA** button in TAK Portal (Controls) pushes `tak-ca.pem` to the portal so enrollment and API use the current CA. Revoke section hides when there are no old CAs; CA/revoke state refetches on visibility and pageshow so the Revoke option disappears after use. Deploy/sync/revoke/rotate use only `tak-ca.pem` (no caCert.p12 or transition bundle).

**Caddy — certificate expiration**
- Caddy (Let's Encrypt) **cert expiration** is shown on the **dashboard card**. On the **Caddy module page**, the top row currently shows only status and URL (e.g. "Caddy is active · test8.taktical.net"); cert expiration is not yet in that top row — planned: show it in the top row after the URL.

---

### v0.2.0-alpha — 2026-03-12

**Two-server TAK Server (split core and database)**
- Deploy TAK Server across two hosts: **Server One** (PostgreSQL database) and **Server Two** (TAK Server core). Server One is configured entirely from the console — installs PostgreSQL, opens remote access, captures the DB password, and configures `pg_hba.conf` for Server Two's IP.
- SSH key management UI: generate or use an existing key for Server One access, with a button to copy the public key.
- Per-server health monitoring: separate status dots for core and database, with dedicated **Restart DB** / **Restart Both** buttons.
- Guard Dog is two-server aware and monitors the remote database host.
- TAK Server version detection works across both hosts (`takserver-core` on Server Two, `takserver-database` on Server One).

**Remote deployments**
- Authentik, CloudTAK, MediaMTX, and Node-RED can each be deployed to a **remote host** via SSH. Choose "On another server via SSH" in the Deployment Target section, enter host/user/port, and deploy from the console.
- Remote module status (running/stopped) is checked via SSH and shown in the sidebar and console cards.
- Remote health metrics (CPU, RAM, disk) shown on module detail pages.

**Gunicorn production server (auto-upgrade)**
- The console now runs on **gunicorn** instead of the Flask dev server. Existing v0.1.x installs auto-upgrade transparently on first restart after pull — no manual steps needed.

**Staggered Docker boot**
- A systemd `docker-stagger.service` starts Docker containers in dependency order on server reboot: Authentik DB → Authentik → LDAP outpost → TAK Portal → CloudTAK DB → CloudTAK. Prevents OOM crashes and 502s from all containers starting simultaneously on small VPS. Updated automatically on every deploy/uninstall.

**Light / high-contrast mode**
- Toggle in the sidebar switches between dark mode and a high-contrast light mode designed for outdoor/sunlight use. Preference saved to localStorage and persists across sessions and pages.

**Unified controls UI**
- All module pages now have a consistent **Controls** section immediately below the status banner, matching the TAK Server page layout. Same `control-btn` styling across every page.
- **Deployment Target** sections only appear when a module is not yet deployed; once deployed, they disappear.
- All pages are full-width, flush with the sidebar.

**CloudTAK — stable release pinning and update awareness**
- Deployments pinned to the **latest stable GitHub release** instead of HEAD. Console card and detail page show **update availability** when a newer stable release exists. One-click **Update** button with glowing indicator.

**Authentik — update awareness and auto-fetch**
- Deploy automatically fetches the **latest stable Authentik release** from GitHub. Console card and detail page display update availability with glowing **Update** button.

**Authentik — reconfigure improvements (local and remote)**
- Remote reconfigure runs entirely against the remote host (SSH + API on `http://<remote>:9090`). No local `~/authentik` required.
- Local reconfigure creates/repairs all four Authentik applications (infra-TAK, MediaMTX, Node-RED, TAK Portal) and ensures all providers are on the embedded outpost.
- Outpost safety: adding a provider never removes existing ones.
- Reconfigure shows a live deploy log instead of immediate redirect.
- Enables the **show password eyeball** on all Authentik login stages (for existing deployments, run "Update config & reconnect").

**TAK Portal — updates preserve custom branding**
- All TAK Portal operations (Update, Update config, reconfigure) now preserve user-configured settings like `BRAND_LOGO_URL` (custom logo/photo). Custom branding survives all updates.

**Email Relay — Authentik SMTP auto-configuration**
- Deploying Email Relay automatically configures Authentik's SMTP settings and sets up the password recovery flow.

**Console UI and branding**
- Version display in the sidebar logo area. **Orbitron** font for "infra-TAK" in the sidebar, matching the login page.
- TAK Server and CloudTAK versions shown on console cards and detail pages.
- Module update indicators on dashboard cards.

**LDAP credential auto-resync**
- Detects when Authentik LDAP credentials have drifted from CoreConfig and auto-resyncs, preventing silent group sync failures.

---

### v0.1.9-alpha — 2026-03-04

**Guard Dog**
- Guard Dog appears in the sidebar **directly under Console** when installed (high-priority placement).
- **Apply Docker log limits** button on the Guard Dog page — set 50 MB × 3 files per container without redeploying Authentik, Node-RED, or another Docker module. Reduces risk of a single container log filling the disk (e.g. Node-RED).
- **Collapsible sections** on the Guard Dog page: Notifications, Database maintenance (CoT), and Activity log are now collapsible (click header to expand/collapse), matching the TAK Server and Help page style.
- **4GB swap on deploy** — When Guard Dog is deployed (or auto-deployed with TAK Server), the console ensures a 4GB swap file at `/swapfile` exists and is enabled. Matches the reference TAK Server Hardening script for memory stability under load.

**Connect LDAP / CoreConfig**
- When writing CoreConfig (full replace or password resync), the console ensures `adminGroup="ROLE_ADMIN"` is present in the LDAP block (adds if missing, verifies after write). Prevents wrong admin console access and "no channels" issues.

**CloudTAK**
- Step 6 waits for the CloudTAK API (`/api/connections` returns 200/401/403) before declaring backend ready, not just port 5000 — avoids 502 when Caddy proxies before the backend is up. Step 4 build output streamed; Step 5 timeout 600s.

**MediaMTX**
- Web editor systemd unit is created and enabled only when `mediamtx_config_editor.py` is present (clone or local fallback). If the editor file is missing, MediaMTX streaming still works; no restart loop. Clone uses default branch of `takwerx/mediamtx-installer`; LDAP overlay applied from repo.

**Unattended upgrades**
- Spinner on the toggle so "Disabling…" is visible while the request runs.

**Docs**
- [GUARDDOG.md](docs/GUARDDOG.md) documents the 4GB swap step and Docker log limits. [COMMANDS.md](docs/COMMANDS.md) has pull-then-restart (two steps), server impact and memory (`free -h`, `docker stats`, `top`), disk-full recovery, CloudTAK 502/backend readiness, and TAK client "no channels" / new-groups sync delay.

---

### v0.1.8-alpha — 2026-03-02

**LDAP QR Registration Fix**
LDAP application was restricted to authentik Admins, blocking QR code enrollment for non-admin users. LDAP is now open to all authenticated users. Connect LDAP / Resync LDAP applies this fix automatically.

**Fresh Deploy Flow**
8446 webadmin login and QR registration now work on initial deployment without manual Sync webadmin or Resync LDAP. LDAP outpost restart runs at end of TAK Server deploy and during Connect LDAP.

**Authentik Deploy**
Caddy reload timeout (30s) prevents indefinite hang. Progress message "Updating Caddy config..." before slow steps.

**Recommended deployment order:** Caddy → Authentik → Email Relay → TAK Server → Connect LDAP → TAK Portal → Node-RED / CloudTAK / MediaMTX

---

### v0.1.7-alpha — 2026-02-24

**Node-RED Authentik Integration**
Node-RED is now protected behind Authentik forward auth at `nodered.{fqdn}`. Requires Authentik login — same flow as TAK Portal.

**Bug Fix: Node-RED proxy provider was never created**
The provider creation payload used `authentication_flow` instead of `authorization_flow` (typo). Every POST returned 400 validation error, not "duplicate" — so the provider was never created. Also added the missing `invalidation_flow` field.

**Bug Fix: Orphaned Node-RED application**
Previous failed deploys created the application with no provider linked. The deploy now PATCHes the existing application to link the provider if it already exists.

**Bug Fix: Update mechanism didn't restart the service**
Clicking "Update Now" ran `git pull` but never restarted `takwerx-console`. Users saw "Updated!" but the old code kept running. The update now triggers a delayed `systemctl restart` after responding.

---

### v0.1.6 — 2026-02-22

**Rebranding:** Project renamed from `takwerx-console` to `tak-infra`. The console interface is now a component within the broader TAK-infra platform.

**Bug Fix: Console not loading after fresh deploy**
The auto-generated Caddyfile was missing the `tls` directive in the console reverse proxy transport block. Since the Flask app runs on HTTPS, Caddy was unable to forward requests to it, causing browsers to spin indefinitely. The TAK Server block already had the correct configuration — the console block now matches.

- `app.py`: Added `tls` to console Caddy transport block

---

### v0.1.5-alpha — 2026-02-21

**LDAP Authentication Fixed**
Authentik blueprint was setting `authentication_flow` instead of `authorization_flow` on the LDAP provider. This was the root cause of "Flow does not apply to current user" errors on every deploy since LDAP was introduced.

**Duplicate LDAP Provider Removed**
A second LDAP provider was being created via API after the blueprint, pointing to the wrong authentication flow. The API block has been removed. The deploy now waits for the blueprint worker to create the correct provider and injects its token directly.

**Token Injection Retry Loop**
LDAP outpost token fetch now retries indefinitely at 5-second intervals instead of timing out. No more manual token injection required after deploy.

**Caddy Reverse Proxy Redirect Fix**
TAK Server behind a reverse proxy was sending `Location: 127.0.0.1:8446` redirects back to the browser after login. Caddy now rewrites these headers to the correct FQDN automatically.

**TAK Portal Forward Auth**
Forward auth and invalidation flow lookups now retry indefinitely. TAK Portal deploy waits 2 minutes after completion for Authentik's embedded outpost to fully sync. Public paths bypass forward auth to support self-service enrollment.

**UX Improvements**
Deploy logs for Authentik and TAK Portal persist after completion. Completion screens show direct launch buttons for each service.

---

### v0.1.4-alpha — 2026-02-18

**GitHub Update Checker**
Switched from Releases API to Tags API — the previous implementation hit `/releases/latest` which returns 404 unless a Release is manually created on GitHub. Now uses `/tags` with semver sorting and 1-hour cache.

**Deploy State Reset**
TAK Server, Authentik, and TAK Portal pages now clear the `deploy_done` flag when services are running. Previously, refreshing after a deploy would keep showing the log instead of the running state.

**CoreConfig LDAP Auth**
`default="ldap"` preserved in the auth block — required for TAK Portal QR code enrollment.

---

### v0.1.3-alpha — 2026-02-18

**CoreConfig LDAP Auth**
`default="ldap"` preserved and File auth listed before LDAP in the auth block.

**Deploy State Reset**
All three module pages (TAK Server, Authentik, TAK Portal) now reset deploy state correctly on refresh.

---

### v0.1.2-alpha — 2026-02-17

**CoreConfig Auth Default Fix**
Changed `default` from `ldap` to `file` to fix `webadmin` access on port 8446. Password auth uses flat file, LDAP users still authenticate via the LDAP block, x509 cert auth still routes groups through LDAP.

**TAK Portal Container Log Cleanup**
Filtered `npm error`, `SIGTERM`, and `command failed` messages from container log display — these were cosmetic restart noise with no functional impact.

**Console Cross-Navigation**
Added links between Authentik, TAK Portal, and TAK Server pages.

---

### v0.1.1-alpha — 2026-02-17

**Authentik Module — Automated Deploy**
Full 10-step automated deployment: bootstrap credentials, LDAP blueprint, Docker Compose patching, API-driven token retrieval, CoreConfig.xml auto-patch, TAK Server restart. Smart API polling handles the full 503 → 403 → 200 startup progression.

**TAK Portal Module — Automated Deploy**
6-step automated deployment: repository clone, container build, TAK Server certificate copy, settings.json auto-configuration.

**Console UI**
Cross-service navigation between all module pages. Real-time step-by-step deploy logging.

---

### v0.1.0-alpha — 2026-02-16

Initial release.

- Services dashboard with live TAK Server process monitoring (Messaging, API, Config, Plugin Manager, Retention)
- Live server log streaming with color-coded ERROR/WARN highlighting
- Certificates page with file browser and direct download
- Deployment improvements: countdown timers, unattended-upgrades detection, cancel button, log reconnection
- Upload management: duplicate detection, cancellation, remove button
- Ubuntu 22.04 support

---

## License

MIT

## Credits

Built by [TAKWERX](https://github.com/takwerx) for emergency services.
