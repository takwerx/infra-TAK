# infra-TAK

Team Awareness Kit Infrastructure Management Platform.

One clone. One password. One URL. Manage everything from your browser.

**Current release: [v10.1.49-alpha](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.49-alpha)**

Older releases on the [GitHub Releases tab](https://github.com/takwerx/infra-TAK/releases) — each tag carries its full release notes.

**Something broken?** Wrong sidebar version, **Update Now** error, merge/rebase/tag-clobber messages, or you are not sure the VPS ever pulled the real repo → go to **[Universal recovery (SSH)](#universal-recovery-ssh)** and run the one block there. **Point people at that section**; it is the single source of truth.

**Universal installer.** Supported platforms: **Ubuntu 22.04 LTS**, **Rocky Linux / RHEL 9**, and **ARM64** (aarch64, e.g. Jetson Orin). The same one-clone install detects your OS, package manager (`apt`/`dnf`), and architecture and configures the firewall (ufw on Ubuntu, firewalld on RHEL) automatically. *Ubuntu is pinned to **22.04** — newer Ubuntu (24.04) and other Debian-family distros wait on TAK Server's certificate tooling supporting OpenSSL 3.x. ARM64 caveats: Cesium 3D-tiles (pmtiles) and Federation Hub are not yet available on ARM — see the release notes.*

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

**Shallow / single-branch clone** (`fetch` errors): clone the full repository (not a single-branch or shallow clone) and re-run `start.sh` from that directory.

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
- **MediaMTX** — Video streaming server for real-time feeds *(mutually exclusive with TAK Video Restreamer — they share streaming ports)*
- **TAK Video Restreamer** — Flask + MediaMTX + FFmpeg streaming server (RTSP, RTSPS, SRT, HLS ABR, RTMP, KLV) deployed as a Docker container *(mutually exclusive with standalone MediaMTX)*. Lives behind Caddy at `stream.<FQDN>`. Has its own admin login (not Authentik SSO — TVR has built-in auth); password is displayed on the module page and changeable without rebuilding the container.
- **Node-RED** — Flow-based automation engine, protected behind Authentik forward auth
- **Email Relay** — Outbound email for notifications and alerts
- **Guard Dog** — TAK Server health monitoring and auto-recovery (port 8089, processes, OOM, PostgreSQL, CoT DB size, disk, disk I/O performance, certificates; optional monitors for Authentik, Node-RED, MediaMTX, CloudTAK, Federation Hub)

No more SSH. No more editing XML by hand. No more running scripts and hoping.

## Quick Start

```bash
# Ensure git is installed (Ubuntu usually has it; bare RHEL/Rocky cloud AMIs often don't)
command -v git >/dev/null 2>&1 || sudo apt-get install -y git 2>/dev/null || sudo dnf install -y git

git clone --depth 1 https://github.com/takwerx/infra-TAK.git
cd infra-TAK
sudo ./start.sh
```

**First boot / automatic updates:** On a new Ubuntu VPS, **`apt`** may run right after SSH is available. **`systemctl status unattended-upgrades`** often shows **active (running)** for **`unattended-upgrade-shutdown`** — that idle process is **normal** and is **not** blocking installs. If **`apt-get`** still reports **“Could not get lock”**, wait until **`sudo fuser /var/lib/dpkg/lock-frontend`** shows nothing, then run **`sudo ./start.sh`** again. **`start.sh`** waits for **real** apt/dpkg activity and for **dpkg/apt lock files** before installing packages.

**Branches:** Default clone uses **main** (stable; tagged releases). For latest features and fixes before they're merged to main, use the **dev** branch: `git clone --depth 1 -b dev https://github.com/takwerx/infra-TAK.git`. The README and changelog here reflect main; dev may include remote deployment, UI tweaks, and fixes not yet in a release.

The script will:
1. Detect your OS, package manager (**Ubuntu 22.04 `apt`** or **Rocky/RHEL 9 `dnf`**), and architecture (**x86-64 or ARM64**) — and on RHEL install + start **firewalld** automatically
2. Wait if automatic updates hold **apt/dpkg**, then install Python dependencies
3. Ask you to set an admin password
4. Start the web console

Then open your browser to the URL shown and log in.

**Updating:** After `git pull` or **Update Now**, restart the console with `sudo systemctl restart takwerx-console`. Your password and config live in the install directory's `.config/`. If you run `start.sh` from a different clone or path, the service keeps using the original install directory so your password continues to work. **Node-RED / Configurator code** (`nodered/`): after pulling on the VPS, also run **`bash nodered/deploy.sh`** from that install directory.

**Guard Dog — automatic since v0.4.7-alpha:** Guard Dog scripts are automatically re-deployed when the console detects a version change. No manual button press needed after upgrading. The button still exists as a fallback if you change alert email or server nickname. Set **Notifications** → alert email and use **Send test email** to verify. Details: [docs/GUARDDOG.md](docs/GUARDDOG.md).

**Upgrading from v0.1.x to v0.2.0:** v0.2.0 switches from Flask dev server to gunicorn (production server). The upgrade is automatic — just `git pull` and restart. On first restart, the console installs gunicorn, rewrites the systemd service, and starts the production server transparently. No manual steps needed.

**Password not working after update?** Use the **backdoor**: **https://&lt;VPS_IP&gt;:5001** (on a **hardened** server that port is closed — tunnel in with `ssh -L 5001:localhost:5001 <user>@<VPS_IP>` and use `https://localhost:5001` instead; see [Recovery](#recovery--backdoor-when-authentik-or-caddy-is-broken)). If login spins or fails, on the server run (from the directory the console runs from — shown by **`systemctl cat takwerx-console | grep WorkingDirectory`**, e.g. `/opt/infratak`): **`sudo ./fix-console-after-pull.sh`** — it pins the config path in the systemd unit and prompts you to set a new password so you can log in again. Alternatively run `sudo ./reset-console-password.sh` from that same directory. After pulling, open the Caddy module and re-save your domain once so the Caddyfile (login bypass) is applied.

## Recovery / backdoor (when Authentik or Caddy is broken)

Git / version / **Update Now** issues: use **[Universal recovery (SSH)](#universal-recovery-ssh)** above, not this section.

If Authentik or Caddy is down and you can't reach **https://infratak.yourdomain.com**:

- **Backdoor:** Open **https://&lt;VPS_IP&gt;:5001** in your browser (use the server's real IP, not the domain). Log in with the **console password** you set when you ran `start.sh`. That path skips Caddy and Authentik, so you can get back into the console and fix things. **If you have applied Hardening (W1), this port is closed — see the next section.**

### If you have applied Hardening (Cyber Controls W1 — SSO + MFA)

**The direct-IP backdoor above is closed on purpose once W1 is applied.** That control's whole point is that the console must not be reachable from the internet with only a password — otherwise anyone could bypass SSO and MFA entirely. So on a hardened server, `https://<VPS_IP>:5001` will simply time out.

On those servers the recovery path is an **SSH tunnel**. From your own computer:

```bash
ssh -L 5001:localhost:5001 <user>@<VPS_IP>
```

Leave that session open, then browse to **https://localhost:5001** and log in with the **console password**. The tunnel reaches the console directly, so it works even when Caddy is completely down — and the password login is deliberately preserved for exactly this case.

> **This means SSH access is your only way back in on a hardened server.** If you lose both the console password and SSH access to the box, there is no remote recovery. Keep the console password in a password manager and make sure at least one SSH key still works.

### If your box is behind a relay (no public inbound)

Both paths above assume you can reach the box's own address. A **relayed** box — behind CGNAT, Starlink or cellular — doesn't have one, so use the **relay's** address instead of the box's.

**Backdoor:** open **https://&lt;RELAY_IP&gt;:5001**. The relay forwards that port to your box, so this is the same direct-IP backdoor described above, reached at the relay's address. Log in with the console password.

**On a hardened box (W1), that port is closed** — same as any other server, because W1 shuts it at the box's own firewall no matter which way the packet arrives. The tunnel version of the SSH recovery path is below. You don't need to open any ports for it: the relay is already an SSH server you can reach, and your box always sits at **`172.31.99.2`** at the other end of the tunnel. From your own computer:

```bash
ssh-add ~/Downloads/your-relay-key.key
ssh -J ubuntu@<RELAY_IP> -L 5001:localhost:5001 <user>@172.31.99.2
```

Leave that session open and browse to **https://localhost:5001**, exactly as above.

- `ubuntu` is the relay's login (Oracle's Ubuntu images use it). `172.31.99.2` is the same on every infra-TAK box — it's the box's address inside the tunnel, not something you set.
- **`ssh-add` matters:** `-i` applies only to the box at the far end, not to the hop through the relay, so a `-i`-only command fails with `Permission denied (publickey)` at the relay.
- If the relay refuses your key, check its permissions — a `.key` file left at `0644` is ignored with only a warning. `chmod 600` it.
- Works whether or not the box is hardened: the traffic arrives over the tunnel as if you were sitting next to the box, and nothing is exposed to the internet.
- **Relays built before v10.1.28 don't forward 5001.** The console re-runs the relay setup by itself on the next restart after the update, so this comes right on its own — no action needed. The SSH path above works either way.

Full relay documentation: [docs/RELAY-SETUP.md](docs/RELAY-SETUP.md).

Not sure whether a server is hardened? Check on the box:

```bash
sudo grep -o '"posture": *"[a-z]*"' /opt/infratak/.config/hardening.json 2>/dev/null || echo "not hardened"
```

The console password is stored as a **hash** in the install directory at `.config/auth.json` (e.g. `/opt/infratak/.config/auth.json`). You **cannot** recover the plaintext password from that file. If you forget it, run the reset script **from the directory the console runs from** — a server can carry more than one clone, and only the one in the systemd unit counts (the script refuses to run from the wrong one):

```bash
systemctl cat takwerx-console | grep WorkingDirectory   # shows the live install dir
cd /opt/infratak   # ← use the directory the line above shows
sudo ./reset-console-password.sh
```

Enter a new password twice; the script updates `.config/auth.json` and restarts the console. Then log in with the new password — at **https://&lt;VPS_IP&gt;:5001**, or at **https://localhost:5001** through the SSH tunnel above if the server is hardened. Store the console password somewhere safe (e.g. password manager); it's your only way in when the domain or Authentik is broken.

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

Full codebase map — how the code is organized, why it's a single service, the
platform-abstraction seams, and where the decomposition is headed:
**[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Ports

> **v0.9.12 hardening:** Every host port is classified by exposure tier. **Tier 1 (Public)** is reachable from the internet, **Tier 3 (Caddy-loopback)** binds to `127.0.0.1` and is reached only via Caddy on 443, **Tier 4 (Docker-internal)** has no host port at all, **Tier 5 (Source-scoped)** is allowed only from a specific peer IP.

### Tier 1 — Public (open in UFW)

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| infra-TAK Console | 5001 | HTTPS | Management web UI (backdoor: direct IP access). **Closed to the internet once Hardening W1 is applied** — reach it via SSH tunnel, see [Recovery](#recovery--backdoor-when-authentik-or-caddy-is-broken). |
| Caddy | 80 | HTTP | Redirect to HTTPS |
| Caddy | 443 | HTTPS | Reverse proxy for all services (Let's Encrypt) |
| TAK Server | 8089 | TLS | TAK client connections (ATAK, iTAK, WinTAK) |
| TAK Server | 8443 | HTTPS | Admin WebGUI (client certificate auth) |
| TAK Server | 8446 | HTTPS | Admin WebGUI (Let's Encrypt, password/LDAP auth) |
| MediaMTX / TAK Video Restreamer | 8554 | RTSP | Video streaming clients (publish + play) |
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

### Subdomains (DNS)

You give infra-TAK **one base domain**; it derives a subdomain per service and gets a
Let's Encrypt certificate for each one Caddy is fronting.

**A wildcard `*.yourdomain.com` A record covers all of them and is the recommended
setup.** If your DNS provider or policy requires individual A records, you must create
one **per subdomain below** — every record points at the same server IP.

| Subdomain | Service | What it is |
|---|---|---|
| `infratak` | infra-TAK Console | The management console (behind Authentik when SSO is enabled) |
| `takserver` | TAK Server | Admin WebGUI + Marti API |
| `tak` | Authentik | Identity provider / SSO login |
| `takportal` | TAK Portal | User & certificate management |
| `nodered` | Node-RED | Flow editor (behind Authentik when SSO is enabled) |
| `map` | CloudTAK | Browser TAK client |
| `tiles.map` | CloudTAK | Tile server |
| `video` | CloudTAK | Map video / HLS |
| `stream` | MediaMTX *or* TAK Video Restreamer | Stream web console & HLS (whichever of the two is installed) |
| `fedhub` | Federation Hub | Hub web UI (TLS terminated at Caddy) |
| `3dtiles` | Cesium 3D Tiles | 3D terrain / photogrammetry tile server |
| `webodm` | WebODM | Drone photogrammetry processing |
| `netbird` | NetBird | Overlay-network management UI |
| `remote` | EUD Remote Assist | Remote-assist portal |

Only the subdomains for modules you actually deploy need to resolve — but a wildcard
record means you never have to come back and add one when you deploy something new.

**Renaming a subdomain:** Caddy page → *Service Domains* → set a per-service override.
The Caddy page always lists the subdomains **this box** is really using, including your
overrides, so treat that list as authoritative over this table.

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

- **[Authentik login branding](docs/AUTHENTIK-LOGIN-BRANDING.md)** — Custom CSS vs **Brand → Attributes** (`theme: dark`), black backgrounds, flow wording; links to official Authentik docs and community guides.
- **[Guard Dog](docs/GUARDDOG.md)** — How Guard Dog works: monitors, 15‑minute boot delay and cooldowns, TAK Server soft start (after PostgreSQL and network), 4GB swap on deploy for memory stability, and restart-loop protection. Apply Docker container log limits from the Guard Dog page without redeploying a module.

---

## Changelog

### v10.1.49-alpha — 2026-08-26 — the safety net that was never actually there

**Headline: on Rocky Linux, a split video server's admin ports were left open — the console said it had closed them, and it had not.**

**Video servers on Rocky Linux were not being firewalled at all.** When the video server runs on its own machine, the console configures that machine's firewall: three ports open for streaming, and three deliberately **closed** — the video web editor, its control API, and the raw HLS feed. Those three are meant to be reachable only through the main web address, never directly from the internet. On Rocky Linux the commands used were the Ubuntu ones, so none of them took effect — and every error was suppressed, so the console reported "Ports opened" over a firewall it had never touched. On a Rocky box with both firewall tools installed it was worse still: the rules were accepted by the tool that was switched off, so they looked applied and enforced nothing. The console now detects which firewall the target machine actually uses, applies the right rules, and if any rule fails it says so plainly and warns that the admin ports may be reachable — instead of printing a tick.

**Removing fail2ban from the console now works.** It had no Remove button at all — the only way to uninstall it was to hand-craft an API request. It now removes like every other module, asking for your admin password first.

**TAK Portal now installs from a published release.** It was previously cloned from whatever happened to be on the project's main branch at that moment, which meant two installs on the same day could get different code. It now installs a tagged release and records exactly which one, so "what version is this box running?" has an answer.

**Ports we open are now ports we check.** Verify Reachability tested five fixed ports and nothing else, so anything a module opened later was forwarded but unverifiable. It now also checks the EUD Remote Assist enrolment port when Remote Assist is installed, and the video streaming ports when the video server is — because a port that is open on the machine can still be blocked by a cloud provider's firewall, and until now the only way to discover that was to watch a device fail to enrol with no explanation.

**Upgrade:** standard console update. No action needed.

### v10.1.48-alpha — 2026-08-25 — every remaining place the console told you something that was not true

**Headline: an email relay that reported success while it could not send, removal buttons that never asked who you were, and a video editor that trusted anyone claiming to be an administrator. All three are closed.**

**Email Relay could report success over a relay that could not send.** On installs where the console runs without root privileges, the step that builds the credential map your mail provider authenticates against was refused outright — and because the result was thrown away, the deployment still reported "Credentials written and hashed". Postfix then had nothing to authenticate with, so every message queued indefinitely with no sign anything was wrong. That step now runs with the privileges it needs, and if it ever cannot, the deployment fails and tells you, instead of finishing with a green tick over a mail relay that cannot send.

**Removing things now asks for your password.** Five actions that destroy state — removing Caddy, fail2ban, Cesium Tiles, Remote Assist's TURN server, and the "clean up and retry" button that deletes a failed TAK Server install — ran on nothing more than being logged in. Every other removal in the console has always asked you to re-enter your admin password first; these five had quietly drifted out of that set. They now match the rest, and an automated check fails the build if a sixth ever appears.

**The video editor now checks who it is talking to.** When the MediaMTX web editor is configured with single sign-on, it decided whether you were an administrator purely from details attached to the incoming request. On a standard install the editor is reachable only from the machine itself, so this was never exposed; on a split video-server setup it was guarded by a firewall rule alone. It now confirms the request genuinely came from your console before believing any of it — and if it is unsure it falls back to the editor's own login screen, so a misconfiguration can never lock you out.

**Guard Dog now says when nobody is listening.** With no alert address configured, alerts were dropped with no record kept anywhere. Setting an address later has always started them flowing again with no redeployment, but until then the silence was invisible. Every suppressed alert is now recorded, and setting up Guard Dog without a recipient warns you at the time.

**A misleading error on non-root installs is gone.** Installs running without root logged a permission denial on every startup, for a log-rotation rule that is deliberately not granted — that privilege would undermine the very isolation those installs exist to provide. Nothing was ever broken: the console has always enforced the same size limit itself. It simply no longer asks for what it knows it will not be given.

**Also:** removing a saved Wi-Fi network no longer leaves a backup file behind every time.

**Behind this release:** the automated security review that runs across this codebase had, through an error in its own documentation, only ever been reading part of it. It now covers every file that runs with elevated privileges. Two of the fixes above were found the first time it looked at the rest.

**Upgrade:** standard console update. No action needed.

### v10.1.47-alpha — 2026-08-24 — the startup protection now works on Rocky Linux too, and one device flooding the server no longer does it unseen

**Headline: the reboot protection we shipped last release only ever worked on Ubuntu. It works everywhere now — and the server has started noticing when a single device opens hundreds or thousands of connections at once.**

**The startup gate now covers Rocky Linux.** When a server reboots, TAK Server accepts connections for a couple of minutes before it is genuinely ready, and devices that connect during that window can end up connected to nothing — the exact fault the last release taught your server to report. v10.1.46 added a gate that holds devices off until the server is actually ready, but it only held on Ubuntu. On Rocky Linux the rule was being wiped seconds after it was placed, by ordinary background activity on the machine, so the protection was never really there. The gate now uses a part of the firewall that nothing else rewrites, and it has been verified to survive everything on the box that touches firewall rules. Your devices are held off for the two or three minutes the server needs, then let straight back in automatically.

**There are three independent ways it lets go**, because a gate that sticks is worse than no gate: the normal release when the server reports ready, a fifteen-minute failsafe timer if that never happens, and it clears on its own at the next restart. Local services and video feeds are never held.

**One device opening thousands of connections is now reported.** A device running a pre-release client was seen holding roughly three thousand simultaneous connections to a server. Nothing detected it, logged it, or reported it. Guard Dog now watches for a single device — or a single address — holding far more connections than any healthy one ever does, and emails you naming the device and the count. As with everything else in this line of work it only reports: it will not disconnect anybody. Using the same account across ATAK, WinTAK, iTAK and TAK Aware at once is normal and will not trigger it.

**Alert emails now tell you the right fix.** The client alert used to tell everyone to restart TAK Server. That is correct for a device missing from your client list, and wrong for an account that has no channel assigned — no amount of restarting gives an account a channel. Each condition now comes with its own instructions.

**The Reboot button now points at the smaller tool.** Rebooting the whole machine is what produces the connected-to-nothing devices in the first place, and it is often reached for to fix something a TAK Server restart would have fixed. The reboot confirmation now says plainly that every connected device will drop, and points at TAK Server → Restart instead.

**infra-TAK is now formally licensed under the AGPL-3.0.** It has always been free and open source; this makes it permanent and legally binding. Anyone can run it, modify it, and deploy it commercially, and anyone who modifies it and offers it as a service must publish their source too.

### v10.1.46-alpha — 2026-08-24 — your server now tells you when people are connected to nothing, and Rocky Linux starts properly for the first time

**Headline: two problems that were invisible by nature — clients who appear connected but are receiving nothing, and, on Rocky Linux, a TAK Server that has been starting up while fighting every other service on the machine for CPU.** Neither announced itself. Both were found because somebody looked.

**Nobody was told when clients were connected to nothing.** After a reboot it is possible for a device to hold a perfectly healthy-looking connection and yet be in no channel at all, or be missing from your client list entirely. The radio shows green. The user sees an empty map. Nothing in the console, the logs, or your inbox said a word about it — the last time this happened on a large deployment, it ran unnoticed until somebody happened to open the client dashboard and spot it. That is what made it expensive: not the fault, the silence.

**Now the server watches for it and emails you.** Guard Dog checks every five minutes for two specific conditions: devices connected but missing from the client list, and devices connected with no channel assigned. If either persists for fifteen minutes you get an email naming how many, what it means, and what to do about it. It only reports — it never disconnects anybody. We would rather tell you about a problem than guess at it and drop a working user in the middle of an incident.

It found a real one the day it was switched on, on a machine we had been running for months without noticing.

**On Rocky Linux, TAK Server has been starting up the hard way this whole time.** When the machine boots, we briefly stop the other services — the map server, the automation engine, the video server and so on — so TAK Server gets the whole machine to itself while it starts. It is a heavy startup and it wants the room. On Rocky Linux that step has never actually worked. It reported success and did nothing, because of a permissions difference in how TAK Server is packaged there that we had never had reason to notice.

The effect was not subtle once we measured it: TAK Server took **three times longer** to accept connections on a Rocky machine than it should have — around three and a half minutes instead of just over one — and on the way up its messaging component would sometimes fall over and need restarting. All of that was TAK competing with everything else on the box for CPU during the worst possible minute. This is fixed, and the improvement is immediate on the next reboot. If you run Rocky Linux, this release is worth having on its own.

**One honest note about this release.** We set out to ship a third thing: holding the client port closed for the few seconds during startup when TAK Server accepts connections before it is ready for them — the root cause of the connected-to-nothing problem above. It works, and we proved it works on Ubuntu, including the safety behaviour that guarantees it can never lock anyone out. It does not yet work on Rocky Linux, for reasons specific to how firewall rules are handled there. We hold ourselves to the rule that a fix has to work the same way on every supported platform, so it is held for the next release rather than shipped half-working. In the meantime the existing safety net that cleans these up after the fact is still in place and still working — the new alerting above now tells you when it happens.

**Who should update:** everyone, and **Rocky Linux deployments especially** — the startup fix is significant there. **Upgrade:** automatic on the next console update. The new monitoring turns itself on; make sure your alert email is set on the Guard Dog page if you want the notifications.

Full notes: [v10.1.46-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.46-alpha).

### v10.1.45-alpha — 2026-08-22 — one bad second on the network cost you the whole video config editor

**Headline: while setting up the video streaming server, a momentary network hiccup could cost you its web configuration editor entirely — and the message it left behind sent you down a path that could not work, when a single button on that same page would have fixed it in seconds.** Streaming itself was never affected. Video kept working, cameras kept connecting, feeds kept flowing. What went missing was the web page you use to configure it all — and everything about how that failure was handled was wrong.

**It gave up after one try.** Setting up the video server involves fetching the configuration editor from the internet. That fetch was given sixty seconds and exactly one attempt. If the network stumbled for those particular sixty seconds — not an outage, just a stumble, the kind that resolves on its own a moment later — the editor was simply not installed. On the machine where this was reported, the video server software itself downloaded successfully seconds earlier. Nothing was wrong with that machine or its connection. It was unlucky, once, for a minute.

**Then it told you to do something impossible.** The setup log advised placing a particular file on the machine by hand and running the whole setup again. That file has never been part of what we ship, so there was nothing to place. The instruction could not be followed by anyone, and following it as closely as possible meant removing the entire video server and reinstalling it from scratch — which is what the person who reported this reasonably did, losing a working streaming configuration in the process.

**And a one-click fix was already sitting right there.** The video server's page in the console has always had a **Patch web editor** button that repairs exactly this: it fetches the editor a different way, reapplies your settings, and restarts it — no reinstall, no lost configuration, a few seconds. Nothing in the failure mentioned it. The information needed to recover was on screen the whole time and the message pointed away from it.

**All three are fixed.** The fetch now tries again before giving up, and if it still cannot get through, it falls back to downloading just the single file it needs by a different route — a much smaller request that succeeds on connections where the full fetch times out. Together these mean a passing network stumble no longer costs you anything. And if a machine genuinely cannot reach the internet, the message now says so plainly and tells you to click Patch web editor once your connection is back, instead of sending you to reinstall.

**Slow connections got a real fix too, and it is a separate one.** Retrying helps when the network stumbles and then recovers — but it does nothing if your connection is simply slow all the time, because a second attempt runs into the same wall as the first. That is the normal state of affairs on satellite, Ku-band, and weak cellular, which is where a great many of these machines actually live. The fetch was being cut off after sixty seconds; elsewhere in the console, the same fetch to the same place was already allowed ninety. There was no reason for the difference. Both now get ninety seconds, so a connection that is merely slow rather than broken has the time it needs to finish.

**One honest note about this release.** The new safety net only runs when a fetch fails, and we could not make a fetch fail on any of the machines we tested on — every one of them succeeded on the first try, exactly as they should. So this ships a fallback we have read carefully and reasoned about, but have not watched save a real installation. The worst case if we got it wrong is that it behaves exactly as before, which is why we are shipping it rather than holding it — but you should know which parts were proven and which were not.

**Who should update:** anyone using video streaming, and anyone about to set it up — particularly on satellite, cellular, or other connections where fetches are slow or unreliable. **Upgrade:** automatic on the next console update, nothing to configure. If you are missing the video configuration editor right now, you do not need this release to fix it — click **Patch web editor** on the video server's page.

Full notes: [v10.1.45-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.45-alpha).

### v10.1.44-alpha — 2026-08-22 — after a reboot, people were connected to nothing

**Headline: reboot your server and some of your users came back connected but in no channels — or vanished from the client list entirely, while their radios showed a healthy green connection.** This was reported from a live public-safety deployment with hundreds of users, and it is the worst shape a fault can take: nothing looks broken. The radio says connected. The operator sees fewer people than they know are out there, and has no way to tell whether those users are offline, out of coverage, or sitting on a connection that quietly carries nothing. Three separate faults were stacked on top of each other, and we found the most important one only because the person who reported it did the work to dig it out himself. **First, we were starting things in the wrong order.** On a reboot the console deliberately stops the identity provider so TAK Server gets the whole machine to itself during its long startup — then brought it back only *after* TAK had already opened its doors to clients. That left roughly a minute where TAK was accepting connections with nothing behind it to identify anybody. Radios reconnect within seconds of the port opening, so they walked straight into that window and were let in as nobody: connected, authenticated against nothing, in no channels, and with no reason to ever try again. The identity provider now starts *first* and is confirmed answering before TAK is allowed to reach the point of accepting anyone. **Second, on many installations the console could not find the identity provider at all.** The code located it relative to the home directory of whoever was running it — and a service started by the system has no home directory at all. On machines whose software lives under the administrator account, that lookup pointed at nothing, so the startup sequence logged "not installed, skipping" and moved on: the identity provider was never started, its readiness was never waited for, and the message-routing service was never held back either, so its data feeds connected the instant the door opened, also as nobody. The console now asks the running container where it actually lives, which is correct regardless of who installed it or where. **The same flaw was in five of the health monitors** — including the one whose entire job is restarting the identity provider when it dies. They exit quietly when they cannot find what they are watching, so a monitor that has never once looked at anything is indistinguishable from a healthy one. Two of them were failing on *our* machines and two on customers', in opposite directions, and none of it was visible anywhere. All five now find their target properly. **Third, and this one is not ours: TAK Server opens its client port before its own management service has finished starting.** The two are separate programs; the door opens between five and twenty-five seconds before the part that tracks who is connected is ready. Anyone who connects in that gap gets a genuinely working session — messages flow both ways, channels are correct — but never appears in the client list, on that screen or in any report, and never corrects itself, because from the radio's side nothing is wrong. This is the "missing users" half of the report, and with hundreds of radios all reconnecting the moment the port opens, a large share of them land in it on every reboot. We cannot change when TAK opens its port, so the console now waits until the management service genuinely answers and then recycles exactly the connections that arrived too early. Each one reconnects itself within about half a minute, into a server that is properly ready. **Be clear about what that last fix is:** it is a cleanup, not a prevention. The gap still happens; it now heals itself in seconds instead of lasting until somebody notices and reconnects the radio by hand. Closing it properly means holding the door shut until TAK is fully ready, and that is deliberately not in this release — getting it wrong locks every radio out of a live server, and that is not a change to rush. **Who should update:** everyone, with priority for anyone whose machine gets rebooted and anyone running more than a handful of radios. **If you are affected right now:** restart TAK Server from its page in the console — the service, not the machine, and not a reboot — and everyone reconnects correctly. A reboot repeats the problem. **Upgrade:** automatic on the next console update, nothing to configure; it takes effect on your next reboot.

Full notes: [v10.1.44-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.44-alpha).

### v10.1.43-alpha — 2026-08-21 — the constant directory traffic, measured to its source — and a warning when CloudTAK is on the wrong certificate

**Headline: we found where the permanent identity-provider traffic comes from, proved no setting on your machine can reduce it, and made the console tell you when CloudTAK is connected on a certificate that quietly breaks Events.** The last release admitted we were still chasing the ambient directory load every machine generates while completely idle — a steady couple of lookups per second, around the clock. This release is the answer, and we want to be precise about what it is and is not. **It is a measurement, not a load fix. Nothing in this release reduces that traffic, and we are claiming no improvement whatsoever.** What the measurement established: TAK Server asks the identity directory for a certificate's group memberships on **every single API request** it receives — whether or not the identity exists in the directory, whether or not its group cache is enabled, whether or not the connection is reused. We proved this directly: sixty requests with an identity that resolves perfectly produced the same one-lookup-per-request traffic as sixty requests with one that doesn't. That rules out every fix on our side of the fence — a "better" service identity, a cache setting, a connection tweak — all of them would have changed nothing, and we know because we measured rather than reasoned. The traffic is simply TAK Server's per-request cost multiplied by how often CloudTAK polls it, and the polling rate lives in CloudTAK's own code. We have taken the numbers upstream to the CloudTAK team with a concrete ask: back off the polling when there is nothing to poll for. Until that lands, the load is a known constant, not a fault on your machine. **What does ship is a warning the measurement surfaced.** Machines that set up CloudTAK before the Bootstrap Admin certificate existed are still connected on the old bootstrap certificate — and on that certificate, CloudTAK 13.59+ silently skips delivering Events to channels it cannot resolve. Silently is the problem: everything looks connected, Events just don't arrive everywhere they should. The CloudTAK page now checks which certificate the connection is actually using and tells you plainly: a warning with the exact fix (generate the Bootstrap Admin certificate — one button, already in the console — and swap it once in CloudTAK's admin page, no re-bootstrap, nobody signed out) or a green confirmation when the right certificate is in use. We validated the whole path live: the swap took effect without dropping the session, and Events demonstrably deliver on the new certificate. **Who should update:** everyone; act on the new warning if your CloudTAK predates v10.1.18. **Upgrade:** automatic on the next console update, nothing to configure.

Full notes: [v10.1.43-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.43-alpha).

### v10.1.42-alpha — 2026-08-20 — the settings it kept putting back, and a number in the wrong unit

**Headline: infra-TAK has been overwriting settings you chose inside TAK Portal, and putting them back every time the portal updated.** It was reported by someone running it who had deliberately set which account TAK Portal uses to reach his server; every update healed his choice away and replaced it with ours. The cause is worth stating plainly, because it was a design mistake rather than a typo: the console decided which settings were *its* by looking at the value. If a setting matched something the console might once have written, it was treated as our leftover and overwritten — which cannot tell our own default apart from an operator who deliberately chose the same thing. Separately, a second piece of code wrote straight into the portal's settings file behind that rule entirely, which is why one field kept getting clobbered even though it was explicitly on the protected list. That same code stamped our own timestamp into a field that records when the *portal* last connected to your server — our fact, written into their record, in a different format. **The console is now hands-off by default.** It writes only the handful of settings it genuinely must own — the identity-provider connection, and mail delivery for as long as the mail relay is configured — fills the rest in once on a fresh install, and never touches them again. There is now exactly one piece of code that can write that file. Anything you set in TAK Portal stays set. **Second, TAK Server's group-membership refresh interval has been corrected.** The setting is specified in milliseconds and we had been writing thirty — thirty milliseconds rather than the thirty seconds intended. It now writes thirty seconds. Channel changes still reach people just as quickly. Existing machines are corrected automatically on the next console update, and TAK Server picks the change up the next time it restarts — deliberately not restarted for you, because restarting it disconnects everyone. **In fairness this is a correctness fix, not a measured speed-up:** we restarted TAK across our own fleet and directory traffic did not measurably change, so if you were hoping for relief from identity-provider load, this is not it. The ambient traffic we can see has a different source and we are still chasing it. **Third, the certificate-authority chooser added in the last release had three faults, every one of them found by clicking the buttons rather than by testing the code.** Saving showed a red failure for work that had completely succeeded, because the web server was restarted before the reply could be sent — the console sits behind that web server, so it was cutting off its own answer. The help text said that changing the authority would not reissue certificates until they came up for renewal; the truth is the opposite, everything is reissued within about a minute, and being told a change is low-impact when it changes what every browser sees at once is how someone ends up locked out of their own machine in the field. That text is corrected, and the button now asks first, naming the consequence and the address to get back in on. And after switching back to the default authority, the console could keep handing TAK Server a certificate from the authority you had just abandoned — it picked whichever was most recently written rather than the one actually in use. It now goes by what is configured. **Who should update:** everyone, with priority for anyone who has customised settings inside TAK Portal. **Upgrade:** automatic on the next console update, with nothing to configure.

Full notes: [v10.1.42-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.42-alpha).

### v10.1.41-alpha — 2026-08-20 — the web map that would not connect, and a certificate assumption nobody had tested

**Headline: WebTAK's live map never connected when reached through your normal address, and the console had been quietly assuming every certificate comes from one particular authority.** The first was reported by someone running it, who had been handed a confident diagnosis that turned out to be wrong. WebTAK loaded, the map drew, and the live connection died instantly with an error code that carries no explanation. Going directly to the server's own port worked, so the fault was in the web server sitting in front of it. The cause is that our web server was telling TAK Server it had been reached at a loopback address rather than at the name the browser actually used. TAK Server compares those two things before it will open a live connection, saw them disagree, and refused — silently, with an empty response the browser reports as a bare failure code. **It now passes the real address through**, and the map connects. This one resisted five earlier attempts, all of them ruled out by testing rather than argument, because the check being tripped is one that only browsers trigger — every command-line test passed for the wrong reason. **The second was found while building something else, and had never fired.** Ten separate places in the console assumed that certificates live in the folder used by Let's Encrypt. That is where they do live, right up until the moment they do not: the web server ships with a second authority as an automatic fallback and switches to it on its own if the first cannot issue — after a rate limit, an outage, or a failed check. Had that ever happened, TAK Server would have stopped being given its certificate and stopped having it renewed, on a machine that looked completely healthy from every page in the console. **The console now finds the certificates wherever they actually are**, and when two authorities have issued for the same name it takes the one being kept up to date rather than the stale one. **New: you can choose your certificate authority from the console.** Agencies whose policy names a specific commercial authority — Sectigo, DigiCert, Google Trust Services — or who run their own internal one can now point the console at it, with the account credentials those authorities issue, from the Caddy page. It is checked with the web server's own parser before anything is applied, so a mistake is refused on the spot with the reason instead of taking the site configuration down. Machines that do not set it are completely unaffected and generate exactly the configuration they did before. **Who should update:** everyone, and with priority if anyone uses WebTAK. **Upgrade:** automatic on the next console update, with nothing to configure.

Full notes: [v10.1.41-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.41-alpha).

### v10.1.40-alpha — 2026-08-20 — nine places the console told you something it had not checked

**Headline: this release fixes a single habit, found in nine different places — code reporting a result it never confirmed.** Every one of them looked healthy from the outside, which is exactly why they lasted. **A privileged helper was being restarted on every console start and the restart was reported as a failure** — it had succeeded every time, but the console misread the result, refused to record it, and so restarted it again on the next start, for ever, on every machine. Roughly forty-five seconds of knock-on failures followed each start, taking web-server, portal and mapping steps with it. **Operating-system updates could be killed by a mirror having a bad minute.** The Ubuntu package tool ships with retries switched off, the RHEL one retries ten times; nobody had noticed the asymmetry, so a transient outage ended the whole run — and a download failure was reported in the same words as a genuine install failure, sending operators hunting for a fault on their own machine. Downloads now retry, and a mirror problem says plainly that nothing was installed and to try again. **Health checks were reporting "unhealthy" when they had simply run out of time.** On a busy machine a two-second probe would occasionally expire and the dashboard card turned amber while the detail page — reading a cache rather than re-running the checks — stayed green. A check that could not finish is now reported as unknown, not as a failure. **Customers were being emailed about an identity-provider update they are not allowed to install.** The watcher compared against whatever the upstream project had published most recently, ignoring the vetted release that the Update button is deliberately pinned to; upstream published a new version and every machine began mailing about an upgrade the console then correctly refused. The email now names the version you can actually install. **In the same watcher, the check for infra-TAK's own updates had never once run.** A guard meant to detect an unfilled placeholder was itself rewritten during installation, so the test could never be true. Machines have been reporting updates for every other component and never for the console itself. **A security control's log feed had been dead since the last time Docker was upgraded, and the console said it was fine.** Enabling the jail could not restart the feed, the page could see it was stopped and did nothing about it, and every attempt to start it reported success without checking. The feed is now restarted automatically, the failure is reported honestly when it cannot be, and a machine that has simply never had a failed login is no longer accused of "protecting nothing". **An old web server could be upgraded from the console — except it never could.** The only upgrade button available after installation could not reach a newer version at all, and said it had upgraded anyway. Such a machine is now lifted automatically, unattended, and told plainly if it cannot be. **On those machines single sign-on silently looped**, because an older web server builds the authentication headers differently: every page loaded and nobody could log in, which is harder to spot than an outage. **And returning after a break could lock you out entirely** — signing in through single sign-on did not reset the inactivity clock, so a valid, fully authenticated login was immediately judged idle and bounced, with clearing browser data the only escape. **Who should update:** everyone. **Upgrade:** automatic on the next console update, nothing to configure. Two things to expect once: machines will start sending infra-TAK update emails they have never sent before, and a machine whose web server gets upgraded will sign everyone out once.

Full notes: [v10.1.40-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.40-alpha).

### v10.1.39-alpha — 2026-08-19 — the update that could never finish, and a web-server config older servers could not read

**Headline: two faults where the console reported a success it had not achieved — both found by people running it, not by us.** The first: on some installs, clicking **Update** on the identity provider pulled the same version down again, restarted it, and said it worked. The page kept offering the newer version, the operator kept clicking, and nothing ever moved — on one report, for twenty-three consecutive releases. The cause is that two files decide which version runs, and we were only ever writing the one the container system ignores whenever the other is present. **Both are written now**, the console asks the container system which version it has actually resolved *before* it downloads anything, and it confirms what ended up running instead of assuming. If it cannot move, it now says so plainly rather than showing a tick. The identity provider page also flags when a version is pinned somewhere that overrides the intended one, so an install stuck in this state is visible at a glance instead of quietly advertising an update forever. **The second is more serious, and it only affects machines that already had the Caddy web server installed before infra-TAK.** On those, the configuration we generate could be rejected outright, because it used a syntax that only exists in newer Caddy versions. What the operator saw was single sign-on never getting its certificate and enrolment ending in login errors that named no cause. What was actually happening is that the web server refused the whole configuration and carried on with its previous one — so the machine limped, apparently fine, until the next restart or reboot, at which point the web server **could not start at all** and every service behind it went down together. Four things change: the console now checks a configuration is loadable *before* anything applies it and puts the previous one back if it is not; it writes the older-compatible form when it detects an older web server; it upgrades a too-old web server during deployment instead of accepting it silently; and a machine already in this state repairs itself on the next console restart, with no intervention. **Who should update:** everyone — and with priority if you installed Caddy yourself before infra-TAK, or if your identity provider has been offering the same update for a while without ever taking it. **Upgrade:** automatic on the next console update, with nothing to configure.

Full notes: [v10.1.39-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.39-alpha).

### v10.1.38-alpha — 2026-08-18 — a security control that cannot work now says so

**Headline: switching on the Authentik brute-force jail now actually arms it, and any protection that cannot work is stated plainly on the page instead of quietly reading as healthy.** The console can block repeated failed logins against single sign-on. Switching that on wrote the rule, started the log reader, and reported success — but it did not change the one setting that decides whether Authentik ever writes the failed-login line the rule looks for. Until the console happened to restart, which might be days or weeks, the jail was loaded, listed as active, counted as coverage, and could not ban anybody. A field report caught it: the SSH jail on the same box was banning normally while this one sat at zero. **Enabling it now arms it in the same click**, and if the setting is one the console will not overwrite because you chose it deliberately, it says so in red rather than congratulating you. **More broadly, the console now shows you a control that cannot fire.** It has been able to detect that condition for twenty-seven releases and had nowhere to display it, so the page showed the same reassuring green for a working jail and a dead one. There is now a panel that names each affected jail and why — in words, not log jargon. **Also in this release:** the "Updates installed" notice came back every time you reloaded the page, no matter how many times you dismissed it, because the dismissal was being erased by the very next page load; it now stays dismissed, while a genuinely new update run still brings it back. And when deploying single sign-on cannot get a certificate because the web server was never told to serve that hostname, the deploy says exactly that instead of reporting success and then stalling five minutes on a certificate that was never going to arrive. **Who should update:** everyone, and particularly anyone who has switched on the Authentik jail. **Upgrade:** automatic on the next console update, with nothing to configure.

Full notes: [v10.1.38-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.38-alpha).

### v10.1.37-alpha — 2026-08-17 — see what an operating-system update will restart, before you run it

**Headline: the console now tells you which pending updates will restart your stack, in plain language, and installs them for you.** Keeping a server patched has meant either ignoring it or opening an SSH session and typing `apt upgrade` — and that command is not as harmless as it looks. It will happily restart Docker, and restarting Docker restarts *every* container at once: single sign-on, the map, your flows, the portal, the mail relay. Nobody was told that in advance. This release adds an **Operating System Updates** panel to the top of the console. It lists what is pending, separates routine patches from the ones that touch something you care about, and names the cost in words rather than package jargon — "restarts every container: Authentik (SSO/LDAP), CloudTAK, Node-RED, TAK Portal, Email Relay", or "restarts PostgreSQL — TAK Server clients reconnect automatically". A major version jump is called out differently from a routine security patch, because one is a behaviour change and the other is not. **One button installs them**, in a detached background job that survives you closing the tab, and TAK Server is held throughout so an operating-system patch can never sweep it up. A reboot, if one is needed, stays a separate explicit click. **It also answers the question people actually have:** is something updating my server behind my back? The panel reads the automatic-update configuration and says so plainly — and on RHEL and Rocky it now reports `dnf-automatic` honestly instead of describing an Ubuntu component that does not exist there. **Also fixed:** the patch job could collide with the system's own scheduled `apt` run and fail outright, leaving nothing installed; it now waits for the package manager to be free. **Who should update:** everyone. **Upgrade:** automatic on the next console update, with nothing to configure.

Full notes: [v10.1.37-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.37-alpha).

### v10.1.36-alpha — 2026-08-17 — a lost phone no longer means a locked-out user

**Headline: when someone loses the phone holding their authenticator app, you can get them back in from the console in about five seconds.** With multi-factor authentication enforced, a lost phone locks a user out of every web sign-in — the console, TAK Portal, Node-RED, NetBird, WebODM. They cannot fix it themselves, and that is deliberate: if a password-reset email could clear MFA, the second factor would only ever be as strong as the mailbox, so the reset flow refuses to act as a bypass. That left the actual fix buried five menus deep in the Authentik administration interface — not something anyone finds while a user is waiting on the phone. This release adds an **MFA Device Recovery** panel to the Authentik page. Search the user by name or email, see which authenticators they have registered, and revoke them. The next time they sign in with their password, they are walked through setting up a new authenticator. You never see or change their password, and they enroll the new device themselves. Their active sessions are signed out at the same time by default, in case the phone was stolen rather than simply lost. **And for when it is your own admin authenticator that is gone**, a break-glass control on the same panel resets the protected admin accounts — and it keeps working even when Authentik's own API is unreachable, which is precisely the situation where every other route has already failed. **TAK clients are not affected:** ATAK, iTAK and CloudTAK authenticate by certificate over LDAP, which is never MFA-gated, so a lost phone does not knock anyone off the map. **Who should update:** anyone running with MFA enforced. **Upgrade:** automatic on the next console update, with nothing to configure.

Full notes: [v10.1.36-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.36-alpha).

### v10.1.35-alpha — 2026-08-15 — one mistyped password no longer knocks users off your server

**Headline: a self-repair feature was tearing down your sign-in service whenever somebody fat-fingered a login — and the fault it was built to repair does not exist.** The console watched TAK Server's log for sign-in errors and, on seeing two within six minutes, rebuilt part of the Authentik sign-in service on the assumption it had become stuck. Two problems. First, **a single mistyped login is enough to set it off** — one rejected sign-in records two errors, which is already the trigger. So one person mistyping their username, once, could take down the sign-in service for everyone. Second, and worse, **the stuck state it was written to clear could not be reproduced at all.** The theory was that after a password change, TAK Server would keep rejecting you even with the correct new password until that service was rebuilt. Testing it directly — including the exact password-change sequence described — the correct password was accepted immediately every time, and every sign-in error observed had reached the identity service normally rather than being answered from a stale cache. In the field this had real cost: a user mistyping their username during device enrollment triggered a rebuild that left the server briefly unable to resolve who was in which channel, and **disconnected a device that was in the middle of a session** — with nothing wrong on that user's end, and no indication of what had happened. The feature has been **removed entirely**. Sign-in errors are now logged and left alone, which is what they always deserved: a mistyped password is a mistyped password, not a fault to repair. The genuine identity health monitoring around it is untouched and still runs — it verifies a real problem before acting, rather than inferring one from error counts. Removing this also takes two privileged system commands out of the console, so it runs with slightly less power than before. **Who should update:** everyone, and especially anyone enrolling new users or running devices in the field. **Upgrade:** automatic on the next console update, with nothing to reconfigure.

Full notes: [v10.1.35-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.35-alpha).

### v10.1.34-alpha — 2026-08-15 — map feeds hold their nerve, and update notices finally tell you the truth

**Headline: a brief hiccup at a data provider could wipe live shapes off your map, and the console's “new version available” notices had never actually worked.** **Map feeds** now refuse to act on a single bad answer. If a data source blips — and they do, several times an hour in some cases — anything that appears to have vanished is held for **15 minutes** before it is removed, and a poll claiming most of a feed has disappeared must persist for **30 minutes**. During testing a real provider outage briefly reported 16 of 17 flight restrictions as gone; nothing was deleted, and everything returned intact. Previously that would have removed all 16 and re-added them minutes later, prompting every connected device to delete things that never actually went away. Quiet feeds are also refreshed periodically, fixing a fault where a rarely-updated feed could silently become impossible for new users to load — the map looked full, but anyone joining fresh saw nothing and had no way to tell why. Feeds now also **watch their own data provider**: if the source stops publishing, you get an email saying so, with the time it stopped and a note that the fault is upstream. It learns each source's normal rhythm, so a wildfire feed that updates hourly is flagged within hours, while a boundary layer that updates monthly is not flagged for being quiet. During testing this caught a statewide power-outage provider that had been down for **46 hours** while the map showed its last data as though current. Separately, the console's **update notices are repaired**. A long-standing fault meant every check for a newer version failed silently and reported nothing at all — so a server could sit several releases behind on its video web editor, or on the video server itself, with the console showing no sign of it and everything looking current. Those checks now work, survive a temporary loss of internet access by reporting the last known answer rather than a reassuring blank, and say so in the log when they genuinely cannot tell. The console's role here is deliberately narrow: it tells you a newer version exists and points you at the video web editor, which is where video updates are performed. It does not perform them and does not interfere with them. Fresh installs still receive a tested version whose download is checksum-verified before it is installed, rather than whatever happened to be newest that minute. **Who should update:** everyone, and especially anyone running map feeds or the video server. **Upgrade:** automatic on the next console update; feeds are corrected for you, with nothing to reconfigure.

Full notes: [v10.1.34-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.34-alpha).

### v10.1.33-alpha — 2026-08-14 — the video server stops restarting forever, and secure streaming finally switches on

**Headline: if your video server refused to come up after an update — restarting every few seconds, endlessly — this release fixes it, along with three further video faults that were hiding behind it.** The streaming software we install published a new version that switches on a new experimental protocol by default. That protocol tries to write itself a security certificate into a location our servers deliberately do not allow it to write to, and in the newest version that single failure takes the **entire** video server down with it, so it restarts every five seconds and never recovers. Anyone who installed or updated their video component in the last few days would have hit this. We never used that protocol, so it is now switched off; servers already running are corrected automatically on the next console update, with no need to reinstall anything. Fixing that uncovered three more problems, all now fixed. **Secure streaming had never actually been turned on** — the installer looked for your SSL certificate in a folder it was not permitted to read, concluded the certificate did not exist, and skipped the whole setup, while the certificate sat there perfectly valid. It then reported "SSL certificates wired" regardless, so nothing looked wrong. Encrypted RTSP was therefore unavailable on every affected server. The installer now checks correctly, confirms the change actually took effect, and says so plainly when it has not. Existing servers have this applied for them automatically. **The video settings page could not save anything** — pressing Save returned "Failed to save settings" for the same underlying reason. It works now. **The video server and its settings page were running with full administrator rights** on servers set up before our move to restricted accounts; both now run with the limited account the rest of the stack uses, and the configuration file holding your stream passwords is no longer readable by other accounts on the machine. **Who should update:** anyone running the video server — particularly if it is stuck restarting, if you have never been able to use secure streaming, or if the settings page refuses to save. **Upgrade:** automatic on the next console update; every correction applies itself, with nothing to reconfigure and no redeployment needed.

Full notes: [v10.1.33-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.33-alpha).

### v10.1.32-alpha — 2026-08-14 — installs no longer stop dead on a server built from a USB stick

**Headline: if the installer stopped with a "does not have a Release file" error and refused to go any further, this release fixes it.** Some servers installed from a USB stick or ISO are left with Ubuntu still listing that install medium as a place to fetch software from. The moment the stick comes out, **every** software operation on that machine fails — not just ours — and infra-TAK's installer stopped at its first step, printed the raw error, and left you to find and hand-edit a system file before you could get any further. That underlying problem is an open defect in Ubuntu's own installer, not anything you did wrong. infra-TAK now recognises the situation and handles it: it backs the file up, switches off **only** the entry pointing at the missing medium, tells you exactly what it changed and where the backup went, and carries on with the install. Servers already running get the same repair automatically on their next console update — which matters more than it sounds, because that leftover entry also silently blocks operating-system security updates. Genuine offline/local software mirrors are checked and left untouched. The installer also now explains several other package-system failures in plain language instead of printing raw output at you. **Who should update:** anyone installing on hardware built from a USB/ISO, and every existing server — the blocked-security-updates repair applies to all of them. **Upgrade:** automatic on the next console update; nothing to reconfigure.

Full notes: [v10.1.32-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.32-alpha).

### v10.1.31-alpha — 2026-08-14 — map feeds stop deleting fires that are still burning

**Headline: a wildfire perimeter could appear on your map, vanish five minutes later, come back, and vanish again — for an hour — while your phone was repeatedly asked to delete it.** During a live incident, the newest perimeter of an active fire kept being stripped off responders' screens, and two phones watching the same feed ended up showing different fires. The cause was upstream, but the damage was ours. Public map services are served through a caching network, and the fire perimeter service is configured to hold each cached copy for a full hour — on data that is updated several times an hour by aircraft. So two consecutive checks, five minutes apart, could get genuinely contradictory answers about whether a fire exists. Our map feed treated **every single check as the whole truth**: anything missing from one response was deleted immediately, and a "delete this" instruction was then broadcast to every connected device. One stale answer was all it took to pull a live fire off every screen. Feeds now refuse to trust a single check. Requests are made so they cannot be answered from a stale cache; anything that goes missing must stay missing across several consecutive checks before it is removed; a shape the map still holds can never be deleted off a device; and a single check claiming that most of a feed has disappeared is ignored until it repeats. New data still appears immediately — only removals are cautious. **Who should update:** anyone running ArcGIS map feeds, especially wildfire perimeter feeds. **Upgrade:** automatic on the next console update; your feeds are corrected for you, with nothing to reconfigure.

Full notes: [v10.1.31-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.31-alpha).

### v10.1.30-alpha — 2026-08-13 — watching your own video streams could get you banned off your own server

**Headline: pulling several camera feeds at once tripped the video server's brute-force protection, and because that protection blocked every port, it took TAK Server with it.** A user running a multi-feed video wall during a live exercise found himself locked out — not just from video, but from his TAK Server entirely, on a phone that had been working minutes earlier. The cause was that the video protection counted **connections**, not **failed logins**. Opening ten streams at once looked identical to an attack, and the default threshold was ten. Every other protection we ship counts failures; this one never did, and it installs itself automatically on any server running the video service, so nobody chose it. Worse, the ban applied to *every* port, so a video-related block severed TAK Server, CloudTAK and the console — and the repeat-offender rule could escalate it to permanent. It now counts **failed stream logins only**: pull fifty feeds if you like, and as long as you are authenticating, this cannot touch you. A ban is also **scoped to the video ports alone**, so it is no longer able to cut anyone off from TAK Server or the console, and repeat offenders are explicitly exempted from the permanent all-ports escalation. On our own test servers this fault had quietly banned 19 addresses in a single week before anyone noticed. Also in this release: **Guard Dog alerts can now be paused** for an hour, four hours, a day, or until you turn them back on — monitoring keeps running, only the emails and texts stop — and **alerts can go to more than one address**. Fixing that surfaced a real fault: **removing or changing your alert email did nothing at all**. The old address was baked into the monitoring scripts when they were installed, so clearing the field said "saved" while mail kept arriving at the old address, and a server set up before you added an email would never send alerts at all no matter what you saved afterwards. That is fixed, and the Notifications page now shows you exactly which addresses are really receiving alerts and warns you when you have unsaved changes. Finally, **removing a WiFi network now works** — previously, deleting the only saved network on a server produced "Config failed validation" and silently changed nothing, which affected any box whose WiFi was set up during the original Ubuntu install. **Who should update:** everyone, and urgently if you run the video service — especially with multiple simultaneous streams. **Upgrade:** automatic on the next console update; the corrected protection is applied to existing servers for you, with no reinstall and no settings to change.

Full notes: [v10.1.30-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.30-alpha).

### v10.1.29-alpha — 2026-08-10 — the CoT database page now tells you the truth, and the cleanup that never ran now runs

**Headline: a user's disk filled up, every button that could have saved him was either impossible to press or did nothing, and the page told him to press the wrong one.** He concluded his database was corrupt and came close to rebuilding it. It was not corrupt: his data retention had never actually deleted anything, so 43 GB of live position reports had piled up, and *compacting* — the button the page pointed at — only reclaims space from rows that were already deleted. On top of that, compacting needs free disk roughly equal to the largest table, so on a full disk it cannot run at all. This release replaces the guesswork with a **Diagnose** button that reads the database and tells you which of those situations you are actually in, then highlights the button that fixes it. It adds the actions that can genuinely recover a full server: **Online Compact** (reclaims space without taking the server down), **Purge Old CoT** (deletes position history by age, or everything, and is the only thing that works when the disk is already full), and **Run Retention Now**. Compacting is now *refused* with a plain explanation when there is not enough free disk, instead of letting the database fail with an error nobody can act on, and **Update Now** refuses below 1 GB free rather than half-applying an update — the reason a full server previously could not even install its own fix. Two long-standing faults were found and fixed along the way, and both affected servers already in the field: **the automatic retention cleanup had never run once since it shipped** — a flaw in how it checked for work made it skip every single time — and when it could not read your retention setting it fell back to assuming one day, which on a server configured to keep a week would have deleted six days of history nobody asked it to remove. It now reads the real setting and deletes nothing at all when no policy is set. The console also **warns on every page when TAK Server has no retention policy configured**, because in that state nothing ever deletes old data and the disk will eventually fill with no warning at all — and Guard Dog now alerts on low free space and on retention that has silently stopped deleting, neither of which it previously watched. **Who should update:** everyone running TAK Server, and urgently if you have never set a data retention policy or have a database over 25 GB. **Upgrade:** automatic on the next console update. After updating, open Guard Dog → Database maintenance (CoT) and press **Diagnose** — it will tell you where you stand in one click.

Full notes: [v10.1.29-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.29-alpha).

### v10.1.28-alpha — 2026-08-10 — password resets finish, the setup WiFi actually appears, and the console works with no internet

**Headline: three things that reported success while doing nothing at all.** First, **password resets now finish.** Clicking the link in a reset email could land you on a blank error page — the password was saved, but the trip back to the app died. The cause is that mail providers rewrite links in email through their own click-tracking domain, so your browser arrives from somewhere else and the browser withholds the sign-in cookie for security. Resets now end at the sign-in page, where you log in with your new password. That is the same behaviour hardened installs have had since v10.1.4, and it removes the dead end entirely regardless of which mail provider you use. Second, **the Setup WiFi now works on Ubuntu.** When a box has no internet it is meant to broadcast its own network so you can connect a laptop and configure it on site — but on Ubuntu it downloaded the software it needed to do that *at the moment it tried to broadcast*, which is precisely when there is no internet to download anything. It never once succeeded. The components are now installed while the box is still online, so the network appears when you need it. Along the way: the setup network no longer shuts itself down seconds after you start it, stopping it actually stops it, and the page now tells you what to do next instead of leaving you guessing — including a warning that WiFi names are case-sensitive, so `OXFORD` and `oxford` are different networks. Third, **the console renders correctly with no internet.** Every page fetched its fonts and logos from the internet, so on the setup network — where the box *is* the network — icons showed up as raw words like `visibility` and logos as broken images. Everything is now served from the box itself, which also fixes air-gapped installs. Also fixed: **relay tunnel setup on servers running as a non-root user** ([#58](https://github.com/takwerx/infra-TAK/issues/58)), and adding a WiFi network on those same servers, which was silently refused. **Who should update:** everyone, and especially anyone using password resets, portable boxes, or air-gapped installs. **Upgrade:** automatic on the next console update — no configuration changes required.

Full notes: [v10.1.28-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.28-alpha).

### v10.1.27-alpha — 2026-08-07 — infra-TAK stops assuming it is the only thing on your server

**Headline: installing onto a server that already runs other software used to fail in confusing ways — and sometimes to report success for work it never did. This release makes infra-TAK check first, and tell you the truth when something goes wrong.** Three separate problems were reported from a single real deployment, and all three came from the same assumption: that infra-TAK is the only thing on the box. First, **port conflicts are now caught before a deploy starts.** If something already on your server holds a port infra-TAK needs — a system OpenLDAP on 389, another web server on 443 — the deploy now stops and tells you the port, the program holding it, and its process ID, instead of failing later with a raw Docker error or hanging forever on "Syncing". infra-TAK will never stop or reconfigure your software to make room for itself; it reports the conflict and steps aside so you can decide. Second, **Caddy failures are visible again.** Start, Restart and Reload reported success immediately and did the real work in the background, so a Caddy that could not start simply showed as "Stopped" and the button appeared to do nothing — the only way to find out why was to read system logs over SSH. The console now waits for the real outcome and shows you the reason it failed. Third, **setting up the PostgreSQL repository can no longer break your server's package manager.** If your server already had a PostgreSQL repository configured, infra-TAK added a second, conflicting one — a combination that breaks *every* package operation on the machine, not just ours, including security updates. It now detects and reuses what is already there; if its own change is ever what breaks things, it removes that change and restores your previous state before reporting the error. That step also no longer prints a checkmark when it has actually failed. Alongside these: **a TAK Server deploy now ends with a summary of anything that needs attention**, so a non-fatal warning is the last thing you read rather than something two hundred lines up; **the DNS setup instructions are correct and complete** — the subdomain list is generated from your actual configuration instead of a hardcoded list that had drifted (it said `portal` where the real subdomain is `takportal`, and omitted `takserver` entirely), and the README now carries the full list; and **Ubuntu 24.04 now warns that it is not yet validated** instead of installing silently, with Ubuntu 22.04 LTS remaining the supported baseline. **Who should update:** everyone, and especially anyone installing onto a server that already runs other services. **Upgrade:** automatic on the next console update — no configuration changes required.

Full notes: [v10.1.27-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.27-alpha).

### v10.1.26-alpha — 2026-08-06 — Apps are admin-only by default; one missing log file no longer stops all of Fail2Ban

**Headline: two security fixes you cannot see from the outside — a set of admin tools that were visible to ordinary users, and a brute-force protection service that could silently be switched off entirely.** First, **applications in the Authentik portal are now admin-only by default.** Agency admins and regular users were seeing tiles they should never have had — Node-RED most visibly, but also WebODM, Federation Hub and TAK Video Restreamer where installed. The cause was two-fold: the console was reading the application list through a filter that hid most applications from it, so its own attempt to lock them down quietly did nothing; and any module added after the original allow-list was written landed in neither list and inherited no restriction at all. Both are fixed, and the logic is inverted — a short list of applications is user-visible (TAK Portal, Stream, MediaMTX) and **everything else, including modules that do not exist yet, is restricted to global admins automatically.** Related: **new users can enroll their devices again on servers where that had broken.** The LDAP application that EUDs authenticate through had, on some servers, picked up a stale multi-factor requirement it was always meant to be exempt from — so a brand-new user could not reach the login path they needed *in order to* set up their second factor. That binding is now removed automatically wherever it drifted in. Second, **Fail2Ban can no longer be taken down by a single missing log file.** If the Authentik log file was absent — which happened whenever Fail2Ban was set up before Authentik was running — the service refused to start *at all*, taking every jail with it, including SSH brute-force protection. Worse, it stayed hidden until the next reboot or package upgrade, and then no amount of restarting would bring it back. The console now guarantees that file exists, and enforces a broader rule: if any jail points at a log that is missing, only **that** jail is set aside and the rest keep protecting the box — and a service left dead by this is brought back automatically. It also caps the Authentik log, which on some installations had never been rotated and was growing without limit. **Who should update:** everyone. Anyone whose Fail2Ban is currently stopped and will not start is fixed by this release with no manual steps. Anyone running TAK Portal with agency admins should update promptly. **Upgrade:** automatic on the next console update — no SSH, no commands, no service reconfiguration.

Full notes: [v10.1.26-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.26-alpha).

### v10.1.25-alpha — 2026-08-06 — Node-RED feeds survive anything; multi-state TFR fixed; CloudTAK cert password shown

**Headline: reinstalling the Node-RED module no longer costs you anything — and two field-reported bugs are gone.** Until now, uninstalling and redeploying Node-RED (or any redeploy that recreated its storage) silently wiped the CoT connector's certificate password and server address: your feed configs came back, but the connection was dead until you retyped both by hand. Now the console re-seeds them automatically from what it already knows — a full uninstall→reinstall produces a working CoT connector with zero re-entry. Second field fix: **TFR feeds covering multiple states work again.** On TAK Server 5.7, creating a new mission from the Configurator failed with an unhelpful 500 error, which surfaced exactly when a new multi-state TFR config used a fresh mission name; alongside the fix, the Configurator now documents the recommended workflow (create the Data Sync feed in TAK Portal first — Subscriber role, channel assigned — then enter that exact name), and the mission auto-create button has been removed in favor of that Portal-first flow. Third: **the CloudTAK bootstrap-certificate button now shows the actual certificate password** instead of a template placeholder (fixes issue [#57](https://github.com/takwerx/infra-TAK/issues/57)), with corrected wording about what the admin cert does. Under the hood, this release also hardens the feed engines against TAK Server 5.7's stricter mission API (mission writes are rate-limited and self-tuning, so one bad entry can no longer starve a whole feed), backs up your Configurator saves on every deploy instead of only some, tells the truth in the logs when a TFR has no drawable geometry (the standing DC-area security NOTAM is a reference to permanent airspace, not a drawable shape), preserves operator customizations to Node-RED's settings file across redeploys, and fixes a bug where reinstalling Node-RED on a non-root (hardened) installation could leave the module empty. **Who should update:** everyone running Node-RED feeds — especially anyone who has ever had to retype a cert password after a redeploy, or seen a multi-state TFR feed fail with a 500. **Upgrade:** automatic on the next console update; after any future reinstall, open each restored feed config and hit Save once to regenerate its flow.

Full notes: [v10.1.25-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.25-alpha).

### v10.1.24-alpha — 2026-08-05 — TAK Video Restreamer joins the registry engine; two fixes you'll feel

**Headline: TAK Video Restreamer now runs on the shared module registry introduced in v10.1.22 — same pages, same behavior — and the migration closes two real gaps.** First, **"Uninstall all services" now actually removes TAK Video Restreamer**: previously a full console reset removed every other service but left the restreamer's containers running and bound to their ports, invisible to a console that thought the box was clean. Second, **removing the restreamer now uses a proper confirmation dialog** (warning, blast-radius description, in-dialog password with show/hide) instead of a bare browser prompt, matching the TAK Server module. Also fixed, after a field report: **the console password reset script (`reset-console-password.sh`) now refuses to run from the wrong directory.** On servers carrying more than one copy of infra-TAK (an old clone next to the live install), the script would happily "reset" a password file the running console never reads — it now detects where the console actually runs from, tells you exactly where to go, and prefers the exact config path the console is configured to use. Passwords containing backslashes are also no longer mangled at the prompt. The recovery instructions in this README now derive the correct directory from the system service instead of assuming a fixed path. **Who should update:** everyone using TAK Video Restreamer or the factory-reset feature, and anyone who may someday need the password reset script — which is everyone. **Upgrade:** automatic on the next console update; no service restarts beyond the console.

Full notes: [v10.1.24-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.24-alpha).

### v10.1.23-alpha — 2026-08-05 — Fresh TAK Server installs work again with current tak.gov downloads

**Headline: if you tried to deploy TAK Server from a recently-downloaded 5.7 package and the deploy aborted with a CoreConfig verification error — this release fixes it.** TAK Server's stock configuration template ships its connection settings in a form our configuration step didn't fully anticipate, and the strict safety check added in v10.1.14 (which correctly refuses to leave a misconfigured TAK Server running) rejected otherwise-good fresh installs. This release makes the configuration step handle every known template generation of the TAK Server packages (verified against 5.4 through 5.7, both .deb and .rpm), makes the certificate-enrollment setup independent of TAK Server's own config-rewriting timing, and strengthens the safety check so it verifies the real configuration rather than being satisfied by boilerplate text in the stock file. Also in this release: a failed TAK Server deploy now stops the half-configured service instead of leaving it running with a healthy-looking status tile, and the Email Relay module's "Configure Authentik to use these settings" button now works on locally-deployed Authentik installations (it previously reported "Authentik is not installed"). Validated end-to-end with a fresh TAK Server install and a real ATAK device enrollment. **Who should update:** anyone deploying TAK Server fresh, and any Email Relay + local-Authentik user — existing working TAK installations are unaffected. **Upgrade:** automatic on the next console update; no service restarts beyond the console.

Full notes: [v10.1.23-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.23-alpha).

### v10.1.22-alpha — 2026-08-05 — A cleaner engine under the hood, and two Email Relay security fixes

**Headline: infra-TAK's modules now run on a shared registry engine, proven first on Email Relay — plus two security fixes for that module.** For months, every module (Email Relay, MediaMTX, Node-RED, …) carried its own copy of the same deploy/status/control plumbing, and each copy could drift out of sync with the others. This release introduces a single module registry that provides that machinery once — one job runner, one route family, one uninstall confirmation — and migrates Email Relay onto it as the proving ground. Every Email Relay page and endpoint behaves exactly as before, with two deliberate exceptions, both security fixes: **removing the Email Relay now requires your admin password** (it was the one module that didn't ask), and **uninstalling now deletes the stored SMTP credentials from disk** (previously `/etc/postfix/sasl_passwd` survived removal with your relay password in it — if you uninstalled Email Relay on an earlier version and never redeployed it, delete that file). Future modules build on the registry instead of copying plumbing, which means fewer places for bugs to hide and faster module development. **Who should update:** everyone — the security fixes apply to any installation that has ever used Email Relay. **Upgrade:** automatic on the next console update; no service restarts beyond the console.

Full notes: [v10.1.22-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.22-alpha).

### v10.1.21-alpha — 2026-08-04 — The console becomes one product: a unified design across every page

**Headline: all console pages now share a single, deliberate design.** Months of rapid development had let the console's 25 pages drift into two visibly different style families with independently-evolved copies of the layout, fonts, and colors on every page. This release converges everything on one look — the terminal-inspired theme of the TAK Server page: JetBrains Mono typography throughout, translucent glowing cards, amber accents — implemented as a single shared template (`base.html`) that every page inherits. What you'll notice: the console feels like one application instead of a collection of related tools, and light/dark mode now applies consistently everywhere. What you won't notice (by design): every button, form, log viewer, and control works exactly as before — each page conversion passed a structural-preservation check guaranteeing the page's working parts are byte-for-byte intact. Prefer a different font? The Customization page's font selection still works and now applies more consistently. **Under the hood** this completes SOLID Wave 1: chrome fixes that used to require editing up to 25 files now happen in one, and the styling drift that produced this situation is structurally impossible going forward. **Who should update:** everyone — purely visual + maintainability; no functional changes, no service restarts beyond the console. **Upgrade:** automatic on the next console update; do a hard refresh (Ctrl/Cmd-Shift-R) in your browser afterward to clear cached styling.

Full notes: [v10.1.21-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.21-alpha).

### v10.1.20-alpha — 2026-08-04 — Email settings flow where they should, and "Forgot password?" appears on every installation

**Headline: this release finishes the email-configuration story started in v10.1.19, and fixes a quietly missing login-page feature.** First, **configuring or switching your Email Relay provider now updates TAK Portal automatically** — the portal's Email panel picks up the new SMTP settings the moment the relay deploy finishes, with no "Update config & reconnect" click. Second, **ownership rules are now explicit**: when the Email Relay module manages your email, it stays authoritative for the SMTP transport settings; when you have no relay and configure SMTP directly in TAK Portal instead, infra-TAK now leaves that configuration completely alone (previously every update overwrote it with blanks — same family as the v10.1.19 BCC bug, now fixed at the root). Your CC/BCC addresses and fail-hard policy remain yours in all cases. Third, **the "Forgot password?" link now exists on every installation**. Installations deployed without the Email Relay module never got a password-recovery flow — the login page silently had no recovery link, and nothing could create one without configuring the relay. The recovery flow is now created on every Authentik deploy regardless of email setup, **and existing installations self-heal automatically on their next console update** — no clicks, no reconfiguration. (Recovery emails send using whatever SMTP Authentik has configured, from any source.) **Who should update:** everyone using TAK Portal or Authentik — especially anyone who set up SMTP directly in either without our Email Relay module. **Upgrade:** automatic on the next console update; the recovery-flow heal runs as part of the update itself.

Full notes: [v10.1.20-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.20-alpha).

### v10.1.19-alpha — 2026-08-04 — Every installation now gets identical software, and TAK Portal stops losing your email settings

**Headline: two invisible-but-important reliability fixes.** First, the console's own Python components (the web framework and its supporting libraries) were installed as "whatever version is newest today" — so two servers installed a month apart could quietly run different software, and a future upstream release could break new installations while old ones kept working. The dependency list is now **pinned to exact, field-validated versions** in a `requirements.txt` shipped with the console: every install, on every platform, gets identical components (including holding the application server at the newest version that supports both Ubuntu's and Rocky/RHEL 9's system Python). Second, **TAK Portal no longer loses the CC/BCC email addresses you configure** — a field-reported bug where every TAK Portal update or configuration push wiped the "Always CC" / "Always BCC" fields back to empty. Root cause was on our side (the console's settings sync treated those fields as its own and always wrote them blank); they're now preserved whenever you've set them. **Also fixed:** the TAK Server page could crash with a server error on its failed-install recovery screen (the "Clean up & retry" path) due to a corrupted character in the page — latent since May, only visible after a failed TAK Server deploy, now repaired. **Under the hood**, this release also completes the first phase of a codebase reorganization: all 25 console pages moved out of the main application file into standard template files, verified byte-for-byte identical — nothing changes in what you see, but page-related fixes land faster and a whole class of page-corruption bugs is now structurally impossible. **Who should update:** everyone — low-risk, no visible changes, no service restarts beyond the console itself. **Upgrade:** automatic on the next console update.

Full notes: [v10.1.19-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.19-alpha).

### v10.1.18-alpha — 2026-08-03 — CloudTAK Events actually reach the field, and a one-click certificate that makes them work

**Headline: CloudTAK's new Core Events feature needs a specific kind of TAK certificate to deliver anything, and this release generates it for you in one click.** CloudTAK 13.59 and newer republishes each Event as a live map marker to the channels you assign it — but it does that over a single administrative certificate, and it *silently skips* any channel that certificate cannot see. With an ordinary user certificate, you create an Event, nothing appears on anyone's map, and nothing anywhere reports an error. The CloudTAK page now has a **Generate CloudTAK Bootstrap Admin p12** button that creates a certificate with exactly the right properties, so Events reach every channel on the server — including channels you create later. Already running CloudTAK? Generate it, then swap it once under CloudTAK Admin → Server; no reinstall and no re-bootstrap. The setup guide has been rewritten around the new step. **Also in this release:** the MediaMTX web editor could enter a restart loop after an editor update, which took every video page offline (watch pages, share links, HLS) — that's fixed at the cause, and Guard Dog now watches the editor and alerts you if it ever goes down, which it previously did not. On Red Hat and Rocky systems, the console's security confinement received a full round of hardening: module folders were being created with incorrect security labels, which is now corrected at the source and repaired automatically on existing systems, and the constant background security logging (tens of thousands of entries a day on some systems) is gone — noticeably less idle CPU on smaller hardware. **Who should update:** anyone running CloudTAK 13.59+ who wants Events to work, anyone using the video restreamer, and all Rocky/RHEL installations. **Upgrade:** automatic on the next console update.

Full notes: [v10.1.18-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.18-alpha).

### v10.1.17-alpha — 2026-08-03 — The identity server stops burning a CPU core doing nothing, and CloudTAK follows upstream releases directly

**Headline: Authentik was quietly consuming about a full CPU core on every installation — at idle — and this release eliminates all three causes.** First, the current Authentik release line carries an upstream one-character bug that makes its internal task scheduler run continuously instead of once a minute; the console now patches that one line automatically (and removes the patch by itself the moment an Authentik release ships with the fix — we've reported it upstream). Second, every login event fanned out into four notification checks that could never notify anyone, which was two-thirds of all background work; those dead-end rules are removed for good, with Guard Dog remaining the alerting authority on this stack. Third, the console's own LDAP session setting forced every connected system to fully re-authenticate every two minutes; that's now one hour. Together with a one-time cleanup of old event records and a database tuning fix, identity-server background load drops by more than 95% — on modest hardware that's the difference between a server that always feels busy and one that's actually idle. **Also in this release: CloudTAK now tracks upstream releases directly.** The version pin is gone — Deploy and Update install the newest CloudTAK release on every channel, so you get their fixes the day they ship, and the update path now self-heals a known CloudTAK startup crash (a bad map icon could previously keep the map UI down after an update). **Two things to know:** the first console update after this release restarts Authentik once to apply the fixes, and an LDAP password change or account disable now takes up to an hour to cut off an already-connected TAK client (was two minutes; restart the LDAP outpost for immediate effect). Authentik's own admin-UI notifications for configuration errors are retired — Guard Dog owns alerting. **Who should update:** everyone, immediately — this affects every installation at idle, around the clock. **Upgrade:** automatic on the next console update.

Full notes: [v10.1.17-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.17-alpha).

### v10.1.16-alpha — 2026-08-02 — Agencies bring their own directory, and a guard against a database migration that would break TAK

**Headline: an agency can now manage its TAK users from its own Microsoft Entra or Active Directory, and the console does the rest.** Their IT points a standard directory feed at a URL you hand them; their staff appear in TAK already assigned to the right agency, with the right username, in the right channels — before anyone logs in for the first time, with no spreadsheets and no clicking through users one at a time. Usernames are built from the identifier the agency already uses for its people (a badge or employee number) joined to your agency code, so they match the format your hand-created users already follow. When someone changes role in the agency's directory, they move to that role's channels and lose the old ones automatically; when they leave the directory, the access stops following them around. The console deliberately refuses to guess: if a person arrives without a unique identifier it declines to create them and tells you why, rather than inventing a username from their name — two people called J. Smith would otherwise end up sharing one TAK account. Someone who has already signed in is never renamed, because that would break the tablet in their vehicle. **Also in this release: TAK Server 5.8 installs are blocked.** TAK 5.8 includes a PostgreSQL database migration, and installing it through the normal update flow would leave TAK stranded partway through an upgrade with no clean way back. Until guided-upgrade support ships, uploading a 5.8 package is safe but the update itself is refused, with an explanation. **Who should update:** everyone. The 5.8 guard matters to every installation the moment 5.8 is released; the directory integration matters if you support more than a handful of agencies. **Upgrade:** automatic on the next console update. The directory integration is opt-in per agency and changes nothing until you connect one.

Full notes: [v10.1.16-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.16-alpha).

### v10.1.15-alpha — 2026-07-30 — The dashboard stops crying wolf, and a better Authentik is approved for everyone

**Headline: the console's resource numbers were scaring operators into hardware upgrades they didn't need — and both numbers are now honest.** The "What's using CPU/RAM?" panel counted the database's shared memory once for every database process that touches it, which could show Authentik at two to four times its real memory footprint (a stack really using ~3 GB displayed as nearly 8 GB); the panel now measures proportional memory, so every row reflects what the process actually occupies. And the big CPU gauge refreshed from a half-second snapshot, so on a busy server it whipsawed between 5% and 90% with every refresh even when nothing was wrong; it now shows a steady one-minute average, with the live instantaneous reading kept as a small "now" detail underneath — a genuinely overloaded server still shows itself within a minute, but a two-second burst no longer reads as a crisis. **Also in this release: Authentik 2026.5.6 is now the approved identity-server version for all installations.** It carries upstream fixes for the database-connection buildup that previously forced periodic automatic restarts, plus task-broker fixes that make recovery from a database interruption dramatically cleaner — validated across x86, ARM64, Rocky Linux, and hardened non-root installations, including a deliberate database-interruption stress test that the previously held-back version failed and this version passed. Existing installations pick it up automatically through the normal update flow. **Who should update:** everyone — especially anyone who has looked at their dashboard and wondered whether they need a bigger server. Check the new numbers before buying hardware. **Upgrade:** automatic on the next console update; Authentik upgrades to 2026.5.6 on its normal update path (brief identity-service restart during that upgrade).

Full notes: [v10.1.15-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.15-alpha).

### v10.1.14-alpha — 2026-07-29 — Guard Dog catches API-process crashes, and a silent TAK Server misconfiguration now heals itself

**Headline: TAK Server runs five separate Java processes, and the one that large Data Sync operations exhaust — the API process — could run out of memory without Guard Dog noticing: it keeps running while returning HTTP 500s (CloudTAK errors, map failures), so the process monitor never fired and the server limped until someone restarted it by hand.** Guard Dog's OOM watch now scans the API process log alongside messaging, restarts TAK Server once (same safety caps as before), and the alert and restart record name *which* process ran out — the evidence needed to tune memory allocation. **Also fixed: a rare deployment fault that left TAK Server silently misconfigured.** If a low-level write failed during one deploy step, the install still reported success — but the server was missing its intermediate certificate trust and its enrollment configuration. The symptoms show up much later and look unrelated: CloudTAK's Initial Server Configuration fails with `UND_ERR_SOCKET: other side closed`, and QR device enrollment fails. The console now detects that exact damage on startup and repairs it automatically from the server's own certificate material (TAK Server restarts once when a repair is applied), and future deploys fail loudly instead of shipping a misconfigured server. **Also fixed: the CloudTAK icon-builder protection from v10.1.13 could be silently undone** — installing or updating a CloudTAK plugin rebuilds the API from source, which discarded the protection and brought the startup crash-loop back with nothing left to heal it. The protection now re-applies itself automatically after plugin rebuilds and through the post-update window. **Also in this release:** every module's failed-deploy banner now has the **Remove failed install** button (previously CloudTAK-only); fresh CloudTAK installs no longer print a scary-but-harmless database-password warning during first boot; and a text-encoding bug that rendered deploy Retry buttons as "Ὠ0 Deploy" instead of "🚀 Deploy" is fixed everywhere. **Who should update:** everyone — especially anyone running large Data Syncs, anyone using CloudTAK plugins, and anyone whose CloudTAK setup or QR enrollment fails as described above. **Upgrade:** automatic on the next console update; no manual steps (if the misconfiguration repair applies, TAK Server restarts once).

Full notes: [v10.1.14-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.14-alpha).

### v10.1.13-alpha — 2026-07-28 — First-time CloudTAK installs no longer fail, and TAK Portal stops forgetting your SSH settings

**Headline: a first-time CloudTAK deployment could fail in several distinct ways — a leftover container from an earlier attempt blocking startup with a name conflict, and the map's icon builder crashing the entire API on its very first boot so the install never finished — and every failure looked the same from the outside: a deploy that never completed, with Retry making no difference.** Both are fixed at the source. The deployer now clears stale containers before starting and recovers automatically if a conflict appears mid-start; and the icon builder can no longer take the API down — a failing icon set is skipped and logged (the underlying icon-processing fault is an upstream CloudTAK issue we have reported), so the map comes online every time. A failed deployment also finally has an exit: the failure banner now includes a **Remove failed install** button (admin password required) that wipes the partial install, including its database, for a truly clean retry. **Also fixed: TAK Portal SSH settings were being overwritten on every configuration push.** Cloud servers got a public address the Portal container can never reach (breaking Integrations and Locate), and on-premises operators watched their manually entered host and username get reverted after every update. The Portal now always receives the correct in-container address and account by default, and any values you set yourself survive every push. **Also fixed:** security-broker updates now take effect on a normal console update — previously the running broker could keep enforcing outdated rules until a manual reinstall, which could make console actions fail with authorization errors after an update. **Who should update:** anyone deploying CloudTAK for the first time, anyone whose CloudTAK install has never completed, and every TAK Portal user. **Upgrade:** automatic on the next console update; no manual steps.

Full notes: [v10.1.13-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.13-alpha).

### v10.1.12-alpha — 2026-07-27 — Hot fix: a fresh Red Hat / Rocky install could leave the web server unable to start

**Headline: v10.1.11 added an access log for the TAK Portal that only the optional brute-force protection knows how to set up — so on a Red Hat or Rocky server without that module, the web server was pointed at a log file nothing had prepared, and refused its entire configuration.** The effect was hidden. Because configuration is reloaded rather than restarted, the running server carried on with its previous settings and everything looked normal — until the next reboot, when the web server would fail to start and every service behind it would go offline with it. The log is now only requested when the component that reads it is actually present, so it is set up correctly or not asked for at all. Nothing else changes: servers already running the brute-force protection keep their log exactly as before. **Who should update:** anyone on v10.1.11, and in particular anyone running Red Hat or Rocky — the fault is silent until a restart, so it is worth applying before one happens. Ubuntu servers were not affected in practice, but the fix applies there too. **Upgrade:** automatic on the next console update; no manual steps.

Full notes: [v10.1.12-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.12-alpha).

### v10.1.11-alpha — 2026-07-27 — The brute-force protection was blocking your own services and, in two places, protecting nothing at all

**Headline: fail2ban was banning infra-TAK's own containers — cutting TAK Portal off from TAK Server — and an audit prompted by that found two more jails that had never once worked, while the console reported all of them healthy.** **Your own services were being banned.** TAK Portal, Node-RED and CloudTAK reach TAK Server over its public address, so TAK logs their container address as the caller. The TAK Server jail bans any address that fails a TLS handshake 20 times in 5 minutes — and TAK Portal's dashboard polls every 15 seconds, which is exactly that rate. One transient certificate fault and the jail banned Portal on every port for an hour, with repeat offences escalating to permanent. Operators were working around it by turning fail2ban off entirely. Container networks are now trusted, and any address already banned in one is released automatically on update. **Authentik brute-force protection had never worked.** It matched a phrase Authentik does not log, at a log level that suppressed the events, reading a file fed by a command that discarded the only stream containing them — and fail2ban was crashing on every line of that file before it reached any of it. All four faults are fixed and the log is now rotated instead of growing without limit. **The TAK Portal lookup jail had never worked either.** It watched a file nothing wrote. It now reads Caddy's access log, so the public lookup and self-enrolment forms are genuinely protected. **A dead jail can no longer hide.** Any jail that is switched on but not running — or running but never receiving anything — is now reported instead of appearing healthy. That check is what found the two above. **A server can no longer ban itself**, and the TAK Portal page in the console no longer errors when its configuration file is owner-restricted. **Upgrade:** everything applies automatically on the next console update; no SSH, no manual steps.

Full notes: [v10.1.11-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.11-alpha).

### v10.1.10-alpha — 2026-07-26 — Relays now maintain themselves, carry video, and the setup guide no longer sends you down a dead end

**Headline: a relay used to be set up once and never updated again — so any improvement we made only ever reached brand-new relays. The console now keeps your relay current on its own, and that channel immediately delivers a security fix plus full video support.** **Relays update themselves.** If your relay was built by an older version of infra-TAK, the console detects it and re-applies the current configuration by itself on the next restart — no terminal, no SSH, nothing to type. The tunnel stays up throughout and nothing you added by hand is removed. An **Update Relay** button on the Connectivity page does the same on demand. **Security fix delivered through it.** Relays built before mid-2026 left their reachability helper listening to the open internet instead of only inside the tunnel. It was password-protected, so nothing was exposed, but it had no business being reachable — and until now there was no way to fix an already-built relay. Updating infra-TAK corrects it automatically. **Video through a relay.** RTSP, RTSPS and SRT streaming are now carried by default. SRT in particular never worked before, and could not have — the relay only ever forwarded TCP, and SRT is UDP. **Setup guide rewritten.** Followed literally, the old guide produced a relay that could never connect: it named the wrong tunnel port. It has been rewritten against the current Oracle console — which is now a four-page wizard — and gained sections on adding a second relay, what Free Tier's idle-reclamation policy means for a relay (which is idle by nature), and which ports actually matter. **Upgrade:** applied automatically on the next console update; if your relay is unreachable at that moment, the console shows a button to finish it later.

Full notes: [v10.1.10-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.10-alpha).

### v10.1.9-alpha — 2026-07-26 — Two-server database links are encrypted, fail2ban stops locking you out of your own server, and wasted disk gets reclaimed

**Headline: the connection between a split TAK Server and its database is now encrypted, three ways fail2ban could lock you out or quietly stop protecting you are fixed, and servers built with unusable disk space get it back.** **Encrypted split-server database link.** When TAK Server and PostgreSQL run on two separate machines, traffic between them — including credentials — was crossing the network unencrypted. It is now encrypted, on existing deployments as well as new ones, and the change only completes after a live encrypted connection is verified. **fail2ban, three field-reported failures.** On some server images fail2ban was crashing at startup, which silently stopped *every* jail — the server looked protected and wasn't. It could also ban the very connection used to manage the server, taking a remote box offline with no way back in; management tunnels are now permanently exempt and any existing ban on one is released. And the never-ban list is now visible in plain English instead of one opaque string, with a warning when the address *you* are connected from isn't covered — the case that strands someone on a server they can't walk up to. **Reclaims stranded disk.** Servers provisioned with a large, unusable partition (common on Rocky/RHEL images) can now hand that space back to TAK, with the existing data verified byte-for-byte before anything is removed. **Red Hat installs (GH #56).** A repository step could fail silently on Red Hat in the cloud and resurface three steps later as a baffling PostGIS dependency error. The installer now asks the system which repository actually exists instead of guessing. **Config safety.** TAK Server's main configuration file is rewritten by roughly a dozen operations and none of them kept a copy — the previous version is now always saved first. **Firewall.** If you had restricted the console to specific addresses, restarting it quietly reopened the port to the entire internet; it now leaves a deliberate restriction alone. **Plus** tighter permissions on files holding passwords and keys, and CloudTAK's approved version moves to 13.54.3. **Upgrade:** applied automatically on the next console update.

Full notes: [v10.1.9-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.9-alpha).

### v10.1.8-alpha — 2026-07-24 — CloudTAK video playback fixed end-to-end, settings can no longer silently lose module config, and RHEL installs fail loudly instead of mysteriously

**Headline: Video in the CloudTAK web map actually plays now — external camera feeds and live phone/drone streams both — and two classes of silent failure are gone.** **CloudTAK video, fixed at every layer.** Clicking play on a map marker with a public camera feed (state DOT traffic cams, any public HLS URL) failed with a 404 on every deployment — the web player's requests were routed to the wrong internal service. Live RTSP streams (phones running TAK ICU, drones) were separately broken by an outdated media component CloudTAK still pins, which couldn't handle non-HTTP sources. Both are fixed: routing corrected with an automatic self-heal for existing deployments (manual Caddy patches are superseded, not fought), the media component updated to the current upstream release with its kernel requirements applied automatically, and the streaming ingest ports actually opened in the firewall — publishes into CloudTAK leases used to be silently dropped. Validated live end-to-end: phone → restreamer → CloudTAK web player, seconds behind live. ARM note: upstream ships no ARM build of the newer media component, so ARM boxes keep the current one (external feeds play; RTSP-lease browser playback remains unavailable there — upstream ask filed). **Settings hardening.** A rare write-race could silently drop module settings (mail relay, database config, admin credentials) while preserving core identity — recovery required manual repair. The guard now restores *every* setting from the last good copy, not just the core keys. **RHEL 9 installs fail loudly.** On genuine RHEL 9, a repository step could fail silently and surface three steps later as a baffling PostGIS dependency error (GH #56). The installer now uses the correct RHEL path automatically, verifies it, and stops with the exact fix if it can't — no more misleading errors. **Plus** plugin update failures can no longer leave a half-updated image behind. **Upgrade:** applied automatically on the next console update.

Full notes: [v10.1.8-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.8-alpha).

### v10.1.7-alpha — 2026-07-24 — Caddy always comes back after a reboot, proactive update emails, and a new SAR containment plugin

**Headline: Servers reliably restore all their web services after a power loss or reboot, you get an email when an update is waiting, and search-and-rescue teams get a new CloudTAK containment tool.** **Caddy reboot resilience.** On some servers — particularly small edge boxes on DHCP — the web front end (Caddy) could fail to come back after a reboot because it started before the network was fully up, taking down every site behind it (the map, TAK admin, SSO, portal) until someone manually restarted it. That's fixed: Caddy now waits for the network and self-recovers if it still loses the race, so a server returns to full service on its own after a power loss or reboot — no console, no SSH. Validated across Ubuntu, Rocky/RHEL, and ARM. **Proactive update emails.** The console now emails you (through the same alerting path Guard Dog uses) when an update is pending — a CloudTAK plugin, CloudTAK itself, or the console — so you find out without having to open the page. You get one email per new version, not a reminder every hour. **New plugin: Search Containment.** An ATAK Chokepoint-style tool for SAR is now installable from the CloudTAK plugins panel: pick a shape, line, or point, set a containment distance, and it drops numbered markers wherever the trail network crosses the ring, posted straight into the active mission. **Plus** a clear "dev" marker on plugin cards for boxes tracking a plugin's test channel. **Upgrade:** applied automatically on the next console update.

Full notes: [v10.1.7-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.7-alpha).

### v10.1.6-alpha — 2026-07-21 — Hardened deployments get map-engine updates again, and CloudTAK moves to the tested 13.50 release

**Headline: On security-hardened deployments — the strictest lockdown posture, where certificate files are mounted read-only — the automatic Node-RED map-engine update could silently fail, leaving the box on the previous engine even though the console itself updated fine. That's fixed: the update now routes file delivery around the read-only mounts, so hardened boxes pick up new map-engine releases (including v10.1.5's Clear Ghosts and feed-lifecycle improvements) automatically like everyone else. Your saved Configurator feeds and settings are preserved through the update — this was validated end-to-end on the hardened posture, including configs surviving a full deploy cycle. Alongside that, CloudTAK moves to the tested 13.50 release** across Ubuntu, Rocky/RHEL, and ARM, with plugin compatibility and post-update self-checks carried forward. One known ARM-only caveat: CloudTAK's optional tiles service doesn't start on ARM64 due to an upstream dependency issue — the map, API, and everything else are unaffected. **Upgrade:** applied automatically on the next console update.

Full notes: [v10.1.6-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.6-alpha).

### v10.1.5-alpha — 2026-07-21 — Fire perimeters and other snapshot map layers stop leaving dead shapes stuck on devices, plus fresh installs and updates that just work

**Headline: DataSync feeds built from snapshot sources — fire perimeters being the main one — no longer strand outdated shapes on tablets that were offline when the data changed, and a device that reconnects days later cleans itself up automatically. Feeds also stop the constant add/remove churn that used to flicker shapes on the map. Alongside that, several fresh-install and update paths that could stall are fixed. Updating is recommended; healthy boxes are left untouched.** **Snapshot map feeds get a real lifecycle.** Sources like the California fire-perimeter layer publish a brand-new record every time a fire grows, which used to mean each update was a delete-and-re-add — and any device that happened to be offline at that moment kept the old outline on its map forever. Feeds can now follow a stable identity per real-world entity (e.g. per fire) so a growing fire updates the same shape in place instead of piling up ghosts, the map stops flip-flopping between competing versions of the same feature, and a new one-tap **Clear Ghosts** action sweeps already-orphaned shapes off every device as it reconnects over the following two weeks — no per-device cleanup, no touching anyone's tablet. **The map bridge sees every channel again.** On deployments where the built-in map's server connection had gotten pinned to an empty channel set, live feeds now reliably reach it. **Fresh installs and updates are more robust:** a brand-new server that doesn't yet have Docker now installs it correctly on locked-down setups, the automatic post-update step that refreshes map feeds could silently skip on some servers and now runs every time, and an internal permissions issue that could make a feed refresh fail on the strictest security posture is resolved. **Upgrade:** applied automatically on the next console update.

Full notes: [v10.1.5-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.5-alpha).

### v10.1.4-alpha — 2026-07-18 — CloudTAK 13.49 with plugins that survive updates, a password reset that can't leave you in someone else's session, and installs/updates that heal themselves

**Headline: CloudTAK moves to the tested 13.49 release and your browser plugins carry across the update automatically; the password-reset flow on hardened boxes now always ends at a fresh sign-in (never dropped into a session that was already open in that browser); and a batch of self-healing so updates and installs recover on their own instead of getting stuck. Updating is recommended; healthy boxes are left untouched.** **CloudTAK updates cleanly to 13.49** across Ubuntu, Rocky/RHEL, and ARM — the update carries your installed plugins (like Dispatcher) across CloudTAK's new internal layout and rebuilds them for you, and after an update the browser picks up the new version on the next reload instead of showing a blank map from a stale cache. **Password recovery is safer on hardened deployments**: finishing a reset now signs the browser out and returns you to the sign-in page, so a reset opened on a shared or admin machine can never leave the new user inside a session that was already open there — and completing a reset always walks you through multi-factor setup as intended. **Updates and installs heal themselves**: a box whose files had been left owned by the wrong user (from an earlier manual fix) could half-apply an update and quietly run two versions at once — the console now repairs ownership and completes the update on its own, telling you plainly to reboot if a step needs it, with no command line. Also in this release: **new-install reliability fixes** so a fresh server missing Docker or PostgreSQL is handled gracefully instead of failing mid-deploy; a Guard Dog maintenance job no longer shows a false failure on split-database boxes; and a security-hardening pass that keeps database credentials out of the audit log. **Upgrade:** applied automatically on the next console update.

Full notes: [v10.1.4-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.4-alpha).

### v10.1.3-alpha — 2026-07-15 — CloudTAK updates that actually finish, a database that repairs itself, and a version pin you can trust

**Headline: CloudTAK updating is fixed end to end — updates complete on slow connections, a database-password mismatch that could leave CloudTAK dead after an update now repairs itself automatically, and CloudTAK is pinned to a tested release so an update can't jump you onto a version that breaks your browser plugins. Updating is recommended; healthy boxes are left untouched.** Three things went wrong when updating CloudTAK, and all three are closed. **Updates no longer time out** — a large rebuild on a slow VPS connection used to get killed partway through; the build now streams its progress and is given the time it actually needs. **CloudTAK no longer comes back dead with a database error** — PostgreSQL only accepts its password the first time a database is created and ignores it forever after, so any box whose configuration had drifted from its database would fail with *"password authentication failed"* the moment an update restarted it. The console now checks the two against each other after every start and **repairs the mismatch itself**, so affected boxes heal on their next update with no intervention. And **CloudTAK now follows the same tested-version track as the identity provider and NetBird**: the main channel installs only the release the fleet has validated, so a newer upstream version that hasn't been checked against browser plugins can't land on your box by surprise — including on brand-new installs, which previously pulled whatever was newest. Every module card now reads the same way: **your version · what main is pinned to · update (only if there's actually one to install)**. Also in this release: a box whose **public IP changed** (common after a cloud stop/start) could write bad data into its own settings and then **fail to start the console at all** — that's now prevented and self-healing; **CloudTAK now validates the console's certificate** instead of skipping verification, so its connections are properly checked; a **TAK Portal map fix** so the map isn't empty for admins; and a batch of **security hardening**. **Upgrade:** applied automatically on the next console update.

Full notes: [v10.1.3-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.3-alpha).

### v10.1.2-alpha — 2026-07-12 — Connectivity Wizard (beta): get any box online and reachable — homelab, on-prem, or in a truck

**Headline: the Connectivity Wizard grows up into a field-ready (beta) tool for getting a box online and reachable anywhere — a permanent home rack, an on-prem server, or a portable kit on the move — plus power controls and platform fixes. Updating is recommended; healthy boxes are left untouched.** The wizard detects your network (clean public IP, carrier-grade NAT, double-NAT) and picks the right path. The big one for portable and CGNAT boxes: a **WireGuard relay on a free-tier cloud VM (e.g. Oracle Always-Free) gives your box the equivalent of a static public IP** — clients connect by name, no business ISP and no port-forwarding required. **Setup WiFi** turns a headless box with no connection into its own access point: strand it, walk up with a phone, join its network, and pick an uplink — it comes back reachable by name, proven end-to-end over cellular. **Reachability diagnostics are now honest** — instead of falsely reporting "not reachable" when a box simply can't probe its own public address (normal on cloud VMs and home routers), it says so plainly and points you to a quick phone-on-cellular check, and it self-installs a detection dependency that was missing after in-place updates. This release also **fixes hardened/compliance posture on boxes using a custom (bring-your-own) SSL certificate** — arming the hardened posture no longer fails with a false certificate-validation error, so custom-cert deployments can enable it cleanly. Plus **console Power Off / Reboot buttons** (password-confirmed) and a batch of platform reliability fixes for Rocky/RHEL and portable networking. Connectivity ships as **beta**. **Upgrade:** applied automatically on the next console update.

Full notes: [v10.1.2-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.2-alpha).

### v10.1.1-alpha — 2026-07-09 — Stability & disk protection: stops runaway database growth, fixes downloads and video on standard installs, and quiets false alerts

**Headline: a reliability release that closes a disk-fill risk, restores certificate and video downloads on the standard console, and stops noisy false alarms. Updating is recommended — healthy boxes are left untouched.** The big one: a background Authentik table could quietly grow without bound and fill the disk on long-running boxes; the console now watches its real size, cleans it automatically, reclaims the space, and Guard Dog raises it on the monitoring board with an alert if notifications aren't set up — so a box can never silently fill up this way again. On the standard (non-root) console, **downloading certificate files** (`.p12`/`.key` for client-cert admin/user login) and **watching video streams** in the browser both work again — two things that regressed when the console moved off root. For two-server deployments, Guard Dog no longer sends **false "database not healthy" emails** when the database is actually fine (it now only acts on a real outage, never restarts a healthy database, and caps repeat alerts), and its **database-maintenance timers now actually run** to keep the CoT database from bloating. Also included: **defense-in-depth hardening** on top of the v10.1.0 login-security fix, and an access-point fix so a headless box's hotspot comes up cleanly. **Upgrade:** applied automatically on the next console update.

Full notes: [v10.1.1-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.1-alpha).

### v10.1.0-alpha — 2026-07-09 — Connectivity Wizard: get any box online and reachable from the browser — plus security patches

**Headline: a new Connectivity Wizard that takes a fresh mini-PC from "just plugged in" to "reachable by TAK clients" entirely from the browser — plus important security and stability fixes. Updating is strongly recommended.** The **Connectivity Wizard** (Connectivity page) detects your network situation, then walks you through the right path: set up a **relay** so friends and clients reach your box from anywhere with **no VPN** (one button — you create a free VPS, upload its key, the console does the rest), or the direct **DDNS + port-forward** path for a home connection with a public IP. It manages **WiFi** the way a phone does — scan and join, *pre-provision a network you're not on yet* so a portable box connects the moment it arrives, switch between known networks, and forget old ones. New **Setup WiFi** mode turns a headless box into its own access point when it has no connection, so you can walk up in a new location, join it from a laptop, and pick a network — no screen, no keyboard, no cable. **Verify Reachability** proves clients can actually reach every TAK port from the public internet (green/red per port, so you stop guessing), and your **relay's health now shows on the Guard Dog board**. Also in this release: **security patches — updating is recommended** — and a fix so **TAK Server LDAP login self-heals on a fresh deploy** (no more manual "Resync LDAP" after installing a new box). **Upgrade:** applied automatically on the next console update; healthy boxes are left untouched.

Full notes: [v10.1.0-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.1.0-alpha).

### v10.0.9-alpha — 2026-07-06 — Self-healing cleanup: user management, streaming, and safer module updates

**Headline: a batch of reliability fixes that repair affected boxes automatically on the next update — no manual steps.** If your TAK Portal Users page ever showed *"Missing AUTHENTIK_TOKEN"* and you couldn't add or list users, that's fixed: the console detects the cleared identity-provider token and restores it on restart, and prevents it from being wiped in the first place. **Video streaming keeps working across automatic certificate renewals** — a renewal used to quietly revoke the streaming server's access to the fresh certificate and could take streaming down until a redeploy; the console now re-grants that access on startup and after any renewal. **NetBird now updates on a tested-version track, the same model as the identity provider:** the console shows you when a newer NetBird has shipped upstream, but only installs versions that have been validated first — so an update can't leave your overlay VPN rejecting every login. **Deploying Email Relay while your identity provider is running** no longer risks a timing collision that could knock the provider offline (the deploy now waits it out and self-recovers). And **uploading the wrong TAK Server package for your OS** now gives a clear, immediate message instead of a confusing late error. **Upgrade:** applied automatically on the next console update; affected boxes repair themselves on restart, and healthy boxes are left untouched.

Full notes: [v10.0.9-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.0.9-alpha).

### v10.0.8-alpha — 2026-07-03 — The security guard becomes a real lock — safely, on your terms

**Headline: the least-privilege "guard" that mediates every privileged action can now actually *block* anything outside its allow-list — and turning that on is a deliberate, one-way operator choice, so it can never surprise a production box.** For several releases the guard has run in *watch* mode: it records what a compromised console would try but lets everything through. This release completes the allow-list so the guard recognizes every legitimate operation your servers perform (validated with zero false-flags across Ubuntu 22.04, Rocky / RHEL 9, and ARM64), then adds enforcement — but **opt-in**. A box never flips itself: after it has run 72 hours with a completely clean record it becomes *eligible*, and a new **"Turn on enforcing"** button appears on the Cyber Controls page. Enabling it is confirmed and one-way from the browser (turning it back off requires SSH break-glass), so a hacked console can only ever make a box *more* locked down. **Existing boxes stay in watch mode until you press the button; brand-new installs are opted-in but still watch for 72 hours first, so a fresh box never breaks its own setup.** Also in this release: **TAK Server snapshots on unprivileged consoles now capture a real database dump** (previously they silently shipped config-only backups with no database), with dumps authenticated so only genuine snapshots can be restored; the **CloudTAK cryptominer scanner** now runs correctly under the guard; and a batch of hardening from an internal security review. **Upgrade:** applied automatically on the next console update — your boxes keep running exactly as before, in watch mode, until you choose to enforce.

Full notes: [v10.0.8-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.0.8-alpha).

### v10.0.7-alpha — 2026-07-03 — One TURN port per job: Remote Assist always on 3479, NetBird always on 3478

**Headline: the Remote Assist TURN server (CoTURN) and NetBird now have a permanent port split, so they can be installed on the same server in any order without conflicts.** Previously the suggested CoTURN port depended on whether NetBird was already installed — which meant the "right" port changed from box to box, and installing CoTURN first on the standard port would make a later NetBird deployment fail with a raw Docker error. Now it's fixed and fleet-wide: **CoTURN always installs on 3479, and 3478 is permanently reserved for NetBird** (Remote Assist clients are told the port explicitly, so nothing needs the standard port). The NetBird deploy also gained a pre-flight check: if an older CoTURN install is still holding 3478, it refuses up front with clear instructions (uninstall CoTURN, reinstall — it lands on 3479 automatically) instead of failing mid-deploy. **Existing CoTURN installs keep working unchanged on their current port.** Remember to open **UDP/TCP 3479 + UDP 50000–50050** in your cloud security group for new installs. Validated on **Ubuntu 22.04, Rocky / RHEL 9, and ARM64** (fresh ARM64 install landed on 3479 first try). **Upgrade:** applied automatically on the next console update; no action required unless you plan to add NetBird to a box whose CoTURN sits on 3478.

Full notes: [v10.0.7-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.0.7-alpha).

### v10.0.6-alpha — 2026-07-03 — WebODM single sign-on, TURN alongside NetBird, same-domain email fixed, and scheduled TAK backups that actually run

**Headline: three user-reported issues fixed end-to-end, and scheduled TAK Server snapshots now genuinely work.** **WebODM** (GitHub #50): the TAK Incident Overlay plugin now actually appears after install (the upstream plugin shipped a packaging defect the deploy now patches automatically), and the double login is gone — WebODM's login page becomes a single **"Login with Authentik"** button using WebODM's native OpenID Connect, with the reverse-proxy gate still in front. Existing WebODM installs get both fixes without losing projects via the new **"⟳ Reapply Plugin & Config"** button on the WebODM page. **Email Relay** (GitHub #48): mail sent *to your own domain* no longer bounces with `550 User unknown` — the relay is now strictly send-only and routes everything through your provider; redeploying the Email Relay applies the fix on existing boxes. **TURN for EUD Remote Assist** (GitHub #49): CoTURN now coexists with NetBird — on boxes running a NetBird hub it installs cleanly on an alternate port (the UI suggests one automatically), and on legacy NetBird installs it can share NetBird's own TURN with dedicated credentials; credential fields gained show/hide toggles and stricter validation. **Scheduled snapshots**: the TAK Server snapshot schedule used to silently never run (and left a red failed unit in `systemctl`) — scheduling now runs inside the console itself, catches up missed runs, enforces the retention count you configure, and cleans up the old broken timer automatically. **Also fixed:** the **Update Now** button no longer locks out for 20 minutes after a successful update; servers upgraded from older releases now reliably start Authentik's redis cache; snapshots on managed/RDS databases can capture a real database dump; and RHEL boxes lose a noisy every-few-seconds package-manager error. Works identically on **Ubuntu 22.04, Rocky / RHEL 9, and ARM64**. **Upgrade:** applied automatically on the next console update; WebODM boxes should click **Reapply Plugin & Config** once, Email Relay boxes should redeploy the relay (Switch Provider → same provider) to pick up the mail fix.

Full notes: [v10.0.6-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.0.6-alpha).

### v10.0.5-alpha — 2026-07-02 — Run the whole stack without root: a one-click least-privilege console

**Headline: the infra-TAK console — and the whole TAK stack it manages — can now run as an unprivileged user instead of root, and existing servers can switch over with a single click.** New installs come up non-root automatically; existing deployments get a **Switch to non-root** button on the **Cyber Controls** page. It migrates the running console to an unprivileged user, carries all of its state across, and relocates every managed service (Authentik/SSO, CloudTAK, TAK Portal, NetBird, Node-RED and more) into the new home so they stay manageable — with automatic rollback if anything doesn't come back cleanly, and without dropping SSO or your hardened firewall posture. Underneath, a small privileged broker mediates the handful of genuinely root-level operations the console still needs, so routine management no longer runs with full root. This release also completes the non-root switch on **Rocky / RHEL 9** (SELinux-aware migration and firewalld-correct port hardening, so admin services stay behind the reverse proxy) and strengthens two-server (separate database host) deployments. **Also fixed:** TAK Video Restreamer **Update Now** (updates were aborting on a config conflict — they now refresh cleanly and preserve your settings), and Docker **build-cache cleanup on large disks** (the automatic reclaim only ran when the disk was nearly full, so big disks could accumulate hundreds of GB of stale build cache — it now caps the cache to a fixed size on every run). **Upgrade:** applied automatically on the next console update; switching to non-root is opt-in from the Cyber Controls page.

Full notes: [v10.0.5-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.0.5-alpha).

### v10.0.4-alpha — 2026-06-24 — See exactly what your server exposes — and a server that heals its own address when the cloud changes it

**Headline: a new read-only Service Exposure panel shows, at a glance, whether every part of your stack is reachable the way it should be — and cloud servers now automatically repair themselves when their public IP changes.** Open the **Firewall** page and you get a green / yellow / red board comparing what each service *should* expose against what it's *actually* doing right now: internet-facing services (TAK, the console, streaming) are green by design; admin-only services that should sit behind the reverse proxy are flagged **red** the moment they're actually reachable from the internet — the exact kind of silent misconfiguration that has caused real incidents elsewhere. It's purely informational (it never changes a firewall rule), it understands both Ubuntu's UFW and Rocky/RHEL's firewalld, it correctly treats firewall-blocked and TAK Server's own connector ports as safe, and a small **Exposure** badge on the Console dashboard gives you the one-glance verdict with a click through to the detail. Alongside it, **server-address self-healing**: a cloud server that is stopped and restarted is often handed a brand-new public IP (common on AWS without a static address), which used to leave the console pointing at a dead address — a certificate-name mismatch and firewall rules aimed at the old IP. The console now re-detects its real address on startup and, only when it has genuinely changed, repairs its settings, regenerates the self-signed console certificate, and re-scopes its firewall rules automatically — so the box comes back reachable instead of broken. Works identically on **Ubuntu 22.04, Rocky / RHEL 9, and ARM64**. **Upgrade:** applied automatically on the next console update; no action required.

Full notes: [v10.0.4-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.0.4-alpha).

### v10.0.3-alpha — 2026-06-24 — Your server can no longer lose its own domain: hardened config + self-healing startup

**Headline: a rare race condition could corrupt the console's settings file and make a perfectly healthy server suddenly behave as if it had no domain — showing a "No Domain Configured" banner, dropping to self-signed certificates, and cascading into broken single sign-on if the domain was then re-entered. v10.0.3 makes that class of failure impossible.** The settings file is now written **atomically** (it can never be caught half-written, even under heavy background activity or a restart), it **refuses to drop the server's core identity** (domain, SSL mode, OS, install paths) no matter what writes it, and on every startup the console **self-heals** any missing core setting — re-detecting the OS and recovering the domain from the server's own configuration — so a box comes back up on its real domain instead of a degraded state. Four related hardening fixes ride along: the domain-change flow no longer produces a malformed sign-on hostname (which could break SSO with an "Authentik — Not found"); single sign-on redirects always point at a browser-reachable address; the console **always finishes starting even if Authentik's LDAP component is briefly unhealthy** (it heals in the background instead of hanging); and the identity provider can no longer get stuck in a database-lock restart loop on a slow disk. Finally, servers that installed TAK Server **natively on ARM before container support existed** are now correctly detected as running (they were wrongly shown as "Stopped"). Works identically on **Ubuntu 22.04, Rocky / RHEL 9, and ARM64**. **Upgrade:** applied automatically on the next console update; no action required — and the protection is most valuable on long-running servers.

Full notes: [v10.0.3-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.0.3-alpha).

### v10.0.2-alpha — 2026-06-22 — Guard Dog reclaims runaway Docker build cache before it fills your disk

**Headline: Guard Dog now automatically reclaims dead Docker build cache, a hidden disk hog that can quietly fill a server's root disk and look like a database or log problem when it isn't.** Servers that update containers over time (CloudTAK and other module rebuilds) silently accumulate tens — sometimes hundreds — of gigabytes of stale Docker BuildKit cache. On a smaller disk that can climb toward 100% and start breaking things, even when TAK's own database and logs are perfectly healthy. Guard Dog now watches for this and cleans it up on its own: it keeps the **last 7 days** of cache so rebuilds stay fast, and only acts when the **root disk is getting tight (70%+)**, so boxes with plenty of room are left untouched. It **self-heals within the hour** (riding the existing hourly disk monitor) and also runs a **daily** pass, and it **never touches your running containers, images, or named volumes** — only dead build cache. Reclaimed space is logged and shown on the Guard Dog page. Works identically on **Ubuntu 22.04, Rocky / RHEL 9, and ARM64**. **Upgrade:** applied automatically on the next console update; no action required.

Full notes: [v10.0.2-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.0.2-alpha).

### v10.0.1-alpha — 2026-06-21 — infra-TAK runs everywhere: Rocky / RHEL 9 and ARM64, not just Ubuntu

**Headline: the universal-installer goal is here — infra-TAK now deploys and self-manages on Rocky Linux / RHEL 9 and on ARM64 hardware, in addition to Ubuntu 22.04, from the same single-clone install.** The installer detects your OS, package manager, and CPU architecture and configures the whole stack accordingly — including the firewall, which now works **identically on RHEL's firewalld and Ubuntu's ufw**: the firewall page and the one-click **Cyber Controls** hardening (default-deny, console lockdown, SSO + MFA) behave the same on every platform, with no change to how you use them. Fresh RHEL installs come up **hands-free** — firewalld is installed and started automatically (without ever locking you out), TLS/Caddy self-heals around an EL9 packaging quirk that could otherwise abort the very first deploy, and service-health detection understands RHEL's package and service names. This release also folds in **EUD Remote Assist** improvements: cleaner module naming, administrator rights passed through from your single sign-on, hardened security headers, more reliable in-place updates, the device API correctly opened on RHEL, and a clean automatic migration from the previous install. **ARM64 caveats:** Cesium 3D-tiles (pmtiles) and Federation Hub are not yet available on ARM. **Upgrade:** applied automatically on the next console update; existing Ubuntu deployments are unaffected.

Full notes: [v10.0.1-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v10.0.1-alpha).

### v0.9.60-alpha — 2026-06-15 — EUD Remote Assist: accurate version checks and an on-demand update check

**Headline: the EUD Remote Assist module now reports its available version reliably and refreshes the moment you ask it to.** The module's "newest version available" check has been reworked to query GitHub directly and cache results sensibly, so the displayed version stays accurate and no longer gets stuck. A new **🔄 Check** button lets you re-check for a newer release on demand — handy when a new build has just been published — and the installed-version and update-ready indicators update in place without a full page reload. **Upgrade:** applied automatically on the next console update.

Full notes: [v0.9.60-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.60-alpha).

### v0.9.59-alpha — 2026-06-15 — EUD Remote Assist: remotely manage your Android devices

**Headline: a new marketplace module for remotely managing company-owned Android end-user devices — device registration, live location, ping, and full screen view with remote touch — all behind your existing single sign-on.** Deploy **EUD Remote Assist** from the Marketplace and the console clones it into Docker, provisions an Authentik OIDC application, and publishes an admin portal at `https://remote.<your-domain>`. Sign-in is restricted to the same administrators as the console (the *authentik Admins* group); Android devices connect over a dedicated, separately-firewalled device API. One-click deploy, update, start/stop, logs, and removal are built in, with the portal's own version tracked alongside the console's other modules. **Upgrade:** applied automatically on the next console update; open the Marketplace and choose **EUD Remote Assist** to deploy (requires a configured domain and Authentik).

Full notes: [v0.9.59-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.59-alpha).

### v0.9.58-alpha — 2026-06-15 — Console reliability behind SSO + gateway-safe brute-force protection

**Headline: the console dashboard stays usable on SSO-protected deployments, and brute-force protection can no longer accidentally lock out your own gateway.** On deployments where the console sits behind single sign-on, the dashboard's background calls — the **"Check for new release"** and **"What's using CPU/RAM"** buttons and the live gauges — could fail once your login session lapsed: the page still looked logged in, but those controls quietly errored until you reloaded. The console now handles an expired session cleanly so the buttons keep working as expected. Brute-force protection (fail2ban) gains a **trusted-upstream whitelist**: on a box behind a reverse proxy, load balancer, or cloud gateway, the upstream's address is never banned — preventing a self-inflicted outage where one traffic blip could block every site at once. The console's web server also picks up its full thread count on a plain restart (not only via Update Now), so busy single-worker consoles stay responsive. **Upgrade:** applied automatically on the next console update.

Full notes: [v0.9.58-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.58-alpha).

### v0.9.57.1-alpha — 2026-06-14 — Authentik 2026.5.3 for all deployments

**Headline: every deployment now updates to Authentik 2026.5.3 — the performance-fixed release — not just dev-channel boxes.** v0.9.57 fixed the Authentik high-CPU / sluggish-sign-on issue by moving to Authentik 2026.5.3, but only for boxes on the development channel; standard deployments stayed on the older 2026.2.3. This patch promotes 2026.5.3 to **all** deployments, so your identity provider updates to the current, performance-validated release on the next console update — snappier single sign-on and lower idle CPU. The 2026.2.3 → 2026.5.3 upgrade path was validated on a live production deployment and the test fleet. **Upgrade:** Authentik pulls 2026.5.3 and restarts automatically on the next console update.

Full notes: [v0.9.57.1-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.57.1-alpha).

### v0.9.57-alpha — 2026-06-14 — Authentik performance fix + self-healing, console reliability, and TAK Portal QR enrollment

**Headline: Authentik runs cool again, the console dashboard stays responsive under load, and TAK Portal enrollment QR codes point devices at the right server.** Authentik is updated to **2026.5.3**, which fixes an upstream bug that pegged the identity provider's CPU and made single sign-on feel sluggish even on an idle system — logins are snappy again. A box that had already built up a large Authentik background-task backlog now **clears it automatically** on the next console restart, so the high-CPU condition self-heals without any manual database work. The **console dashboard** is more reliable on busy boxes: the "What's using CPU/RAM" and "Check for new release" buttons no longer fail while the page's background refreshes are running, and the memory gauge now reads accurately. **Guard Dog** no longer raises a false "network down" alert on cloud/Azure hosts that block ping (it confirms real internet egress another way), and it now **reclaims leftover swap** automatically after a memory spike. And **TAK Portal** enrollment QR codes once again carry your server's real hostname instead of an internal Docker address, so scanning a QR enrolls a device correctly — while the Portal still reaches an on-box TAK Server reliably. **Upgrade:** applied automatically on the next console restart.

Full notes: [v0.9.57-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.57-alpha).

### v0.9.56-alpha — 2026-06-14 — Portal & CloudTAK deploy reliability + Authentik database hygiene

**Headline: cloud and gateway-fronted deployments get more reliable — TAK Portal reconnects to a local TAK Server even behind a load balancer, fresh CloudTAK deploys come up clean, and Authentik stops growing its database without bound.** TAK Portal now reaches an on-box TAK Server through the Docker host even when your domain resolves to a TLS-terminating front end (an App Gateway or load balancer) whose certificate doesn't chain to TAK's CA — the case that previously left the Portal unable to sync — and it derives the TAK certificate password from the certificate itself, so a mismatched setting can't silently break the connection. Fresh **CloudTAK** deploys now harden their container ports *before* the containers start, so the video port no longer collides with the web proxy and leaves a blank map page — the map serves correctly on the first deploy. **Authentik** event-log retention is now capped to a sane window instead of the year-long default that let the events table — and its CPU cost — grow without bound. In the hardened security posture, the **30-minute idle auto-logout now truly re-prompts** through single sign-on instead of silently refreshing, and a new **off-box audit option** (syslog/CEF to your SIEM) keeps a tamper-resistant copy of the console's audit trail. **Upgrade:** applied automatically on the next console restart; the CloudTAK port fix takes effect on its next deploy.

Full notes: [v0.9.56-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.56-alpha).

### v0.9.55-alpha — 2026-06-13 — Cyber Controls: one-click SSO + MFA hardening

**Headline: flip your whole TAK stack into a hardened security posture in one click — and back out just as easily.** The new **Cyber Controls** page adds a Standard↔Hardened toggle that closes the security gaps a reviewer fails a system for, then self-documents what it did. In Hardened posture: **per-user single sign-on with enforced multi-factor authentication on every app behind Authentik** (console, Node-RED, TAK Portal, WebODM, MediaMTX, NetBird), with MFA **force-enrolled at first login** so no account slips through; the **admin console is taken off the public internet** (reachable only through authenticated SSO) and its shared password becomes an **on-box break-glass** recovery, not a network login; a **30-minute idle auto-logout**; a **per-user audit log** (who/what/when); read-only **boundary checks** (firewall deny-by-default, intrusion prevention, TAK Tomcat exposure); and a printable **readiness report** plus an editable "what to tell your security office" statement. Every control is reversible with one click, and the on-box recovery path means hardening can never permanently lock you out. TAK clients (ATAK/iTAK/CloudTAK) and TAK Server keep their native authentication and are unaffected. Login screens also got plainer, on-brand wording. **Upgrade:** the Cyber Controls page appears automatically; the default stays **Standard** (no change to current behavior) — enroll an MFA device, then flip to Hardened when you're ready.

Full notes: [v0.9.55-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.55-alpha).

### v0.9.54-alpha — 2026-06-12 — Guard Dog catches slow-disk stalls + CloudTAK update reliability

**Headline: Guard Dog now catches the slow-disk problem that silently takes TAK stacks down — and the CloudTAK "update available" banner stops crying wolf.** On shared/cloud hosting, a disk can pass a normal speed test while individual database writes stall for seconds — exactly the condition that quietly snowballs into an Authentik/login slowdown. Guard Dog now measures small-write commit latency directly (the metric that actually matters for the database), charts it alongside throughput, and warns you when it crosses a safe ceiling. Even better, when slow commits coincide with the database having clients waiting, Guard Dog sends a distinct "provider disk contention — act now" alert that points you at your host *before* an outage instead of after — and its disk report now matches the small-write numbers your provider quotes. **Also in this release:** CloudTAK's "Update Now" no longer shows a stuck "update available" badge after a successful update — CloudTAK's upstream sometimes ships a release whose internal version label lags the release tag, which made the console think an update never took; the console now reads the release correctly and shows the true version. **Upgrade:** applied automatically; the new disk-latency watch rides Guard Dog's existing schedule and the CloudTAK fix takes effect on the next console restart.

Full notes: [v0.9.54-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.54-alpha).

### v0.9.53-alpha — 2026-06-11 — Self-hosted NetBird VPN module

**Headline: stand up a private, self-hosted VPN for your TAK deployment in one click — with single sign-on built in.** NetBird gives you a zero-trust WireGuard overlay network deployed straight from the console — no SSH, no third-party VPN service, no cloud dependency. You sign in with your existing Authentik accounts (the same identity as the rest of your TAK stack), and access is restricted to operators: the VPN is bound to your admin group, so an ordinary SSO user can't join the network. Use it to securely reach your TAK box, or to link sites and remote sensors over an encrypted private overlay. The module pins vetted NetBird images for fleet-consistent installs and reloads the web proxy gracefully so other services stay online during deploy. **Upgrade:** the NetBird module appears in the console — deploy it when you want it; existing services are unaffected.

Full notes: [v0.9.53-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.53-alpha).

### v0.9.52-alpha — 2026-06-11 — ArcGIS configurator: per-class polygon styling + decoded zone labels

**Headline: ArcGIS feeds can now be styled per feature class, and coded data fields show their real labels everywhere.** Polygon and polyline feeds get per-class styling — distinct stroke color, fill color, fill opacity, line thickness, and line style for each class, with anything you leave unset inheriting the feed's uniform style. Coded-value fields (a field that stores a number like `1`/`2` that actually means something like "Infested Zone"/"Adjacent Surveillance Zone") now display the human label everywhere — the configurator preview, the class and source-filter pickers, the on-map callsign, and the DataSync feed's item names — instead of the raw code. Large polygons render much smoother in TAK while staying light enough not to stall the web client: each feed automatically gets a per-shape point budget tuned to how many features it has, so a handful of big boundaries keep their detail while a feed of hundreds stays performant — no tuning required. **Also in this release:** style and label edits now reliably reach TAK on the next sync; the per-feed TAK group is no longer hardcoded; and the dev-channel update path is more reliable. **Upgrade:** applied automatically; existing feeds are unaffected and pick up the improvements on their next sync.

Full notes: [v0.9.52-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.52-alpha).

### v0.9.51-alpha — 2026-06-10 — Bring-your-own TLS certificate + cleaner service removal

**Headline: you can now use your own TLS certificate instead of Let's Encrypt.** When you set up your domain (or later on the Caddy page) you can choose **Custom certificate** and upload your own full-chain PEM + private key. It's applied to every subdomain and to TAK Server's enrollment endpoint, so infra-TAK works behind a corporate gateway/WAF or on networks where automatic (ACME) certificates can't be issued — the box never even attempts Let's Encrypt in this mode. Your upload is validated first (the key matches the certificate, it isn't expired, and it covers your hostnames), Caddy reloads with no downtime, and there's a one-click switch back to automatic. Renewal is a manual re-upload, with the existing certificate-expiry indicator and Guard Dog alert watching the date. **Also in this release:** uninstalling a service (MediaMTX, TAK Video Restreamer, Node-RED) now removes it cleanly from Authentik instead of leaving a dead entry behind — and any box that already had a leftover is tidied up automatically on the next restart; and the TAK Video Restreamer "update available" check is now reliable. **Upgrade:** applied automatically; no action required.

Full notes: [v0.9.51-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.51-alpha).

### v0.9.50-alpha — 2026-06-09 — Node-RED Configurator configs survive updates

**Headline: updating your box will no longer wipe the feeds you built in the Node-RED Configurator.** Configurator configs (ArcGIS/TAK feeds, TextChat, PulsePoint, IPAWS, TAK settings) live in Node-RED's in-memory state, and a chain of flaws in the backup/restore path could erase them on an update or restart — and the emergency restore sometimes loaded nothing. This release hardens that path end to end: configs are now backed up to disk the instant you save **or** delete one; the persistence setting is written to the file Node-RED actually reads (and verified); a restore can never replace your live feeds with an older, smaller backup (it keeps the larger set); and the restore screen now tells you the real config counts instead of silently "succeeding" with an empty backup. Field-validated on two boxes (≥99-min soak): a full update kept every config, and they also survived a Node-RED restart. Also: CloudTAK's `/sw.js` is now served no-cache so the browser picks up new builds sooner, and stale "hard-refresh" advice (which never worked) was replaced with the **Clear site data** steps that do. **Upgrade:** applied automatically. Configs already lost before this release can't be recovered, but anything you (re)create now will stick.

Full notes: [v0.9.50-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.50-alpha).

### v0.9.49-alpha — 2026-06-08 — CloudTAK "Update Now" reaches the latest release cleanly

**Headline: updating CloudTAK from the console works again, and the version readout tells the truth.** Two fixes. (1) **"Update Now" no longer fails at the final step.** Updating to the current CloudTAK release used to die with `address already in use` on port `:9997`: the update checks out the new version, which resets CloudTAK's container port bindings back to the public defaults, and that collided with the auth-gated video proxy added in v0.9.48. The updater now re-applies the loopback port hardening immediately after checkout, so the rebuild completes and the box lands on the latest CloudTAK — this also re-closes a set of CloudTAK admin ports that every past update briefly re-exposed until the next restart. (2) **No more phantom "update available."** When CloudTAK's published version number lags its release tag, a fully-updated box used to show a permanent "update available" badge; the console now recognizes it is current and clears the badge, while still flagging a genuinely failed update. **Upgrade:** applied automatically — after updating the console, run CloudTAK **Update Now** to move to the latest CloudTAK.

Full notes: [v0.9.49-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.49-alpha).

### v0.9.48-alpha — 2026-06-08 — CloudTAK foreign-source video (RTSP/SRT) plays in the browser map

**Headline: CloudTAK's built-in video proxy now works end-to-end.** When a CoT carries a video URL from a *separate* media server — an RTSP or SRT feed (e.g. a drone published to another MediaMTX) — CloudTAK's embedded media server now ingests it and serves browser-playable HLS, and it **keeps playing** instead of dropping after ~10 seconds. Four root causes fixed: (1) CloudTAK addresses its media server on port `:9997`, which the console's reverse proxy never exposed, so every video lease timed out — the console now fronts that port (still TLS + auth-gated, no new attack surface); (2) the embedded media server's HLS profile is tuned for low-latency playback (~3s behind the source); (3) a teardown bug that deleted the active viewer's stream every 10 seconds is fixed, so video holds while open and is still cleaned up on close (no leak); (4) SRT feeds whose stream id contains `#` (e.g. ATAK's UAS Tool) now connect automatically with no manual URL edits. All of it is applied as a self-heal that converges on every box and survives CloudTAK updates. Also in this release: the CloudTAK updater now surfaces the *real* error when an upstream rebuild fails (instead of a misleading "docker-compose: not found"), and the console reports the actually-running CloudTAK version. **Upgrade:** applied automatically on update — no action needed.

Full notes: [v0.9.48-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.48-alpha).

### v0.9.47-alpha — 2026-06-07 — Custom TAK Portal domain · Network & Fanout metrics · WebODM resource cap

**Headline: three areas.** (1) **TAK Portal links + Authentik forward-auth now honor a custom Caddy domain.** If you set a custom TAK Portal domain in the Caddy module (e.g. `portal.<fqdn>` instead of the default `takportal.<fqdn>`), the console's TAK Portal buttons, the Self-Service Enrollment URL, and — critically — Authentik's proxy `external_host` now all resolve that configured domain instead of hardcoding `takportal.<fqdn>`. The startup canonicalizer used to silently revert Authentik's `external_host` back to the default on every restart, breaking forward auth on the custom host (GH #41); it no longer does. IP-only / no-FQDN boxes are unchanged. (2) **Network & Fanout monitoring panel** (Guard Dog extension) makes TAK Server CoT-fanout load browser-visible — external NIC throughput, kernel `:8089` send-queue depth (the leading indicator of fanout backpressure, separated from stalled connections), connected-client count, and JVM heap, each with an inline "how to read it" guide. (3) **WebODM hardening:** a co-located ODM processing job is now hard-capped (CPU + memory + thread concurrency) so it can't starve or OOM the rest of the TAK stack — applied at deploy and **self-healed onto existing WebODM installs on the next console restart, no redeploy** (GH #32); plus the WebODM remote-deployment **Test connection / Save / SSH-key** buttons now correctly show success instead of a false red error (GH #31).

Full notes: [v0.9.47-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.47-alpha).

### v0.9.46-alpha — 2026-06-07 — Fed Hub co-location guard + split remote-server hardening

**Headline: two areas, both surfaced by a field-reported split (two-server) deployment.** (1) **Federation Hub can no longer be deployed on the same OS as TAK Server.** The hub's JVM + MongoDB would contend with TAK Server's JVM + Postgres for RAM (MongoDB alone defaults to ~50% of system memory) and a single outage would take down both. The Deployment Target page now disables the "this machine" option and forces a separate SSH target when TAK Server is present — a dedicated console host with no TAK Server still deploys the hub locally; an already-deployed local hub is grandfathered with a migrate-recommended notice. (2) **Split-deployment security + reliability hardening.** The Guard Dog **Health Agent** on the remote DB server now turns green on private-LAN splits: its `:8080` UFW rule is scoped to the source IP the DB box *actually sees* from the console (`$SSH_CLIENT`), not a possibly-private configured `server_ip` — and a UFW rule-ordering bug (a `deny` appended *above* the `allow`, so first-match-wins kept blocking) is fixed. The remote **Postgres `5432`** and the **Federation Hub UI `8080`/`9100`** ports that earlier builds left `ALLOW Anywhere` (Postgres and the hub admin UI, incl. plaintext 8080, reachable from the internet) are now scoped to the console and denied to the world — the legacy broad allow that shadowed the deny is deleted, the core never loses its DB, and the Fed Hub firewall **re-converges on every console restart with no `.deb` update**. The Guard Dog **DB-auth** check no longer false-fails when the database password contains an XML-special character (`&`/`<`/`>`/`"`/`'`) — it decodes CoreConfig's XML entities like TAK's JDBC does, and surfaces the real PostgreSQL error (password vs `pg_hba` vs missing-db) instead of a blanket "rejected". And remote `VACUUM`/`REINDEX` no longer leak a harmless-but-alarming `could not change directory to "/root"` warning.

Full notes: [v0.9.46-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.46-alpha).

### v0.9.45-alpha — 2026-06-06 — webadmin LDAP login on no-hairpin / self-hosted boxes

**Headline:** `webadmin` 8446 login now works on self-hosted boxes behind NAT that lack hairpin routing (home lab / Hyper-V / Starlink) — **even with a public IP and full port forwarding**. The Authentik LDAP outpost's internal→FQDN routing migration was silently aborting on those boxes: its pre-check needed NAT hairpin (a container reaching its own host's public IP), the `docker exec wget` probe hung until a 15s timeout, and the box stayed on spiral-prone internal routing — so `webadmin` cold binds died with `exceeded stage recursion depth` (a flow spiral, not a wrong password) and 8446 rejected the correct password. The migration now treats the hairpin timeout as the signal it is and routes the outpost to Caddy via the host gateway (`extra_hosts: host-gateway`) instead, with the existing post-recreate validation + auto-rollback as the safety net; the **Resync LDAP to TAK Server** button runs it directly and visibly. Plus three supporting fixes: the LDAP bind verifier no longer shows a false-red "NOT READY" when `ldapsearch` can't be installed (tri-state OK / FAIL / UNVERIFIED, with a hardened install that rides out apt locks); the outpost-log diagnostic is un-truncated and classifies the failure (flow spiral vs invalid credentials vs authenticated); and the Download Certificates password no longer shows the pre-deploy default until you refresh.

Full notes: [v0.9.45-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.45-alpha).

### v0.9.44-alpha — 2026-06-03 — Daily console-restart timer (wedged-worker recovery)

**Headline:** the console (`takwerx-console`, gunicorn 1 worker / 4 threads) can wedge — the worker stops serving while port 5001 stays in `LISTEN`, so systemd still reports `active (running)` and nothing recovers it; front door and backdoor both hang while Authentik stays up (observed in the field after 5–7 days of uptime). The only periodic restart in the project was Authentik's — the console had none. This adds **`takconsolerestart.timer`**: a daily 04:00 oneshot that bounces the console (idle-gated via a new localhost-only `GET /api/console/restart-safe`, so it defers if a deploy/update is in flight and restarts immediately if the worker is unresponsive). Self-installs on every boot via `_startup_migrations`, so fresh installs and existing boxes both get it on their next restart. Bonus: a long-lived console now loads pulled code instead of running a stale process across `git pull`s.

Full notes: [v0.9.44-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.44-alpha).

### v0.9.43-alpha — 2026-06-03 — CloudTAK Dispatcher plugin + webadmin LDAP spiral deploy hardening

**Headline: two areas.** (1) **CloudTAK Dispatcher plugin** — a Computer-Aided Dispatch panel inside CloudTAK, installed from CloudTAK → Plugins and deployed from its own public repo (`takwerx/cloudtak-dispatcher-plugin`, like the ping plugin). Works **standalone** with no TAK-CAD server plugin: incidents are server-backed in CloudTAK's own Postgres (shared across dispatchers), drawn on the map as native CoT and optionally pushed into a DataSync feed so every client (ATAK/iTAK/TAK Aware/WinTAK) sees them; multi-select responder assignment with notification over mission thread + direct message; markers use a foldered color-less `iconsetpath` that renders on all field clients. Auto-upgrades to full TAK-CAD mode when the TAK-CAD server plugin is detected. (2) **webadmin LDAP spiral deploy hardening** — fresh TAK Server installs on boxes that can't reach FQDN/Caddy routing (no public IP / no LE cert / slow disk) were dead-ending at the final `webadmin` LDAP-bind verification with `exceeded stage recursion depth` (a flow spiral, not a bad password). The deploy now repairs the flow before retrying, the verifier no longer destroys the webadmin user on a spiral verdict (which had wiped the cached session and locked the box into a cold-spiral loop), and a verify miss no longer aborts the whole deploy. Plus CloudTAK plugin install/update robustness (copy-not-symlink, restore plugins after a CloudTAK update, container-ID version check, GitHub-tag-fetch tolerance).

Full notes: [v0.9.43-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.43-alpha).

### v0.9.42-alpha — 2026-05-29 — TAK Video Restreamer module

New Marketplace module: **TAK Video Restreamer** (`raytheonbbn/tak-video-restreamer`) — a Flask + MediaMTX + FFmpeg streaming server deployed as a Docker container, behind Caddy at `stream.<FQDN>`. Mutually exclusive with the standalone MediaMTX module (shared streaming ports; the console blocks deploying both). Built-in Flask admin login (separate from Authentik), changeable without a rebuild. RTSP/RTSPS/SRT/RTMP/HLS-ABR endpoints, Guard Dog HTTP monitor on `/login:3100`, Update Now via `git pull` + `docker compose up -d --build`.

Full notes: [v0.9.42-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.42-alpha).

### v0.9.41-alpha — 2026-05-28 — LDAP spiral fix + Azure External DB hardening

Two bug areas: (1) **LDAP identification-stage spiral** — a silent PATCH failure left every webadmin bind returning error 49, spiraling across resync attempts. (2) **Azure External DB** — five hardening fixes covering extension provisioning, deploy gating, SchemaManager execution, uninstall cleanup, and a malformed-XML crash from `&` in generated passwords.

Full notes: [v0.9.41-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.41-alpha).

### v0.9.40-alpha — 2026-05-27 — Azure PostgreSQL end-to-end support + CloudTAK first-time setup guide + MediaMTX readiness fix

**Headline: four areas.** (1) **Azure PostgreSQL Flexible Server** — full end-to-end External DB support: auto-create `cot` database, grant `azure_pg_admin` to `martiuser`, pre-create all 5 required extensions as admin so SchemaManager never hits the extension permission wall, Test Connection Azure extension probe with exact portal instructions if any are missing, collapsible Azure pre-flight guide in the UI, uninstall drops the remote `cot` database for clean re-deploy. (2) **External DB UX fixes** — button order corrected (Provision → Test), admin username field uses placeholder instead of hardcoded `postgres`, passwords with `#` no longer break psql `-v` parser, provision correctly targets `postgres` DB first, deploy mode preserved after Configure. (3) **CloudTAK first-time setup guide** — collapsible three-step card on the CloudTAK page: create `cloudtakadmin` in TAK Portal (with org-suffix warning), download `user.p12` + cert password from Certificates page, configure CloudTAK with `takserver.fqdn` + credentials + cert; bootstrap is one-time, subsequent users just log in with username and password. (4) **MediaMTX readiness poll** — deploy now waits up to 30s for `systemctl is-active mediamtx` before declaring success, eliminating the "Not Found" error when operators hit `stream.fqdn` immediately after deploy.

Full notes: [v0.9.40-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.9.40-alpha).

Older releases: [GitHub Releases tab](https://github.com/takwerx/infra-TAK/releases) — each tag carries its full release notes.


## License

Copyright (C) 2026 Andreas Johansson (TAKWERX).

infra-TAK is free software, licensed under the
**[GNU Affero General Public License v3.0 or later](LICENSE)** (AGPL-3.0-or-later).

You may run it, study it, modify it, and share it — for any purpose, commercial
or not, with no fee and no per-seat licence. What the AGPL adds over a permissive
licence is a guarantee that it **stays** free: if you modify infra-TAK and let
other people use it — including over a network, as a hosted console — you must
offer those users the complete corresponding source of your modified version
under the same licence (AGPL §13). That is the point. Nobody can take this,
close it, and sell it back to the emergency-services community.

**If you only deploy and use infra-TAK, this obligation never touches you.**
Running the console for your own agency — however many boxes, however many users
— triggers nothing. The source offer is owed only by someone who *modifies* the
code and then serves it to others.

**Scope.** The AGPL covers infra-TAK's own code. It does not change the licence
of the software infra-TAK installs and orchestrates — TAK Server, Authentik,
CloudTAK, Caddy, MediaMTX, Node-RED and the rest are separate programs, invoked
at arm's length over Docker and systemd, and each keeps its own licence and its
own terms.

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
contribution terms and the [Contributor Licence Agreement](CLA.md).

Releases before v10.1.47 were published under the MIT licence and remain
available under those terms.

## Credits

Built by [TAKWERX](https://github.com/takwerx) for emergency services.
