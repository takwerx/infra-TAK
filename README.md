# infra-TAK

Team Awareness Kit Infrastructure Management Platform.

One clone. One password. One URL. Manage everything from your browser.

**Current release: [v10.4.5-alpha](https://github.com/takwerx/infra-TAK/releases/tag/v10.4.5-alpha)**

Older releases on the [GitHub Releases tab](https://github.com/takwerx/infra-TAK/releases) — each tag carries its full release notes.

**Something broken?** Wrong sidebar version, **Update Now** error, merge/rebase/tag-clobber messages, or you are not sure the VPS ever pulled the real repo → go to **[Universal recovery (SSH)](#universal-recovery-ssh)** and run the one block there. **Point people at that section**; it is the single source of truth.

**Universal installer.** Supported platforms: **Ubuntu 22.04 LTS or 24.04 LTS**, **Rocky Linux / RHEL 9**, and **ARM64** (aarch64, e.g. Jetson Orin). The same one-clone install detects your OS, package manager (`apt`/`dnf`), and architecture and configures the firewall (ufw on Ubuntu, firewalld on RHEL) automatically. Existing Ubuntu 22.04 installs upgrade to 24.04 from the **Console** page — take a snapshot first. *ARM64 is validated on Ubuntu 22.04. ARM64 caveats: Cesium 3D-tiles (pmtiles) and Federation Hub are not yet available on ARM — see the release notes.*

## Contents

- [Universal recovery (SSH)](#universal-recovery-ssh)
  - [If the privilege broker does not start after an update (non-root boxes)](#if-the-privilege-broker-does-not-start-after-an-update-non-root-boxes)
- [What Is This?](#what-is-this)
- [Quick Start](#quick-start)
- [Recovery / backdoor (when Authentik or Caddy is broken)](#recovery--backdoor-when-authentik-or-caddy-is-broken)
  - [If you have applied Hardening (Cyber Controls W1 — SSO + MFA)](#if-you-have-applied-hardening-cyber-controls-w1--sso--mfa)
  - [If your box is behind a relay (no public inbound)](#if-your-box-is-behind-a-relay-no-public-inbound)
- [Deployment Order](#deployment-order)
- [Remote deployment and firewalls](#remote-deployment-and-firewalls)
- [What Gets Automated](#what-gets-automated)
- [Requirements](#requirements)
  - [VPS disk I/O check](#vps-disk-io-check)
- [Architecture](#architecture)
- [Ports](#ports)
  - [Tier 1 — Public (open in UFW)](#tier-1--public-open-in-ufw)
  - [Tier 3 — Caddy-loopback (bound to 127.0.0.1, **deny in UFW**)](#tier-3--caddy-loopback-bound-to-127001-deny-in-ufw)
  - [Tier 4 — Docker-internal (no host port, **service reachable only on the Docker network**)](#tier-4--docker-internal-no-host-port-service-reachable-only-on-the-docker-network)
  - [Tier 5 — Source-scoped (UFW allow from specific peer IP only)](#tier-5--source-scoped-ufw-allow-from-specific-peer-ip-only)
- [Actions Reference (Sync, Update Config, Resync)](#actions-reference-sync-update-config-resync)
  - [TAK Server Page](#tak-server-page)
  - [TAK Portal Page](#tak-portal-page)
  - [Authentik Page](#authentik-page)
  - [Email Relay Page](#email-relay-page)
  - [CloudTAK: keeping your own source patches (pre-build hooks)](#cloudtak-keeping-your-own-source-patches-pre-build-hooks)
  - [Caddy: your own lines inside a generated site](#caddy-your-own-lines-inside-a-generated-site)
  - [General Rules](#general-rules)
- [Access Modes](#access-modes)
  - [Subdomains (DNS)](#subdomains-dns)
- [QR Code Enrollment](#qr-code-enrollment)
- [Security](#security)
- [Design notes](#design-notes)
- [Changelog](#changelog)
- [License](#license)
- [Credits](#credits)

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

### If the privilege broker does not start after an update (non-root boxes)

On a non-root box, root runs the privilege broker from its own copy of the code, one folder per version in **`/usr/local/lib/infratak-broker/`**. The link **`current`** points at the copy in use, and the last 3 copies stay on disk. The console user cannot change these files, so the fix needs root over SSH.

Use this when console actions fail with "broker not answering" after an update, and **`systemctl status takwerx-broker`** shows the broker failing or restarting over and over. Go back to the previous copy:

```bash
sudo ls -lt /usr/local/lib/infratak-broker/
sudo ln -sfn /usr/local/lib/infratak-broker/<previous folder> /usr/local/lib/infratak-broker/current
sudo systemctl restart takwerx-broker
sudo systemctl status takwerx-broker --no-pager
```

**`ls -lt`** shows the newest folder first; **`current ->`** names the copy that fails. Use the folder just below it. Then open a GitHub issue with the output of **`sudo journalctl -u takwerx-broker -n 50 --no-pager`**. The next update that installs a fixed broker moves **`current`** again by itself.

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
command -v git >/dev/null 2>&1 || { command -v apt-get >/dev/null 2>&1 && sudo apt-get update -qq && sudo apt-get install -y git; } || { command -v dnf >/dev/null 2>&1 && sudo dnf install -y git; }

git clone --depth 1 https://github.com/takwerx/infra-TAK.git
cd infra-TAK
sudo ./start.sh
```

**First boot / automatic updates:** On a new Ubuntu VPS, **`apt`** may run right after SSH is available. **`systemctl status unattended-upgrades`** often shows **active (running)** for **`unattended-upgrade-shutdown`** — that idle process is **normal** and is **not** blocking installs. If **`apt-get`** still reports **“Could not get lock”**, wait until **`sudo fuser /var/lib/dpkg/lock-frontend`** shows nothing, then run **`sudo ./start.sh`** again. **`start.sh`** waits for **real** apt/dpkg activity and for **dpkg/apt lock files** before installing packages.

**Branches:** Default clone uses **main** (stable; tagged releases). For latest features and fixes before they're merged to main, use the **dev** branch: `git clone --depth 1 -b dev https://github.com/takwerx/infra-TAK.git`. The README and changelog here reflect main; dev may include remote deployment, UI tweaks, and fixes not yet in a release.

The script will:
1. Detect your OS, package manager (**Ubuntu 22.04/24.04 `apt`** or **Rocky/RHEL 9 `dnf`**), and architecture (**x86-64 or ARM64**) — and on RHEL install + start **firewalld** automatically
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

- **Ubuntu 22.04 LTS or 24.04 LTS**, **Rocky Linux / RHEL 9**, or **ARM64** (Ubuntu 22.04). Fresh installation recommended; existing 22.04 installs upgrade to 24.04 from the Console page.
- **Root access**
- **RAM:** 8 GB+ recommended for TAK Server; more if you run the full stack (Authentik, TAK Portal, Node-RED, MediaMTX, CloudTAK, Guard Dog).
- **Disk:** At max deployment (all modules) you can sit around **26 GB** used. Plan for growth: CoT data, logs, and retention. **50 GB+** disk is recommended so you have headroom; TAK Server's own minimum is 40 GB per the official configuration guide. Apply Docker log limits (Guard Dog → Apply Docker log limits) to avoid containers filling the disk.
- **Disk I/O:** SSD-backed storage strongly recommended. **Test your VPS before deploying** — slow disk I/O causes Docker build timeouts, service startup failures, and unreliable boots. See [VPS disk I/O check](#vps-disk-io-check) below.
- **CPU:** Enough cores for all processes (TAK Server, PostgreSQL, Authentik, Caddy, Node-RED, etc.). TAK Server's minimum is 4 cores; more is better for the full stack.
- **Running in a VM (TrueNAS, KVM, Proxmox, etc.):** set the VM's CPU mode to **host passthrough** or **host model**, not a generic or "basic" CPU. With a generic CPU, TAK Portal and CloudTAK won't start. The console now checks this before it deploys either one and tells you if the CPU is too basic.
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

Building a Marketplace module (descriptor contract, generated API, the `ctx`
seams, privilege model, SSO patterns, review bar):
**[docs/MODULE-DEVELOPMENT.md](docs/MODULE-DEVELOPMENT.md)**.

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
| CloudTAK Media | 9997 | HTTPS | Video control — CloudTAK puts this port on every media URL; Caddy answers it (TLS, auth-gated). Blocked, videos opened from a map marker fail with "Failed to generate proxy stream" |
| TAK Video Restreamer *(when deployed)* | 8555 | RTSPS | TLS-wrapped RTSP (its RTSP and SRT use MediaMTX's 8554 and 8890) |
| TAK Video Restreamer *(when deployed)* | 1935 | RTMP | RTMP publishers |
| ATLAS MDM *(when deployed)* | 8449 | TLS | Enrolled tablets' device channel (mutual TLS) — the provisioning QR points here |
| EUD Remote Assist *(when deployed)* | 8448 | HTTPS | Device API — the enrolment QR points here |
| CoTURN — EUD Remote Assist *(when deployed)* | 3479 / 50000–50050 | TCP+UDP / UDP | TURN control / relayed media |

> **Cloud servers and relays:** infra-TAK opens these ports in the server's own firewall, but it can't reach your cloud provider's firewall (AWS security group, Oracle security list, Azure NSG). Allow the ones you use there yourself, module ports included: a tablet that can't reach 8449 installs the ATLAS agent and then times out. On an Oracle relay, the paste-in rule block in [docs/RELAY-SETUP.md](docs/RELAY-SETUP.md#the-fast-way--cloud-shell-recommended) covers all of them.

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
| CloudTAK | 9997 | CloudTAK media admin API (the container's own publish; the public side is Caddy's listener in Tier 1) |
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

### CloudTAK: keeping your own source patches (pre-build hooks)

CloudTAK **Update** checks out a clean release, so any edit you made to `~/CloudTAK`'s source is wiped before the rebuild. To have it put back every time, put a script in `.config/cloudtak-hooks/pre-build.d/` inside the infra-TAK folder. Executable files there run in name order (`10-…`, `20-…`) right before every CloudTAK build: on Update, on a plugin install/update/remove, and on the tree a failed update rolls back to. They run as the console user, with `~/CloudTAK` as the working directory and `INFRATAK_HOOK_PHASE` (`update` / `plugin` / `revert`), `INFRATAK_CLOUDTAK_DIR`, `INFRATAK_CLOUDTAK_TAG` and `INFRATAK_CLOUDTAK_PREV_SHA` set. If a hook exits non-zero or runs over 5 minutes, the build does not start: the update rolls back and CloudTAK keeps running, and the log names the hook and shows its output. Hooks must be safe to run twice and should fail loudly when the code they patch has moved. The folders and scripts must be owned by the console user and not writable by anyone else, or nothing runs; `chmod -x` a script to turn it off. On a non-root console, anything a hook runs or reads (a script in another user's home, a patch file) must be readable by the console user too, or the hook fails with `Permission denied`. Hooks run only for a CloudTAK on the same server as the console, not for a remote CloudTAK host or a fresh Deploy.

### Caddy: your own lines inside a generated site

infra-TAK rewrites `/etc/caddy/Caddyfile` on every deploy, domain change and Update, so a line you add inside a generated site block is lost. New sites go below the `# --- User-added blocks (do not remove) ---` line at the bottom. For lines that must sit inside a generated site (an extra route on the CloudTAK map host, for example), use the include folders, which infra-TAK never writes:

- `/etc/caddy/sites.d/<host>/*.caddy` is imported as the first line of that host's site block. `<host>` is the site address exactly as the Caddyfile shows it, e.g. `/etc/caddy/sites.d/map.example.com/10-print.caddy`.
- `/etc/caddy/snippets.d/*.caddy` is imported at the top of the file, right after the global options, for named snippets you use from a site file.

Only files ending in `.caddy` are read, so a `.bak` copy is ignored. Files must be readable by caddy (`0644`). Press **Reload** on the Caddy page to apply them; the page lists the files in use. If an include makes the Caddyfile invalid, infra-TAK writes it without any includes so every site keeps working, and the Caddy page names the files and Caddy's error. Fix the file and press **Reload** again.

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

## Changelog

Every release, newest first, is in **[CHANGELOG.md](CHANGELOG.md)**. Each tag also carries its full notes on the [GitHub Releases tab](https://github.com/takwerx/infra-TAK/releases).

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
