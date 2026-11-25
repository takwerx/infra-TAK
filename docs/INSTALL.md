# Install and set up

Everything you need to install infra-TAK and deploy your first services. Back to the [README](../README.md).

## Quick Start

```bash
# Ensure git is installed (Ubuntu usually has it; bare RHEL/Rocky cloud AMIs often don't)
command -v git >/dev/null 2>&1 || { command -v apt-get >/dev/null 2>&1 && sudo apt-get update -qq && sudo apt-get install -y git; } || { command -v dnf >/dev/null 2>&1 && sudo dnf install -y git; }

git clone --depth 1 https://github.com/takwerx/infra-TAK.git
cd infra-TAK
sudo ./start.sh
```

**First boot / automatic updates:** On a new Ubuntu VPS, **`apt`** may run right after SSH is available. **`systemctl status unattended-upgrades`** often shows **active (running)** for **`unattended-upgrade-shutdown`** — that idle process is **normal** and is **not** blocking installs. If **`apt-get`** still reports **“Could not get lock”**, wait until **`sudo fuser /var/lib/dpkg/lock-frontend`** shows nothing, then run **`sudo ./start.sh`** again. **`start.sh`** waits for **real** apt/dpkg activity and for **dpkg/apt lock files** before installing packages.

**Branches:** Default clone uses **main** (stable; tagged releases). For latest features and fixes before they're merged to main, use the **dev** branch: `git clone --depth 1 -b dev https://github.com/takwerx/infra-TAK.git`. The README and [CHANGELOG.md](../CHANGELOG.md) reflect main; dev may include remote deployment, UI tweaks, and fixes not yet in a release.

The script will:
1. Detect your OS, package manager (**Ubuntu 22.04/24.04 `apt`** or **Rocky/RHEL 9 `dnf`**), and architecture (**x86-64 or ARM64**) — and on RHEL install + start **firewalld** automatically
2. Wait if automatic updates hold **apt/dpkg**, then install Python dependencies
3. Ask you to set an admin password
4. Start the web console

Then open your browser to the URL shown and log in.

**Updating:** After `git pull` or **Update Now**, restart the console with `sudo systemctl restart takwerx-console`. Your password and config live in the install directory's `.config/`. If you run `start.sh` from a different clone or path, the service keeps using the original install directory so your password continues to work. **Node-RED / Configurator code** (`nodered/`): after pulling on the VPS, also run **`bash nodered/deploy.sh`** from that install directory.

**Guard Dog — automatic since v0.4.7-alpha:** Guard Dog scripts are automatically re-deployed when the console detects a version change. No manual button press needed after upgrading. The button still exists as a fallback if you change alert email or server nickname. Set **Notifications** → alert email and use **Send test email** to verify. Details: [GUARDDOG.md](GUARDDOG.md).

**Upgrading from v0.1.x to v0.2.0:** v0.2.0 switches from Flask dev server to gunicorn (production server). The upgrade is automatic — just `git pull` and restart. On first restart, the console installs gunicorn, rewrites the systemd service, and starts the production server transparently. No manual steps needed.

**Password not working after update?** Use the **backdoor**: **https://&lt;VPS_IP&gt;:5001** (on a **hardened** server that port is closed — tunnel in with `ssh -L 5001:localhost:5001 <user>@<VPS_IP>` and use `https://localhost:5001` instead; see [Recovery](RECOVERY.md#recovery--backdoor-when-authentik-or-caddy-is-broken)). If login spins or fails, on the server run (from the directory the console runs from — shown by **`systemctl cat takwerx-console | grep WorkingDirectory`**, e.g. `/opt/infratak`): **`sudo ./fix-console-after-pull.sh`** — it pins the config path in the systemd unit and prompts you to set a new password so you can log in again. Alternatively run `sudo ./reset-console-password.sh` from that same directory. After pulling, open the Caddy module and re-save your domain once so the Caddyfile (login bypass) is applied.

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
