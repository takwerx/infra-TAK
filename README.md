# infra-TAK

Team Awareness Kit Infrastructure Management Platform.

One clone. One password. One URL. Manage everything from your browser.

**Current release: [v10.4.10-alpha](https://github.com/takwerx/infra-TAK/releases/tag/v10.4.10-alpha)**

Older releases on the [GitHub Releases tab](https://github.com/takwerx/infra-TAK/releases) — each tag carries its full release notes.

**Something broken?** Wrong sidebar version, **Update Now** error, merge/rebase/tag-clobber messages, or you are not sure the VPS ever pulled the real repo → go to **[Universal recovery (SSH)](docs/RECOVERY.md#universal-recovery-ssh)** and run the one block there. **Point people at that page**; it is the single source of truth.

**Universal installer.** Supported platforms: **Ubuntu 22.04 LTS or 24.04 LTS**, **Rocky Linux / RHEL 9**, and **ARM64** (aarch64, e.g. Jetson Orin). The same one-clone install detects your OS, package manager (`apt`/`dnf`), and architecture and configures the firewall (ufw on Ubuntu, firewalld on RHEL) automatically. Existing Ubuntu 22.04 installs upgrade to 24.04 from the **Console** page — take a snapshot first. *ARM64 is validated on Ubuntu 22.04. ARM64 caveats: Cesium 3D-tiles (pmtiles) and Federation Hub are not yet available on ARM — see the release notes.*

## Contents

- [What Is This?](#what-is-this)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [Architecture](#architecture)
- [QR Code Enrollment](#qr-code-enrollment)
- [Security](#security)
- [Design notes](#design-notes)
- [Changelog](#changelog)
- [License](#license)
- [Credits](#credits)

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

The script detects your OS, installs what it needs, asks you to set an admin password and starts the web console. Open the URL it prints and log in.

Requirements, the deployment order, updating, branches and first-boot notes are in **[docs/INSTALL.md](docs/INSTALL.md)**.

**Forgot the console password?** Run this on the server, from the directory the console runs from. It asks for a new password twice and restarts the console:

```bash
systemctl cat takwerx-console | grep WorkingDirectory   # shows the live install dir
cd /opt/infratak   # ← use the directory the line above shows
sudo ./reset-console-password.sh
```

More ways back in (backdoor port, SSH tunnel, relayed boxes): **[docs/RECOVERY.md](docs/RECOVERY.md)**.

## Documentation

| Page | What is in it |
|------|---------------|
| [Install and set up](docs/INSTALL.md) | Quick Start details, requirements, disk I/O check, deployment order, remote hosts and firewalls, access modes and DNS names |
| [Recovery](docs/RECOVERY.md) | Universal recovery over SSH, the console backdoor, hardened servers, relayed boxes, password reset |
| [Ports](docs/PORTS.md) | Every port, by exposure tier |
| [Console actions](docs/CONSOLE-ACTIONS.md) | What each button does and when to use it, CloudTAK build hooks, your own Caddy lines |
| [Architecture](ARCHITECTURE.md) | How the code is organized and why it is one service |
| [Module development](docs/MODULE-DEVELOPMENT.md) | Building a Marketplace module |
| [Changelog](CHANGELOG.md) | Every release, newest first |

## Architecture

```
start.sh                    ← One CLI command to launch everything
├── app.py                  ← Gunicorn web application (HTTPS on :5001)
├── uploads/                ← Uploaded .deb packages
└── .config/                ← Auth + settings (gitignored)
```

The full codebase map is in **[ARCHITECTURE.md](ARCHITECTURE.md)**. To build a Marketplace module, start with **[docs/MODULE-DEVELOPMENT.md](docs/MODULE-DEVELOPMENT.md)**. Every port is listed in **[docs/PORTS.md](docs/PORTS.md)**.

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

For security officers and IT reviewers: **[How we keep infra-TAK secure](docs/SECURITY-PRACTICES.md)** ([PDF](docs/infra-TAK-security-practices.pdf)) says what we do to find and fix problems, how fast we patch, what is still open, and how to report a problem or suggest something we should test.

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
