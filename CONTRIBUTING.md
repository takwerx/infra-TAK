# Contributing to infra-TAK

infra-TAK is built for emergency services, and it is free software under the
[GNU Affero General Public License v3.0 or later](LICENSE). Contributions are
welcome — bug reports, field evidence from real deployments, and code.

## Before you write code

Open an issue first for anything larger than a bug fix. infra-TAK ships to
agencies running live incidents; a change that is right for one deployment can
break a fleet. Describing the problem before the patch saves everyone the
round-trip.

The most valuable contribution is often not code at all: a precise field report
— what you ran, what you expected, the exact log lines — is worth more than a
speculative fix.

## Ground rules for code

- **Multiplatform is mandatory.** Ubuntu 22.04, Rocky/RHEL 9, and ARM64 are all
  first-class targets. Package installs go through the `apt`/`dnf` shim, firewall
  changes through the `ufw`/`firewalld` shim. "Works on my Ubuntu box" is not done.
- **No hardcoded secrets, and no new unauthenticated surface.** Every new route
  carries `@login_required`. Every newly opened port is justified and firewalled.
- **Fleet-uniform config.** A config value is either a constant every box
  converges to, or is computed from observable signals on that box. Never
  preserve a number someone typed during an incident.
- **State lives in `.config/`** (mode 600), never in the repo.

## Licensing of contributions

By submitting a contribution you agree to the terms in [CLA.md](CLA.md).

In short: you keep the copyright in your work, and you grant TAKWERX a licence
broad enough to ship it as part of infra-TAK. This is what lets the project be
enforced as a whole — the AGPL's promise that infra-TAK stays open is only
meaningful if there is a single party with standing to enforce it.

Sign by adding a `Signed-off-by:` line to your commits:

```
git commit -s -m "your message"
```

That line certifies you wrote the contribution, or otherwise have the right to
submit it under the AGPL, and that you accept [CLA.md](CLA.md).

## Licence headers on new files

Every new source file gets an SPDX identifier and the AGPL notice. For a Python
or shell file:

```
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

For TypeScript/Vue files under `cloudtak-plugins/`, use the `//` comment form.

## Vendoring third-party code

Third-party code must be licence-compatible with AGPL-3.0-or-later. MIT, BSD,
ISC and Apache-2.0 are fine. GPLv2-**only** code is not — it cannot be combined
with AGPLv3. Pin external repositories to a release tag and commit SHA, never to
a moving branch, and note the licence in the pull request.

## Reporting a security issue

Do not open a public issue. Email the maintainers, and give us a reasonable
window to ship a fix before disclosure. infra-TAK runs CJIS-class deployments —
responsible disclosure protects real agencies.
