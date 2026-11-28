# infra-TAK security practices

**For:** security officers and IT reviewers at agencies that plan to deploy infra-TAK.\
**From:** TAKWERX.\
**Version:** 1.0, Nov 23, 2026. The date of the last change is in the Git history of this file.

This paper says what we do today to keep infra-TAK secure, and how you can check it. We say "aligned with" a standard when we follow its practices. We hold no certification and we have had no outside audit. Section 9 lists what is still open.

## 1. What infra-TAK is

infra-TAK is open-source software that installs and runs a TAK Server and its support services on a server that you own: sign-in (Authentik), a web front door with automatic TLS (Caddy), TAK Portal, CloudTAK, video (MediaMTX), Node-RED, a monitor (Guard Dog), and optional modules. You run it on your host, in your network, with your accounts. TAKWERX does not have access to your server and does not receive your data.

The source code is public at github.com/takwerx/infra-TAK. Every claim below can be checked against the public repositories or the release files.

## 2. How we build and release

- **One protected release branch.** Only the owner can change `main`. Changes arrive as reviewed pull requests with automatic checks (tests, compile check, shell lint, code scanning).
- **Every fix has a proof test.** A fix is not accepted without a test that fails before the fix and passes after it.
- **Each release is tested the way a customer uses it.** Before a release we install it fresh on several servers (Ubuntu 22.04, Rocky Linux 9, ARM), update a server from the last public version, deploy every module, connect TAK clients, install CloudTAK plugins, play video, and roll back. A release candidate also runs under watch for 60 minutes (soak).
- **Releases go out on weekday mornings**, so staff are present if a problem shows.
- **Release files you can verify.** Each release has a source archive, a software bill of materials (SBOM, CycloneDX format) and SHA-256 checksums. Release tags are signed.
- **Third-party parts are pinned.** We keep an inventory of every component with its version and where it is set. Components that have caused problems before (Authentik, TAK Server, NetBird and others) move to a new version only after a full test on three or more servers.

## 3. How we find vulnerabilities

**Every day:**

- We compare every component we ship with the CISA Known Exploited Vulnerabilities list, GitHub security advisories for each upstream project, OSV, the NVD, and Ubuntu and Red Hat security notices.
- We rank each result with three measures: the CISA list, the EPSS exploit forecast from FIRST, and CVSS severity.
- We scan our release SBOMs, our dependency lock files and every container image infra-TAK pulls (grype, trivy, osv-scanner).

**Every week:**

- **Code audit.** One part of our own code is audited each week on a fixed rotation (console sign-in and sessions; web front door and single sign-on; secrets and certificates; install scripts; Guard Dog and mail; the three installer tools). The checklist is OWASP ASVS 4.0 Level 2 for web parts and the OWASP Top 10 for scripts.
- **Static analysis** of our code (semgrep, bandit), secret scanning, and configuration scanning of Docker files (trivy).
- **Outside scan.** We install the current release with every module on a new throwaway server and scan it from outside with OWASP ZAP (spider, passive scan, active scan). The question is: what can a stranger reach or break without an account?
- **Hardening baseline.** On the same throwaway server we measure the host and Docker against CIS-based checks (Lynis, Docker Bench for Security) and track the score from week to week. First measured Nov 2026: the host scored 65 out of 100 on the Lynis hardening index, and 46 of 117 Docker Bench checks passed. We are fixing the failed items or writing each one down as accepted, with a reason.

We never run scanners or attack tools against customer servers.

## 4. How fast we patch

Each finding goes into one of four classes, with a written reason:

| Class | Meaning | What happens |
|---|---|---|
| Patch now | Exploited in the wild, or serious and reachable in a default install, with a fix available | Work starts at any hour. Emergency release when tested. |
| Patch next release | Real, but limited exposure | Fixed and tested, ships in the next weekday release. |
| Watch | No fix yet, or exposure not clear | Re-checked on a schedule. |
| Not affected | The vulnerable version or feature is not used | Recorded with the reason, so it is not raised twice. |

Measured examples, Nov 2026:

- A sign-in gap in a module editor, found Nov 10: fixed and released the same day; the wider follow-up audit shipped the next morning.
- Six findings from the Nov 16 code audit: all released between Nov 17 and Nov 19.
- PostgreSQL security release of Nov 12: in our release of Nov 16.

A security fix goes through the same full release test as any other change. A fix that breaks a feature is not done.

## 5. How your operators hear about security updates

- **Guard Dog email.** The monitor on your server sends "Update pending" and "Security update pending" mail to the address you set, with the exact steps (for example "Console page, Update Now").
- **In the console.** The console shows available updates, operating-system patch status and a restart notice, and updates infra-TAK and each module with one button. Updates can be rolled back.
- **Release notes** are written for operators, in plain words.

We describe a vulnerability in public only after the fix is released.

## 6. How infra-TAK is hardened by default

- Web modules are published only through the front door (Caddy) with TLS. Modules that have no login of their own are published only behind single sign-on, or not at all.
- Administrator applications are limited to an administrators group by default (default-deny for new modules).
- Internal service ports listen on the server itself only. Where Docker publishes a port, firewall rules limit who can reach it.
- An optional **Hardened** posture adds per-user multi-factor sign-in for every web application, an idle lock, and removes the shared-password page from the network.
- A Fail2ban module and sign-in rate limits are included.
- Service passwords and keys are generated per server at install time.

## 7. Standards we align with

| Standard | How we use it |
|---|---|
| NIST SSDF (SP 800-218) | We keep a map of each practice to what we do, with evidence and open gaps. It is refreshed each month. |
| NIST Cybersecurity Framework 2.0 | Mapped at function level (Govern, Identify, Protect, Detect, Respond, Recover). |
| OWASP ASVS 4.0 Level 2 | Checklist for the weekly code audit of web parts. |
| CIS Benchmarks | Basis of the weekly host and Docker hardening measurement. |
| CISA Secure by Design | Secure defaults, no default passwords, security updates at no cost, public vulnerability reporting. |

"Aligned with" means we follow these practices and can show evidence. It does not mean certified or compliant.

## 8. Working with us on security

**To report a vulnerability:** send an email to takwerx@gmail.com. Say what is affected, the version, and how to repeat it. Please do not open a public issue, discussion or pull request for a security problem. We answer within 3 working days, work with you in private until a fix is released, and credit you if you want. Only the latest release gets security fixes. The same rules are in [SECURITY.md](../SECURITY.md).

**To suggest something we should test:** open a GitHub issue on the infra-TAK repository. Start the title with "Security test idea:". Describe the kind of attack or weakness you want us to check. Do not include a working exploit, a password or a key. If you think you found a real hole, send an email instead. We add good ideas to our weekly scans and code audits, and we say so on the issue.

## 9. What is still open

We prefer to say this ourselves:

- No outside penetration test or audit yet.
- The weekly outside scan is not signed in. A monthly scan signed in as an administrator, and port and template scans (nmap, nuclei), start in Dec 2026.
- Release SBOMs and archives have checksums but no cryptographic signature of their own yet (the release tags are signed).
- The hardening baseline was first measured in Nov 2026. Items that fail are being fixed or written down as accepted with a reason. A DISA STIG comparison for Ubuntu is planned.
- A written threat model per product is planned.

## 10. What stays your responsibility

- The host: operating-system updates and restarts (infra-TAK shows the status; your policy decides when), disk encryption, physical security, backups off the server.
- The network: firewall in front of the server, DNS, who can reach it.
- The accounts: who is an administrator, multi-factor enrollment, removing people who leave.
- Reading the Guard Dog mail and installing updates.
- TAK Server itself is a U.S. Government product from TAK.gov. You download it under your own TAK.gov account. infra-TAK installs and configures it and does not change its code.

*Questions about this paper: open a GitHub issue on the infra-TAK repository. For anything sensitive, send an email to takwerx@gmail.com.*
