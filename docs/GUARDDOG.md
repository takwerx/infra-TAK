# Guard Dog — How it works

Guard Dog is TAK Server health monitoring and auto-recovery: nine monitors plus an HTTP health endpoint. It runs as systemd timers and a small health service.

## Monitors

| Monitor      | Interval | What it does | On failure |
|-------------|----------|--------------|------------|
| **Port 8089** | 1 min  | Checks TAK Server port 8089 is **LISTEN** and a **TCP connect to 127.0.0.1:8089** succeeds within 5s. Queue depth is no longer used — scanners can fill the backlog without triggering a restart as long as TAK accepts connections. | Auto-restart after **5** consecutive failures |
| **Process**   | 1 min  | Verifies all 5 TAK Server Java processes (messaging, api, config, plugins, retention) | Auto-restart after 3 consecutive failures |
| **Network**   | 1 min  | Pings 1.1.1.1 and 8.8.8.8 | Alert only (no restart) — helps tell network vs server issues |
| **PostgreSQL**| 5 min  | Checks PostgreSQL is running | Attempts restart and sends alert |
| **CoT database size** | 6 hr | Monitors the TAK Server CoT (Cursor on Target) database size | Alert when over 25GB (warning) or 40GB (critical). Retention deletes rows but PostgreSQL does not free disk until **VACUUM**; alert includes tips (retention, tak-db-cleanup.service, VACUUM). |

**How to run VACUUM:** On the **TAK Server** page in the console, use **Database maintenance (CoT)** → **Run VACUUM ANALYZE** (safe while TAK is running). For maximum space reclaim, use **VACUUM FULL** during a maintenance window (it locks tables).

| **OOM**       | 1 min  | Scans TAK Server logs for OutOfMemoryError | Auto-restart and alert (once until log clears) |
| **Disk**      | 1 hr   | Root and TAK logs filesystem usage | Alert at 80% (warning) and 90% (critical) |
| **Disk I/O performance** | 15 min | Lightweight `dd` sync-write benchmark to `/tmp`, CSV history, optional email/SMS when 1h avg &lt; 50 MB/s or ~70%+ below 24h rolling avg | **v0.6.6-alpha+:** math fix for drop %; Guard Dog page can **disable the timer** or **mute only disk I/O** email/SMS while keeping other alerts. See the **[v0.6.6-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.6.6-alpha)**. |
| **Certificate**| Daily | Let's Encrypt / TAK Server cert expiry (`takserver-le.jks`) | Auto-renewal runs at 35 days remaining. Alert fires at **25 days or less** — meaning auto-renewal failed and action is required. **v0.3.2-alpha+:** the watch script reads the **actual keystore alias** (TAK hostname), not a hardcoded `takserver` name — redeploy Guard Dog after upgrading so `/opt/tak-guarddog/tak-cert-watch.sh` updates. |
| **Root CA / Intermediate CA** | Escalating | Monitors Root CA and Intermediate CA certificate expiry | First alert at 90 days, then 75, 60, 45, 30, then daily until expiry. Email includes CA name, days remaining, and exact expiry date. |


> **Caddy certificates are NOT monitored by Guard Dog.** Caddy manages its own Let's Encrypt certificates (90-day validity) and auto-renews them at ~30 days remaining. The TAK Server JKS cert is rebuilt from Caddy's renewed cert by the renewal script (fires at ≤35 days). Since both run before 30 days, the Caddy card stays **green** under normal operation. It turns **red at ≤30 days** — meaning renewal ran and failed. No yellow/warning state: if you're below 30 days, something is broken and action is required. Guard Dog's **Certificate** monitor watches the same `takserver-le.jks` and alerts at ≤25 days (giving you a 5-day window after the 30-day failure threshold before emailing).

## Avoiding restart loops and boot races

Guard Dog is designed so that **a restart does not trigger another monitor to restart again in a loop**. Multiple safeguards prevent that:

- **15-minute boot skip**  
  Port 8089, Process, and OOM monitors do not run for the first 15 minutes after boot. That gives TAK Server and PostgreSQL time to start without Guard Dog restarting them during startup.

- **15-minute grace after any restart**  
  After Guard Dog (or anything) restarts TAK Server, no monitor will trigger another restart for 15 minutes. This avoids rapid restart loops.

- **15-minute cooldown between restarts**  
  At most one TAK Server restart per 15 minutes from the 8089 monitor, regardless of how many times the check fails.

- **Restart lock**  
  Only one monitor can perform a restart at a time. Others see the lock and skip, so 8089 and Process (and OOM) never restart in parallel.

- **Service-age grace (10 min)**  
  Before restarting TAK, Guard Dog checks how long ago the TAK service was actually started (by anyone — operator, systemd, or Guard Dog) using `systemctl show ActiveEnterTimestampMonotonic`. If TAK was started less than 10 minutes ago, Guard Dog backs off. This covers operator restarts and reboots, not just Guard Dog's own restarts.

- **Daily restart cap (3/day)**  
  All TAK Guard Dog scripts share a single restart counter (`tak_restart_count_24h`). After 3 restarts in 24 hours, Guard Dog logs `SKIP … manual intervention required` and stops. Prevents infinite loops from destroying the system.

- **Clean restart**  
  Instead of `systemctl restart takserver` (which orphans Java processes on TAK's LSB init script), Guard Dog does: `stop → pkill -9 -u tak → rm -rf /opt/tak/work → start`. This kills orphan Java processes and clears the Ignite cache.

- **Boot sequencer (staggered start)**  
  When Guard Dog is deployed, it installs two systemd hooks that orchestrate the full boot sequence:
  1. **Pre-start** (`tak-boot-sequencer.sh` as `ExecStartPre`): stops *all* non-essential services (Authentik, TAK Portal, CloudTAK, Node-RED, MediaMTX) and waits for PostgreSQL. Caddy is left running — it's lightweight and harmless.
  2. **Post-start** (`tak-post-start.service`): waits for TAK Server to be listening on 8089 (up to 15 min), then starts services one at a time: Authentik (waits for healthy) → TAK Portal → CloudTAK → Node-RED → MediaMTX.

  This prevents the CPU stampede where 5 TAK Java processes + Docker containers all compete for CPU simultaneously. Only services that are actually installed are stopped/started; everything else is skipped.

- **TAK Server soft start**  
  The same systemd drop-in ensures TAK starts **after** `network-online.target` and `postgresql.service` (or `postgresql-15.service`). That prevents TAK Server from starting before the network or database are ready.

- **4GB swap**  
  On deploy, Guard Dog ensures a 4GB swap file exists at `/swapfile` (create if missing, enable and add to `/etc/fstab`). This matches the reference TAK Server Hardening script and helps memory stability under load (reduces OOM risk during spikes).

## Health endpoint

Guard Dog runs a small HTTP service on **port 8080**. The path `/health` returns 200 when TAK Server is considered healthy (port 8089 and processes). infra-TAK's Caddy config also exposes this as `https://<infratak-host>/health`, so Uptime Robot can check over normal HTTPS/443 without opening 8080 publicly. **Use that URL as-is (no port)** in Uptime Robot.

### Dedicated health domain (e.g. health.example.com)

If you want a separate hostname for monitoring (e.g. `https://health.tntak.net/health`), add a server block to the Caddyfile **below** this line so infra-TAK does not overwrite it when it regenerates the file:

```
# --- User-added blocks (do not remove) ---
```

Example (add once; it will be preserved across domain changes and deploys):

```
# --- User-added blocks (do not remove) ---
health.tntak.net {
    reverse_proxy 127.0.0.1:8080
}
```

Then point DNS for `health.tntak.net` at your server and use `https://health.tntak.net/health` in Uptime Robot.

## Remote Database — Health Agent red

In **two-server** mode, Guard Dog deploys a small **health agent** on Server One (the DB server) that listens on **port 8080** and serves `/health`. The **Health Agent** monitor (under Remote Database in the UI) is **green** when the console can reach `http://<Server One IP>:8080/health` and it returns 200.

**Why it might be red:**

- **Agent not deployed** — The agent is installed automatically during **two-server step 4 (Deploy Server One)** when an SSH key to Server One is set, so a fresh two-server install gets the agent before Guard Dog is deployed. Guard Dog also deploys the agent when you deploy Guard Dog (if two-server + SSH are configured). If you set up two-server after installing Guard Dog, or SSH failed during step 4 or Guard Dog deploy, the agent may not be there. **Fix:** Use **Deploy health agent to Server One** on the Guard Dog page, or re-deploy Guard Dog.
- **Agent not running on Server One** — On Server One run `systemctl status tak-db-health`. If it’s inactive, run `sudo systemctl start tak-db-health` and `sudo systemctl enable tak-db-health`.
- **Port 8080 not reachable** — Server Two (the console host) must be able to reach Server One:8080. On Server One run `sudo ufw allow 8080/tcp` (or allow from Server Two’s IP only) and ensure nothing else is blocking 8080.
- **Agent returns 503** — The agent returns 200 only when PostgreSQL is ready, the `cot` database exists, and disk usage is under 90%. If any of those fail, it returns 503 and the monitor shows red. Fix PG, the database, or disk on Server One.

**TCP + SSH** (the other Remote Database check) only verifies port 5432 and SSH; it does not run the agent. So TCP + SSH can be green while Health Agent is red if the agent isn’t installed or 8080 isn’t open.

**After migrating the database to a new Server One:** The console monitors (**TCP + SSH**, **Health Agent**) use the **saved TAK deployment** `server_one.host` (same as **DB Auth**). On successful migration, infra-TAK also rewrites `/opt/tak-guarddog/guarddog.conf` and `tak-remotedb-*.sh` so timer-based alerts match the new host. If you moved DB before this behavior existed, click **Deploy health agent to Server One** once (it also runs that sync) or use **↻ Update Guard Dog** / redeploy Guard Dog to refresh scripts.

## Alerts

**Upgraded infra-TAK from before v0.2.7-alpha?** Open **Guard Dog** → **↻ Update Guard Dog** once so installed scripts match the new email path. See the [v0.2.7-alpha release notes](https://github.com/takwerx/infra-TAK/releases/tag/v0.2.7-alpha).

Configure an alert email in the Guard Dog **Notifications** section. **All Guard Dog email alerts** (monitors, updates, cert expiry, etc.) are sent through the **Email Relay** you set up (e.g. Brevo SMTP): the watch scripts call the console, which sends via the same path as the "Send test email" button. No system `mail` command is used. Optional SMS (Twilio or Brevo) can be set for critical alerts.

**Which server?** Every alert includes the server identity so you can tell which host sent it when monitoring multiple infra-TAK servers. In **Guard Dog → Notifications** you can set an optional **Server nickname** (e.g. Production, Staging). Alerts then show the nickname plus IP/FQDN (e.g. `Production (63.250.55.132)`). Without a nickname, the subject and body use your configured FQDN and IP from **Settings**, or the OS hostname if neither is set. Use **Save email & nickname** to apply the nickname without redeploying; re-deploy or **Update** after changing server IP or FQDN to refresh the identifier.

### Update notifications (infra-TAK, Authentik, MediaMTX, CloudTAK, TAK Portal)

The **Updates** monitor (under Monitors) runs every **6 hours** and checks for newer versions of infra-TAK, Authentik, MediaMTX (binary + web editor), CloudTAK, and TAK Portal. When the set of available updates **changes**, it sends **one email** to the same alert address (no spam — same set is not re-sent for 24 hours).

**Not getting update emails?**

1. **Set the alert email** in **Guard Dog → Notifications** and click **Save email & nickname**.
2. **Update Guard Dog** (or redeploy) so the updates script on disk gets the current email. The script is only written during deploy/update; changing the email alone does not rewrite it until you click **Update**.
3. **Mail delivery** — Alerts go through the console to **localhost:25** (Postfix → your **Email Relay**). Deploy **Email Relay** in infra-TAK and use **Send test email** on the Guard Dog page to verify.
4. **Log** — The script logs to `/var/log/takguard/updates.log` when it runs: "No updates available", "Updates available but already notified", or "Updates email sent to …" (or "FAILED" if mail failed). Run `tail -f /var/log/takguard/updates.log` after the next 6h run to confirm.

## Where to do things (VACUUM, retention, etc.)

| Task | Where | Notes |
|------|--------|------|
| **VACUUM** (reclaim CoT DB disk after retention deletes) | **infra-TAK console → TAK Server** → **Database maintenance (CoT)** | Use **Run VACUUM ANALYZE** (safe while TAK is running). Use **VACUUM FULL** only during a maintenance window (locks tables). |
| **Data retention** (how long to keep CoT data) | **TAK Server's own web UI** (Core Config / Data Retention) | Set TTL and schedule; retention deletes rows but PostgreSQL does not free disk until you run VACUUM. |
| **tak-db-cleanup.service** (if present) | **CLI** | `systemctl status tak-db-cleanup.service`, `sudo journalctl -u tak-db-cleanup.service -f` to see deletion activity. |
| **VACUUM from CLI** | **CLI** | `sudo -u postgres psql -d cot -c 'VACUUM ANALYZE;'` (same as the console button). |
| **Guard Dog activity** (restarts, alerts) | **infra-TAK console → Guard Dog** → **Activity log** | Or on the server: `cat /var/log/takguard/restarts.log`. |

## Scope

Guard Dog monitors **TAK Server** (port 8089, processes, PostgreSQL, CoT DB size, OOM, disk, network, certificate, Root CA / Intermediate CA). When installed, Guard Dog also monitors Authentik, MediaMTX, Node-RED, and CloudTAK (alert and restart on failure). For those, use each module's page for status and the **health endpoint + Uptime Robot** for outside-in checks. Re-deploy Guard Dog to add monitors for services you install later.

## Certificate Rotation Workflow

The Root CA / Intermediate CA monitor is the first step in a rotation workflow:

1. **90 days out** — Guard Dog sends first notification. Go to **TAK Server → Rotate Intermediate CA** to begin rotation.
2. **Rotate** — Creates new Intermediate CA, regenerates admin/user certs, keeps old CA in truststore. **The server TLS cert is not replaced**, so existing ATAK clients keep connecting; new enrollments get certs signed by the new CA. TAK Portal is updated with a **CA bundle containing both** the old and new intermediate CAs so clients who re-enroll once will keep working after Revoke (see [mytecknet.com/tak-pki-intermediateca](https://mytecknet.com/tak-pki-intermediateca/)).
3. **Notify users** — When convenient, have users re-enroll (e.g. scan new CloudTAK QR) to get certs from the new CA.
4. **Revoke old CA** — When everyone has re-enrolled, use **Revoke Old CA** on the TAK Server page. This creates the new server cert (signed by the new CA), removes the old CA from the truststore, and restarts TAK Server. After that, only re-enrolled clients can connect; the server TLS cert is now signed by the new intermediate.

For **Root CA rotation** (rare, ~10 year cycle): this is a hard cutover. New Root CA, new Intermediate CA, all certs regenerated. All clients must re-enroll. Use **TAK Server → Rotate Root CA** during a planned maintenance window.

**If you already rotated and ATAK shows "Remote host cert not trusted":** Earlier rotation behavior replaced the server TLS cert with one signed by the new CA, so clients that only had the old CA in their trust store could no longer connect. **Option A** — Restore from a backup of `/opt/tak/certs` (and CoreConfig.xml) from before the rotation, then restart TAK Server; all clients work again. **Option B** — Have each client update the connection’s trust store with the new CA: download the current server CA chain (e.g. **TAK Server → Download Certificates → truststore.p12** or the PEM chain from the server), then in ATAK edit the connection and set the server certificate/ca to that file (or re-enroll via TAK Portal with a new QR code that includes the new CA). After infra-TAK is updated, future rotations do **not** replace the server cert, so existing clients keep working.

## Runbook vs Guard Dog (disk full, Docker logs, etc.)

If you have a **TAK Server VM runbook** (disk full, Docker container logs, PostgreSQL recovery, journal limits), here’s how it maps:

| Runbook “watch for” | In Guard Dog? | Where else |
|--------------------|----------------|------------|
| **Root disk full** | Yes — **Disk** monitor (alert at 80% / 90%) | Truncate big container logs and set Docker log limits from the Guard Dog page |
| **Docker container logs (e.g. Node-RED 8 GB)** | No — Guard Dog doesn’t truncate or cap logs | One-time: truncate + `scripts/set-docker-log-limits.sh`; see DISK-AND-LOGS.md |
| **PostgreSQL down / recovery** | Yes — **PostgreSQL** monitor + TAK starts *after* Postgres (Guard Dog deploy sets that) | — |
| **TAK Server down (port 8089, processes)** | Yes — **Port 8089** (5 failures; backlog near-full only), **Process** (3 failures) | — |
| **CoT DB size / retention** | Yes — **CoT database size** monitor (alert at 25 GB / 40 GB); VACUUM via TAK Server page | — |
| **OOM in TAK logs** | Yes — **OOM** monitor (scans logs, restart + alert) | — |
| **Authentik / Node-RED / MediaMTX / CloudTAK down** | Yes — **Authentik**: **`/-/health/live/`** or **`/`**, with a **3s** retry before a failed check counts; **Node-RED / MediaMTX / CloudTAK**: unchanged. All: alert + restart after **3** failures when installed | — |
| **Journal / APT / Docker build cache** | No | One-time or periodic: journald limit, `apt-get clean`, `docker builder prune`; see runbook or DISK-AND-LOGS.md |

**Do Guard Dog monitors “just have to run”?** Yes. Once Guard Dog is **deployed**, systemd **timers** run the watch scripts on a schedule (every 1 min, 5 min, 1 hr, 6 hr, or daily). You don’t run them by hand; they run automatically. Use the Guard Dog page **Activity log** (or `/var/log/takguard/restarts.log`) to see restarts and alerts.

**Can you add more?** Yes. If you install more services later (e.g. another Docker stack), **re-deploy Guard Dog** and it will enable the matching service monitors (Authentik, Node-RED, MediaMTX, CloudTAK) for whatever is present. To add new *kinds* of checks (e.g. “Docker log size” or “run builder prune”), you’d add a new script and timer in the Guard Dog deploy logic.

## More

- [infra-TAK README](https://github.com/takwerx/infra-TAK) — Quick start, deployment order, backdoor access
- **Disk full / container logs** — set Docker container log limits from the Guard Dog page (no redeploy needed)
