# Recovery

Use this page when the console will not start, **Update Now** fails, or you cannot sign in.
Back to the [README](../README.md).

## Universal recovery (SSH)

Use this on the **VPS** when anything below is true:

- **Update Now** failed (including **`would clobber existing tag`**, merge/rebase errors, or a vague git error).
- The sidebar **VERSION** does not match the **Latest release** line at the top of the [README](../README.md) (e.g. stuck on **v0.2.4** while the README says **v0.4.5-alpha**).
- You are unsure whether **`git remote -v`** points at **`github.com/takwerx/infra-TAK`** (forks, typos, and old mirrors leave **`origin/main`** years behind — **`git fetch origin`** is not safe until **`origin` is fixed**).

This pulls **`main` from the official repo URL** (same as the **Quick Start** in [INSTALL.md](INSTALL.md#quick-start)), checks **`VERSION`**, restarts the service. Your **`.config/`** is not touched.

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

**After the console is up:** If **Guard Dog** is installed, open **Guard Dog** and click **↻ Update Guard Dog** once (see the **Guard Dog** note under **Quick Start** in [INSTALL.md](INSTALL.md#quick-start)).

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

Full relay documentation: [RELAY-SETUP.md](RELAY-SETUP.md).

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
