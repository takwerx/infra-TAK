# Setting up a Relay (Oracle Free Tier)

When your box has no public inbound — you're behind CGNAT (Starlink, most cellular) or you move
between networks — it reaches the internet by dialing OUT to a **relay**: a tiny always-free public
VPS. Friends and clients connect to the relay's public address with **no VPN**, the same from any
network your box is on. The relay never sees your TAK traffic in the clear — it forwards raw
encrypted packets straight through to your box.

You create the relay VM once (about 5 minutes in Oracle's console). After that, the **Connect a
Relay** card in the Connectivity page does everything else automatically — you just give it the
relay's IP and upload the key file.

> **Oracle is the walkthrough, not a requirement.** It is used here because it is the only provider
> with a permanently free server that has a public address and real bandwidth. The console only ever
> asks for an IP and an SSH key, so any small VPS works identically — see [Where to run the
> relay](#where-to-run-the-relay--you-are-not-tied-to-oracle). If Oracle keeps telling you it is
> **out of capacity**, go straight to [that section](#if-oracle-says-out-of-capacity) — it is the
> most common thing that stalls people here, and the usual fix takes one dropdown.

## 1. Create the relay

This is two parts — **the network first, then the VM.**

> ⚠️ **Do them in this order.** If you let the instance wizard create the subnet for you, Oracle
> leaves *Automatically assign public IPv4 address* greyed out with the message "You must select a
> public subnet" — even though you just told it to make a public subnet. You end up with a relay
> that has no public address and nothing can reach. Building the network first avoids it entirely.

### 1a. The network (about 2 minutes)

Sign in to the [Oracle Cloud console](https://cloud.oracle.com), then get to the home page: **☰ menu
(top-left) → Home → Infrastructure**. Scroll down to the **Build** panel and click **Set up a network
with a wizard**.

(Long way round if you prefer menus: ☰ → **Networking → Virtual Cloud Networks → Actions → Start VCN
Wizard**.)

1. Choose **Create VCN with internet connectivity** → **Start VCN Wizard**.
2. **VCN name:** `TAK-RELAY-VCN`. **Compartment:** your root/tenancy compartment.
3. **Leave every default.** VCN CIDR `10.0.0.0/16`, public subnet `10.0.0.0/24`, private subnet
   `10.0.1.0/24`, IPv6 off, DNS hostnames on.
4. **Next** → review → **Create**.

That one wizard builds the VCN, a public subnet, a private subnet, an internet gateway, a NAT
gateway, a service gateway, and the route tables. The relay only uses the public subnet; the rest is
harmless. The amber "Resource availability checked successfully" box along the way is informational,
not a problem.

When it finishes it offers **View VCN** — you don't need to look at anything, so go straight on to
1b.

### 1b. The VM (about 3 minutes)

Back to the home page the same way — **☰ menu → Home → Infrastructure** — then scroll to the **Build**
panel and click **Create a VM instance**.

(Long way round: ☰ → **Compute → Instances → Create instance**.)

The wizard runs across four sections — *Basics → Security → Networking → Storage*.

**Basics**

- **Name:** anything (e.g. `tak-relay`). **Create in compartment:** the same one as the VCN.
- **Placement:** leave the availability domain Oracle picked.
- **Image:** click *Change image* → **Canonical Ubuntu** → **22.04 or 24.04** (both field-validated).
  The plain one, not "Minimal".
- **Shape:** click *Change shape* → **Ampere → VM.Standard.A1.Flex**, 1 OCPU / 6 GB (Always Free).

> ⚠️ **The default shape is not free.** Oracle preselects **VM.Standard.E5.Flex** (1 OCPU / 12 GB),
> which is a paid shape. If you click through without changing it you will be billed for a VM that
> only forwards packets.

  - **Pick the image before the shape.** Oracle cross-filters the two lists, so choosing an x86 shape
    first can hide the ARM builds of an image and make it look like that image "isn't available" on
    A1.
  - *If Oracle says "out of capacity"* for A1: that is the shape being full, not a problem with your
    account. The short answer is to pick **VM.Standard.E2.1.Micro** instead — also Always Free, and
    fine for a relay. Full list of things to try: [If Oracle says "Out of
    capacity"](#if-oracle-says-out-of-capacity) below.
  - **ARM or x86 makes no difference here.** A1.Flex is ARM, E2.1.Micro is x86, and the relay setup
    is identical on both — it installs only WireGuard and standard Linux packet forwarding, which
    ship for both architectures. A1 is the better pick when available (more free network bandwidth),
    not a required one.

**Security:** nothing here applies to a relay. You will probably see an amber *"The current instance
settings prevent you from enabling confidential computing"* — that is expected on Ampere shapes and
is not an error. Click **Next**.

**Networking**

- **Primary network:** **Select existing virtual cloud network** → `TAK-RELAY-VCN`.
- **Subnet:** **Select existing subnet** → **public subnet-TAK-RELAY-VCN**. Take the *public* one.
- **Automatically assign public IPv4 address:** **ON**. This is the whole reason for doing 1a first —
  with a pre-existing public subnet the toggle is live.
- **IPv6:** leave off. The "selected VCN and subnet combination does not support IPv6" warning is
  expected.
- Everything else — VNIC name, DNS record, hostname, launch options — stays default.

**Also on the Networking page — SSH keys.** Keep **Generate a key pair for me** and click **Download
private key**. Save that `.key` file somewhere you'll find it: it is the only thing the console needs
to set the relay up, and you never have to open it yourself. You don't need the public key.

> ⚠️ **This is the only time Oracle offers the key.** If this launch attempt fails and you retry,
> download again on the attempt that actually succeeds — each attempt generates a different key.

**Storage:** accept the defaults (46.6 GB boot volume, in-transit encryption on). A relay forwards
packets and stores nothing. Don't attach a block volume.

Then **Create**, and wait for the instance to show **Running**.

## 2. Note the relay's IP

Your VM already has a public address. On the instance page → **Details** tab → **Public IP
address**. **Write it down — that's your relay's IP**, and it's the one thing the console asks you
for in step 6.

That's the whole step. The address stays put through reboots and stop/start; it only changes if you
terminate the instance and build a new one. In step 4 you'll point a domain name at it, so even that
is a one-line DNS edit rather than a problem.

## 3. Open the ports

These are the rules the relay needs. **Set Up Relay** configures the relay itself automatically — the
moment the tunnel comes up these ports are already being forwarded — so Oracle's cloud firewall is
the only part you do by hand.

| Protocol | Port | What it carries |
|---|---|---|
| **UDP** | **51820** | WireGuard tunnel — the console's default port |
| **UDP** | **443** | WireGuard tunnel — the alternate port (restrictive venue Wi-Fi) |
| **TCP** | **80** | Let's Encrypt cert validation + HTTP→HTTPS redirect |
| **TCP** | **443** | HTTPS — every web UI (Portal enrollment, Authentik SSO, CloudTAK, Node-RED, admin console) |
| **TCP** | **8089** | ATAK / iTAK / WinTAK client connections (mutual-TLS) |
| **TCP** | **8443** | TAK admin WebGUI (client-cert auth) |
| **TCP** | **8446** | TAK admin WebGUI (Let's Encrypt cert / LDAP login) |
| TCP | 8554 | MediaMTX **RTSP** video |
| TCP | 8322 | MediaMTX **RTSPS** video |
| UDP | 8890 | MediaMTX **SRT** video |
| TCP + UDP | 3479 | CoTURN control channel — EUD Remote Assist |
| UDP | 50000–50050 | CoTURN relayed media — EUD Remote Assist |
| **TCP** | **5001** | The infra-TAK console's direct-IP backdoor — see the note below |

That list is exactly what the relay forwards — nothing else would get through even if you opened it.

> **About 5001.** That's the console's direct-IP backdoor, the same one every infra-TAK box has and
> the one the README's recovery section tells you to use. It's a password login with no SSO in front
> of it, which is the deal on any box with a public address — and applying **Hardening (Cyber
> Controls W1)** closes it, on a relayed box exactly as on any other, because W1 shuts the port at
> the box's own firewall no matter which way the packet came in.

**There are two ways to enter them. Pick one, not both:**

- **Paste them all at once** — one command in Oracle's Cloud Shell sets every rule in the table.
  Takes about a minute and can't be typed wrong. Carry on reading below.
- **Type them in by hand** — Oracle's rule dialog, one row at a time. Skip ahead to
  *[The manual way](#the-manual-way--oracles-dialog)*.

Same result either way. The paste is recommended; the manual route is there if you'd rather not
touch a command line.

### The fast way — Cloud Shell (recommended)

First get your security list's OCID. **☰ menu → Networking → Virtual Cloud Networks →
TAK-RELAY-VCN → Security tab → click "Default Security List for TAK-RELAY-VCN".** The **OCID** is on
that page with a **Copy** button next to it.

> ⚠️ **Make sure you're one level deep.** The VCN page also shows an OCID, and copying that one is an
> easy mistake — the command then fails with `NotAuthorizedOrNotFound` / 404. Check the prefix: you
> want the one starting **`ocid1.securitylist.`**, not `ocid1.vcn.`

Then open **Cloud Shell** — the `>_` icon in the top bar of the Oracle console. It comes with the OCI
CLI already signed in as you; there is no API key to set up.

**Paste 1 — your OCID.** Type `SL=`, paste the OCID straight after it (no spaces, no quotes, no
angle brackets), press Enter:

```bash
SL=ocid1.securitylist.oc1.phx.aaaaaaaaEXAMPLEEXAMPLEEXAMPLE
```

**Paste 2 — the rules.** Nothing in this one needs editing, so paste the whole block as-is:

```bash
cat > ingress.json <<'EOF'
[
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"SSH (console relay setup)","tcpOptions":{"destinationPortRange":{"min":22,"max":22}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"1","isStateless":false,"description":"ICMP path MTU","icmpOptions":{"type":3,"code":4}},
  {"source":"10.0.0.0/16","sourceType":"CIDR_BLOCK","protocol":"1","isStateless":false,"description":"ICMP intra-VCN","icmpOptions":{"type":3}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"17","isStateless":false,"description":"WireGuard tunnel (default port)","udpOptions":{"destinationPortRange":{"min":51820,"max":51820}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"17","isStateless":false,"description":"WireGuard tunnel (alternate port)","udpOptions":{"destinationPortRange":{"min":443,"max":443}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"HTTP - Lets Encrypt validation + redirect","tcpOptions":{"destinationPortRange":{"min":80,"max":80}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"HTTPS - all web UIs via Caddy","tcpOptions":{"destinationPortRange":{"min":443,"max":443}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"TAK client connections (mutual TLS)","tcpOptions":{"destinationPortRange":{"min":8089,"max":8089}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"TAK admin WebGUI (client cert)","tcpOptions":{"destinationPortRange":{"min":8443,"max":8443}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"TAK admin WebGUI (LE cert / LDAP)","tcpOptions":{"destinationPortRange":{"min":8446,"max":8446}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"MediaMTX RTSP video","tcpOptions":{"destinationPortRange":{"min":8554,"max":8554}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"MediaMTX RTSPS video","tcpOptions":{"destinationPortRange":{"min":8322,"max":8322}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"17","isStateless":false,"description":"MediaMTX SRT video","udpOptions":{"destinationPortRange":{"min":8890,"max":8890}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"CoTURN control (Remote Assist)","tcpOptions":{"destinationPortRange":{"min":3479,"max":3479}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"17","isStateless":false,"description":"CoTURN control (Remote Assist)","udpOptions":{"destinationPortRange":{"min":3479,"max":3479}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"17","isStateless":false,"description":"CoTURN relayed media (Remote Assist)","udpOptions":{"destinationPortRange":{"min":50000,"max":50050}}},
  {"source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","protocol":"6","isStateless":false,"description":"infra-TAK console backdoor (closed by Hardening W1)","tcpOptions":{"destinationPortRange":{"min":5001,"max":5001}}}
]
EOF

oci network security-list update \
  --security-list-id "$SL" \
  --ingress-security-rules file://ingress.json \
  --force
```

Refresh the **Security rules** page and you should see 17 ingress rules.

> **Why two pastes?** Editing a long command in a terminal is miserable — the arrow keys scroll
> through command history instead of moving the cursor, so a mis-paste is easier to start over than
> to fix. Putting the OCID in `SL` on its own line means the big block never needs touching. (If you
> do need to move around a line: **Ctrl+A** jumps to the start, **Ctrl+E** to the end.)

> **⚠️ This REPLACES the ingress list, it doesn't append.** That's why the first three entries
> re-state the SSH and ICMP rules Oracle created with the VCN. Don't trim them — dropping the SSH row
> locks the console out of the relay and setup can never run.
>
> `"protocol"` is the IP protocol number: **6** = TCP, **17** = UDP, **1** = ICMP. The port lives
> inside `tcpOptions`/`udpOptions`, which is why this route can't hit the port-field trap below.

### The manual way — Oracle's dialog

**☰ menu → Networking → Virtual Cloud Networks → TAK-RELAY-VCN → Security tab → Default Security
List for TAK-RELAY-VCN → Security rules tab → Add Ingress Rules.** There's a **+ Another Ingress
Rule** button, so you can enter them all in one pass.
For each rule: *Stateless* unchecked, **Source Type** CIDR, **Source CIDR** `0.0.0.0/0`, the protocol,
and the port in **Destination Port Range**.

> **⚠️ Watch out for the port field.** The dialog has two port boxes — *Source Port Range* first,
> then *Destination Port Range*. Put the port number in **Destination Port Range** and leave Source
> blank. Putting it in Source silently drops all traffic while looking correct.
>
> **⚠️ Add BOTH UDP rows, even though you only picked one port.** The relay listens on the port you
> chose in the console and redirects the other one to it, so the tunnel survives networks that block
> one or the other. The console's default is **51820** — if you open only UDP 443 and leave the
> console on its default, **the tunnel never comes up.** Open both and it works either way.
>
> **⚠️ UDP 443 and TCP 443 are BOTH required — they're different.** UDP 443 is a tunnel fallback;
> TCP 443 is the HTTPS web traffic. Same number, different protocol, two separate rules. With only
> the UDP row, no website loads and Let's Encrypt can't issue.

### Security list or network security group?

Both do the same job — allow or deny traffic. The difference is what they attach to. A **security
list** attaches to the *subnet*, so it covers everything launched into it. A **network security
group** attaches to individual *VNICs* and has to be opted into per instance.

Your relay has a security list and no NSG — that's what the VCN wizard builds. The subnet attachment
is also why a second relay needs no firewall work at all: launch it into the same public subnet and
it inherits every rule above.

### What about all the other ports?

A full infra-TAK stack runs a lot of services — Authentik, TAK Portal, CloudTAK, Node-RED, MediaMTX,
Guard Dog — and it's fair to expect a long list here. There isn't one, because **Caddy fronts all of
them on TCP 443.** Authentik (9000/9443), TAK Portal (3000), Node-RED (1880), CloudTAK (5000/5002),
the MediaMTX HLS player and web editor (8888/5080) never listen to the public internet even on a
normal box — they're reached through 443 with SSO in front. One rule covers the lot.

### Adding a second relay

If this account already runs a relay, don't build a second network for it. **Skip step 1a entirely.**
In the instance wizard's **Networking** section choose **Select existing virtual cloud network**, pick
`TAK-RELAY-VCN` and the same **public subnet** as your first relay, and leave the public IP toggle on.

That's all. Because the port rules live on a *security list attached to the subnet*, the new VM
inherits every one of them the moment it launches — nothing to opt into, no NSG to select. **You can
skip steps 1a and 3 entirely**. Give the new relay its own DNS name pointing at its own
public address and you're done.

Two relays in one VCN don't interfere: each gets its own private and public address, and each one's
WireGuard overlay (`172.31.99.x`) exists only on its own machine.

## 4. Point your domain at the relay

**Do this before you deploy Caddy.** Everything with a web UI is reached by name, not by address, and
Let's Encrypt issues a certificate by connecting back to that name on port 80. If DNS isn't in place
first, Caddy has nothing to validate against and cert issuance fails.

At your registrar or DNS host, create these records pointing at the relay's public IP from step 2:

| Type | Name | Value |
|---|---|---|
| **A** | `tak.example.com` (your FQDN) | the relay's public IP |
| **A** | `*.tak.example.com` (wildcard) | the relay's public IP |

The **wildcard is the easy answer to a real problem**: modules put themselves on their own hostname —
`portal.`, `cloudtak.`, `nodered.`, `stream.`, `webodm.` — and each one needs to resolve before Caddy
can get a certificate for it. One wildcard record covers every module you'll ever add. Without it,
you're back at the registrar adding another A record every time you deploy something, and the symptom
when you forget is a module that installs cleanly and then won't load in a browser.

**Set the TTL low (300 seconds) while you're setting up.** If you get a record wrong, a long TTL means
waiting hours for the mistake to expire. Raise it once everything works.

**Verify before moving on** — from your laptop, not from the relay:

```
dig +short tak.example.com          # must return the relay's public IP
dig +short portal.tak.example.com   # must return the same IP (proves the wildcard works)
```

If those come back empty or with the wrong address, stop and fix DNS. Nothing downstream works until
they're right, and a Caddy failure caused by DNS looks exactly like a Caddy failure caused by
anything else.

> **Using the relay's raw IP instead?** Don't. A relay's address ends up inside enrollment packages
> and data packages you've already handed to clients, so rebuilding the relay means re-issuing
> configuration to every device in the field. With a domain name it's one DNS edit.

## 5. Finish in the console — automatically

That's all the manual work. Back in infra-TAK → **Connectivity → Connect a Relay**:

1. Enter the relay's **public IP** (from step 2).
2. **Choose .key file** — the `.key` you downloaded in step 1.
3. Leave **port** on its default (**51820**) unless you know you're on a network that only permits
   443. You opened both UDP rules in step 3, so either choice works.
4. Click **Set Up Relay.**

The console SSHes into the relay, installs and configures everything, and brings up the tunnel. When
the status line reads **● Tunnel UP**, your box is reachable through the relay from anywhere — no
further steps, and it re-connects on its own every time your box changes networks.

## Getting in when the web side is broken

Normally you reach the console at `https://your-domain` with SSO in front of it. If Caddy or
Authentik is down, that door is shut — and on a relayed box there's no direct-IP fallback either.

You don't need to open anything for this. Your relay is already an SSH server you can reach, and
your box sits at the fixed address **`172.31.99.2`** on the other end of the tunnel. So you hop
through the relay and forward the console's port back to your own machine.

First load the relay key into your SSH agent — `-i` on its own does **not** apply to the hop through
the relay, only to the box at the far end:

```bash
chmod 600 ~/Downloads/your-relay-key.key      # once, if you haven't already
ssh-add ~/Downloads/your-relay-key.key
```

Then, in one command:

```bash
ssh -J ubuntu@<relay-ip> -L 5001:localhost:5001 <your-box-user>@172.31.99.2
```

Leave that session open and browse to **https://localhost:5001**. That's the console, reached
directly, with the password login that exists for exactly this situation.

- `ubuntu` is the relay's login (Oracle's Ubuntu images use it); `<your-box-user>` is whatever you
  log into your box with.
- `172.31.99.2` is the same on every infra-TAK box — it's the box's address inside the tunnel, not
  something you configure.
- This works whether or not the box is hardened, because the traffic arrives over the tunnel as if
  you were sitting next to it. Nothing is exposed to the internet.
- If SSH to the relay is refused, check the key file's permissions first — `0644` makes SSH ignore
  it silently apart from a warning.

## If Oracle says "Out of capacity"

This is the single most common thing that stops people building a relay, and it can go on for days.
It is not a problem with your account, your card, or your region choice — it means the specific
**shape** you asked for has no free machines left in that availability domain right now. Work down
this list; most people are fixed at step 1.

**1. Stop asking for Ampere.** The error is almost always **VM.Standard.A1.Flex** (ARM) — it is the
shape everyone wants and the one that runs dry. Pick **VM.Standard.E2.1.Micro** instead. It is also
Always Free, it is x86, and it is very rarely capacity-blocked. A relay forwards packets and runs
nothing else, so the micro is ample. See *ARM or x86 makes no difference here* in step 1b — the
console's relay setup installs only WireGuard and standard Linux packet forwarding, both of which
exist for either architecture. A1 is the nicer option when it is available (more headroom and
bandwidth), never a required one.

> **Pick the image before the shape.** Oracle cross-filters the two lists. If you select an x86
> shape first, ARM builds of an image disappear from the list and it looks like the image "isn't
> available" — and vice versa. Choose Ubuntu 22.04/24.04 first, then the shape.

**2. If you specifically want A1, ask for less of it.** Request **1 OCPU / 6 GB** rather than the
full 4 OCPU / 24 GB. A smaller request fits into fragmented capacity that a large one can't.

**3. Try each availability domain by hand.** In multi-AD regions (Ashburn, Phoenix, Frankfurt,
London) the *Placement* section on the Basics page lets you pick AD-1, AD-2 or AD-3 explicitly.
Oracle's default placement will not walk them for you — try each one.

**4. Upgrade to Pay As You Go — this costs nothing and is the real fix.** Free Tier accounts are
last in line for Always Free Ampere capacity; accounts with a payment method on file are served
first. Upgrading does **not** start billing you for the relay: Always Free resources stay free on a
paid account, and a 1 OCPU / 6 GB A1 or an E2.1.Micro sits inside the allowance. It also solves the
idle-reclamation problem described in the next section, which you want solved anyway. Read that
section before you upgrade.

**5. Understand what you cannot change.** Your **home region is fixed when you create the account**
and Always Free resources can only be built there. Switching to Phoenix or another region means a
whole new tenancy with that home region — you cannot move an existing account, so retrying the same
account in a different region is not a thing that exists. If you do start a fresh account, pick a
less-contended home region at signup.

**6. Don't script a retry storm.** People post loops that hammer the launch API every few seconds.
Oracle rate-limits and it does not improve your odds. Retry by hand a few times a day, at different
hours, while working steps 1–4.

**7. If none of it works, don't wait on Oracle.** Any small server with a public IP works as a
relay, and the console setup is identical — see [Where to run the relay](#where-to-run-the-relay--you-are-not-tied-to-oracle).

## Free Tier vs Pay As You Go — read this before you rely on a relay

Oracle reclaims **idle** Always Free compute instances. An instance counts as idle if, over a 7-day
period, its CPU sits below 20% at the 95th percentile (plus network, and memory on A1 shapes).

**A relay is idle almost by definition.** It forwards packets and runs nothing else — a WireGuard
tunnel with a handful of TAK clients on it will not come close to 20% CPU on a 1-OCPU machine. So a
relay on a pure Free Tier account is exactly the workload that policy is written to catch, and the
consequence lands badly: if the relay goes away, the box behind it is unreachable from the internet
until you rebuild and re-provision.

**The fix is to upgrade the account to Pay As You Go.** Always Free resources are not reclaimed on a
paid account, and Oracle does not charge for resources that stay inside the Always Free limits — a
relay on an A1.Flex 1 OCPU / 6 GB or an E2.1.Micro stays inside them. You put a card on file and keep
paying nothing. That is the whole difference.

You'll see people keep Free Tier instances busy with artificial load to dodge this. Don't — it burns
the box's CPU continuously to defeat a policy that a payment method removes outright.

> **Watch your billing if you upgrade.** Pay As You Go means resources *outside* the Always Free
> limits do bill. Adding a second relay, a bigger shape, or extra block storage can put you over the
> line. The Always Free allowance is per tenancy, not per instance — 4 OCPUs and 24 GB of Ampere
> capacity total, so two 1-OCPU relays still fit.

Either way, Guard Dog monitors the relay tunnel and will alert you if it drops, so a reclaimed or
stopped relay surfaces as an alert rather than a silent outage.

## Where to run the relay — you are not tied to Oracle

This guide walks through Oracle because it is the only provider that gives you a permanently free
server with a public address and enough bandwidth to be useful. But nothing in infra-TAK is
Oracle-specific. **The console asks for an IP address and an SSH key — that is all.** If a provider
gives you those, the Connectivity page sets the relay up the same way.

**What a relay actually needs** — the bar is low, which is why the free tiers are viable at all:

- **A public IPv4 address that doesn't change.** This is the whole point; the entire job is having a
  stable address your clients can be pointed at.
- **1 vCPU and 512 MB–1 GB of RAM.** It forwards packets. It does not terminate TLS, run a database,
  or hold state.
- **Root/sudo SSH access with a key**, and the ability to open UDP and TCP ports.
- **Bandwidth headroom** — the one spec that genuinely matters, see below.
- Ubuntu 22.04 or 24.04. (Other distributions are not field-validated by the console's setup.)

### Free forever

| Provider | What you get | Verdict for a relay |
|---|---|---|
| **Oracle Cloud Always Free** | 4 OCPU / 24 GB Ampere ARM total (a relay uses 1/6), **or** 2× E2.1.Micro x86; 200 GB block storage; **10 TB/month egress** | **The only genuinely viable free option.** Capacity fights on A1 and idle-reclaim on Free Tier are the two catches — both covered above |
| **Google Cloud** e2-micro | 1 e2-micro in `us-west1`, `us-central1` or `us-east1`; 30 GB disk | **Not usable as a relay.** Two hard blockers below |
| **AWS** | Since 15 July 2025, new accounts get a credit balance (Free plan, up to 6 months or until credits run out) — not the old 12-month always-free EC2 | **Temporary.** Fine to trial, will stop being free |
| **Azure** | $200 credit for 30 days, plus 12-month limited offers | **Temporary.** Same problem |

**Why Google Cloud's free VM does not work here**, despite being the closest thing to a competitor:
its Always Free allowance includes **1 GB of egress per month**, and since February 2024 an in-use
external IPv4 address bills at $0.005/hour (about **$3.65/month**) — the public address a relay
exists to provide is no longer part of the free tier. So it is neither free nor big enough. One GB a
month is less than an hour of a single video stream, and even a CoT-only relay for a small team will
pass it. Don't build a relay there expecting it to hold.

That leaves Oracle as the only free-forever option worth the effort — which is exactly why the
capacity errors are worth working through rather than abandoning.

### Paid, if free isn't happening

Any small VPS works, and at this size they are all much cheaper than paying Oracle. Approximate
pricing as of August 2026 — check current rates before you buy:

| Option | Spec | Approx/month |
|---|---|---|
| **Hetzner** CX22 | 2 vCPU / 4 GB / 40 GB, **20 TB traffic** (EU; US in Ashburn + Hillsboro) | **~$4.59** + ~€0.70 for the IPv4 |
| **Vultr / DigitalOcean / Linode** | 1 vCPU / 1 GB, 0.5–1 TB transfer | **~$4–6** |
| **Budget hosts** (RackNerd and similar) | 1 vCPU / 1 GB, annual billing | **~$1–2** equivalent |
| Oracle **A1.Flex**, paid | 1 OCPU / 6 GB | **~$13.90** |
| Oracle **E5.Flex** — *the shape Oracle preselects* | 1 OCPU / 12 GB | **~$31** |

Two things fall out of that table. First, **once you are paying, Oracle is one of the worse deals** —
roughly two to three times a Hetzner-class VPS for a machine that forwards packets. Its advantage is
being free, and it is a strong advantage; it does not survive contact with a bill. Second, watch the
shape if you build on Oracle anyway: the **preselected** default is the ~$31/month one, and clicking
through the wizard without changing it is the expensive mistake in this whole process — far more
costly than the capacity errors that made you look at paid options in the first place.

### The one thing that flips it back to Oracle: bandwidth

Oracle includes **10 TB/month** of egress. That is enormous for this workload and no low-cost VPS
matches it outright, though Hetzner's included 20 TB does.

Whether it matters depends entirely on what crosses your relay:

- **CoT only** — position reports, chat, markers for a team. Trivial. Hundreds of megabytes a month.
  Every option above is fine and bandwidth should not influence your choice.
- **Video restreaming** — this is what consumes an allowance. A single stream at infra-TAK's default
  2500 kbps is about **1.1 GB/hour**, so one continuous feed is roughly 800 GB/month, and several
  feeds or several viewers multiply that. At that point compare transfer allowances first and price
  second, and read the per-GB overage rate before you commit.

## Notes

- **Cost:** Oracle's Always Free tier covers this VM at no charge. If you can't get free capacity,
  or you'd rather not use Oracle at all, see [Where to run the
  relay](#where-to-run-the-relay--you-are-not-tied-to-oracle) for what else works and what it costs.
- **Why two tunnel ports:** 51820 is WireGuard's standard port and the carrier-safe default —
  cellular networks run QUIC-aware middleboxes that sometimes eat non-QUIC traffic on UDP 443. But
  some hotel and guest Wi-Fi permits *only* 443. The relay listens on whichever you picked and
  redirects the other to it, so you can switch in the console without touching Oracle again — as
  long as both UDP rules are open.
- **If an SRT video stream stutters, send smaller packets.** The tunnel runs at an MTU of 1280 bytes
  (deliberate — cellular carriers add IPv6 translation overhead, and anything larger silently breaks
  big packets on those networks) while SRT defaults to 1316. Most streams play fine as-is; if yours
  breaks up, add `&pkt_size=1200` to the URL — `srt://<relay-ip>:8890?streamid=<stream>&pkt_size=1200`.
  Encoders call this *packet size*, *payload size* or `pkt_size`. RTSP needs nothing special.
- **Privacy:** the relay is a packet forwarder with no TLS stack in the path, so it never terminates
  or decrypts a connection. TAK's mutual-TLS, HTTPS, and RTSPS all run end-to-end between the client
  and your box — the relay can't read any of it. Note that this cuts both ways: traffic that isn't
  encrypted to begin with, such as plain **RTSP** on 8554 or **SRT** without a passphrase, crosses
  the relay in the clear exactly as it would over any other network path. Use RTSPS, or set an SRT
  passphrase, if that matters for your streams.
