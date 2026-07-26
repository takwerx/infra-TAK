# Setting up a Relay (Oracle Free Tier)

When your box has no public inbound — you're behind CGNAT (Starlink, most cellular) or you move
between networks — it reaches the internet by dialing OUT to a **relay**: a tiny always-free public
VPS. Friends and clients connect to the relay's public address with **no VPN**, the same from any
network your box is on. The relay never sees your TAK traffic in the clear — it forwards raw
encrypted packets straight through to your box.

You create the relay VM once (about 5 minutes in Oracle's console). After that, the **Connect a
Relay** card in the Connectivity page does everything else automatically — you just give it the
relay's IP and upload the key file.

## 1. Create the VM

In the [Oracle Cloud console](https://cloud.oracle.com) → **Compute → Instances → Create instance**.
Oracle's wizard runs across four pages — *Basics → Security → Networking → Storage* — with a **Next**
button at the bottom of each. Only two pages need anything from you.

**Page 1 — Basics** (name, placement, image, shape)

- **Name:** anything (e.g. `tak-relay`).
- **Placement:** leave the availability domain Oracle picked.
- **Image:** click *Change image* → **Canonical Ubuntu 22.04** (the plain one, not "Minimal").
- **Shape:** click *Change shape* → **Ampere → VM.Standard.A1.Flex**, 1 OCPU / 6 GB (Always Free).
  - *If Oracle says "out of capacity"* for A1: either try a different Availability Domain, or pick
    **VM.Standard.E2.1.Micro** instead — it's also Always Free and works fine for a relay.
  - **ARM or x86 makes no difference here.** A1.Flex is ARM, E2.1.Micro is x86, and the relay setup
    is identical on both — it installs only WireGuard and standard Linux packet forwarding, which
    ship for both architectures. Take whichever Oracle has capacity for. A1 is the better pick when
    it's available (more free network bandwidth), not a required one.

**Page 2 — Security:** nothing here applies to a relay. Click **Next**.

**Page 3 — Networking.** This is the page that matters.

- **Primary network:** *Create new virtual cloud network*, and **Subnet:** *Create new public
  subnet*. Accept the generated names.
  - *Already have a relay in this account?* Pick **Select existing virtual cloud network** and choose
    the VCN and public subnet from your first one instead — see *Adding a second relay* below.
- **Public IPv4 address assignment:** leave **Automatically assign public IPv4 address** ON. (Step 2
  converts it to a permanent address.)
- **IPv6:** leave off. If the page warns that the subnet doesn't support IPv6, ignore it.
- **Advanced options → Use network security groups to control traffic:** leave this OFF on a first
  relay — you'll create the NSG in step 3, after the VM exists. On a second relay, turn it ON and
  select your existing NSG.
- Everything else on the page — DNS record, hostname, launch options — stays default.

**Also on the Networking page — SSH keys.** Keep **Generate a key pair for me** and click **Download
private key**. Save that `.key` file somewhere you'll find it: it is the only thing the console needs
to set the relay up, and you never have to open it yourself. You don't need the public key.

> ⚠️ **This is the only time Oracle offers the key.** If this launch attempt fails and you retry,
> download again on the attempt that actually succeeds — each attempt generates a different key.

**Page 4 — Storage:** accept the defaults (46.6 GB boot volume, in-transit encryption on). A relay
forwards packets and stores nothing, so the default volume is far more than it needs. Don't attach a
block volume.

Then **Review** → **Create**, and wait for the instance to show **Running**.

## 2. Give it a public IP

Your VM already has a public address — it's on the instance's **Networking** tab as **Public IPv4
address**. That address is *ephemeral*: it survives reboots and stop/start, and is only released if
you terminate the instance.

- On the instance page → **Networking** tab. If you see a **"Connect public subnet to internet"**
  quick action, click **Connect** and apply it (this adds the internet gateway).
  - **Skip this if you reused an existing relay's subnet** — it already has a gateway, and clicking
    it creates a second NSG and rewrites the route table for nothing.
- **Note the address down — this is your relay's IP.**

### Should you reserve it?

**Running one box? Yes — do it.** A *reserved* address survives rebuilding the VM, and Oracle
doesn't charge for it (your tenancy includes one). It costs a few clicks now and saves you a mess
later, because a relay's address ends up inside enrollment packages and data packages you've already
handed to clients.

- Click your VNIC name → **IP administration** tab → the primary IP row → **⋮ → Edit**.
- Set **Public IP type: Reserved public IP** → create a new one → **Update**.

**Running several relays, or just testing? Don't bother.** The included allowance is one address, and
relays don't get rebuilt in normal operation. If you ever do rebuild one, changing a DNS A record
takes ten seconds.

> **Either way, hand clients a domain name, not the raw IP.** Point an A record at the relay and use
> that name in enrollment and data packages. Then a rebuilt relay is one DNS edit instead of
> re-issuing configuration to every client in the field. You need that A record anyway — it's how
> Let's Encrypt reaches port 80 to issue your certificate.

## 3. Open the ports

On the **Networking** tab → click the network security group (**ig-quick-action-NSG**) → **Add
Rules**. Add these ingress rules, each with **Source `0.0.0.0/0`**:

| Protocol | Port | What it carries |
|---|---|---|
| **UDP** | **51820** | WireGuard tunnel — the console's default port |
| **UDP** | **443** | WireGuard tunnel — the alternate port (restrictive venue Wi-Fi) |
| **TCP** | **80** | Let's Encrypt cert validation + HTTP→HTTPS redirect |
| **TCP** | **443** | HTTPS — every web UI (Portal enrollment, Authentik SSO, CloudTAK, Node-RED, admin console) |
| **TCP** | **8089** | ATAK / iTAK / WinTAK client connections (mutual-TLS) |
| **TCP** | **8443** | TAK admin WebGUI (client-cert auth) |
| **TCP** | **8446** | TAK admin WebGUI (Let's Encrypt cert / LDAP login) |
| TCP | 8554 | MediaMTX **RTSP** video — only if you stream |
| TCP | 8322 | MediaMTX **RTSPS** video — only if you stream |
| UDP | 8890 | MediaMTX **SRT** video — only if you stream |

**Set Up Relay** configures all of these automatically on the relay itself — the moment the tunnel
comes up they're already being forwarded, so the NSG rules above are the only part you do by hand.
The three video rows are only needed if you stream. Optional extras are in *Going beyond the
defaults* below.

> **⚠️ Add BOTH UDP rows, even though you only picked one port.** The relay listens on the port you
> chose in the console and redirects the other one to it, so the tunnel survives networks that block
> one or the other. The console's default is **51820** — if you open only UDP 443 and leave the
> console on its default, **the tunnel never comes up.** Open both and it works either way.
>
> **⚠️ UDP 443 and TCP 443 are BOTH required — they're different.** UDP 443 is a tunnel fallback;
> TCP 443 is the HTTPS web traffic. Same number, different protocol, two separate rules. With only
> the UDP row, no website loads and Let's Encrypt can't issue.
>
> **⚠️ Watch out for the port field.** Oracle's Add-Rule dialog has two port boxes — *Source Port
> Range* first, then *Destination Port Range*. Put the port number in **Destination Port Range** and
> leave Source blank. Putting it in Source silently drops all traffic while looking correct.

### What about all the other ports?

A full infra-TAK stack runs a lot of services — Authentik, TAK Portal, CloudTAK, Node-RED, MediaMTX,
Guard Dog — and it's fair to expect a long list here. There isn't one, because **Caddy fronts all of
them on TCP 443.** Authentik (9000/9443), TAK Portal (3000), Node-RED (1880), CloudTAK (5000/5002),
the MediaMTX HLS player and web editor (8888/5080) never listen to the public internet even on a
normal box — they're reached through 443 with SSO in front. One rule covers the lot.

### Adding a second relay

If this account already runs a relay, don't build a second network for it. On the **Networking**
page choose **Select existing virtual cloud network**, pick the VCN and public subnet from your first
relay, then under **Advanced options** turn on **Use network security groups to control traffic** and
select the NSG you already made (`ig-quick-action-NSG`).

That reuses the internet gateway and every port rule you already entered, so **you can skip steps 2
and 3 entirely** — apart from giving the new VM its own Reserved public IP.

Two relays in one VCN don't interfere: each gets its own private and public address, and each one's
WireGuard overlay (`172.31.99.x`) exists only on its own machine.

## 4. Going beyond the defaults (optional)

**A rule in the NSG is only half of a forward.** Oracle's NSG decides what reaches the relay's
network card; the relay's own forwarding table decides what actually gets carried down the tunnel to
your box. Adding an NSG rule for a port the relay doesn't forward is harmless but does nothing — the
packet arrives and is dropped. This catches people out, because the NSG page then *looks* like the
port is open.

These two are worth adding, and each needs both halves. SSH to the relay
(`ssh -i <your.key> ubuntu@<relay-ip>`) and run the matching command, then add the NSG rule:

| Port | Gives you | On the relay |
|---|---|---|
| TCP **2222** | SSH to the box behind the relay, on 2222 → the box's 22 | `sudo iptables -t nat -I PREROUTING -p tcp --dport 2222 -j DNAT --to-destination 172.31.99.2:22` then `sudo iptables -I FORWARD -d 172.31.99.2 -p tcp --dport 22 -j ACCEPT` |
| TCP **5001** | The infra-TAK console on the relay's public IP — see the warning below | same two commands with `5001` in place of both `2222` and `22` |

Both commands use `-I` (insert), not `-A` (append) — that matters. Oracle's images ship a FORWARD
chain that ends in a blanket REJECT, so an appended ACCEPT lands *after* the REJECT and never
matches. The rule looks present in `iptables -S` and does nothing.

Run `sudo netfilter-persistent save` afterwards so the rules survive a reboot. Re-running **Set Up
Relay** from the console will not remove them — the setup script only ever adds rules, it never
flushes.

> **⚠️ Think before forwarding 5001.** That is the admin console, and it is deliberately a
> direct-IP backdoor with no Caddy and no SSO in front of it — that design is fine on a LAN, and a
> different proposition on a public Oracle address where anyone can reach the login page. The
> supported path to the console from outside is HTTPS on 443 through Caddy, with Authentik in front.

### Video through a relay

All three MediaMTX streaming options work through a relay and are forwarded automatically — **RTSP**
(8554), **RTSPS** (8322) and **SRT** (8890). Add the matching NSG rules for the ones you use.

**If an SRT stream stutters, try a smaller packet size.** The tunnel runs at an MTU of 1280 bytes
(deliberate — cellular carriers add IPv6 translation overhead, and anything larger silently breaks
big packets on those networks), while SRT defaults to 1316. Streams generally play fine as-is on a
clean connection; if yours breaks up over cellular or a lossy link, send at 1200:

```
srt://<relay-ip>:8890?streamid=<stream>&pkt_size=1200
```

Encoders expose this as *packet size*, *payload size* or `pkt_size`.

RTSP needs nothing special — our MediaMTX ships `rtspTransports: [tcp]`, which is what a relay
carries cleanly, and players negotiate it automatically.

**Remote Assist screen sharing is the one thing still outside this** — CoTURN needs UDP 3479 plus a
wide range of media ports, which isn't forwarded.

Watching a stream *inside* the CloudTAK or MediaMTX web player works regardless of any of the above,
because that's HTTPS on 443 rather than a raw video port.

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

## Notes

- **Cost:** Oracle's Always Free tier covers this VM and a reserved IP at no charge.
- **Why two tunnel ports:** 51820 is WireGuard's standard port and the carrier-safe default —
  cellular networks run QUIC-aware middleboxes that sometimes eat non-QUIC traffic on UDP 443. But
  some hotel and guest Wi-Fi permits *only* 443. The relay listens on whichever you picked and
  redirects the other to it, so you can switch in the console without touching Oracle again — as
  long as both UDP rules are open.
- **Privacy:** the relay is a packet forwarder with no TLS stack in the path, so it never terminates
  or decrypts a connection. TAK's mutual-TLS, HTTPS, and RTSPS all run end-to-end between the client
  and your box — the relay can't read any of it. Note that this cuts both ways: traffic that isn't
  encrypted to begin with, such as plain **RTSP** on 8554 or **SRT** without a passphrase, crosses
  the relay in the clear exactly as it would over any other network path. Use RTSPS, or set an SRT
  passphrase, if that matters for your streams.
