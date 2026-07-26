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

In the [Oracle Cloud console](https://cloud.oracle.com) → **Compute → Instances → Create instance**:

- **Name:** anything (e.g. `tak-relay`).
- **Image:** click *Change image* → **Canonical Ubuntu 22.04** (the plain one, not "Minimal").
- **Shape:** click *Change shape* → **Ampere → VM.Standard.A1.Flex**, 1 OCPU / 6 GB (Always Free).
  - *If Oracle says "out of capacity"* for A1: either try a different Availability Domain, or pick
    **VM.Standard.E2.1.Micro** instead — it's also Always Free and works fine for a relay.
  - **ARM or x86 makes no difference here.** A1.Flex is ARM, E2.1.Micro is x86, and the relay setup
    is identical on both — it installs only WireGuard and standard Linux packet forwarding, which
    ship for both architectures. Take whichever Oracle has capacity for. A1 is the better pick when
    it's available (more free network bandwidth), not a required one.
- **Networking:** *Create new virtual cloud network* + *Create new public subnet* (accept the
  defaults).
- **SSH keys:** choose **Generate a key pair for me**, then click **Download private key** and save
  the `.key` file somewhere safe. ⚠️ This is the only time Oracle offers the key — if you have to
  re-create the VM, download the key again on the attempt that actually launches.
- Click **Create**. Wait for the instance to show **Running**.

## 2. Give it a public IP

Fresh VMs often launch without one.

- On the instance page → **Networking** tab. If you see a **"Connect public subnet to internet"**
  quick action, click **Connect** and apply it (this adds the internet gateway).
- Click your VNIC name → **IP administration** tab → the primary IP row → **⋮ → Edit**.
- Set **Public IP type: Reserved public IP** → create a new one → **Update**. (Reserved means the
  address stays the same for good, even across reboots.)
- The row now shows a public IP — **this is your relay's address.** Note it down.

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

**One setting matters for SRT.** The tunnel runs at an MTU of 1280 bytes, deliberately — cellular
carriers translate IPv4 into IPv6 and add overhead, and anything larger silently breaks big packets
on those networks. SRT's default packet size is 1316 bytes, which is over that budget, so send at
**1200** instead:

```
srt://<relay-ip>:8890?streamid=<stream>&pkt_size=1200
```

Encoders expose this as *packet size*, *payload size* or `pkt_size`. Symptom if you skip it: the
stream connects and reports healthy, then delivers stuttering or broken video.

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
