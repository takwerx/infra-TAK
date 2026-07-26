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

That is the complete list. Seven rules — nothing else needs to be opened, and adding more does
nothing (see *What about all the other ports?* below).

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

The relay forwards exactly the seven rules above and nothing else, so opening extra ports on the NSG
has no effect — the relay has no forwarding rule to match them.

**Two things therefore do NOT work through a relay today:**

- **Raw streaming ports** — MediaMTX RTSP (8554), SRT/RTMP, and the CloudTAK media ports
  (18554/11935/18890). Watching a stream in the CloudTAK or MediaMTX *web* UI works fine (that's
  HTTPS on 443); pointing a player straight at `rtsp://<relay-ip>:8554` does not.
- **Remote Assist screen sharing** — CoTURN needs UDP 3478 plus a UDP relay range, and the relay's
  forwarding is TCP-only.

If you need those, give the box real public inbound (port-forward or a public-IP VPS) rather than a
relay. *Advanced:* an operator comfortable at a terminal can widen the forward by re-running the
bootstrap on the relay with extra TCP ports — `sudo TAK_PORTS="8089 8443 8446 8554" bash
~/connectivity-anchor-bootstrap.sh setup` — and adding matching NSG rules. It stays TCP-only, and the
console will reset it to the default set the next time you run **Set Up Relay**.

## 4. Finish in the console — automatically

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
- **Privacy:** the relay forwards encrypted packets only. TAK's own mutual-TLS runs end-to-end
  between the client and your box — the relay can't read it.
