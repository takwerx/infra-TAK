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

| Protocol | Port |
|---|---|
| UDP | 443 |
| TCP | 8089 |
| TCP | 8443 |
| TCP | 8446 |
| TCP | 5099 |

> **Watch out for the port field.** Oracle's Add-Rule dialog has two port boxes — *Source Port
> Range* first, then *Destination Port Range*. Put the port number in **Destination Port Range** and
> leave Source blank. Putting it in Source silently drops all traffic while looking correct.

## 4. Finish in the console — automatically

That's all the manual work. Back in infra-TAK → **Connectivity → Connect a Relay**:

1. Enter the relay's **public IP** (from step 2).
2. **Choose .key file** — the `.key` you downloaded in step 1.
3. Click **Set Up Relay.**

The console SSHes into the relay, installs and configures everything, and brings up the tunnel. When
the status line reads **● Tunnel UP**, your box is reachable through the relay from anywhere — no
further steps, and it re-connects on its own every time your box changes networks.

## Notes

- **Cost:** Oracle's Always Free tier covers this VM and a reserved IP at no charge.
- **Port 443:** the tunnel uses UDP 443 because it looks like normal HTTPS traffic and slips through
  restrictive networks (hotel, guest, and cellular Wi-Fi often block uncommon ports).
- **Privacy:** the relay forwards encrypted packets only. TAK's own mutual-TLS runs end-to-end
  between the client and your box — the relay can't read it.
