# Going Direct: DDNS + Port Forwarding (no relay)

If your box sits on a network with a **real public IP** and **a router you control** — most home
fiber/cable/DSL, many office networks — you don't need a relay. Clients connect straight to your
internet address, and a small DNS trick (DDNS) keeps your hostname pointed at it even when your ISP
changes the IP.

This is the **Class A** path the Connectivity page recommends when Detection finds a clean public
IP. If Detection said **CGNAT** (Starlink, most cellular) — stop here; no amount of router config
can forward what your ISP never routes to you. Use a relay instead
([RELAY-SETUP.md](RELAY-SETUP.md)).

## 1. Give the box a permanent LAN address (load-bearing — don't skip)

Port forwards point at your box's **LAN IP**. If that IP changes (DHCP hands it to your printer
after a power cut), every forward silently dies and nothing tells you why.

In your router's admin page, find **DHCP reservation** (sometimes "static lease" / "always use this
IP") and pin your box's MAC address to its current LAN IP. Do this **before** creating forwards.

## 2. Forward the ports

In the router's **Port Forwarding** section, forward these to your box's LAN IP — same external
and internal port:

| Protocol | Port | What it carries |
|---|---|---|
| **TCP** | **80** | Let's Encrypt cert validation + HTTP→HTTPS redirect |
| **TCP** | **443** | HTTPS — all web UIs (Portal enrollment, Authentik, CloudTAK, admin) |
| TCP | 8089 | ATAK / iTAK / WinTAK client connections |
| TCP | 8443 | TAK admin WebGUI (client-cert auth) |
| TCP | 8446 | TAK admin WebGUI (Let's Encrypt / LDAP login) |

> **⚠️ Never use "DMZ host" as a shortcut.** DMZ forwards *every* port — including ones nothing on
> the box is hardened to answer — and turns one compromised service into a fully exposed machine.
> Five explicit forwards is the whole job; do it properly.

## 3. Get a hostname that follows your IP (Cloudflare DDNS)

Home IPs change. A hostname + a tiny updater makes that invisible to your users and keeps your
Let's Encrypt certificates valid.

1. Put your domain on **Cloudflare** (free plan is fine): add the domain, follow their nameserver
   switch.
2. Create an **A record** for your box, e.g. `tak.example.com` → your current public IP (the
   Connectivity page's Detection shows it). Set the cloud icon to **DNS only (grey)** — Cloudflare's
   orange-cloud proxy is HTTP-only and will silently break TAK's 8089/8443/8446.
3. Create a **scoped API token**: Cloudflare dashboard → My Profile → API Tokens → Create Token →
   *Edit zone DNS* template → limit it to **just that one zone**. Never use the Global API Key.
4. Run an updater on the box. Simplest is a cron entry (replace the three values):

```bash
# /etc/cron.d/cloudflare-ddns — updates the A record when the public IP changes
*/5 * * * * root /usr/local/bin/cf-ddns.sh
```

```bash
#!/bin/bash
# /usr/local/bin/cf-ddns.sh  (chmod 700, root-owned — it holds your token)
TOKEN="cf_your_scoped_token"; ZONE_ID="your_zone_id"; RECORD="tak.example.com"
IP=$(curl -fsS https://api.ipify.org) || exit 0
RID=$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=A&name=$RECORD" \
  | grep -o '"id":"[a-f0-9]*"' | head -1 | cut -d'"' -f4)
curl -fsS -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RID" \
  --data "{\"type\":\"A\",\"name\":\"$RECORD\",\"content\":\"$IP\",\"ttl\":300,\"proxied\":false}" >/dev/null
```

(`ddclient` or any Cloudflare-DDNS container does the same job if you prefer packaged tools.)

5. In infra-TAK, set this hostname as your **FQDN** (Settings) so certificates and all module URLs
   use it.

## 4. Prove it — Verify Reachability

Connectivity page → **Verify Reachability**. It TCP-connects to every port in the table over the
public path and shows a green/red matrix — with a hint per red row telling you whether the service
isn't running yet or the path (router/ISP) is blocking. Fix reds, run again, repeat until all green.

> **Hairpin caveat:** some home routers can't reach their own public IP from inside the network
> ("NAT hairpin"). If Verify shows red but you followed everything above, confirm from a phone on
> **cellular** (WiFi off) before touching anything — if the phone connects, your setup is fine and
> only the in-network shortcut is missing.

## Survival notes (things that break this at home)

- **Guest WiFi is a trap.** Guest networks isolate devices and usually can't be forwarded to. Put
  the box on the main network — **wired if at all possible**; WiFi adds another way to silently
  drop off the network.
- **Two routers = double NAT (Class B).** If Detection said double-NAT (ISP modem/router + your own
  router, common with mesh kits), forwards on the inner router alone do nothing. Best fix: put the
  ISP box in **bridge mode** so only your router does NAT. (Second-best: forward the same ports on
  *both* boxes — fragile, but works.)
- **ISP blocks:** some residential ISPs block inbound 80/443. If exactly those two stay red while
  the 8xxx ports go green, ask your ISP or fall back to a relay.
- **Router reboots forget UPnP, not forwards.** Manual forwards survive reboots; UPnP leases may
  not. The five manual rules above are the reliable form.

## Notes

- **Cost:** free — Cloudflare's free plan and your existing router.
- **Relay vs direct:** direct has one less moving part and no VPS to babysit; the relay wins when
  you can't control the router, the ISP is CGNAT, or the box moves between networks. Both end at
  the same all-green Verify matrix.
