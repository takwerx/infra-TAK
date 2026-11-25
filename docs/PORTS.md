# Ports

Back to the [README](../README.md).

> **v0.9.12 hardening:** Every host port is classified by exposure tier. **Tier 1 (Public)** is reachable from the internet, **Tier 3 (Caddy-loopback)** binds to `127.0.0.1` and is reached only via Caddy on 443, **Tier 4 (Docker-internal)** has no host port at all, **Tier 5 (Source-scoped)** is allowed only from a specific peer IP.

## Tier 1 — Public (open in UFW)

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| infra-TAK Console | 5001 | HTTPS | Management web UI (backdoor: direct IP access). **Closed to the internet once Hardening W1 is applied** — reach it via SSH tunnel, see [Recovery](RECOVERY.md#recovery--backdoor-when-authentik-or-caddy-is-broken). |
| Caddy | 80 | HTTP | Redirect to HTTPS |
| Caddy | 443 | HTTPS | Reverse proxy for all services (Let's Encrypt) |
| TAK Server | 8089 | TLS | TAK client connections (ATAK, iTAK, WinTAK) |
| TAK Server | 8443 | HTTPS | Admin WebGUI (client certificate auth) |
| TAK Server | 8446 | HTTPS | Admin WebGUI (Let's Encrypt, password/LDAP auth) |
| MediaMTX / TAK Video Restreamer | 8554 | RTSP | Video streaming clients (publish + play) |
| MediaMTX | 8322 | RTSPS | TLS-wrapped RTSP |
| MediaMTX | 8890 | SRT | SRT streaming clients |
| MediaMTX | 8000/8001 | UDP | RTP/RTCP companion ports for RTSP |
| CloudTAK Media | 18554 | RTSP | CloudTAK video tab — RTSP clients |
| CloudTAK Media | 11935 | RTMP | CloudTAK video tab — RTMP publishers |
| CloudTAK Media | 18890 | SRT | CloudTAK video tab — SRT clients |
| CloudTAK Media | 9997 | HTTPS | Video control — CloudTAK puts this port on every media URL; Caddy answers it (TLS, auth-gated). Blocked, videos opened from a map marker fail with "Failed to generate proxy stream" |
| TAK Video Restreamer *(when deployed)* | 8555 | RTSPS | TLS-wrapped RTSP (its RTSP and SRT use MediaMTX's 8554 and 8890) |
| TAK Video Restreamer *(when deployed)* | 1935 | RTMP | RTMP publishers |
| ATLAS MDM *(when deployed)* | 8449 | TLS | Enrolled tablets' device channel (mutual TLS) — the provisioning QR points here |
| EUD Remote Assist *(when deployed)* | 8448 | HTTPS | Device API — the enrolment QR points here |
| CoTURN — EUD Remote Assist *(when deployed)* | 3479 / 50000–50050 | TCP+UDP / UDP | TURN control / relayed media |

> **Cloud servers and relays:** infra-TAK opens these ports in the server's own firewall, but it can't reach your cloud provider's firewall (AWS security group, Oracle security list, Azure NSG). Allow the ones you use there yourself, module ports included: a tablet that can't reach 8449 installs the ATLAS agent and then times out. On an Oracle relay, the paste-in rule block in [RELAY-SETUP.md](RELAY-SETUP.md#the-fast-way--cloud-shell-recommended) covers all of them.

## Tier 3 — Caddy-loopback (bound to `127.0.0.1`, **deny in UFW**)

Reached only through Caddy on 443 via the public FQDN. Raw ports are NOT reachable from the internet. v0.9.12 enforces this via `!reset` Docker port overrides plus UFW deny rules.

| Service | Port | Description |
|---------|------|-------------|
| Authentik | 9090/9443 | Identity provider HTTP/HTTPS (Caddy proxies `https://authentik.example.com`) |
| TAK Portal | 3000 | User/cert management portal (Caddy proxies `https://portal.example.com`) |
| Node-RED | 1880 | Flow editor (Caddy proxies `https://nodered.example.com` with forward_auth) |
| MediaMTX | 8888 | HLS playback (Caddy proxies `/hls-proxy/` on the MediaMTX FQDN) |
| MediaMTX | 5080 | MediaMTX webedit (Caddy proxies the MediaMTX FQDN) |
| MediaMTX | 9898 | MediaMTX admin API (consumed by webedit on loopback) |
| CloudTAK | 5000 | CloudTAK API (Caddy proxies `https://cloudtak.example.com`) |
| CloudTAK | 5002 | CloudTAK tiles |
| CloudTAK | 18888 | CloudTAK media HLS |
| CloudTAK | 9997 | CloudTAK media admin API (the container's own publish; the public side is Caddy's listener in Tier 1) |
| CloudTAK | 9002 | MinIO web console (operator SSH-tunnels for bucket management) |

## Tier 4 — Docker-internal (no host port, **service reachable only on the Docker network**)

| Service | Internal endpoint | Description |
|---------|-------------------|-------------|
| Authentik PostgreSQL | `postgresql:5432` | Authentik DB |
| Authentik Redis | `redis:6379` | Authentik task queue |
| CloudTAK PostGIS | `postgis:5432` | CloudTAK DB (was Tier 1 + default creds pre-v0.9.11 — root cause of the PG_MEM incident) |
| CloudTAK MinIO S3 | `store:9000` | CloudTAK S3 storage |
| CloudTAK events | `events:5003` | CloudTAK background worker |

## Tier 5 — Source-scoped (UFW allow from specific peer IP only)

| Service | Port | Source | Description |
|---------|------|--------|-------------|
| Server One PostgreSQL | 5432 (default) | Server Two IP | Two-server TAK Server DB (was unconditional `allow 5432/tcp` pre-v0.9.12) |
| Guard Dog health agent | 8080 | Console IP (`settings.server_ip`) | Two-server DB health endpoint on Server One |
| LDAP Outpost | 389/636 | Console IP | Reachable only when Authentik is deployed remotely; consumed by TAK Server's LDAP auth block |
| Email Relay | 25 | localhost | Local Postfix relay (apps send here) |
