#!/usr/bin/env python3
"""Guard Dog network / fanout metrics collector (v0.9.47-alpha).

Always-on systemd service (tak-metrics-collector.service, Type=simple) that samples
TAK Server CoT-fanout load and writes time-series to SQLite at
/var/lib/takguard/metrics.db. Read back by the console via /api/guarddog/net-metrics.

Layers sampled:
  host_net     external NIC RX/TX bytes+pkts/s, drops, errors        (/proc/net/dev)   30s
  tcp_queue    :8089 kernel send/recv queue depth (fanout backlog)   (/proc/net/tcp*)  30s
  bridge_net   per Docker-bridge + lo RX/TX bytes/s                  (/proc/net/dev)   60s
  docker_stats per-container cpu/mem/net/blk                         (docker stats)    60s
  host_sys     cpu%/mem/swap/disk/load                               (/proc, statvfs)  60s
  marti        JVM heap + connected-client count (best-effort)       (Marti API)       60s

Stdlib only (sqlite3, subprocess, socket, os) — no pip deps. Runs as root.
Every interval / port / retention window below is a FLEET CONSTANT — no operator knobs.
"""

import sqlite3, subprocess, os, time, json, re, urllib.request

# ---- fleet constants -------------------------------------------------------
DB_PATH        = '/var/lib/takguard/metrics.db'
CONF_PATH      = '/opt/tak-guarddog/guarddog.conf'
FAST_INTERVAL  = 30        # host_net, tcp_queue
SLOW_INTERVAL  = 60        # bridge_net, docker_stats, host_sys, marti
RETENTION_DAYS = 7         # raw-only; prune hourly
PRUNE_EVERY    = 3600
TAK_PORT       = 8089
TAK_PORT_HEX   = '%04X' % TAK_PORT            # 8089 -> '1F99'  (NOT 0x1999)
STALL_FLOOR    = 4096   # bytes; below this a constant queue is noise, not a stuck client
STALL_SAMPLES  = 2      # consecutive unchanged reads before a connection counts as "stalled"
MARTI_SUBS_URL = 'https://127.0.0.1:8443/Marti/api/subscriptions/all'  # data[] = live streaming clients
ADMIN_P12      = '/opt/tak/certs/files/admin.p12'
ADMIN_PEM      = '/opt/tak-guarddog/_marti_admin.pem'
ADMIN_KEY      = '/opt/tak-guarddog/_marti_admin.key'

SCHEMA = """
CREATE TABLE IF NOT EXISTS host_net(ts INT, rx_bytes_s REAL, tx_bytes_s REAL,
  rx_pkts_s REAL, tx_pkts_s REAL, rx_drops INT, tx_drops INT, rx_errors INT, tx_errors INT);
CREATE TABLE IF NOT EXISTS bridge_net(ts INT, iface TEXT, network_name TEXT,
  rx_bytes_s REAL, tx_bytes_s REAL);
CREATE TABLE IF NOT EXISTS tcp_queue(ts INT, port INT, conn_count INT,
  tx_queue_sum INT, tx_queue_max INT, rx_queue_sum INT, rx_queue_max INT,
  tx_queue_active INT, tx_queue_active_max INT, stalled_conns INT);
CREATE TABLE IF NOT EXISTS docker_stats(ts INT, container TEXT, cpu_pct REAL, mem_mb REAL,
  net_rx_bytes_s REAL, net_tx_bytes_s REAL, blk_read_mb_s REAL, blk_write_mb_s REAL);
CREATE TABLE IF NOT EXISTS host_sys(ts INT, cpu_pct REAL, mem_used_mb INT, mem_avail_mb INT,
  swap_used_mb INT, disk_used_pct REAL, load_1 REAL, load_5 REAL, load_15 REAL);
CREATE TABLE IF NOT EXISTS marti(ts INT, heap_used_mb INT, heap_committed_mb INT,
  clients_connected INT, scrape_ok INT);
CREATE INDEX IF NOT EXISTS ix_host_net_ts   ON host_net(ts);
CREATE INDEX IF NOT EXISTS ix_bridge_ts     ON bridge_net(ts);
CREATE INDEX IF NOT EXISTS ix_tcpq_ts       ON tcp_queue(ts);
CREATE INDEX IF NOT EXISTS ix_docker_ts     ON docker_stats(ts);
CREATE INDEX IF NOT EXISTS ix_hostsys_ts    ON host_sys(ts);
CREATE INDEX IF NOT EXISTS ix_marti_ts      ON marti(ts);
"""

# ---- helpers ---------------------------------------------------------------
def _now():
    return int(time.time())

def _conf():
    try:
        with open(CONF_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def _run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None

def default_iface():
    """External NIC = iface owning the default route. Auto-detected, not hardcoded."""
    try:
        with open('/proc/net/route') as f:
            next(f)
            for line in f:
                p = line.split()
                if p[1] == '00000000' and (int(p[3], 16) & 2):   # dest 0.0.0.0, RTF_GATEWAY
                    return p[0]
    except Exception:
        pass
    return None

def read_net_dev():
    """Returns {iface: dict of cumulative counters} from /proc/net/dev."""
    out = {}
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if ':' not in line:
                    continue
                name, rest = line.split(':', 1)
                c = rest.split()
                out[name.strip()] = dict(
                    rx_bytes=int(c[0]), rx_pkts=int(c[1]), rx_errors=int(c[2]), rx_drops=int(c[3]),
                    tx_bytes=int(c[8]), tx_pkts=int(c[9]), tx_errors=int(c[10]), tx_drops=int(c[11]))
    except Exception:
        pass
    return out

def read_tcp_conns():
    """Per-connection send/recv queue for ESTABLISHED conns on :8089 (v4+v6).
    Returns {remote_hex: (tx_queue, rx_queue)} keyed on the remote ADDR:PORT (unique per conn)."""
    out = {}
    for path in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    p = line.split()
                    if p[1].rsplit(':', 1)[1].upper() != TAK_PORT_HEX:   # local port == 8089
                        continue
                    if p[3] != '01':                                     # 01 = ESTABLISHED
                        continue
                    txq, rxq = p[4].split(':')
                    out[p[2]] = (int(txq, 16), int(rxq, 16))             # key = remote ADDR:PORT
        except Exception:
            pass
    return out

def docker_bridge_map():
    """Map bridge iface -> docker network name. Best-effort; falls back to iface name."""
    m = {}
    r = _run(['docker', 'network', 'ls', '--format', '{{.ID}} {{.Name}}'])
    if not r or r.returncode != 0:
        return m
    for line in (r.stdout or '').splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        nid, name = parts
        if name in ('host', 'none'):
            continue
        ins = _run(['docker', 'network', 'inspect', nid,
                    '-f', '{{index .Options "com.docker.network.bridge.name"}}'])
        iface = (ins.stdout.strip() if ins and ins.returncode == 0 else '')
        if not iface:
            iface = 'br-' + nid[:12]            # docker default bridge naming
        m[iface] = name
    m.setdefault('docker0', 'bridge')
    return m

def _bytes(s):
    """Parse docker-stats size like '1.2MB' / '3.4GiB' -> bytes (SI and IEC)."""
    s = s.strip()
    mtch = re.match(r'([\d.]+)\s*([a-zA-Z]*)', s)
    if not mtch:
        return 0.0
    val, unit = float(mtch.group(1)), mtch.group(2).lower()
    mul = {'': 1, 'b': 1, 'kb': 1e3, 'mb': 1e6, 'gb': 1e9, 'tb': 1e12,
           'kib': 1024, 'mib': 1024**2, 'gib': 1024**3, 'tib': 1024**4}
    return val * mul.get(unit, 1)

def read_docker_stats():
    """Returns {container: dict(cpu_pct, mem_mb, net_rx, net_tx, blk_r, blk_w)} (cumulative net/blk)."""
    out = {}
    r = _run(['docker', 'stats', '--no-stream', '--format', '{{json .}}'], timeout=20)
    if not r or r.returncode != 0:
        return out
    for line in (r.stdout or '').splitlines():
        try:
            d = json.loads(line)
        except Exception:
            continue
        name = d.get('Name', '')
        if not name:
            continue
        netio = d.get('NetIO', '0B / 0B').split('/')
        blkio = d.get('BlockIO', '0B / 0B').split('/')
        out[name] = dict(
            cpu_pct=float((d.get('CPUPerc', '0%') or '0%').rstrip('%') or 0),
            mem_mb=_bytes(d.get('MemUsage', '0B / 0B').split('/')[0]) / 1e6,
            net_rx=_bytes(netio[0]), net_tx=_bytes(netio[1] if len(netio) > 1 else '0B'),
            blk_r=_bytes(blkio[0]), blk_w=_bytes(blkio[1] if len(blkio) > 1 else '0B'))
    return out

def read_cpu_times():
    try:
        with open('/proc/stat') as f:
            p = f.readline().split()[1:]
        vals = [int(x) for x in p]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        return sum(vals), idle
    except Exception:
        return None, None

def read_host_sys(prev_cpu):
    cpu_pct = 0.0
    tot, idle = read_cpu_times()
    if tot is not None and prev_cpu[0] is not None:
        dt, di = tot - prev_cpu[0], idle - prev_cpu[1]
        if dt > 0:
            cpu_pct = round(100.0 * (1 - di / dt), 1)
    mem = {}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k, v = line.split(':')
                mem[k] = int(v.split()[0])      # kB
    except Exception:
        pass
    try:
        with open('/proc/loadavg') as f:
            la = f.read().split()
        l1, l5, l15 = float(la[0]), float(la[1]), float(la[2])
    except Exception:
        l1 = l5 = l15 = 0.0
    try:
        st = os.statvfs('/')
        disk_pct = round(100.0 * (1 - st.f_bavail / st.f_blocks), 1)
    except Exception:
        disk_pct = 0.0
    row = dict(
        cpu_pct=cpu_pct,
        mem_used_mb=int((mem.get('MemTotal', 0) - mem.get('MemAvailable', 0)) / 1024),
        mem_avail_mb=int(mem.get('MemAvailable', 0) / 1024),
        swap_used_mb=int((mem.get('SwapTotal', 0) - mem.get('SwapFree', 0)) / 1024),
        disk_used_pct=disk_pct, load_1=l1, load_5=l5, load_15=l15)
    return row, (tot, idle)

# ---- Marti scrape (best-effort) -------------------------------------------
def ensure_admin_cert(cert_pass):
    """Extract admin.p12 -> PEM+key once. Mirrors app.py Marti auth (legacy flag)."""
    if os.path.isfile(ADMIN_PEM) and os.path.isfile(ADMIN_KEY):
        return True
    if not (cert_pass and os.path.isfile(ADMIN_P12)):
        return False
    import shlex
    p = shlex.quote(cert_pass)
    ok1 = _run(['bash', '-c',
        f'openssl pkcs12 -in {ADMIN_P12} -passin pass:{p} -clcerts -nokeys -legacy 2>/dev/null > {ADMIN_PEM}'])
    ok2 = _run(['bash', '-c',
        f'openssl pkcs12 -in {ADMIN_P12} -passin pass:{p} -nocerts -nodes -legacy 2>/dev/null > {ADMIN_KEY}'])
    good = (ok1 and ok1.returncode == 0 and ok2 and ok2.returncode == 0
            and os.path.getsize(ADMIN_PEM) > 0 and os.path.getsize(ADMIN_KEY) > 0)
    if good:
        os.chmod(ADMIN_PEM, 0o600); os.chmod(ADMIN_KEY, 0o600)
    return good

def read_jvm_heap():
    """TAK messaging JVM heap via jcmd (no cert). Returns (used_mb, committed_mb) or (0,0).
    TAK has no /Marti heap endpoint — jcmd GC.heap_info is the reliable source."""
    try:
        pg = _run(['pgrep', '-f', 'spring.profiles.active=messaging'])
        if not pg or not (pg.stdout or '').strip():
            return 0, 0
        pid = pg.stdout.split()[0]
        r = _run(['jcmd', pid, 'GC.heap_info'], timeout=10)
        out = (r.stdout if r else '') or ''
        if 'heap' not in out:                       # attach may need the JVM's own uid
            own = _run(['stat', '-c', '%U', '/proc/%s' % pid])
            owner = (own.stdout.strip() if own else '')
            if owner and owner != 'root':
                r = _run(['sudo', '-u', owner, 'jcmd', pid, 'GC.heap_info'], timeout=10)
                out = (r.stdout if r else '') or ''
        m = re.search(r'total\s+(\d+)K,\s+used\s+(\d+)K', out)   # G1: "total 724992K, used 363455K"
        if m:
            return int(m.group(2)) // 1024, int(m.group(1)) // 1024   # used_mb, committed(total)_mb
    except Exception:
        pass
    return 0, 0

def scrape_marti(cert_pass):
    """Live connected-client count from Marti subscriptions/all + JVM heap from jcmd."""
    clients, ok = 0, 0
    if ensure_admin_cert(cert_pass):
        r = _run(['curl', '-sk', '--max-time', '8', '--cert', ADMIN_PEM, '--key', ADMIN_KEY, MARTI_SUBS_URL])
        if r and r.returncode == 0 and (r.stdout or '').strip():
            try:
                clients = len(json.loads(r.stdout).get('data', []))
                ok = 1
            except Exception:
                ok = 0
        if not ok:
            # cert may have rotated / TAK down — drop extracted copies so next loop re-extracts
            for p in (ADMIN_PEM, ADMIN_KEY):
                try: os.remove(p)
                except OSError: pass
    heap_used, heap_comm = read_jvm_heap()
    return dict(heap_used_mb=heap_used, heap_committed_mb=heap_comm,
                clients_connected=clients, scrape_ok=ok)

# ---- main loop -------------------------------------------------------------
def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    # Migrate older DBs: add the stalled-vs-active columns if the table predates them.
    for _col in ('tx_queue_active', 'tx_queue_active_max', 'stalled_conns'):
        try:
            db.execute("ALTER TABLE tcp_queue ADD COLUMN %s INT DEFAULT 0" % _col)
        except Exception:
            pass
    db.commit()

    conf = _conf()
    cert_pass = conf.get('tak_cert_pass', '')
    ext_iface = default_iface()
    bridges = docker_bridge_map()

    prev_dev = read_net_dev()
    prev_docker = read_docker_stats()
    prev_cpu = (None, None)
    prev_tcp = {}              # remote_hex -> (tx_queue, unchanged_streak) for stall detection
    last_slow = 0
    last_prune = 0
    last_bridge_refresh = _now()

    while True:
        t0 = time.time()
        ts = _now()

        # ---- FAST: host_net + tcp_queue (every loop) ----
        cur_dev = read_net_dev()
        if ext_iface and ext_iface in cur_dev and ext_iface in prev_dev:
            c, p = cur_dev[ext_iface], prev_dev[ext_iface]
            dt = FAST_INTERVAL
            db.execute(
                "INSERT INTO host_net VALUES (?,?,?,?,?,?,?,?,?)",
                (ts, (c['rx_bytes']-p['rx_bytes'])/dt, (c['tx_bytes']-p['tx_bytes'])/dt,
                 (c['rx_pkts']-p['rx_pkts'])/dt, (c['tx_pkts']-p['tx_pkts'])/dt,
                 c['rx_drops'], c['tx_drops'], c['rx_errors'], c['tx_errors']))

        # Classify each :8089 connection. A queue that's been constant for STALL_SAMPLES reads
        # is a stuck/idle client (dead socket, or a passive client like Node-RED holding a buffer);
        # exclude it from the "active" backpressure figure so the headline reflects LIVE fanout.
        cur_tcp = read_tcp_conns()
        txs = txm = rxs = rxm = 0
        act_sum = act_max = stalled_n = 0
        new_prev = {}
        for rem, (txq, rxq) in cur_tcp.items():
            txs += txq; rxs += rxq
            txm = max(txm, txq); rxm = max(rxm, rxq)
            pv = prev_tcp.get(rem)
            streak = (pv[1] + 1) if (pv and pv[0] == txq) else 0
            new_prev[rem] = (txq, streak)
            if txq >= STALL_FLOOR and streak >= STALL_SAMPLES:
                stalled_n += 1
            else:
                act_sum += txq; act_max = max(act_max, txq)
        prev_tcp = new_prev
        db.execute("INSERT INTO tcp_queue VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (ts, TAK_PORT, len(cur_tcp), txs, txm, rxs, rxm, act_sum, act_max, stalled_n))

        # ---- SLOW: bridge_net, docker_stats, host_sys, marti ----
        if ts - last_slow >= SLOW_INTERVAL:
            dt = max(1, ts - last_slow) if last_slow else SLOW_INTERVAL

            if ts - last_bridge_refresh >= 300:        # re-resolve bridges (stacks redeploy)
                bridges = docker_bridge_map()
                last_bridge_refresh = ts
            for iface, name in list(bridges.items()) + [('lo', 'localhost')]:
                if iface in cur_dev and iface in prev_dev:
                    c, p = cur_dev[iface], prev_dev[iface]
                    db.execute("INSERT INTO bridge_net VALUES (?,?,?,?,?)",
                               (ts, iface, name,
                                (c['rx_bytes']-p['rx_bytes'])/dt, (c['tx_bytes']-p['tx_bytes'])/dt))

            cur_docker = read_docker_stats()
            for name, c in cur_docker.items():
                p = prev_docker.get(name)
                nrx = (c['net_rx']-p['net_rx'])/dt if p else 0.0
                ntx = (c['net_tx']-p['net_tx'])/dt if p else 0.0
                br  = (c['blk_r']-p['blk_r'])/dt/1e6 if p else 0.0
                bw  = (c['blk_w']-p['blk_w'])/dt/1e6 if p else 0.0
                db.execute("INSERT INTO docker_stats VALUES (?,?,?,?,?,?,?,?)",
                           (ts, name, c['cpu_pct'], c['mem_mb'], max(0, nrx), max(0, ntx),
                            max(0, br), max(0, bw)))
            prev_docker = cur_docker

            hs, prev_cpu = read_host_sys(prev_cpu)
            db.execute("INSERT INTO host_sys VALUES (?,?,?,?,?,?,?,?,?)",
                       (ts, hs['cpu_pct'], hs['mem_used_mb'], hs['mem_avail_mb'], hs['swap_used_mb'],
                        hs['disk_used_pct'], hs['load_1'], hs['load_5'], hs['load_15']))

            m = scrape_marti(cert_pass)
            db.execute("INSERT INTO marti VALUES (?,?,?,?,?)",
                       (ts, m['heap_used_mb'], m['heap_committed_mb'], m['clients_connected'], m['scrape_ok']))

            last_slow = ts

        # ---- prune (hourly) ----
        if ts - last_prune >= PRUNE_EVERY:
            cutoff = ts - RETENTION_DAYS * 86400
            for tbl in ('host_net', 'bridge_net', 'tcp_queue', 'docker_stats', 'host_sys', 'marti'):
                db.execute(f"DELETE FROM {tbl} WHERE ts < ?", (cutoff,))
            last_prune = ts

        db.commit()
        prev_dev = cur_dev
        time.sleep(max(1, FAST_INTERVAL - (time.time() - t0)))

if __name__ == '__main__':
    main()
