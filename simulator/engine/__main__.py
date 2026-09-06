# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""Entry point: `python3 -m engine` (the container's ENTRYPOINT) or `--healthcheck`."""
import os
import signal
import sys
import threading
import urllib.request

from .control import serve
from .core import Engine, config_from_env


def healthcheck(cfg):
    host, _, port = cfg['bind'].rpartition(':')
    host = '127.0.0.1' if host in ('', '0.0.0.0') else host
    req = urllib.request.Request(f'http://{host}:{port}/health',
                                 headers={'Authorization': f'Bearer {cfg["token"]}'})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return 0 if r.status == 200 else 1
    except Exception:
        return 1


def main(argv):
    cfg = config_from_env()
    if '--healthcheck' in argv:
        return healthcheck(cfg)
    if len(cfg['token']) < 16:
        print('FATAL: SIM_CONTROL_TOKEN missing or too short', flush=True)
        return 2
    engine = Engine(cfg)
    srv = serve(engine, cfg['bind'], cfg['token'])
    engine.log(f'tak-simulator {cfg["version"]} — control API on {cfg["bind"]}, TAK {cfg["tak_host"] or "(unset)"}:'
               f'{cfg["tak_port"]}, lanes enrolled: {engine.lane_ids_available() or "none"}'
               f'{" — DRY RUN" if cfg["dry_run"] else ""}')

    def _term(signum, _frame):
        engine.log(f'signal {signum}: shutting down')
        threading.Thread(target=lambda: (engine.shutdown(), srv.shutdown()), daemon=True).start()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    try:
        srv.serve_forever(poll_interval=0.5)
    finally:
        engine.shutdown()
        srv.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
