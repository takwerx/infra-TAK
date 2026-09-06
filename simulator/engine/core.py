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
"""Engine orchestration: configuration from the environment, scenario catalog, lanes, one
run at a time (PLAN v10.1.61 §4.2). The control API (control.py) is a thin JSON front on
this class; the console's module routes are its only client."""
import collections
import glob
import json
import os
import re
import threading
import time
from datetime import datetime, timezone

from . import scenario as sc
from .lane import Lane
from .sim import Run

LANE_FILE_RE = re.compile(r'lane-([A-Za-z0-9][A-Za-z0-9_-]{0,15})\.pem')


def config_from_env(env=None):
    env = os.environ if env is None else env
    return {
        'token': env.get('SIM_CONTROL_TOKEN', ''),
        'bind': env.get('SIM_CONTROL_BIND', '0.0.0.0:5090'),
        'tak_host': env.get('SIM_TAK_HOST', ''),
        'tak_port': int(env.get('SIM_TAK_PORT', '8089') or 8089),
        'tak_api_port': int(env.get('SIM_TAK_API_PORT', '8443') or 8443),
        'cert_dir': env.get('SIM_CERT_DIR', '/certs'),
        'ca_file': env.get('SIM_CA_FILE', '/certs/ca.pem'),
        'scenario_dir': env.get('SIM_SCENARIO_DIR', '/scenarios'),
        'video_base': env.get('SIM_VIDEO_RTSP_BASE', ''),
        'default_channel': env.get('SIM_DEFAULT_CHANNEL', 'tak_simulation'),
        'activate_groups': env.get('SIM_ACTIVATE_GROUPS', '1') not in ('0', 'false', 'no'),
        'dry_run': env.get('SIM_DRY_RUN', '') in ('1', 'true', 'yes'),
        'version': env.get('SIM_VERSION', 'dev'),
        'connect_wait_s': float(env.get('SIM_CONNECT_WAIT_S', '20') or 20),
        'activate_wait_s': float(env.get('SIM_ACTIVATE_WAIT_S', '45') or 45),
    }


class Engine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.run = None
        self._lock = threading.Lock()
        self._log = collections.deque(maxlen=1000)
        self.started_at = time.time()

    # ── logging (ring buffer + stdout → docker logs) ──────────────────────
    def log(self, msg):
        line = f'{datetime.now(timezone.utc).strftime("%H:%M:%S")} {msg}'
        self._log.append(line)
        print(line, flush=True)

    def log_lines(self, n=200):
        return list(self._log)[-n:]

    # ── lanes ─────────────────────────────────────────────────────────────
    def lane_ids_available(self):
        ids = []
        try:
            for name in sorted(os.listdir(self.cfg['cert_dir'])):
                m = LANE_FILE_RE.fullmatch(name)
                if m:
                    ids.append(m.group(1))
        except OSError:
            pass
        return ids

    def _lane_cert(self, lane_id):
        return os.path.join(self.cfg['cert_dir'], f'lane-{lane_id}.pem')

    # ── scenarios ─────────────────────────────────────────────────────────
    def list_scenarios(self):
        out = []
        for path in sorted(glob.glob(os.path.join(self.cfg['scenario_dir'], '*.json'))):
            name = os.path.basename(path)[:-5]
            entry = {'name': name, 'file': os.path.basename(path)}
            try:
                with open(path, 'rb') as f:
                    doc = sc.validate_bytes(f.read(), name)
                entry.update(sc.summarize(doc))
                entry['valid'] = True
            except sc.ScenarioError as e:
                entry.update({'valid': False, 'errors': e.errors[:10]})
            except OSError as e:
                entry.update({'valid': False, 'errors': [str(e)[:120]]})
            out.append(entry)
        return out

    def load_scenario(self, ref):
        if isinstance(ref, dict):
            return sc.validate(ref, ref.get('name'))
        if not sc.NAME_RE.fullmatch(ref or ''):
            raise sc.ScenarioError(['scenario name has an invalid format'])
        path = os.path.join(self.cfg['scenario_dir'], f'{ref}.json')
        if not os.path.isfile(path):
            raise sc.ScenarioError([f'no scenario named {ref!r}'])
        with open(path, 'rb') as f:
            return sc.validate_bytes(f.read(), ref)

    # ── runs ──────────────────────────────────────────────────────────────
    def start_run(self, payload):
        """Validate, build lanes, connect, activate channels, start. Raises ScenarioError
        for anything the operator can fix; RuntimeError for a busy engine or a dead server."""
        with self._lock:
            if self.run is not None and self.run.state in ('running', 'paused', 'stopping'):
                raise RuntimeError('a scenario is already running — stop it first')
            params = sc.validate_run_params(payload, self.lane_ids_available())
            doc = self.load_scenario(params['scenario'])
            needed = {e['lane'] for e in doc['entities']} | {ev.get('lane') or doc['defaults']['lane'] for ev in doc['events']}
            if doc['generate']:
                needed.add(doc['generate']['lane'])
            missing = sorted(needed - set(params['lanes']))
            if missing:
                raise sc.ScenarioError([f'scenario uses lane {m!r} but no channel was assigned to it' for m in missing])
            if not self.cfg['tak_host'] and not self.cfg['dry_run']:
                raise RuntimeError('SIM_TAK_HOST is not set')

            lanes = {}
            for lid, spec in params['lanes'].items():
                if lid not in needed:
                    continue
                exercise = bool(spec['exercise'] or params['exercise']
                                or spec['channel'] != params['default_channel'])
                lanes[lid] = Lane(lid, spec['channel'], self._lane_cert(lid), self.cfg['ca_file'],
                                  self.cfg['tak_host'], self.cfg['tak_port'], self.cfg['tak_api_port'],
                                  exercise=exercise, log=self.log, dry_run=self.cfg['dry_run'])
            self.log(f'run request: scenario={doc["name"]} center={params["center"][0]:.5f},{params["center"][1]:.5f} '
                     f'tempo={params["tempo"]}x lanes={{{", ".join(f"{k}->{v.channel}{" (EXERCISE)" if v.exercise else ""}" for k, v in lanes.items())}}}')
            for ln in lanes.values():
                ln.start()
            deadline = time.monotonic() + self.cfg['connect_wait_s']
            while time.monotonic() < deadline and not all(ln.connected for ln in lanes.values()):
                time.sleep(0.2)
            dead = [ln for ln in lanes.values() if not ln.connected]
            if dead:
                for ln in lanes.values():
                    ln.stop()
                errs = '; '.join(f'lane {ln.id}: {ln.last_error or "no connection"}' for ln in dead)
                raise RuntimeError(f'could not connect to TAK Server {self.cfg["tak_host"]}:{self.cfg["tak_port"]} — {errs}')
            run = Run(doc, params, lanes, self.log, self.cfg['video_base'], params['default_channel'])
            run.start()
            self.run = run
            if self.cfg['activate_groups']:
                # After the socket exists AND the first reports are out (TAK binds the
                # subscription to a user from the first message), so the server applies the
                # activation to the live subscription. Retried while the LDAP outpost catches
                # up with a membership change (~30 s cache). Runs off the request thread.
                threading.Thread(target=self._activate_all, args=(run, list(lanes.values())),
                                 name='activate', daemon=True).start()
            return {'started': True, 'scenario': doc['name'], 'entities': len(run.entities),
                    'events': len(run.events), 'lanes': {k: v.channel for k, v in lanes.items()}}

    def _activate_all(self, run, lanes):
        time.sleep(1.5)
        for ln in lanes:
            if run.state in ('stopping', 'stopped'):
                return
            self._activate_lane(ln)

    def _activate_lane(self, ln):
        want = ln.channel[4:] if ln.channel.startswith('tak_') else ln.channel
        t_end = time.monotonic() + self.cfg['activate_wait_s']
        names, changed = [], 0
        while True:
            names, changed = ln.ensure_groups_active()
            if want in names or time.monotonic() > t_end or self.cfg['dry_run']:
                break
            self.log(f'lane {ln.id}: server does not list channel {want!r} yet (has {names or "none"}); waiting for LDAP')
            time.sleep(5)
        if want in names or self.cfg['dry_run']:
            self.log(f'lane {ln.id}: server groups {names} ({changed} activated)')
        else:
            self.log(f'lane {ln.id}: WARNING server groups {names} do not include {want!r} — traffic may reach no one')

    def pause(self):
        r = self.run
        if r is None or r.state not in ('running',):
            return False
        r.pause()
        return True

    def resume(self):
        r = self.run
        if r is None or r.state != 'paused':
            return False
        r.resume()
        return True

    def stop(self, reason='stopped by operator'):
        r = self.run
        if r is None or r.state in ('stopped', 'idle'):
            return False
        r.stop(reason)
        return True

    def status(self):
        r = self.run
        return {
            'version': self.cfg['version'], 'engine_uptime_s': round(time.time() - self.started_at),
            'tak_host': self.cfg['tak_host'], 'tak_port': self.cfg['tak_port'],
            'dry_run': self.cfg['dry_run'], 'lanes_enrolled': self.lane_ids_available(),
            'default_channel': self.cfg['default_channel'],
            'state': r.state if r is not None else 'idle',
            'run': r.stats() if r is not None else None,
        }

    def shutdown(self):
        """SIGTERM / container stop: deletes go out before we exit (§4.3)."""
        r = self.run
        if r is not None and r.state in ('running', 'paused'):
            self.log('shutdown requested — stopping run and deleting emitted objects')
            r.stop('engine shutdown')
