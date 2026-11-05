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
"""ops #502 — the 25G tileset upload rule is lost when TAK Portal recreates the CloudTAK api.

The rule (ops #470) lives in the api container's nginx.conf, which the container writes afresh on
every start. A TAK Portal plugin install or update recreates the api, so on test12 (v10.3.6 T&E)
a 6 GiB upload got 413 in 0.2 s until the next console restart. Nothing looked for the rule: the
console's drift check and Guard Dog's CloudTAK watcher only knew the compose override, the HLS
profile and Print. The drift logic itself is tested in test_cloudtak_autorepair_ops197.py; this
file runs the shipped check script against real nginx.conf text and ties it to the apply script,
so the three readers of the rule (check, apply, Guard Dog) cannot drift apart.
"""

import os
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-cloudtak-watch.sh').read_text()

# What nginx.conf.js writes on a container start (the rule is not in it), and the file that is
# there for a moment before that.
WRITTEN_CONF = """user nginx;
http {
    server {
        listen 5000;
        client_max_body_size 5G;

        location ~ ^/api(?:/(.*))?$ {
            proxy_pass http://127.0.0.1:5001;
        }
    }
}
"""
STOCK_CONF = 'events {}\nhttp { server { listen 80; } }\n'


def _sh(name):
    m = re.search(rf"^{name} = r'''(.*?)'''\n", APP, re.M | re.S)
    assert m, f'{name} is gone'
    return m.group(1)


def _max():
    return re.search(r"^CLOUDTAK_TILESET_UPLOAD_MAX = '(\w+)'", APP, re.M).group(1)


def _run(script, conf_path, tmp_path):
    bindir = tmp_path / 'bin'
    bindir.mkdir(exist_ok=True)
    stub = bindir / 'nginx'
    stub.write_text('#!/bin/sh\nexit 0\n')
    stub.chmod(0o755)
    script = script.replace('/etc/nginx/nginx.conf', str(conf_path)).replace('__MAX__', _max())
    r = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=30,
                       env={**os.environ, 'PATH': f'{bindir}:{os.environ["PATH"]}'})
    return r.stdout.strip()


def test_check_says_missing_for_a_freshly_written_config(tmp_path):
    conf = tmp_path / 'nginx.conf'
    conf.write_text(WRITTEN_CONF)
    assert _run(_sh('_CT_NGINX_UPLOAD_CHECK_SH'), conf, tmp_path) == 'MISSING'


def test_check_says_ok_once_the_apply_script_has_run(tmp_path):
    conf = tmp_path / 'nginx.conf'
    conf.write_text(WRITTEN_CONF)
    assert _run(_sh('_CT_NGINX_UPLOAD_SH'), conf, tmp_path) == 'HEALED'
    before = conf.read_text()
    assert _run(_sh('_CT_NGINX_UPLOAD_CHECK_SH'), conf, tmp_path) == 'OK'
    assert conf.read_text() == before                     # reading never edits the file


def test_check_is_not_drift_while_the_stock_config_is_still_there(tmp_path):
    conf = tmp_path / 'nginx.conf'
    conf.write_text(STOCK_CONF)
    assert _run(_sh('_CT_NGINX_UPLOAD_CHECK_SH'), conf, tmp_path) == 'NOCONF'
    assert conf.read_text() == STOCK_CONF


def test_check_is_not_drift_when_the_file_cannot_be_read(tmp_path):
    assert _run(_sh('_CT_NGINX_UPLOAD_CHECK_SH'), tmp_path / 'absent.conf', tmp_path) == 'NOCONF'


def test_guard_dog_reads_the_same_markers_as_the_apply_script():
    # the watcher greps nginx.conf itself; it must look for what the apply script writes and for
    # the line that tells the real config from the stock one
    apply_sh = _sh('_CT_NGINX_UPLOAD_SH')
    for marker in ('location = /api/server/tileset', 'location ~ ^/api'):
        assert marker in apply_sh and marker in WATCH and marker in _sh('_CT_NGINX_UPLOAD_CHECK_SH')


def test_guard_dog_alarm_names_the_symptom_and_the_check():
    assert 'CloudTAK api is missing the large-upload (tileset) limit' in WATCH
    assert "docker exec cloudtak-api-1 grep 'location = /api/server/tileset'" in WATCH
