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
"""ops #470 / infra-TAK #398 — a 20 GB hosted-tileset upload got a 413 from CloudTAK's own nginx.

The api container's nginx.conf (written by nginx.conf.js on every start) caps every request body
at 5G. The API behind it streams the file into the object store with no cap of its own: on test12
a 6 GiB file POSTed to /api/server/tileset got 413 at 5G and 200 (141 s) with the limit raised.

nginx buffers a body to disk before it forwards it, so the cap is raised for that one URL only
(an exact-match location), and _cloudtak_upload_limit_heal re-applies it after every recreate.

app.py cannot be imported in a test, so this reads the shipped text and runs the shipped script
against a sample nginx.conf with a stub `nginx`.
"""

import os
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

STOCK_CONF = """user nginx;
http {
    server {
        listen 5000;
        client_max_body_size 5G;

        location / {
            alias /home/etl/app/dist/;
        }

        location ~ ^/api(?:/(.*))?$ {
            proxy_pass http://127.0.0.1:5001;
            proxy_read_timeout 600s;
        }

    }
}
"""


def _script():
    m = re.search(r"^_CT_NGINX_UPLOAD_SH = r'''(.*?)'''\n", APP, re.M | re.S)
    assert m, 'the nginx upload script is gone'
    mx = re.search(r"^CLOUDTAK_TILESET_UPLOAD_MAX = '(\w+)'", APP, re.M)
    assert mx, 'the upload limit constant is gone'
    return m.group(1).replace('__MAX__', mx.group(1)), mx.group(1)


def _run(tmp_path, conf_text, nginx_test_ok=True):
    conf = tmp_path / 'nginx.conf'
    conf.write_text(conf_text)
    bindir = tmp_path / 'bin'
    bindir.mkdir(exist_ok=True)
    log = tmp_path / 'nginx.log'
    stub = bindir / 'nginx'
    stub.write_text('#!/bin/sh\necho "$@" >> %s\n[ "$1" = "-t" ] && exit %d\nexit 0\n'
                    % (log, 0 if nginx_test_ok else 1))
    stub.chmod(0o755)
    script = _script()[0].replace('/etc/nginx/nginx.conf', str(conf))
    r = subprocess.run(['sh', '-c', script], capture_output=True, text=True,
                       env={**os.environ, 'PATH': f'{bindir}:{os.environ["PATH"]}'}, timeout=30)
    return r.stdout.strip(), conf.read_text(), (log.read_text() if log.exists() else '')


def test_script_adds_a_scoped_location_and_reloads(tmp_path):
    out, conf, nginx_log = _run(tmp_path, STOCK_CONF)
    assert out == 'HEALED'
    limit = _script()[1]
    block = conf[conf.index('location = /api/server/tileset'):]
    block = block[:block.index('}')]
    assert f'client_max_body_size {limit};' in block
    assert 'proxy_pass http://127.0.0.1:5001;' in block
    # streamed, not buffered: an anonymous POST must not make nginx write the body to disk first
    assert 'proxy_request_buffering off;' in block
    # exact match is tried before the regex /api location, wherever it sits in the file
    assert conf.index('location = /api/server/tileset') < conf.index('location ~ ^/api')
    # every other URL keeps the 5G cap
    assert conf.count('client_max_body_size') == 2
    assert 'client_max_body_size 5G;' in conf
    assert '-t' in nginx_log and '-s reload' in nginx_log


def test_script_is_a_no_op_when_already_applied(tmp_path):
    _run(tmp_path, STOCK_CONF)
    first = (tmp_path / 'nginx.conf').read_text()
    (tmp_path / 'nginx.log').unlink()
    out, conf, nginx_log = _run(tmp_path, first)
    assert out == 'OK'
    assert conf == first
    assert nginx_log == ''   # no reload when nothing changed


def test_script_leaves_the_stock_nginx_conf_alone(tmp_path):
    stock = 'events {}\nhttp { server { listen 80; } }\n'   # before nginx.conf.js has written the real one
    out, conf, _ = _run(tmp_path, stock)
    assert out == 'NOCONF'
    assert conf == stock


def test_script_restores_the_config_when_nginx_rejects_it(tmp_path):
    out, conf, _ = _run(tmp_path, STOCK_CONF, nginx_test_ok=False)
    assert out == 'FAIL'
    assert conf == STOCK_CONF
    assert not (tmp_path / 'nginx.conf.ops470.bak').exists()


def test_limit_covers_the_reporters_20gb_file():
    gb = int(re.fullmatch(r'(\d+)G', _script()[1]).group(1))
    assert gb >= 20


def test_heal_runs_wherever_cloudtak_is_recreated_or_started():
    # deploy (local + remote), update, restart, recreate-and-heal, console start
    assert len(re.findall(r'^\s+_cloudtak_upload_limit_heal\(', APP, re.M)) >= 7
    startup = APP[APP.index('def _startup_heal_cloudtak_media_hls'):]
    assert '_cloudtak_upload_limit_heal()' in startup[:startup.index('_startup_heal_cloudtak_media_hls()\n')]
    recreate = APP[APP.index('def _cloudtak_recreate_and_heal'):]
    assert '_cloudtak_upload_limit_heal(' in recreate[:recreate.index('def _startup_harden_cloudtak_ports')]
