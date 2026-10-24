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
"""A native (.deb/.rpm) TAK Server deploy must re-sync TAK Portal's certs (ops #195).

Field, 2026-10-23: TAK Server had been reinstalled natively a month earlier, which generates a
new CA and admin.p12. The container deploy re-syncs TAK Portal's tak-client.p12 + tak-ca.pem
(v10.0.1); the native run_takserver_deploy never did. The portal kept the OLD CA and client
cert for a month: every 8443 call failed SELF_SIGNED_CERT_IN_CHAIN, every 8089 stream
handshake failed "peer not verified", and the dashboard said TAK Server not connected with
no clients.
"""

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_FUNCS = {n.name: ast.get_source_segment(APP, n) for n in ast.parse(APP).body
          if isinstance(n, ast.FunctionDef)}


def test_native_deploy_resyncs_portal_certs_after_generating_them():
    body = _FUNCS['run_takserver_deploy']
    call = body.index('_takportal_sync_certs(plog=log_step, restart=True)')
    # After the new CA/admin.p12 exist, and before the deploy reports success.
    assert body.index('━━━ Step 7/9: Generating Certificates') < call
    assert call < body.index('✓ DEPLOYMENT COMPLETE!')
    guard = body[body.rindex('try:', 0, call):call]
    assert 'if _takportal_web_running():' in guard
    # Non-fatal: a portal hiccup must never fail a TAK Server deploy.
    after = body[call:call + 400]
    assert 'except Exception' in after and 'FATAL' not in after


def test_every_path_that_makes_a_new_tak_ca_resyncs_the_portal():
    # Each of these regenerates the TAK Server CA that TAK Portal pins.
    for fn in ('run_takserver_deploy', '_deploy_takserver_container', 'takserver_rotate_rootca'):
        assert '_takportal_sync_certs(' in _FUNCS[fn], fn
