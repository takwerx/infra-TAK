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
"""ops #845: a box that already has SMS set up gets the fixed sms_send.py on update.

sms_send.py / sms_send.sh are "optional" Guard Dog scripts (installed when SMS is saved), so
the startup copy (_auto_update_guarddog) skips them. Without this, the HTTPS fix in
sms_send.py reached only boxes where the operator saved the SMS settings again; every
existing SMS box kept the old plain-HTTP script and still sent no alert texts.

Fails on dev 22e58b1 (the startup copy writes neither file).
"""
import os
import pathlib
import re
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
STARTUP_SRC = APP[APP.index('def _auto_update_guarddog():'):
                  APP.index('def _start_guarddog_background_at_boot(')]
GD_HELPER_SRC = APP[APP.index('_GD_PLACEHOLDER_RE = re.compile('):APP.index('def _write_priv(')]
GD = '/opt/tak-guarddog'
SCRIPTS = REPO / 'scripts' / 'guarddog'


class _Stop(BaseException):   # BaseException: the code under test catches Exception
    pass


class _Proc:
    @staticmethod
    def run(*a, **k):
        return None


def _run_startup(tmp_path, monkeypatch, capsys, settings, on_box):
    """Run the real _auto_update_guarddog up to the end of its script loop.
    on_box: names present in /opt/tak-guarddog before the run. Returns {name: written text}."""
    written = {}
    present = set(on_box)

    def _write_priv(path, content, mode='w', perm=None):
        written[os.path.basename(path)] = content

    def _stop(*a, **k):
        raise _Stop()   # first call after the script loop and the SMS refresh

    ns = {
        'os': os, 're': re, 'datetime': datetime, 'BASE_DIR': str(REPO), 'VERSION': '10.2.11-alpha',
        'AUTHENTIK_VETTED_RELEASE': '2025.10', '_pin_takserver_jvm': lambda *a, **k: None,
        '_gd_baked_remote_values': lambda p: None,
        '_guarddog_server_identifier': lambda s: (_ for _ in ()).throw(_Stop()),   # first use after the SMS refresh
        'subprocess': _Proc, '_sudo_wrap': lambda a: a, '_makedirs_priv': lambda d: None,
        '_read_priv': lambda p: (_ for _ in ()).throw(FileNotFoundError(p)),
        '_write_priv': _write_priv, '_chmod_priv': lambda p, m: None,
        '_tak_is_container': _stop,
        'load_settings': lambda: settings,
        '_get_tak_deployment_config': lambda s: {'mode': 'single'},
        '_get_fedhub_deployment_config': lambda s: {},
        '_guarddog_alert_recipient_warning': lambda s: '',
        '_safe_alert_email_list': lambda e: e or '',
        '_get_tak_cert_password': lambda s: 'atakatak',
        '_broker_should_route': lambda: False,
    }
    monkeypatch.undo()    # STARTUP_SRC ends with a call of its own: run it on the real filesystem
    exec(GD_HELPER_SRC, ns)
    exec(STARTUP_SRC, ns)
    capsys.readouterr()
    real_exists, real_isdir = os.path.exists, os.path.isdir
    monkeypatch.setattr(os.path, 'exists', lambda p: (
        True if p in ('/opt/tak', GD) else
        (os.path.basename(p) in present) if p.startswith(GD + '/') else real_exists(p)))
    monkeypatch.setattr(os.path, 'isdir', lambda p: True if p == GD else real_isdir(p))
    try:
        ns['_auto_update_guarddog']()
    except _Stop:
        pass            # reached code past the script loop; not under test
    out = capsys.readouterr().out
    assert 'auto-update skipped' not in out, out   # the harness itself must not be what stopped it
    return written


SMS_ON = {'guarddog_alert_email': 'ops@example.com',
          'guarddog_sms': {'provider': 'brevo', 'api_key': 'k', 'sender': 's', 'to_numbers': '+10000000000'}}


def test_box_with_sms_gets_the_fixed_scripts_on_startup(tmp_path, monkeypatch, capsys):
    w = _run_startup(tmp_path, monkeypatch, capsys, SMS_ON, {'sms_send.py', 'sms_send.sh'})
    assert w.get('sms_send.py') == (SCRIPTS / 'sms_send.py').read_text()
    assert w.get('sms_send.sh') == (SCRIPTS / 'sms_send.sh').read_text()
    assert 'https' in w['sms_send.py'] and 'http://127.0.0.1:5001' not in w['sms_send.py']


def test_box_without_sms_set_up_gets_no_sms_scripts(tmp_path, monkeypatch, capsys):
    """Optional means optional: SMS off (provider empty) or never set up writes nothing."""
    w = _run_startup(tmp_path, monkeypatch, capsys, {'guarddog_alert_email': 'ops@example.com'}, set())
    assert 'sms_send.py' not in w and 'sms_send.sh' not in w
    w = _run_startup(tmp_path, monkeypatch, capsys, {'guarddog_sms': {}}, {'sms_send.py'})
    assert 'sms_send.py' not in w and 'sms_send.sh' not in w


def test_sms_configured_but_script_not_on_box_is_left_alone(tmp_path, monkeypatch, capsys):
    """The folder can be missing the file (never saved on this box): do not create it here."""
    w = _run_startup(tmp_path, monkeypatch, capsys, SMS_ON, set())
    assert 'sms_send.py' not in w and 'sms_send.sh' not in w
