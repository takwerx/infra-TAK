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
"""mediamtx-cert-sync.sh is refreshed on update (ops #863).

The script that sends the stream cert to a remote MediaMTX host was written only when
MediaMTX was deployed to that host, and the console's startup refresh skips it (it is an
optional Guard Dog script). A fix to its template reached a box only after the owner
deployed again. The startup refresh now reads the endpoint baked into the installed copy
and renders the current template with it.
"""

import importlib.util
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text()
TEMPLATE = (REPO / 'scripts' / 'guarddog' / 'mediamtx-cert-sync.sh').read_text()

PLACEHOLDERS = ('MTX_DOMAIN_PLACEHOLDER', 'MTX_HOST_PLACEHOLDER', 'MTX_USER_PLACEHOLDER',
                'MTX_PORT_PLACEHOLDER', 'MTX_KEYFILE_PLACEHOLDER')
ENDPOINT = {
    'MTX_DOMAIN_PLACEHOLDER': 'stream.example.com',
    'MTX_HOST_PLACEHOLDER': '10.0.0.9',
    'MTX_USER_PLACEHOLDER': 'ubuntu',
    'MTX_PORT_PLACEHOLDER': '2222',
    'MTX_KEYFILE_PLACEHOLDER': '/home/takwerx/.ssh/id_ed25519',
}


def _installed_by_an_older_release(vals=ENDPOINT):
    """What a box holds: the template of an earlier release, filled at deploy time."""
    text = TEMPLATE.replace('systemctl restart mediamtx', 'OLD-RESTART-LINE')
    for k, v in vals.items():
        text = text.replace(k, v)
    return text


def _helpers(installed, calls):
    """The two new functions from app.py, with the console's own helpers stubbed."""
    m = re.search(r'^_GD_BAKED_MTX_KEYS = .*?(?=^def _auto_update_guarddog)', APP, re.S | re.M)
    assert m, 'app.py has no _GD_BAKED_MTX_KEYS / _gd_refresh_mtx_cert_sync'

    def read(path):
        if installed is None:
            raise FileNotFoundError(path)
        return installed

    def install(name, template, values):
        calls.append((name, template, dict(values)))
        return True

    ns = {'re': re, '_read_priv': read, '_gd_install_script': install,
          '_gd_template': lambda name: TEMPLATE}
    exec(compile(m.group(0), 'app.py:mtx', 'exec'), ns)
    return ns


def test_update_renders_the_current_template_with_the_endpoint_the_box_holds():
    calls = []
    ns = _helpers(_installed_by_an_older_release(), calls)
    assert ns['_gd_refresh_mtx_cert_sync']() is True
    assert len(calls) == 1
    name, template, values = calls[0]
    assert name == 'mediamtx-cert-sync.sh'
    assert template == TEMPLATE                       # the current template, not the box's copy
    assert values == ENDPOINT                         # the deployed endpoint, unchanged
    # and the result is a complete script with the template's current code
    out = template
    for k, v in values.items():
        out = out.replace(k, v)
    assert 'PLACEHOLDER' not in out
    assert 'OLD-RESTART-LINE' not in out and 'systemctl restart mediamtx' in out
    assert 'PORT="2222"' in out and 'REMOTE_HOST="10.0.0.9"' in out


def test_an_empty_key_file_is_kept_empty():
    calls = []
    vals = dict(ENDPOINT, MTX_KEYFILE_PLACEHOLDER='')           # the deploy found no key file
    ns = _helpers(_installed_by_an_older_release(vals), calls)
    assert ns['_gd_refresh_mtx_cert_sync']() is True
    assert calls[0][2] == vals


def test_a_box_without_the_script_is_left_alone():
    calls = []
    ns = _helpers(None, calls)                                   # no remote MediaMTX here
    assert ns['_gd_baked_mtx_values']('/opt/tak-guarddog/mediamtx-cert-sync.sh') is None
    assert ns['_gd_refresh_mtx_cert_sync']() is False
    assert calls == []


@pytest.mark.parametrize('installed', [
    TEMPLATE,                                                    # never filled in
    'DOMAIN="stream.example.com"\nREMOTE_HOST="h"\n',            # a script we cannot read an endpoint from
    _installed_by_an_older_release(dict(ENDPOINT, MTX_HOST_PLACEHOLDER='')),
    _installed_by_an_older_release(dict(ENDPOINT, MTX_DOMAIN_PLACEHOLDER='')),
])
def test_a_script_with_no_readable_endpoint_is_not_rewritten(installed):
    calls = []
    ns = _helpers(installed, calls)
    assert ns['_gd_refresh_mtx_cert_sync']() is False
    assert calls == []


def test_a_refused_render_never_stops_the_startup_sync():
    calls = []
    ns = _helpers(_installed_by_an_older_release(), calls)

    def refuse(*a, **k):
        raise RuntimeError('Guard Dog script mediamtx-cert-sync.sh not installed: refused')
    ns['_gd_install_script'] = refuse
    assert ns['_gd_refresh_mtx_cert_sync']() is False


def test_every_template_placeholder_is_read_back_from_the_script():
    """The keys read from an installed copy must be exactly what the deploy fills in, or a
    new placeholder would be rendered blank on update."""
    assert set(re.findall(r'\b[A-Z][A-Z0-9_]*_PLACEHOLDER\b', TEMPLATE)) == set(PLACEHOLDERS)
    ns = _helpers(_installed_by_an_older_release(), [])
    assert {ph for _, ph in ns['_GD_BAKED_MTX_KEYS']} == set(PLACEHOLDERS)
    # each variable is a `VAR="PLACEHOLDER"` line in the template, which is what the regex reads
    for var, ph in ns['_GD_BAKED_MTX_KEYS']:
        assert re.search(r'^%s="%s"$' % (var, ph), TEMPLATE, re.M), (var, ph)


def test_the_console_start_calls_it_outside_the_guard_dog_sync():
    """_auto_update_guarddog returns early on a box with no TAK Server (/opt/tak). A console
    with a remote MediaMTX and no local TAK Server still holds the cert-sync script, so the
    refresh is its own call at module level, after the sync, not a line inside it (found on
    a throwaway box: ops #863)."""
    body = re.search(r'^def _auto_update_guarddog\(.*?(?=^_auto_update_guarddog\(\))', APP, re.S | re.M).group(0)
    code = re.sub(r'#.*', '', body)
    assert "if not os.path.exists('/opt/tak'):\n        return" in code     # the early return this works around
    assert '_gd_refresh_mtx_cert_sync' not in code
    assert re.search(r'^_auto_update_guarddog\(\)\n(?:#.*\n)*_gd_refresh_mtx_cert_sync\(\)$', APP, re.M)
    # it stays an optional script: the generic loop still skips it
    assert 'name in _GD_OPTIONAL_SCRIPTS' in code


def test_root_accepts_the_values_read_back_from_an_installed_script():
    """The console only names values; root checks each one. A box's baked endpoint must pass."""
    spec = importlib.util.spec_from_file_location('takwerx_broker_863', REPO / 'broker' / 'takwerx_broker.py')
    B = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(B)
    ns = _helpers(_installed_by_an_older_release(), [])
    baked = ns['_gd_baked_mtx_values']('/opt/tak-guarddog/mediamtx-cert-sync.sh')
    assert set(baked) == set(PLACEHOLDERS)
    for ph, value in baked.items():
        assert B._GD_VALUE_RES[ph].match(value), (ph, value)
        assert not B._GD_UNSAFE_RE.search(value), (ph, value)


def _converge(converge, refresh, cert_sync):
    """The real _startup_broker_converge from app.py, with its three callees stubbed."""
    start = APP.index('def _startup_broker_converge():')
    ns = {'_broker_converge_running_source': converge, '_auto_update_guarddog': refresh,
          '_gd_refresh_mtx_cert_sync': cert_sync}
    exec(APP[start:APP.index('\n_startup_broker_converge()', start)], ns)
    return ns['_startup_broker_converge']


def test_cert_sync_is_rendered_again_once_the_broker_changed():
    """ops #845 pattern: at module load root's broker still holds the previous release's
    templates and gd_render fills from them, so the first restart after Update Now would
    keep the old cert-sync script. Once the broker has the new commit, refresh it again."""
    calls = []
    _converge(lambda: True, lambda: calls.append('guarddog'), lambda: calls.append('cert-sync'))()
    assert calls == ['guarddog', 'cert-sync']


def test_no_second_cert_sync_pass_when_the_broker_did_not_change():
    calls = []
    _converge(lambda: False, lambda: calls.append('guarddog'), lambda: calls.append('cert-sync'))()
    assert calls == []


def test_a_failed_second_pass_never_stops_startup_and_each_pass_is_independent(capsys):
    calls = []

    def boom():
        raise RuntimeError('gd_render refused')

    _converge(lambda: True, boom, lambda: calls.append('cert-sync'))()      # guarddog pass fails
    assert calls == ['cert-sync']
    _converge(lambda: True, lambda: None, boom)()                           # cert-sync pass fails
    assert 'cert-sync refresh after broker convergence skipped' in capsys.readouterr().out
